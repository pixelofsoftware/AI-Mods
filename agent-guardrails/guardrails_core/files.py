"""File write and file read decisions (host-independent).

Ported from .claude/hooks/file_guard.py and read_guard.py: same checks, same order,
same messages. Hosts only differ in how they name a tool's path and content
fields; the adapters extract those and call the functions below.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List

from .common import (
    CREDENTIAL_CATEGORIES,
    GUARDRAIL_PATH_RE,
    IAC_PATH_RE,
    MAX_SCAN_CHARS,
    SECRET_PATH_RE,
    SECURITY_CRITICAL_PATH_RE,
    Redactor,
    Severity,
    looks_secret,
    relative,
)
from .verdict import Verdict


def evaluate_write(path: str, content: str, root: Path) -> Verdict:
    """Decide on writing `content` to `path` (absolute or project-relative)."""
    rel = relative(path, root)

    if SECRET_PATH_RE.search(rel):
        return Verdict(
            "deny",
            f"`{rel}` is a secrets file. The AI agent may not create or edit it; "
            "update the matching `.example` template and let a human fill real values.",
            ["secret_file_write"],
        )

    if len(content) > MAX_SCAN_CHARS:
        return Verdict(
            "ask",
            f"`{rel}`: content too large to scan for secrets ({len(content)} chars); review before approving",
            ["oversized_content"],
            {"path": rel},
        )
    findings = Redactor().scan(content)
    creds = [f for f in findings if f.category in CREDENTIAL_CATEGORIES and f.severity >= Severity.CRITICAL]
    if creds:
        kinds = ", ".join(sorted({f.category for f in creds}))
        return Verdict(
            "deny",
            f"hardcoded credential detected ({kinds}) in `{rel}`. Read it from an environment variable "
            "or the secret manager instead, and rotate the value if it is real.",
            [f.rule for f in creds],
            {"path": rel},
        )

    reasons: List[str] = []
    rules: List[str] = []
    probable = [f for f in findings if f.severity >= Severity.HIGH]
    if probable:
        rules += [f.rule for f in probable]
        reasons.append(
            "content contains likely secrets or regulated personal data ("
            + ", ".join(sorted({f.category for f in probable}))
            + "); use obviously synthetic fixtures"
        )
    if GUARDRAIL_PATH_RE.search(rel):
        rules.append("guardrail_change")
        reasons.append("this file is part of the AI guardrails; changes need security review (CODEOWNERS)")
    if IAC_PATH_RE.search(rel):
        rules.append("iac_change")
        reasons.append("infrastructure-as-code: AI-generated changes require human review before merge (HITL)")
    elif SECURITY_CRITICAL_PATH_RE.search(rel):
        rules.append("security_critical_change")
        reasons.append("security-critical code (auth/crypto/access control): human review required (HITL)")

    if reasons:
        return Verdict("ask", f"`{rel}`: " + "; ".join(reasons), rules, {"path": rel})
    return Verdict()


def evaluate_read(targets: Iterable[str]) -> Verdict:
    """Decide on reading or searching the given paths or glob patterns."""
    for target in targets:
        if looks_secret(target):
            return Verdict(
                "deny",
                f"reading `{os.path.basename(target) or target}` is blocked: it may contain secrets. "
                "Use the matching .example file, or ask the developer for the non-secret value you need.",
                ["secret_file_read"],
                {"target": os.path.basename(target)},
            )
    return Verdict()
