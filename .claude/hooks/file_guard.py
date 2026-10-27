#!/usr/bin/env python3
"""PreToolUse hook for Write / Edit / MultiEdit / NotebookEdit.

Catches problems at the moment Claude writes them, before pre-commit:

  deny -> hardcoded credentials in new content; writing to secret files (.env, keys)
  ask  -> infrastructure-as-code, security-critical code, the guardrails
          themselves, or PII-like data in fixtures. These need a human to
          approve the edit (HITL) even in acceptEdits / auto mode.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from guard_common import (
        CREDENTIAL_CATEGORIES,
        GUARDRAIL_PATH_RE,
        IAC_PATH_RE,
        MAX_SCAN_CHARS,
        PROJECT_DIR,
        SECRET_PATH_RE,
        SECURITY_CRITICAL_PATH_RE,
        Redactor,
        Severity,
        audit,
        pre_tool_decision,
        read_event,
    )
except Exception as _exc:  # fail closed: a missing or broken shared module must not allow
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
        "permissionDecisionReason": f"[AI guardrail] file_guard could not load its rules ({type(_exc).__name__}); manual review required"}}))
    sys.exit(0)

WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def new_content(tool_input: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in ("content", "new_string", "new_source"):
        if isinstance(tool_input.get(key), str):
            parts.append(tool_input[key])
    for edit in tool_input.get("edits") or []:
        if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
            parts.append(edit["new_string"])
    return "\n".join(parts)


def relative(path: str) -> str:
    try:
        return Path(path).resolve().relative_to(PROJECT_DIR).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix()


def main() -> None:
    event = read_event()
    if event.get("tool_name") not in WRITE_TOOLS:
        return
    tool_input = event.get("tool_input") or {}
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    rel = relative(path)

    if SECRET_PATH_RE.search(rel):
        audit("file_guard", event, "deny", ["secret_file_write"])
        pre_tool_decision(
            "deny",
            f"`{rel}` is a secrets file. The AI agent may not create or edit it; "
            "update the matching `.example` template and let a human fill real values.",
        )

    content = new_content(tool_input)
    if len(content) > MAX_SCAN_CHARS:
        audit("file_guard", event, "ask", ["oversized_content"], {"path": rel})
        pre_tool_decision("ask", f"`{rel}`: content too large to scan for secrets ({len(content)} chars); review before approving")
    findings = Redactor().scan(content)
    creds = [f for f in findings if f.category in CREDENTIAL_CATEGORIES and f.severity >= Severity.CRITICAL]
    if creds:
        audit("file_guard", event, "deny", [f.rule for f in creds], {"path": rel})
        kinds = ", ".join(sorted({f.category for f in creds}))
        pre_tool_decision(
            "deny",
            f"hardcoded credential detected ({kinds}) in `{rel}`. Read it from an environment variable "
            "or the secret manager instead, and rotate the value if it is real.",
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
        audit("file_guard", event, "ask", rules, {"path": rel})
        pre_tool_decision("ask", f"`{rel}`: " + "; ".join(reasons))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # fail closed
        pre_tool_decision("ask", f"file_guard error ({type(exc).__name__}); manual review required")
