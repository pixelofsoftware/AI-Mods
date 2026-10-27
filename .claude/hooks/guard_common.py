"""Shared helpers for the Claude Code guardrail hooks.

Hooks receive the event as JSON on stdin and answer with JSON on stdout
(https://code.claude.com/docs/en/hooks). Detection patterns come from
scripts/claude_safeguard.py so the API wrapper and the hooks never drift apart.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

# .claude/hooks/guard_common.py -> repository root
PROJECT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_DIR / "scripts"))

from claude_safeguard import (  # noqa: E402  (import after sys.path setup)
    CREDENTIAL_CATEGORIES,
    Redactor,
    Severity,
    detect_prompt_injection,
)

__all__ = [
    "CREDENTIAL_CATEGORIES",
    "Redactor",
    "Severity",
    "detect_prompt_injection",
    "SECRET_PATH_RE",
    "GUARDRAIL_PATH_RE",
    "IAC_PATH_RE",
    "SECURITY_CRITICAL_PATH_RE",
    "ENV_GLOB_RE",
    "ENV_TEMPLATE_SUFFIXES",
    "looks_secret",
    "MAX_SCAN_CHARS",
    "read_event",
    "pre_tool_decision",
    "audit",
    "fingerprint",
]

# Overridable so tests (and CI) never write into a developer's real audit log.
AUDIT_DIR = Path(os.environ.get("CLAUDE_GUARDRAIL_AUDIT_DIR") or PROJECT_DIR / ".claude" / "audit")

# Template suffixes that are safe to read and commit (keep in sync with the policy
# allowed_paths and .gitignore; tests/test_drift.py enforces it).
ENV_TEMPLATE_SUFFIXES = ("example", "sample", "template", "dist", "defaults")

# Files that hold secrets. `.env.example` style templates stay usable.
SECRET_PATH_RE = re.compile(
    r"""(?ix)
    (?:^|[/\\])\.env(?:\.(?!(?:example|sample|template|dist|defaults)$)[\w.\-]+)?$
  | (?:^|[/\\])\.envrc$
  | (?:^|[/\\])kubeconfig[\w.\-]*$
  | ^/proc/[^/]+/environ$
  | (?:^|[/\\])(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$
  | \.(?:pem|key|p12|pfx|jks|keystore|kdbx|ppk)$
  | (?:^|[/\\])\.(?:aws|ssh|gnupg|kube|docker|azure)(?:[/\\]|$)
  | (?:^|[/\\])\.config[/\\]gcloud(?:[/\\]|$)
  | (?:^|[/\\])\.(?:netrc|npmrc|pypirc|pgpass|git-credentials)$
  | \.tfstate(?:\.backup)?$
  | (?:^|[/\\])secrets?[/\\]
  | (?:^|[/\\])(?:credentials|client_secrets?|service[-_]?account[\w\-]*)\.json$
  | ^/etc/(?:shadow|gshadow|sudoers)
    """
)

# Changes to the guardrails themselves always need a human.
GUARDRAIL_PATH_RE = re.compile(
    r"""(?ix)
    (?:^|/)\.claude/
  | (?:^|/)\.mcp\.json$
  | (?:^|/)CLAUDE\.md$
  | (?:^|/)scripts/claude_safeguard\.py$
  | (?:^|/)scripts/precommit/
  | (?:^|/)\.pre-commit-config\.yaml$
  | (?:^|/)\.gitleaks\.toml$
  | (?:^|/)(?:\.github/)?CODEOWNERS$
  | (?:^|/)config/claude-guardrails-policy\.json$
  | (?:^|/)\.github/workflows/
  | (?:^|/)enterprise/
  | (?:^|/)docs/claude-guardrails(?:-setup)?\.md$
  | (?:^|/)scripts/setup_guardrails\.sh$
  | (?:^|/)pyproject\.toml$
  | (?:^|/)\.gitignore$
    """
)

# Globs that expand to secrets files: `.env*`, `.env.{prod,local}`, `*.pem`.
ENV_GLOB_RE = re.compile(r"(?:^|/)\.env[^/]*[*?\[{]|(?:^|/)\*\.(?:pem|key|p12|pfx)$")


def looks_secret(path: str) -> bool:
    """True if a path (or glob) names secret material. `~` is treated as a home directory."""
    return bool(SECRET_PATH_RE.search(path.replace("~", "/home/user")) or ENV_GLOB_RE.search(path))

# Infrastructure-as-code: AI-generated changes require human-in-the-loop review.
IAC_PATH_RE = re.compile(
    r"""(?ix)
    \.(?:tf|tfvars|hcl|bicep)$
  | (?:^|/)(?:Dockerfile|Containerfile)(?:\.[\w\-]+)?$
  | (?:^|/)(?:docker-)?compose(?:\.[\w\-]+)?\.ya?ml$
  | (?:^|/)(?:k8s|kubernetes|manifests|helm|charts|kustomize|deploy|deployment|infra|terraform|ansible|cloudformation|cdk)/.+\.(?:ya?ml|json|j2|ts|py)$
  | (?:^|/)(?:serverless|skaffold|template)\.ya?ml$
  | \.template\.(?:json|ya?ml)$
    """
)

# Security-critical application code: auth, crypto, access control.
SECURITY_CRITICAL_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:auth\w*|oauth\w*|sso|saml|security|crypto\w*|iam|rbac|acl|permissions?|secrets?|keys?)(?:/|\.\w+$|_)"
)

# Hooks scan at most this many characters; anything larger is sent for human review
# so a huge payload cannot push a hook past its timeout (which would fail open).
MAX_SCAN_CHARS = 500_000


def read_event() -> Dict[str, Any]:
    """Parse the hook event. Malformed input raises, so the hook's fail-closed path runs."""
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    event = json.loads(raw)
    if not isinstance(event, dict):
        raise ValueError("hook event is not a JSON object")
    return event


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def pre_tool_decision(decision: str, reason: str) -> None:
    """Emit a PreToolUse decision ("deny" or "ask") and exit 0."""
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": decision,
                    "permissionDecisionReason": f"[AI guardrail] {reason}",
                }
            }
        )
    )
    sys.exit(0)


def audit(hook: str, event: Dict[str, Any], decision: str, rules: Iterable[str], extra: Optional[Dict[str, Any]] = None) -> None:
    """Append a metadata-only record to .claude/audit/guardrail-events.jsonl.

    Never records prompt text, file content or full commands, only rule names
    and a short fingerprint. The directory is gitignored and blocked by pre-commit.
    Set CLAUDE_GUARDRAIL_AUDIT=0 to disable.
    """
    if os.environ.get("CLAUDE_GUARDRAIL_AUDIT", "1") == "0":
        return
    record = {
        "@timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "hook": hook,
        "session_id": event.get("session_id"),
        "event": event.get("hook_event_name"),
        "tool": event.get("tool_name"),
        "permission_mode": event.get("permission_mode"),
        "decision": decision,
        "rules": sorted(set(rules)),
        "user": os.environ.get("USER") or os.environ.get("USERNAME"),
    }
    if extra:
        record.update(extra)
    try:
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_DIR / "guardrail-events.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        pass  # auditing must never break the developer's session
