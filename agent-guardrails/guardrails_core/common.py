"""Shared path patterns, project location and audit log (host-independent).

The path patterns are copied unchanged from .claude/hooks/guard_common.py.
What differs: the project directory comes from the host's environment instead of
the hook file's location, and every audit record names the host.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from .safeguard import CREDENTIAL_CATEGORIES, Redactor, Severity, detect_prompt_injection  # noqa: F401  (re-exported)

PROJECT_ENV_VARS = ("AGENT_GUARDRAILS_PROJECT_DIR", "CLAUDE_PROJECT_DIR", "CURSOR_PROJECT_DIR")


def project_dir(event_cwd: Optional[str] = None) -> Path:
    """The workspace root: from the host's environment, else the event's cwd, else the process cwd."""
    for var in PROJECT_ENV_VARS:
        if os.environ.get(var):
            return Path(os.environ[var]).resolve()
    # No variable (Copilot): use the enclosing repository, never a subfolder the
    # session happens to run in, or the path patterns would lose their prefixes.
    for start in (event_cwd, os.getcwd()):
        if start:
            folder = Path(start).resolve()
            for candidate in (folder, *folder.parents):
                if (candidate / ".git").exists():
                    return candidate
    return Path(os.getcwd()).resolve()


def relative(path: str, root: Path) -> str:
    """Path relative to the project root, as POSIX; unchanged when it lies outside.

    A relative path is taken as relative to the project root, not to the hook
    process's working directory (Cursor and Copilot may pass relative paths).
    """
    try:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = root / candidate
        return candidate.resolve().relative_to(root).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix()


# Template suffixes that are safe to read and commit (keep in sync with the policy
# allowed_paths and .gitignore; tests/test_review2_regressions.py enforces it).
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
  | (?:^|/)\.agent-guardrails/
  | (?:^|/)\.cursor/
  | (?:^|/)\.cursorrules$
  | (?:^|/)\.github/(?:hooks|skills|copilot|instructions|agents|prompts)/
  | (?:^|/)\.github/copilot-instructions\.md$
  | (?:^|/)\.copilot/
  | (?:^|/)\.vscode/(?:mcp|settings)\.json$
  | (?:^|/)AGENTS\.md$
    """
)
# The lines from .agent-guardrails/ on are additions for Cursor and Copilot: their
# hooks, MCP servers, rules, skills, agent instructions and settings (where auto-approval
# and hook switches live) need the same protection as .claude/, .mcp.json and CLAUDE.md.

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


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def audit_dir(root: Path) -> Path:
    override = os.environ.get("AGENT_GUARDRAILS_AUDIT_DIR") or os.environ.get("CLAUDE_GUARDRAIL_AUDIT_DIR")
    return Path(override) if override else root / ".agent-guardrails" / "audit"


def audit(host: str, guard: str, root: Path, meta: Dict[str, Any], decision: str, rules: Iterable[str], extra: Optional[Dict[str, Any]] = None) -> None:
    """Append a metadata-only record to <project>/.agent-guardrails/audit/guardrail-events.jsonl.

    Never records prompt text, file content or full commands, only rule names and
    short fingerprints. The directory ignores itself in git. Set
    AGENT_GUARDRAILS_AUDIT=0 (or CLAUDE_GUARDRAIL_AUDIT=0) to disable.
    """
    if "0" in (os.environ.get("AGENT_GUARDRAILS_AUDIT"), os.environ.get("CLAUDE_GUARDRAIL_AUDIT")):
        return
    record = {
        "@timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "host": host,
        "hook": guard,
        "session_id": meta.get("session_id"),
        "event": meta.get("event"),
        "tool": meta.get("tool"),
        "permission_mode": meta.get("permission_mode"),
        "decision": decision,
        "rules": sorted(set(rules)),
        "user": os.environ.get("USER") or os.environ.get("USERNAME"),
    }
    if extra:
        record.update(extra)
    try:
        target = audit_dir(root)
        target.mkdir(parents=True, exist_ok=True)
        ignore = target / ".gitignore"
        if not ignore.exists():
            ignore.write_text("*\n", encoding="utf-8")
        with open(target / "guardrail-events.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        pass  # auditing must never break the developer's session
