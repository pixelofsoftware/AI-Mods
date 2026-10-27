#!/usr/bin/env python3
"""Pre-commit / CI checks specific to AI-assisted development.

Subcommands:
  forbid-paths FILE...     fail if a staged path is a Claude session log, local
                           config, MCP override, key or secrets file
  validate-config          fail if .claude/settings.json or .mcp.json drift from
                           config/claude-guardrails-policy.json (guardrail tamper check)
  scan-secrets FILE...     fail if a file contains a credential (same detectors as the
                           Claude Code hooks and the API wrapper)

Exit codes: 0 ok, 1 policy violation, 2 usage/internal error.
Stdlib only, so it runs in pre-commit, CI and on a bare workstation.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from claude_safeguard import CREDENTIAL_CATEGORIES, Redactor, Severity  # noqa: E402

POLICY_REL = "config/claude-guardrails-policy.json"
MAX_SCAN_BYTES = 2_000_000


def load_policy(root: Path) -> Dict[str, Any]:
    return json.loads((root / POLICY_REL).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# forbid-paths
# --------------------------------------------------------------------------- #


def _matches(path: str, pattern: str) -> bool:
    """gitignore-like: a pattern without '/' matches the basename at any depth."""
    p = PurePosixPath(path)
    if "/" not in pattern.rstrip("/*"):
        return fnmatch.fnmatchcase(p.name, pattern)
    if pattern.startswith("**/"):
        pattern = pattern[3:]
    return fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(path, "*/" + pattern)


def forbidden(paths: Iterable[str], policy: Dict[str, Any]) -> List[str]:
    bad = []
    for raw in paths:
        path = raw.replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        if any(_matches(path, a) for a in policy.get("allowed_paths", [])):
            continue
        if any(_matches(path, f) for f in policy.get("forbidden_paths", [])):
            bad.append(path)
    return bad


def cmd_forbid_paths(args: argparse.Namespace) -> int:
    policy = load_policy(REPO_ROOT)
    bad = forbidden(args.files, policy)
    if not bad:
        return 0
    print("Blocked: these files must not be committed (AI session data, local config or secrets):")
    for b in bad:
        print(f"  - {b}")
    print("\nUnstage with `git restore --staged <file>` and make sure it is in .gitignore.")
    print("If a secret was ever committed or pasted into a prompt, rotate it.")
    return 1


# --------------------------------------------------------------------------- #
# validate-config
# --------------------------------------------------------------------------- #


def _get(d: Dict[str, Any], dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def url_allowed(url: str, patterns: Sequence[str]) -> bool:
    """Match scheme, host (with * wildcard) and path separately, so wildcards cannot cross '/'."""
    try:
        u = urlsplit(url)
    except ValueError:
        return False
    for pat in patterns:
        p = urlsplit(pat)
        if p.scheme != u.scheme:
            continue
        if not fnmatch.fnmatchcase((u.hostname or "").lower(), (p.hostname or "").lower()):
            continue
        if p.port is not None and p.port != u.port:
            continue
        if fnmatch.fnmatchcase(u.path or "/", p.path or "/*"):
            return True
    return False


def _has_literal(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != "" and "${" not in value


def check_settings(settings: Dict[str, Any], policy: Dict[str, Any]) -> List[str]:
    errors = []
    for key, expected in policy.get("required_settings", {}).items():
        actual = _get(settings, key)
        if actual != expected:
            errors.append(f".claude/settings.json: `{key}` must be {json.dumps(expected)} (found {json.dumps(actual)})")

    perms = settings.get("permissions", {})
    mode = perms.get("defaultMode", "default")
    if mode in policy.get("forbidden_default_modes", []):
        errors.append(f".claude/settings.json: permissions.defaultMode `{mode}` is not allowed in shared project settings")

    deny, ask, allow = set(perms.get("deny", [])), set(perms.get("ask", [])), set(perms.get("allow", []))
    for rule in policy.get("required_deny_rules", []):
        if rule not in deny:
            errors.append(f".claude/settings.json: required deny rule missing: {rule}")
    for rule in policy.get("required_ask_rules", []):
        if rule not in ask and rule not in deny:
            errors.append(f".claude/settings.json: required ask rule missing: {rule}")
    for rule in policy.get("forbidden_allow_rules", []):
        if rule in allow:
            errors.append(f".claude/settings.json: forbidden allow rule: {rule}")
    for rule in allow:
        if rule.startswith("mcp__") and rule.split("__")[1] not in set(settings.get("enabledMcpjsonServers", [])):
            errors.append(f".claude/settings.json: allow rule for unapproved MCP server: {rule}")

    for event, scripts in policy.get("required_hooks", {}).items():
        event_blob = json.dumps(settings.get("hooks", {}).get(event, []))
        for script in scripts:
            if script not in event_blob:
                errors.append(f".claude/settings.json: required {event} hook missing: {script}")
    if settings.get("disableAllHooks") is True:
        errors.append(".claude/settings.json: disableAllHooks must not be true")
    if any(k.startswith("OTEL_") for k in settings.get("env", {})):
        # Not an error, but a common misconception worth flagging.
        print("note: OTEL_* exporter variables in .claude/settings.json are ignored by Claude Code; set them in managed settings.")
    return errors


def check_mcp(mcp: Dict[str, Any], settings: Dict[str, Any], policy: Dict[str, Any]) -> List[str]:
    errors = []
    servers = mcp.get("mcpServers", {})
    approved_urls = policy.get("approved_mcp_url_patterns", [])
    approved_cmds = [list(c) for c in policy.get("approved_mcp_commands", [])]
    for name, cfg in servers.items():
        stype = cfg.get("type", "stdio" if "command" in cfg else "http")
        if stype in {"http", "sse", "streamable-http"}:
            url = cfg.get("url", "")
            if not url_allowed(url, approved_urls):
                errors.append(f".mcp.json: server `{name}` url `{url}` is not on the approved list ({POLICY_REL})")
            for header, value in (cfg.get("headers") or {}).items():
                if _has_literal(value) and header.lower() in {"authorization", "x-api-key", "api-key", "cookie", "proxy-authorization"}:
                    errors.append(f".mcp.json: server `{name}` header `{header}` holds a literal credential; use ${{VAR}} expansion")
        else:
            cmd = [cfg.get("command", "")] + list(cfg.get("args", []))
            if cmd not in approved_cmds:
                errors.append(f".mcp.json: local (stdio) server `{name}` runs `{' '.join(cmd)}`, which is not an approved command")
        for key, value in (cfg.get("env") or {}).items():
            if _has_literal(value) and any(s in key.upper() for s in ("TOKEN", "SECRET", "KEY", "PASSWORD")):
                errors.append(f".mcp.json: server `{name}` env `{key}` holds a literal secret; use ${{VAR}} expansion")
    enabled = set(settings.get("enabledMcpjsonServers", []))
    for name in enabled - set(servers):
        errors.append(f".claude/settings.json: enabledMcpjsonServers lists `{name}`, which .mcp.json does not define")
    for name in set(servers) - enabled:
        errors.append(f".mcp.json: server `{name}` is not listed in enabledMcpjsonServers (unreviewed server)")
    return errors


def cmd_validate_config(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve() if args.root else REPO_ROOT
    try:
        policy = load_policy(root)
        settings_path = root / ".claude/settings.json"
        if not settings_path.exists():
            print(".claude/settings.json is missing: the project guardrails were removed")
            return 1
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        mcp_path = root / ".mcp.json"
        mcp = json.loads(mcp_path.read_text(encoding="utf-8")) if mcp_path.exists() else {"mcpServers": {}}
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read guardrail config: {exc}")
        return 1
    errors = check_settings(settings, policy) + check_mcp(mcp, settings, policy)
    if errors:
        print("AI guardrail configuration drift detected:")
        for e in errors:
            print(f"  - {e}")
        print(f"\nIf the change is intentional, update {POLICY_REL} in the same PR so security review sees it.")
        return 1
    return 0


# --------------------------------------------------------------------------- #
# scan-secrets
# --------------------------------------------------------------------------- #


def scan_file(path: Path, redactor: Optional[Redactor] = None) -> List[str]:
    redactor = redactor or Redactor()
    try:
        data = path.read_bytes()[:MAX_SCAN_BYTES]
    except OSError:
        return []
    if b"\x00" in data[:8192]:
        return []  # binary
    text = data.decode("utf-8", "replace")
    hits = []
    for f in redactor.scan(text):
        if f.category in CREDENTIAL_CATEGORIES and f.severity >= Severity.CRITICAL:
            line = text.count("\n", 0, f.start) + 1
            hits.append(f"{path}:{line}: {f.rule} ({f.category})")
    return hits


def cmd_scan_secrets(args: argparse.Namespace) -> int:
    hits: List[str] = []
    for name in args.files:
        hits += scan_file(Path(name))
    if not hits:
        return 0
    print("Possible hardcoded credentials (values not shown):")
    for h in hits:
        print(f"  - {h}")
    print("\nMove the value to an environment variable or the secret manager, and rotate it if it is real.")
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("forbid-paths")
    p.add_argument("files", nargs="*")
    p.set_defaults(func=cmd_forbid_paths)
    p = sub.add_parser("validate-config")
    p.add_argument("--root", help="repository root (default: this repository)")
    p.set_defaults(func=cmd_validate_config)
    p = sub.add_parser("scan-secrets")
    p.add_argument("files", nargs="*")
    p.set_defaults(func=cmd_scan_secrets)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # report, do not crash the commit with a traceback
        print(f"check_ai_guardrails internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
