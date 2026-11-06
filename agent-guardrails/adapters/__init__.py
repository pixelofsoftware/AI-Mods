"""Host adapters: translate each host's hook events to and from the engine."""

from __future__ import annotations

import importlib
import json
import re
import sys
from typing import Any, Dict, List

HOSTS = {"claude": "claude_code", "cursor": "cursor", "copilot": "copilot"}


def load(host: str):
    if host not in HOSTS:
        raise ValueError(f"unknown host {host!r}; expected one of {sorted(HOSTS)}")
    return importlib.import_module(f"adapters.{HOSTS[host]}")


def read_event() -> Dict[str, Any]:
    """Parse the hook event. Malformed input raises, so the adapter's fail-closed path runs."""
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    event = json.loads(raw)
    if not isinstance(event, dict):
        raise ValueError("hook event is not a JSON object")
    return event


def emit(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload))


def as_object(value: Any) -> Dict[str, Any]:
    """Tool arguments arrive as an object or as a JSON string, depending on the host."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


PATH_KEYS = ("file_path", "path", "filePath", "target_file", "notebook_path", "filename", "new_path", "destination")
READ_KEYS = ("file_path", "path", "filePath", "notebook_path", "glob", "glob_pattern", "globPattern", "target_directory", "include", "paths")
PATCH_RE = re.compile(r"^(?:\*\*\* (?:Begin Patch|Add File:|Update File:|Delete File:|Move to:)|\+\+\+ |--- )", re.M)


def _strings_of(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [s for item in value for s in _strings_of(item)]
    return []


def all_paths(args: Dict[str, Any]) -> List[str]:
    """Every path a write may target, including nested edits. The agent writes the
    arguments, so checking only the first path field would let a decoy pass."""
    paths: List[str] = []
    for key, value in args.items():
        if key in PATH_KEYS:
            paths += _strings_of(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    paths += all_paths(item)
        elif isinstance(value, dict):
            paths += all_paths(value)
    return list(dict.fromkeys(paths))


def all_content(value: Any, key: str = "") -> List[str]:
    """Every string a write carries except paths and the text being replaced, so an
    unknown content field name can't skip the credential scan."""
    if isinstance(value, str):
        return [] if key in PATH_KEYS or key.lower().startswith("old") else [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in all_content(v, k)]
    if isinstance(value, list):
        return [s for item in value for s in all_content(item, key)]
    return []


def read_targets(args: Dict[str, Any], include_pattern: bool) -> List[str]:
    """Paths and globs a read or search tool will touch. For Glob the pattern is a
    path; for Grep it is a regex, so it is left out."""
    keys = READ_KEYS + (("pattern",) if include_pattern else ())
    return [t for key in keys for t in _strings_of(args.get(key))]


def worst(verdicts: List[Any]):
    from guardrails_core.verdict import Verdict

    for level in ("deny", "ask"):
        for verdict in verdicts:
            if verdict.decision == level:
                return verdict
    return Verdict()


def evaluate_write_args(name: str, args: Dict[str, Any], root):
    """Decide on a write tool call: every target path and every patch-like field is
    checked against all of the new content; the strictest verdict wins."""
    from guardrails_core import evaluate_write
    from guardrails_core.verdict import Verdict

    strings = all_content(args)
    content = "\n".join(strings)
    verdicts = [evaluate_write(path, content, root) for path in all_paths(args)]
    for text in strings:
        if PATCH_RE.search(text):
            for path, added in patch_files(text).items():
                verdicts.append(evaluate_write(path, added + "\n" + content, root))
    if not verdicts:
        return Verdict("ask", f"{name}: could not determine the target file; manual review required", ["unknown_target"])
    return worst(verdicts)


def patch_files(patch: str):
    """Paths and added lines of an apply_patch / unified-diff style payload."""
    files: Dict[str, list] = {}
    current = None
    for line in patch.splitlines():
        for marker in ("*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: ", "+++ b/", "+++ "):
            if line.startswith(marker):
                current = line[len(marker):].strip()
                if current and current != "/dev/null":
                    files.setdefault(current, [])
                break
        else:
            if current and line.startswith("+") and not line.startswith("+++"):
                files.setdefault(current, []).append(line[1:])
    return {path: "\n".join(lines) for path, lines in files.items()}
