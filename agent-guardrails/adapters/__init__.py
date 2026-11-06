"""Host adapters: translate each host's hook events to and from the engine."""

from __future__ import annotations

import importlib
import json
import sys
from typing import Any, Dict

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


PATH_KEYS = ("file_path", "path", "filePath", "target_file", "notebook_path", "filename")
CONTENT_KEYS = ("content", "contents", "file_text", "new_string", "new_str", "newString", "new_source", "code_edit", "insert_text", "text")


def first_path(args: Dict[str, Any]) -> str:
    for key in PATH_KEYS:
        if isinstance(args.get(key), str) and args[key]:
            return args[key]
    return ""


def joined_content(args: Dict[str, Any]) -> str:
    """Every new-content field a write tool may carry, joined, so nothing escapes the scan."""
    parts = [args[key] for key in CONTENT_KEYS if isinstance(args.get(key), str)]
    for edit in args.get("edits") or []:
        if isinstance(edit, dict):
            parts += [edit[key] for key in CONTENT_KEYS if isinstance(edit.get(key), str)]
    return "\n".join(parts)


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
