#!/usr/bin/env python3
"""PreToolUse hook for Read / Grep / Glob.

Read-only tools need no approval inside the workspace, so a `Read(...)` deny list
that enumerates names (`.env`, `.env.local`, ...) always misses a variant
(`.env.prod`, `.envrc`, `kubeconfig-staging`). This hook applies the same secret-path
pattern the Bash and file guards use, so every variant is denied in one place.
`.env.example` / `.sample` / `.template` stay readable.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guard_common import audit, looks_secret, pre_tool_decision, read_event  # noqa: E402

READ_TOOLS = {"Read", "Grep", "Glob", "NotebookRead"}


def targets(tool_name: str, tool_input: dict) -> list:
    keys = ["file_path", "notebook_path", "path", "glob"]  # "glob" is Grep's file filter
    if tool_name == "Glob":
        keys.append("pattern")  # for Glob the pattern is a path; for Grep it is a regex
    return [tool_input[k] for k in keys if isinstance(tool_input.get(k), str) and tool_input[k]]


def main() -> None:
    event = read_event()
    if event.get("tool_name") not in READ_TOOLS:
        return
    tool_input = event.get("tool_input") or {}
    for target in targets(event["tool_name"], tool_input):
        if looks_secret(target):
            audit("read_guard", event, "deny", ["secret_file_read"], {"target": os.path.basename(target)})
            pre_tool_decision(
                "deny",
                f"reading `{os.path.basename(target) or target}` is blocked: it may contain secrets. "
                "Use the matching .example file, or ask the developer for the non-secret value you need.",
            )


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # fail closed
        pre_tool_decision("ask", f"read_guard error ({type(exc).__name__}); manual review required")
