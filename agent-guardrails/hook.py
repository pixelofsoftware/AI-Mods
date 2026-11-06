#!/usr/bin/env python3
"""Single hook entry point for every host.

    python3 hook.py <host> <guard>

host:  claude | cursor | copilot
guard: bash | file | read | prompt | tool   ("tool" routes a generic pre-tool event)

The host's hook configuration calls this script; it reads the event on stdin and
answers on stdout in that host's format. If the engine cannot even be loaded,
it still answers in a way that blocks or asks, never silently allows.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _load_failure(host: str, guard: str, exc: BaseException) -> None:
    """Fail closed without importing anything from the engine."""
    name = f"{guard}_guard"
    why = f"[AI guardrail] {name} could not load its rules ({type(exc).__name__}); manual review required"
    if host == "claude":
        if guard == "prompt":
            print(json.dumps({"systemMessage": f"[AI guardrail] {name} could not load its rules ({type(exc).__name__}); prompts are NOT being checked."}))
        else:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": why}}))
    elif host == "cursor":
        if guard == "prompt":
            print(json.dumps({"continue": True}))
        else:
            print(json.dumps({"permission": "ask" if guard == "bash" else "deny", "user_message": why, "agent_message": why}))
    elif host == "copilot":
        if guard != "prompt":
            print(json.dumps({"permissionDecision": "ask", "permissionDecisionReason": why}))
    else:
        print(why, file=sys.stderr)
        sys.exit(2)


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else ""
    guard = sys.argv[2] if len(sys.argv) > 2 else ""
    try:
        from adapters import load

        adapter = load(host)
    except Exception as exc:  # fail closed: a broken install must not allow
        _load_failure(host, guard, exc)
        return
    adapter.run(guard)


if __name__ == "__main__":
    main()
