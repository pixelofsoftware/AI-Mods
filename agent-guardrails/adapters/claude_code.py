"""Claude Code adapter.

Produces exactly the output of the original hooks in .claude/hooks/, so the
plugin and a project install behave the same as this repository's own setup.
tests/test_parity_claude.py checks that, case by case.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from guardrails_core import evaluate_prompt, evaluate_read, evaluate_shell, evaluate_write
from guardrails_core.common import audit, fingerprint, project_dir

from . import emit, read_event

HOST = "claude-code"
SHELL_TOOLS = {"Bash", "Monitor"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
READ_TOOLS = {"Read", "Grep", "Glob", "NotebookRead"}


def _meta(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "session_id": event.get("session_id"),
        "event": event.get("hook_event_name"),
        "tool": event.get("tool_name"),
        "permission_mode": event.get("permission_mode"),
    }


def _decide(decision: str, reason: str) -> None:
    emit({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": f"[AI guardrail] {reason}"}})


def _new_content(tool_input: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in ("content", "new_string", "new_source"):
        if isinstance(tool_input.get(key), str):
            parts.append(tool_input[key])
    for edit in tool_input.get("edits") or []:
        if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
            parts.append(edit["new_string"])
    return "\n".join(parts)


def _read_targets(tool_name: str, tool_input: Dict[str, Any]) -> list:
    keys = ["file_path", "notebook_path", "path", "glob"]  # "glob" is Grep's file filter
    if tool_name == "Glob":
        keys.append("pattern")  # for Glob the pattern is a path; for Grep it is a regex
    return [tool_input[k] for k in keys if isinstance(tool_input.get(k), str) and tool_input[k]]


def bash(event: Dict[str, Any]) -> None:
    if event.get("tool_name") not in SHELL_TOOLS:
        return
    command = (event.get("tool_input") or {}).get("command") or ""
    verdict = evaluate_shell(command)
    if verdict.decision:
        root = project_dir(event.get("cwd"))
        audit(HOST, "bash_guard", root, _meta(event), verdict.decision, verdict.rules, {"command_fp": fingerprint(command)})
        _decide(verdict.decision, verdict.reason)


def file(event: Dict[str, Any]) -> None:
    if event.get("tool_name") not in WRITE_TOOLS:
        return
    tool_input = event.get("tool_input") or {}
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    root = project_dir(event.get("cwd"))
    verdict = evaluate_write(path, _new_content(tool_input), root)
    if verdict.decision:
        audit(HOST, "file_guard", root, _meta(event), verdict.decision, verdict.rules, verdict.audit)
        _decide(verdict.decision, verdict.reason)


def read(event: Dict[str, Any]) -> None:
    if event.get("tool_name") not in READ_TOOLS:
        return
    verdict = evaluate_read(_read_targets(event["tool_name"], event.get("tool_input") or {}))
    if verdict.decision:
        audit(HOST, "read_guard", project_dir(event.get("cwd")), _meta(event), verdict.decision, verdict.rules, verdict.audit)
        _decide(verdict.decision, verdict.reason)


def prompt(event: Dict[str, Any]) -> None:
    verdict = evaluate_prompt(event.get("prompt") or "")
    root = project_dir(event.get("cwd"))
    for decision, rules, extra in verdict.audits:
        audit(HOST, "prompt_guard", root, _meta(event), decision, rules, extra)
    if verdict.blocked:
        emit({"decision": "block", "reason": verdict.reason})
    elif verdict.notes:
        emit(
            {
                "systemMessage": "[AI guardrail] " + " ".join(verdict.notes),
                "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": verdict.context},
            }
        )


GUARDS = {"bash": bash, "file": file, "read": read, "prompt": prompt}


def run(guard: str) -> None:
    try:
        handler = GUARDS[guard]
        handler(read_event())
    except Exception as exc:
        if guard == "prompt":  # never lose the developer's prompt to a hook bug; report instead
            print(json.dumps({"systemMessage": f"[AI guardrail] prompt_guard error: {type(exc).__name__}"}))
        else:  # fail closed: a crashing guard must not silently allow
            _decide("ask", f"{guard}_guard error ({type(exc).__name__}); manual review required")
