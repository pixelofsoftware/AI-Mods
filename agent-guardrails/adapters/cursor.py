"""Cursor adapter (native .cursor/hooks.json events).

Events used (https://cursor.com/docs/hooks):
  beforeShellExecution -> bash   permission allow | deny | ask
  beforeReadFile       -> read   permission allow | deny
  preToolUse           -> tool   permission allow | deny  (Write, Delete, Grep)
  beforeSubmitPrompt   -> prompt continue true | false

Where Cursor cannot ask a human (beforeReadFile, preToolUse), "ask" becomes "deny"
by default, because a guard that wants a human must not be skipped.
AGENT_GUARDRAILS_CURSOR_ASK=allow lets those actions through instead (audited).
Cursor cannot show non-blocking prompt notices, so personal-data and injection
notes are audited only.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from guardrails_core import evaluate_prompt, evaluate_read, evaluate_shell, evaluate_write
from guardrails_core.common import audit, fingerprint, project_dir
from guardrails_core.shell import evaluate_powershell
from guardrails_core.verdict import Verdict

from . import as_object, emit, first_path, joined_content, read_event

HOST = "cursor"
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "Delete"}
READ_TOOLS = {"Read", "Grep", "Glob"}


def _root(event: Dict[str, Any]):
    roots = event.get("workspace_roots") or []
    return project_dir(event.get("cwd") or (roots[0] if roots and isinstance(roots[0], str) else None))


def _meta(event: Dict[str, Any]) -> Dict[str, Any]:
    return {"session_id": event.get("conversation_id"), "event": event.get("hook_event_name"), "tool": event.get("tool_name"), "permission_mode": None}


def _message(reason: str) -> Dict[str, str]:
    text = f"[AI guardrail] {reason}"
    return {"user_message": text, "agent_message": text}


def _no_ask(decision: Optional[str]) -> Optional[str]:
    """Map "ask" for events where Cursor cannot ask a human."""
    if decision != "ask":
        return decision
    return "allow" if os.environ.get("AGENT_GUARDRAILS_CURSOR_ASK") == "allow" else "deny"


def _answer(event: Dict[str, Any], guard: str, verdict: Verdict, can_ask: bool, extra: Optional[Dict[str, Any]] = None) -> None:
    if not verdict.decision:
        emit({"permission": "allow"})
        return
    decision = verdict.decision if can_ask else _no_ask(verdict.decision)
    record = dict(verdict.audit, **(extra or {}))
    if decision != verdict.decision:
        record["mapped_from"] = verdict.decision
    audit(HOST, guard, _root(event), _meta(event), decision, verdict.rules, record)
    if decision == "allow":
        emit({"permission": "allow"})
        return
    reason = verdict.reason
    if verdict.decision == "ask" and decision == "deny":
        reason += " (needs human review; Cursor cannot ask here, so make or approve this change yourself)"
    emit(dict({"permission": decision}, **_message(reason)))


def bash(event: Dict[str, Any]) -> None:
    command = event.get("command") or ""
    # On Windows Cursor runs terminal commands in PowerShell.
    evaluate = evaluate_powershell if os.name == "nt" else evaluate_shell
    _answer(event, "bash_guard", evaluate(command), can_ask=True, extra={"command_fp": fingerprint(command)})


def read(event: Dict[str, Any]) -> None:
    path = event.get("file_path") or ""
    _answer(event, "read_guard", evaluate_read([path] if path else []), can_ask=False)


def tool(event: Dict[str, Any]) -> None:
    name = event.get("tool_name") or ""
    args = as_object(event.get("tool_input"))
    if name in WRITE_TOOLS:
        path = first_path(args)
        if not path:
            verdict = Verdict("ask", f"{name}: could not determine the target file; manual review required", ["unknown_target"])
        else:
            verdict = evaluate_write(path, joined_content(args), _root(event))
        _answer(event, "file_guard", verdict, can_ask=False)
    elif name in READ_TOOLS:
        targets = [args[k] for k in ("path", "file_path", "glob", "target_directory", "include", "pattern") if isinstance(args.get(k), str) and args[k]]
        if name == "Grep":  # for Grep the pattern is a regex, not a path
            targets = [args[k] for k in ("path", "file_path", "glob", "target_directory", "include") if isinstance(args.get(k), str) and args[k]]
        _answer(event, "read_guard", evaluate_read(targets), can_ask=False)
    else:
        emit({"permission": "allow"})


def prompt(event: Dict[str, Any]) -> None:
    verdict = evaluate_prompt(event.get("prompt") or "")
    root = _root(event)
    for decision, rules, extra in verdict.audits:
        audit(HOST, "prompt_guard", root, _meta(event), decision, rules, extra)
    if verdict.blocked:
        emit({"continue": False, "user_message": verdict.reason})
    else:
        emit({"continue": True})


GUARDS = {"bash": bash, "read": read, "tool": tool, "file": tool, "prompt": prompt}


def run(guard: str) -> None:
    try:
        GUARDS[guard](read_event())
    except Exception as exc:
        reason = f"[AI guardrail] {guard}_guard error ({type(exc).__name__}); manual review required"
        if guard == "prompt":  # never lose the prompt to a hook bug (same as Claude Code)
            emit({"continue": True})
        else:  # fail closed: ask where Cursor can ask, deny where it cannot
            emit({"permission": "ask" if guard == "bash" else "deny", "user_message": reason, "agent_message": reason})
