"""GitHub Copilot adapter (Copilot CLI, VS Code agent hooks, Copilot cloud agent).

Events used (https://docs.github.com/en/copilot/reference/hooks-reference):
  preToolUse            -> tool    permissionDecision allow | deny | ask
                           bash/powershell -> shell guard; view/grep/rg/glob -> read guard;
                           create/edit/str_replace_editor/apply_patch -> file guard
  userPromptTransformed -> prompt  modifiedTransformedPrompt (redaction)

Copilot ignores the output of prompt-submission hooks, so a prompt cannot be
blocked. Instead the prompt guard rewrites the model-facing text with the blocked
values redacted. In the cloud agent "ask" is treated as "deny" by Copilot itself.
"""

from __future__ import annotations

from typing import Any, Dict, List

from guardrails_core import evaluate_prompt, evaluate_read, evaluate_shell, evaluate_write
from guardrails_core.common import audit, fingerprint, project_dir
from guardrails_core.shell import evaluate_powershell
from guardrails_core.verdict import Verdict

from . import as_object, emit, first_path, joined_content, patch_files, read_event

HOST = "copilot"
SHELL_TOOLS = {"bash", "powershell", "Bash"}
READ_TOOLS = {"view", "grep", "rg", "glob", "Read", "Grep", "Glob"}
WRITE_TOOLS = {"create", "edit", "str_replace_editor", "apply_patch", "Write", "Edit"}
REDACTION_NOTE = "[AI guardrail: sensitive values in this message were redacted before it reached the model]\n\n"


def _fields(event: Dict[str, Any]):
    """Accept both the camelCase payload and the snake_case (PascalCase event) one."""
    name = event.get("toolName") or event.get("tool_name") or ""
    args = as_object(event.get("toolArgs") if "toolArgs" in event else event.get("tool_input"))
    return name, args


def _meta(event: Dict[str, Any], name: str = "") -> Dict[str, Any]:
    return {"session_id": event.get("sessionId") or event.get("session_id"), "event": event.get("hook_event_name") or "preToolUse", "tool": name or None, "permission_mode": None}


def _answer(event: Dict[str, Any], guard: str, name: str, verdict: Verdict, extra: Dict[str, Any] = None) -> None:
    if not verdict.decision:
        emit({})
        return
    audit(HOST, guard, project_dir(event.get("cwd")), _meta(event, name), verdict.decision, verdict.rules, dict(verdict.audit, **(extra or {})))
    emit({"permissionDecision": verdict.decision, "permissionDecisionReason": f"[AI guardrail] {verdict.reason}"})


def _worst(verdicts: List[Verdict]) -> Verdict:
    for level in ("deny", "ask"):
        for verdict in verdicts:
            if verdict.decision == level:
                return verdict
    return Verdict()


def tool(event: Dict[str, Any]) -> None:
    name, args = _fields(event)
    root = project_dir(event.get("cwd"))
    if name in SHELL_TOOLS:
        command = args.get("command") if isinstance(args.get("command"), str) else ""
        evaluate = evaluate_powershell if name == "powershell" else evaluate_shell
        _answer(event, "bash_guard", name, evaluate(command), {"command_fp": fingerprint(command)})
    elif name in READ_TOOLS or (name == "str_replace_editor" and args.get("command") == "view"):
        keys = ["path", "file_path", "glob"] + (["pattern"] if name in {"glob", "Glob"} else [])
        targets = [args[k] for k in keys if isinstance(args.get(k), str) and args[k]]
        _answer(event, "read_guard", name, evaluate_read(targets))
    elif name in WRITE_TOOLS:
        patch = next((args[k] for k in ("patch", "input") if isinstance(args.get(k), str)), "")
        if name == "apply_patch" or (patch and "*** " in patch):
            files = patch_files(patch)
            if not files:
                verdict = Verdict("ask", f"{name}: could not determine the files this patch changes; manual review required", ["unknown_target"])
            else:
                verdict = _worst([evaluate_write(path, content, root) for path, content in files.items()])
        else:
            path = first_path(args)
            if not path:
                verdict = Verdict("ask", f"{name}: could not determine the target file; manual review required", ["unknown_target"])
            else:
                verdict = evaluate_write(path, joined_content(args), root)
        _answer(event, "file_guard", name, verdict)
    else:
        emit({})


def prompt(event: Dict[str, Any]) -> None:
    text = event.get("transformedPrompt") or event.get("prompt") or ""
    verdict = evaluate_prompt(text)
    root = project_dir(event.get("cwd"))
    for decision, rules, extra in verdict.audits:
        audit(HOST, "prompt_guard", root, _meta(event), "redact" if decision == "block" else decision, rules, extra)
    if verdict.blocked and verdict.redacted != text:
        emit({"modifiedTransformedPrompt": REDACTION_NOTE + verdict.redacted})
    else:
        emit({})


GUARDS = {"tool": tool, "bash": tool, "file": tool, "read": tool, "prompt": prompt}


def run(guard: str) -> None:
    try:
        GUARDS[guard](read_event())
    except Exception as exc:
        if guard == "prompt":
            emit({})
        else:  # fail closed
            emit({"permissionDecision": "ask", "permissionDecisionReason": f"[AI guardrail] {guard}_guard error ({type(exc).__name__}); manual review required"})
