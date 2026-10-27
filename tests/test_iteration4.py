"""Iteration 4: the three UAT FAILs in .sdlc/claude-guardrails/test-3.md."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

import claude_safeguard as cs
from conftest import HOOKS


def bash(hook, command):
    out = hook("bash_guard.py", {"tool_name": "Bash", "tool_input": {"command": command}})
    return out.get("hookSpecificOutput", {}).get("permissionDecision", "none")


# --------------------------------------------------------------------------- #
# AC-5: history rewrites ask at hook level, including wrapped forms
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "command",
    [
        "git rebase -i HEAD~3",
        "git rebase main",
        "git -C . rebase main",
        "bash -c 'git rebase origin/main'",
        "git commit --amend --no-edit",
    ],
)
def test_history_rewrites_ask(hook, command):
    assert bash(hook, command) == "ask"


def test_plain_commit_and_pull_stay_silent(hook):
    assert bash(hook, "git commit -m 'feat: x'") == "none"
    assert bash(hook, "git pull origin main") == "none"


# --------------------------------------------------------------------------- #
# AC-9: card-shaped digit runs are not phone numbers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("text", ["4242 4242 4242 4242", "test card 4111 1111 1111 1111 ok", "ref 4111 1111 1111 1112", "5555-5555-5555-4444"])
def test_card_shaped_runs_are_not_phones(text):
    assert not [f for f in cs.Redactor().scan(text) if f.category == "PHONE"]


@pytest.mark.parametrize("text", ["call +1 415-555-0134", "office 415 555 0134 today", "+48 601 234 567", "(030) 1234 5678"])
def test_real_phone_numbers_still_redacted(text):
    assert [f.category for f in cs.Redactor().scan(text)] == ["PHONE"]


def test_luhn_valid_spaced_card_still_detected(fake):
    assert [f.category for f in cs.Redactor().scan(f"card {fake.card}")] == ["CARD_NUMBER"]


# --------------------------------------------------------------------------- #
# AC-14: import-time failures fail closed
# --------------------------------------------------------------------------- #


@pytest.fixture(params=["missing", "broken"])
def broken_install(tmp_path, request):
    """A repo copy where scripts/claude_safeguard.py is missing or does not import."""
    hooks = tmp_path / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    for f in HOOKS.glob("*.py"):
        shutil.copy(f, hooks / f.name)
    if request.param == "broken":
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "claude_safeguard.py").write_text("def broken(:\n")
    return hooks


def _run(hooks, name, event):
    proc = subprocess.run(
        [sys.executable, str(hooks / name)], input=json.dumps(event), capture_output=True, text=True, timeout=30,
        env={**os.environ, "CLAUDE_GUARDRAIL_AUDIT": "0"},
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.parametrize(
    "name,event",
    [
        ("bash_guard.py", {"tool_name": "Bash", "tool_input": {"command": "git status"}}),
        ("file_guard.py", {"tool_name": "Write", "tool_input": {"file_path": "a.py", "content": "x"}}),
        ("read_guard.py", {"tool_name": "Read", "tool_input": {"file_path": "a.py"}}),
    ],
)
def test_tool_guards_ask_when_rules_cannot_load(broken_install, name, event):
    out = _run(broken_install, name, event)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "could not load its rules" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_prompt_guard_warns_when_rules_cannot_load(broken_install):
    out = _run(broken_install, "prompt_guard.py", {"prompt": "hello"})
    assert "NOT being checked" in out["systemMessage"] and "decision" not in out
