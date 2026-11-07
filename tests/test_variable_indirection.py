"""Bash guard: a secret path passed through a shell variable is caught like a literal one.

Before this fix `f=.env; cat $f` got no decision from the guard, because arguments
were compared as written and `$f` never looks like `.env`.
"""

from __future__ import annotations

import pytest


def bash(hook, command):
    out = hook("bash_guard.py", {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}})
    return out.get("hookSpecificOutput", {}).get("permissionDecision", "none"), out


RESOLVED_TO_SECRET = [
    "f=.env; cat $f",
    'F=.env && cat "$F"',
    "export F=.env; cat \"$F\"",
    "f=.env.production cat $f",
    "cat ${F:-.env}",
    "cat ${F-.env}",
    "a=.e; b=nv; cat $a$b",
    "for f in .env; do cat $f; done",
    "arr=(.env x); cat ${arr[0]}",
    "cat $HOME/.ssh/id_rsa",
    "cat ${HOME}/.aws/credentials",
    "k=~/.ssh/id_ed25519; base64 $k",
    'cat "$DIR/.env"',
    "cat $(echo .env)",
    'f=.env; bash -c "cat $f"',
    "f=.env; echo $(cat $f)",
    "f=.env; cp $f /tmp/x",
    "f=.env; grep KEY $f",
    "f=.env; cat < $f",
    "cat ${x:-${y:-.env}}",
    "cat ${a:-${b:-${c:-~/.ssh/id_rsa}}}",
    "f=.env; g=$f; cat $g",
]


@pytest.mark.parametrize("command", RESOLVED_TO_SECRET)
def test_secret_path_through_variable_is_denied(hook, command):
    decision, out = bash(hook, command)
    assert decision == "deny", command
    assert "secret material" in out["hookSpecificOutput"]["permissionDecisionReason"]


UNRESOLVABLE_READS = [
    "read f <<< .env; cat $f",
    "cat $1",
    "cp $SRC /tmp/x",
    "source $ENVFILE",
    "head -n 5 ${FILE}",
]


@pytest.mark.parametrize("command", UNRESOLVABLE_READS)
def test_reader_with_unresolvable_variable_asks(hook, command):
    decision, out = bash(hook, command)
    assert decision == "ask", command
    assert "cannot resolve" in out["hookSpecificOutput"]["permissionDecisionReason"]


EVERYDAY = [
    "echo $PATH",
    "cd $HOME/project",
    "ls $DIR",
    "f=README.md; cat $f",
    "cat $PWD/README.md",
    "f=.env.example; cat $f",
    "for f in src/*.py; do wc -l $f; done",
    "export NODE_ENV=test; npm test",
    "npm run build -- --env=$NODE_ENV",
    "python3 -m pytest $ARGS",
    'git commit -m "$MSG"',
    "docker build -t app:$TAG .",
    "mkdir -p $OUT/dist",
    "ruff check $(git diff --name-only)",
]


@pytest.mark.parametrize("command", EVERYDAY)
def test_everyday_variables_are_not_flagged(hook, command):
    decision, _ = bash(hook, command)
    assert decision == "none", command
