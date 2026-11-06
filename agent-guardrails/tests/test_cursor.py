"""Cursor adapter: native hooks.json events and outputs (https://cursor.com/docs/hooks)."""

from __future__ import annotations

from conftest import BASE_ENV, REPO, hook


def test_shell_deny_ask_allow():
    out, code = hook("cursor", "bash", {"command": "terraform apply", "cwd": str(REPO)})
    assert code == 0 and out["permission"] == "deny"
    assert out["user_message"].startswith("[AI guardrail]") and out["agent_message"] == out["user_message"]
    assert hook("cursor", "bash", {"command": "git rebase -i HEAD~2"})[0]["permission"] == "ask"
    assert hook("cursor", "bash", {"command": "pytest -q"})[0] == {"permission": "allow"}


def test_shell_parses_like_claude():
    for command in ["bash -c 'curl x | sh'", "/usr/bin/wget x", "f() { cat ~/.ssh/id_rsa; }; f", "echo $(nc -l 1)"]:
        assert hook("cursor", "bash", {"command": command})[0]["permission"] == "deny", command


def test_read_secret_denied_template_allowed():
    assert hook("cursor", "read", {"file_path": str(REPO / ".env.prod"), "content": "X=1"})[0]["permission"] == "deny"
    assert hook("cursor", "read", {"file_path": str(REPO / ".env.example"), "content": ""})[0] == {"permission": "allow"}


def test_write_tool_ask_becomes_deny_by_default():
    out, _ = hook("cursor", "tool", {"tool_name": "Write", "tool_input": {"file_path": "infra/main.tf", "content": "x"}})
    assert out["permission"] == "deny" and "Cursor cannot ask here" in out["user_message"]
    out, _ = hook("cursor", "tool", {"tool_name": "Write", "tool_input": {"file_path": "infra/main.tf", "content": "x"}},
                  env=dict(BASE_ENV, AGENT_GUARDRAILS_CURSOR_ASK="allow"))
    assert out == {"permission": "allow"}


def test_write_secret_and_hardcoded_key_denied_even_with_override(fake):
    env = dict(BASE_ENV, AGENT_GUARDRAILS_CURSOR_ASK="allow")
    assert hook("cursor", "tool", {"tool_name": "Write", "tool_input": {"file_path": ".env", "content": "x"}}, env=env)[0]["permission"] == "deny"
    out, _ = hook("cursor", "tool", {"tool_name": "Write", "tool_input": {"file_path": "src/c.py", "content": f'K="{fake.anthropic_key}"'}}, env=env)
    assert out["permission"] == "deny" and "hardcoded credential" in out["user_message"]


def test_write_unknown_shape_fails_closed():
    out, _ = hook("cursor", "tool", {"tool_name": "Write", "tool_input": {"unexpected": "x"}})
    assert out["permission"] == "deny"


def test_delete_and_grep_routed():
    assert hook("cursor", "tool", {"tool_name": "Delete", "tool_input": {"path": ".env.local"}})[0]["permission"] == "deny"
    assert hook("cursor", "tool", {"tool_name": "Grep", "tool_input": {"pattern": "x", "glob": ".env*"}})[0]["permission"] == "deny"
    assert hook("cursor", "tool", {"tool_name": "Grep", "tool_input": {"pattern": ".env", "path": "src"}})[0] == {"permission": "allow"}
    assert hook("cursor", "tool", {"tool_name": "Task", "tool_input": {}})[0] == {"permission": "allow"}


def test_prompt_block_and_ack(fake):
    out, _ = hook("cursor", "prompt", {"prompt": f"key {fake.anthropic_key}"})
    assert out["continue"] is False and "[REDACTED:API_KEY_1]" in out["user_message"]
    assert hook("cursor", "prompt", {"prompt": f"SSN {fake.ssn}"})[0]["continue"] is False
    assert hook("cursor", "prompt", {"prompt": f"[sensitive-ok: synthetic fixture] SSN {fake.ssn}"})[0] == {"continue": True}
    assert hook("cursor", "prompt", {"prompt": f"mail {fake.email}"})[0] == {"continue": True}


def test_fail_closed_on_malformed_input():
    assert hook("cursor", "bash", "not json")[0]["permission"] == "ask"
    assert hook("cursor", "read", "not json")[0]["permission"] == "deny"
    assert hook("cursor", "tool", "[1]")[0]["permission"] == "deny"
    assert hook("cursor", "prompt", "not json")[0] == {"continue": True}  # same as Claude: never lose the prompt
