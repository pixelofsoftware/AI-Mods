"""Plugin, skill, templates and installer."""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404
import sys

import pytest

from conftest import ROOT, run


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_plugin_manifest_and_marketplace():
    plugin = load(".claude-plugin/plugin.json")
    market = load(".claude-plugin/marketplace.json")
    assert plugin["name"] == "agent-guardrails" and re.fullmatch(r"\d+\.\d+\.\d+", plugin["version"])
    assert market["plugins"][0]["name"] == plugin["name"] and market["plugins"][0]["source"] == "./"


def test_repository_root_marketplace_points_at_this_plugin():
    from conftest import REPO

    root = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    package = load(".claude-plugin/marketplace.json")
    entry = root["plugins"][0]
    assert root["name"] == package["name"] and entry["name"] == load(".claude-plugin/plugin.json")["name"]
    assert (REPO / entry["source"]).resolve() == ROOT


def test_plugin_hooks_cover_all_guards():
    hooks = load("hooks/hooks.json")["hooks"]
    commands = json.dumps(hooks)
    for guard in ("prompt", "bash", "file", "read"):
        assert f'hook.py\\" claude {guard}' in commands
    matchers = {g["matcher"] for g in hooks["PreToolUse"]}
    assert matchers == {"Bash|Monitor", "Write|Edit|MultiEdit|NotebookEdit", "Read|Grep|Glob|NotebookRead"}
    assert "${CLAUDE_PLUGIN_ROOT}" in commands


@pytest.mark.skipif(shutil.which("claude") is None, reason="claude CLI not installed")
def test_claude_plugin_validate():
    proc = subprocess.run(["claude", "plugin", "validate", str(ROOT)], capture_output=True, text=True, timeout=120)  # nosec B603 B607
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_skill_frontmatter():
    text = (ROOT / "skills/agent-guardrails/SKILL.md").read_text(encoding="utf-8")
    match = re.match(r"---\nname: ([a-z0-9-]+)\ndescription: (.+?)\n---\n", text, re.S)
    assert match and match.group(1) == "agent-guardrails" and 50 < len(match.group(2)) <= 1024


def test_skill_scan_script_finds_engine(fake):
    out, code = run([str(ROOT / "skills/agent-guardrails/scripts/scan.py"), f"key {fake.anthropic_key}"], "")
    assert code == 2 and fake.anthropic_key not in out and "[REDACTED:API_KEY_1]" in out


def test_templates_never_add_allow_rules():
    claude = load("templates/claude-code/settings.json")
    assert "allow" not in claude["permissions"] and claude["permissions"]["disableBypassPermissionsMode"] == "disable"
    cursor = load("templates/cursor/hooks.json")["hooks"]
    assert all(e.get("failClosed") for event in ("beforeShellExecution", "beforeReadFile", "preToolUse") for e in cursor[event])


def test_install_all_targets(tmp_path, fake):
    project = tmp_path / "repo"
    (project / ".claude").mkdir(parents=True)
    existing = {"permissions": {"allow": ["Bash(make test)"], "deny": ["Bash(curl *)"]}, "model": "x"}
    (project / ".claude/settings.json").write_text(json.dumps(existing))
    for _ in range(2):  # idempotent
        out, code = run([str(ROOT / "install.py"), "--target", "all", "--project", str(project)], "")
        assert code == 0, out
    settings = json.loads((project / ".claude/settings.json").read_text())
    assert settings["permissions"]["allow"] == ["Bash(make test)"] and settings["model"] == "x"
    assert settings["permissions"]["deny"].count("Bash(curl *)") == 1
    assert all(len(groups) == len(load("templates/claude-code/settings.json")["hooks"][event]) for event, groups in settings["hooks"].items())
    cursor = json.loads((project / ".cursor/hooks.json").read_text())
    assert all(len(v) == 1 for v in cursor["hooks"].values())
    assert (project / ".github/hooks/agent-guardrails.json").is_file()
    for skills in (".claude/skills", ".cursor/skills", ".github/skills"):
        assert (project / skills / "agent-guardrails/SKILL.md").is_file()
    # The installed runtime works from the project, without this source tree.
    env = {"PATH": "/usr/bin:/bin", "AGENT_GUARDRAILS_AUDIT": "0"}
    proc = subprocess.run([sys.executable, ".agent-guardrails/hook.py", "cursor", "bash"], input='{"command": "cat .env"}',  # nosec B603
                          capture_output=True, text=True, cwd=project, env=env, timeout=60)
    assert json.loads(proc.stdout)["permission"] == "deny"


def test_install_dry_run_changes_nothing(tmp_path):
    out, code = run([str(ROOT / "install.py"), "--target", "copilot", "--project", str(tmp_path), "--dry-run"], "")
    assert code == 0 and "Planned changes" in out and list(tmp_path.iterdir()) == []


def test_audit_is_metadata_only_and_self_ignoring(tmp_path, fake):
    from conftest import BASE_ENV, hook

    env = dict(BASE_ENV, AGENT_GUARDRAILS_AUDIT="1", CLAUDE_GUARDRAIL_AUDIT="1", AGENT_GUARDRAILS_AUDIT_DIR=str(tmp_path / "audit"))
    hook("cursor", "prompt", {"prompt": f"key {fake.anthropic_key}", "conversation_id": "c1"}, env=env)
    hook("copilot", "tool", {"toolName": "bash", "toolArgs": {"command": "cat .env"}}, env=env)
    lines = (tmp_path / "audit/guardrail-events.jsonl").read_text().splitlines()
    records = [json.loads(line) for line in lines]
    assert {r["host"] for r in records} == {"cursor", "copilot"}
    assert fake.anthropic_key not in "".join(lines) and "cat .env" not in "".join(lines)
    assert (tmp_path / "audit/.gitignore").read_text() == "*\n"
