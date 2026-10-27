"""AC-2, AC-3, AC-4, AC-8, AC-14: configuration files and the pre-commit validator."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
import yaml

from conftest import ROOT

SETTINGS = json.loads((ROOT / ".claude/settings.json").read_text())
MANAGED = json.loads((ROOT / "enterprise/managed-settings.json").read_text())
MCP = json.loads((ROOT / ".mcp.json").read_text())
VALIDATOR = ROOT / "scripts/precommit/check_ai_guardrails.py"
LITERAL_BEARER = "Bearer " + "abcdef1234567890" * 2  # built at runtime; see conftest docstring


def test_ac2_settings_allowlist_and_denials():
    perms = SETTINGS["permissions"]
    for rule in ["Bash(npm run test)", "Bash(git status)"]:
        assert rule in perms["allow"]
    for rule in ["WebSearch", "Bash(curl *)", "Bash(wget *)", "Read(**/.env)"]:
        assert rule in perms["deny"]
    assert "WebFetch" in perms["ask"]
    assert perms["disableBypassPermissionsMode"] == "disable"
    assert perms["defaultMode"] == "default"


def test_ac2_hooks_and_sandbox_wired():
    hooks = json.dumps(SETTINGS["hooks"])
    for name in ["prompt_guard.py", "bash_guard.py", "file_guard.py", "read_guard.py"]:
        assert name in hooks
        assert (ROOT / ".claude/hooks" / name).exists()
    assert SETTINGS["sandbox"]["enabled"] is True
    assert SETTINGS["sandbox"]["allowUnsandboxedCommands"] is False


def test_ac14_no_blanket_allow():
    allow = SETTINGS["permissions"]["allow"]
    for bad in ["Bash", "Bash(*)", "WebFetch", "WebFetch(domain:*)", "Bash(curl *)"]:
        assert bad not in allow
    assert not set(SETTINGS["permissions"]["allow"]) & set(SETTINGS["permissions"]["deny"])


def test_ac3_telemetry_in_managed_settings_not_repo():
    env = MANAGED["env"]
    assert env["CLAUDE_CODE_ENABLE_TELEMETRY"] == "1"
    assert env["OTEL_LOG_USER_PROMPTS"] == "1"
    assert env["OTEL_LOGS_EXPORTER"] == "otlp" and env["OTEL_METRICS_EXPORTER"] == "otlp"
    assert env["OTEL_EXPORTER_OTLP_ENDPOINT"].startswith("https://")
    # OTEL exporter vars are ignored in project settings, so they must not pretend to work there.
    assert not any(k.startswith("OTEL_") for k in SETTINGS.get("env", {}))


def test_ac4_mcp_only_internal_https_with_env_credentials():
    assert set(MCP["mcpServers"]) == set(SETTINGS["enabledMcpjsonServers"])
    for server in MCP["mcpServers"].values():
        assert server["url"].startswith("https://") and ".internal." in server["url"]
        for value in server.get("headers", {}).values():
            assert "${" in value
    assert SETTINGS["enableAllProjectMcpServers"] is False
    assert MANAGED["allowManagedMcpServersOnly"] is True
    assert all("serverUrl" in e for e in MANAGED["allowedMcpServers"])


def test_ac8_precommit_config_contents():
    cfg = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text())
    ids = {h["id"] for repo in cfg["repos"] for h in repo["hooks"]}
    for required in ["gitleaks", "detect-private-key", "bandit", "checkov", "forbid-ai-artifacts", "validate-claude-config", "scan-ai-secrets"]:
        assert required in ids, required
    for repo in cfg["repos"]:
        if repo["repo"] != "local":
            assert repo["rev"][0] in "v0123456789", repo


def run_validator(*args, cwd=ROOT):
    return subprocess.run([sys.executable, str(VALIDATOR), *args], cwd=cwd, capture_output=True, text=True, timeout=60)


@pytest.mark.parametrize(
    "path",
    [
        ".claude/settings.local.json",
        ".claude/audit/guardrail-events.jsonl",
        ".claude/projects/abc/session.jsonl",
        ".mcp.local.json",
        "CLAUDE.local.md",
        ".env",
        "config/.env.production",
        "certs/tls.key",
        "deploy/id_rsa",
        "infra/terraform.tfstate",
        "keys/service-account-prod.json",
    ],
)
def test_ac8_forbidden_paths_blocked(path):
    proc = run_validator("forbid-paths", path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert path in proc.stdout


@pytest.mark.parametrize("path", [".env.example", "src/app.py", ".claude/settings.json", "deploy/id_rsa.pub", "docs/claude-guardrails.md"])
def test_ac8_normal_paths_pass(path):
    proc = run_validator("forbid-paths", path)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_ac8_repo_config_validates():
    proc = run_validator("validate-config")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def _copy_repo_config(tmp_path):
    for rel in [".claude/settings.json", ".mcp.json", "config/claude-guardrails-policy.json"]:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text((ROOT / rel).read_text())
    return tmp_path


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (lambda s, m: s["permissions"]["deny"].remove("Bash(curl *)"), "Bash(curl *)"),
        (lambda s, m: s["permissions"].update(defaultMode="bypassPermissions"), "defaultMode"),
        (lambda s, m: s["permissions"]["allow"].append("Bash(*)"), "Bash(*)"),
        (lambda s, m: s.update(enableAllProjectMcpServers=True), "enableAllProjectMcpServers"),
        (lambda s, m: s["hooks"].pop("UserPromptSubmit"), "prompt_guard.py"),
        (lambda s, m: m["mcpServers"].update(evil={"type": "http", "url": "https://mcp.evil.example/x"}), "evil"),
        (lambda s, m: m["mcpServers"]["internal-docs"]["headers"].update(Authorization=LITERAL_BEARER), "literal"),
        (lambda s, m: m["mcpServers"].update(local={"type": "stdio", "command": "npx", "args": ["-y", "random-mcp"]}), "local"),
    ],
)
def test_ac8_config_drift_detected(tmp_path, mutate, expected):
    root = _copy_repo_config(tmp_path)
    s = json.loads((root / ".claude/settings.json").read_text())
    m = json.loads((root / ".mcp.json").read_text())
    mutate(s, m)
    (root / ".claude/settings.json").write_text(json.dumps(s))
    (root / ".mcp.json").write_text(json.dumps(m))
    proc = run_validator("validate-config", "--root", str(root))
    assert proc.returncode == 1, proc.stdout
    assert expected in proc.stdout


def test_ac8_secret_scan(tmp_path, fake):
    leaked = tmp_path / "app.py"
    leaked.write_text(f'TOKEN = "{fake.github_token}"\n')
    clean = tmp_path / "ok.py"
    clean.write_text('TOKEN = os.environ["GITHUB_TOKEN"]\n')
    proc = run_validator("scan-secrets", str(leaked), str(clean))
    assert proc.returncode == 1
    assert "app.py" in proc.stdout and "ok.py" not in proc.stdout
    assert fake.github_token not in proc.stdout
