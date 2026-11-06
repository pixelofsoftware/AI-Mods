"""Shared helpers. Credential-shaped values are built at runtime so no scanner sees a literal."""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - tests run the hooks as the hosts do
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]  # agent-guardrails/
REPO = ROOT.parent  # the original repository, whose .claude/hooks are the reference
sys.path.insert(0, str(ROOT))

BASE_ENV = dict(
    os.environ,
    CLAUDE_PROJECT_DIR=str(REPO),
    AGENT_GUARDRAILS_AUDIT="0",
    CLAUDE_GUARDRAIL_AUDIT="0",
)
BASE_ENV.pop("AGENT_GUARDRAILS_CURSOR_ASK", None)


def run(argv, stdin: str, env=None, cwd=None):
    proc = subprocess.run(  # nosec B603 - fixed argv, test input only
        [sys.executable, *argv], input=stdin, capture_output=True, text=True, env=env or BASE_ENV, cwd=cwd or REPO, timeout=60
    )
    return proc.stdout, proc.returncode


def hook(host: str, guard: str, event, env=None, cwd=None):
    stdin = event if isinstance(event, str) else json.dumps(event)
    out, code = run([str(ROOT / "hook.py"), host, guard], stdin, env=env, cwd=cwd)
    return (json.loads(out) if out.strip() else None), code


class Fake:
    anthropic_key = "sk-" + "ant-" + "api03-" + "Zq9xLm2Pw7" * 5
    aws_key_id = "AK" + "IA" + "QWERTYUIOPASDF12"
    github_token = "gh" + "p_" + "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5"
    ssn = "123-45-" + "6789"
    card = "4012 8888 " + "8888 1881"
    email = "jane.doe" + "@example.org"


@pytest.fixture
def fake():
    return Fake
