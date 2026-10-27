"""Test fixtures.

Fake secrets are assembled at runtime so the repository's own secret scanners
(gitleaks, detect-private-key) never see a literal credential in source.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "precommit"))
HOOKS = ROOT / ".claude" / "hooks"


class Fake:
    """Credential-shaped strings built at runtime."""

    anthropic_key = "sk-ant-" + "api03-" + "Zq9xLm2Pw7" * 5
    aws_key_id = "AKIA" + "QZ7XRT5MNB2KLW4P"
    github_token = "gh" + "p_" + "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5"
    private_key = (
        "-----BEGIN " + "RSA PRIVATE" + " KEY-----\n"
        + "MIIEowIBAAKCAQEA7x9Qm2" * 3
        + "\n-----END " + "RSA PRIVATE" + " KEY-----"
    )
    ssn = "-".join(["123", "45", "6789"])
    card = " ".join(["4012", "8888", "8888", "1881"])  # Luhn-valid, not in test-value allowlist
    iban = "DE89" + "370400440532013000"
    db_url = "postgres://app:" + "S3cr3tPassw0rd" + "@db.internal:5432/app"


@pytest.fixture
def fake() -> type:
    return Fake


def run_hook(name: str, event: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Run a hook script like Claude Code does: JSON on stdin, JSON (or nothing) on stdout."""
    proc = subprocess.run(
        [sys.executable, str(HOOKS / name)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "CLAUDE_GUARDRAIL_AUDIT": "0", **(env or {})},
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


@pytest.fixture
def hook():
    return run_hook
