#!/usr/bin/env python3
"""Scan text for credentials and personal data offline, with the same detectors as the hooks.

    python3 scan.py "text"
    python3 scan.py - < file.txt

Prints a JSON report with a redacted copy. Exit code 2 means the text would be blocked.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def find_engine() -> Path:
    """Locate guardrails_core: env override, the plugin root, or a project install."""
    candidates = []
    if os.environ.get("AGENT_GUARDRAILS_HOME"):
        candidates.append(Path(os.environ["AGENT_GUARDRAILS_HOME"]))
    if os.environ.get("CLAUDE_PLUGIN_ROOT"):
        candidates.append(Path(os.environ["CLAUDE_PLUGIN_ROOT"]))
    candidates.append(HERE.parents[2])  # plugin: <root>/skills/agent-guardrails/scripts -> <root>
    # Project install: <repo>/.<tool>/skills/agent-guardrails/scripts -> <repo>/.agent-guardrails.
    # Only folders above this script are searched, never the current directory, so
    # scanning inside an untrusted checkout can't load that checkout's code.
    for folder in HERE.parents:
        candidates.append(folder / ".agent-guardrails")
    for candidate in candidates:
        if (candidate / "guardrails_core" / "safeguard.py").is_file():
            return candidate
    raise SystemExit("agent-guardrails engine not found; set AGENT_GUARDRAILS_HOME to the folder that contains guardrails_core/")


def main() -> int:
    sys.path.insert(0, str(find_engine()))
    from guardrails_core.safeguard import main as safeguard_main

    return safeguard_main(["scan", *sys.argv[1:]])


if __name__ == "__main__":
    sys.exit(main())
