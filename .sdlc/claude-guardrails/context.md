# Context: Claude enterprise guardrail framework

## Repository
- `pixelofsoftware/AI-Mods`, branch `claude/kind-hamilton-1g3q7h`.
- Before this feature: one commit (`5f31b0e Initial commit`) holding `.gitattributes` (`* text=auto`). No CLAUDE.md, README, manifests, tests or CI.
- No conventions to inherit. Adopted: Python 3.9+ stdlib-only for hooks/validators, JSON for Claude Code config, YAML for pre-commit/CI, Markdown docs under `docs/`.

## Stack decisions
- Language: Python (user allowed Python or TypeScript; Python covers hooks, validators and the API wrapper with one runtime).
- Claude API: official `anthropic` SDK (2.3.0 latest at time of writing), imported lazily so detectors run without it. Default model `claude-opus-5-5`; server-side refusal fallback `fallbacks="default"` with beta `server-side-fallback-2026-07-01`.
- Claude Code facts verified against live docs (code.claude.com, 2026-10-27):
  - `OTEL_*` exporter vars in `.claude/settings.json` are **ignored**; telemetry must be set in managed settings or the user's shell/user settings.
  - `permissions.defaultMode` `auto`/`bypassPermissions` do not take effect from project settings.
  - Bash permission rules match command text only (`/usr/bin/curl`, `sh -c 'curl'` bypass them) → PreToolUse hook + sandbox needed.
  - Managed settings paths: `/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`, `C:\Program Files\ClaudeCode\`.
  - MCP allowlist entries: `serverUrl` / `serverCommand` / `serverName`; `allowManagedMcpServersOnly` is managed-only.

## Commands
- Tests: `python3 -m pytest -q` (venv in scratchpad has pytest 9, pre-commit 4.7.0, anthropic 2.3.0).
- Hooks/lint: `pre-commit run --all-files`.
- Compile check: `python3 -m py_compile scripts/*.py .claude/hooks/*.py`.

## Baseline
- No pre-existing tests. Baseline = 0 tests, 0 failures.
- Code already written in this session compiles; smoke checks OK (bash_guard allows `git status`; scan redacts email + SSN).

## Environment note
- This cloud session loaded the new `.claude/settings.json` after a restart, so the guardrail hooks are live on the agent's own tool calls (useful as a real-world test).
