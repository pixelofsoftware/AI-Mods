# Roadmap: Claude enterprise guardrail framework

## Architecture (Agent 3)
Defense in depth, four layers, each independently useful:

| Layer | Where it runs | Enforced by | Bypassable by developer? |
|---|---|---|---|
| Org policy | every workstation | `enterprise/managed-settings.json` (MDM / server-managed) | No |
| Project policy | Claude Code in this repo | `.claude/settings.json` + hooks + sandbox | Partly (local settings), audited |
| Commit gate | `git commit` + CI | `.pre-commit-config.yaml`, CI workflow, CODEOWNERS | Locally yes (`--no-verify`), CI no |
| App runtime | apps calling the API | `scripts/claude_safeguard.py` | n/a (library) |

Single source of truth for detection patterns: `scripts/claude_safeguard.py`. Hooks import it; the pre-commit validator imports it for its secret scan. Policy baseline for config drift: `config/claude-guardrails-policy.json`.

## Tasks (Agent 4)
| # | Task | Files | ACs | Depends |
|---|---|---|---|---|
| T1 | Safeguard library (done, review) | `scripts/claude_safeguard.py` | 9-12 | – |
| T2 | Hooks (done, review) | `.claude/hooks/*.py` | 5-7, 14 | T1 |
| T3 | Claude Code + MCP + managed config (done, review) | `.claude/settings.json`, `.mcp.json`, `enterprise/*` | 2-4, 14 | T2 |
| T4 | Tests from ACs | `tests/test_*.py`, `pyproject.toml` | 5-12 | – |
| T5 | Pre-commit validator | `scripts/precommit/check_ai_guardrails.py` | 8, 4 | T1 |
| T6 | Pre-commit config | `.pre-commit-config.yaml`, `pyproject.toml` (bandit) | 8 | T5 |
| T7 | Repo hygiene | `.gitignore`, `.github/CODEOWNERS`, `.github/workflows/ai-guardrails.yml`, `CLAUDE.md` | 3, 8 | T6 |
| T8 | Setup script | `scripts/setup_guardrails.sh` | 13 | T6 |
| T9 | Docs | `docs/claude-guardrails.md`, `docs/claude-guardrails-setup.md`, `README.md` | 1, 3, 13 | T1-T8 |
| T10 | Validate: pytest, `pre-commit run --all-files`, live hook checks | – | all | all |
| T11 | Commit + push to `claude/kind-hamilton-1g3q7h` | – | – | T10 |
