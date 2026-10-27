# Working in this repository

This repo enforces the AI development policy in `docs/claude-guardrails.md`. Hooks in `.claude/hooks/` check prompts, shell commands and file writes; pre-commit and CI re-check everything.

## Rules for Claude
- Never read, print or write secrets: `.env*` (except `.env.example`), keys, `~/.ssh`, `~/.aws`, cloud secret stores. Reference configuration through environment variables.
- No arbitrary network access from the shell (`curl`, `wget`, `nc`, ...). If something must be fetched, say what and why and let the developer do it.
- Infrastructure-as-code (`*.tf`, Kubernetes, Helm, Dockerfiles, CI workflows) and security-critical code (`auth/`, `security/`, `crypto/`): propose the change, explain the security impact, and expect human review. Never run `terraform apply/destroy`, `kubectl delete`, or deploys.
- Do not edit the guardrails (`.claude/`, `.mcp.json`, `.pre-commit-config.yaml`, `scripts/claude_safeguard.py`, `scripts/precommit/`, `config/claude-guardrails-policy.json`) unless the developer explicitly asks, and call out any change that loosens a control.
- Never bypass checks: no `--no-verify`, no disabling hooks, no force-push.
- Use synthetic test data. Placeholders like `[REDACTED:EMAIL_1]` are intentional; do not guess originals.

## Commands
- Tests: `python3 -m pytest`
- All checks: `pre-commit run --all-files`
- Dry-run a prompt for sensitive data: `python3 scripts/claude_safeguard.py scan "text"`
