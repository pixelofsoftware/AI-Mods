# Claude Enterprise Guardrails

A guardrail framework for developing software with Anthropic's Claude (Claude Code and the Claude API). It keeps routine work frictionless and puts hard controls around credentials, personal data, network access, infrastructure changes and the guardrails themselves.

- **Policy:** [docs/claude-guardrails.md](docs/claude-guardrails.md)
- **Install, configure, use:** [docs/claude-guardrails-setup.md](docs/claude-guardrails-setup.md)

```bash
scripts/setup_guardrails.sh      # developers: install hooks + self-test
python3 -m pytest                # tests for hooks, wrapper and validators
pre-commit run --all-files       # everything CI runs
```

## What's in the box

| Path | Purpose |
|---|---|
| `docs/claude-guardrails.md` | Developer policy: execution modes per risk tier, data protection, HITL review, tooling/MCP rules |
| `docs/claude-guardrails-setup.md` | Step-by-step guide for developers, admins and API app builders |
| `.claude/settings.json` | Project Claude Code config: least-privilege allow/ask/deny rules, sandbox, hooks, approved MCP servers |
| `.claude/hooks/prompt_guard.py` | `UserPromptSubmit`: blocks credentials and regulated PII before they reach Claude; offers a redacted copy |
| `.claude/hooks/bash_guard.py` | `PreToolUse(Bash)`: parses real commands to block network egress, secret access, force-push, `--no-verify`, `terraform apply`, … |
| `.claude/hooks/read_guard.py` | `PreToolUse(Read/Grep/Glob)`: blocks reading any secrets-file variant (`.env.*`, `.envrc`, keys, kubeconfig) |
| `.claude/hooks/file_guard.py` | `PreToolUse(Write/Edit)`: blocks hardcoded secrets; requires approval for IaC, security-critical and guardrail files |
| `.mcp.json` | Internally hosted MCP servers (HTTPS, `${VAR}` credentials) |
| `enterprise/managed-settings.json` | Org-wide policy: OpenTelemetry + prompt logging, bypass lock, MCP URL allowlist, sandbox network lock |
| `enterprise/claude-otel-headers.sh` | `otelHeadersHelper`: rotating collector token from the OS keychain |
| `.pre-commit-config.yaml` | gitleaks, detect-private-key, bandit, checkov + AI-specific checks |
| `scripts/precommit/check_ai_guardrails.py` | Blocks session logs, local configs and keys; detects guardrail config drift; secret scan |
| `config/claude-guardrails-policy.json` | Machine-readable baseline the drift check enforces |
| `scripts/claude_safeguard.py` | Claude API middleware: PII/credential redaction, JSON audit events (SIEM), output validation |
| `.github/workflows/ai-guardrails.yml`, `.github/CODEOWNERS` | CI re-run of all checks; mandatory code-owner review for Tier 2 paths |
| `CLAUDE.md` | Standing instructions Claude reads in every session |
| `.sdlc/claude-guardrails/` | Requirements, plan, reviews and verification record for this framework |

Placeholders (`*.internal.example.com`, `@your-org/*` teams, Slack channels) must be replaced before rollout; see setup guide §B1.
