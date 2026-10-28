Every environment variable this project reads or sets, where it's read, its default, and what happens when you change it. The list comes from a search of the code for `os.environ`, `getenv` and `${…}` references, plus the variables Claude Code and the setup script use.

## At a glance

| Group | Variables | Read by | Set where |
|---|---|---|---|
| [API middleware](#claude-api-middleware-claude_safeguard_) | `CLAUDE_SAFEGUARD_*` (10) | [`scripts/claude_safeguard.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/scripts/claude_safeguard.py) `Policy.from_env()` | Your service's environment |
| [Hook audit log](#hook-audit-log) | `CLAUDE_GUARDRAIL_AUDIT`, `CLAUDE_GUARDRAIL_AUDIT_DIR`, `USER` / `USERNAME` | [`.claude/hooks/guard_common.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/hooks/guard_common.py) | Your shell, tests, CI |
| [Set by Claude Code](#set-by-claude-code) | `CLAUDE_PROJECT_DIR` | Hook commands in `.claude/settings.json` | Claude Code |
| [Credentials](#credentials) | `INTERNAL_MCP_TOKEN`, `ANTHROPIC_API_KEY` | `.mcp.json`; the `anthropic` SDK | Your shell profile or secret manager. Never a file in the repo |
| [Telemetry](#telemetry-managed-settings-only) | `CLAUDE_CODE_ENABLE_TELEMETRY`, `OTEL_*` | Claude Code | `enterprise/managed-settings.json` only |
| [OTEL headers helper](#otel-headers-helper) | `USER`, `USERNAME`, `HOME` | `enterprise/claude-otel-headers.sh` | The OS |
| [Setup and CI](#setup-script-and-ci) | `VIRTUAL_ENV`, `SKIP` | `scripts/setup_guardrails.sh`, pre-commit in CI | Your shell; the CI workflow |

Legend: ⛔ Deny/Block · ✋ Ask · ⚠️ Warn · ✅ Allow.

## Claude API middleware: `CLAUDE_SAFEGUARD_*`

`Policy.from_env()` reads these once, when you create `SafeClaude()` without passing a `policy`. The `scan` and `check-output` command-line tools also call it. Changing a variable later doesn't affect a `SafeClaude` instance that already exists.

| Variable | Default | Allowed values | Effect |
|---|---|---|---|
| `CLAUDE_SAFEGUARD_MODEL` | `claude-opus-5-5` | Any model ID | Model used when `create()` gets no `model=`. On Amazon Bedrock use the provider's ID, for example `anthropic.claude-opus-5-5` |
| `CLAUDE_SAFEGUARD_BLOCK_ON` | `critical` | `low`, `medium`, `high`, `critical`, `none`; comma-separated values allowed | The lowest severity that refuses the request locally, before anything is sent. With several values, the lowest wins. `none` means never refuse, only redact |
| `CLAUDE_SAFEGUARD_REDACT_MIN` | `medium` | `low`, `medium`, `high`, `critical` | The lowest severity that gets masked with a `[REDACTED:TYPE_N]` placeholder |
| `CLAUDE_SAFEGUARD_OUTPUT_ACTION` | `raise` | `raise`, `sanitize`, `warn` | What happens when output validation returns BLOCK: raise `UnsafeOutputError`, strip the blocked spans, or only log. A blocked **tool input** can't be sanitised, so it raises unless the action is `warn` |
| `CLAUDE_SAFEGUARD_FALLBACKS` | on | boolean | Server-side refusal fallback: adds the `server-side-fallback-2026-07-01` beta and `fallbacks="default"`. **Set it to `0` on Amazon Bedrock, Vertex AI and Microsoft Foundry**, which don't support it |
| `CLAUDE_SAFEGUARD_CANARY` | on | boolean | Adds a random `[internal-ref:<hex>]` token to the system prompt. If it shows up in the output, the system prompt leaked and the output is BLOCK |
| `CLAUDE_SAFEGUARD_HARDEN_SYSTEM` | on | boolean | Appends the anti-injection preamble to the system prompt |
| `CLAUDE_SAFEGUARD_BLOCK_UNSCANNABLE` | off | boolean | Refuses requests that contain images or PDFs (`base64`, `file` or `url` sources), which regex can't scan. Turn it on for regulated workloads |
| `CLAUDE_SAFEGUARD_TRUSTED_IMAGE_HOSTS` | empty | Comma-separated host names | Markdown images from these hosts aren't flagged as `markdown_image_exfiltration` |
| `CLAUDE_SAFEGUARD_APP` | `claude-app` | Any string | `service.name` in audit events. `SafeClaude(app_name=…)` overrides it |

Severities map to detectors like this (full list on [Detectors reference](Detectors-Reference)):

| Severity | Detectors |
|---|---|
| CRITICAL | Private keys; Anthropic, OpenAI, GitHub, GitLab, Slack and Stripe keys; AWS, GCP and Azure credentials; bearer tokens; passwords in URLs |
| HIGH | JWTs, `password=` style assignments, US SSNs, card numbers, IBANs, medical record numbers |
| MEDIUM | Email addresses, phone numbers |

So the defaults mean: credentials are refused locally; SSNs, cards, emails and phone numbers are masked and sent.

### Parsing rules and gotchas

- **Booleans:** `1`, `true`, `yes` and `on` (any case) mean on. **Any other value means off**, including an empty string or a typo such as `ture`. If the variable isn't set at all, the default applies.
- **`CLAUDE_SAFEGUARD_BLOCK_ON=""` (set but empty) turns blocking off**, the same as `none`. Leave the variable unset to keep the `critical` default.
- **Invalid severities or actions raise `ValueError`** when `SafeClaude()` is created, for example `expected one of low|medium|high|critical, got 'hi'` or `CLAUDE_SAFEGUARD_OUTPUT_ACTION must be raise|sanitize|warn, got 'block'`. A misconfigured service fails at start-up instead of running unprotected.
- **`REDACT_MIN` only controls masking.** Every finding is still counted in the audit event and still counts toward `BLOCK_ON`. With `REDACT_MIN=critical` and `BLOCK_ON=high`, a prompt with an SSN is refused, not sent unmasked.
- **`low` is accepted** but there are no LOW detectors today, so `BLOCK_ON=low` behaves like `medium`.

Try a setting offline before you deploy it. `scan` exits `2` when the text would be blocked:

```bash
CLAUDE_SAFEGUARD_BLOCK_ON=high python3 scripts/claude_safeguard.py scan "text with a synthetic SSN"
```

## Hook audit log

| Variable | Default | Effect |
|---|---|---|
| `CLAUDE_GUARDRAIL_AUDIT` | `1` | Set to exactly `0` to stop the hooks writing audit records. Any other value keeps auditing on. The hooks still block, ask and warn as usual |
| `CLAUDE_GUARDRAIL_AUDIT_DIR` | `<repo>/.claude/audit` | Directory for `guardrail-events.jsonl`. Created if missing. If it can't be written, the record is silently skipped |
| `USER`, then `USERNAME` | from the OS | Copied into each record's `user` field. `null` if neither is set |

The setup script's self-test and the test suite run the hooks with `CLAUDE_GUARDRAIL_AUDIT=0`, so tests never write into your real log. The project settings may not set `CLAUDE_GUARDRAIL_AUDIT` in `env` (the drift check fails), but `CLAUDE_GUARDRAIL_AUDIT_DIR` isn't on that list. See [Audit logs](Audit-Logs).

```bash
# Write to a temporary directory instead of .claude/audit/
export CLAUDE_GUARDRAIL_AUDIT_DIR="$HOME/guardrail-audit-test"
```

## Set by Claude Code

| Variable | Used in | Effect |
|---|---|---|
| `CLAUDE_PROJECT_DIR` | Every hook command in `.claude/settings.json`: `python3 "${CLAUDE_PROJECT_DIR}/.claude/hooks/<script>.py"` | Claude Code sets it to the project root, so the hooks run from any working directory. The drift check requires this exact command shape |

The hook scripts themselves don't read `CLAUDE_PROJECT_DIR`. `guard_common.py` finds the repository root from its own file location, and so does `check_ai_guardrails.py`.

## Credentials

Never put these in a committed file, a prompt, or `.claude/settings.json`. The drift check rejects any `ANTHROPIC_*` name in the project settings' `env`.

| Variable | Used by | How to provide it |
|---|---|---|
| `INTERNAL_MCP_TOKEN` | `.mcp.json`: the `internal-docs` server's `Authorization: Bearer ${INTERNAL_MCP_TOKEN}` header | Export it from your shell profile, for example from a password manager: `export INTERNAL_MCP_TOKEN="$(op read 'op://Engineering/internal-mcp/token')"`. Export it in the shell that launches `claude`. See [MCP servers](Settings-MCP-Servers) |
| `ANTHROPIC_API_KEY` | The `anthropic` SDK, when `SafeClaude` creates its default client (`anthropic.Anthropic()`) | Inject it from your secret manager (Vault, AWS Secrets Manager, GCP Secret Manager). For local development, `ant auth login` stores a profile the SDK picks up ([setup guide C1](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#c1-install-and-authenticate)). Keys look like `sk-ant-api03-…` |

`claude_safeguard.py` never reads `ANTHROPIC_API_KEY` itself. Its output validator does BLOCK model output where a network command (`curl`, `wget`, `nc`, `Invoke-WebRequest`) sends `$ANTHROPIC_API_KEY`, `$AWS_SECRET_ACCESS_KEY`, `$GITHUB_TOKEN` or `$OPENAI_API_KEY` (rule `credential_exfiltration`).

## Telemetry: managed settings only

`CLAUDE_CODE_ENABLE_TELEMETRY` and the `OTEL_*` variables are set in the `env` block of [`enterprise/managed-settings.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/enterprise/managed-settings.json). Claude Code ignores OTEL exporter variables from a repository's settings, and the drift check prints a note if you add one there. Every variable and its privacy impact is on [Organisation policy](Settings-Organisation-Policy#env-telemetry-variables).

| Variable | Value shipped |
|---|---|
| `CLAUDE_CODE_ENABLE_TELEMETRY` | `1` |
| `OTEL_METRICS_EXPORTER` | `otlp` |
| `OTEL_LOGS_EXPORTER` | `otlp` |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `https://otel-collector.internal.example.com:4318` (placeholder) |
| `OTEL_LOG_USER_PROMPTS` | `1` (sends prompt text to the collector) |
| `OTEL_LOG_TOOL_DETAILS` | `1` |
| `OTEL_METRIC_EXPORT_INTERVAL` | `60000` |
| `OTEL_LOGS_EXPORT_INTERVAL` | `5000` |
| `OTEL_RESOURCE_ATTRIBUTES` | `service.namespace=engineering,deployment.environment=workstation` |

## OTEL headers helper

[`enterprise/claude-otel-headers.sh`](https://github.com/pixelofsoftware/AI-Mods/blob/main/enterprise/claude-otel-headers.sh) reads:

| Variable | Effect |
|---|---|
| `USER`, then `USERNAME`, else `unknown` | Sent as the informational `X-Claude-User` header. The client controls it, so the collector must not trust it for identity |
| `HOME` | Locates the fallback token file `~/.config/claude-otel/token` |

It passes the token and user to its embedded Python as `CLAUDE_OTEL_TOKEN` and `CLAUDE_OTEL_USER`. Those are internal to the script; don't set them yourself.

## Setup script and CI

`scripts/setup_guardrails.sh` flags:

| Flag | Effect |
|---|---|
| (none) | Checks prerequisites, installs pre-commit if missing, runs `pre-commit install --install-hooks` (pre-commit and pre-push), creates `.claude/audit/`, then self-tests every guard |
| `--with-sdk` | Also installs `anthropic>=2.3,<3` for the API middleware |
| `--check` | Self-test only. Installs nothing and doesn't create `.claude/audit/` |
| `-h`, `--help` | Prints the usage lines and exits |
| anything else | `unknown option: …`, exit code `2` |

| Variable | Read by | Effect |
|---|---|---|
| `VIRTUAL_ENV` | `setup_guardrails.sh` | When set, `pip install` runs without `--user`, because a virtualenv rejects it |
| `CLAUDE_GUARDRAIL_AUDIT=0` | Set by the self-test | Keeps self-test runs out of your audit log |
| `SKIP` | pre-commit | CI sets `SKIP: no-commit-to-branch`, because branch protection guards `main` there. For Claude, `bash_guard` denies `SKIP=…`, `PRE_COMMIT_ALLOW_NO_CONFIG=…` and `HUSKY=…` in front of `git commit`, `push`, `merge`, `rebase` and `am` (rule `guardrail_bypass`) |

## Variables the project settings may not set

The drift check rejects these names in the `env` block of `.claude/settings.json` (`forbidden_env_patterns`): anything starting with `ANTHROPIC_` or `CLAUDE_CODE_USE_`, anything ending in `_BASE_URL`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, lowercase `http_proxy` and `https_proxy`, `NODE_OPTIONS`, `NODE_TLS_REJECT_UNAUTHORIZED` and `CLAUDE_GUARDRAIL_AUDIT`. Details on [Policy baseline](Settings-Policy-Baseline#forbidden_env_patterns).

## Related pages

- [API safeguard](Guardrail-API-Safeguard)
- [Claude API apps](Use-Case-Claude-API-Apps)
- [Audit logs](Audit-Logs)
- [Organisation policy](Settings-Organisation-Policy)
- [MCP servers](Settings-MCP-Servers)
- [Detectors reference](Detectors-Reference)
