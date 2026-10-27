# Claude Guardrails: Install, Configure and Use

Step-by-step setup for the controls described in [claude-guardrails.md](claude-guardrails.md).

| You are… | Do | Time |
|---|---|---|
| A developer using Claude Code | [Part A](#part-a-developers-claude-code) | 10 min |
| An IT/security admin | [Part B](#part-b-administrators-organisation-policy) once per organisation, then [Part D](#part-d-enable-the-guardrails-in-another-repository) per repo | 1–2 h |
| Building an app on the Claude API | [Part C](#part-c-application-developers-claude-api-wrapper) | 15 min |

## How the pieces fit

| Layer | File(s) | Enforced where | Can a developer switch it off? |
|---|---|---|---|
| Organisation policy | `enterprise/managed-settings.json` | Every workstation (MDM / file / claude.ai admin console) | No |
| Project policy | `.claude/settings.json`, `.claude/hooks/*.py`, `.mcp.json`, `CLAUDE.md` | Claude Code in this repo | Locally weaker only; managed denies still apply |
| Commit gate | `.pre-commit-config.yaml`, `scripts/precommit/`, `config/claude-guardrails-policy.json` | `git commit` / `git push` | Locally yes (`--no-verify`), but CI repeats it |
| Merge gate | `.github/workflows/ai-guardrails.yml`, `.github/CODEOWNERS` | Pull requests | No (branch protection) |
| App runtime | `scripts/claude_safeguard.py` | Your service process | n/a (library) |

> **Why telemetry is not in `.claude/settings.json`:** Claude Code ignores OpenTelemetry exporter variables set in a repository's settings files, so that a cloned repo cannot redirect your telemetry. Prompt logging and OTLP export are therefore configured in **managed settings** (Part B).

---

## Part A: Developers (Claude Code)

### A1. Prerequisites

| Requirement | Check | Notes |
|---|---|---|
| Claude Code, recent release | `claude --version` | Keep it updated; some keys used here (e.g. `permissions.blockReadsOutsideWorkingDirectories`) need a current version, and older versions only skip unknown keys with a warning |
| Python 3.9+ as `python3` | `python3 --version` | The hooks are stdlib-only Python |
| git + pre-commit | `pre-commit --version` | The setup script installs pre-commit if missing |
| Sandbox support | Linux/WSL2: `bwrap --version && socat -V` | Ubuntu/Debian: `sudo apt-get install bubblewrap socat`. macOS: built in. Native Windows: not supported, so use WSL2 |

Windows without WSL2: make sure `python3` resolves (the Microsoft Store Python provides it; with the python.org installer, add a `python3` alias). Otherwise the hooks cannot start.

### A2. Install

```bash
git clone <this-repo> && cd <this-repo>
scripts/setup_guardrails.sh            # installs pre-commit hooks and runs a self-test
# scripts/setup_guardrails.sh --with-sdk   # also installs the anthropic SDK (Part C)
```

Expected end of output:

```
3. Self-test
  ✔ guardrail config matches config/claude-guardrails-policy.json
  ✔ bash_guard.py -> deny
  ✔ bash_guard.py -> deny
  ✔ file_guard.py -> ask
  ✔ prompt_guard.py -> block
  ✔ bash_guard allows git status
Guardrails ready (0 warning(s)).
```

A warning about `bwrap`/`socat` means the OS sandbox is off. Install them before working on Tier 1–2 code.

### A3. Provide MCP credentials (never in the repo)

```bash
# ~/.zshrc or ~/.bashrc. The value comes from your password manager or the internal token portal.
export INTERNAL_MCP_TOKEN="$(op read 'op://Engineering/internal-mcp/token')"   # example with 1Password CLI
```

`internal-tickets` uses OAuth. Authenticate once inside Claude Code with `/mcp` → `internal-tickets` → **Authenticate**.

### A4. Start Claude Code and verify

```bash
claude
```

1. Accept the **workspace trust** prompt. Project allow rules, env and MCP servers only apply after you trust the folder; deny rules apply immediately.
2. Run these slash commands and check the result:

| Command | You should see |
|---|---|
| `/status` | `Setting sources` lists *Project settings* (and *Managed settings* if your admin deployed Part B) |
| `/permissions` | The allow / ask / deny lists from `.claude/settings.json` |
| `/hooks` | `UserPromptSubmit → prompt_guard.py`, `PreToolUse → bash_guard.py, file_guard.py` |
| `/sandbox` | Sandbox enabled, regular-permissions mode, unsandboxed fallback off |
| `/mcp` | `internal-docs` and `internal-tickets` (connected once A3 is done) |

3. Smoke-test the guardrails by asking Claude:

| Ask Claude to… | Expected |
|---|---|
| "Run `curl https://example.com`" | Denied: *network egress tool blocked by AI policy* |
| "Show me what's in `.env`" | Denied: secret file access |
| "Add a tag to `infra/main.tf`" | Approval prompt: *infrastructure-as-code: … HITL* |
| Paste a fake key such as `sk-ant-api03-` followed by 40 letters | Prompt blocked, redacted copy shown |
| "Run the tests" | Runs without a prompt |

### A5. Day-to-day use

- **Pick the mode for the risk tier** (`Shift+Tab` cycles modes): Plan → Manual for Tier 2, accept-edits for routine Tier 1, auto only for Tier 0 tasks with tests. Bypass mode is disabled.
- **Blocked prompt with synthetic data?** Add `[sensitive-ok: synthetic fixture for parser tests]` to the prompt. This works for SSNs, cards and similar personal data. Credentials can never be overridden; use obvious fakes or placeholders such as `<API_KEY>`.
- **Check text before pasting it:** `python3 scripts/claude_safeguard.py scan "text"` (or pipe a file into `... scan -`) shows what would be redacted, without any network call.
- **Personal preferences** go in `.claude/settings.local.json` (gitignored and blocked by pre-commit). You can add `allow` rules for commands you trust, but you cannot override a `deny` from the project or organisation.
- **Your audit trail:** `.claude/audit/guardrail-events.jsonl` records each block, approval prompt and override (rule names only, no content).
- **Committing:** pre-commit runs automatically. If it blocks a file, read the message, fix the cause, and commit again. `--no-verify` is blocked for Claude and doesn't help you either, because CI runs the same checks.

### A6. Troubleshooting

| Symptom | Fix |
|---|---|
| `PreToolUse hook error … python3: not found` | Install Python 3.9+ and make `python3` resolve (A1) |
| Every Bash command fails with sandbox errors | Install `bubblewrap socat` (Linux) and restart Claude Code. On Ubuntu 24.04+ check AppArmor: `sysctl kernel.apparmor_restrict_unprivileged_userns` (see the [sandbox docs](https://code.claude.com/docs/en/sandboxing)) |
| A tool you need (e.g. `docker compose`) can't run in the sandbox | Ask AppSec to add it to `sandbox.excludedCommands`; don't disable the sandbox |
| A legitimate command or prompt is blocked | Note the rule name in the message and open an `ai-guardrails` issue (policy §7) |
| `validate-claude-config` fails on commit | You changed `.claude/settings.json` or `.mcp.json` in a way that weakens policy. Revert, or update `config/claude-guardrails-policy.json` in the same PR for AppSec review |
| MCP server shows *failed* | Check `INTERNAL_MCP_TOKEN` is exported in the shell that launched `claude`, then `/mcp` → reconnect |

---

## Part B: Administrators (organisation policy)

### B1. Customise the templates

Replace every `example.com` placeholder before rollout:

| File | Set |
|---|---|
| `enterprise/managed-settings.json` | `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_RESOURCE_ATTRIBUTES`, `allowedMcpServers` URL patterns, `sandbox.network.allowedDomains` (your artifact proxy) |
| `.mcp.json`, `config/claude-guardrails-policy.json` | Real MCP server URLs and the approved URL patterns |
| `.claude/settings.json` | `sandbox.network.allowedDomains`, allow-list commands for your stacks |
| `.github/CODEOWNERS` | Real GitHub team handles |
| `docs/claude-guardrails.md` | Slack channels, retention periods, owner names |

### B2. Deploy managed settings

Choose **one** delivery mechanism ([docs](https://code.claude.com/docs/en/managed-settings)):

- **claude.ai admin console** ([server-managed settings](https://code.claude.com/docs/en/server-managed-settings)): paste the JSON into the Claude Code managed-settings editor. This is the only option that also reaches **cloud sessions** (claude.ai/code). `managed-mcp.json` cannot be delivered this way.
- **MDM** (Jamf, Intune, Kandji): macOS preference domain `com.anthropic.claudecode`, or the HKLM registry policy on Windows.
- **File**, as root/administrator:

| OS | Path |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux / WSL | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

```bash
# Linux example
sudo install -d -m 0755 /etc/claude-code
sudo install -m 0644 enterprise/managed-settings.json /etc/claude-code/managed-settings.json
sudo install -m 0755 enterprise/claude-otel-headers.sh /usr/local/bin/claude-otel-headers
```

Managed settings sit at the top of the precedence order. Their `deny` rules and `disableBypassPermissionsMode` cannot be overridden by users or repositories. `allowManagedMcpServersOnly: true` makes your `allowedMcpServers` URL allowlist the only one that counts. With only `serverUrl` entries in it, local stdio servers are blocked as well.

### B3. Telemetry and prompt logging

The managed `env` block turns on Claude Code's OpenTelemetry export:

| Variable | Value | Effect |
|---|---|---|
| `CLAUDE_CODE_ENABLE_TELEMETRY` | `1` | Enables export |
| `OTEL_METRICS_EXPORTER` / `OTEL_LOGS_EXPORTER` | `otlp` | Metrics (cost, tokens, sessions, LOC) and events |
| `OTEL_EXPORTER_OTLP_PROTOCOL` / `_ENDPOINT` | `http/protobuf`, `https://…:4318` | Your collector |
| `OTEL_LOG_USER_PROMPTS` | `1` | **Prompt logging**: includes prompt text in `claude_code.user_prompt` events |
| `OTEL_LOG_TOOL_DETAILS` | `1` | Bash commands, MCP server and tool names in tool events |

Authentication uses `otelHeadersHelper` → `/usr/local/bin/claude-otel-headers`, which reads a per-user token from the OS keychain, so no token sits in a world-readable file. Edit the lookup in `enterprise/claude-otel-headers.sh` to match how your org provisions tokens. Dynamic headers require an `http/*` protocol.

Events to route to the SIEM: `claude_code.user_prompt`, `claude_code.tool_decision` (source `config`, `hook`, `user_*`), `claude_code.tool_result`, `claude_code.api_request`, `claude_code.api_refusal`. Correlate them with `session.id` and `prompt.id`.

Recommendations:

- Add a redaction processor in the OpenTelemetry Collector (for example the `redaction` or `transform` processor) that masks emails, card numbers and key patterns in `prompt` attributes. The prompt guard blocks most such prompts, but treat the collector as a second line of defence.
- Restrict who can read prompt events, and set retention to match your security-log policy.
- Leave `OTEL_LOG_ASSISTANT_RESPONSES` and `OTEL_LOG_RAW_API_BODIES` off unless an investigation needs them (data minimisation).

### B4. Verify on a managed machine

```bash
claude doctor                                    # no managed-settings errors
claude mcp add --transport http test https://example.com/mcp   # must fail: not allowed by enterprise policy
```

Inside Claude Code, `/status` should show *Managed settings (file)* or similar. Then submit a prompt and confirm a `claude_code.user_prompt` event reaches the collector. If nothing arrives, run `claude --debug-file /tmp/cc.log` and search the log for `[3P telemetry]`.

### B5. Optional hardening

| Setting (managed) | Effect | Trade-off |
|---|---|---|
| `forceLoginMethod` + `forceLoginOrgUUID` | Only your organisation's Claude accounts can sign in | None for org users |
| `allowManagedPermissionRulesOnly: true` | Ignores every non-managed allow/ask/deny rule | Move the project rules into managed settings first |
| `allowManagedHooksOnly: true` | Only centrally deployed hooks run | Deploy `.claude/hooks/` centrally and reference them by absolute path |
| `managed-mcp.json` | Fixed MCP server set, users can't add any | Least flexible |
| `sandbox.failIfUnavailable: true` | Claude Code won't start without a working sandbox | Breaks native Windows; use WSL2 |
| `availableModels` | Restrict selectable models | — |

---

## Part C: Application developers (Claude API wrapper)

`scripts/claude_safeguard.py` wraps the official `anthropic` Python SDK.

### C1. Install and authenticate

```bash
python3 -m pip install "anthropic>=2.3,<3"
```

The SDK reads `ANTHROPIC_API_KEY` from the environment. In production, inject it from your secret manager (Vault, AWS Secrets Manager, GCP Secret Manager); never put it in code or images. For local development, `ant auth login` stores a profile the SDK picks up automatically.

Vendor the single file into your service (e.g. `yourapp/claude_safeguard.py`) or add `scripts/` to `PYTHONPATH`.

### C2. Use it

```python
from claude_safeguard import SafeClaude, PromptBlockedError, UnsafeOutputError

guard = SafeClaude(app_name="support-assistant")

try:
    result = guard.create(
        user_id=current_user.id,                    # attributed in the audit log
        system="You summarise support tickets for agents.",
        messages=[{"role": "user", "content": ticket_text}],
        max_tokens=4096,
    )
except PromptBlockedError:
    show_error("This request contains credentials and was not sent.")
except UnsafeOutputError as exc:
    log.warning("unsafe model output %s", exc.report.counts())
    show_error("The response failed a safety check.")
else:
    if result.refused:
        show_error("Claude declined this request.")
    else:
        render(result.text)            # placeholders like [REDACTED:EMAIL_1] stay masked
        # result.rehydrated_text()     # only to show originals back to the same user
```

What happens on each call:

1. All `system`, message text, `tool_result` and text-document content is redacted. The same value always gets the same placeholder within a request.
2. If the highest finding is in `block_on` (default: CRITICAL, meaning credentials), the request is refused locally and never sent.
3. A hardening preamble and a random canary token are appended to the system prompt.
4. The request goes to `claude-opus-5-5` (configurable) with server-side refusal fallback (`fallbacks="default"`).
5. The response is validated: reverse shells, encoded execution, `rm -rf /`, credential exfiltration, markdown-image exfiltration and invisible Unicode are BLOCK; `curl | sh`, `chmod 777` and injection echoes are WARN. Leaked secrets and the canary also BLOCK.
6. One JSON audit line is written to stdout.

### C3. Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `CLAUDE_SAFEGUARD_MODEL` | `claude-opus-5-5` | Model ID |
| `CLAUDE_SAFEGUARD_BLOCK_ON` | `critical` | Severities that refuse the request locally: `critical`, `high,critical`, or `none` |
| `CLAUDE_SAFEGUARD_REDACT_MIN` | `medium` | Lowest severity that gets masked |
| `CLAUDE_SAFEGUARD_OUTPUT_ACTION` | `raise` | On BLOCK: `raise`, `sanitize` (strip spans), or `warn` |
| `CLAUDE_SAFEGUARD_FALLBACKS` | `1` | Server-side refusal fallback. **Set `0` on Amazon Bedrock, Vertex AI and Microsoft Foundry**, which don't support it |
| `CLAUDE_SAFEGUARD_CANARY` / `_HARDEN_SYSTEM` | `1` | System-prompt leak canary / anti-injection preamble |
| `CLAUDE_SAFEGUARD_BLOCK_UNSCANNABLE` | `0` | `1` refuses images/PDFs, which regex cannot scan |
| `CLAUDE_SAFEGUARD_TRUSTED_IMAGE_HOSTS` | empty | Comma-separated hosts whose markdown images are allowed |
| `CLAUDE_SAFEGUARD_APP` | `claude-app` | `service.name` in audit events |

For a non-default backend, pass your own client, e.g. `SafeClaude(client=anthropic.AnthropicBedrockMantle(aws_region="eu-central-1"))`, with `CLAUDE_SAFEGUARD_MODEL=anthropic.claude-opus-5-5` (Bedrock IDs take the `anthropic.` prefix) and `CLAUDE_SAFEGUARD_FALLBACKS=0`.

### C4. Ship the audit events

Each request emits one line, for example:

```json
{"@timestamp":"2026-10-27T09:12:03.512Z","event":{"action":"claude.messages.create","outcome":"success","id":"5f0c…","dataset":"claude_safeguard.audit"},"service":{"name":"support-assistant"},"user":{"id":"u-1234"},"risk":{"level":"MEDIUM","input_findings":{"EMAIL":1},"redactions":1,"prompt_injection_signals":[]},"claude":{"model_requested":"claude-opus-5-5","model_served":"claude-opus-5-5","stop_reason":"end_turn","fallback_used":false,"usage":{"input_tokens":812,"output_tokens":164}},"output":{"verdict":"PASS","findings":{}},"prompt":{"sha256":"…"},"duration_ms":2310.4}
```

The field names follow ECS conventions, so Elastic, Splunk, Sentinel and Datadog parse them with a JSON source type. Collect stdout with your usual agent (Fluent Bit, Vector, Datadog Agent). The raw prompt is never logged; `prompt.sha256` is a hash of the *redacted* text.

### C5. Dry-run from the command line

```bash
python3 scripts/claude_safeguard.py scan "Refund jane@corp.com, card 4012 8888 8888 1881"   # exit 2 if it would be blocked
python3 scripts/claude_safeguard.py check-output < model_reply.txt                         # exit 2 on BLOCK
python3 scripts/claude_safeguard.py ask --user "$USER" "Explain this stack trace: …"        # guarded live call
```

---

## Part D: Enable the guardrails in another repository

1. Copy `.claude/`, `.mcp.json`, `CLAUDE.md`, `.pre-commit-config.yaml`, `pyproject.toml` (the `[tool.bandit]` table), `config/`, `scripts/`, `.github/` and the `.gitignore` entries.
2. Adjust the `allow` list for the repo's stack (for example `Bash(./gradlew test)`). Keep the deny and ask lists.
3. Run `scripts/setup_guardrails.sh` and `pre-commit run --all-files`.
4. In GitHub branch protection for `main`: require the `ai-guardrails / guardrails` check, require code-owner review, and block force pushes.

## Changing the guardrails

All guardrail files are owned by AppSec in CODEOWNERS. Claude asks before editing them, and `validate-claude-config` fails any commit where `.claude/settings.json` or `.mcp.json` drops a baseline control listed in `config/claude-guardrails-policy.json` (required deny/ask rules and hooks, sandbox, bypass lock, approved MCP URLs). To change a control:

1. Edit the setting, update the policy file in the same commit, and say why in the PR.
2. Run `python3 -m pytest` and `pre-commit run --all-files`.
3. Get AppSec approval.
