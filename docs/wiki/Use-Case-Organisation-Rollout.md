This page is for IT, platform and security admins rolling the guardrails out across an organisation. It covers a phased plan from pilot to company-wide, the placeholders to replace, deploying managed settings, telemetry and privacy, the MCP allowlist, branch protection, a verification checklist and how to tell developers.

> **Placeholders on this page:** *AppSec*, *Platform Engineering*, `#appsec`, `#security-incidents`, `*.internal.example.com` and `otel-collector.internal.example.com` are example values from the template. Replace them with your own teams, channels and hosts.

## The plan at a glance

| Phase | Who | Duration (suggested) | Goal | Exit criteria |
|---|---|---|---|---|
| **0. Prepare** | AppSec + Platform | 1 week | Placeholders replaced, managed settings ready, collector ready | Verification checklist passes on one admin machine |
| **1. Pilot** | 1–2 volunteer teams | 2–4 weeks | Find false positives and missing allowlist entries | False-positive issues triaged; no open blockers |
| **2. Wider rollout** | Remaining teams, in waves | 2–6 weeks | Managed settings on every workstation; guardrails in every active repo | MDM reports full coverage; branch protection on every repo |
| **3. Steady state** | AppSec owns it | Ongoing | Policy reviewed every 6 months; drift and exceptions tracked | Review dates in the calendar |

Start the pilot with teams that already use Claude Code heavily. They hit the edge cases fastest, and their feedback shapes the allowlist for everyone else.

## 1. Customise the placeholders

The template ships with example values for a fictional company. The guardrails work as they are, but replace these before the pilot:

| File | What to set |
|---|---|
| [`enterprise/managed-settings.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/enterprise/managed-settings.json) | `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_RESOURCE_ATTRIBUTES`, the `allowedMcpServers` URL patterns, `sandbox.network.allowedDomains` (your artifact proxy) |
| [`.mcp.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.mcp.json) | Your real MCP server URLs (replacing `internal-docs` and `internal-tickets`) |
| [`config/claude-guardrails-policy.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/config/claude-guardrails-policy.json) | `approved_mcp_url_patterns` and `allowed_sandbox_domains`, to match the two files above and below |
| [`.claude/settings.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/settings.json) | `sandbox.network.allowedDomains`, and the allowlist commands for your stacks |
| [`.github/CODEOWNERS`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.github/CODEOWNERS) | Replace `@pixelofsoftware` with your teams, for example `@your-org/appsec` and `@your-org/platform-engineering` |
| [`docs/claude-guardrails.md`](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md) | Slack channels, retention periods, owner names |

Change `.claude/settings.json`, `.mcp.json` and the policy file **in the same commit**, or the `validate-claude-config` drift check fails. See [Policy baseline](Settings-Policy-Baseline).

## 2. Deploy the managed settings

Managed settings sit at the top of Claude Code's settings precedence. Their deny rules and `disableBypassPermissionsMode` can't be overridden by a user or a repository. Choose **one** delivery mechanism:

| Mechanism | How | Notes |
|---|---|---|
| **claude.ai admin console** (server-managed settings) | Paste the JSON into the Claude Code managed-settings editor | The only option that also reaches cloud sessions (claude.ai/code). `managed-mcp.json` can't be delivered this way |
| **MDM** (Jamf, Intune, Kandji, …) | macOS preference domain `com.anthropic.claudecode`, or the HKLM registry policy on Windows | Fits fleets you already manage |
| **System file** | Install as root/administrator at the path below | Simple; good for the pilot |

| OS | Path |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux / WSL | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

Linux example, run by an admin:

```bash
sudo install -d -m 0755 /etc/claude-code
sudo install -m 0644 enterprise/managed-settings.json /etc/claude-code/managed-settings.json
sudo install -m 0755 enterprise/claude-otel-headers.sh /usr/local/bin/claude-otel-headers
```

What the template enforces (full detail on [Organisation policy](Settings-Organisation-Policy)):

| Control | Setting |
|---|---|
| Bypass mode disabled for everyone | `permissions.disableBypassPermissionsMode: "disable"` |
| Org-wide deny baseline (28 rules) | `WebSearch`, network clients, `sudo`, `printenv`, `git push --force`, `git commit --no-verify`, `terraform apply`/`destroy`, reads of `.env`, keys, `*.tfstate` and credential directories |
| `WebFetch` always asks | `permissions.ask: ["WebFetch"]` |
| MCP allowlist | `allowManagedMcpServersOnly: true`, `allowedMcpServers`, `deniedMcpServers` |
| Sandbox locked to your domain list | `sandbox.enabled`, `allowUnsandboxedCommands: false`, `network.allowManagedDomainsOnly: true` |
| Local transcripts deleted after 14 days | `cleanupPeriodDays: 14` |
| Telemetry | The `env` block and `otelHeadersHelper` (next two sections) |

## 3. Telemetry and privacy

Claude Code ignores OpenTelemetry exporter variables in a repository's settings, so that a cloned repo can't redirect your telemetry. That's why telemetry lives in managed settings. The template's `env` block:

| Variable | Template value | Effect |
|---|---|---|
| `CLAUDE_CODE_ENABLE_TELEMETRY` | `1` | Turns export on |
| `OTEL_METRICS_EXPORTER`, `OTEL_LOGS_EXPORTER` | `otlp` | Metrics (cost, tokens, sessions, lines of code) and events |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | Dynamic headers need an `http/*` protocol |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `https://otel-collector.internal.example.com:4318` | **Replace** with your collector |
| `OTEL_LOG_USER_PROMPTS` | `1` | Prompt text is included in `claude_code.user_prompt` events |
| `OTEL_LOG_TOOL_DETAILS` | `1` | Full Bash commands, MCP server and tool names in tool events |
| `OTEL_METRIC_EXPORT_INTERVAL`, `OTEL_LOGS_EXPORT_INTERVAL` | `60000`, `5000` | Export intervals in milliseconds |
| `OTEL_RESOURCE_ATTRIBUTES` | `service.namespace=engineering,deployment.environment=workstation` | **Replace** with your own attributes |

Events worth routing to the SIEM: `claude_code.user_prompt`, `claude_code.tool_decision`, `claude_code.tool_result`, `claude_code.api_request`, `claude_code.api_refusal`. Correlate them with `session.id` and `prompt.id`.

Prompt logging is a privacy decision. Make it deliberately:

1. **Add a redaction processor in the collector** (for example the OpenTelemetry Collector `redaction` or `transform` processor) that masks emails, card numbers and key patterns in prompt attributes. The prompt guard blocks most such prompts, but it isn't documented whether the prompt event is emitted before a hook blocks, so assume it can be.
2. **Redact tool details too.** Bash commands can contain inline secrets.
3. **Restrict access.** The template policy says prompt text is visible only to Security Operations under an access review, and is never used for performance evaluation. Write down your own rule and publish it.
4. **Set retention** to match your security-log policy (the template says 1 year by default).
5. **Leave `OTEL_LOG_ASSISTANT_RESPONSES` and `OTEL_LOG_RAW_API_BODIES` off** unless an investigation needs them.
6. **Attribute events from the authenticated token** (or an mTLS certificate), not from the `X-Claude-User` header, which the client controls.

If your organisation can't log prompt text, set `OTEL_LOG_USER_PROMPTS` to `0` or remove it. You keep metrics and tool decisions.

## 4. Install the keychain headers helper

[`enterprise/claude-otel-headers.sh`](https://github.com/pixelofsoftware/AI-Mods/blob/main/enterprise/claude-otel-headers.sh) is the `otelHeadersHelper`. Claude Code runs it at startup and roughly every 29 minutes, so short-lived tokens rotate. It prints a JSON object of HTTP headers for the exporter.

How it finds the token, in order:

1. macOS Keychain: `security find-generic-password -s claude-otel-ingest -w`
2. Linux Secret Service (GNOME Keyring, KWallet): `secret-tool lookup service claude-otel-ingest`
3. A fallback file: `~/.config/claude-otel/token`

It outputs `Authorization: Bearer <token>` (when a token was found) and an informational `X-Claude-User` header. If no token is found, it warns on stderr and the collector rejects the exports.

Steps:

1. Provision a per-user ingest token into the keychain item `claude-otel-ingest` through your MDM, or edit the lookup in the script to match how your organisation issues tokens.
2. Install the script to `/usr/local/bin/claude-otel-headers` (the path in the template's `otelHeadersHelper`), mode `0755`.
3. Never hardcode a token in the script: it's world-readable on every workstation. Prefer the keychain over the fallback file.

## 5. The MCP allowlist

The template allows only HTTPS MCP servers on your internal domain:

```json
"allowManagedMcpServersOnly": true,
"allowedMcpServers": [
  { "serverUrl": "https://*.mcp.internal.example.com/*" }
],
"deniedMcpServers": [
  { "serverUrl": "http://*:*/*" }
]
```

With `allowManagedMcpServersOnly: true`, your `allowedMcpServers` list is the only one that counts. With only `serverUrl` entries in it, local stdio servers are blocked too. The `deniedMcpServers` pattern only matches plain-HTTP URLs that include an explicit port, so the HTTPS-only allowlist is what really keeps plain HTTP out.

To approve a new server, AppSec reviews its data access, its authentication, and whether its outputs could carry prompt injection. Then one pull request adds it to:

1. `.mcp.json` (credentials as `${VAR}` references, never literal tokens),
2. `enabledMcpjsonServers` in `.claude/settings.json`,
3. `approved_mcp_url_patterns` in `config/claude-guardrails-policy.json`,
4. and, if the URL isn't covered yet, `allowedMcpServers` in the managed settings.

Details: [MCP servers](Settings-MCP-Servers).

## 6. Optional hardening

| Managed setting | Effect | Trade-off |
|---|---|---|
| `forceLoginMethod` + `forceLoginOrgUUID` | Only your organisation's Claude accounts can sign in | None for org users |
| `allowManagedPermissionRulesOnly: true` | Ignores every non-managed allow/ask/deny rule | Move the project rules into managed settings first |
| `allowManagedHooksOnly: true` | Only centrally deployed hooks run | Deploy `.claude/hooks/` centrally and reference them by absolute path |
| `managed-mcp.json` | A fixed MCP server set; users can't add any | Least flexible; not deliverable through the admin console |
| `sandbox.failIfUnavailable: true` | Claude Code won't start without a working sandbox | Breaks native Windows; use WSL2 |
| `availableModels` | Restricts which models can be selected | — |

Turn these on after the pilot, once you know what teams need.

## 7. Protect `main` with two rulesets

Pre-commit runs on developer machines, and `--no-verify` skips it locally. The merge gate is what makes it binding: the `guardrails` CI job re-runs every check, and code owners review Tier 2 changes. Both only block merges when branch protection requires them.

We recommend two **repository rulesets** (Settings → Rules → Rulesets) targeting the default branch, rather than one:

| | Ruleset A: "main – required checks" | Ruleset B: "main – review" |
|---|---|---|
| Enforcement | Active | Active |
| Bypass list | **Empty.** Nobody bypasses it, admins included | Repository admins, for pull requests only |
| Rules | Require status checks to pass: add the `guardrails` check · Block force pushes · Restrict deletions | Require a pull request before merging · Required approvals: 1 · Require review from Code Owners |

Why two? GitHub doesn't let you approve your own pull request. A solo maintainer, or a small team where the only code owner wrote the change, would be stuck without a bypass. If the bypass were on a single combined ruleset, it would skip the CI check as well. Splitting them means an admin can merge without an approval, but **never without a green `guardrails` check**.

Notes:

- The check is the job `guardrails` in the workflow `ai-guardrails`. GitHub shows it as `ai-guardrails / guardrails` in the pull request's checks list; you select `guardrails` when you add the required check. It appears in the picker after the workflow has run once.
- The workflow runs on every `pull_request` and on pushes to `main`.
- When the team grows past one reviewer, remove the bypass from Ruleset B.
- Locally, the `no-commit-to-branch` pre-commit hook already stops direct commits to `main` and `master`.

## 8. Verification checklist

Run this on one managed machine before the pilot, and on a sample of machines in each wave. The repository's [verification record](https://github.com/pixelofsoftware/AI-Mods/blob/main/.sdlc/claude-guardrails/verification.md) lists these as items that need a real environment.

**Managed settings**

- [ ] `claude doctor` reports no managed-settings errors.
- [ ] `/status` in Claude Code lists *Managed settings* among the setting sources.
- [ ] `claude mcp add --transport http test https://example.com/mcp` fails (not allowed by policy).
- [ ] Bypass mode can't be selected.

**Telemetry**

- [ ] Submit a prompt and confirm a `claude_code.user_prompt` event reaches the collector. If nothing arrives, run `claude --debug-file /tmp/cc.log` and search the log for `[3P telemetry]`.
- [ ] The collector's redaction processor masks a synthetic email in that event.
- [ ] Events carry identity derived from the token, not only `X-Claude-User`.

**Project guardrails** (in a repository with the guardrails)

- [ ] `scripts/setup_guardrails.sh --check` ends with `Guardrails ready`.
- [ ] `/hooks` shows `prompt_guard` on UserPromptSubmit and `bash_guard`, `file_guard`, `read_guard` on PreToolUse.
- [ ] `/sandbox` shows the sandbox enabled. A command reaching a domain that isn't on the list fails.
- [ ] The smoke tests from [Installation](Installation) behave as expected: `curl` denied, `.env` denied, `infra/main.tf` asks, a fake key in a prompt is blocked, tests run without a prompt.

**Merge gate**

- [ ] A test pull request with a failing check can't be merged, even by an admin.
- [ ] A pull request touching `*.tf` requests a code-owner review.

## 9. Tell developers

Developers adopt guardrails when they understand them and when the safe path is fast. Send something short before the pilot starts. A template:

> **Subject: Claude Code guardrails are on from <date>**
>
> Claude Code is an approved tool, and we want you to use it. From <date>, your machine and our repositories enforce a few guardrails:
>
> - Routine work (reading code, running tests, linters, git status/diff) needs no approval.
> - Claude asks before pushing, installing packages, or editing infrastructure, CI, auth and crypto code. Read those prompts.
> - Claude can't reach the internet from its shell, read `.env` or key files, or run `terraform apply`. Prompts containing secrets are blocked, and you get a redacted copy to resubmit.
> - Prompts are logged centrally for security investigations only. Don't paste customer data.
>
> Setup takes ten minutes: <link to Installation>. If a guard blocks legitimate work, open a false-positive issue with the rule name from your audit log. Don't switch to another tool. Questions: `#appsec` (placeholder).

Also:

- Link the [developer policy](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md) and this wiki's [Daily development](Use-Case-Daily-Development) page.
- Commit to a turnaround for false positives (the template policy says 2 business days) and keep it.
- After the pilot, share what changed because of developer feedback. It builds trust for the next wave.

## Related pages

- [Organisation policy](Settings-Organisation-Policy)
- [MCP servers](Settings-MCP-Servers)
- [Commit and merge gates](Guardrail-Commit-and-Merge-Gates)
- [Adopting in another repository](Use-Case-Adopting-in-Another-Repository)
- [Audit logs](Audit-Logs)
- [Limitations and threat model](Limitations-and-Threat-Model)
