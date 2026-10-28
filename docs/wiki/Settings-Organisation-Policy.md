`enterprise/managed-settings.json` is the organisation-wide Claude Code policy. Admins deploy it to every workstation, and developers and repositories can't override it. It turns on OpenTelemetry export (including prompt logging), sets a permission baseline, locks the MCP server list and the sandbox domains, and caps local transcript retention.

## At a glance

| | |
|---|---|
| **Files** | [`enterprise/managed-settings.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/enterprise/managed-settings.json), [`enterprise/claude-otel-headers.sh`](https://github.com/pixelofsoftware/AI-Mods/blob/main/enterprise/claude-otel-headers.sh) |
| **Who edits it** | IT / security admins. In this repo the files are owned by code owners and Claude asks before editing them (`Edit(/enterprise/**)`) |
| **Enforced by** | Claude Code on each machine, delivered by the claude.ai admin console, MDM, or a system file |
| **Can developers override it?** | No. Managed settings sit at the top of the precedence order |
| **Checked by the drift check?** | No. `validate-config` checks only `.claude/settings.json` and `.mcp.json`. `tests/test_config.py` asserts the telemetry keys and the MCP allowlist shape |

Legend: ⛔ Deny/Block · ✋ Ask · ⚠️ Warn · ✅ Allow.

> [!IMPORTANT]
> The file ships with placeholders for a fictional company: `otel-collector.internal.example.com`, `*.mcp.internal.example.com` and `artifacts.internal.example.com`. Replace them before rollout ([setup guide B1](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#b1-customise-the-templates)).

## Why telemetry lives here and not in the project

Claude Code ignores OpenTelemetry exporter variables set in a repository's settings files, so a cloned repository can't redirect your telemetry ([setup guide](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#how-the-pieces-fit)). That's why the OTLP endpoint, prompt logging and the headers helper are all here.

The drift check knows this too. If `.claude/settings.json` has any `OTEL_*` variable in `env`, it prints:

```text
note: OTEL_* exporter variables in .claude/settings.json are ignored by Claude Code; set them in managed settings.
```

It's a note, not a failure. `otelHeadersHelper` in project settings, on the other hand, is a hard failure (`forbidden_settings_keys`).

## Top-level keys

| Key | Value | What it does | Why |
|---|---|---|---|
| `$schema` | `https://json.schemastore.org/claude-code-settings.json` | Editor validation | Catches typos |
| `env` | 10 variables | Environment for every Claude Code session on the machine | Turns on and configures telemetry ([below](#env-telemetry-variables)) |
| `otelHeadersHelper` | `/usr/local/bin/claude-otel-headers` | A command that prints the HTTP headers for the OTLP exporter | The collector token comes from the OS keychain, not a world-readable file ([below](#otelheadershelper-and-claude-otel-headerssh)) |
| `permissions` | bypass lock, 28 deny, 1 ask | Org-wide permission baseline | A floor that holds in every repository, with or without project settings |
| `allowManagedMcpServersOnly` | `true` | Only the managed `allowedMcpServers` list counts | Repositories and users can't add their own MCP servers |
| `allowedMcpServers` | `[{ "serverUrl": "https://*.mcp.internal.example.com/*" }]` | URL allowlist for MCP servers | Internal HTTPS servers only |
| `deniedMcpServers` | `[{ "serverUrl": "http://*:*/*" }]` | URL denylist for MCP servers | Blocks plain-HTTP servers as a second line |
| `sandbox` | enabled, no unsandboxed fallback, managed domains only | Org-wide sandbox floor | Projects can't widen network access |
| `cleanupPeriodDays` | `14` | Local transcripts (`~/.claude/projects/`) are deleted after 14 days | Data minimisation ([policy §5](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#5-logging-and-monitoring)) |

## `env`: telemetry variables

| Variable | Value | What it does |
|---|---|---|
| `CLAUDE_CODE_ENABLE_TELEMETRY` | `1` | Turns on OpenTelemetry export |
| `OTEL_METRICS_EXPORTER` | `otlp` | Exports metrics: cost, tokens, sessions, lines of code |
| `OTEL_LOGS_EXPORTER` | `otlp` | Exports events (prompts, tool decisions, API requests) |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | OTLP over HTTP. Dynamic headers from `otelHeadersHelper` need an `http/*` protocol |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `https://otel-collector.internal.example.com:4318` | Your collector (placeholder). Keep it HTTPS |
| `OTEL_LOG_USER_PROMPTS` | `1` | **Prompt logging**: prompt text is included in `claude_code.user_prompt` events |
| `OTEL_LOG_TOOL_DETAILS` | `1` | Full Bash commands, MCP server names and tool names in tool events |
| `OTEL_METRIC_EXPORT_INTERVAL` | `60000` | Metrics export interval in milliseconds (60 s) |
| `OTEL_LOGS_EXPORT_INTERVAL` | `5000` | Events export interval in milliseconds (5 s) |
| `OTEL_RESOURCE_ATTRIBUTES` | `service.namespace=engineering,deployment.environment=workstation` | Tags on every metric and event, so you can filter workstation traffic in the SIEM |

Events worth routing to the SIEM ([setup guide B3](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#b3-telemetry-and-prompt-logging)): `claude_code.user_prompt`, `claude_code.tool_decision` (source `config`, `hook`, `user_*`), `claude_code.tool_result`, `claude_code.api_request` and `claude_code.api_refusal`. Correlate them with `session.id` and `prompt.id`. For the full list of telemetry variables and events, see the [Claude Code documentation](https://code.claude.com/docs/en/settings).

### Privacy: what prompt logging sends

> [!WARNING]
> `OTEL_LOG_USER_PROMPTS=1` sends the **text of every prompt** to your collector. `OTEL_LOG_TOOL_DETAILS=1` sends full Bash commands, which can contain inline secrets.

Before you turn these on:

- **Redact at the collector.** Add a redaction processor in the OpenTelemetry Collector (for example the `redaction` or `transform` processor) that masks emails, card numbers and key patterns in `prompt` attributes. The [prompt guard](Guardrail-Prompt-Guard) blocks most such prompts, but treat the collector as a second line of defence.
- **Assume a blocked prompt can still be logged.** Whether a `claude_code.user_prompt` event is emitted before the prompt guard blocks a prompt isn't documented. Rely on collector-side redaction.
- **Restrict access.** Only Security Operations should read prompt events, under an access-review process. [Policy §5](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#5-logging-and-monitoring) says prompt text is never used for performance evaluation. Tell your developers.
- **Set retention** to match your security-log policy (the policy template says 1 year by default).
- **Leave `OTEL_LOG_ASSISTANT_RESPONSES` and `OTEL_LOG_RAW_API_BODIES` off** unless an investigation needs them. They aren't set in this file.
- **Check your legal basis.** Logging prompt text is monitoring of employees in many jurisdictions. Involve your privacy team.

## `otelHeadersHelper` and `claude-otel-headers.sh`

`otelHeadersHelper` points at a command that prints a JSON object of HTTP headers for the OTLP exporter. The script's own comments say Claude Code calls it at startup and roughly every 29 minutes, so short-lived tokens rotate.

Install it once per machine, as root:

```bash
sudo install -m 0755 enterprise/claude-otel-headers.sh /usr/local/bin/claude-otel-headers
```

What [`claude-otel-headers.sh`](https://github.com/pixelofsoftware/AI-Mods/blob/main/enterprise/claude-otel-headers.sh) does, in order:

1. **macOS:** if the `security` command exists, reads the Keychain generic password with service `claude-otel-ingest`.
2. **Linux:** otherwise, if `secret-tool` exists, reads the Secret Service item `service claude-otel-ingest` (GNOME Keyring / KWallet).
3. **Fallback file:** if no token was found and `~/.config/claude-otel/token` is readable, reads it.
4. **No token:** prints a warning to stderr (`the collector will reject exports`) and continues without an `Authorization` header.
5. Prints the headers with Python's `json.dumps`, so a token or user name can't break the JSON:

```json
{"X-Claude-User": "alice", "Authorization": "Bearer <token from the keychain>"}
```

Notes:

- `X-Claude-User` comes from `$USER` (or `$USERNAME`, else `unknown`). The client controls it, so it's **informational only**. Your collector must derive identity from the authenticated token or an mTLS certificate.
- The script is world-readable on every workstation. Never hardcode a token in it. Change the lookup to however your organisation provisions tokens.
- If you use the fallback file, make it readable only by its owner.

## `permissions`: the baseline

| Key | Value | Effect |
|---|---|---|
| `disableBypassPermissionsMode` | `"disable"` | Bypass mode is off for everyone. Users and repositories can't override it ([setup guide B2](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#b2-deploy-managed-settings)) |
| `ask` | `WebFetch` | ✋ Every web fetch needs approval, in every repository |
| `deny` | 28 rules, below | ⛔ Denied in every repository. A managed deny can't be overridden |

The 28 managed deny rules:

| Group | Rules |
|---|---|
| Web search | `WebSearch` |
| Network clients | `Bash(curl *)`, `Bash(wget *)`, `Bash(nc *)`, `Bash(ncat *)`, `Bash(netcat *)`, `Bash(telnet *)`, `Bash(socat *)` |
| Privilege escalation | `Bash(sudo *)` |
| Environment dumps | `Bash(printenv)`, `Bash(printenv *)` |
| Git safety | `Bash(git push --force *)`, `Bash(git commit --no-verify *)` |
| Infrastructure | `Bash(terraform apply *)`, `Bash(terraform destroy *)` |
| Secret files | `Read(**/.env)`, `Read(**/.env.local)`, `Read(**/.env.production)`, `Read(**/*.pem)`, `Read(**/*.key)`, `Read(**/*.tfstate)` |
| Home credentials | `Read(~/.ssh/**)`, `Read(~/.aws/**)`, `Read(~/.azure/**)`, `Read(~/.config/gcloud/**)`, `Read(~/.kube/**)`, `Read(~/.netrc)`, `Read(~/.git-credentials)` |

Every managed rule is also in the project's deny list. The project adds 34 more, for example `Bash(ssh *)`, `Bash(scp *)`, `Bash(su *)`, `Bash(env)`, `Bash(git push -f *)`, `Bash(kubectl delete *)`, `Bash(npm publish *)`, the bare `Bash(terraform apply)` and more `.env` variants. In a repository **without** this project's `.claude/settings.json` and hooks, only the 28 managed rules apply. If you want any of the others everywhere, add them here. See [Project settings](Settings-Project#-deny-rules-62) for the full list.

## MCP: `allowManagedMcpServersOnly`, `allowedMcpServers`, `deniedMcpServers`

| Key | Value | Effect |
|---|---|---|
| `allowManagedMcpServersOnly` | `true` | Your managed `allowedMcpServers` list is the only allowlist that counts |
| `allowedMcpServers` | `serverUrl: https://*.mcp.internal.example.com/*` | Only HTTPS servers under your internal MCP domain. With only `serverUrl` entries in the list, local stdio servers are blocked as well ([setup guide B2](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#b2-deploy-managed-settings)) |
| `deniedMcpServers` | `serverUrl: http://*:*/*` | Denies plain-HTTP server URLs |

A server must pass **both** this allowlist and the project's own review (`.mcp.json` + `enabledMcpjsonServers` + the policy's `approved_mcp_url_patterns`). Keep the managed pattern and the policy pattern in sync. See [MCP servers](Settings-MCP-Servers). For the exact wildcard semantics of `serverUrl`, see the [Claude Code settings documentation](https://code.claude.com/docs/en/settings).

## `sandbox`

| Key | Value | Effect |
|---|---|---|
| `sandbox.enabled` | `true` | Bash runs in the OS sandbox |
| `sandbox.allowUnsandboxedCommands` | `false` | No unsandboxed fallback |
| `sandbox.network.allowManagedDomainsOnly` | `true` | Only the managed `allowedDomains` count, so a project can't widen network access |
| `sandbox.network.allowedDomains` | `github.com`, `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `proxy.golang.org`, `artifacts.internal.example.com` | The same six domains as the project file and the policy's `allowed_sandbox_domains` |

When you add a domain, change it in all three places: here, `.claude/settings.json` and `config/claude-guardrails-policy.json`.

## Deploying managed settings

Choose **one** delivery mechanism ([setup guide B2](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#b2-deploy-managed-settings)):

| Mechanism | How | Notes |
|---|---|---|
| **claude.ai admin console** (server-managed settings) | Paste the JSON into the Claude Code managed-settings editor | The only option that also reaches **cloud sessions** (claude.ai/code). `managed-mcp.json` can't be delivered this way |
| **MDM** (Jamf, Intune, Kandji) | macOS preference domain `com.anthropic.claudecode`, or the HKLM registry policy on Windows | |
| **System file**, as root/administrator | Copy the file to the path below | |

| OS | Path |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux / WSL | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

Linux example:

```bash
sudo install -d -m 0755 /etc/claude-code
sudo install -m 0644 enterprise/managed-settings.json /etc/claude-code/managed-settings.json
sudo install -m 0755 enterprise/claude-otel-headers.sh /usr/local/bin/claude-otel-headers
```

## Precedence over project and user settings

- Managed settings sit at the **top** of the precedence order.
- Managed `deny` rules and `disableBypassPermissionsMode` can't be overridden by users or repositories.
- `allowManagedMcpServersOnly: true` makes the managed MCP allowlist the only one that counts.
- `allowManagedDomainsOnly: true` does the same for sandbox domains.
- OpenTelemetry exporter variables only take effect from managed settings, not from repository settings.

For the complete order of settings sources, see the [Claude Code settings documentation](https://code.claude.com/docs/en/settings).

## Verify on a managed machine

```bash
claude doctor                                                   # no managed-settings errors
claude mcp add --transport http test https://example.com/mcp    # must fail: not allowed by enterprise policy
```

Inside Claude Code, `/status` should list *Managed settings*. Submit a prompt and confirm a `claude_code.user_prompt` event reaches the collector. If nothing arrives, run `claude --debug-file /tmp/cc.log` and search the log for `[3P telemetry]` ([setup guide B4](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#b4-verify-on-a-managed-machine)). These checks need a real managed workstation; the repository's [verification record](https://github.com/pixelofsoftware/AI-Mods/blob/main/.sdlc/claude-guardrails/verification.md) lists them as unverified in CI.

## Optional hardening

Not in the shipped file. From [setup guide B5](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#b5-optional-hardening):

| Managed setting | Effect | Trade-off |
|---|---|---|
| `forceLoginMethod` + `forceLoginOrgUUID` | Only your organisation's Claude accounts can sign in | None for org users |
| `allowManagedPermissionRulesOnly: true` | Ignores every non-managed allow / ask / deny rule | Move the project rules into managed settings first |
| `allowManagedHooksOnly: true` | Only centrally deployed hooks run | Deploy `.claude/hooks/` centrally and reference them by absolute path |
| `managed-mcp.json` | A fixed MCP server set; users can't add any | Least flexible |
| `sandbox.failIfUnavailable: true` | Claude Code won't start without a working sandbox | Breaks native Windows; use WSL2 |
| `availableModels` | Restricts selectable models | None |

## Related pages

- [Project settings](Settings-Project)
- [MCP servers](Settings-MCP-Servers)
- [Organisation rollout](Use-Case-Organisation-Rollout)
- [Audit logs](Audit-Logs)
- [Environment variables](Settings-Environment-Variables)
- [Limitations and threat model](Limitations-and-Threat-Model)
