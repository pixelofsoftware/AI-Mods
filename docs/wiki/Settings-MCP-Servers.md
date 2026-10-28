MCP servers give Claude Code extra tools, such as searching internal docs or updating tickets. This repository allows only internally hosted, reviewed servers over HTTPS, with credentials supplied through environment variables. Four places have to agree before a server works: `.mcp.json`, `enabledMcpjsonServers` in `.claude/settings.json`, the policy file, and (on managed machines) the organisation allowlist.

## At a glance

| | |
|---|---|
| **Files** | [`.mcp.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.mcp.json), [`.claude/settings.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/settings.json) (`enabledMcpjsonServers`, `mcp__…` rules), [`config/claude-guardrails-policy.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/config/claude-guardrails-policy.json) (`approved_mcp_url_patterns`, `approved_mcp_commands`), [`enterprise/managed-settings.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/enterprise/managed-settings.json) (`allowedMcpServers`) |
| **Who edits them** | Code owners (AppSec) through a reviewed PR. Claude asks before editing any of them |
| **Enforced by** | Claude Code (project approval, permissions, managed allowlist) and `validate-claude-config` in pre-commit and CI |
| **Can developers override it?** | Not on a managed machine: `allowManagedMcpServersOnly` makes the org allowlist the only one. Local MCP override files (`.mcp.local.json`, `*.mcp.local.json`) can't be committed |

Legend: ⛔ Deny/Block · ✋ Ask · ⚠️ Warn · ✅ Allow.

## The servers in `.mcp.json`

```json
{
  "mcpServers": {
    "internal-docs": {
      "type": "http",
      "url": "https://docs.mcp.internal.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${INTERNAL_MCP_TOKEN}"
      }
    },
    "internal-tickets": {
      "type": "http",
      "url": "https://tickets.mcp.internal.example.com/mcp"
    }
  }
}
```

| Server | Purpose | Auth | Permission rule | Why |
|---|---|---|---|---|
| `internal-docs` | Search internal engineering docs | `Authorization: Bearer ${INTERNAL_MCP_TOKEN}`, expanded from your shell environment | ✅ `mcp__internal-docs__*` (allow) | Read-only, so no prompt |
| `internal-tickets` | Read and update tickets | OAuth: in Claude Code run `/mcp` → `internal-tickets` → **Authenticate** ([setup A3](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#a3-provide-mcp-credentials-never-in-the-repo)) | ✋ `mcp__internal-tickets__*` (ask) | It can write, so every call needs approval |

Both servers are **examples** for a fictional company. Until you replace them, Claude Code shows them as *failed*. That's harmless.

| Key in each server | Meaning here |
|---|---|
| `type` | `http`. The drift check treats `http`, `sse` and `streamable-http` as remote servers. A server with `command` and no `type` is treated as local (stdio) |
| `url` | The server endpoint. Must match `approved_mcp_url_patterns` ([below](#how-validate-config-checks-mcp-urls)) |
| `headers` | Extra HTTP headers. Credentials must use `${VAR}` expansion |
| `env` | Not used here. For any server, `env` keys whose name contains `TOKEN`, `SECRET`, `KEY` or `PASSWORD` must use `${VAR}` too |

## How the pieces interact

A server is usable only when every layer allows it:

| Layer | Setting | Value here | What it does |
|---|---|---|---|
| 1. Defined | `.mcp.json` → `mcpServers` | `internal-docs`, `internal-tickets` | The project declares the server |
| 2. Approved by the project | `.claude/settings.json` → `enableAllProjectMcpServers` | `false` | Servers in `.mcp.json` aren't approved automatically |
| | `.claude/settings.json` → `enabledMcpjsonServers` | `["internal-docs", "internal-tickets"]` | These are approved by name |
| 3. Workspace trust | (Claude Code) | | Project MCP servers apply only after you trust the folder ([setup A4](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#a4-start-claude-code-and-verify)) |
| 4. Allowed by the organisation | managed `allowManagedMcpServersOnly` | `true` | Only the managed allowlist counts |
| | managed `allowedMcpServers` | `serverUrl: https://*.mcp.internal.example.com/*` | Internal HTTPS servers only. With only `serverUrl` entries, stdio servers are blocked too |
| | managed `deniedMcpServers` | `serverUrl: http://*:*/*` | Plain-HTTP servers are denied |
| 5. Tool permissions | `permissions.allow` / `ask` | `mcp__internal-docs__*` / `mcp__internal-tickets__*` | Whether each tool call needs approval |

The drift check ties layers 1, 2 and 5 together. It fails when:

| Condition | Message |
|---|---|
| A server in `.mcp.json` isn't in `enabledMcpjsonServers` | ``.mcp.json: server `<name>` is not listed in enabledMcpjsonServers (unreviewed server)`` |
| `enabledMcpjsonServers` names a server `.mcp.json` doesn't define | ``.claude/settings.json: enabledMcpjsonServers lists `<name>`, which .mcp.json does not define`` |
| `enableAllProjectMcpServers` isn't `false` | `` `enableAllProjectMcpServers` must be false `` |
| An allow rule names a server that isn't in `enabledMcpjsonServers` (for example `mcp__jira__*`) | `allow rule for unapproved MCP server: mcp__jira__*` |
| An allow rule starts with `mcp__*` (every server) | `forbidden allow rule: mcp__*…` |

The managed allowlist (layer 4) isn't checked by the drift check. Keep `allowedMcpServers` and `approved_mcp_url_patterns` in sync by hand. See [Organisation policy](Settings-Organisation-Policy#mcp-allowmanagedmcpserversonly-allowedmcpservers-deniedmcpservers).

## Allow vs ask: `mcp__internal-docs__*` and `mcp__internal-tickets__*`

Tool names from an MCP server look like `mcp__<server>__<tool>`. A rule ending in `__*` covers every tool of that server.

- ✅ **`mcp__internal-docs__*` is in `allow`.** Searching docs is read-only and frequent. Prompting each time would push people to copy and paste instead.
- ✋ **`mcp__internal-tickets__*` is in `ask`.** The ticket server can change state that other people see. A human approves every call.

Treat every MCP response as untrusted input. Ticket text and docs can contain prompt-injection payloads ([policy §4.3](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#43-mcp-servers)).

## The `${VAR}` credential pattern

Never put a token in `.mcp.json`. Reference an environment variable and export it from your shell profile:

```bash
# ~/.zshrc or ~/.bashrc. The value comes from your password manager.
export INTERNAL_MCP_TOKEN="$(op read 'op://Engineering/internal-mcp/token')"   # example with the 1Password CLI
```

Claude Code expands `${INTERNAL_MCP_TOKEN}` when it connects. Export the variable in the shell that **launches** `claude`; if the server shows *failed*, check that first, then use `/mcp` → reconnect ([setup A6](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#a6-troubleshooting)).

What the drift check treats as a literal credential (`_has_literal` in [`check_ai_guardrails.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/scripts/precommit/check_ai_guardrails.py)): a non-empty string that doesn't contain `${`.

| Where | Checked names | Failure message |
|---|---|---|
| `headers` (remote servers) | `Authorization`, `X-Api-Key`, `Api-Key`, `Cookie`, `Proxy-Authorization` (case-insensitive) | ``server `<name>` header `<header>` holds a literal credential; use ${VAR} expansion`` |
| `env` (any server) | Names containing `TOKEN`, `SECRET`, `KEY` or `PASSWORD` (case-insensitive) | ``server `<name>` env `<key>` holds a literal secret; use ${VAR} expansion`` |

> [!NOTE]
> Other header names aren't checked. A literal value in a header such as `X-Auth-Token` passes the drift check. `gitleaks` and `scan-ai-secrets` may still catch a real-looking token, but name credential headers with one of the checked names, or always use `${VAR}`.

## How `validate-config` checks MCP URLs

`url_allowed()` in [`scripts/precommit/check_ai_guardrails.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/scripts/precommit/check_ai_guardrails.py) checks each remote server's `url` against `approved_mcp_url_patterns` (here only `https://*.mcp.internal.example.com/*`):

1. **Refuse anything ambiguous.** A URL that contains `\`, `@`, whitespace or a control character is rejected outright. Python's URL parser and the WHATWG parser Claude Code uses disagree on these, so the check doesn't guess.
2. **Parse the URL.** An invalid port (for example `:99999`) is rejected. Any user name or password in the URL is rejected.
3. **Match each part separately**, so a host wildcard can't swallow the path:
   - **Scheme** must be equal (`https` ≠ `http`).
   - **Host** is matched with shell-style wildcards, case-insensitively. `*` also matches dots, so `a.b.mcp.internal.example.com` matches.
   - **Port** must be equal only if the pattern names one. This pattern doesn't, so any port passes.
   - **Path** is matched against the pattern's path (`/*`). A URL without a path counts as `/`. The query string isn't checked.

Results for the shipped pattern, from running the function:

| URL | Result | Why |
|---|---|---|
| `https://docs.mcp.internal.example.com/mcp` | ✅ | Matches |
| `https://a.b.mcp.internal.example.com/mcp` | ✅ | `*` matches `a.b` |
| `https://docs.mcp.internal.example.com:8443/mcp` | ✅ | The pattern has no port |
| `https://docs.mcp.internal.example.com` | ✅ | No path counts as `/` |
| `https://mcp.internal.example.com/mcp` | ⛔ | The pattern needs a subdomain before `.mcp.` |
| `http://docs.mcp.internal.example.com/mcp` | ⛔ | Wrong scheme |
| `https://docs.mcp.internal.example.com.evil.net/mcp` | ⛔ | Host doesn't end with the internal domain |
| `https://evil.net/x.mcp.internal.example.com/` | ⛔ | The wildcard can't cross into the path |
| `https://user@docs.mcp.internal.example.com/mcp` | ⛔ | Contains `@` (userinfo) |
| `https://docs.mcp.internal.example.com:99999/mcp` | ⛔ | Invalid port |

A failure prints:

```text
  - .mcp.json: server `internal-docs` url `https://docs.mcp.internal.example.com@evil.example.net/mcp` is not on the approved list (config/claude-guardrails-policy.json)
```

### Local (stdio) servers

A server with `command` (and no remote `type`) is a local process. Its full command line, `[command] + args`, must exactly equal an entry in `approved_mcp_commands`. That list is **empty**, so every stdio server fails:

```text
  - .mcp.json: local (stdio) server `local-fs` runs `npx -y some-mcp-server`, which is not an approved command
```

That matches the policy: local and public third-party MCP servers aren't allowed on workstations ([policy §4.3](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#43-mcp-servers)).

## Adding a new server safely

1. **Get it reviewed.** AppSec reviews the server's data access, its authentication, and whether its outputs could carry prompt injection.
2. **Add it to `.mcp.json`** with `"type": "http"`, an HTTPS URL under your approved domain, and credentials only as `${VAR}`.
3. **Add its name to `enabledMcpjsonServers`** in `.claude/settings.json`.
4. **Pick a permission rule.** Read-only and low-risk: `mcp__<name>__*` in `allow`. Anything that writes or reaches sensitive data: `mcp__<name>__*` in `ask`. Leaving it out of both lists leaves the decision to the permission mode, so add an explicit rule.
5. **If the URL is on a new domain**, add a pattern to `approved_mcp_url_patterns` in the policy file **and** to `allowedMcpServers` in managed settings. Keep patterns tight: a scheme, a specific host suffix and a path.
6. **Document the credential.** Tell developers which variable to export, or how to authenticate through `/mcp`.
7. **Run the checks:** `python3 scripts/precommit/check_ai_guardrails.py validate-config`, then `python3 -m pytest` (`tests/test_config.py` also asserts that every server is HTTPS, internal and uses `${…}` headers).
8. **Open a PR** that explains what the server can read and write. Code owners approve it.

To remove a server, delete it from `.mcp.json` and `enabledMcpjsonServers` together, and remove its `mcp__…` rules.

## Related pages

- [Project settings](Settings-Project)
- [Organisation policy](Settings-Organisation-Policy)
- [Policy baseline](Settings-Policy-Baseline)
- [Environment variables](Settings-Environment-Variables)
- [Changing the guardrails](Use-Case-Changing-the-Guardrails)
- [Troubleshooting](Troubleshooting)
