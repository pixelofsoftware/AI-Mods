`config/claude-guardrails-policy.json` is the machine-readable baseline for this repository's guardrails. The drift check, `scripts/precommit/check_ai_guardrails.py`, compares `.claude/settings.json` and `.mcp.json` against it on every commit, push and pull request, and fails if a control was weakened. The same file lists the paths that must never be committed.

## At a glance

| | |
|---|---|
| **File** | [`config/claude-guardrails-policy.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/config/claude-guardrails-policy.json) |
| **Read by** | [`scripts/precommit/check_ai_guardrails.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/scripts/precommit/check_ai_guardrails.py): `validate-config` and `forbid-paths` |
| **Who edits it** | Code owners (AppSec). Claude asks before editing it (`Edit(/config/claude-guardrails-policy.json)` and `file_guard`) |
| **Enforced by** | Pre-commit hooks `validate-claude-config` and `forbid-ai-artifacts` (on commit and push), and the CI `guardrails` job on every PR |
| **Can developers override it?** | Locally with `--no-verify`, but CI runs the same checks and branch protection blocks the merge |

Legend: ⛔ Deny/Block · ✋ Ask · ⚠️ Warn · ✅ Allow.

**The rule of thumb:** if you change a guardrail on purpose, change this file in the same pull request. Then the reviewer sees the loosening in one place. Every failure ends with:

```text
If the change is intentional, update config/claude-guardrails-policy.json in the same PR so security review sees it.
```

## Run the checks yourself

```bash
python3 scripts/precommit/check_ai_guardrails.py validate-config                 # this repository
python3 scripts/precommit/check_ai_guardrails.py validate-config --root /path    # another checkout or a scratch copy
python3 scripts/precommit/check_ai_guardrails.py forbid-paths <file>...          # what pre-commit runs on staged files
pre-commit run validate-claude-config --all-files                                 # through pre-commit
```

| Exit code | Meaning |
|---|---|
| `0` | No drift, or no forbidden paths |
| `1` | Policy violation. Also returned when `.claude/settings.json` is missing (`.claude/settings.json is missing: the project guardrails were removed`) |
| `2` | Usage or internal error, for example the policy file can't be read or a file isn't valid JSON (`could not read guardrail config: …`) |

If `.mcp.json` is missing, `validate-config` treats it as having no servers. Then every name in `enabledMcpjsonServers` fails as undefined.

## Sections, and how each is enforced

`validate-config` checks sections in this order: required settings, default mode, deny and ask rules, allow rules, hooks, forbidden keys, `env`, sandbox domains, then MCP. It prints every error it finds, not just the first.

### `version` and `description`

`version` is `1`. `description` explains the file's purpose. The checker doesn't read either.

### `required_settings`

| Dotted key | Required value |
|---|---|
| `permissions.disableBypassPermissionsMode` | `"disable"` |
| `enableAllProjectMcpServers` | `false` |
| `sandbox.enabled` | `true` |
| `sandbox.allowUnsandboxedCommands` | `false` |
| `sandbox.autoAllowBashIfSandboxed` | `false` |
| `sandbox.excludedCommands` | `[]` |

**How it's enforced:** each dotted key is looked up in `.claude/settings.json`. A missing key counts as `null`. The value must be exactly equal, type included, so the string `"true"` fails where `true` is required. Adding any entry to `excludedCommands` fails.

```text
  - .claude/settings.json: `sandbox.enabled` must be true (found false)
  - .claude/settings.json: `sandbox.excludedCommands` must be [] (found ["docker"])
```

**Not in this list**, so not enforced: `permissions.blockReadsOutsideWorkingDirectories`, `sandbox.filesystem.denyRead`, `cleanupPeriodDays` and any other `sandbox.network.*` key. Removing them passes the drift check.

### `forbidden_default_modes`

`bypassPermissions`, `auto`, `acceptEdits`.

**How it's enforced:** `permissions.defaultMode` (treated as `default` when missing) must not be one of these. Developers can still switch modes during a session; this only stops the shared file from starting everyone in a permissive mode. Any other value passes.

```text
  - .claude/settings.json: permissions.defaultMode `acceptEdits` is not allowed in shared project settings
```

### `required_deny_rules`

`WebSearch`, `Bash(curl *)`, `Bash(wget *)`, `Bash(nc *)`, `Bash(sudo *)`, `Bash(git push --force *)`, `Bash(git commit --no-verify *)`, `Bash(terraform apply *)`, `Bash(terraform destroy *)`, `Read(**/.env)`, `Read(**/*.pem)`, `Read(~/.ssh/**)`, `Read(~/.aws/**)`.

**How it's enforced:** each rule must appear in `permissions.deny`, as an exact string. The project file has 62 deny rules; only these 13 are required.

```text
  - .claude/settings.json: required deny rule missing: Bash(curl *)
```

### `required_ask_rules`

`WebFetch`, `Bash(git push *)`, `Edit(**/*.tf)`, `Edit(/.claude/**)`.

**How it's enforced:** each rule must be in `permissions.ask` **or** `permissions.deny`. Moving an ask rule to deny is stricter, so it passes.

```text
  - .claude/settings.json: required ask rule missing: WebFetch
```

### `forbidden_allow_rule_patterns`

Each regular expression is searched in every `permissions.allow` rule. One match fails the rule.

| Pattern | Catches | Example that fails |
|---|---|---|
| `^Bash$` | Every shell command | `Bash` |
| `^Bash\(\s*\*` | A rule that starts with a wildcard | `Bash(*)` |
| `^Bash\([^)]*\*:\*` | A Bash rule containing `*:*` | `Bash(npm run *:*)` |
| `^WebFetch` | Any web fetch, including domain-scoped ones | `WebFetch(domain:*)` |
| `^WebSearch` | Web search | `WebSearch` |
| `^mcp__\*` | Every tool of every MCP server | `mcp__*` |
| `^Bash\((?:curl\|wget\|nc\|ncat\|ssh\|scp\|sudo\|su\|env\|printenv)\b` | Network clients, privilege escalation, environment dumps | `Bash(ssh deploy@host)` |
| `^Bash\(git push\b` | Any push without a prompt | `Bash(git push origin main)` |
| `^Bash\((?:terraform\|tofu) (?:apply\|destroy)\b` | Infrastructure changes | `Bash(tofu apply *)` |
| `^Bash\(kubectl (?:delete\|apply)\b` | Cluster changes | `Bash(kubectl apply -f k8s/)` |
| `^Read\(//` | Reads by absolute filesystem path | `Read(//etc/**)` |
| `^Read\(~` | Reads in your home directory | `Read(~/notes/**)` |

```text
  - .claude/settings.json: forbidden allow rule: Bash(*)
  - .claude/settings.json: forbidden allow rule: Bash(git push origin main)
```

A second allow check, not driven by the policy file: any `mcp__<server>__…` allow rule whose server isn't in `enabledMcpjsonServers` fails with `allow rule for unapproved MCP server: mcp__jira__*`.

> [!WARNING]
> These patterns are a deny list, so they can't catch everything. On a scratch copy, `Bash(python3 *)`, `Bash(bash *)`, `Edit(**)` and `Read(/etc/**)` all **passed**. Each of these gives Claude broad power without a prompt. Code-owner review is the only control for them.

### `required_hooks`

| Event | Script | Tools its matcher must cover |
|---|---|---|
| `UserPromptSubmit` | `prompt_guard.py` | none (no matcher needed) |
| `PreToolUse` | `bash_guard.py` | `Bash` |
| `PreToolUse` | `file_guard.py` | `Write`, `Edit` |
| `PreToolUse` | `read_guard.py` | `Read`, `Grep`, `Glob` |

**How it's enforced:** the checker collects every hook in `.claude/settings.json`, keeps only approved ones (see the next section), then checks that each required script is wired on its event. For each listed tool, at least one of that script's matchers must cover it. An empty matcher or `*` covers everything; otherwise the matcher is a regular expression that must **fully** match the tool name. So `Bash|Monitor` covers `Bash`, but `Monitor` alone doesn't.

```text
  - .claude/settings.json: required UserPromptSubmit hook missing: prompt_guard.py
  - .claude/settings.json: PreToolUse hook bash_guard.py must match tool `Bash`
```

The project's matchers also include `Monitor`, `MultiEdit`, `NotebookEdit` and `NotebookRead`. The policy doesn't require those, so removing them passes the drift check.

### `allowed_hook_scripts`

`prompt_guard.py`, `bash_guard.py`, `file_guard.py`, `read_guard.py`.

**How it's enforced:** every hook handler in `.claude/settings.json` must be `"type": "command"` with a command that fully matches:

```text
python3 "${CLAUDE_PROJECT_DIR}/.claude/hooks/<name>.py"
```

and `<name>.py` must be in this list. Anything else, such as another script, extra arguments, a different interpreter, or an `http` hook, fails. So nobody can add a hook that runs arbitrary code from shared settings.

```text
  - .claude/settings.json: PreToolUse hook `python3 /tmp/my_hook.py` is not an approved guardrail script
```

### `forbidden_settings_keys`

`apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `statusLine`, `disableAllHooks`.

**How it's enforced:** none of these may appear as a top-level key in `.claude/settings.json`. Why: the first five configure commands that Claude Code runs outside the hooks, and `apiKeyHelper` and the two AWS keys also decide where credentials come from. `otelHeadersHelper` belongs in [managed settings](Settings-Organisation-Policy). `disableAllHooks` would turn the guards off. For what each key does, see the [Claude Code settings documentation](https://code.claude.com/docs/en/settings).

```text
  - .claude/settings.json: `statusLine` is not allowed in shared project settings
```

### `forbidden_env_patterns`

Each regular expression is searched in every **name** in the `env` block of `.claude/settings.json`.

| Pattern | Blocks | Why |
|---|---|---|
| `^ANTHROPIC_` | `ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL`, … | Credential and endpoint overrides |
| `_BASE_URL$` | Any `*_BASE_URL` | Redirecting API traffic |
| `^CLAUDE_CODE_USE_` | `CLAUDE_CODE_USE_*` | Switching the model provider from a repository |
| `^(?:HTTPS?\|ALL)_PROXY$` | `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` | Routing traffic through a proxy |
| `(?i)^https?_proxy$` | `http_proxy`, `https_proxy` (any case) | The lowercase forms |
| `^NODE_OPTIONS$` | `NODE_OPTIONS` | Injecting code into the Node.js runtime |
| `^NODE_TLS_REJECT_UNAUTHORIZED$` | `NODE_TLS_REJECT_UNAUTHORIZED` | Turning off TLS certificate checks |
| `^CLAUDE_GUARDRAIL_AUDIT$` | `CLAUDE_GUARDRAIL_AUDIT` | Turning off the hook audit log ([Audit logs](Audit-Logs)) |

```text
  - .claude/settings.json: env `ANTHROPIC_BASE_URL` is not allowed in shared project settings
```

Not covered: lowercase `all_proxy`, `NO_PROXY`, and `CLAUDE_GUARDRAIL_AUDIT_DIR`. This repository's docs don't say whether `env` from settings reaches the hook processes, so review any `env` addition by hand. Separately, any `OTEL_*` name only prints a note, because Claude Code ignores those in project settings.

### `allowed_sandbox_domains`

`github.com`, `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `proxy.golang.org`, `artifacts.internal.example.com`.

**How it's enforced:** every entry in `sandbox.network.allowedDomains` must be in this list, as an exact string. Removing a domain from the settings is fine; adding one that isn't here fails.

```text
  - .claude/settings.json: sandbox domain `pastebin.com` is not in allowed_sandbox_domains
```

### `approved_mcp_url_patterns` and `approved_mcp_commands`

| Key | Value | Used for |
|---|---|---|
| `approved_mcp_url_patterns` | `["https://*.mcp.internal.example.com/*"]` | Every remote server URL in `.mcp.json` must match one, using `url_allowed()` |
| `approved_mcp_commands` | `[]` | Every local (stdio) server's `[command] + args` must equal one entry. Empty, so all stdio servers fail |

The MCP checks also reject literal credentials in headers and `env`, and require `.mcp.json` and `enabledMcpjsonServers` to list the same servers. The details, with real results, are on [MCP servers](Settings-MCP-Servers#how-validate-config-checks-mcp-urls).

```text
  - .mcp.json: server `internal-tickets` header `Authorization` holds a literal credential; use ${VAR} expansion
  - .mcp.json: local (stdio) server `local-fs` runs `npx -y some-mcp-server`, which is not an approved command
  - .mcp.json: server `local-fs` is not listed in enabledMcpjsonServers (unreviewed server)
```

### `forbidden_paths` and `allowed_paths`

Used by `forbid-paths`, which the `forbid-ai-artifacts` pre-commit hook runs on staged files at commit and push time.

| Group | `forbidden_paths` entries |
|---|---|
| Claude Code local and session data | `.claude/settings.local.json`, `.claude/audit/*`, `.claude/**/*.jsonl`, `.claude/projects/*`, `.claude/todos/*`, `.claude/shell-snapshots/*`, `.claude.json`, `.claude.json.backup*`, `CLAUDE.local.md` |
| Local MCP overrides | `.mcp.local.json`, `*.mcp.local.json` |
| Environment files | `.env`, `.env.*`, `.envrc` |
| Keys and keystores | `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.kdbx`, `*.ppk`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`, `anthropic_api_key*`, `*.anthropic-key` |
| Terraform state | `*.tfstate`, `*.tfstate.backup`, `*.tfstate.*` |
| Cloud and service credentials | `credentials.json`, `client_secret*.json`, `client_secrets.json`, `service-account*.json`, `service_account*.json`, `kubeconfig*`, `**/secrets/*` |
| Tool credential files | `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.pgpass` |

`allowed_paths`: `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.defaults`, `*.pub`.

**How matching works** (`_matches()`, gitignore-like):

1. Backslashes become `/` and a leading `./` is removed.
2. **Allowed paths win.** If a path matches any `allowed_paths` entry, it passes, even if it also matches a forbidden one. So `deploy/id_rsa.pub` passes while `deploy/id_rsa` fails.
3. A pattern **without `/`** (ignoring a trailing `/*`) matches the file name at any depth: `*.key` matches `certs/tls.key`.
4. A pattern **with `/`** matches the path, or the path under any parent directory. `**/` can stand for zero or more directories, so `.claude/**/*.jsonl` matches `.claude/x.jsonl` too. Matching uses shell-style wildcards, where `*` can also match `/`.
5. **Session transcripts by content:** any staged `.jsonl` file, anywhere, is blocked if its first 20 lines contain `"sessionId"` and a `"type":"user"` or `"type":"assistant"` record.

A failure prints:

```text
Blocked: these files must not be committed (AI session data, local config or secrets):
  - .claude/settings.local.json
  - CLAUDE.local.md
  - .mcp.local.json

Unstage with `git restore --staged <file>` and make sure it is in .gitignore.
If a secret was ever committed or pasted into a prompt, rotate it.
```

[`tests/test_config.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/test_config.py) shows more cases: `config/.env.production`, `certs/tls.key`, `infra/terraform.tfstate` and `keys/service-account-prod.json` are blocked; `.env.example`, `src/app.py` and `.claude/settings.json` pass.

Keep [`.gitignore`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.gitignore) in step with this list, so the files never show up as untracked in the first place. The two lists are close but not identical: `.gitignore` also ignores `.terraform/`, and only the policy lists `anthropic_api_key*` and `*.anthropic-key`.

## A full failing run

This is real output from `validate-config --root <scratch copy>`, after loosening a copy of the settings and `.mcp.json` in a temporary directory (the real files weren't touched):

```text
note: OTEL_* exporter variables in .claude/settings.json are ignored by Claude Code; set them in managed settings.
AI guardrail configuration drift detected:
  - .claude/settings.json: `sandbox.enabled` must be true (found false)
  - .claude/settings.json: `sandbox.excludedCommands` must be [] (found ["docker"])
  - .claude/settings.json: permissions.defaultMode `acceptEdits` is not allowed in shared project settings
  - .claude/settings.json: required deny rule missing: Bash(curl *)
  - .claude/settings.json: required ask rule missing: WebFetch
  - .claude/settings.json: forbidden allow rule: Bash(git push origin main)
  - .claude/settings.json: forbidden allow rule: Read(~/notes/**)
  - .claude/settings.json: forbidden allow rule: Bash(*)
  - .claude/settings.json: allow rule for unapproved MCP server: mcp__jira__*
  - .claude/settings.json: PreToolUse hook `python3 /tmp/my_hook.py` is not an approved guardrail script
  - .claude/settings.json: PreToolUse hook bash_guard.py must match tool `Bash`
  - .claude/settings.json: `statusLine` is not allowed in shared project settings
  - .claude/settings.json: env `ANTHROPIC_BASE_URL` is not allowed in shared project settings
  - .claude/settings.json: sandbox domain `pastebin.com` is not in allowed_sandbox_domains
  - .mcp.json: server `internal-docs` url `https://docs.mcp.internal.example.com@evil.example.net/mcp` is not on the approved list (config/claude-guardrails-policy.json)
  - .mcp.json: server `internal-tickets` header `Authorization` holds a literal credential; use ${VAR} expansion
  - .mcp.json: local (stdio) server `local-fs` runs `npx -y some-mcp-server`, which is not an approved command
  - .mcp.json: server `local-fs` is not listed in enabledMcpjsonServers (unreviewed server)

If the change is intentional, update config/claude-guardrails-policy.json in the same PR so security review sees it.
```

To reproduce safely, copy the three files into a temporary directory and point `--root` at it:

```bash
tmp="$(mktemp -d)"
mkdir -p "$tmp/.claude" "$tmp/config"
cp .claude/settings.json "$tmp/.claude/"
cp .mcp.json "$tmp/"
cp config/claude-guardrails-policy.json "$tmp/config/"
# edit the copies in "$tmp", then:
python3 scripts/precommit/check_ai_guardrails.py validate-config --root "$tmp"
```

## What the baseline doesn't check

Know the gaps, so reviewers look for them:

| Not checked | Example that passes |
|---|---|
| Settings outside `required_settings` | Removing `blockReadsOutsideWorkingDirectories`, `sandbox.filesystem.denyRead` or `cleanupPeriodDays` |
| Deny and ask rules outside the required lists | Removing `Bash(ssh *)` from deny or `Bash(docker *)` from ask |
| Broad allow rules that don't match a forbidden pattern | `Bash(python3 *)`, `Bash(bash *)`, `Edit(**)`, `Read(/etc/**)` |
| Default modes not in the forbidden list | `"defaultMode": "dontAsk"` |
| `env` names outside the forbidden patterns | `CLAUDE_GUARDRAIL_AUDIT_DIR`, lowercase `all_proxy` |
| Hook matchers for tools that aren't required | Dropping `MultiEdit` or `NotebookRead` from a matcher |
| Header names outside the checked set | A literal in `X-Auth-Token` |
| `enterprise/managed-settings.json` | Not read by the checker at all |
| Personal files | `.claude/settings.local.json` is never read (and can't be committed) |

[Policy §7](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#7-exceptions-false-positives-and-incidents) says approved exceptions are recorded in this file. It has no dedicated exceptions section today, so record an exception by changing the relevant list and explaining it in the PR.

## Related pages

- [Project settings](Settings-Project)
- [MCP servers](Settings-MCP-Servers)
- [Pre-commit](Settings-Pre-Commit)
- [Commit and merge gates](Guardrail-Commit-and-Merge-Gates)
- [Changing the guardrails](Use-Case-Changing-the-Guardrails)
- [False positives and exceptions](Use-Case-False-Positives-and-Exceptions)
