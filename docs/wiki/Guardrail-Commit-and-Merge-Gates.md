The commit and merge gates are the guardrails that don't depend on Claude Code at all. Pre-commit checks every commit on your machine, the `ai-guardrails` workflow repeats the checks on every pull request, and CODEOWNERS makes a human review changes to infrastructure, security code and the guardrails. This page lists every check they run.

## At a glance

| | |
|---|---|
| **Runs on** | `git commit` and `git push` (pre-commit), every pull request and every push to `main` (CI) |
| **Decides** | Commit or push fails; CI check fails; merge needs code-owner approval |
| **Can be skipped?** | Locally, yes (`--no-verify`). CI repeats every check, and branch protection enforces CI and CODEOWNERS |
| **Fails** | Exit code 1 for a policy violation, 2 for a usage or internal error. Either fails the commit |
| **Source** | [`.pre-commit-config.yaml`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.pre-commit-config.yaml), [`scripts/precommit/check_ai_guardrails.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/scripts/precommit/check_ai_guardrails.py), [`.github/workflows/ai-guardrails.yml`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.github/workflows/ai-guardrails.yml), [`.github/CODEOWNERS`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.github/CODEOWNERS) |

Legend: ⛔ Deny/Block · ✋ Ask · ⚠️ Warn · ✅ Allow

## The layers

| Layer | When | What it adds |
|---|---|---|
| Pre-commit | Every commit, and some hooks on every push | Fast feedback on your machine |
| CI `guardrails` job | Every pull request, and pushes to `main` | Runs the tests and all pre-commit hooks on all files, so a local `--no-verify` only moves the failure to the pull request |
| CODEOWNERS + branch protection | Every pull request | A named human approves changes to sensitive paths |

Pre-commit installs itself for both `pre-commit` and `pre-push` (`default_install_hook_types`). Hooks run at the `pre-commit` stage unless they say otherwise. Minimum pre-commit version: 3.5.0. Setup and day-to-day use are on [Pre-commit settings](Settings-Pre-Commit).

## Every pre-commit hook

| Hook | Source | Stage | ⛔ Fails the commit when… |
|---|---|---|---|
| `detect-private-key` | pre-commit-hooks v6.0.0 | commit | A file contains a private key block |
| `check-added-large-files` | pre-commit-hooks | commit | An added file is over 1,024 KB (`--maxkb=1024`) |
| `check-merge-conflict` | pre-commit-hooks | commit | A file contains merge conflict markers |
| `check-json` | pre-commit-hooks | commit | A `.json` file doesn't parse |
| `check-yaml` | pre-commit-hooks | commit | A YAML file doesn't parse (multiple documents allowed) |
| `check-executables-have-shebangs` | pre-commit-hooks | commit | An executable file has no shebang |
| `no-commit-to-branch` | pre-commit-hooks | commit | You commit directly to `main` or `master` |
| `gitleaks` | gitleaks v8.30.1 | commit | gitleaks finds a secret |
| `forbid-ai-artifacts` | local | commit, push | A path is on the forbidden list (see [forbid-paths](#forbid-paths)) |
| `validate-claude-config` | local | commit, push | Settings or MCP config drift from the policy (see [validate-config](#validate-config)). Runs on every commit, whatever changed |
| `scan-ai-secrets` | local | commit | A text file outside `tests/` and `.sdlc/` contains a credential (see [scan-secrets](#scan-secrets)) |
| `bandit` | PyCQA bandit 1.9.4 | commit | Python security issues at medium severity **and** medium confidence or higher; config from `pyproject.toml` (skips `tests` and `.sdlc`) |
| `checkov` | checkov 3.3.30 | commit | Misconfiguration in Terraform, CloudFormation, Kubernetes, Helm, Dockerfiles, GitHub Actions or Bicep. Runs on `.tf`, `.tfvars`, `.yml`/`.yaml`, `.json`, `.bicep` and `Dockerfile*` |

The three local hooks are subcommands of one stdlib-only script, `scripts/precommit/check_ai_guardrails.py`, so they run in pre-commit, in CI and on a bare workstation.

## forbid-paths

**Hook:** `forbid-ai-artifacts` → `check_ai_guardrails.py forbid-paths FILE...`

Fails if a staged path is a file that must never be committed. The lists live in [`config/claude-guardrails-policy.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/config/claude-guardrails-policy.json) (see [Policy baseline](Settings-Policy-Baseline)):

| Kind | `forbidden_paths` patterns |
|---|---|
| Claude Code local state | `.claude/settings.local.json`, `.claude/audit/*`, `.claude/**/*.jsonl`, `.claude/projects/*`, `.claude/todos/*`, `.claude/shell-snapshots/*`, `.claude.json`, `.claude.json.backup*`, `CLAUDE.local.md`, `.mcp.local.json`, `*.mcp.local.json` |
| Environment files | `.env`, `.env.*`, `.envrc` |
| Keys and keystores | `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.kdbx`, `*.ppk`, `id_rsa*`, `id_dsa*`, `id_ed25519*`, `id_ecdsa*`, `anthropic_api_key*`, `*.anthropic-key` |
| Credential files | `credentials.json`, `client_secret*.json`, `client_secrets.json`, `service-account*.json`, `service_account*.json`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.pgpass`, `kubeconfig*`, `**/secrets/*` |
| Terraform state | `*.tfstate`, `*.tfstate.backup`, `*.tfstate.*` |

How matching works:

- `allowed_paths` win: `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.defaults` and `*.pub` are never blocked.
- A pattern without a `/` matches the file name at any depth (`*.pem` blocks `certs/server.pem`).
- A pattern with a `/` matches the path from the repository root or from any directory; `**/` matches zero or more directories.
- Separately, **any** `.jsonl` file whose first 20 lines contain `"sessionId"` and a `"type":"user"` or `"type":"assistant"` record is treated as a Claude Code session transcript and blocked, wherever it is.

Real output:

```text
Blocked: these files must not be committed (AI session data, local config or secrets):
  - .env.production
  - .claude/settings.local.json
  - .claude/audit/guardrail-events.jsonl
  - infra/prod.tfstate
  - config/secrets/db.yaml
  - CLAUDE.local.md

Unstage with `git restore --staged <file>` and make sure it is in .gitignore.
If a secret was ever committed or pasted into a prompt, rotate it.
```

In the same run, `.env.example`, `keys/deploy.pub` and `src/app.py` passed.

**Why.** Session transcripts hold whole conversations, possibly including pasted data. Local settings and audit logs are personal. Keys and state files are secrets.

**False positive?** Rename the file, or if it's a template, use one of the allowed `.env.*` suffixes. Changing the lists is a policy change that needs security review.

## validate-config

**Hook:** `validate-claude-config` → `check_ai_guardrails.py validate-config [--root DIR]`

Compares `.claude/settings.json` and `.mcp.json` with `config/claude-guardrails-policy.json` and fails on any drift that weakens the guardrails. It runs on every commit and push (`always_run: true`). The values below are the current policy; [Policy baseline](Settings-Policy-Baseline) explains each one.

### Checks on `.claude/settings.json`

| Check | Policy key | Fails when |
|---|---|---|
| Required settings | `required_settings` | Any of these differs: `permissions.disableBypassPermissionsMode` = `"disable"`, `enableAllProjectMcpServers` = `false`, `sandbox.enabled` = `true`, `sandbox.allowUnsandboxedCommands` = `false`, `sandbox.autoAllowBashIfSandboxed` = `false`, `sandbox.excludedCommands` = `[]` |
| Default mode | `forbidden_default_modes` | `permissions.defaultMode` is `bypassPermissions`, `auto` or `acceptEdits` |
| Deny rules | `required_deny_rules` | A required deny rule is missing (13 rules, e.g. `WebSearch`, `Bash(curl *)`, `Bash(sudo *)`, `Bash(terraform apply *)`, `Read(**/.env)`, `Read(~/.ssh/**)`) |
| Ask rules | `required_ask_rules` | A required ask rule is in neither the ask nor the deny list (`WebFetch`, `Bash(git push *)`, `Edit(**/*.tf)`, `Edit(/.claude/**)`) |
| Allow rules | `forbidden_allow_rule_patterns` | An allow rule matches a forbidden pattern: bare `Bash`, `Bash(*…)`, a `Bash(…*:*` wildcard, anything starting `WebFetch`, `WebSearch` or `mcp__*`, `Bash(` followed by `curl`, `wget`, `nc`, `ncat`, `ssh`, `scp`, `sudo`, `su`, `env` or `printenv`, `Bash(git push…`, `Bash(terraform`/`tofu apply`/`destroy…`, `Bash(kubectl delete`/`apply…`, `Read(//…` and `Read(~…` |
| MCP allow rules | – | An `mcp__<server>__…` allow rule names a server that isn't in `enabledMcpjsonServers` |
| Hook commands | `allowed_hook_scripts` | Any hook, on any event, isn't exactly `python3 "${CLAUDE_PROJECT_DIR}/.claude/hooks/<script>.py"` with a `type` of `command` and a script from `prompt_guard.py`, `bash_guard.py`, `file_guard.py`, `read_guard.py` |
| Required hooks | `required_hooks` | `prompt_guard.py` isn't on `UserPromptSubmit`, or `bash_guard.py`/`file_guard.py`/`read_guard.py` aren't on `PreToolUse` with a matcher that covers `Bash`; `Write` and `Edit`; `Read`, `Grep` and `Glob` respectively. A matcher of `""` or `*` covers everything; otherwise it's a full regex match |
| Forbidden keys | `forbidden_settings_keys` | `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `statusLine` or `disableAllHooks` is present |
| Forbidden env | `forbidden_env_patterns` | An `env` name matches `^ANTHROPIC_`, `_BASE_URL$`, `^CLAUDE_CODE_USE_`, an HTTP(S)/ALL proxy variable, `NODE_OPTIONS`, `NODE_TLS_REJECT_UNAUTHORIZED` or `CLAUDE_GUARDRAIL_AUDIT` |
| Sandbox domains | `allowed_sandbox_domains` | `sandbox.network.allowedDomains` has a domain outside: `github.com`, `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `proxy.golang.org`, `artifacts.internal.example.com` |
| OTEL note | – | Never fails. Prints a note if `OTEL_*` variables are in project settings, because Claude Code ignores them there |

### Checks on `.mcp.json`

| Check | Fails when |
|---|---|
| Remote server URL | An `http`, `sse` or `streamable-http` server's URL isn't approved by `approved_mcp_url_patterns` (currently `https://*.mcp.internal.example.com/*`). Scheme, host (with `*` wildcards), port and path are matched separately, so a wildcard can't cross a `/`. URLs with a backslash, `@`, whitespace, control characters or user info are always rejected |
| Literal header credential | An `Authorization`, `X-Api-Key`, `Api-Key`, `Cookie` or `Proxy-Authorization` header holds a literal value instead of `${VAR}` |
| Local (stdio) server | Its command and arguments aren't exactly one of `approved_mcp_commands` (currently none, so any stdio server fails) |
| Literal env secret | An `env` key containing `TOKEN`, `SECRET`, `KEY` or `PASSWORD` holds a literal value |
| Enabled vs defined | A server is defined but not in `enabledMcpjsonServers`, or enabled but not defined |

A missing `.mcp.json` counts as no servers.

### Output and exit codes

Real output from a copy of the repository with a weakened `settings.json`:

```text
AI guardrail configuration drift detected:
  - .claude/settings.json: permissions.defaultMode `bypassPermissions` is not allowed in shared project settings
  - .claude/settings.json: required deny rule missing: Bash(curl *)
  - .claude/settings.json: forbidden allow rule: Bash(curl *)
  - .claude/settings.json: required PreToolUse hook missing: bash_guard.py
  - .claude/settings.json: env `ANTHROPIC_BASE_URL` is not allowed in shared project settings
  - .claude/settings.json: sandbox domain `evil.example` is not in allowed_sandbox_domains

If the change is intentional, update config/claude-guardrails-policy.json in the same PR so security review sees it.
```

And with an unreviewed MCP server:

```text
AI guardrail configuration drift detected:
  - .mcp.json: server `rogue` url `https://mcp.evil.example/x` is not on the approved list (config/claude-guardrails-policy.json)
  - .mcp.json: server `rogue` header `Authorization` holds a literal credential; use ${VAR} expansion
  - .mcp.json: local (stdio) server `local` runs `npx some-mcp`, which is not an approved command
  - .mcp.json: server `local` is not listed in enabledMcpjsonServers (unreviewed server)
  - .mcp.json: server `rogue` is not listed in enabledMcpjsonServers (unreviewed server)
```

| Situation | Exit code |
|---|---|
| No drift | 0 |
| Drift found, or `.claude/settings.json` is missing (`the project guardrails were removed`) | 1 |
| Policy, settings or `.mcp.json` can't be read or parsed | 2 |

`--root DIR` checks another checkout; the default is the repository the script lives in.

**Why.** The guardrails are only as strong as their configuration. This check makes loosening them a visible, reviewed change instead of a quiet edit.

**False positive?** If the change is intended, update the policy file in the same pull request and explain why. Both files are code-owned. See [Changing the guardrails](Use-Case-Changing-the-Guardrails).

## scan-secrets

**Hook:** `scan-ai-secrets` → `check_ai_guardrails.py scan-secrets FILE...`

Runs the shared detectors from `scripts/claude_safeguard.py` (the same ones the Claude Code hooks use) over each staged text file and fails on any finding that is in a credential category **and** `CRITICAL` severity. That's the same bar as the [File guard](Guardrail-File-Guard)'s deny: private keys, cloud and API keys, bearer tokens and passwords in URLs. JWTs, `password=` assignments and personal data don't fail this hook. See [Detectors reference](Detectors-Reference#how-severities-become-decisions).

- Reads at most the first 2,000,000 bytes of a file.
- Skips files with a NUL byte in the first 8 KB (binary).
- Skips paths it can't read.
- The pre-commit config excludes `tests/` and `.sdlc/` and only passes text files.

Real output for a file with a fake key built at runtime:

```text
Possible hardcoded credentials (values not shown):
  - client.py:3: anthropic_api_key (API_KEY)

Move the value to an environment variable or the secret manager, and rotate it if it is real.
```

The value is never printed. Exit code 1 on a finding, 0 otherwise.

**False positive?** Use a placeholder (`${API_KEY}`, `<your-key>`) or read the value from the environment. Test fixtures should build credential-shaped strings at runtime (see `tests/conftest.py`).

## gitleaks

gitleaks adds entropy checks and a large set of provider rules on top of `scan-ai-secrets`. The upstream pre-commit hook definition we inspected runs `gitleaks git --pre-commit --redact --staged --verbose`, which scans **staged** changes. That's what you want on a commit. In CI, `pre-commit run --all-files` runs on a fresh checkout with nothing staged, so check your CI logs to confirm what gitleaks actually scanned there; `scan-ai-secrets` and `detect-private-key` do run over all files.

## The CI workflow

[`.github/workflows/ai-guardrails.yml`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.github/workflows/ai-guardrails.yml), workflow name `ai-guardrails`, job `guardrails`:

| Setting | Value |
|---|---|
| Triggers | `pull_request`, and `push` to `main` |
| Token permissions | `contents: read` |
| Concurrency | One run per ref; a new push cancels the old run |
| Runner and timeout | `ubuntu-latest`, 20 minutes |
| Checkout | `actions/checkout` pinned to a commit SHA, full history, `persist-credentials: false` |
| Python | `actions/setup-python` pinned to a commit SHA, Python 3.12 |
| Tooling | `pre-commit==4.7.0`, `pytest>=8`, `pyyaml>=6` |

Steps:

1. `python -m pytest`: the whole test suite, including the hook regression tests and the drift tests.
2. `pre-commit run --all-files --show-diff-on-failure` with `SKIP: no-commit-to-branch`, because in CI branch protection, not that hook, guards `main`.

Make the `guardrails` check **required** in branch protection. Otherwise a failing run is only advice.

## CODEOWNERS

[`.github/CODEOWNERS`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.github/CODEOWNERS) names an owner for each sensitive path. In this repository every entry is `@pixelofsoftware`; replace it with your teams (for example AppSec and Platform Engineering).

| Area | Paths |
|---|---|
| Infrastructure and deployment | `*.tf`, `*.tfvars`, `*.hcl`, `Dockerfile*`, `**/k8s/`, `**/helm/`, `.github/workflows/` |
| Security-critical code | `**/auth/`, `**/security/`, `**/crypto/` |
| The guardrails | `.claude/`, `.mcp.json`, `CLAUDE.md`, `.pre-commit-config.yaml`, `config/claude-guardrails-policy.json`, `scripts/claude_safeguard.py`, `scripts/precommit/`, `enterprise/`, `docs/claude-guardrails.md`, `docs/claude-guardrails-setup.md`, `scripts/setup_guardrails.sh`, `pyproject.toml`, `.gitignore`, `.github/CODEOWNERS` |

CODEOWNERS only blocks a merge when branch protection has **Require review from Code Owners** turned on.

The CODEOWNERS list is narrower than the [File guard](Guardrail-File-Guard)'s ask patterns. For example, YAML under `infra/` or `deploy/`, compose files, and `oauth…`, `iam` or `permissions` code ask in Claude Code but have no code owner here. Add owners for the paths that matter in your repository.

## Branch protection

The README recommends these settings for `main`. They live in GitHub, not in this repository, so nothing here can check them:

- Require the `guardrails` status check.
- Require review from Code Owners.
- Block force pushes.

## Pull request template

[`.github/pull_request_template.md`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.github/pull_request_template.md) asks the author to say whether the change makes a guard stricter or **loosens** one, and to confirm tests, synthetic test data and a matching policy-file update.

## What `--no-verify` does and doesn't do

| | Locally | In CI |
|---|---|---|
| Developer runs `git commit --no-verify` | Skips every pre-commit hook | Every check runs again on the pull request |
| Claude runs `git commit --no-verify` | ⛔ Denied by the [Bash guard](Guardrail-Bash-Guard#guardrail_bypass) and the `Bash(git commit --no-verify *)` deny rule | – |

## Try it

```bash
pre-commit run --all-files                                        # everything CI runs
python3 scripts/precommit/check_ai_guardrails.py validate-config   # just the drift check
```

## Related pages

- [Pre-commit settings](Settings-Pre-Commit)
- [Policy baseline](Settings-Policy-Baseline)
- [Changing the guardrails](Use-Case-Changing-the-Guardrails)
- [Detectors reference](Detectors-Reference)
- [Organisation rollout](Use-Case-Organisation-Rollout)
- [Limitations and threat model](Limitations-and-Threat-Model)
