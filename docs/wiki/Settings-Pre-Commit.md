`.pre-commit-config.yaml` is the commit gate. It runs 13 hooks: hygiene checks, two secret scanners, three AI-specific checks from this repository, and SAST for Python and infrastructure files. CI runs the same file on every pull request, so skipping it locally only moves the failure to the PR.

## At a glance

| | |
|---|---|
| **Files** | [`.pre-commit-config.yaml`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.pre-commit-config.yaml), [`pyproject.toml`](https://github.com/pixelofsoftware/AI-Mods/blob/main/pyproject.toml) (bandit and pytest config), [`scripts/precommit/check_ai_guardrails.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/scripts/precommit/check_ai_guardrails.py) |
| **Who edits it** | Code owners. Claude asks before editing either file (`Edit(/.pre-commit-config.yaml)`, `Edit(/pyproject.toml)` and `file_guard`) |
| **Enforced by** | Git hooks installed by `pre-commit install` (commit and push), then the CI `guardrails` job in [`.github/workflows/ai-guardrails.yml`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.github/workflows/ai-guardrails.yml) |
| **Can developers override it?** | Locally, yes (`--no-verify`). Claude can't: `bash_guard` and the deny rules block `--no-verify`, `SKIP=…` and `core.hooksPath` changes. CI and branch protection can't be skipped |

Legend: ⛔ Deny/Block · ✋ Ask · ⚠️ Warn · ✅ Allow.

## Install and run

```bash
pre-commit install --install-hooks      # or scripts/setup_guardrails.sh, which does this for you
pre-commit run --all-files              # everything, as CI does
pre-commit run gitleaks --all-files     # one hook, by id
pre-commit run scan-ai-secrets --files src/app.py
pre-commit run --hook-stage pre-push --all-files   # the push-time hooks
```

For Claude, `pre-commit run` and `pre-commit run --all-files` are ✅ allowlisted. Other forms, such as running one hook, aren't on the allowlist, so the permission mode decides whether Claude asks.

## Top-level keys

| Key | Value | What it does | Why |
|---|---|---|---|
| `minimum_pre_commit_version` | `"3.5.0"` | Older pre-commit versions refuse to run the file | A clear error instead of odd behaviour on an old install. The setup script installs `pre-commit>=4.7`; CI pins `pre-commit==4.7.0` |
| `default_install_hook_types` | `[pre-commit, pre-push]` | `pre-commit install` installs both git hooks | Some checks run again at push time, after commits made with `--no-verify` |
| `default_stages` | `[pre-commit]` | Hooks without their own `stages` run only at commit time | Keeps pushes fast |

## Every hook

| # | Hook id | Repo and pin | Args / options | Stages | What it catches |
|---|---|---|---|---|---|
| 1 | `detect-private-key` | `pre-commit/pre-commit-hooks` `v6.0.0` | | commit | Private key blocks in any text file |
| 2 | `check-added-large-files` | same | `--maxkb=1024` | commit, push | Files over 1 MB: data dumps, binaries, model files |
| 3 | `check-merge-conflict` | same | | commit | Leftover conflict markers |
| 4 | `check-json` | same | | commit | Invalid JSON, such as a broken `.claude/settings.json` or `.mcp.json` |
| 5 | `check-yaml` | same | `--allow-multiple-documents` | commit | Invalid YAML. Multi-document files (Kubernetes manifests) are allowed |
| 6 | `check-executables-have-shebangs` | same | | commit, push | Executable files without a `#!` line |
| 7 | `no-commit-to-branch` | same | `--branch main --branch master` | commit | Direct commits to `main` or `master`. CI skips it, because branch protection does this job there |
| 8 | `gitleaks` | `gitleaks/gitleaks` `v8.30.1` | | commit | Secrets in staged changes, using gitleaks' default provider rules and entropy checks. Runs `gitleaks git --pre-commit --redact --staged --verbose`, so values are masked in its output |
| 9 | `forbid-ai-artifacts` | `local` | `forbid-paths` on staged file names | commit, push | Claude session transcripts, `settings.local.json`, audit logs, local MCP configs, `.env*`, keys, Terraform state and other credential files ([Policy baseline](Settings-Policy-Baseline#forbidden_paths-and-allowed_paths)) |
| 10 | `validate-claude-config` | `local` | `validate-config`; `pass_filenames: false`, `always_run: true` | commit, push | Any change to `.claude/settings.json` or `.mcp.json` that drifts from the policy file ([Policy baseline](Settings-Policy-Baseline)) |
| 11 | `scan-ai-secrets` | `local` | `scan-secrets` on text files; `exclude: ^(tests/\|\.sdlc/)` | commit | Credentials, using the same detectors as the Claude Code hooks |
| 12 | `bandit` | `PyCQA/bandit` `1.9.4` | `-c pyproject.toml --severity-level medium --confidence-level medium`; extra dependency `bandit[toml]` | commit | Python security issues of medium severity and confidence or higher |
| 13 | `checkov` | `bridgecrewio/checkov` `3.3.30` | `files:` override; `--quiet --compact --framework terraform,cloudformation,kubernetes,helm,dockerfile,github_actions,bicep` | commit | Insecure Terraform, CloudFormation, Kubernetes, Helm, Dockerfiles, GitHub Actions and Bicep |

Stages come from each hook's upstream manifest when it sets them, otherwise from `default_stages`. That's why `check-added-large-files` and `check-executables-have-shebangs` also run on push.

## Hook details

### The three local hooks

All three call `scripts/precommit/check_ai_guardrails.py` with `language: python`. It uses only the standard library and exits `0` (ok), `1` (policy violation) or `2` (usage or internal error).

**`forbid-ai-artifacts`** gets the staged file names. It blocks a file if it matches `forbidden_paths` and not `allowed_paths`, or if it's a `.jsonl` file that looks like a Claude Code session transcript. Output:

```text
Blocked: these files must not be committed (AI session data, local config or secrets):
  - .claude/settings.local.json

Unstage with `git restore --staged <file>` and make sure it is in .gitignore.
If a secret was ever committed or pasted into a prompt, rotate it.
```

**`validate-claude-config`** ignores file names and always runs, so deleting `.claude/settings.json` can't skip it. See [Policy baseline](Settings-Policy-Baseline) for every check and message.

**`scan-ai-secrets`** reads up to 2,000,000 bytes of each text file and skips files with a NUL byte in the first 8 KB (binary). It reports only CRITICAL credential findings (private keys, API keys, cloud credentials, bearer tokens, passwords in URLs), with the file, line, rule and category, but never the value:

```text
Possible hardcoded credentials (values not shown):
  - src/client.py:12: github_token (API_KEY)

Move the value to an environment variable or the secret manager, and rotate it if it is real.
```

It skips `tests/` and `.sdlc/`, where credential-shaped strings are built at runtime for tests. Detector list: [Detectors reference](Detectors-Reference).

### `gitleaks`

`pass_filenames` is off: gitleaks reads the staged diff itself. There's no `.gitleaks.toml` in this repository, so it uses gitleaks' built-in rules. If you add one, note that `file_guard` already treats `.gitleaks.toml` as a guardrail file and asks before Claude edits it.

### `bandit`

`-c pyproject.toml` loads the `[tool.bandit]` table, which needs the `bandit[toml]` extra. `--severity-level medium --confidence-level medium` reports only findings that are at least medium on both scales, to keep the noise down.

### `checkov` and the `files` override

Upstream, the `checkov` hook runs `checkov -d .` (the whole directory, `pass_filenames: false`) and triggers only when a `\.tf$` file changes. This repository overrides `files` so it also triggers on other infrastructure files:

```yaml
files: (\.tf|\.tfvars|\.ya?ml|\.json|\.bicep|(^|/)Dockerfile[^/]*)$
```

Because the entry is `checkov -d .`, any matching staged file makes checkov scan the whole repository with the listed frameworks, not just the changed file. `--quiet` prints failed checks only; `--compact` drops code snippets from the output.

## What runs where

| Hook | `git commit` | `git push` | CI |
|---|---|---|---|
| `forbid-ai-artifacts`, `validate-claude-config` | ✅ | ✅ | ✅ |
| `check-added-large-files`, `check-executables-have-shebangs` | ✅ | ✅ | ✅ |
| `no-commit-to-branch` | ✅ | | Skipped (`SKIP: no-commit-to-branch`) |
| All others | ✅ | | ✅ |

CI runs `python -m pytest`, then `pre-commit run --all-files --show-diff-on-failure` on Python 3.12, with `pre-commit==4.7.0`. See [Commit and merge gates](Guardrail-Commit-and-Merge-Gates).

## Updating the pinned versions safely

The config's own comment says pins are bumped with `pre-commit autoupdate` in a reviewed PR.

1. Create a branch. Don't do this on `main`.
2. Run `pre-commit autoupdate`. Read the release notes of each tool that changed, especially for new rules or changed defaults.
3. Run `pre-commit run --all-files` and `python3 -m pytest`. Fix or justify new findings.
4. Open a PR. `.pre-commit-config.yaml` is a guardrail file, so code owners review it.

Notes:

- Pin to release tags. `tests/test_config.py` checks that every external `rev` starts with `v` or a digit. A frozen commit hash (`pre-commit autoupdate --freeze`) that starts with a letter `a`–`f` would fail that test.
- If you remove or rename any of `gitleaks`, `detect-private-key`, `bandit`, `checkov`, `forbid-ai-artifacts`, `validate-claude-config` or `scan-ai-secrets`, `tests/test_config.py` fails.
- Don't loosen a hook to make a bump pass. If a new rule is noisy, raise it as a [false positive](Use-Case-False-Positives-and-Exceptions).

## `pyproject.toml`

| Table / key | Value | Effect |
|---|---|---|
| `[project] name` | `claude-guardrails` | Package name |
| `[project] version` | `1.0.0` | Package version |
| `[project] requires-python` | `>=3.9` | The hooks must run on Python 3.9 |
| `[project] dependencies` | `[]` | No runtime dependencies: the hooks and scanners are standard library only |
| `[project.optional-dependencies] api` | `anthropic>=2.3,<3` | Needed only for real API calls through `claude_safeguard.py` |
| `[project.optional-dependencies] dev` | `pytest>=8`, `pyyaml>=6`, `pre-commit>=4.7` | Test and gate tooling |
| `[tool.pytest.ini_options] testpaths` | `["tests"]` | `python3 -m pytest` collects only `tests/` |
| `[tool.pytest.ini_options] addopts` | `"-q"` | Quiet output |
| `[tool.bandit] exclude_dirs` | `["tests", ".sdlc"]` | Bandit skips tests and the build record, even when pre-commit passes those files explicitly |

## Related pages

- [Commit and merge gates](Guardrail-Commit-and-Merge-Gates)
- [Policy baseline](Settings-Policy-Baseline)
- [Detectors reference](Detectors-Reference)
- [Changing the guardrails](Use-Case-Changing-the-Guardrails)
- [Troubleshooting](Troubleshooting)
