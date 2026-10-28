This page is for engineers adding the guardrails to an existing repository. It covers which files to copy, tuning the allowlist for your stack (Node, Python, Go, Java/Gradle), replacing placeholders, running setup and pre-commit, protecting `main`, and keeping the policy file and drift tests in sync afterwards.

> **Placeholders on this page:** `*.internal.example.com`, *AppSec*, `#appsec` and `@your-org/…` teams are examples. Use your own.

## 1. Copy the files

From a clone of [pixelofsoftware/AI-Mods](https://github.com/pixelofsoftware/AI-Mods), copy these into the root of your repository:

| Copy | Why | Notes |
|---|---|---|
| `.claude/settings.json`, `.claude/hooks/*.py` | Permissions, sandbox and the four hooks | Skip `.claude/audit/`, `.claude/settings.local.json` and `__pycache__/` |
| `.mcp.json` | Approved MCP servers | Replace the two sample servers, or empty `mcpServers` and `enabledMcpjsonServers` if you use none |
| `CLAUDE.md` | The rules Claude reads at the start of every session | Merge with your existing `CLAUDE.md` if you have one |
| `.pre-commit-config.yaml` | The commit gate | Merge with your existing hooks |
| `config/claude-guardrails-policy.json` | The drift-check baseline | |
| `scripts/claude_safeguard.py` | Shared detectors (the hooks import them) and the API middleware | **Required**: the hooks fail closed without it |
| `scripts/precommit/check_ai_guardrails.py` | `forbid-ai-artifacts`, `validate-claude-config`, `scan-ai-secrets` | |
| `scripts/setup_guardrails.sh` | One-command install and self-test | |
| `.github/workflows/ai-guardrails.yml` | The CI merge gate (`guardrails` job) | |
| `.github/CODEOWNERS` | Human review for Tier 2 paths | Merge with your existing file; replace `@pixelofsoftware` |
| The `[tool.bandit]` table from `pyproject.toml` | Keeps bandit off test fixtures | Add to your own `pyproject.toml`, or create one |
| The entries from `.gitignore` | Keeps local AI files, secrets and Terraform state out of git | Append to your `.gitignore` |
| `docs/claude-guardrails.md` | The developer policy | Optional, but `CLAUDE.md` refers to it |
| `tests/` and `enterprise/managed-settings.json` | The guardrail test suite (CI runs it) | See [step 5](#5-decide-how-ci-runs-the-guardrail-tests) |
| `.github/ISSUE_TEMPLATE/false_positive.yml` | A form for false-positive reports | Optional |

A sketch, run from your repository with the template cloned next to it as `../AI-Mods`:

```bash
mkdir -p .claude/hooks config scripts/precommit .github/workflows
cp ../AI-Mods/.claude/settings.json .claude/
cp ../AI-Mods/.claude/hooks/*.py .claude/hooks/
cp ../AI-Mods/.mcp.json ../AI-Mods/CLAUDE.md ../AI-Mods/.pre-commit-config.yaml .
cp ../AI-Mods/config/claude-guardrails-policy.json config/
cp ../AI-Mods/scripts/claude_safeguard.py ../AI-Mods/scripts/setup_guardrails.sh scripts/
cp ../AI-Mods/scripts/precommit/check_ai_guardrails.py scripts/precommit/
cp ../AI-Mods/.github/workflows/ai-guardrails.yml .github/workflows/
```

Then merge `CODEOWNERS`, `.gitignore` and `pyproject.toml` by hand.

The `.gitignore` entries matter: the drift tests check that every secret path the hooks know about is also gitignored, and that the `.env.example`-style templates are not.

If you use Claude Code to do the copying, expect ✋ prompts: every one of these files is a guardrail path. That's intended.

## 2. Replace the placeholders

| Placeholder | Where | Replace with |
|---|---|---|
| `*.internal.example.com` | `.mcp.json`, `sandbox.network.allowedDomains` in `.claude/settings.json`, `config/claude-guardrails-policy.json` | Your MCP servers and internal package registry |
| `internal-docs`, `internal-tickets` | `.mcp.json`, `enabledMcpjsonServers`, the `mcp__internal-docs__*` allow rule and `mcp__internal-tickets__*` ask rule | Your approved servers, or remove them |
| `INTERNAL_MCP_TOKEN` | `.mcp.json` and developers' shell profiles | Your token variable |
| `@pixelofsoftware` | `.github/CODEOWNERS` | Your reviewers or teams |
| *AppSec*, *Platform Engineering*, `#appsec`, `#security-incidents` | `docs/claude-guardrails.md` | Your teams and channels |

Until you replace the sample MCP servers, Claude Code shows both as *failed*. That's harmless.

## 3. Tune the allowlist for your stack

The template's `allow` list covers git, npm, pytest, ruff, mypy, Go and read-only Terraform. Add your own build and test commands so routine work doesn't prompt. **Keep the `deny` and `ask` lists as they are.**

Ground rules, enforced by the drift check (`forbidden_allow_rule_patterns` in the policy file):

- No blanket rules: `Bash`, `Bash(*)`, any `Bash(…)` rule that starts with `*`, and `*:*` wildcards are rejected.
- No `WebFetch`, `WebSearch` or `mcp__*` allow rules, and no allow rule for an MCP server that isn't in `enabledMcpjsonServers`.
- Never allow network clients (`curl`, `wget`, `nc`, `ncat`, `ssh`, `scp`), `sudo`/`su`, `env`/`printenv`, `git push`, `terraform`/`tofu` `apply`/`destroy`, `kubectl apply`/`delete`, or `Read(//…)` / `Read(~…)`.

Prefer exact commands or a fixed prefix. If a command also matches an `ask` rule (for example anything starting with `npx`), expect it to keep asking; route it through a project script such as `npm run lint` instead.

### Node (npm, pnpm, yarn)

```json
"Bash(pnpm test)",
"Bash(pnpm run test *)",
"Bash(pnpm run lint)",
"Bash(yarn test)",
"Bash(yarn lint)",
"Bash(npm run format:check)"
```

`npm publish`, `pnpm publish` and `yarn publish` stay ⛔ denied by the bash guard. The template already allows `npm test`, `npm run test`, `npm run lint`, `npm run typecheck`, `npm run build` and `npx tsc --noEmit`.

### Python (uv, Poetry, tox)

```json
"Bash(uv run pytest *)",
"Bash(poetry run pytest *)",
"Bash(tox -e lint)",
"Bash(black --check *)"
```

`twine upload`, `poetry publish` and `uv publish` stay denied. `pip install`, `uv add` and `poetry add` stay ✋ ask.

### Go

```json
"Bash(go build ./...)",
"Bash(go test -race ./...)",
"Bash(golangci-lint run *)"
```

`go get` stays ✋ ask. The sandbox already allows `proxy.golang.org`; depending on your `GOSUMDB` setting you may also need `sum.golang.org` (see the next section).

### Java (Gradle, Maven)

```json
"Bash(./gradlew test)",
"Bash(./gradlew test *)",
"Bash(./gradlew check)",
"Bash(./gradlew build)",
"Bash(mvn test)",
"Bash(mvn verify)"
```

> **Add deny rules for the wrapper scripts.** The bash guard denies `gradle publish` and `mvn deploy`, but it matches the program name, so `./gradlew publish` and `./mvnw deploy` are **not** caught. Add these to `deny` in `.claude/settings.json` (tightening a control needs no policy-file change):
>
> ```json
> "Bash(./gradlew publish *)",
> "Bash(./gradlew publish)",
> "Bash(./mvnw deploy *)",
> "Bash(./mvnw deploy)"
> ```

Gradle and Maven download from hosts that aren't on the default sandbox list (for example `repo.maven.apache.org`, `services.gradle.org`, `plugins.gradle.org`). See the next section, or point the build at your internal artifact registry.

### Sandbox domains

If a build needs another registry, add the host in **three** places, in one pull request:

1. `sandbox.network.allowedDomains` in `.claude/settings.json`.
2. `allowed_sandbox_domains` in `config/claude-guardrails-policy.json` (or the drift check fails with ``sandbox domain `…` is not in allowed_sandbox_domains``).
3. `sandbox.network.allowedDomains` in the **managed** settings, if your organisation deploys them. With `allowManagedDomainsOnly: true`, only the managed list counts.

Pointing every package manager at one internal artifact proxy keeps this list short.

## 4. Run setup and pre-commit

```bash
scripts/setup_guardrails.sh
pre-commit run --all-files
```

The setup script installs the git hooks (pre-commit and pre-push) and self-tests every guard. It should end with:

```text
3. Self-test
  ✔ guardrail config matches config/claude-guardrails-policy.json
  ✔ bash_guard.py -> deny
  ✔ bash_guard.py -> deny
  ✔ file_guard.py -> ask
  ✔ read_guard.py -> deny
  ✔ prompt_guard.py -> block
  ✔ bash_guard allows git status

Guardrails ready (0 warning(s)). Next: start `claude` in this folder, trust it, then run /status, /hooks and /sandbox.
```

The first `pre-commit run --all-files` on an existing repository often finds things that were already there: a committed key, a Terraform misconfiguration flagged by checkov, a Python issue flagged by bandit. Fix them (and rotate any real secret) before you turn on the merge gate.

If the drift check fails, it tells you exactly what's wrong. For example, after removing a deny rule, adding a forbidden allow rule and a new domain:

```text
AI guardrail configuration drift detected:
  - .claude/settings.json: required deny rule missing: Bash(curl *)
  - .claude/settings.json: forbidden allow rule: Bash(kubectl apply *)
  - .claude/settings.json: sandbox domain `repo.maven.apache.org` is not in allowed_sandbox_domains

If the change is intentional, update config/claude-guardrails-policy.json in the same PR so security review sees it.
```

## 5. Decide how CI runs the guardrail tests

The workflow installs only `pre-commit`, `pytest` and `pyyaml`, then runs `python -m pytest` and `pre-commit run --all-files`. Plan for the test step:

| Your repository | What to do |
|---|---|
| Not Python, no `tests/` folder | Copy `tests/` as is, plus the `[tool.pytest.ini_options]` table (`testpaths = ["tests"]`) from `pyproject.toml`. Also copy `enterprise/managed-settings.json`, which the config tests read |
| Python, with its own `tests/` | `python -m pytest` would run your suite without your dependencies. Put the guardrail tests in their own top-level folder (for example `guardrail-tests/`; the tests find the repository root as the folder's parent) and change the workflow step to `python -m pytest guardrail-tests`. Update the `exclude` pattern of `scan-ai-secrets` and bandit's `exclude_dirs` to match |
| You don't want the tests | Remove the "Guardrail unit tests" step. You lose the drift tests, so you'll have to keep the lists in sync by hand |

Some tests are tied to the template's example values. For example, `tests/test_config.py` checks that every MCP URL contains `.internal.`. If your real URLs differ, update those assertions in the same pull request.

## 6. Protect `main`

In GitHub, require the `guardrails` check (shown as `ai-guardrails / guardrails`) and code-owner review, and block force pushes. We recommend two rulesets, so admins can bypass the approval but never the check; see [Organisation rollout](Use-Case-Organisation-Rollout#7-protect-main-with-two-rulesets).

## 7. Verify in Claude Code

Start `claude` in the repository, accept the workspace trust prompt, then:

| Command | You should see |
|---|---|
| `/status` | *Project settings* among the setting sources |
| `/hooks` | `prompt_guard` on UserPromptSubmit; `bash_guard`, `file_guard`, `read_guard` on PreToolUse |
| `/permissions` | Your allow, ask and deny lists |
| `/sandbox` | Sandbox enabled, unsandboxed fallback off |

Then ask Claude to run your test command. It should run without a prompt.

## 8. Keep it in sync

Guardrail lists live in several places. When you change one, change the others in the same pull request:

| If you change… | Also update | Checked by |
|---|---|---|
| A deny or ask rule required by policy | `required_deny_rules` / `required_ask_rules` in the policy file | `validate-claude-config` |
| A sandbox domain | `allowed_sandbox_domains`, and managed settings | `validate-claude-config` |
| An MCP server | `.mcp.json`, `enabledMcpjsonServers`, `approved_mcp_url_patterns` | `validate-claude-config` |
| A hook script or its matcher | `required_hooks`, `allowed_hook_scripts` | `validate-claude-config` |
| What counts as a secret path | `SECRET_PATH_RE` in `.claude/hooks/guard_common.py`, `forbidden_paths` in the policy file, `.gitignore` | `tests/test_review2_regressions.py` |
| What counts as a guardrail path | `GUARDRAIL_PATH_RE`, `.github/CODEOWNERS`, the list in `CLAUDE.md` | `tests/test_review2_regressions.py` |

To pick up fixes from the template later, diff your copies against the latest release and review the [CHANGELOG](https://github.com/pixelofsoftware/AI-Mods/blob/main/CHANGELOG.md). Keep a note of which template commit you copied.

## Related pages

- [Installation](Installation)
- [Project settings](Settings-Project)
- [Policy baseline](Settings-Policy-Baseline)
- [Pre-commit](Settings-Pre-Commit)
- [Changing the guardrails](Use-Case-Changing-the-Guardrails)
- [Organisation rollout](Use-Case-Organisation-Rollout)
