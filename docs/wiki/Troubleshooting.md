Find your symptom, check the cause, apply the fix. The messages quoted here are the real ones from the code, so you can search this page for the text you see. If a guard blocks legitimate work, see [False positives and exceptions](Use-Case-False-Positives-and-Exceptions) rather than working around it.

## Before you start

1. Run the self-test. It checks Python, the sandbox tools, the configuration and every hook in about a second, and installs nothing:

   ```bash
   scripts/setup_guardrails.sh --check
   ```

2. Note the **rule name** in the message (for example `network_egress`), or find it in `.claude/audit/guardrail-events.jsonl`. You need it for any issue you open. See [Audit logs](Audit-Logs).
3. Remember the legend: ⛔ deny or block, ✋ ask, ⚠️ warn, ✅ allow.

## Hooks: start-up and errors

| Symptom | Cause | Fix |
|---|---|---|
| `PreToolUse hook error … python3: not found` (or similar) | Claude Code runs every hook as `python3 "${CLAUDE_PROJECT_DIR}/.claude/hooks/<name>.py"`, and `python3` isn't on the `PATH` Claude Code sees. The hooks don't run at all; only the permission rules and the sandbox protect you | Install Python 3.9+ so that `python3` resolves. On Windows, use the Microsoft Store Python or add a `python3` alias. Restart Claude Code |
| Every Bash, Write or Read call asks with `[AI guardrail] bash_guard could not load its rules (ModuleNotFoundError); manual review required` (or `file_guard` / `read_guard`) | The hooks import their detectors from `scripts/claude_safeguard.py`. It's missing, broken, or the `.claude/hooks/` folder was copied without `scripts/`. The hooks fail closed | Restore the file (`git checkout -- scripts/claude_safeguard.py`) or copy `scripts/` alongside `.claude/`. Then run `scripts/setup_guardrails.sh --check` |
| A system message: `[AI guardrail] prompt_guard could not load its rules (…); prompts are NOT being checked. Run scripts/setup_guardrails.sh --check.` | Same cause, but the prompt guard fails **open** by design so it never swallows your prompt | Fix it before you paste anything sensitive. Until then, nothing checks your prompts |
| `[AI guardrail] bash_guard error (JSONDecodeError); manual review required` (or another exception name) | The hook received an event it couldn't handle, or hit a bug. It answered ✋ ask instead of allowing | Read the command and approve only if you'd run it yourself. Report it as a [bug](https://github.com/pixelofsoftware/AI-Mods/issues/new/choose) with your Claude Code version |
| `[AI guardrail] prompt_guard error: AttributeError` (or another exception name) | The prompt guard hit an unexpected event shape. The prompt went through **unchecked** | Report it as a bug. Check the prompt yourself with `python3 scripts/claude_safeguard.py scan -` |
| A hook seems to be ignored, or `/hooks` doesn't list it | The workspace isn't trusted, the hook was removed from `.claude/settings.json`, or a local setting turned hooks off | Accept the workspace trust prompt. Run `python3 scripts/precommit/check_ai_guardrails.py validate-config`, which reports `required PreToolUse hook missing: bash_guard.py` and similar. Check your own `.claude/settings.local.json` |
| A tool call goes through after a long pause, with a hook timeout error | Each hook has a 15-second timeout. Claude Code treats a timeout as a non-blocking error, so the call continues under the permission rules alone | Usually a very slow machine or a huge input. The hooks send oversized input to a human on purpose (see below). Report it if it happens with normal input |
| No entries in `.claude/audit/guardrail-events.jsonl` | `CLAUDE_GUARDRAIL_AUDIT=0` is set, `CLAUDE_GUARDRAIL_AUDIT_DIR` points elsewhere, or the folder isn't writable. Write errors are ignored on purpose | Unset the variables, or fix the folder permissions. Only decisions (deny, ask, block, override, warn) are logged; allowed actions aren't |
| `"user": null` in audit records | `$USER` (or `$USERNAME` on Windows) isn't set in the environment Claude Code runs in | Set it in your shell profile |

## Hooks: something was blocked or asked

### Bash commands

| Message (after `[AI guardrail]`) | Rule | What to do |
|---|---|---|
| `` `curl` performs arbitrary network requests; use approved tooling or ask a human to run it `` | ⛔ `network_egress` | By design. Fetch the file yourself, or ask Claude to explain what it needs. Package managers and git still work through the sandbox |
| `command could not be parsed safely` | ✋ `unparseable` | Usually unbalanced quotes. Ask Claude to simplify the command or split it into steps. If the line also names a network client, it's ⛔ `unparseable command referencing a network client` |
| `command name is computed at runtime and cannot be checked` | ✋ `dynamic_command` | The program name is a variable or substitution (`$CMD file`). Ask Claude to write the command out literally |
| `command nesting too deep to analyse` | ✋ `nesting_limit` | More than three levels of `bash -c`, `$(…)` or `find -exec`. Flatten it |
| `command too large to analyse` | ✋ `oversized` | Over 100,000 characters. Put the logic in a script file and run that |
| `` `git rebase` rewrites history `` / `` `git commit --amend` rewrites the last commit `` | ✋ `git_history_rewrite` | Approve if you meant it |
| `force/mirror/delete pushes rewrite shared history` | ⛔ `git_force_push` | Run it yourself if you really need it. `--force-with-lease` only asks |
| `` `--no-verify` skips the pre-commit security hooks `` / `skipping pre-commit hooks via environment variable` | ⛔ `guardrail_bypass` | Fix what pre-commit reports instead. CI runs the same checks anyway |
| `recursive search for secret-like names may read .env and key files` | ✋ `secret_search` | `grep -r` with a pattern like `token`, `secret` or `password`. Narrow the path, or approve if the tree has no secrets |
| `` inline python code performs network I/O `` | ✋ `inline_network_code` | `python -c`, `node -e` or an interpreter heredoc that imports a network library |
| `` `dig` can exfiltrate data through DNS `` | ✋ `dns_query` | Approve only if you know why Claude needs it |
| `` shell write to AI guardrail file `.claude/settings.local.json` needs security review `` | ✋ `guardrail_change` | Redirects, `tee`, `cp`, `mv`, `sed -i` and `truncate` into guardrail files ask, just like edits do |
| `printing a secret-named environment variable` | ⛔ `secret_echo` | `echo $GITHUB_TOKEN` and similar. Check that a variable is set with `test -n "$VAR"` instead |
| `dumping the environment can expose credentials` | ⛔ `env_dump` | `env`, `printenv`, `export -p`, `declare -p`, `compgen -v`. Ask for the one non-secret value you need |
| `` access to secret material `.env.production` is blocked; reference it via env vars or a secret manager `` | ⛔ `secret_file_access` | By design. Use the `.example` template |
| `` `terraform apply` mutates real infrastructure; run it through the reviewed CI pipeline `` | ⛔ `iac_apply` | Run `terraform plan` (✋ asks) and apply through CI |

Every rule is listed on the [Bash guard](Guardrail-Bash-Guard) page.

### File writes and reads

| Message | Cause | Fix |
|---|---|---|
| `` `src/auth/login.py`: security-critical code (auth/crypto/access control): human review required (HITL) `` | ✋ The path matches the security-critical pattern. It's broad on purpose: names starting with `auth`, `oauth` or `crypto`, and `sso`, `saml`, `security`, `iam`, `rbac`, `acl`, `permission(s)`, `secret(s)`, `key(s)`, when followed by `/`, `_` or a file extension. So `src/author.py`, `src/keys.py` and `src/permissions.py` all ask | Approve after reading the diff. If a path is clearly not security code, report a [false positive](Use-Case-False-Positives-and-Exceptions) |
| `` `deploy/run.py`: infrastructure-as-code: AI-generated changes require human review before merge (HITL) `` | ✋ YAML, JSON, Jinja, TypeScript and Python files under folders such as `deploy/`, `infra/`, `k8s/`, `helm/`, `terraform/`, `ansible/` or `cdk/` count as IaC, as do `*.tf`, Dockerfiles, compose files and `template.yaml` | Approve after reading. Code-owner review applies at merge |
| `` `.env.local` is a secrets file. The AI agent may not create or edit it; update the matching `.example` template and let a human fill real values. `` | ⛔ Secret path | Edit `.env.example` instead |
| `` hardcoded credential detected (API_KEY) in `src/client.py`. Read it from an environment variable or the secret manager instead, and rotate the value if it is real. `` | ⛔ A key-shaped value in the new content. Test fixtures trip this too | Read it from an environment variable. In tests, build fake values at runtime (`"sk-ant-" + "api03-" + …`) as [`tests/conftest.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/conftest.py) does |
| `` content contains likely secrets or regulated personal data (AUTH_TOKEN); use obviously synthetic fixtures `` | ✋ JWTs, `password=` assignments, SSNs, card numbers, IBANs or medical record numbers in the content | Use obviously fake fixtures, then approve |
| `` content too large to scan for secrets (612000 chars); review before approving `` | ✋ More than 500,000 characters in one write | Approve only after checking it, or split the file |
| `` reading `.env.local.example` is blocked: it may contain secrets. `` | ⛔ Only `.env.example`, `.env.sample`, `.env.template`, `.env.dist` and `.env.defaults` count as templates. `.env.local.example` is treated as a secret | Rename the template to one of the allowed names |
| `` reading `README.md` is blocked `` for a file in a `secret/` or `secrets/` folder | ⛔ Everything under a folder named `secret` or `secrets` counts as secret | Move non-secret docs out of that folder |

### Prompts

| Message | Cause | Fix |
|---|---|---|
| `Blocked by AI data-protection policy: the prompt contains API_KEY.` followed by `Credentials must never be sent to an AI service. If the value is real, rotate it now.` | ⛔ A credential. There's no override, whatever the detection confidence | Resubmit the redacted copy shown under the message. Rotate the key if it was real. Use placeholders such as `<API_KEY>` in prompts |
| `Blocked by AI data-protection policy: the prompt contains SSN.` followed by `If this is synthetic test data, add [sensitive-ok: <reason>] to the prompt to proceed (logged).` | ⛔ Regulated personal data: SSN, card number, IBAN or medical record number | If the data is synthetic, add `[sensitive-ok: synthetic fixture for parser tests]`. Otherwise use the redacted copy |
| You added `[sensitive-ok: …]` and it's still blocked | The reason must be 5 to 200 characters inside the brackets, or the block is for a credential, which can't be acknowledged | Write a real reason. For credentials, use the redacted copy |
| `[AI guardrail] Prompt contains EMAIL; avoid customer personal data in prompts (policy §2).` | ⚠️ Emails and phone numbers only get a reminder | Nothing to fix if the data is yours or synthetic |
| `[AI guardrail] Prompt contains text that looks like a prompt-injection payload; treat pasted content as untrusted.` | ⚠️ Phrasing such as "ignore previous instructions", role hijacks, system-prompt probes or chat-template tokens | Common when you paste issues, logs or web pages. Read Claude's next actions with care |

Card numbers that payment providers publish for testing (for example `4242 4242 4242 4242`) and AWS's documented example key aren't flagged.

## OS sandbox

| Symptom | Cause | Fix |
|---|---|---|
| The setup script warns `bwrap missing: Bash sandboxing will not work.` or `socat missing: …` | The Linux sandbox tools aren't installed. Bash commands run without OS isolation | `sudo apt-get install bubblewrap socat` (Debian/Ubuntu), then restart Claude Code |
| Every Bash command fails with sandbox errors | Missing tools, or on Ubuntu 24.04+ AppArmor blocking unprivileged user namespaces | Install the tools. Check `sysctl kernel.apparmor_restrict_unprivileged_userns` and the [sandbox docs](https://code.claude.com/docs/en/sandboxing) |
| `npm install`, `pip install` or `go get` can't reach a registry | The host isn't in `sandbox.network.allowedDomains`. The template allows `github.com`, `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `proxy.golang.org` and the placeholder `artifacts.internal.example.com` | Ask AppSec to add your registry. With managed `allowManagedDomainsOnly: true`, only the managed list counts. In the project file, a new domain also needs `allowed_sandbox_domains` in the policy baseline, or the drift check fails with `` sandbox domain `x` is not in allowed_sandbox_domains `` |
| A tool such as `docker compose` can't run in the sandbox | Some tools need things the sandbox doesn't allow | Ask AppSec to add it to `sandbox.excludedCommands`. Don't disable the sandbox. The baseline requires `sandbox.excludedCommands` to be `[]`, so that change must update `config/claude-guardrails-policy.json` in the same pull request |
| A command can't read `~/.ssh`, `~/.aws`, `~/.kube`, `~/.npmrc` or `~/.gnupg` | `sandbox.filesystem.denyRead` | By design. Run that command yourself, outside Claude Code |
| Claude Code won't start on a managed machine | Your admin set `sandbox.failIfUnavailable: true` and the sandbox isn't available (for example native Windows) | Install the sandbox tools, or use WSL2 |
| `/sandbox` shows the sandbox as off on Windows | Native Windows isn't supported | Use WSL2 |

## Setup script

| Symptom | Cause | Fix |
|---|---|---|
| `run this inside the repository` (exit 1) | You ran it outside a git checkout | `cd` into the repository first |
| `unknown option: …` (exit 2) | Only `--with-sdk`, `--check` and `-h`/`--help` exist | Fix the option |
| `pre-commit not on PATH after install; add ~/.local/bin to PATH and re-run` | pip installed pre-commit with `--user` into a folder that isn't on `PATH`, or the install failed. On Debian and Ubuntu, pip refuses to install into the system Python (`externally-managed-environment`) | Add `~/.local/bin` to `PATH`, install `pipx` and re-run (the script prefers `pipx`), or activate a virtualenv first |
| `pre-commit install failed (see the error above; a custom core.hooksPath is a common cause)` | pre-commit won't install while git's `core.hooksPath` is set, for example by another hook manager | Run `git config --show-origin core.hooksPath`, remove the setting if nothing else needs it, and re-run. Claude can't change `core.hooksPath`: the bash guard denies it |
| `guardrail config drift: run python3 scripts/precommit/check_ai_guardrails.py validate-config` | `.claude/settings.json` or `.mcp.json` doesn't match the policy baseline | Run that command to see each problem; see the pre-commit table below |
| `<hook> expected deny, got: …` | A hook script was changed, or its imports fail | `git diff .claude/ scripts/`, restore the files, and run `--check` again |
| `scripts/setup_guardrails.sh: line …: python3: command not found`, then exit 127 without a summary line | No `python3` on `PATH` | Install Python 3.9+ as `python3` |

## Pre-commit and CI

| Message | Cause | Fix |
|---|---|---|
| `AI guardrail configuration drift detected:` then lines such as `required deny rule missing: Bash(curl *)`, `forbidden allow rule: Bash(curl *)`, `` env `ANTHROPIC_BASE_URL` is not allowed in shared project settings `` (exit 1) | `validate-claude-config` found a change that weakens policy | Revert it. If the change is intentional, update `config/claude-guardrails-policy.json` in the same pull request and explain why. See [Policy baseline](Settings-Policy-Baseline) |
| `` PreToolUse hook `…` is not an approved guardrail script `` | A hook command isn't exactly `python3 "${CLAUDE_PROJECT_DIR}/.claude/hooks/<approved>.py"` | Use the exact command shape. Only the four guard scripts are approved |
| `` permissions.defaultMode `auto` is not allowed in shared project settings `` | `bypassPermissions`, `auto` and `acceptEdits` can't be the shared default | Keep `default` in the project. Pick a mode per session with `Shift+Tab` |
| `` `apiKeyHelper` is not allowed in shared project settings `` | `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `statusLine` and `disableAllHooks` are forbidden in the shared file | Move personal settings to `.claude/settings.local.json`. Telemetry belongs in managed settings |
| `could not read guardrail config: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)` (exit 2) | `.claude/settings.json`, `.mcp.json` or the policy file isn't valid JSON, or can't be read | Fix the JSON. The `check-json` hook points at the file |
| `.claude/settings.json is missing: the project guardrails were removed` (exit 1) | The settings file was deleted or moved | Restore it. Removing the guardrails needs code-owner review |
| `check_ai_guardrails internal error: …` (exit 2) | A bug in the checker | Report it as a bug |
| `note: OTEL_* exporter variables in .claude/settings.json are ignored by Claude Code; set them in managed settings.` | A note, not a failure | Move telemetry to [managed settings](Settings-Organisation-Policy) |
| `Blocked: these files must not be committed (AI session data, local config or secrets):` | `forbid-ai-artifacts` matched a transcript, `settings.local.json`, an audit log, a `.env*` file, a key or Terraform state | `git restore --staged <file>`, and check it's in `.gitignore`. Rotate anything that was ever committed |
| `Possible hardcoded credentials (values not shown):` followed by `path:line: rule (CATEGORY)` | `scan-ai-secrets` found a credential. `tests/` and `.sdlc/` aren't scanned | Move the value to an environment variable or secret manager. Build test credentials at runtime |
| gitleaks fails | gitleaks found a secret pattern | Same as above. Don't add allowlist entries without AppSec review |
| `no-commit-to-branch` fails | You committed directly on `main` or `master` | Create a branch. CI skips this check because branch protection guards `main` there |
| `check-added-large-files` fails | A file over 1,024 KB | Don't commit large artefacts |
| bandit or checkov fails | A Python security issue at medium severity and confidence, or an insecure Terraform, Kubernetes, Dockerfile or workflow setting | Fix the finding. Discuss suppressions with AppSec in the pull request |
| The first `pre-commit` run fails offline | pre-commit downloads each hook repository the first time it runs | Connect once, or run `pre-commit install --install-hooks` while online |
| CI fails but your local commit passed | Hooks weren't installed, a check was skipped locally, or CI's test suite failed | Run `pre-commit run --all-files` and `python3 -m pytest` |
| The pull request waits for a code owner | It touches infrastructure, CI, security-critical or guardrail files listed in CODEOWNERS | Ask a code owner to review. That's the human-in-the-loop control working |

## MCP servers

| Symptom | Cause | Fix |
|---|---|---|
| `/mcp` shows `internal-docs` or `internal-tickets` as *failed* | The URLs are still the `*.internal.example.com` placeholders, or `INTERNAL_MCP_TOKEN` isn't exported in the shell that launched `claude` | Ask your admin for the real servers. Export the token in your shell profile, restart Claude Code, then reconnect in `/mcp` |
| `internal-tickets` needs a sign-in | It uses OAuth | `/mcp`, pick `internal-tickets`, then **Authenticate** |
| Every `internal-tickets` call asks for approval | `mcp__internal-tickets__*` is an ask rule | By design: it can change tickets |
| A server in `.mcp.json` doesn't load | It isn't in `enabledMcpjsonServers` (`enableAllProjectMcpServers` is `false`), or you haven't trusted the workspace | Trust the folder. New servers need a reviewed pull request |
| `claude mcp add …` fails on a managed machine | `allowManagedMcpServersOnly: true` limits servers to the managed URL allowlist | Ask AppSec to approve the server |
| `` .mcp.json: server `x` url `…` is not on the approved list (config/claude-guardrails-policy.json) `` | The URL doesn't match `approved_mcp_url_patterns`. The scheme must match the pattern (the template only allows `https`), and URLs with `@`, backslashes, whitespace or control characters are always rejected | Use an approved HTTPS URL, or add the pattern to the policy in the same pull request |
| `` header `Authorization` holds a literal credential; use ${VAR} expansion `` | A token is written into `.mcp.json` | Use `"Bearer ${INTERNAL_MCP_TOKEN}"` and rotate the leaked token |
| `` server `x` is not listed in enabledMcpjsonServers (unreviewed server) `` or `` enabledMcpjsonServers lists `x`, which .mcp.json does not define `` | The two lists disagree | Add or remove the server in both places |
| `` local (stdio) server `x` runs `…`, which is not an approved command `` | `approved_mcp_commands` is empty: local servers aren't allowed on workstations | Use an internally hosted HTTPS server |

See [MCP servers](Settings-MCP-Servers).

## API middleware (`claude_safeguard.py`)

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'anthropic'` | The SDK isn't installed. Scanning works without it; API calls don't | `python3 -m pip install "anthropic>=2.3,<3"` or `scripts/setup_guardrails.sh --with-sdk` |
| `PromptBlockedError: Prompt blocked by policy (input contains CRITICAL data: ['API_KEY']). Remove the data and retry.` | The input's highest finding is at or above `CLAUDE_SAFEGUARD_BLOCK_ON` (default `critical`, meaning credentials). Nothing was sent | Remove the credential. Show the user a clear message |
| `PromptBlockedError: Prompt blocked by policy (input contains images/PDFs that cannot be scanned for sensitive data). …` | `CLAUDE_SAFEGUARD_BLOCK_UNSCANNABLE=1` and the request has an image or PDF | Expected for regulated workloads. Unset it if images are acceptable |
| `UnsafeOutputError: Response blocked by output validation: [...]` | The reply (or a `tool_use` input) hit a BLOCK rule, such as `reverse_shell`, `markdown_image_exfiltration` or `system_prompt_leak` | Check `exc.report.findings`. `CLAUDE_SAFEGUARD_OUTPUT_ACTION=sanitize` strips the spans from text instead, but blocked tool inputs still raise unless the action is `warn` |
| `ValueError: CLAUDE_SAFEGUARD_OUTPUT_ACTION must be raise\|sanitize\|warn, got 'drop'` | Typo in the variable | Use `raise`, `sanitize` or `warn` |
| `ValueError: expected one of low\|medium\|high\|critical, got 'severe'` | Typo in `CLAUDE_SAFEGUARD_BLOCK_ON` or `CLAUDE_SAFEGUARD_REDACT_MIN` | Fix the value. `BLOCK_ON` also accepts `none` (redact only) |
| SSNs or card numbers are redacted but not blocked | By default only credentials block. HIGH data is masked and sent | Set `CLAUDE_SAFEGUARD_BLOCK_ON=high` |
| Requests fail on Amazon Bedrock, Vertex AI or Microsoft Foundry | Those platforms don't support server-side refusal fallback | Set `CLAUDE_SAFEGUARD_FALLBACKS=0` and use the platform's model ID (Bedrock IDs take the `anthropic.` prefix) |
| Images from your own CDN are blocked as `markdown_image_exfiltration` | Any markdown image URL with query parameters is treated as an exfiltration channel | Add the host to `CLAUDE_SAFEGUARD_TRUSTED_IMAGE_HOSTS` (comma-separated; subdomains match) |
| The reply contains `[REDACTED:EMAIL_1]` | Placeholders are by design | Use `result.rehydrated_text()` only to show originals back to the same user, and never log it |
| JSON audit lines appear in your program's output | The library writes audit events to stdout by default | Pass `SafeClaude(audit=AuditLogger(stream=…))` to send them elsewhere. The `ask` CLI already writes them to stderr |
| `scan` or `check-output` exits 2 | `scan`: the input would be blocked. `check-output`: the verdict is BLOCK | Expected, so scripts can act on it. `ask` exits 2 when blocked, 3 on unsafe output and 4 on a refusal |

See [API safeguard](Guardrail-API-Safeguard) and [Environment variables](Settings-Environment-Variables).

## Still stuck?

- A legitimate action is blocked: [open a false-positive issue](https://github.com/pixelofsoftware/AI-Mods/issues/new/choose) with the rule name and synthetic input.
- Something that should be blocked gets through: don't open a public issue. Report it privately as described in [SECURITY.md](https://github.com/pixelofsoftware/AI-Mods/blob/main/SECURITY.md).

## Related pages

- [Installation](Installation)
- [FAQ](FAQ)
- [False positives and exceptions](Use-Case-False-Positives-and-Exceptions)
- [Bash guard](Guardrail-Bash-Guard)
- [Commit and merge gates](Guardrail-Commit-and-Merge-Gates)
- [Audit logs](Audit-Logs)
