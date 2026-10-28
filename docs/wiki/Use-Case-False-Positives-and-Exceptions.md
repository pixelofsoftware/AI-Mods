This page is for anyone whose legitimate work was blocked or slowed down by a guard. It shows how to find the rule that fired, decide whether it's really a false positive, work around it safely, report it, and, when you need something the policy forbids, get a time-boxed exception.

> **Placeholders on this page:** *AppSec* and `#appsec` are example names from the template policy. Your organisation's team and channel will differ.

## The short version

1. Find the rule name: it's in your audit log.
2. Decide: false positive, or the guard doing its job?
3. Use a safe workaround if there is one. **Never** `--no-verify`, never disable a hook.
4. Report the false positive with the issue form. Use synthetic data only.
5. If you need something the policy forbids, ask for an exception. It's time-boxed and recorded in the policy file.

Unapproved AI tools aren't a workaround. If a guard gets in your way, tell us, so we can fix it for everyone ([policy §7](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#7-exceptions-false-positives-and-incidents)).

## Step 1: Find the rule name

Messages start with `[AI guardrail]` and describe the problem in words. The machine-readable rule name is recorded in your local audit log, `.claude/audit/guardrail-events.jsonl`:

```bash
tail -n 3 .claude/audit/guardrail-events.jsonl
```

```json
{"@timestamp": "2026-10-28T06:15:22.144025+00:00", "command_fp": "648b13a0a3555ec5", "decision": "deny", "event": "PreToolUse", "hook": "bash_guard", "permission_mode": "default", "rules": ["secret_file_access"], "session_id": "3f1c9a2e-demo", "tool": "Bash", "user": "dev"}
```

The audit log never stores the command or the content, only a fingerprint (`command_fp`, `prompt_fp`). Keep the matching command or prompt text yourself, with secrets replaced, for the report.

Common messages and their rule names:

| Message starts with… | Hook | Rule |
|---|---|---|
| `` `curl` performs arbitrary network requests `` | bash_guard | `network_egress` |
| `access to secret material` | bash_guard | `secret_file_access` |
| `dumping the environment can expose credentials` | bash_guard | `env_dump` |
| `printing a secret-named environment variable` | bash_guard | `secret_echo` |
| `recursive search for secret-like names` | bash_guard | `secret_search` |
| `` `dig` can exfiltrate data through DNS `` | bash_guard | `dns_query` |
| `inline python code performs network I/O` | bash_guard | `inline_network_code` |
| `command name is computed at runtime` | bash_guard | `dynamic_command` |
| `command could not be parsed safely` | bash_guard | `unparseable` |
| `shell write to AI guardrail file` | bash_guard | `guardrail_change` |
| ``… `is a secrets file` `` | file_guard | `secret_file_write` |
| `hardcoded credential detected (…)` | file_guard | the detector, for example `anthropic_api_key` |
| `content contains likely secrets or regulated personal data` | file_guard | the detector, for example `us_ssn`, `secret_assignment` |
| `infrastructure-as-code: …` | file_guard | `iac_change` |
| `security-critical code (auth/crypto/access control)` | file_guard | `security_critical_change` |
| `this file is part of the AI guardrails` | file_guard | `guardrail_change` |
| `reading … is blocked: it may contain secrets` | read_guard | `secret_file_read` |
| `Blocked by AI data-protection policy: the prompt contains …` | prompt_guard | the detector, for example `us_ssn`, `anthropic_api_key` |

Every rule is described on [Bash guard](Guardrail-Bash-Guard), [File guard](Guardrail-File-Guard), [Read guard](Guardrail-Read-Guard), [Prompt guard](Guardrail-Prompt-Guard) and [Detectors reference](Detectors-Reference). A pre-commit or CI failure names its check (for example `validate-claude-config`) in the output.

> A denial by a plain permission rule from `.claude/settings.json` (for example `Bash(curl *)`) may come from Claude Code itself rather than a hook, so it may not appear in the hook audit log. `/permissions` shows the rule lists.

## Step 2: False positive, or working as intended?

It's a **false positive** when the guard blocks or asks about something that's actually safe. Real examples from the current code:

| What you did | What happened | Why |
|---|---|---|
| `python3 scripts/precommit/check_ai_guardrails.py forbid-paths config/.env.production` | ⛔ `access to secret material` | Any argument that looks like a secret path counts, even if the command only checks the name. (metadata-only commands such as `ls`, `stat`, `rm`, `git rm` and `git status` are exempt) |
| `grep -rn token src/` | ✋ `recursive search for secret-like names` | A recursive grep for `token`, `secret`, `password`… could read `.env` files |
| Edit `src/author_utils.py` or `app/keys.py` | ✋ `security-critical code` | The path pattern matches names starting with `auth`, and `key(s)` |
| `[sensitive-ok: ok] …` | ⛔ prompt still blocked | The reason must be 5 to 200 characters |
| A fixture with a Luhn-valid card number | ✋ `use obviously synthetic fixtures` | Only well-known test card numbers are skipped |

It's **working as intended** when the guard stops something the policy forbids, even if your intent was fine: `curl` to download a file, reading `.env` to "check a value", `terraform apply` from the agent shell. Those aren't false positives. If you need one of them regularly, that's an [exception](#step-5-ask-for-an-exception-when-you-need-something-the-policy-forbids).

## Step 3: Safe workarounds, and forbidden ones

| ✅ Safe | ⛔ Forbidden |
|---|---|
| Read the ✋ prompt and approve it, if you'd run the command yourself | `git commit --no-verify`, `git commit -n`, `SKIP=… git commit` |
| Run the command yourself in your own terminal, and give Claude only the non-secret result | `git config core.hooksPath …`, uninstalling pre-commit |
| Resubmit the redacted copy of a blocked prompt | Editing, renaming or deleting `.claude/hooks/*.py` or the settings to get past a guard |
| Use a placeholder or a known test value (see [Sensitive data](Use-Case-Sensitive-Data)) | Setting `disableAllHooks`, or `CLAUDE_GUARDRAIL_AUDIT=0` to hide events |
| Narrow the command (search one folder, use an exact path) | Rewriting a command so the parser can't see it (`base64 -d \| sh`, `eval`, building the command name at runtime) |
| Add an `allow` rule for a harmless command to your own `.claude/settings.local.json` | Pasting a secret file's contents into the prompt by hand |
| Point Claude at `.env.example` instead of `.env` | Switching to an unapproved AI tool for the same task |

Why the forbidden ones don't work anyway:

- The bash guard denies `--no-verify`, `-n` on commit, `SKIP=`, `PRE_COMMIT_ALLOW_NO_CONFIG=`, `HUSKY=` and `core.hooksPath` changes.
- Shell writes to guardrail files ask for approval; edits to them need code-owner review.
- `validate-claude-config` rejects `disableAllHooks`, unwired hooks, and `CLAUDE_GUARDRAIL_AUDIT` in shared settings.
- CI re-runs every pre-commit check, so a commit made with `--no-verify` still fails the pull request.

If you find a way to get past a guard, that's a vulnerability, not a workaround. Report it privately (see below).

## Step 4: Report the false positive

Open an issue with the **False positive** form: [new issue](https://github.com/pixelofsoftware/AI-Mods/issues/new/choose) (or your organisation's fork). The form is [`.github/ISSUE_TEMPLATE/false_positive.yml`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.github/ISSUE_TEMPLATE/false_positive.yml) and asks for:

| Field | What to put |
|---|---|
| **Which guard?** | `prompt_guard`, `bash_guard`, `file_guard`, `read_guard`, `claude_safeguard.py`, `pre-commit or CI check`, or `Not sure` |
| **Rule name** | From the audit log, for example `secret_search` |
| **What triggered it** | The command, prompt, path or text, **with sensitive values replaced by placeholders** |
| **The message you got** | The full `[AI guardrail]` text |
| **Why it should be allowed** | What you were doing, and why it's safe |
| **Environment** | OS, Python version, Claude Code version, commit |

Rules for the report:

- **Synthetic data only.** Never paste a real secret, key or personal data, even an expired one.
- If you need a credential-shaped example, describe it ("an `sk-ant-` key") or truncate it (`sk-ant-api03-…`).
- The template policy targets a turnaround of 2 business days.

The form adds the label `false-positive`. (The template policy text says to label it `ai-guardrails`; use whatever your organisation agreed.)

**Is it the opposite?** If a guard **allowed** something it should have blocked, don't open a public issue. Report it privately through [GitHub Security Advisories](https://github.com/pixelofsoftware/AI-Mods/security/advisories/new), as described in [SECURITY.md](https://github.com/pixelofsoftware/AI-Mods/blob/main/SECURITY.md).

## Step 5: Ask for an exception when you need something the policy forbids

An exception is a deliberate, approved loosening of a control for a specific use case. It isn't a bug fix.

1. **Ask** AppSec (`#appsec` in the template) with:
   - the use case,
   - how long you need it,
   - which data is involved.
2. **If approved**, open a pull request that makes the change **and** updates [`config/claude-guardrails-policy.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/config/claude-guardrails-policy.json) in the same commit, so the drift check passes and the reviewer sees the loosening.
3. **Tick** "Loosens a guard" in the pull request template and explain why it's safe.
4. **Record the expiry**: in the PR description, and in a tracking issue that reverts the change on the date.
5. **Revert** when it expires, with another reviewed pull request.

The policy file has no dedicated `exceptions` field today. The exception is recorded as the change to the baseline itself, plus the PR and the tracking issue. If you want the record inside the file, agree a convention with AppSec; the drift check ignores keys it doesn't know.

### Example: a tool that can't run in the sandbox

The setup guide's example: a team needs `docker compose` to run outside the sandbox. The policy requires `sandbox.excludedCommands` to be empty, so the change touches both files:

```diff
--- a/.claude/settings.json
+++ b/.claude/settings.json
-    "excludedCommands": [],
+    "excludedCommands": ["docker compose"],
```

```diff
--- a/config/claude-guardrails-policy.json
+++ b/config/claude-guardrails-policy.json
-    "sandbox.excludedCommands": []
+    "sandbox.excludedCommands": ["docker compose"]
```

`docker …` still asks for approval through the `Bash(docker *)` rule, and the bash guard still denies privileged containers, host mounts and the Docker socket. The PR explains that, names the team, and sets the review date. Code-owner review is required because both files are guardrail paths.

For more on making a change like this, see [Changing the guardrails](Use-Case-Changing-the-Guardrails).

## Related pages

- [Audit logs](Audit-Logs)
- [Troubleshooting](Troubleshooting)
- [Changing the guardrails](Use-Case-Changing-the-Guardrails)
- [Policy baseline](Settings-Policy-Baseline)
- [Bash guard](Guardrail-Bash-Guard)
- [FAQ](FAQ)
