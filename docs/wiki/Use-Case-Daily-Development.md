This page is for developers who use Claude Code every day in a repository that has the guardrails installed. It walks through a normal day: choosing a permission mode, what runs without a prompt, what asks, what's blocked, running tests, committing, and reading your own audit trail.

> **Before you start:** you've run `scripts/setup_guardrails.sh` and trusted the folder in Claude Code. If not, see [Installation](Installation).

## 1. Pick a permission mode for the task

The guardrails are tiered by risk. Before you start a task, decide which tier it's in and pick the mode to match. Cycle modes with `Shift+Tab`.

| Tier | Typical work | Mode to use | Review |
|---|---|---|---|
| **0: General** | Questions, explanations, docs, boilerplate, tests, refactors with tests | Any approved mode, including auto | Normal PR review |
| **1: Product code** | Features and bug fixes | Manual (`default`) or accept-edits | Normal PR review; you must understand every line |
| **2: Critical** | Terraform, CI/CD, auth, crypto, access control, payments, the guardrails | Plan first, then Manual | **Code-owner review** |

When in doubt, use the higher tier. Auto mode is for Tier 0 tasks with tests, in the sandbox. Source: [policy §0–§1](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#0-risk-tiers-at-a-glance).

A few facts about modes in this repository:

- The project default is `default` (Manual). The drift check rejects `bypassPermissions`, `auto` and `acceptEdits` as the **shared** default in `.claude/settings.json`, so everyone starts supervised. You can still switch modes in your session.
- Bypass mode is disabled (`disableBypassPermissionsMode: "disable"`), both in the project and in the organisation policy.
- Hook decisions don't depend on the mode. A guard that says ✋ Ask still asks in accept-edits or auto, and a ⛔ Deny is a deny in every mode.

Tier 2 work has its own walkthrough: [Infrastructure and security code](Use-Case-Infrastructure-and-Security-Code).

## 2. What runs without a prompt

These commands are on the allowlist in [`.claude/settings.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/settings.json) (35 rules), and no guard objects to them:

| Group | Allowlisted commands |
|---|---|
| Read-only git | `git status`, `git diff`, `git log …`, `git show …`, `git branch`, `git branch --show-current`, `git blame …`, `git rev-parse …` |
| Node | `npm test`, `npm run test`, `npm run lint`, `npm run typecheck`, `npm run build`, `npx tsc --noEmit` |
| Python | `pytest`, `python -m pytest …`, `python3 -m pytest …`, `ruff check …`, `ruff format --check …`, `mypy …` |
| Go | `go test ./...`, `go vet ./...` |
| Terraform (read-only) | `terraform fmt -check …`, `terraform validate` |
| Checks | `pre-commit run`, `pre-commit run --all-files`, `python3 scripts/claude_safeguard.py scan …` and `check-output …` |
| MCP | Every tool on the read-only `internal-docs` server |

Reading files inside the project (`Read`, `Grep`, `Glob`) doesn't prompt either, unless the target is a secret file (see below).

> **Allowlisted test runners execute code Claude wrote.** That's the trade-off for speed. The OS sandbox is what contains them: no network except the allowlisted registries, and no access to credential directories. Keep `bwrap` and `socat` installed on Linux.

Not in your stack? A team can add its own commands; see [Adopting in another repository](Use-Case-Adopting-in-Another-Repository). For yourself only, see [Personal settings](#6-personal-settings-claudesettingslocaljson) below.

## 3. What asks, and what's blocked

| You'll see | When | Examples |
|---|---|---|
| ✅ Nothing | Allowlisted and the guards are silent | `git diff`, `python3 -m pytest -q` |
| ✋ Normal Claude Code approval | Not allowlisted, no rule matched | Most edits in Manual mode, `make`, `ls -la` |
| ✋ Ask rule | Matches an `ask` rule in settings | `git push …`, `pip install …`, `npm install …`, `npx …`, `docker …`, `kubectl …`, `gh …`, `rm …`, `WebFetch` |
| ✋ `[AI guardrail]` ask | A hook wants a human to look | Edits to `auth/`, `*.tf`, `.claude/`; `git reset --hard`; `dig` |
| ⛔ `[AI guardrail]` deny | A hook or deny rule blocks it | `curl`, `sudo`, `cat .env`, `env`, `--no-verify`, `terraform apply` |

The full lists are on [Bash guard](Guardrail-Bash-Guard), [File guard](Guardrail-File-Guard), [Read guard](Guardrail-Read-Guard) and [Project settings](Settings-Project).

## 4. Walkthrough: a typical morning

These are real hook outputs from this repository. Hooks answer with a decision and a reason. Claude Code shows you the reason, and on a deny Claude gets it too, so it can change course. The exact way Claude Code renders the prompt depends on your version, so focus on the `[AI guardrail]` text.

### Action 1: "Explain how the parser works"

Claude reads `src/parse.py` and greps for callers.

✅ No prompt. Reads inside the workspace are free, and `read_guard` is silent for normal files.

### Action 2: "Run the tests"

Claude runs:

```bash
python3 -m pytest -q
```

✅ No prompt. `Bash(python3 -m pytest *)` is allowlisted and `bash_guard` has no objection.

### Action 3: Claude fixes a bug in `src/app/views.py`

✋ In Manual mode, Claude Code asks you to approve the edit, as usual. In accept-edits mode the edit goes through. No guard fires: this is ordinary product code.

### Action 4: Claude wants a new dependency

```bash
pip install requests
```

✋ Approval prompt, from the `Bash(pip install *)` ask rule. Read the package name before you approve. Package installs reach the network through the sandbox, which only allows the approved registries.

### Action 5: Claude tries to check a URL

```bash
curl https://example.com
```

⛔ Denied:

```text
[AI guardrail] `curl` performs arbitrary network requests; use approved tooling or ask a human to run it. See docs/claude-guardrails.md#4-tooling-controls
```

That's expected. If Claude genuinely needs something from the internet, it should tell you what and why, and you fetch it. `WebFetch` is available with approval for documentation you'd open yourself.

### Action 6: Claude needs a config value and reaches for `.env`

```bash
cat .env
```

⛔ Denied:

```text
[AI guardrail] access to secret material `.env` is blocked; reference it via env vars or a secret manager. See docs/claude-guardrails.md#4-tooling-controls
```

`cat .env.example` is fine. Give Claude the non-secret value it needs, or point it at the template. More on this in [Sensitive data](Use-Case-Sensitive-Data).

### Action 7: The fix touches session handling in `src/auth/session.py`

✋ Approval prompt, even in accept-edits or auto mode:

```text
[AI guardrail] `src/auth/session.py`: security-critical code (auth/crypto/access control): human review required (HITL)
```

This is now Tier 2 work. Read the diff carefully, and expect a code owner to review the pull request.

### Action 8: Claude wants to tidy up history

```bash
git reset --hard HEAD~1
```

✋ Approval prompt:

```text
[AI guardrail] `git reset` discards work
```

`git commit --amend` and `git rebase` ask the same way (`rewrites the last commit`, `rewrites history`). Approve only if you meant it.

## 5. Committing and pushing

When you or Claude run `git commit`, pre-commit runs these checks on the staged files: `gitleaks`, `scan-ai-secrets`, `detect-private-key`, `forbid-ai-artifacts`, `validate-claude-config`, `bandit`, `checkov`, plus hygiene checks such as `no-commit-to-branch` (no direct commits to `main` or `master`). Details: [Pre-commit settings](Settings-Pre-Commit).

If a check fails, read the message, fix the cause and commit again. For example, if a personal config file got staged:

```text
Blocked: these files must not be committed (AI session data, local config or secrets):
  - .claude/settings.local.json

Unstage with `git restore --staged <file>` and make sure it is in .gitignore.
If a secret was ever committed or pasted into a prompt, rotate it.
```

Things that don't work, by design:

| Attempt | Result |
|---|---|
| `git commit --no-verify` or `git commit -n` | ⛔ `` `--no-verify` skips the pre-commit security hooks `` |
| `SKIP=gitleaks git commit …` | ⛔ `skipping pre-commit hooks via environment variable` |
| `git config core.hooksPath /dev/null` | ⛔ `redirecting git hooks disables pre-commit checks` |
| `git push --force …` | ⛔ `force/mirror/delete pushes rewrite shared history` |
| `git push --force-with-lease …` | ✋ `force-with-lease push` |

These rules stop Claude. You can still type `--no-verify` in your own terminal, but it doesn't help: CI runs the same checks on every pull request (the `guardrails` job), and branch protection won't merge until it passes.

`git push` itself always asks (`Bash(git push *)`). Approve it when you're happy with the branch.

## 6. Personal settings: `.claude/settings.local.json`

Put your own preferences in `.claude/settings.local.json`. It's gitignored, and the `forbid-ai-artifacts` check blocks it from being committed.

```json
{
  "permissions": {
    "allow": [
      "Bash(make lint)",
      "Bash(npm run format)"
    ]
  }
}
```

What to know:

- You can add `allow` rules for commands you'd run yourself without thinking. Don't allow anything that deploys, deletes, pushes or reaches the network.
- You can't override a `deny` from the project or the organisation.
- The hooks still run on every command, whatever you allow. An allowed command that a guard denies is still denied.
- Edit this file yourself. If Claude tries to edit it, `file_guard` asks first, because it's under `.claude/`:

  ```text
  [AI guardrail] `.claude/settings.local.json`: this file is part of the AI guardrails; changes need security review (CODEOWNERS)
  ```

- Your organisation may turn on `allowManagedPermissionRulesOnly`, in which case only managed rules count. See [Organisation policy](Settings-Organisation-Policy).

## 7. Reading your audit log

Every time a hook blocks, asks, or records an override, it appends one line to `.claude/audit/guardrail-events.jsonl` on your machine. It stores rule names and short fingerprints, never prompt text, file content or full commands. The folder is gitignored and blocked from commits.

Show the last few events:

```bash
tail -n 5 .claude/audit/guardrail-events.jsonl
```

A real example, after an Edit to `infra/main.tf` and a `cat .env` (the session ID and user name are illustrative):

```json
{"@timestamp": "2026-10-28T06:15:22.034179+00:00", "decision": "ask", "event": "PreToolUse", "hook": "file_guard", "path": "infra/main.tf", "permission_mode": "acceptEdits", "rules": ["iac_change"], "session_id": "3f1c9a2e-demo", "tool": "Edit", "user": "dev"}
{"@timestamp": "2026-10-28T06:15:22.144025+00:00", "command_fp": "648b13a0a3555ec5", "decision": "deny", "event": "PreToolUse", "hook": "bash_guard", "permission_mode": "default", "rules": ["secret_file_access"], "session_id": "3f1c9a2e-demo", "tool": "Bash", "user": "dev"}
```

Only the denies, one per line (needs `jq`):

```bash
jq -c 'select(.decision == "deny") | {t: .["@timestamp"], hook, rules}' .claude/audit/guardrail-events.jsonl
```

The `rules` field is the rule name to quote in a false-positive report. The `user` field comes from `$USER`; it's `null` if that's unset. Every field is explained on [Audit logs](Audit-Logs).

## Quick reference

**Do:** pick the mode for the tier · let the allowlist do its job · read every `[AI guardrail]` prompt before approving · review AI diffs as if a new teammate wrote them · report false positives.

**Don't:** approve network, deploy or push actions on autopilot · paste secrets or customer data · reach for `--no-verify` · edit the guardrails without review.

## Related pages

- [Installation](Installation)
- [Bash guard](Guardrail-Bash-Guard)
- [Project settings](Settings-Project)
- [Audit logs](Audit-Logs)
- [Sensitive data](Use-Case-Sensitive-Data)
- [False positives and exceptions](Use-Case-False-Positives-and-Exceptions)
