This page is the complete install guide: prerequisites for each operating system, exactly what `scripts/setup_guardrails.sh` does, how to check the result in Claude Code, and how to upgrade or remove the guardrails. Most developers need only the first four sections, which take about 10 minutes.

## Which parts you need

| You are… | You install | Guide |
|---|---|---|
| A developer using Claude Code in this repository | Prerequisites, then `scripts/setup_guardrails.sh` | This page |
| An admin rolling out org policy | `enterprise/managed-settings.json` and the OTEL headers helper on every workstation | [Organisation rollout](Use-Case-Organisation-Rollout) |
| A team building on the Claude API | The `anthropic` SDK and `scripts/claude_safeguard.py` | [Claude API apps](Use-Case-Claude-API-Apps) |
| Adding the guardrails to another repository | Copy the files, then run the setup script there | [Adopting in another repository](Use-Case-Adopting-in-Another-Repository) |

## Prerequisites

| Requirement | Check | Why |
|---|---|---|
| Claude Code, recent release | `claude --version` | Some keys used here, such as `permissions.blockReadsOutsideWorkingDirectories`, need a current version. Older versions skip unknown keys with a warning |
| Python 3.9 or newer, as `python3` | `python3 --version` | Every hook runs as `python3 "${CLAUDE_PROJECT_DIR}/.claude/hooks/<name>.py"`. The hooks use only the standard library |
| git | `git --version` | The setup script must run inside a git checkout |
| pre-commit | `pre-commit --version` | The setup script installs it if it's missing |
| Sandbox tools (Linux and WSL2) | `bwrap --version && socat -V` | Claude Code's OS sandbox needs `bubblewrap` and `socat` on Linux |
| Bash | `bash --version` | The setup script is a Bash script |

### macOS

- The sandbox uses the built-in Seatbelt profile, so there is nothing extra to install.
- Make sure `python3` on your `PATH` is 3.9 or newer.

### Linux

- Install the sandbox tools. On Debian or Ubuntu:

  ```bash
  sudo apt-get install bubblewrap socat
  ```

  On other distributions, install the `bubblewrap` and `socat` packages with your package manager.
- On Ubuntu 24.04 and later, AppArmor can stop unprivileged user namespaces, which the sandbox needs. Check `sysctl kernel.apparmor_restrict_unprivileged_userns` and see the [Claude Code sandbox docs](https://code.claude.com/docs/en/sandboxing).

### Windows with WSL2

Use WSL2 and follow the Linux steps inside your WSL distribution. WSL2 is the supported way to get the OS sandbox on Windows.

### Native Windows (without WSL2)

- The OS sandbox isn't supported. Hooks, permission rules and the commit gate still work.
- Make sure `python3` resolves. The Microsoft Store Python provides it. With the python.org installer, add a `python3` alias. Without it, the hooks can't start.
- The setup script needs a Bash shell. When it runs on an OS it doesn't recognise, it warns `Bash sandboxing is not available on this OS; use WSL2 on Windows`. This setup isn't covered by the [verification record](https://github.com/pixelofsoftware/AI-Mods/blob/main/.sdlc/claude-guardrails/verification.md).
- Don't turn on `sandbox.failIfUnavailable` in managed settings for these machines: Claude Code wouldn't start.

## Install

```bash
git clone https://github.com/pixelofsoftware/AI-Mods.git
cd AI-Mods
scripts/setup_guardrails.sh
```

### Options

| Command | What it does |
|---|---|
| `scripts/setup_guardrails.sh` | Checks prerequisites, installs the pre-commit hooks, creates `.claude/audit/`, then self-tests every guard |
| `scripts/setup_guardrails.sh --with-sdk` | The same, and also installs the `anthropic` SDK for the [API safeguard](Guardrail-API-Safeguard) |
| `scripts/setup_guardrails.sh --check` | Prerequisites and self-test only. Installs nothing. Use it after an upgrade or when something looks wrong |
| `scripts/setup_guardrails.sh --help` | Prints the usage lines and exits 0 |

The script is safe to re-run. `--check` wins over `--with-sdk`: with both, nothing is installed. Any other option prints `unknown option: <option>` and exits 2.

### What the script does, step by step

**0. Find the repository.** It changes to the top of the git checkout, so you can run it from any subfolder. Outside a git repository it prints `run this inside the repository` and exits 1.

**1. Prerequisites**

| Check | Pass | Not met |
|---|---|---|
| `python3` on `PATH` and at least 3.9 | ✔ `python3 3.12.7` | ✘ failure: ``python3 >= 3.9 is required on PATH (the Claude Code hooks call `python3`)`` |
| `claude` on `PATH` | ✔ `Claude Code <version>` | ! warning: `Claude Code CLI not found on PATH (install: https://code.claude.com/docs/en/setup)` |
| Linux: `bwrap`, then `socat` | ✔ `bwrap (sandbox dependency)` | ! warning, once per missing tool: `bwrap missing: Bash sandboxing will not work. Ubuntu/Debian: sudo apt-get install bubblewrap socat` |
| macOS | ✔ `macOS: sandbox uses the built-in Seatbelt profile` | n/a |
| Any other OS | n/a | ! warning: `Bash sandboxing is not available on this OS; use WSL2 on Windows` |

**2. Install** (skipped with `--check`)

1. If `pre-commit` isn't on `PATH`, it installs `pre-commit>=4.7`: with `pipx` if you have it, otherwise with `python3 -m pip install`. Outside a virtualenv it adds `--user` to keep the system Python clean; inside one (`$VIRTUAL_ENV` set) it doesn't. An install error doesn't stop the script; the next check catches it.
2. If `pre-commit` still isn't on `PATH`: ✘ `pre-commit not on PATH after install; add ~/.local/bin to PATH and re-run`.
3. It runs `pre-commit install --install-hooks`. Because the config sets `default_install_hook_types: [pre-commit, pre-push]`, this installs both git hooks and downloads the hook environments. On success: ✔ `pre-commit hooks installed (pre-commit + pre-push)`. On failure: ✘ `pre-commit install failed (see the error above; a custom core.hooksPath is a common cause)`.
4. With `--with-sdk`, it installs `anthropic>=2.3,<3` the same way (✔ `anthropic SDK installed` or ✘ `anthropic SDK install failed`).
5. It creates `.claude/audit/`, which is gitignored: ✔ `local audit directory .claude/audit (gitignored)`.

**3. Self-test**

1. Runs `python3 scripts/precommit/check_ai_guardrails.py validate-config`. ✔ `guardrail config matches config/claude-guardrails-policy.json`, or ✘ `guardrail config drift: run python3 scripts/precommit/check_ai_guardrails.py validate-config`.
2. Pipes five synthetic events into the hooks, with `CLAUDE_GUARDRAIL_AUDIT=0` so nothing reaches your audit log, and checks each decision:

   | Hook | Synthetic input | Expected |
   |---|---|---|
   | `bash_guard.py` | A `wget` download | ⛔ `deny` |
   | `bash_guard.py` | `cat .env` | ⛔ `deny` |
   | `file_guard.py` | Edit `infra/main.tf` | ✋ `ask` |
   | `read_guard.py` | Read `config/.env.prod` | ⛔ `deny` |
   | `prompt_guard.py` | A prompt with a fake `sk-ant-api03-…` key built at runtime | ⛔ `block` |

   A mismatch prints ✘ `<hook> expected <decision>, got: <output>`.
3. Checks that `bash_guard.py` stays silent on `git status`: ✔ `bash_guard allows git status`.

**Summary and exit codes**

| Result | Last line | Exit code |
|---|---|---|
| No failures (warnings are fine) | ``Guardrails ready (N warning(s)). Next: start `claude` in this folder, …`` | 0 |
| One or more ✘ failures | `Setup finished with N failure(s) and M warning(s).` | 1 |
| Not inside a git repository | `run this inside the repository` | 1 |
| Unknown option | `unknown option: …` | 2 |
| `python3` missing entirely | The script stops at the `git status` check, before the summary line | 127 (from the shell) |

Warnings (missing `claude`, `bwrap` or `socat`) never change the exit code. A sandbox warning still matters: it means the OS sandbox is off, so install the tools before you work on [Tier 1 or Tier 2](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#0-risk-tiers-at-a-glance) code.

### Expected output

A full install on Linux with the sandbox tools present:

```text
1. Prerequisites
  ✔ python3 3.12.7
  ✔ Claude Code 2.1.311 (Claude Code)
  ✔ bwrap (sandbox dependency)
  ✔ socat (sandbox dependency)
2. Install
  ✔ pre-commit hooks installed (pre-commit + pre-push)
  ✔ local audit directory .claude/audit (gitignored)
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

A real `--check` run on a Linux machine without `bwrap` and `socat`. Section 2 is skipped, warnings show as `!`, and the exit code is 0:

```text
1. Prerequisites
  ✔ python3 3.13.17
  ✔ Claude Code 2.1.312 (Claude Code)
  ! bwrap missing: Bash sandboxing will not work. Ubuntu/Debian: sudo apt-get install bubblewrap socat
  ! socat missing: Bash sandboxing will not work. Ubuntu/Debian: sudo apt-get install bubblewrap socat
3. Self-test
  ✔ guardrail config matches config/claude-guardrails-policy.json
  ✔ bash_guard.py -> deny
  ✔ bash_guard.py -> deny
  ✔ file_guard.py -> ask
  ✔ read_guard.py -> deny
  ✔ prompt_guard.py -> block
  ✔ bash_guard allows git status

Guardrails ready (2 warning(s)). Next: start `claude` in this folder, trust it, then run /status, /hooks and /sandbox.
```

### Optional: run the test suite

```bash
python3 -m pip install pytest pyyaml
python3 -m pytest
```

At the time of writing the suite has 331 tests. CI runs the same suite on every pull request.

## Provide MCP credentials

Only needed if you use the MCP servers in [`.mcp.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.mcp.json). The two shipped servers are examples for a fictional company; until your admin replaces them, Claude Code shows them as *failed*, which is harmless.

```bash
# ~/.zshrc or ~/.bashrc. Never commit the value.
export INTERNAL_MCP_TOKEN="$(op read 'op://Engineering/internal-mcp/token')"   # example using the 1Password CLI
```

`internal-tickets` uses OAuth: inside Claude Code, run `/mcp`, pick `internal-tickets`, then **Authenticate**. See [MCP servers](Settings-MCP-Servers).

## Verify in Claude Code

1. Start Claude Code in the repository folder:

   ```bash
   claude
   ```

2. Accept the **workspace trust** prompt. Project allow rules, environment variables and MCP servers apply only after you trust the folder. Deny rules apply immediately.
3. Run these commands. The expected results come from the [setup guide](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#a4-start-claude-code-and-verify); the verification record lists them as still to be checked on a real workstation, so tell us if yours differ.

| Command | You should see |
|---|---|
| `/status` | *Project settings* among the setting sources, plus *Managed settings* if your admin deployed them |
| `/permissions` | The allow, ask and deny lists from `.claude/settings.json` |
| `/hooks` | `prompt_guard.py` on `UserPromptSubmit`; `bash_guard.py` (matcher `Bash\|Monitor`), `file_guard.py` (`Write\|Edit\|MultiEdit\|NotebookEdit`) and `read_guard.py` (`Read\|Grep\|Glob\|NotebookRead`) on `PreToolUse` |
| `/sandbox` | Sandbox enabled, with the unsandboxed fallback off |
| `/mcp` | `internal-docs` and `internal-tickets`, connected once your credentials are set |

On a machine with managed settings, admins can also run `claude doctor` and check that it reports no managed-settings errors. For what the commands themselves show, see the [Claude Code docs](https://code.claude.com/docs).

## Smoke tests

### Inside Claude Code

| Ask Claude to… | Expected |
|---|---|
| "Run `curl https://example.com`" | ⛔ Denied by the `Bash(curl *)` rule. Variants such as `/usr/bin/curl` or `bash -c 'curl …'` are denied by the bash guard |
| "Show me what's in `.env`" | ⛔ Denied: secret file |
| "Add a tag to `infra/main.tf`" | ✋ Approval prompt: `infrastructure-as-code: AI-generated changes require human review before merge (HITL)` |
| Paste a fake key: `sk-ant-api03-` followed by 40 letters | ⛔ Prompt blocked, with a redacted copy to resubmit |
| "Run the tests" | ✅ Runs without a prompt |

### From your own shell, without Claude Code

The hooks are plain scripts, so you can feed them a synthetic event. Set `CLAUDE_GUARDRAIL_AUDIT=0` so your audit log stays clean:

```console
$ printf '%s' '{"tool_name":"Bash","tool_input":{"command":"sudo ls"}}' \
    | CLAUDE_GUARDRAIL_AUDIT=0 python3 .claude/hooks/bash_guard.py
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "[AI guardrail] privilege escalation (sudo/su/doas) is not permitted for the AI agent. See docs/claude-guardrails.md#4-tooling-controls"}}
```

No output means the hook has no opinion and the normal permission rules decide. To check text for secrets and personal data before you paste it anywhere:

```bash
python3 scripts/claude_safeguard.py scan "Refund jane@corp.io"   # exit 0; exit 2 if it would be blocked
```

## Admins and API teams

- **Managed settings.** Replace the `*.internal.example.com` placeholders and the OTEL endpoint first, then deploy through the claude.ai admin console, MDM, or a system file:

  | OS | Path |
  |---|---|
  | macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
  | Linux / WSL | `/etc/claude-code/managed-settings.json` |
  | Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

  ```bash
  # Linux example
  sudo install -d -m 0755 /etc/claude-code
  sudo install -m 0644 enterprise/managed-settings.json /etc/claude-code/managed-settings.json
  sudo install -m 0755 enterprise/claude-otel-headers.sh /usr/local/bin/claude-otel-headers
  ```

  Full walkthrough: [Organisation rollout](Use-Case-Organisation-Rollout) and [Organisation policy](Settings-Organisation-Policy).
- **Branch protection.** Require the `ai-guardrails / guardrails` check and code-owner review on `main`, and block force pushes. Without it, the merge gate doesn't block anything.
- **Claude API.** `scripts/setup_guardrails.sh --with-sdk`, or `python3 -m pip install "anthropic>=2.3,<3"`. See [Claude API apps](Use-Case-Claude-API-Apps).

## Upgrading

1. Read [`CHANGELOG.md`](https://github.com/pixelofsoftware/AI-Mods/blob/main/CHANGELOG.md) for behaviour changes.
2. Pull the new version:

   ```bash
   git pull
   ```

3. Re-run the setup script. It re-installs the git hooks and their environments, then self-tests:

   ```bash
   scripts/setup_guardrails.sh
   ```

4. Restart Claude Code, then re-check `/hooks` and `/permissions` so you know the new settings and hooks are the ones in use.
5. If `enterprise/managed-settings.json` changed, your admin has to redeploy it. Managed settings don't update from the repository.
6. Pinned pre-commit hook revisions are bumped with `pre-commit autoupdate` in a reviewed pull request, never ad hoc.

In a repository that [adopted the guardrails](Use-Case-Adopting-in-Another-Repository), copy the updated files in a pull request, keep your own `allow` rules, and update `config/claude-guardrails-policy.json` in the same commit, or the drift check fails. Guardrail files need code-owner review. See [Changing the guardrails](Use-Case-Changing-the-Guardrails).

## Uninstalling and rolling back

Removing a control is a guardrail change. Do it in a pull request with code-owner review, and say in the description that it loosens a control.

| To remove | Do this | Notes |
|---|---|---|
| The git hooks on your machine | `pre-commit uninstall -t pre-commit -t pre-push` | CI still runs every check on your pull requests |
| The API SDK | `python3 -m pip uninstall anthropic` | Scanning with `claude_safeguard.py scan` keeps working; it's stdlib-only |
| Your local audit log | Delete `.claude/audit/` | It's gitignored and only on your machine |
| Managed settings | Admin removes the system file, MDM profile or admin-console entry, and `/usr/local/bin/claude-otel-headers` | Developers can't do this themselves |
| The guardrails from a repository | Remove `.claude/settings.json` and `.claude/hooks/`, the local hooks in `.pre-commit-config.yaml`, and the `ai-guardrails` workflow in the same pull request | While the `validate-claude-config` hook is still configured, it fails with `.claude/settings.json is missing: the project guardrails were removed` |

To roll back to an earlier version, revert the commits that changed the guardrails (`git revert <commit>`) in a pull request, then re-run `scripts/setup_guardrails.sh --check`. Keep `config/claude-guardrails-policy.json` in step with `.claude/settings.json` and `.mcp.json`, or the drift check fails.

## Related pages

- [Architecture](Architecture)
- [Troubleshooting](Troubleshooting)
- [Project settings](Settings-Project)
- [Pre-commit settings](Settings-Pre-Commit)
- [Organisation rollout](Use-Case-Organisation-Rollout)
- [FAQ](FAQ)
