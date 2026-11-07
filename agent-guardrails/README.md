# Agent Guardrails: Claude Code, Cursor and GitHub Copilot

The guardrails from this repository, packaged for three AI coding tools. The same engine makes every decision. Each tool gets a thin adapter for its hook format, plus one skill that teaches the agent the policy.

> **Status: 0.1.0, preview.** The engine is the code from [`../.claude/hooks`](../.claude/hooks), moved here unchanged. The tests prove that the Claude Code adapter answers byte for byte the same as the original hooks. The Cursor and Copilot adapters follow those tools' published hook references (November 2026) and are tested against them, but haven't been tried in live sessions yet. See [Verify in your tool](#verify-in-your-tool).
>
> This folder is self-contained. Nothing in the rest of the repository depends on it, and its tests don't run in the repository's CI.

## Why hooks, not only a skill

A skill is guidance the model loads when it thinks it's relevant. It can't stop an action. The protection here comes from **hooks**, which the tool runs before every prompt, command, file write and file read, whatever the model decides. The skill complements them: it explains the rules so the agent works with the guardrails instead of against them.

## What runs where

| Guard | Claude Code | Cursor | GitHub Copilot |
|---|---|---|---|
| **Shell commands** (network egress, secrets, privilege escalation, force push, `terraform apply`, …) | ✅ `PreToolUse` | ✅ `beforeShellExecution` (deny, ask) | ✅ `preToolUse` for `bash` and `powershell` (deny, ask) |
| **File writes** (secret files, hardcoded keys, human review for IaC, auth and guardrail files) | ✅ deny, ask | 🟡 `preToolUse` can't ask, so **ask becomes deny** ([why](#limitations)) | ✅ `create`, `edit`, `str_replace_editor`, `apply_patch` (every file in a patch) |
| **File reads** (`.env`, keys, credential folders) | ✅ | ✅ `beforeReadFile`, plus `Grep`/`Glob` through `preToolUse` | ✅ `view`, `grep`, `glob` |
| **Prompts** (credentials, regulated personal data) | ✅ blocked, with a redacted copy | 🟡 blocked with a redacted copy, but no non-blocking notices | 🟡 **redacted, not blocked**: Copilot ignores prompt-hook output, so the model receives a redacted copy |
| **Skill** (policy and procedures, `scan.py`) | ✅ | ✅ | ✅ |
| **Fail closed** when a guard crashes | ✅ asks | ✅ `failClosed: true` | ✅ errors deny; ⚠️ **timeouts let the action through** (Copilot rule) |
| **Permission rules, OS sandbox, bypass lock** | ✅ project or managed settings | Cursor's own settings | Copilot's own settings |
| **Pre-commit and CI gates** | same everywhere: they run in git, see the [main README](../README.md) | | |

## Install

Requires Python 3.9 or later on the developer's machine. Nothing else to install: the engine uses only the standard library.

### Claude Code: plugin

In Claude Code:

```text
/plugin marketplace add pixelofsoftware/AI-Mods
/plugin install agent-guardrails@agent-guardrails
```

No clone needed: the repository root carries the marketplace (`.claude-plugin/marketplace.json`). From a local clone, `/plugin marketplace add ./AI-Mods` works too.

The plugin brings the hooks and the skill. **Plugins can't carry permission rules or sandbox settings**, so for those also run the project install below with `--target claude`, or deploy them as managed settings.

### Any tool: project install

```bash
python3 agent-guardrails/install.py --target cursor  --project /path/to/your/repo
python3 agent-guardrails/install.py --target copilot --project /path/to/your/repo
python3 agent-guardrails/install.py --target claude  --project /path/to/your/repo
python3 agent-guardrails/install.py --target all     --project /path/to/your/repo --dry-run
```

The installer:

1. **Copies the runtime** to `<repo>/.agent-guardrails/`: `hook.py`, `guardrails_core/` and `adapters/`.
2. **Copies the skill** to `.claude/skills/`, `.cursor/skills/` or `.github/skills/`.
3. **Adds the hook configuration** to `.claude/settings.json`, `.cursor/hooks.json` or `.github/hooks/agent-guardrails.json`, merging with what is already there.

It refuses to write through a symlink or outside the project, and checks every destination before writing anything. It only adds restrictive settings: hooks, deny and ask rules, the bypass lock, and the sandbox when none is set. It never adds allow rules or removes anything. Running it twice changes nothing. Commit the result so the whole team gets it.

## Enforce it across an organisation

| Tool | Mechanism | Users can't turn it off? |
|---|---|---|
| Claude Code | Managed settings: `extraKnownMarketplaces` (GitHub repo `pixelofsoftware/AI-Mods`, or your fork) + `enabledPlugins: {"agent-guardrails@agent-guardrails": true}`, plus `allowManagedHooksOnly` and `strictKnownMarketplaces`. Put the permission and sandbox template in the same file | Yes |
| Cursor | Copy the runtime and a `hooks.json` with **absolute** paths to `/etc/cursor/hooks.json` (Linux), `/Library/Application Support/Cursor/hooks.json` (macOS) or `C:\ProgramData\Cursor\hooks.json` via MDM, or use the Enterprise dashboard | Yes (enterprise hooks run first) |
| GitHub Copilot | Policy hooks in `/etc/github-copilot/policy.d/*.json` or `C:\ProgramData\GitHub\Copilot\policy.d\` (root-owned), with absolute paths to the runtime | Yes (`disableAllHooks` doesn't affect them) |

## Layout

```text
agent-guardrails/
├── hook.py                    # entry point: python3 hook.py <claude|cursor|copilot> <guard>
├── guardrails_core/           # the engine, standard library only
│   ├── shell.py               #   shell parser and rules (from bash_guard.py)
│   ├── files.py               #   write and read decisions (from file_guard.py, read_guard.py)
│   ├── prompt.py              #   prompt decisions (from prompt_guard.py)
│   ├── common.py              #   path patterns and audit log (from guard_common.py)
│   └── safeguard.py           #   detectors (scripts/claude_safeguard.py, unchanged)
├── adapters/                  # claude_code.py · cursor.py · copilot.py
├── skills/agent-guardrails/   # SKILL.md, references/policy.md, scripts/scan.py
├── .claude-plugin/            # plugin.json, marketplace.json, icon.png
├── hooks/hooks.json           # Claude Code plugin hooks
├── templates/                 # host configs the installer writes
├── install.py
└── tests/
```

## How "the same" is checked

`tests/test_parity_claude.py` compares the Claude Code adapter with the original hooks in three ways:

- **Shell parser and rules.** It gets identical decisions for every string in the repository's test suite (over 300), a hand-written set of tricky commands and 4,000 generated commands.
- **End to end.** For about 130 events across all four guards, including malformed input, `hook.py` gives the same stdout and exit code as the original scripts.
- **Not vacuous.** It also checks that the comparison really covered deny, ask, block, notice and allow results.

The Cursor and Copilot adapters reuse that engine, so their decisions are the same. Only the output format differs. Their tests cover each documented event and the cases where a tool can't express a decision. `tests/test_review_findings.py` holds a regression test for each finding of an independent adversarial review (decoy arguments, unknown fields, subfolder sessions, symlinks and others).

```bash
cd agent-guardrails && python3 -m pytest
```

## Limitations

- **Cursor can't ask before a file write.** Its `preToolUse` hook ignores "ask", so a write that needs human review (infrastructure, auth, the guardrails) is **denied**, with a message telling the user to make or approve the change themselves. Set `AGENT_GUARDRAILS_CURSOR_ASK=allow` to let such review-only writes through instead (they are still audited). Secret files, hardcoded keys, likely personal data, oversized content and writes whose target can't be determined stay denied either way.
- **Cursor and Copilot don't show non-blocking prompt notices.** Personal-data notices and prompt-injection warnings are only written to the audit log.
- **Copilot can't block a prompt.** The prompt guard rewrites what the model receives (`userPromptTransformed`), replacing blocked values with placeholders. GitHub documents output for this event, but it hasn't been verified in a live session.
- **Copilot hook timeouts fail open**, by Copilot's design. The hooks are given 30 seconds and usually finish in well under one.
- **Tool argument names** for Cursor's `Write` and Copilot's editing tools aren't fully documented. So the adapters check **every** path field and every patch in a tool call, scan **every** text value for credentials, and take the strictest result. A decoy field can't hide the real target. When no target file can be found, they deny or ask rather than allow.
- **Tools the adapters don't recognise**, such as MCP tools, are left to the tool's own permission flow, as the original hooks leave them to Claude Code's permission rules. Keystrokes sent to a Copilot background shell (`write_bash`, `write_powershell`) go through the shell guard. Web search is denied and web fetch asks, matching `.claude/settings.json`.
- **Project root.** Copilot sets no project variable, so the adapters use the enclosing git repository. A session running in a subfolder therefore can't weaken path rules such as `.github/workflows/`.
- **Windows:** the Cursor template calls `python3`. If that isn't on the PATH, change it to `python` or `py -3`. The Copilot template already uses `python` for PowerShell.
- **Policy links** in messages point to `docs/claude-guardrails.md`, as in the original. The skill ships that policy as `references/policy.md`.
- **Extra protection.** Compared with the original, the engine also asks before changes to the new tools' equivalents of `.claude/`, `.mcp.json` and `CLAUDE.md`. That covers `.agent-guardrails/`, `.cursor/`, `.cursorrules`, `.github/hooks/`, `skills/`, `copilot/`, `instructions/`, `agents/` and `prompts/`, `.github/copilot-instructions.md`, `~/.copilot/`, `.vscode/mcp.json`, `.vscode/settings.json` and `AGENTS.md`. In PowerShell it also checks commands as if launched through `pwsh -Command`, so `iwr … | iex` is caught.
- Everything in the main [Honest limitations](../README.md#%EF%B8%8F-honest-limitations) section still applies. Detection is pattern-based.

## Verify in your tool

Before relying on it, start a session in each tool you use and check:

1. Ask the agent to run `cat .env` → it's denied with `[AI guardrail] …`.
2. Ask it to read `.env.production` → denied. `.env.example` → allowed.
3. Ask it to edit `infra/main.tf` → Claude Code and Copilot ask; Cursor denies.
4. Paste a fake key such as `sk-ant-api03-` followed by 40 letters → Claude Code and Cursor block the prompt; Copilot's model sees `[REDACTED:API_KEY_1]`.
5. Look at `.agent-guardrails/audit/guardrail-events.jsonl` → one line per decision, rule names only.

Please report results, especially differences, in an [issue](https://github.com/pixelofsoftware/AI-Mods/issues/new/choose). Report ways past a guard privately through [SECURITY.md](../SECURITY.md).
