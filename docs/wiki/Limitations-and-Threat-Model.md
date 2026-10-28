This page says plainly what Claude Guardrails protects against, what it doesn't, where the known gaps are, and what still has to be verified in a real environment. Read it before you rely on the framework, and use it to decide which compensating controls you need.

## Trust assumptions

| Actor | Assumed to be | Why it matters |
|---|---|---|
| The developer | Trusted, but busy and fallible: they might paste a secret, approve a prompt too quickly, or use real data in a test | Most controls catch mistakes. They aren't designed to stop a determined insider |
| Claude (the agent) | Helpful, but steerable by content it reads: a README, an issue, a web page, an MCP result or a tool output can carry prompt injection | Every risky action is checked outside the model. No control relies on Claude following `CLAUDE.md` |
| Admins | Trusted. They deploy managed settings and set branch protection | The top layers are only as strong as their deployment |
| The workstation | Not compromised. Claude Code, Python, git and the hook scripts are what they claim to be | An attacker with control of the machine can replace or bypass any local control |
| Model output in your apps | Untrusted input | The API middleware validates it, and the policy says never to execute it unchecked |

## What it defends against

| Threat | Main controls | Layers |
|---|---|---|
| **Accidental disclosure of secrets or regulated personal data** in prompts | `prompt_guard` blocks credentials (no override) and SSNs, card numbers, IBANs and medical record numbers (override with `[sensitive-ok: …]`), and offers a redacted copy. The API middleware redacts before sending | Hooks, API middleware |
| **The agent reading secrets** | `read_guard`, `Read(...)` deny rules, `bash_guard`'s `secret_file_access`, `secret_echo`, `env_dump` and `secret_store_read` rules, `blockReadsOutsideWorkingDirectories`, and `sandbox.filesystem.denyRead` for `~/.ssh`, `~/.aws` and other credential locations | Project, hooks, sandbox, org |
| **Secrets or session data committed** | `file_guard` denies hardcoded keys and writes to secret files; `scan-ai-secrets`, gitleaks, `detect-private-key` and `forbid-ai-artifacts` at commit; `.gitignore`; CI repeats it all | Hooks, commit gate, merge gate |
| **Risky agent commands** | `bash_guard` parses real shell and denies network clients, `sudo`, force pushes, `terraform apply`, `kubectl delete`, publishing, destructive deletes and privileged containers; it asks about cluster, cloud, history and persistence changes. Permission rules and the managed baseline repeat the key denies | Hooks, project, org |
| **Prompt-injection-driven actions**, such as exfiltration through `curl` | Network clients denied, `WebSearch` denied, `WebFetch` always asks, sandbox network allowlist, MCP server allowlist, injection-phrasing warnings in prompts. In apps: a hardening preamble, a canary token and output validation | Hooks, sandbox, org, API middleware |
| **Guardrail tampering** | ✋ ask on every edit or shell write to guardrail files, `--no-verify`/`SKIP=`/`core.hooksPath` denied, bypass mode disabled, `validate-claude-config` drift check, CODEOWNERS review, CI re-runs everything | Hooks, commit gate, merge gate, org |
| **Unreviewed infrastructure and security-critical code** | `file_guard` asks before any edit to IaC, CI, auth, crypto or access-control paths, even in accept-edits or auto mode. Applies and deletes are denied in the shell. checkov at commit, code-owner review at merge | Hooks, commit gate, merge gate |
| **Unsafe model output in your apps** | `OutputValidator` blocks reverse shells, encoded execution, destructive commands, credential exfiltration, markdown-image exfiltration, invisible Unicode, leaked secrets and canary leaks, and checks `tool_use` inputs too | API middleware |

The deep-dive pages list every rule: [Prompt guard](Guardrail-Prompt-Guard), [Bash guard](Guardrail-Bash-Guard), [File guard](Guardrail-File-Guard), [Read guard](Guardrail-Read-Guard), [Commit and merge gates](Guardrail-Commit-and-Merge-Gates), [API safeguard](Guardrail-API-Safeguard).

## What it doesn't defend against

| Out of scope | Why | What to do instead |
|---|---|---|
| **Free-text personal data**, such as a patient's name and diagnosis written in a sentence | Detection is pattern-based. It finds credentials, SSNs, card numbers, IBANs, medical record numbers, emails and phone numbers, not names or facts in prose | The written [policy](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#2-data-protection) is the real control. ML-based detection is on the roadmap |
| **A malicious developer with admin rights** | They can edit managed settings, replace the hook scripts, uninstall the sandbox tools, or push from another tool. [SECURITY.md](https://github.com/pixelofsoftware/AI-Mods/blob/main/SECURITY.md) lists this as out of scope | Endpoint management, least-privilege admin rights, branch protection that applies to admins, and normal insider-threat controls |
| **Determined evasion of pattern-based detection** | New credential formats, unusual encodings, and indirection the shell parser can't resolve without running the command can slip past the regexes and the bash guard | Defence in depth: the sandbox, managed deny rules, secret scanning at commit, and short-lived credentials. Report what you find (see below) |
| **Anything outside Claude Code** | Other AI tools, IDE plugins, browser chat and copy-paste aren't covered by the hooks, permission rules or sandbox | The commit and merge gates still check every commit. The policy forbids unapproved AI tools |
| **A compromised machine or supply chain** | If Claude Code, Python, git, a pre-commit hook repository or the hook scripts are tampered with, local checks can't be trusted | EDR, disk encryption, pinned and reviewed dependencies, and the server-side merge gate |
| **Vulnerabilities in Claude Code, the Claude API or the `anthropic` SDK** | They belong to Anthropic | Report them through Anthropic's responsible disclosure policy |

## Known gaps

These come from the code and the project's own test and review records.

### Hooks

- **The prompt guard fails open.** If its rules can't load, or it hits an error, the prompt goes through with a visible warning (`prompts are NOT being checked`, or `prompt_guard error: <name>`). This is deliberate, so a broken install never swallows a prompt, but nothing checks prompts until you fix it. The three tool hooks fail closed (✋ ask).
- **Hooks that don't run can't fail closed.** If `python3` isn't on `PATH`, or a hook passes its 15-second timeout, Claude Code reports a non-blocking hook error and the call continues under the permission rules and the sandbox alone.
- **Some tools have no hook.** Hooks cover prompts, `Bash`/`Monitor`, `Write`/`Edit`/`MultiEdit`/`NotebookEdit` and `Read`/`Grep`/`Glob`/`NotebookRead`. MCP tool calls, `WebFetch` and other tools rely on permission rules (`WebFetch` and `mcp__internal-tickets__*` ask) and on the managed MCP allowlist.
- **Huge prompts are partly scanned.** Above 500,000 characters, the prompt guard scans only the first and last 250,000 characters.
- **Grep over a folder.** `read_guard` checks Grep's `path` and `glob`, not its search pattern. A Grep over a folder without a glob relies on ripgrep skipping gitignored files such as `.env` (listed in the [backlog](https://github.com/pixelofsoftware/AI-Mods/blob/main/.sdlc/claude-guardrails/backlog.md)).
- **Bare commands and ask rules.** The test record notes that `git push`, `npm install` and `git rebase` have no bare (no-argument) ask rule. The bash guard has no opinion on a plain `git push`, so the permission mode decides.
- **The bash guard sees text, not values.** It treats a command name computed at runtime as ✋ ask, but it can't know what a variable holds when the command runs.
- **Path lists live in several places.** The secret and guardrail path lists are repeated in the hooks, settings, CODEOWNERS, `.gitignore` and the policy file. Drift tests keep them in sync; loading them from one file is on the roadmap.

### Configuration and process

- **Local settings aren't drift-checked.** `validate-claude-config` checks the shared `.claude/settings.json` and `.mcp.json`. A developer's own `.claude/settings.local.json` and user settings aren't checked, though project and managed deny rules still apply.
- **The sandbox can be absent.** Without `bwrap` and `socat` on Linux, or on native Windows, Bash runs without OS isolation. The setup script only warns.
- **Allowed domains are reachable.** Code that runs in the sandbox, including allowlisted test suites, can reach `github.com`, the npm, PyPI and Go registries and your internal registry.
- **`deniedMcpServers`.** The managed pattern `http://*:*/*` only matches URLs with an explicit port (test record). The managed HTTPS allowlist with `allowManagedMcpServersOnly: true` is the control that counts.
- **Exceptions.** The policy says approved exceptions are recorded in `config/claude-guardrails-policy.json`, but the file has no `exceptions` field yet.
- **Telemetry may contain what the prompt guard blocked.** Whether Claude Code emits `claude_code.user_prompt` before a hook blocks a prompt isn't documented. Assume it can, and redact at the collector.
- **Identity in logs is client-controlled.** The hook audit `user` field comes from `$USER`, and the OTEL helper's `X-Claude-User` header too. Attribute events from the authenticated collector token or mTLS certificate.
- **Fingerprints aren't secrets.** Audit records hold a 16-character unsalted SHA-256 prefix of the prompt or command. Someone with the log can confirm a guess for a short input. The log stays on the developer's machine.

### API middleware

- **Images and PDFs aren't scanned** unless you set `CLAUDE_SAFEGUARD_BLOCK_UNSCANNABLE=1`, which refuses them.
- **Only credentials block by default.** SSNs, cards and other HIGH findings are redacted and sent. Set `CLAUDE_SAFEGUARD_BLOCK_ON=high` to refuse them.
- **The service owner can weaken it** with environment variables such as `CLAUDE_SAFEGUARD_BLOCK_ON=none` or `CLAUDE_SAFEGUARD_OUTPUT_ACTION=warn`.
- **Output validation is pattern-based.** Treat every reply as untrusted, as the policy requires.

## Still to be verified in a real environment

From the [verification record](https://github.com/pixelofsoftware/AI-Mods/blob/main/.sdlc/claude-guardrails/verification.md). The configuration and the drift checks are tested; these behaviours need a real machine, collector or human:

| Item | How to check |
|---|---|
| Managed settings, slash commands and permission precedence | Setup guide A4 and B4 on a managed workstation: `/status` lists managed settings, `claude doctor` shows no errors |
| OpenTelemetry export and prompt logging | Submit a prompt and look for `claude_code.user_prompt` at the collector. If nothing arrives, run `claude --debug-file /tmp/cc.log` and search for `[3P telemetry]` |
| OS sandbox | Install `bubblewrap` and `socat`, run `/sandbox`, and try a domain that isn't allowlisted |
| MCP allowlist enforcement | `claude mcp add --transport http test https://example.com/mcp` must fail on a managed machine |
| Live API calls, server-side fallback and real refusals | `python3 scripts/claude_safeguard.py ask --user test "hello"` |
| Adversarial red-team of the hooks | A human red-team. Both automated adversarial review passes were cut short |
| Independent review of the last iteration | Optional re-run; the iteration-4 review was a clean-room pass, not independent |

## Residual risk by layer

| Layer | Residual risk | Compensating controls |
|---|---|---|
| **Organisation policy** | Not deployed, deployed to only some machines, or edited by a local admin | Deploy through MDM or the admin console and check compliance. Confirm with `/status`. Consider `forceLoginMethod` with `forceLoginOrgUUID`, `allowManagedPermissionRulesOnly` and `allowManagedHooksOnly` ([setup guide B5](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md#b5-optional-hardening)) |
| **Project settings and hooks** | Pattern-based detection misses something; a developer weakens their local settings; a hook doesn't run | Deploy the hooks centrally with `allowManagedHooksOnly`. Keep the managed deny baseline. Keep Claude Code and Python current. Red-team the bash guard |
| **OS sandbox** | Missing dependencies; allowed domains used as an exfiltration channel | `sandbox.failIfUnavailable: true` on supported platforms. Keep the domain list short and use an internal registry proxy. Add network egress filtering outside the workstation |
| **Commit gate** | Skipped with `--no-verify`, or hooks never installed | CI repeats every check. Require the `ai-guardrails / guardrails` status check |
| **Merge gate** | Branch protection off, admins exempt, or a single code owner | Require code-owner review, block force pushes, apply the rules to admins, and use GitHub teams rather than one person in CODEOWNERS |
| **Telemetry** | Prompt text, and possibly secrets, in central logs | Collector-side redaction, restricted access, retention matching your security-log policy. Leave `OTEL_LOG_ASSISTANT_RESPONSES` and `OTEL_LOG_RAW_API_BODIES` off |
| **API middleware** | Free-text personal data sent; weakened by configuration; unsafe output used unchecked | Architecture review before handling personal, health or financial data. Pin the configuration in deployment manifests. Alert on `outcome: blocked` and `verdict: WARN`/`BLOCK` audit events. Never execute model output |
| **Workstation** | Compromise, stolen credentials | EDR, disk encryption, short-lived credentials from a secret manager, fast rotation ([Incident response](Use-Case-Incident-Response)) |

## Reporting a bypass

A way around a guard is a vulnerability. Report it privately through [GitHub Security Advisories](https://github.com/pixelofsoftware/AI-Mods/security/advisories/new), not a public issue. Include:

- **The payload:** the command, prompt, file write or model output that gets through
- **Where it applies:** `bash_guard`, `prompt_guard`, `file_guard`, `read_guard`, `claude_safeguard.py` or a pre-commit check
- **Expected and actual decision:** for example "expected deny, got allow"
- **Environment:** OS, Python version, Claude Code version and the commit you tested

Use synthetic data only, built the way [`tests/conftest.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/conftest.py) builds fake credentials. Never send a real secret, even an expired one.

In scope: a guard that allows what it should deny or ask about, a detector that misses a format it claims to support, model output that `OutputValidator` should block, a weakening change that passes `validate-claude-config`, a hook that fails open, and bugs such as ReDoS or audit logs recording secrets. Out of scope: the documented limitations above, attacks that already need control of the machine, false positives (open a [normal issue](https://github.com/pixelofsoftware/AI-Mods/issues/new/choose)), and vulnerabilities in Anthropic's products.

The project has one maintainer, so the targets are: acknowledge within 7 days, confirm or decline within 14 days, then fix and publish an advisory as soon as practical. Only the latest release and `main` get security fixes. See [SECURITY.md](https://github.com/pixelofsoftware/AI-Mods/blob/main/SECURITY.md).

## Related pages

- [Architecture](Architecture)
- [Detectors reference](Detectors-Reference)
- [Organisation policy](Settings-Organisation-Policy)
- [Incident response](Use-Case-Incident-Response)
- [Audit logs](Audit-Logs)
- [FAQ](FAQ)
