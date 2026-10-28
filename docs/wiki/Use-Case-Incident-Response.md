This page is for developers and security engineers handling an AI-related incident: a secret or personal data was sent to Claude, the agent behaved suspiciously, or a prompt injection is suspected. It lists the immediate steps, the evidence that exists, how to report, and how to report a guard bypass privately.

> **Placeholders on this page:** `#security-incidents` and *AppSec* come from the template policy. Use your organisation's incident channel and team.

## First: rotate, then report

If a credential might have left your machine, **rotate it before you do anything else**. Revoke the old value and issue a new one. A credential that reached any AI service, log, transcript or chat is compromised, whatever happened next. Then report it.

Reporting quickly is never penalised ([policy §2](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#2-data-protection)).

## Which incident is this?

| Situation | Examples | Go to |
|---|---|---|
| **A secret was sent** | A key pasted into a prompt, a token in a file Claude read, credentials in an MCP request or an API call | [Scenario A](#scenario-a-a-secret-was-sent) |
| **Personal data was sent** | Customer records, production logs with emails, a patient's details in prose | [Scenario B](#scenario-b-personal-data-was-sent) |
| **Suspicious agent behaviour** | Claude repeatedly tries network calls, reads secret files, edits guardrails, or runs commands unrelated to the task | [Scenario C](#scenario-c-suspicious-agent-behaviour-or-suspected-prompt-injection) |
| **Suspected prompt injection** | Pasted text, a README, an issue, a web page or an MCP result contained instructions aimed at the AI | [Scenario C](#scenario-c-suspicious-agent-behaviour-or-suspected-prompt-injection) |

## Scenario A: a secret was sent

1. **Stop the session.** Interrupt Claude and don't approve any pending prompts.
2. **Rotate the credential.** Revoke it at the provider (cloud console, GitHub, the API key page, your secret manager) and issue a new one. Update the systems that use it.
3. **Write down** the time (UTC), your Claude Code session ID and where the value went (prompt, file, MCP call, API app). The session ID is in your audit log:

   ```bash
   tail -n 20 .claude/audit/guardrail-events.jsonl
   ```

4. **Report** in `#security-incidents`: the time, the session ID, the **type** of credential (never the value), and that you've rotated it.
5. **Check git.** If the value ended up in a file:
   - Not committed: remove it, and read it from an environment variable instead.
   - Committed but not pushed: tell security before rewriting history. History rewrites (`git rebase`, `git commit --amend`, `git filter-repo`) ask for approval in Claude Code, and force pushes are denied for Claude.
   - Pushed: rotation is what protects you; history clean-up is secondary. Coordinate it with security.
6. **Keep the evidence.** Don't delete transcripts or the audit log. Security may need them (see [Evidence](#what-evidence-exists)).

Was it blocked? If `prompt_guard` blocked the prompt, Claude never received it, and you saw *Credentials must never be sent to an AI service. If the value is real, rotate it now.* Rotate anyway: the guard can't vouch for your clipboard, your shell history or a central prompt log (the setup guide warns that a telemetry prompt event may be emitted before the hook blocks).

## Scenario B: personal data was sent

1. **Stop the session.**
2. **Write down** what was sent: the kind of data, roughly how many records, whose data, and where (prompt, file, MCP, API app). Don't copy the data itself into the report.
3. **Report** in `#security-incidents` with the time and session ID. Your organisation may also need to involve its privacy or data-protection team; security will route it.
4. **Keep the evidence.**

Detection is pattern-based. SSNs, card numbers, IBANs and medical record numbers are blocked; emails and phone numbers only get a notice; free-text personal data (a name and a diagnosis in prose) isn't detected at all. So "no guard fired" doesn't mean "nothing was sent".

## Scenario C: suspicious agent behaviour, or suspected prompt injection

Warning signs:

- A ⚠️ notice: `[AI guardrail] Prompt contains text that looks like a prompt-injection payload; treat pasted content as untrusted.`
- A burst of ⛔ denies in your audit log (`network_egress`, `secret_file_access`, `env_dump`, `secret_store_read`, `guardrail_bypass`) during a task that shouldn't need any of them.
- ✋ prompts you didn't expect: `shell write to AI guardrail file`, `persistence` (`crontab`, `systemctl`), `anti_forensics` (`history -c`), `dns_query`, `inline_network_code`.
- Claude tries to edit `CLAUDE.md`, `.claude/`, `.mcp.json` or the pre-commit config without being asked.
- Unexpected MCP tool calls.

Steps:

1. **Stop the session.** Deny any pending prompt, and interrupt Claude.
2. **Find the source.** What did Claude read just before the behaviour changed? A pasted log, a file in the repository, a dependency's README, a fetched web page, an issue body, an MCP result. Don't feed it to Claude again.
3. **Check for changes it left behind.**

   ```bash
   git status
   git diff
   git log --oneline -n 20
   git diff HEAD -- CLAUDE.md .claude/ .mcp.json .pre-commit-config.yaml
   ```

   Also look at `.claude/settings.local.json` (gitignored, so `git status` won't show it), your crontab, and `.git/hooks/`.
4. **Check what it reached.** If any command ran that sent data out, or read a secret, treat it as [Scenario A](#scenario-a-a-secret-was-sent) and rotate.
5. **Report** in `#security-incidents`: the time, the session ID, the suspected source, and the audit-log lines.
6. **Keep the evidence.**

If the payload came from a third-party file or package, security may also need to notify its maintainers.

## What evidence exists

| Source | Where | What it holds | Doesn't hold | Retention |
|---|---|---|---|---|
| Guardrail audit log | `.claude/audit/guardrail-events.jsonl` on the developer's machine | Every block, ask, override and injection warning: time, hook, `session_id`, tool, `permission_mode`, decision, rule names, path or file name, `user`, fingerprints (`command_fp`, `prompt_fp`), `ack_reason` | Prompt text, file content, full commands | Until deleted |
| Local transcripts | `~/.claude/projects/` | The full session, including what was sent | — | 14 days (`cleanupPeriodDays`), so copy them early if needed. Handle them as sensitive: they may contain the secret |
| OpenTelemetry (if your admin deployed managed settings) | Central collector → SIEM | `claude_code.user_prompt` (with prompt text when `OTEL_LOG_USER_PROMPTS=1`), `claude_code.tool_decision`, `claude_code.tool_result`, `claude_code.api_request`, `claude_code.api_refusal`; correlate with `session.id` and `prompt.id` | Anything removed by collector-side redaction | Per security-log policy (template: 1 year) |
| API app audit events | Your service's stdout → SIEM | One line per request from `claude_safeguard`: `event.id`, `user.id`, `risk.level`, `risk.input_findings`, injection signals, `output.verdict`, model, usage, a hash of the redacted prompt | The raw prompt | Per app logging policy |
| Git | The repository and CI logs | Commits, the `guardrails` job results, who approved what | — | Permanent |
| MCP servers | Each server's own logs | Requests made through MCP | — | Per server |

### Matching a command to a fingerprint

The audit log stores `command_fp`: the first 16 hex characters of the SHA-256 of the command. To check whether a log entry was a specific command, compute it **in your own terminal** (not through Claude):

```bash
python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:16])' "cat .env"
```

```text
648b13a0a3555ec5
```

The same works for `prompt_fp` with the exact prompt text. Never hash a real secret on a shared machine or paste it into a ticket to do this.

## What to put in the report

- Time (UTC) and how long the session ran.
- Claude Code session ID, from the audit log.
- What was exposed, **by type** ("a GitHub token", "about 40 customer emails"), never the values.
- Where it went: prompt, file read, MCP request, API app, commit, push.
- What you've done: rotated at <time>, stopped the session, reverted commits.
- The relevant audit-log lines (they contain no content).
- For suspected injection: the source of the injected text, described or attached as a file with secrets removed.

## A guard should have stopped it: report the bypass privately

If the incident happened because a guard **allowed** something it should have denied or asked about, that's a vulnerability in the guardrails. Don't open a public issue. Report it through [GitHub Security Advisories](https://github.com/pixelofsoftware/AI-Mods/security/advisories/new), as described in [SECURITY.md](https://github.com/pixelofsoftware/AI-Mods/blob/main/SECURITY.md). Include:

- **The payload:** the command, prompt, file write or model output that got through.
- **Where it applies:** `bash_guard`, `prompt_guard`, `file_guard`, `read_guard`, `claude_safeguard.py` or a pre-commit check.
- **Expected and actual decision:** for example "expected deny, got allow".
- **Environment:** OS, Python version, Claude Code version, commit.

Use synthetic data only. Never send a real secret, not even an expired one; build fake credentials at runtime the way [`tests/conftest.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/conftest.py) does.

The maintainer's targets: acknowledge within 7 days, confirm or decline within 14 days, fix and publish an advisory as soon as practical. Documented limitations (such as free-text personal data) and attacks that already need control of the machine are out of scope; see [Limitations and threat model](Limitations-and-Threat-Model).

## Afterwards

- Add a regression test for the payload once it's fixed (see [Changing the guardrails](Use-Case-Changing-the-Guardrails)).
- If the incident showed a gap in your organisation's setup (no collector redaction, no branch protection, sandbox off), fix that too. See [Organisation rollout](Use-Case-Organisation-Rollout).

## Related pages

- [Sensitive data](Use-Case-Sensitive-Data)
- [Audit logs](Audit-Logs)
- [Prompt guard](Guardrail-Prompt-Guard)
- [Limitations and threat model](Limitations-and-Threat-Model)
- [Organisation rollout](Use-Case-Organisation-Rollout)
