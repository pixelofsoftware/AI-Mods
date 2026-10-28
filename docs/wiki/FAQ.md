Short answers to the questions developers, admins and security reviewers ask most. Each answer links to the page with the details.

## General

### What is Claude Guardrails?

A drop-in set of controls for teams using Claude Code and the Claude API: a one-page developer policy, four Claude Code hooks, least-privilege project settings, an organisation policy template, pre-commit and CI gates, and a Python middleware for apps that call the Claude API. See [Architecture](Architecture).

### Is this affiliated with Anthropic?

No. It's an independent community project, not affiliated with or endorsed by Anthropic. Claude and Claude Code are trademarks of Anthropic, PBC. Bugs in Claude Code, the Claude API or the `anthropic` SDK go to Anthropic, not here.

### What's the licence?

[MIT](https://github.com/pixelofsoftware/AI-Mods/blob/main/LICENSE). Use it, fork it and adapt it for your organisation.

### Is it production-ready?

It's a first release (`0.1.0` in the changelog) with 331 passing tests and two review rounds. Several things still need checking in a real environment, such as managed settings on a workstation, telemetry export and the OS sandbox. A human red-team is recommended before you rely on it in a regulated environment. See [Limitations and threat model](Limitations-and-Threat-Model).

## Day-to-day use

### Does it slow me down?

Very little. Reading code, running tests, linters and read-only git run without prompts: the project allowlists 35 such commands. Each hook is a short Python script; on a typical Linux machine one run takes about a tenth of a second. Prompts appear only where the risk is real: pushes, installs, cloud and cluster commands, and edits to infrastructure, security-critical or guardrail files. See [Daily development](Use-Case-Daily-Development).

### Why is `curl` blocked but `git push` only asks?

`curl` can send anything anywhere. One prompt injection in a README or issue could turn it into data exfiltration, and there's no way to tell a safe URL from a bad one by looking at the command. `git push` goes to a remote you configured, carries commits you can review, and is checked again by CI and code-owner review. So it asks (`Bash(git push *)`) rather than being denied. Force pushes, `--mirror`, `--delete` and `+ref`/`:ref` pushes are denied, because they rewrite shared history. See [Bash guard](Guardrail-Bash-Guard).

### What does "ask" mean in accept-edits or auto mode?

A ✋ ask from a hook means a human must approve, whatever the permission mode. That's how infrastructure, security-critical and guardrail edits keep a human in the loop even when you've told Claude Code to accept edits.

### I'm using synthetic test data and the prompt was blocked. What now?

For SSNs, card numbers, IBANs and medical record numbers, add `[sensitive-ok: <reason>]` to the prompt, for example `[sensitive-ok: synthetic fixture for parser tests]`. The reason must be 5 to 200 characters, and the override is recorded in your local audit log. Credentials can never be overridden: use the redacted copy the block message gives you, or placeholders such as `<API_KEY>`. See [Prompt guard](Guardrail-Prompt-Guard).

### Can Claude still read `.env.example`?

Yes. `.env.example`, `.env.sample`, `.env.template`, `.env.dist` and `.env.defaults` stay readable. Every other `.env*` variant and `.envrc` is denied. See [Read guard](Guardrail-Read-Guard).

### Does it work on Windows?

Use WSL2. On native Windows the hooks, permission rules and commit gate work if `python3` resolves, but Claude Code's OS sandbox isn't available. See [Installation](Installation#native-windows-without-wsl2).

### Does it need internet access?

The hooks and the scanner run entirely offline. pre-commit downloads its hook repositories the first time it runs. Inside Claude Code, the sandbox allows only `github.com`, the npm, PyPI and Go registries and your internal artifact registry.

## Control and tampering

### Can a developer turn it off?

Partly, on their own machine, and it shows up later:

| Layer | Can a developer turn it off? |
|---|---|
| Organisation policy (managed settings) | No, unless they administer the machine |
| Project settings and hooks | They control their own local settings. Project and managed deny rules still apply. The shared `.claude/settings.json` is checked by `validate-claude-config` on every commit and in CI |
| OS sandbox | On Linux, by uninstalling `bwrap`/`socat`. Admins can make Claude Code refuse to start without it (`sandbox.failIfUnavailable`) |
| Commit gate | Yes, with `git commit --no-verify`. CI runs every check again |
| Merge gate | No. Only repository admins can change branch protection |

The guardrails assume a developer who wants to do the right thing. They don't stop a determined insider with admin rights. See [Limitations and threat model](Limitations-and-Threat-Model).

### Can Claude edit the guardrails?

Not without you. Any edit to `.claude/`, `.mcp.json`, `CLAUDE.md`, `.pre-commit-config.yaml`, `.gitignore`, `pyproject.toml`, the guardrail scripts, the policy file, `enterprise/`, the guardrail docs, `.github/workflows/` or `CODEOWNERS` triggers ✋ ask, both through the edit tools and through shell writes (`>`, `tee`, `cp`, `mv`, `sed -i`, `truncate`). Claude is also denied `--no-verify`, `SKIP=…`, `core.hooksPath` changes and force pushes. Every guardrail file needs code-owner review to merge.

### Can a repository I clone redirect my telemetry or my API key?

Not through this project's checks. Claude Code ignores OpenTelemetry exporter variables in a repository's settings files. The drift check also rejects `apiKeyHelper`, `otelHeadersHelper`, `statusLine`, `disableAllHooks`, `ANTHROPIC_*`, `*_BASE_URL`, proxy variables and `NODE_OPTIONS` in shared settings. Those checks protect repositories that run them; a different repository can contain anything, which is why the organisation policy matters.

### Why isn't the deny list enough on its own?

Permission rules match command text. `Bash(curl *)` doesn't match `/usr/bin/curl`, `bash -c 'curl …'` or `$(curl …)`. The bash guard parses the real shell syntax to catch those, and the OS sandbox limits the network for everything else. See [Architecture](Architecture#defence-in-depth).

### What happens if a hook crashes?

The bash, file and read guards fail closed: on a crash, a malformed event or a broken install they answer ✋ ask with `manual review required`. The prompt guard fails open on purpose, so it never swallows your prompt, but it shows a warning such as `prompts are NOT being checked`. If `python3` is missing or a hook times out, Claude Code continues under the permission rules and the sandbox alone. See [Troubleshooting](Troubleshooting).

## Data and logging

### Does it send my data anywhere?

The hooks and the scanner make no network calls. Their audit log stays on your machine in `.claude/audit/`. Two things do send data, both by design:

- **Organisation telemetry**, if your admin deploys the managed settings: Claude Code exports metrics and events, including prompt text and tool details, to **your organisation's** OpenTelemetry collector.
- **The API middleware**, in apps that use it: it sends the **redacted** request to the Claude API and writes an audit line to your service's stdout.

### What's logged, and where?

| Log | Where | Contains | Never contains |
|---|---|---|---|
| Hook audit | `.claude/audit/guardrail-events.jsonl` on your machine (gitignored, blocked by pre-commit) | Timestamp, hook, session ID, tool, permission mode, decision, rule names, `$USER`, a 16-character hash prefix of the prompt or command, a file base name or relative path | Prompt text, file content, full commands |
| Claude Code telemetry | Your OpenTelemetry collector, if managed settings enable it | Prompts, tool decisions and details, usage and cost | Depends on collector-side redaction |
| API middleware audit | Your service's stdout | User ID, risk level, finding counts, model, verdict, token usage, a SHA-256 of the redacted prompt | The raw prompt |

See [Audit logs](Audit-Logs). Set `CLAUDE_GUARDRAIL_AUDIT=0` to turn the local hook audit off.

### Does it catch all personal data?

No. Detection is pattern-based: credentials, US SSNs, card numbers, IBANs, medical record numbers, emails and phone numbers. It won't catch free text such as a patient's name and diagnosis in a sentence. The written policy is the real control; the tooling is a safety net. See [Detectors reference](Detectors-Reference).

## Compatibility

### Does it work with other AI coding tools?

Partly. The hooks and settings are specific to Claude Code. The commit and merge gates (gitleaks, the credential scanner, `forbid-ai-artifacts`, the drift check, bandit, checkov) check any commit, whoever or whatever wrote it. `python3 scripts/claude_safeguard.py scan` checks any text. Other AI tools on the same machine aren't covered by the hooks, the permission rules or the sandbox.

### Can I use the API middleware on Amazon Bedrock, Vertex AI or Microsoft Foundry?

Yes. Pass your own client, for example `SafeClaude(client=anthropic.AnthropicBedrockMantle(aws_region="eu-central-1"))`, set the platform's model ID, and set `CLAUDE_SAFEGUARD_FALLBACKS=0`, because those platforms don't support server-side refusal fallback. The middleware is Python only. See [API safeguard](Guardrail-API-Safeguard).

### Can I use it in my own repository?

Yes. Copy the files, adjust the allowlist for your stack, run the setup script and protect `main`. See [Adopting in another repository](Use-Case-Adopting-in-Another-Repository).

## Getting help

### A guard blocked something legitimate. What do I do?

Note the rule name from the message and [open a false-positive issue](https://github.com/pixelofsoftware/AI-Mods/issues/new/choose) with synthetic input. Don't switch to an unapproved tool. See [False positives and exceptions](Use-Case-False-Positives-and-Exceptions).

### I found a way past a guard. How do I report it?

Privately, through [GitHub Security Advisories](https://github.com/pixelofsoftware/AI-Mods/security/advisories/new), not a public issue. Include the payload, the component, the expected and actual decision, and your environment, using synthetic data only. See [SECURITY.md](https://github.com/pixelofsoftware/AI-Mods/blob/main/SECURITY.md).

## Related pages

- [Installation](Installation)
- [Architecture](Architecture)
- [Troubleshooting](Troubleshooting)
- [Audit logs](Audit-Logs)
- [Limitations and threat model](Limitations-and-Threat-Model)
