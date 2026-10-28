Welcome to the **Claude Guardrails** wiki: the deep dive behind the [README](https://github.com/pixelofsoftware/AI-Mods#readme). It explains every guardrail, every setting and every common use case, with real outputs from the code.

> **New here?** Start with the [README](https://github.com/pixelofsoftware/AI-Mods#readme) for the 10-minute overview, then come back for the details.

## Find your way

| I want to… | Start here |
|---|---|
| Install it and check it works | [Installation](Installation) |
| Understand how the pieces fit | [Architecture](Architecture) |
| Know why something was blocked | [Troubleshooting](Troubleshooting) and the guardrail pages below |
| Roll it out across a company | [Organisation rollout](Use-Case-Organisation-Rollout) |
| Protect an app built on the Claude API | [Claude API apps](Use-Case-Claude-API-Apps) |
| Use it in my own repository | [Adopting in another repository](Use-Case-Adopting-in-Another-Repository) |
| Know what it does **not** protect against | [Limitations and threat model](Limitations-and-Threat-Model) |

## 🛡️ Guardrails

Each page lists every rule, what triggers it, real examples, and what to do about a false positive.

| Guardrail | Runs on | Page |
|---|---|---|
| Prompt guard | Every prompt, before it reaches Claude | [Guardrail-Prompt-Guard](Guardrail-Prompt-Guard) |
| Bash guard | Every shell command Claude runs | [Guardrail-Bash-Guard](Guardrail-Bash-Guard) |
| File guard | Every file Claude writes or edits | [Guardrail-File-Guard](Guardrail-File-Guard) |
| Read guard | Every file Claude reads or searches | [Guardrail-Read-Guard](Guardrail-Read-Guard) |
| Commit and merge gates | `git commit`, `git push` and every pull request | [Guardrail-Commit-and-Merge-Gates](Guardrail-Commit-and-Merge-Gates) |
| API safeguard | Every request your app sends to the Claude API | [Guardrail-API-Safeguard](Guardrail-API-Safeguard) |
| Detectors | The credential and personal-data patterns they share | [Detectors-Reference](Detectors-Reference) |

## ⚙️ Settings

Every key and every rule, with the reason it's set the way it is.

| File | Page |
|---|---|
| `.claude/settings.json`: permissions, sandbox, hooks | [Settings-Project](Settings-Project) |
| `enterprise/managed-settings.json`: org policy, telemetry | [Settings-Organisation-Policy](Settings-Organisation-Policy) |
| `.mcp.json`: approved MCP servers | [Settings-MCP-Servers](Settings-MCP-Servers) |
| `config/claude-guardrails-policy.json`: the drift-check baseline | [Settings-Policy-Baseline](Settings-Policy-Baseline) |
| Environment variables | [Settings-Environment-Variables](Settings-Environment-Variables) |
| `.pre-commit-config.yaml` | [Settings-Pre-Commit](Settings-Pre-Commit) |

## 🧭 Use cases

Step-by-step walkthroughs showing what you'll see at each step.

- [Daily development](Use-Case-Daily-Development): a normal day with Claude Code
- [Sensitive data](Use-Case-Sensitive-Data): working near secrets and personal data
- [Infrastructure and security code](Use-Case-Infrastructure-and-Security-Code): Terraform, Kubernetes, CI, auth
- [Organisation rollout](Use-Case-Organisation-Rollout): from pilot to company-wide
- [Claude API apps](Use-Case-Claude-API-Apps): `SafeClaude` in your service
- [Adopting in another repository](Use-Case-Adopting-in-Another-Repository)
- [False positives and exceptions](Use-Case-False-Positives-and-Exceptions)
- [Incident response](Use-Case-Incident-Response)
- [Changing the guardrails](Use-Case-Changing-the-Guardrails)

## 📚 Reference

- [Audit logs](Audit-Logs): what is recorded, and what never is
- [Troubleshooting](Troubleshooting)
- [FAQ](FAQ)
- [Limitations and threat model](Limitations-and-Threat-Model)

## Legend

Used on every page:

| Symbol | Meaning |
|---|---|
| ⛔ | **Deny / Block**: stopped outright |
| ✋ | **Ask**: a human must approve, even in auto-accept modes |
| ⚠️ | **Warn**: allowed, with a notice |
| ✅ | **Allow**: runs without a prompt |

## Contributing to this wiki

These pages are generated from [`docs/wiki/`](https://github.com/pixelofsoftware/AI-Mods/tree/main/docs/wiki) in the main repository, so edits go through a pull request and CI like any other change. Please don't edit pages directly on GitHub; the next publish would overwrite them. See [CONTRIBUTING.md](https://github.com/pixelofsoftware/AI-Mods/blob/main/CONTRIBUTING.md).

Found a way past a guardrail? Please report it privately: see [SECURITY.md](https://github.com/pixelofsoftware/AI-Mods/blob/main/SECURITY.md).
