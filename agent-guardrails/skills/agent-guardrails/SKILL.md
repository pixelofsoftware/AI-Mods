---
name: agent-guardrails
description: Security guardrails for AI coding agents. Use when a guardrail hook denied or asked about an action, before touching secrets, credentials or .env files, before putting personal data (PII/PHI) in prompts, test fixtures or code, before changing infrastructure-as-code (Terraform, Kubernetes, Helm, Dockerfiles, CI workflows), auth, crypto or the guardrail files themselves, and to scan text for secrets before sharing it.
---

# Agent guardrails

This project runs security hooks around the agent. They check every prompt, shell command, file write and file read **before** it happens, in Claude Code, Cursor and GitHub Copilot alike. This skill explains how to work with them. The hooks enforce the rules whether or not this skill is loaded.

## What the hooks decide

| Decision | Meaning | What to do |
|---|---|---|
| **Deny** | The action is blocked by policy | Don't retry it, rephrase it or reach the same result another way (another tool, an encoding, a script file, a variable). Tell the user what was blocked and why, and suggest the safe alternative from the message |
| **Ask** | A human must approve | Explain why the action is needed and let the user decide. Never try to make an action look harmless to avoid the prompt |
| No message | Normal permissions apply | Carry on |

Messages start with `[AI guardrail]`. Quote the message to the user; it names the reason.

## Rules to follow

1. **Never read, print, copy or write secrets.** That covers `.env` and its variants (but `.env.example`, `.sample`, `.template`, `.dist` and `.defaults` are fine), private keys, keystores, `~/.ssh`, `~/.aws`, cloud credential files, Terraform state, `secrets/` and environment dumps. Reference configuration through environment variable names instead.
2. **No arbitrary network access from the shell.** `curl`, `wget`, `nc`, `ssh`, `scp` and similar are blocked. If something must be fetched, say what and why and let the developer do it.
3. **Infrastructure and security-critical code needs a human.** For Terraform, Kubernetes, Helm, Dockerfiles, CI workflows, `auth/`, `security/` or `crypto/`: plan first, explain the security impact, expect review. Never run `terraform apply` or `destroy`, `kubectl delete`, deploys or package publishing.
4. **Don't change the guardrails** (`.claude/`, `.cursor/hooks.json`, `.github/hooks/`, `.agent-guardrails/`, pre-commit config, policy files) unless the user explicitly asks. Say so when a change loosens a control.
5. **Never bypass checks:** no `--no-verify`, no disabling hooks, no force-push.
6. **Use synthetic test data.** Build credential-shaped test strings at runtime (`"sk-" + "ant-" + ...`) rather than writing them literally. Placeholders such as `[REDACTED:EMAIL_1]` are intentional; don't guess the original.

## Procedures

**Before sharing text with any AI service or pasting it into a prompt**, scan it offline (no network call):

```bash
python3 scripts/scan.py "text to check"
python3 scripts/scan.py - < file.txt
```

Exit code 2 means the text would be blocked. The output contains a redacted copy that is safe to use.

**When the user's prompt was blocked**, the block message contains a redacted copy. For synthetic personal data (not credentials), the user can add `[sensitive-ok: <reason>]` to the prompt; the override is audited. Credentials can never be overridden: use an obvious placeholder such as `<API_KEY>`.

**When a guard blocks legitimate work** (a false positive), tell the user the rule from the message and suggest reporting it. The audit log at `.agent-guardrails/audit/guardrail-events.jsonl` names the rule. Don't work around the block.

**If a secret or personal data may have been exposed**, tell the user immediately: the credential must be rotated first, then reported.

## Reference

- [references/policy.md](references/policy.md): the full developer policy (risk tiers, data protection, human review, tooling).
- Project wiki: https://github.com/pixelofsoftware/AI-Mods/wiki (every rule, setting and use case).
