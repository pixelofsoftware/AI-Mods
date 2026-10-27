# Security policy

Claude Guardrails is a security tool, so a way around it is a vulnerability. Please report it privately.

## Reporting a vulnerability

**Don't open a public issue.** Report it through [GitHub Security Advisories](https://github.com/pixelofsoftware/AI-Mods/security/advisories/new).

Please include:

- **The payload:** the command, prompt, file write or model output that gets through
- **Where it applies:** the hook or component (`bash_guard`, `prompt_guard`, `file_guard`, `read_guard`, `claude_safeguard.py`, a pre-commit check)
- **Expected and actual decision:** for example "expected deny, got allow"
- **Environment:** OS, Python version, Claude Code version and the commit you tested

Use synthetic data only. **Never send a real secret, key or personal data**, not even an expired one. Build fake credentials the way the tests do (see `tests/conftest.py`).

## What happens next

This project has one maintainer, so these are targets, not guarantees:

| Step | Target |
|---|---|
| Acknowledge your report | Within 7 days |
| Confirm or decline, with reasoning | Within 14 days |
| Fix and publish an advisory | As soon as practical, depending on severity |

You'll be credited in the advisory and in `CHANGELOG.md` unless you'd rather not be.

## Scope

**In scope**

- A command, prompt or file operation that a guard should deny or ask about but allows. This covers shell parsing tricks, wrappers, encodings and path variants.
- A credential or personal-data format that a detector claims to support but misses.
- Model output that `OutputValidator` should block but passes.
- A change that weakens `.claude/settings.json` or `.mcp.json` but passes the `validate-claude-config` drift check.
- A failure mode where a hook "fails open" and allows instead of asking.
- Bugs in this code itself, such as catastrophic regex backtracking (ReDoS), code execution, or audit logs recording secret values.

**Out of scope**

- **Documented limitations** in the README's "Honest limitations" section. For example, free-text personal data such as a name and diagnosis written in prose isn't detected.
- **Attacks that already require control of the machine,** such as editing managed settings with admin rights or replacing the hook scripts.
- **False positives,** where a guard blocks something legitimate. Please open a normal [false-positive issue](https://github.com/pixelofsoftware/AI-Mods/issues/new/choose) instead.
- **Vulnerabilities in Claude Code, the Claude API or the `anthropic` SDK themselves.** Report those to Anthropic through its responsible disclosure policy.

## Supported versions

Only the latest release and `main` receive security fixes.
