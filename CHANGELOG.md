# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-27

First public release.

### Added

- **Claude Code hooks**, standard-library Python only:
  - `prompt_guard`: blocks credentials and sensitive personal data in prompts and offers a redacted copy.
  - `bash_guard`: parses real shell syntax (pipelines, `$(…)`, heredocs, `bash -c`, wrappers). It denies network egress, secret access, privilege escalation, guardrail bypasses, force pushes, infrastructure applies and package publishing, and asks for approval on risky changes.
  - `file_guard`: denies writes to secret files and hardcoded keys. It asks for human review on infrastructure-as-code, security-critical code and the guardrails themselves.
  - `read_guard`: denies reads of secret files and credential directories.
- **Least-privilege project settings** (`.claude/settings.json`): an allowlist of safe commands, ask and deny rules, bypass mode disabled, an OS sandbox with a domain allowlist, and approved MCP servers only.
- **Organisation policy template** (`enterprise/managed-settings.json`): OpenTelemetry export with a keychain-backed headers helper, an org-wide deny baseline, an MCP server allowlist and managed sandbox domains.
- **Commit and merge gates**: gitleaks, bandit, checkov, a credential scanner shared with the hooks, a block on Claude session transcripts and key files, and a drift check that fails any commit that weakens the guardrail configuration. CI repeats all of these and runs the test suite.
- **Claude API middleware** (`scripts/claude_safeguard.py`): redaction with stable placeholders, a local block on credentials, a hardening preamble and canary token, server-side refusal fallback, output validation and one ECS-style JSON audit event per request. It also provides `scan` and `check-output` command-line tools.
- **Documentation**: a developer policy, a step-by-step setup guide for developers, admins and API teams, and a one-command installer with a self-test.
- **More than 300 tests**, including regression tests for every finding from the independent security and code-quality reviews.

[Unreleased]: https://github.com/pixelofsoftware/AI-Mods/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pixelofsoftware/AI-Mods/releases/tag/v0.1.0
