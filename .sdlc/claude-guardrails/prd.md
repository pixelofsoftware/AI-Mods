# PRD: Claude enterprise guardrail framework

## Goal
Let developers use Claude Code and the Claude API productively while enforcing enterprise security, data-privacy and code-quality controls, with low enough friction that nobody routes around them to unsanctioned AI tools ("shadow AI").

## User stories
- **US-1 Developer**: I can ask Claude low-risk questions and run tests/lint without approval prompts, so the tool is faster than the alternatives.
- **US-2 Security**: credentials and regulated personal data never leave a workstation or an app inside a prompt.
- **US-3 Platform/SRE**: AI-generated infrastructure and security-critical code always gets a human review before it ships.
- **US-4 Compliance**: every AI session produces an auditable trail (who, when, risk level) in our SIEM.
- **US-5 App developer**: I have a drop-in wrapper that redacts, logs and validates Claude API traffic.
- **US-6 New joiner**: I can install and verify the guardrails by following one step-by-step guide.

## Acceptance criteria
- **AC-1 Policy doc**: `docs/claude-guardrails.md` covers execution controls (supervised vs autopilot by risk tier), data protection (no PII/PHI/production credentials), mandatory HITL review for IaC and security-critical code, and tooling (approved MCP servers, restricted commands incl. blanket curl/wget block). Professional, developer-friendly, concise.
- **AC-2 Settings**: `.claude/settings.json` is valid JSON that (a) allowlists safe commands (`npm run test`, `git status`, ...), (b) denies `WebSearch` and asks for every `WebFetch`, (c) denies curl/wget and secret-file reads, (d) disables bypass mode, (e) approves only the internally hosted MCP servers from `.mcp.json`, (f) wires the guard hooks, (g) enables the sandbox without unsandboxed fallback.
- **AC-3 Telemetry**: OpenTelemetry + prompt logging are configured where Claude Code honors them (managed settings: `CLAUDE_CODE_ENABLE_TELEMETRY`, OTLP exporters, `OTEL_LOG_USER_PROMPTS=1`), and the docs say plainly why repo settings cannot do this.
- **AC-4 MCP**: `.mcp.json` lists only https internal servers with credentials via `${VAR}`; managed settings enforce a URL allowlist (`allowManagedMcpServersOnly`).
- **AC-5 Bash guard**: given a Bash command, the PreToolUse hook denies network egress (`curl`, `wget`, incl. `/usr/bin/curl`, `bash -c 'curl …'`, `$(curl …)`, `xargs curl`), secret access (`cat .env`, `~/.ssh`, env dumps, secret-store reads), privilege escalation, force-push, `--no-verify`, `terraform apply/destroy`, package publish; asks for pipe-to-shell, kubectl apply, history rewrites; stays silent for `git status`, `npm run test`, `pytest`, `cat .env.example`.
- **AC-6 File guard**: Write/Edit containing a hardcoded credential is denied; writes to `.env`/key files are denied; edits to IaC, security-critical paths and guardrail files return `ask`.
- **AC-7 Prompt guard**: prompts with credentials are blocked (no override) and the reason includes a redacted copy; HIGH PII is blocked unless `[sensitive-ok: reason]`; emails pass with a notice; clean prompts produce no output.
- **AC-8 Pre-commit**: `.pre-commit-config.yaml` runs secret detection (gitleaks + detect-private-key + custom), SAST (bandit, checkov), and blocks committing `.claude/settings.local.json`, `.claude/audit/*`, transcripts (`*.jsonl`), local MCP configs, `.env`, keys; validates `.claude/settings.json`/`.mcp.json` against `config/claude-guardrails-policy.json`.
- **AC-9 Wrapper redaction**: `scripts/claude_safeguard.py` masks emails, SSNs, card numbers (Luhn), IBAN, phone, MRN and credentials before the request is built; same value → same placeholder; vendor test values (e.g. `AKIAIOSFODNN7EXAMPLE`, `4242…`) are not flagged.
- **AC-10 Wrapper observability**: one JSON line per request on stdout with timestamp, user, request id, risk level, finding counts, model, usage, outcome; never the raw prompt.
- **AC-11 Wrapper output validation**: responses with reverse shells, encoded exec, `rm -rf /`, credential exfil, markdown-image exfil, invisible Unicode, leaked secrets or system-prompt canary are BLOCK; curl|sh, chmod 777, injection echoes are WARN; policy `raise|sanitize|warn`.
- **AC-12 Wrapper blocking**: CRITICAL input (configurable) raises `PromptBlockedError` without any network call; refusals (`stop_reason=refusal`) are surfaced, not crashed on.
- **AC-13 Setup guide**: `docs/claude-guardrails-setup.md` gives step-by-step install, configuration and usage for developers (Claude Code), admins (managed settings, OTEL, MCP) and app developers (wrapper), with verification commands.
- **AC-14 Least privilege**: no allow rule grants blanket Bash/WebFetch; bypass mode disabled; sandbox network allowlist minimal; hooks fail closed (`ask`) on internal error (prompt guard fails open with a visible notice, by design, see edge cases).

## Edge cases
- Commands with unbalanced quotes → `ask` (or `deny` if a network client is visible).
- Placeholders (`${TOKEN}`, `<your-key>`, `os.environ[...]`, `self.api_key`) are not secrets.
- Overlapping detections (key inside a URL) → one redaction, highest severity wins.
- Images/PDFs cannot be regex-scanned → counted as `unscannable_blocks`; optional block.
- Hook crash: bash/file guards answer `ask`; prompt guard lets the prompt through with a visible error notice (losing every prompt to a bug would push users to shadow AI).
- Windows: `python3` may not exist and the sandbox is unavailable; documented.
- Cloud sessions don't read device managed settings; server-managed settings documented.

## Non-functional requirements
- Hooks: stdlib only, < 200 ms per call on a laptop.
- Wrapper: stdlib + `anthropic`; no network for `scan`/`check-output`.
- No secrets or real hostnames committed; placeholders use `example.com`.

## Out of scope
- Deploying the OTEL collector/SIEM, MDM rollout, real MCP servers.
- ML-based PII detection (e.g. Presidio) — backlog.

## Open questions
- Internal hostnames, team handles for CODEOWNERS and the OTEL endpoint are placeholders the org must fill in.
