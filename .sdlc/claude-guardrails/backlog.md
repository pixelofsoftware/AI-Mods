# Backlog

- Optional ML/NER PII detector (Microsoft Presidio) behind the same `Redactor` interface for free-text PHI and names.
- OpenTelemetry Collector `transform`/`redaction` processor config as a second redaction pass for `claude_code.user_prompt` events.
- TypeScript port of `claude_safeguard` for Node services.
- `trivy config` (tfsec successor) hook once Terraform lands in this repo.
- Split `bash_guard.check_segment` (~220 lines) into small registered rule functions (review-2 Q19).
- Load guardrail/secret path lists in the hooks directly from `config/claude-guardrails-policy.json` (today a drift test keeps them in sync).
- `read_guard`: Grep over a directory without a glob relies on ripgrep honouring `.gitignore` for `.env`; consider an ask rule for secret-like Grep patterns.
- Human red-team of `bash_guard` (heredoc parsing, wrappers, dynamic-command check): the review-2 adversarial pass was cut short.
