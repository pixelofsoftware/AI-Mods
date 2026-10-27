# Verification: Claude enterprise guardrail framework

## 1. Status: COMPLETE WITH UNVERIFIED ITEMS

- **Iterations 1–3:** ended with three minor acceptance FAILs and hit the dispatcher's 3-iteration limit.
- **Iteration 4:** the human approved a fourth iteration, which fixed all three.
- **Iteration-4 review:** a clean-room pass, not independent, because the reviewer subagent was stopped by an account rate limit (see `test-4.md`).
- **What remains UNVERIFIED:** everything that needs a real managed workstation, a collector, the OS sandbox, MCP servers, the live API, or a human red-team (§6).

## 2. What was built

| Area | Files |
|---|---|
| Policy and guides | `docs/claude-guardrails.md`, `docs/claude-guardrails-setup.md`, `README.md`, `CLAUDE.md` |
| Claude Code config | `.claude/settings.json`, `.mcp.json` |
| Claude Code hooks | `.claude/hooks/{guard_common,prompt_guard,bash_guard,file_guard,read_guard}.py` |
| Org policy (admin-deployed) | `enterprise/managed-settings.json`, `enterprise/claude-otel-headers.sh` |
| Commit and merge gates | `.pre-commit-config.yaml`, `scripts/precommit/check_ai_guardrails.py`, `config/claude-guardrails-policy.json`, `.github/workflows/ai-guardrails.yml`, `.github/CODEOWNERS`, `.gitignore`, `pyproject.toml` |
| API middleware | `scripts/claude_safeguard.py` |
| Tooling | `scripts/setup_guardrails.sh` |
| Tests | `tests/` (331 tests) |

Commits: `0ebe06a` (iteration 1), `751aafe` (iteration 2), `306da19` (iteration 3), `a48ef1b` (iteration 4), plus SDLC records.

## 3. Acceptance criteria

| AC | Status | Evidence |
|---|---|---|
| AC-1 Policy doc | PASS | test-3.md |
| AC-2 Settings | PASS | test-3.md; `tests/test_config.py` |
| AC-3 Telemetry + prompt logging | UNVERIFIED | Config correct; collector export not testable here |
| AC-4 MCP allowlist | UNVERIFIED | Config and drift check correct; enforcement needs a managed machine |
| AC-5 Bash guard | PASS | test-3.md (119/121) + test-4.md (rebase/amend fixed) |
| AC-6 File guard | PASS | test-3.md |
| AC-7 Prompt guard | PASS | test-3.md |
| AC-8 Pre-commit | PASS | test-3.md; 13/13 hooks |
| AC-9 Redaction | PASS | test-4.md (spaced test card fixed) |
| AC-10 Observability | PASS | test-3.md |
| AC-11 Output validation | PASS | test-3.md |
| AC-12 Blocking and refusal | PASS | test-3.md (live API UNVERIFIED) |
| AC-13 Setup guide | PASS | test-3.md (slash commands UNVERIFIED) |
| AC-14 Least privilege | PASS | test-4.md (import-time failure now fails closed) |

## 4. Test evidence

- `python -m pytest`: **331 passed**, 0 failed.
- `pre-commit run --all-files`: **13/13 passed**; checkov ran 28 GitHub Actions checks with 0 failures.
- `scripts/setup_guardrails.sh --check`: exit 0.
- Iteration-4 clean-room probes: 29/29 PASS.
- All `.py` files parse under the Python 3.9 grammar.
- Live dogfooding: the hooks ran on this session's own tool calls during development. They blocked a test file containing a literal fake bearer token, and exposed a heredoc parsing flaw that was then fixed.

## 5. Review results

| Iteration | Security (Agent 7) | Code quality (Agent 8) | Outcome |
|---|---|---|---|
| 1 | REJECT: 6 BLOCKER, 8 MAJOR | Report not delivered | All 14 fixed in iteration 2 |
| 2 | APPROVE (provisional; adversarial pass cut short by a safety classifier) | REJECT: 1 BLOCKER, 9 MAJOR | All 10 fixed in iteration 3 |
| 3 | — | — | UAT: 3 minor FAILs |
| 4 | Clean-room pass only (independent reviewer rate-limited) | same | All 3 FAILs fixed; 29/29 retest |

## 6. Open items

**UNVERIFIED (needs a real environment):**

| Item | How to check |
|---|---|
| Managed settings, slash commands, permission precedence | Setup guide A4 + B4 on a managed workstation |
| OTEL export and prompt logging | B4: look for `claude_code.user_prompt` at the collector |
| OS sandbox | Install `bubblewrap socat`, run `/sandbox`, try a non-allowlisted domain |
| MCP allowlist | `claude mcp add --transport http test https://example.com/mcp` must fail |
| Live API (fallback beta, real refusal) | `python3 scripts/claude_safeguard.py ask --user test "hello"` |
| Adversarial red-team of the hooks | Human red-team; both automated adversarial passes were cut short |
| Independent review of iteration 4 | Optional re-run; the change is 7 files, +154/−20 |

**Backlog:** see `backlog.md` and the doc mismatches in `test-3.md`.

## 7. Next steps for the human

1. Replace the placeholders: `*.internal.example.com`, `@your-org/*` teams, Slack channels, the OTEL endpoint.
2. Deploy `enterprise/managed-settings.json` (setup guide B2), install the OTEL headers helper, and set up collector-side redaction.
3. Turn on branch protection: require the `ai-guardrails / guardrails` check and code-owner review.
4. Run a human red-team against the hooks before org-wide rollout.
