# Verification: Claude enterprise guardrail framework

## 1. Status: INCOMPLETE (limit reached)

Three Develop → Review → Test iterations were used, the maximum the dispatcher allows. The final acceptance pass found **3 minor FAILs**. None is a data leak, and each has a small fix (§6). The dispatcher does not start a fourth iteration on its own, so these wait for the human's decision.

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
| Tests | `tests/` (308 tests) |

Commits on `claude/kind-hamilton-1g3q7h`: `0ebe06a` (iteration 1), `751aafe` (iteration 2), `306da19` (iteration 3), plus SDLC records.

## 3. Acceptance criteria

| AC | Status | Evidence |
|---|---|---|
| AC-1 Policy doc | PASS | test-3.md; all required sections present |
| AC-2 Settings | PASS | Static check of (a)–(g); `tests/test_config.py` |
| AC-3 Telemetry + prompt logging | UNVERIFIED | Config correct; export to a collector not testable here |
| AC-4 MCP allowlist | UNVERIFIED | Config and drift check correct; enforcement needs a managed machine |
| AC-5 Bash guard | **FAIL (minor)** | 119/121 probes; no hook-level `ask` for `git rebase` |
| AC-6 File guard | PASS | 24/24 UAT probes; `test_hooks.py`, drift tests |
| AC-7 Prompt guard | PASS | UAT and `test_hooks.py` |
| AC-8 Pre-commit | PASS | 13/13 hooks; 15/15 tamper cases |
| AC-9 Redaction | **FAIL (minor)** | Spaced `4242 4242 4242 4242` is redacted as PHONE |
| AC-10 Observability | PASS | One JSON audit line per request, no raw PII |
| AC-11 Output validation | PASS | BLOCK/WARN/PASS cases; raise/sanitize/warn |
| AC-12 Blocking and refusal | PASS | No network call on CRITICAL; refusal surfaced (live API UNVERIFIED) |
| AC-13 Setup guide | PASS | Runnable steps reproduce; slash commands UNVERIFIED |
| AC-14 Least privilege | **FAIL (narrow)** | Import-time hook crash exits 1 instead of answering `ask` |

## 4. Test evidence

- `python -m pytest`: **308 passed**, 0 failed.
- `pre-commit run --all-files`: **13/13 passed**; checkov ran 28 GitHub Actions checks with 0 failures.
- `scripts/setup_guardrails.sh --check`: exit 0, 7/7 self-tests.
- All `.py` files parse under the Python 3.9 grammar.
- Live dogfooding: the hooks ran on this session's own tool calls throughout development. They blocked a test file containing a literal bearer token, and blocked a heredoc that contained regex text. That second case exposed a real parsing flaw, which was fixed and tested.

## 5. Review results

| Iteration | Security (Agent 7) | Code quality (Agent 8) | Outcome |
|---|---|---|---|
| 1 | REJECT: 6 BLOCKER, 8 MAJOR | Report not delivered | All 14 fixed in iteration 2 |
| 2 | APPROVE (provisional; adversarial pass cut short by a safety classifier) | REJECT: 1 BLOCKER, 9 MAJOR | All 10 fixed in iteration 3 |
| 3 | — | — | UAT: 3 minor FAILs |

## 6. Open items

**FAILs (proposed fixes, not applied because the iteration limit was reached):**

1. **AC-5:** in `.claude/hooks/bash_guard.py`, add `rebase` (and `commit --amend`) to the `git_history_rewrite` ask set, so wrapped forms such as `bash -c 'git rebase …'` are covered.
2. **AC-9:** in `scripts/claude_safeguard.py`, have the phone validator reject 16-digit groups of four (or have the card rule claim known test PANs as a LOW, non-redacted finding) so the phone rule doesn't take them.
3. **AC-14:** in each hook, move the `guard_common` import inside the fail-closed `try`, and on `ImportError` answer `ask` (or `systemMessage` for the prompt guard).

**UNVERIFIED (needs a real environment):**

| Item | How to check |
|---|---|
| Managed settings, slash commands, permission precedence | Setup guide A4 + B4 on a managed workstation |
| OTEL export and prompt logging | B4: look for `claude_code.user_prompt` at the collector |
| OS sandbox | Install `bubblewrap socat`, run `/sandbox`, try a non-allowlisted domain |
| MCP allowlist | `claude mcp add --transport http test https://example.com/mcp` must fail |
| Live API (fallback beta, real refusal) | `python3 scripts/claude_safeguard.py ask --user test "hello"` |
| Adversarial red-team of `bash_guard` | Human red-team; the automated pass was cut short |

**Backlog:** see `backlog.md` and the doc mismatches in `test-3.md`.

## 7. Next steps for the human

1. Decide whether to apply the three small fixes in §6 (a fourth iteration).
2. Replace the placeholders: `*.internal.example.com`, `@your-org/*` teams, Slack channels, the OTEL endpoint.
3. Deploy `enterprise/managed-settings.json` (setup guide B2), install the OTEL headers helper, and stand up collector-side redaction.
4. Turn on branch protection: require the `ai-guardrails / guardrails` check and code-owner review.
5. Run a human red-team against the hooks before org-wide rollout.
