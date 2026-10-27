# Test report, iteration 3 (commit 306da19)

## Agent 9: automated checks (run by the dispatcher)

| Check | Command | Result |
|---|---|---|
| Unit + regression tests | `python -m pytest -p no:cacheprovider` (scratchpad venv, Python 3.13) | **308 passed**, 0 failed |
| Pre-commit, all files | `pre-commit run --all-files` | **13/13 hooks passed** (detect-private-key, large files, merge conflict, check-json, check-yaml, shebangs, no-commit-to-branch, gitleaks, forbid-ai-artifacts, validate-claude-config, scan-ai-secrets, bandit, checkov with 28 GitHub Actions checks) |
| Setup self-test | `bash scripts/setup_guardrails.sh --check` | exit 0; 7/7 self-tests ✔; 2 expected warnings (bwrap/socat absent in this container) |
| Python 3.9 grammar | `ast.parse(..., feature_version=(3, 9))` on every `.py` | ok |
| Baseline regressions | Step 0 baseline: no prior tests | none possible |

## Agent 10: functional / UAT (independent subagent)

| AC | Status | Evidence (summary) |
|---|---|---|
| AC-1 Policy doc | PASS | All required sections present: tiers and modes, data protection, HITL, tooling and MCP |
| AC-2 Settings | PASS | (a)–(g) checked in `.claude/settings.json`; runtime honouring UNVERIFIED |
| AC-3 Telemetry | UNVERIFIED | Static config correct in `enterprise/managed-settings.json`; no collector or managed machine here |
| AC-4 MCP | UNVERIFIED | Static config correct and the drift check rejects bad servers; enforcement needs a managed machine |
| AC-5 Bash guard | **FAIL (minor)** | 119/121 probes as expected; the hook gives no `ask` for `git rebase` (a settings ask rule covers the plain form only) |
| AC-6 File guard | PASS | 24/24 probes |
| AC-7 Prompt guard | PASS | Credentials blocked with no override and a redacted copy; HIGH PII needs an ack; email gets a notice; clean prompts are silent |
| AC-8 Pre-commit | PASS | forbid-paths, 15/15 tamper cases, scan-secrets |
| AC-9 Wrapper redaction | **FAIL (minor)** | `4242 4242 4242 4242` (spaced vendor test card) is redacted as PHONE |
| AC-10 Observability | PASS | One JSON line per request, all fields present, no raw PII |
| AC-11 Output validation | PASS | All BLOCK, WARN and PASS cases; raise/sanitize/warn behave as specified |
| AC-12 Blocking and refusal | PASS | No client call on CRITICAL; refusal handled; live API UNVERIFIED |
| AC-13 Setup guide | PASS | Runnable steps behave as documented; slash commands UNVERIFIED |
| AC-14 Least privilege | **FAIL (narrow)** | Runtime errors fail closed, but an import-time error (e.g. missing `scripts/claude_safeguard.py`) exits 1, and Claude Code treats that as non-blocking |

Totals: 8 PASS, 3 FAIL (minor), 3 UNVERIFIED. Probe scripts are in the session scratchpad (`uat/`).

## Doc/behaviour mismatches reported (MINOR, moved to backlog)

- **CODEOWNERS:** two teams on one line means either team can approve, but the policy says both are needed.
- **Policy §7:** says exceptions are recorded in the policy file, but it has no `exceptions` field.
- **Setup C2:** says audit goes to stdout, but the `ask` CLI writes it to stderr.
- **Ask rules:** `git push`, `npm install` and `git rebase` have no bare (no-argument) form.
- **`deniedMcpServers`:** the `http://*:*/*` pattern only matches URLs with an explicit port.
- **Stale comment:** `guard_common.py` points to `tests/test_drift.py`, which doesn't exist; the drift tests are in `test_review2_regressions.py`.
- **Setup A2:** doesn't mention `--check`.
- **Audit record:** `user` is null when `$USER` is unset.
