# Review 2 (iteration 2, commit 751aafe)

## Agent 7: Architecture and Security, verdict: APPROVE (provisional, partial review)

- **Review-1 fix verification:** S1–S14 are all FIXED according to the iteration-2 regression tests (`tests/test_review1_regressions.py`, all passing).
- **False-positive sweep:** 48 ordinary developer commands (git, npm/pnpm/yarn/npx, pytest, docker compose/build, go/cargo test, heredocs that write files, find -exec, loops, `rm -rf node_modules`, `sed -i`, kubectl get, terraform plan/fmt, pre-commit, `source .venv/bin/activate`) all pass silently, except:
  - `grep -rn token src/auth/` → ask (the S10 `secret_search` rule, intended; some friction)
  - `cp .env.example .env.example.bak` → deny (the target name matches the secrets pattern; acceptable)
- **New issues:** none confirmed.
- **Limitation:** a safety classifier stopped the reviewer while it was writing bypass payloads, so the independent adversarial probing of the iteration-2 code (heredoc parsing, `strip_wrappers`, the dynamic-command check, `find -exec` extraction, Grep over a directory without a glob filter, redaction timing) **was not completed**. It is recorded as UNVERIFIED in `verification.md` and recommended for a human red-team before merge.
- **Note:** `python3 -m pytest` needs pytest installed; system Python in the review container did not have it.

## Agent 8: Code Quality, verdict: REJECT → fixed in iteration 3

Every finding was reproduced with probe scripts. Python 3.9 grammar check passed for all files, and all 228 tests passed at review time.

| # | Severity | Finding | Fix (iteration 3) |
|---|---|---|---|
| Q1 | BLOCKER | `enterprise/`, guardrail docs, setup script and `pyproject.toml` missing from GUARDRAIL_PATH_RE, so `enterprise/managed-settings.json` could be edited with no prompt | Added to the regex, settings ask rules, CODEOWNERS and CLAUDE.md; drift test checks all four against one sample list |
| Q2 | MAJOR | Hook tamper check matched the script name anywhere in the command | Exact `python3 "${CLAUDE_PROJECT_DIR}/.claude/hooks/<x>.py"` form required |
| Q3 | MAJOR | A second `AuditLogger` silently reused the first logger's handler | Each instance writes to its own stream |
| Q4 | MAJOR | ZWNJ/ZWJ treated as smuggling: blocks Persian/Indic text and emoji | Removed from the invisible set |
| Q5 | MAJOR | Braces split words, so `cat .env.{prod,local}` was silent | Braces separate only as whole words; shared `looks_secret` / ENV_GLOB_RE |
| Q6 | MAJOR | `which sudo`, `man su` denied | Privilege check only on the resolved command |
| Q7 | MAJOR | forbidden_paths/.gitignore narrower than the hook secret pattern | Lists synced; drift test over every secret family |
| Q8 | MAJOR | Setup script reported success when `pre-commit install` failed | Failures counted, exit 1; venv-aware pip |
| Q9 | MAJOR | Audit test rewrote the real audit log | `CLAUDE_GUARDRAIL_AUDIT_DIR` → tmp_path |
| Q10 | MAJOR | Untested: fail-closed hooks, output_action=warn, block_unscannable, unbalanced quote + network client | Tests added |
| Q11–Q22 | MINOR | Malformed JSON failed open; Severity.parse KeyError; IPv4 read as phone; template suffix lists out of sync; doc output/text/`block_on` wording; validator exit code; OTEL helper silent with no token; check_segment size and `Verdict` name; duplicated chat-template regex; read_guard missing from test_ac2 | All fixed except splitting check_segment into rule functions (backlog). `Verdict` renamed to `Decision` |
