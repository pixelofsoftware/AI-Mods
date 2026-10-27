# Review 1 (iteration 1, commit 0ebe06a)

Reviewers ran as independent subagents with only `prd.md`, `context.md` and the code.

## Agent 7: Architecture and Security, verdict: REJECT

Every bypass claim came with a reproduction command run against the hooks. Credential-shaped strings were built by concatenation.

| # | Severity | Location | Problem | Planned fix |
|---|---|---|---|---|
| S1 | BLOCKER | bash_guard.py tokenize | A newline is not a separator, so anything after line 1 of a multi-line command is invisible (`ls\nsudo …`, `ls\ngit push --force`) | Treat unquoted newlines as separators; add tests |
| S2 | BLOCKER | bash_guard.py SAFE_SECRET_PATH_CMDS + allow `git diff *` | `git diff --no-index /dev/null .env` prints secrets with no prompt | Check git args for secret paths (except rm/ls-files/check-ignore/status) |
| S3 | BLOCKER | allow `git log/show/diff *` | `--output=<file>` writes arbitrary content (e.g. into `.pre-commit-config.yaml`) with no prompt | Deny git `--output`; `ask` when a shell write target is a guardrail file |
| S4 | BLOCKER | settings.json | No hook on Read/Grep/Glob; the deny list misses `.env.prod`, `.envrc`, kubeconfig … | New `read_guard.py` on `Read\|Grep\|Glob` using SECRET_PATH_RE; extend the regex |
| S5 | BLOCKER | claude_safeguard.py `_redact_block` | Document title/context, content-source documents, search_result, tool_use.input and SDK objects are sent unredacted | Recursive redaction of all non-structural strings; count only binary sources as unscannable |
| S6 | BLOCKER | claude_safeguard.py destructive_command rule | Exponential backtracking (100 bytes ≈ 1 s+, doubling) | Single bounded flag group + Python flag check; timing test |
| S7 | MAJOR | email / url_embedded_password rules | Quadratic on long runs; a 130 KB write takes 26 s > 15 s hook timeout → fail open | Lookbehind-anchored, bounded quantifiers; size cap → `ask` |
| S8 | MAJOR | output rules `[^\n]*` | Quadratic on long lines | Bound gaps to `{0,300}` |
| S9 | MAJOR | bash_guard network egress | Dynamic command names (`$c`, `$(echo …)`, globs), `bash <<<`, `bash -c --`, `find -exec`, busybox, git alias `!`, openssl s_client, DNS tools | Handle each; dynamic argv[0] → ask/deny |
| S10 | MAJOR | bash_guard secrets/env | `cat .env*`, `.envrc`, bare `export`, `env -0`, `env -u X`, `declare -px`, `/proc/self/environ`, recursive grep for KEY | Extend rules and regex |
| S11 | MAJOR | check_ai_guardrails.url_allowed | `https://evil\@good/` passes urlsplit but Node resolves evil | Reject `\`, `@`, userinfo, whitespace/control chars |
| S12 | MAJOR | validate-config | Accepts autoAllowBashIfSandboxed, excludedCommands, wildcard domains, `Bash(* *)`, apiKeyHelper, base-URL env, hooks with a wrong matcher | Policy additions + matcher verification |
| S13 | MAJOR | claude_safeguard output validation | tool_use inputs are not validated | Validate tool_use / server_tool_use input JSON |
| S14 | MAJOR | forbid-paths | `**` doesn't match zero dirs; transcripts outside `.claude/` are not caught | gitignore-style `**/`; content sniff for Claude transcript JSONL |
| S15–S22 | MINOR | various | ack reason logged raw; JWT/password override; git -c hooksPath / SKIP= / `-fu` / `:ref`; kubectl global flags; recursion depth; `block_on` set semantics; OTEL tool details; otel header JSON escaping; case-insensitive guardrail paths; `pre-commit run *` | Fix the cheap ones in iteration 2, rest to backlog |

## Agent 8: Code Quality

See the section appended below once the report is received.
