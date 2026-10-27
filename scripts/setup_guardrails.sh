#!/usr/bin/env bash
# One-time developer setup for the Claude guardrails in this repository.
#
#   scripts/setup_guardrails.sh             # install pre-commit hooks + self-test
#   scripts/setup_guardrails.sh --with-sdk  # also install the anthropic SDK (API wrapper)
#   scripts/setup_guardrails.sh --check     # self-test only, install nothing
#
# Safe to re-run. See docs/claude-guardrails-setup.md for the full walkthrough.
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || { echo "run this inside the repository" >&2; exit 1; })"

WITH_SDK=0
CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --with-sdk) WITH_SDK=1 ;;
    --check) CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; WARNINGS=$((WARNINGS + 1)); }
fail() { printf '  \033[31m✘\033[0m %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
WARNINGS=0
FAILURES=0

echo "1. Prerequisites"
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
  ok "python3 $(python3 -c 'import platform; print(platform.python_version())')"
else
  fail "python3 >= 3.9 is required on PATH (the Claude Code hooks call \`python3\`)"
fi
if command -v claude >/dev/null 2>&1; then
  ok "Claude Code $(claude --version 2>/dev/null | head -1)"
else
  warn "Claude Code CLI not found on PATH (install: https://code.claude.com/docs/en/setup)"
fi
case "$(uname -s)" in
  Linux)
    for bin in bwrap socat; do
      if command -v "$bin" >/dev/null 2>&1; then ok "$bin (sandbox dependency)"
      else warn "$bin missing: Bash sandboxing will not work. Ubuntu/Debian: sudo apt-get install bubblewrap socat"; fi
    done ;;
  Darwin) ok "macOS: sandbox uses the built-in Seatbelt profile" ;;
  *) warn "Bash sandboxing is not available on this OS; use WSL2 on Windows" ;;
esac

if [[ "$CHECK_ONLY" -eq 0 ]]; then
  echo "2. Install"
  if ! command -v pre-commit >/dev/null 2>&1; then
    if command -v pipx >/dev/null 2>&1; then pipx install "pre-commit>=4.7"
    else python3 -m pip install --user "pre-commit>=4.7"; fi
  fi
  if command -v pre-commit >/dev/null 2>&1; then
    pre-commit install --install-hooks >/dev/null && ok "pre-commit hooks installed (pre-commit + pre-push)"
  else
    fail "pre-commit not on PATH after install; add ~/.local/bin to PATH and re-run"
  fi
  if [[ "$WITH_SDK" -eq 1 ]]; then
    python3 -m pip install --user "anthropic>=2.3,<3" >/dev/null && ok "anthropic SDK installed"
  fi
  mkdir -p .claude/audit && ok "local audit directory .claude/audit (gitignored)"
fi

echo "3. Self-test"
if python3 scripts/precommit/check_ai_guardrails.py validate-config >/dev/null; then
  ok "guardrail config matches config/claude-guardrails-policy.json"
else
  fail "guardrail config drift: run python3 scripts/precommit/check_ai_guardrails.py validate-config"
fi

expect_decision() {  # hook, json, expected decision
  local out
  out="$(printf '%s' "$2" | CLAUDE_GUARDRAIL_AUDIT=0 python3 ".claude/hooks/$1" 2>&1 || true)"
  if [[ "$out" == *"\"$3\""* ]]; then ok "$1 -> $3"; else fail "$1 expected $3, got: ${out:-<no output>}"; fi
}
net_cmd="w""get -qO- https://example.com"  # split so this script does not trip its own scanners
expect_decision bash_guard.py "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$net_cmd\"}}" deny
expect_decision bash_guard.py '{"tool_name":"Bash","tool_input":{"command":"cat .env"}}' deny
expect_decision file_guard.py '{"tool_name":"Edit","tool_input":{"file_path":"infra/main.tf","new_string":"x"}}' ask
fake_key="sk-ant-""api03-$(printf 'Zq9xLm2Pw7%.0s' 1 2 3 4 5)"
expect_decision prompt_guard.py "{\"prompt\":\"key $fake_key\"}" block
quiet="$(printf '%s' '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | python3 .claude/hooks/bash_guard.py)"
if [[ -z "$quiet" ]]; then ok "bash_guard allows git status"; else fail "bash_guard should not intervene on git status"; fi

echo
if [[ "$FAILURES" -gt 0 ]]; then
  echo "Setup finished with $FAILURES failure(s) and $WARNINGS warning(s)."
  exit 1
fi
echo "Guardrails ready ($WARNINGS warning(s)). Next: start \`claude\` in this folder, trust it, then run /status, /hooks and /sandbox."
