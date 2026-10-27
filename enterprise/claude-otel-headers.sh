#!/usr/bin/env bash
# otelHeadersHelper for Claude Code (see enterprise/managed-settings.json).
# Prints a JSON object of HTTP headers for the OTLP exporter. Claude Code calls it
# at startup and roughly every 29 minutes, so short-lived tokens rotate.
#
# Install: sudo install -m 0755 enterprise/claude-otel-headers.sh /usr/local/bin/claude-otel-headers
#
# Replace the token lookup with your org's mechanism. Never hardcode the token here:
# this script is world-readable on every workstation.
set -euo pipefail

token=""
if command -v security >/dev/null 2>&1; then
  # macOS Keychain item provisioned by MDM
  token="$(security find-generic-password -s claude-otel-ingest -w 2>/dev/null || true)"
elif command -v secret-tool >/dev/null 2>&1; then
  # Linux Secret Service (GNOME Keyring / KWallet)
  token="$(secret-tool lookup service claude-otel-ingest 2>/dev/null || true)"
fi
if [[ -z "${token}" && -r "${HOME}/.config/claude-otel/token" ]]; then
  token="$(<"${HOME}/.config/claude-otel/token")"
fi

if [[ -z "${token}" ]]; then
  echo "claude-otel-headers: no ingest token found (keychain item 'claude-otel-ingest' or ~/.config/claude-otel/token); the collector will reject exports" >&2
fi

# X-Claude-User is informational only: the collector must derive identity from the
# authenticated token (or mTLS certificate), because the client controls $USER.
# json.dumps escapes values, so a token or user name cannot break the JSON.
CLAUDE_OTEL_TOKEN="${token}" CLAUDE_OTEL_USER="${USER:-${USERNAME:-unknown}}" python3 -c '
import json, os
headers = {"X-Claude-User": os.environ["CLAUDE_OTEL_USER"]}
if os.environ["CLAUDE_OTEL_TOKEN"]:
    headers["Authorization"] = "Bearer " + os.environ["CLAUDE_OTEL_TOKEN"]
print(json.dumps(headers))
'
