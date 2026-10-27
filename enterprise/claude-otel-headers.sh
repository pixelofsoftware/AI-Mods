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

user="${USER:-${USERNAME:-unknown}}"
if [[ -n "${token}" ]]; then
  printf '{"Authorization":"Bearer %s","X-Claude-User":"%s"}\n' "${token}" "${user}"
else
  # Collector should reject unauthenticated writes; emit only the identity header.
  printf '{"X-Claude-User":"%s"}\n' "${user}"
fi
