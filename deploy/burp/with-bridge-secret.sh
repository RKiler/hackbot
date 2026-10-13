#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${CREDENTIALS_DIRECTORY:-}" || ! -r "${CREDENTIALS_DIRECTORY}/burp_bridge" ]]; then
  printf '%s\n' 'Burp bridge credential is unavailable' >&2
  exit 1
fi
HACKBOT_SECRET_BURP_BRIDGE="$(<"${CREDENTIALS_DIRECTORY}/burp_bridge")"
if [[ ! "$HACKBOT_SECRET_BURP_BRIDGE" =~ ^[A-Za-z0-9._~-]{32,256}$ ]]; then
  printf '%s\n' 'Burp bridge credential is invalid' >&2
  exit 1
fi
export HACKBOT_SECRET_BURP_BRIDGE
exec "$@"
