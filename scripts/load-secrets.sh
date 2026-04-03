#!/usr/bin/env bash
# Source this file to load Sentinel security tokens into environment variables.
#
# Multi-agent scoping:
#   Each agent gets its own audience-scoped Splunk token. This prevents one
#   agent's token from being used to access another agent's data. When you
#   source this script with an agent name, only that agent's token is exported
#   as SPLUNK_TOKEN — the rest are cleaned up.
#
# Usage:
#   source scripts/load-secrets.sh sentinel   # loads sentinel token (default)
#   source scripts/load-secrets.sh agent2      # loads a second agent's token
#   source scripts/load-secrets.sh             # defaults to sentinel

SECRETS_FILE="$HOME/.sentinel-secrets"

if [ ! -f "$SECRETS_FILE" ]; then
  echo "ERROR: Secrets file not found at $SECRETS_FILE" >&2
  return 1 2>/dev/null || exit 1
fi

# Export all vars from secrets file
set -a
source "$SECRETS_FILE"
set +a

AGENT="${1:-sentinel}"
case "$AGENT" in
  agent2)
    # Second agent — uses its own audience-scoped token
    export SPLUNK_TOKEN="$SPLUNK_TOKEN_AGENT2"
    ;;
  sentinel|*)
    # Sentinel agent — default
    export SPLUNK_TOKEN="$SPLUNK_TOKEN_SENTINEL"
    ;;
esac

# Also export the admin token if present (for token rotation, admin tasks)
if [ -n "${SPLUNK_ADMIN_TOKEN:-}" ]; then
  export SPLUNK_ADMIN_TOKEN
fi

# Clean up the agent-specific vars so they don't leak into the environment
unset SPLUNK_TOKEN_SENTINEL SPLUNK_TOKEN_AGENT2
