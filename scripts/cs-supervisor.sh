#!/usr/bin/env bash
# CrowdStrike → Splunk forwarder supervisor
# Runs in a tmux session, auto-restarts on crash
#
# Usage:
#   ./scripts/cs-supervisor.sh
#   # Or in a tmux session:
#   tmux new-session -d -s cs-forwarder './scripts/cs-supervisor.sh'

set -euo pipefail

SCRIPT="$HOME/sentinel/crowdstrike-to-splunk.py"
SECRETS="$HOME/.sentinel-secrets"
LOG="$HOME/sentinel/crowdstrike-forwarder.log"

source "$SECRETS"
export CROWDSTRIKE_CLIENT_ID CROWDSTRIKE_CLIENT_SECRET CROWDSTRIKE_BASE_URL
export SPLUNK_HEC_TOKEN SPLUNK_HEC_URL

echo "[$(date -Iseconds)] CrowdStrike forwarder supervisor starting" >> "$LOG"

while true; do
    python3 "$SCRIPT" 2>&1
    EXIT_CODE=$?
    echo "[$(date -Iseconds)] Forwarder exited with code $EXIT_CODE, restarting in 30s..." >> "$LOG"
    sleep 30
done
