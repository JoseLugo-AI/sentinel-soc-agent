#!/usr/bin/env bash
# Sentinel Agent Supervisor
# Runs the Claude Code-powered Sentinel agent in a loop with auto-restart.
# Designed to run inside a tmux session for persistent operation.
#
# Usage:
#   ./scripts/supervisor.sh
#   # Or in a tmux session:
#   tmux new-session -d -s sentinel './scripts/supervisor.sh'
#
# Configuration:
#   SENTINEL_DIR  - Root directory for Sentinel (default: $HOME/sentinel)

set -euo pipefail

SENTINEL_DIR="${SENTINEL_DIR:-$HOME/sentinel}"
LOG_DIR="$SENTINEL_DIR/logs"
LOG_FILE="$LOG_DIR/supervisor.log"

mkdir -p "$LOG_DIR"

log() {
  echo "[$(date -Iseconds)] $1" | tee -a "$LOG_FILE"
}

# ── Rate limiting ──────────────────────────────────────────────────────────
# Track restarts to avoid spinning if the agent keeps crashing immediately.
# Max 5 restarts in 10 minutes, then back off to 5-minute delay.

RESTART_TIMES=()
MAX_RESTARTS=5
WINDOW_SECONDS=600       # 10 minutes
NORMAL_DELAY=30           # seconds between restarts
BACKOFF_DELAY=300         # 5 minutes if rate-limited

check_rate_limit() {
  local now
  now=$(date +%s)
  local cutoff=$(( now - WINDOW_SECONDS ))

  # Prune old timestamps outside the window
  local fresh=()
  for ts in "${RESTART_TIMES[@]:-}"; do
    if [[ -n "$ts" ]] && (( ts > cutoff )); then
      fresh+=("$ts")
    fi
  done
  RESTART_TIMES=("${fresh[@]}")

  if (( ${#RESTART_TIMES[@]} >= MAX_RESTARTS )); then
    return 1  # rate-limited
  fi
  return 0
}

record_restart() {
  RESTART_TIMES+=("$(date +%s)")
}

# ── Main loop ──────────────────────────────────────────────────────────────

log "=== Sentinel supervisor starting ==="
log "SENTINEL_DIR=$SENTINEL_DIR"

while true; do
  log "Starting Sentinel agent..."

  # Run the Claude Code agent pointed at the agent project directory
  claude --project-dir "$SENTINEL_DIR/agent" 2>&1 | tee -a "$LOG_FILE" || true
  EXIT_CODE=${PIPESTATUS[0]}

  log "Agent exited with code $EXIT_CODE"
  record_restart

  if check_rate_limit; then
    log "Restarting in ${NORMAL_DELAY}s..."
    sleep "$NORMAL_DELAY"
  else
    log "Rate limit hit (${MAX_RESTARTS} restarts in ${WINDOW_SECONDS}s). Backing off for ${BACKOFF_DELAY}s..."
    sleep "$BACKOFF_DELAY"
    # Reset the counter after backoff so we don't stay stuck
    RESTART_TIMES=()
  fi
done
