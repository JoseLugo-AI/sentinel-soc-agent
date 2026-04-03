#!/usr/bin/env bash
# Sentinel — Splunk Token Rotation
# Automatically rotates Sentinel and secondary agent tokens before expiry.
# Called by cron weekly. Only rotates if tokens expire within 7 days.
# Self-healing: if rotation fails, notifies via ntfy.

set -euo pipefail

SECRETS_FILE="$HOME/.sentinel-secrets"
NTFY_TOPIC="${NTFY_TOPIC:?NTFY_TOPIC not set}"
SPLUNK_URL="${SPLUNK_URL:?SPLUNK_URL not set}"
ROTATION_LOG="$HOME/sentinel/logs/rotation.log"

mkdir -p "$(dirname "$ROTATION_LOG")"

log() {
  echo "[$(date -Iseconds)] $1" >> "$ROTATION_LOG"
}

notify_error() {
  curl -s -o /dev/null \
    -H "Title: Sentinel — Token Rotation Failed" \
    -H "Priority: high" \
    -H "Tags: warning" \
    -d "$1" \
    "https://ntfy.sh/$NTFY_TOPIC"
}

if [ ! -f "$SECRETS_FILE" ]; then
  log "FATAL: Secrets file not found"
  notify_error "Secrets file missing at $SECRETS_FILE. Tokens cannot be rotated."
  exit 1
fi

source "$SECRETS_FILE"

# Check token expiry (returns days until expiry)
check_expiry() {
  local token="$1"
  local payload
  payload=$(echo "$token" | cut -d. -f2 | base64 -d 2>/dev/null)
  local exp
  exp=$(echo "$payload" | python3 -c "import sys,json; print(json.load(sys.stdin)['exp'])" 2>/dev/null)
  local now
  now=$(date +%s)
  local days_left=$(( (exp - now) / 86400 ))
  echo "$days_left"
}

# Extract JTI from token
get_jti() {
  local token="$1"
  echo "$token" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['jti'])" 2>/dev/null
}

# Rotate a single token
rotate_token() {
  local audience="$1"
  local auth_token="$2"  # token with admin rights to create new tokens

  # Create new token
  local response
  response=$(curl -sk -H "Authorization: Bearer $auth_token" \
    "$SPLUNK_URL/services/authorization/tokens" \
    -d name=admin -d "audience=$audience" 2>/dev/null)

  # Extract new token from XML response
  local new_token
  new_token=$(echo "$response" | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.fromstring(sys.stdin.read())
ns = {'a': 'http://www.w3.org/2005/Atom', 's': 'http://dev.splunk.com/ns/rest'}
for key in tree.findall('.//s:key[@name=\"token\"]', ns):
    if key.text:
        print(key.text)
        break
" 2>/dev/null)

  if [ -z "$new_token" ]; then
    log "ERROR: Failed to create new token for audience=$audience"
    return 1
  fi

  echo "$new_token"
}

# Delete old token by JTI
delete_token() {
  local jti="$1"
  local auth_token="$2"
  curl -sk -H "Authorization: Bearer $auth_token" \
    -X DELETE \
    "$SPLUNK_URL/services/authorization/tokens/$jti" >/dev/null 2>&1
}

log "=== Token rotation check started ==="

SENTINEL_DAYS=$(check_expiry "$SPLUNK_TOKEN_SENTINEL")
AGENT2_DAYS=$(check_expiry "$SPLUNK_TOKEN_AGENT2")

log "Sentinel token: $SENTINEL_DAYS days remaining"
log "Agent2 token: $AGENT2_DAYS days remaining"

ROTATED=false

# Rotate if either token expires within 7 days
if [ "$SENTINEL_DAYS" -le 7 ] || [ "$AGENT2_DAYS" -le 7 ]; then
  log "Rotation needed — at least one token expiring soon"

  # Use whichever token is still valid as auth for rotation
  if [ "$AGENT2_DAYS" -gt 0 ]; then
    AUTH_TOKEN="$SPLUNK_TOKEN_AGENT2"
  elif [ "$SENTINEL_DAYS" -gt 0 ]; then
    AUTH_TOKEN="$SPLUNK_TOKEN_SENTINEL"
  else
    log "CRITICAL: Both tokens expired! Cannot self-rotate."
    notify_error "Both Splunk tokens are expired. Manual rotation required. Run: source ~/sentinel/load-secrets.sh && check token expiry."
    exit 1
  fi

  # Rotate Sentinel token
  if [ "$SENTINEL_DAYS" -le 7 ]; then
    OLD_JTI=$(get_jti "$SPLUNK_TOKEN_SENTINEL")
    NEW_SENTINEL=$(rotate_token "sentinel" "$AUTH_TOKEN")
    if [ -n "$NEW_SENTINEL" ]; then
      SPLUNK_TOKEN_SENTINEL="$NEW_SENTINEL"
      delete_token "$OLD_JTI" "$AUTH_TOKEN"
      log "Sentinel token rotated successfully"
      ROTATED=true
    else
      log "ERROR: Sentinel token rotation failed"
      notify_error "Sentinel token rotation failed. $SENTINEL_DAYS days remaining."
    fi
  fi

  # Rotate Agent2 token (use new sentinel token if we just rotated it, otherwise use agent2's)
  if [ "$AGENT2_DAYS" -le 7 ]; then
    if [ "$ROTATED" = true ]; then
      AUTH_TOKEN="$SPLUNK_TOKEN_SENTINEL"
    fi
    OLD_JTI=$(get_jti "$SPLUNK_TOKEN_AGENT2")
    NEW_AGENT2=$(rotate_token "agent2" "$AUTH_TOKEN")
    if [ -n "$NEW_AGENT2" ]; then
      SPLUNK_TOKEN_AGENT2="$NEW_AGENT2"
      delete_token "$OLD_JTI" "$AUTH_TOKEN"
      log "Agent2 token rotated successfully"
      ROTATED=true
    else
      log "ERROR: Agent2 token rotation failed"
      notify_error "Agent2 token rotation failed. $AGENT2_DAYS days remaining."
    fi
  fi

  # Write updated secrets file
  if [ "$ROTATED" = true ]; then
    NEW_EXPIRY=$(date -d "+30 days" +%Y-%m-%d)
    cat > "$SECRETS_FILE" << SECRETS_EOF
# Sentinel — Splunk/Security API Tokens
# chmod 600 — DO NOT commit this file anywhere
# Last rotated: $(date +%Y-%m-%d)
# Tokens expire: ~$NEW_EXPIRY (30 days from creation)

# Splunk tokens (audience-scoped, auto-rotated by Sentinel)
SPLUNK_TOKEN_SENTINEL="$SPLUNK_TOKEN_SENTINEL"
SPLUNK_TOKEN_AGENT2="$SPLUNK_TOKEN_AGENT2"

# VirusTotal
VIRUSTOTAL_API_KEY="$VIRUSTOTAL_API_KEY"

# Splunk connection
SPLUNK_URL="$SPLUNK_URL"
SECRETS_EOF
    chmod 600 "$SECRETS_FILE"
    log "Secrets file updated with new tokens"
    log "=== Rotation complete ==="
  fi
else
  log "No rotation needed. Sentinel: ${SENTINEL_DAYS}d, Agent2: ${AGENT2_DAYS}d"
  log "=== Check complete ==="
fi
