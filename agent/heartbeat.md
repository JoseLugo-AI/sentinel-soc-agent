# Sentinel Persistent Heartbeat

You are running as a **persistent agent**. You stay alive between heartbeat cycles. Do NOT exit after a single cycle.

## Loop Protocol

1. **Read checkpoint**: read `./last-heartbeat.txt` for the timestamp of your last completed cycle. If the file doesn't exist, default to 30 minutes ago.

2. **Run heartbeat**: follow the procedure in CLAUDE.md, but query Splunk for events **since the checkpoint timestamp only** (use `earliest=<checkpoint>` in your SPL). Do NOT re-query the full 30-minute window from now. Only query what's NEW since your last cycle. The actual SPL queries live in `rules/queries/splunk.md`.

3. **Log results**: follow the slim logging rules below.

4. **Update checkpoint**: write the current ISO8601 timestamp to `./last-heartbeat.txt` (overwrite, not append).

5. **Sleep**: run `sleep 1800` (30 minutes) via Bash, then go back to step 1.

## Slim Logging Rules

**ALL CLEAR cycles** (every event suppressed, nothing MEDIUM or above):
- Write a **one-line** JSON entry to `triage.jsonl`:
  ```json
  {"timestamp":"ISO8601","type":"HEARTBEAT","severity":"LOW","score":0,"details":"ALL CLEAR: [N] events, [N] suppressed","action":"SUPPRESSED"}
  ```
- Print a **one-line** summary to stdout:
  `SENTINEL [timestamp]: [N] events, all suppressed - ALL CLEAR`
- Do NOT write detailed per-event reasoning for suppressed events.

**Cycles with MEDIUM+ events:**
- Write detailed triage entries (full reasoning, enrichment) for MEDIUM+ events only.
- Suppressed events still get the one-line summary, not individual entries.

**CRITICAL/HIGH events:**
- Full detailed entry in triage.jsonl + ntfy escalation as normal.

## Gap Recovery

If you restart (supervisor restarted you), read `last-heartbeat.txt` to know where you left off. Query from that timestamp to now to catch up. No gap in coverage.

**On gap detection (>2 hours):** Query the missed window, but cap the catch-up query at **24 hours**. Gaps over 24 hours are logged as `GAP_EXCEEDED` in triage.jsonl:
```json
{"timestamp":"ISO8601","type":"GAP_EXCEEDED","severity":"HIGH","score":60,"details":"Sentinel was down for [duration]. Gap exceeds 24h cap. Events before [cutoff timestamp] are NOT covered. Manual review recommended.","action":"LOGGED"}
```

For gaps between 2 and 24 hours, send an ntfy notification:
- Title: "Sentinel Gap Detected"
- Priority: high
- Body: "Sentinel was down for [duration]. Catching up from [timestamp]. Review triage log for gap period."

## Tool Check

On your **first cycle only** (after startup), verify MCP server availability. On subsequent cycles, skip the tool check. Only re-check if a tool call fails.

## Important

- Do NOT exit after a heartbeat. Sleep and loop.
- Do NOT re-analyze events you already processed (checkpoint prevents this).
- Keep stdout output minimal. One line per cycle unless escalating.
