# Customization Guide

## Adding Detection Rules

Detection rules live in `rules/gdpr.md` (and any additional `.md` files you create in `rules/`). Follow the existing format:

1. Give the rule a descriptive heading.
2. Explain what it detects and why it matters.
3. Provide the SPL query (or reference a query from the query pack).
4. Specify the minimum triage score and severity.

Example:

```markdown
## USB File Exfiltration

Detects files being written to removable storage from the protected data directory.

**Query:** See `rules/queries/splunk.md` > "USB File Exfiltration"
**Minimum score:** 70 (HIGH)
**MITRE ATT&CK:** T1052.001 - Exfiltration Over Physical Medium
```

The agent reads these rules as part of its system prompt and applies them during the Reason phase of each heartbeat cycle.

## Adding a SIEM Backend

Sentinel ships with Splunk queries in `rules/queries/splunk.md`. To add support for another SIEM (Elastic, Wazuh, Microsoft Sentinel, etc.), create a new query file following the same contract.

### The Query File Contract

1. **Location:** `rules/queries/<siem>.md` (e.g., `rules/queries/elastic.md`)
2. **Headings:** Use the **same level-2 heading names** as `splunk.md`. The agent references queries by heading name, so they must match exactly.
3. **Format:** Each heading contains a fenced code block with the query in that SIEM's native language.

Example structure:

```markdown
# Elastic Queries

## Process Creation
​```kql
event.code: 1 AND winlog.channel: "Microsoft-Windows-Sysmon/Operational"
| ...
​```

## Network Connections
​```kql
event.code: 3 AND winlog.channel: "Microsoft-Windows-Sysmon/Operational"
| ...
​```

## GDPR File Access
​```kql
event.code: 4663 AND winlog.event_data.ObjectName: *Desktop\\Work*
| ...
​```
```

The key rule: **same heading names across all SIEM query files**. The agent resolves which file to use based on your configuration in `agent/CLAUDE.md`.

### Switching the Active SIEM

In `agent/CLAUDE.md`, update the MCP server configuration to point to your SIEM's API, and set the query file reference:

```markdown
- **SIEM query pack:** `rules/queries/elastic.md`
```

## Customizing Personality

The agent's communication style is defined in `agent/PERSONALITY.md`. You can make the agent as terse or verbose as you like.

For a minimal starting point, see `examples/personality-minimal.md` -- it covers just the functional requirements in 6 lines.

Things you can adjust:

- **Tone** -- Military brevity, corporate formal, casual, whatever fits your team.
- **Escalation language** -- How the agent phrases notifications. Some people want "CRITICAL: mimikatz detected on PID 1234" while others want a full paragraph.
- **Autonomy level** -- How much the agent investigates before escalating vs. immediately notifying you.

The personality file is loaded as part of the system prompt, so changes take effect on the next agent restart.

## Changing Notification Channels

The default notification channel is [ntfy.sh](https://ntfy.sh), a lightweight HTTP-based push service. To switch to a different channel, modify the escalation section in `agent/CLAUDE.md`.

### Slack

Replace the ntfy notification command with a Slack webhook:

```markdown
- **Notification method:** POST to Slack webhook
- **Webhook URL:** Loaded from `SLACK_WEBHOOK_URL` in `~/.sentinel-secrets`
- **Format:** JSON payload with `text` field containing the alert
```

Add to `~/.sentinel-secrets`:

```
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

### PagerDuty

For on-call rotation integration:

```
PAGERDUTY_ROUTING_KEY="your-routing-key"
```

The agent can use `curl` to send PagerDuty Events API v2 payloads for CRITICAL findings.

### Email

Use a local `sendmail` or `msmtp` configuration. Add the recipient to your secrets file and update the escalation instructions in `agent/CLAUDE.md` to use the mail command.

### Multiple Channels

You can configure the agent to use different channels for different severities. For example: PagerDuty for CRITICAL, Slack for HIGH, and log-only for MEDIUM. Define this in the escalation section of `agent/CLAUDE.md`.

## Building Your Baseline

The baseline file (`baseline.csv`) tells the agent which processes, network connections, and file operations are normal for your environment. Without a good baseline, you will get flooded with false positives.

### Format

```csv
type,pattern,description
process,explorer.exe -> chrome.exe,User launching browser
process,svchost.exe -> WmiPrvSE.exe,WMI provider host
network,chrome.exe -> 443,Browser HTTPS traffic
network,OneDrive.exe -> 443,Cloud sync
file,OneDrive.exe -> *Desktop\\Work*,Authorized backup sync
```

### Building It

1. Run the agent for 24-48 hours without any baseline.
2. Review `triage.jsonl` for all LOW and MEDIUM findings.
3. Identify patterns that are clearly normal for your workstation.
4. Add them to `baseline.csv`.
5. Repeat after installing new software or changing your workflow.

The agent checks the baseline during the Reason phase. Matching entries are automatically suppressed (scored LOW).

## Tuning Triage Thresholds

The triage scoring ranges are defined in `agent/CLAUDE.md`:

```
| Score   | Severity | Action                          |
|---------|----------|---------------------------------|
| 80-100  | CRITICAL | Push notification (urgent) + log |
| 50-79   | HIGH     | Push notification (high) + log   |
| 20-49   | MEDIUM   | Log only                         |
| 0-19    | LOW      | Suppress                         |
```

To adjust:

- **Lower the HIGH threshold** (e.g., 40 instead of 50) if you want more notifications.
- **Raise it** (e.g., 60) if you are getting too many alerts.
- **Add auto-escalation rules** for specific patterns. For example: "Any process touching the customer data directory is always HIGH minimum" or "Any connection to a non-standard port after midnight is MEDIUM minimum."

These thresholds live in the agent's system prompt, so edit `agent/CLAUDE.md` and restart the agent for changes to take effect.
