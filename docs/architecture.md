# Architecture

Sentinel is a Claude Code-powered SOC analyst agent that runs inside WSL2, queries Splunk on the Windows host, reasons about what it finds, enriches suspicious events with threat intelligence, and notifies you when something needs attention.

## System Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Windows 11 Host                       │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────────┐  │
│  │  Sysmon   │  │ Splunk   │  │ CrowdStrike (optional)│  │
│  │ (events)  │──│Enterprise│──│ Falcon sensor          │  │
│  └──────────┘  └────┬─────┘  └───────────┬───────────┘  │
│                     │ :8089 REST API      │ Event Stream │
└─────────────────────┼─────────────────────┼──────────────┘
                      │                     │
┌─────────────────────┼─────────────────────┼──────────────┐
│                  WSL2 Ubuntu              │              │
│                     │                     │              │
│  ┌──────────────────┴──────────────────┐  │              │
│  │         Claude Code Agent           │  │              │
│  │  ┌────────────┐ ┌────────────────┐  │  │              │
│  │  │ CLAUDE.md  │ │ heartbeat.md   │  │  │              │
│  │  │ (brain)    │ │ (loop control) │  │  │              │
│  │  └────────────┘ └────────────────┘  │  │              │
│  │  ┌────────────────────────────────┐ │  │              │
│  │  │ MCP Servers                    │ │  │              │
│  │  │ splunk-siem | virustotal |     │ │  │              │
│  │  │ greynoise   | cve-intel        │ │  │              │
│  │  └────────────────────────────────┘ │  │              │
│  └──────────────┬──────────────────────┘  │              │
│                 │                          │              │
│  ┌──────────────┴───┐  ┌─────────────────┴────────────┐ │
│  │  supervisor.sh   │  │ crowdstrike-to-splunk.py     │ │
│  │  (tmux, restart) │  │ (Falcon -> Splunk HEC)       │ │
│  └──────────────────┘  └──────────────────────────────┘ │
│                 │                                        │
│           ┌─────┴─────┐                                  │
│           │  ntfy.sh  │──── Push to phone/Slack/webhook  │
│           └───────────┘                                  │
└──────────────────────────────────────────────────────────┘
```

## Components

### Windows 11 Host

- **Sysmon** -- Microsoft Sysinternals System Monitor. Logs process creation (EventCode 1), network connections (EventCode 3), file creation (EventCode 11), DNS queries (EventCode 22), and more. These events feed into Splunk.
- **Splunk Enterprise** -- Indexes Sysmon and Windows Event Log data. Exposes a REST API on port 8089 that the agent queries from WSL2. A free license handles up to 500MB/day, which is sufficient for a single workstation.
- **CrowdStrike Falcon (optional)** -- If installed, the `crowdstrike-to-splunk.py` forwarder streams Falcon detections into Splunk via HEC (HTTP Event Collector). Not required for core functionality.

### WSL2 Ubuntu

- **Claude Code Agent** -- The core. A Claude Code session running in tmux that wakes every 30 minutes, queries Splunk, reasons about the events like a Tier 2 SOC analyst, and decides what to escalate. Its behavior is defined by `agent/CLAUDE.md` (the system prompt) and `agent/PERSONALITY.md` (communication style).
- **CLAUDE.md (brain)** -- Contains the full system prompt: heartbeat procedure, detection rules, triage scoring, escalation policy, known-good baseline, and GDPR red lines.
- **heartbeat control** -- A checkpoint file (`last-heartbeat.txt`) tracks when the agent last ran. Each cycle only analyzes events since the last checkpoint, preventing duplicate analysis and saving API tokens.
- **MCP Servers** -- Model Context Protocol servers that give the agent direct tool access:
  - `splunk-siem` -- Run SPL queries against the Splunk REST API
  - `virustotal` -- Check IP addresses, file hashes, URLs, and domains
  - `greynoise` -- Determine if an IP is mass-scanning or targeted
  - `cve-intel` -- Look up CVE details from NVD, CISA KEV, and EPSS scores
- **supervisor.sh** -- A shell script that runs the Claude Code agent inside a tmux session. Handles restarts if the agent crashes, and sends a notification on failure.
- **crowdstrike-to-splunk.py** -- Optional. Polls the CrowdStrike Falcon Event Stream API and forwards detection events to Splunk via HEC.
- **ntfy.sh** -- Lightweight push notification service. The agent sends alerts here, which reach your phone, Slack, or any webhook endpoint.

## Data Flow

1. **Sysmon** generates Windows telemetry events (process, network, file, registry, DNS).
2. **Splunk** indexes these events into the `sysmon` and `wineventlog` indexes.
3. Every 30 minutes, the **Claude Code agent** wakes up and queries Splunk via the `splunk-siem` MCP server.
4. The agent **reasons** about each event: Is this in the baseline? Does the parent-child relationship make sense? Is customer data involved? Is the timing suspicious?
5. For suspicious events, the agent **enriches** with VirusTotal, GreyNoise, and CVE lookups.
6. The agent **scores** each finding and decides: suppress, log, or escalate.
7. Findings are written to `triage.jsonl`. CRITICAL and HIGH findings trigger a **push notification** via ntfy.

## Heartbeat Cycle

Each 30-minute cycle follows six phases:

1. **Collect** -- Query Splunk for new events since the last checkpoint. Covers process creation, network connections, file operations, GDPR file access, failed logins, and CrowdStrike alerts.
2. **Reason** -- Evaluate each event against the baseline, known attack patterns (MITRE ATT&CK), time-of-day context, and prior triage decisions.
3. **Enrich** -- For suspicious findings, query VirusTotal for IP/hash reputation, GreyNoise for scan classification, and CVE databases for vulnerability context.
4. **Triage** -- Assign a severity score (0-100) to each finding.
5. **Escalate** -- Send push notifications for CRITICAL and HIGH findings.
6. **Log** -- Write triage decisions to `triage.jsonl` and update the checkpoint.

## Triage Scoring

Every finding receives a score from 0 to 100:

| Score   | Severity | Action                          |
|---------|----------|---------------------------------|
| 80-100  | CRITICAL | Push notification (urgent) + log |
| 50-79   | HIGH     | Push notification (high) + log   |
| 20-49   | MEDIUM   | Log only                         |
| 0-19    | LOW      | Suppress                         |

The agent does not use hardcoded score tables. It reasons about context -- the same process might score 10 during business hours and 70 at 3am. Customer data involvement automatically floors the score at HIGH (50+).

Credential theft tools (mimikatz, procdump, lazagne, etc.) and reverse shell patterns are always CRITICAL (80+), with no reasoning required.

## Notification Flow

```
Agent detects finding (score >= 50)
    |
    v
Formats alert: verdict + process + evidence + recommendation
    |
    v
Sends to ntfy.sh topic via HTTP POST
    |
    v
ntfy.sh delivers to configured endpoints:
  - Phone (ntfy app)
  - Slack (webhook)
  - Email (SMTP)
  - Any HTTP endpoint
```

CRITICAL alerts use `priority: urgent` with the `rotating_light` tag. HIGH alerts use `priority: high` with the `warning` tag. The agent never sends "all clear" notifications -- silence means everything is fine.
