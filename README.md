# Sentinel SOC Agent

**A SOC analyst that thinks. Not another regex with a marketing budget.**

Sentinel is a Claude Code-powered SOC analyst agent that monitors your Windows workstation for threats, reasons about what it sees like a Tier 2 analyst, and enforces GDPR compliance rules. It runs as a persistent agent in a tmux session, waking every 30 minutes to query Splunk, triage events, enrich suspicious findings, and escalate when something actually matters.

No Docker. No Kubernetes. No YAML hell. Just markdown, Claude Code, and Splunk.

---

## Features

- **AI-powered reasoning.** Correlates process, network, and file events. Doesn't just pattern-match; connects kill chains across event types.
- **GDPR-aware monitoring.** 7 detection rules for customer data protection. Unauthorized access, data exfiltration, bulk enumeration, all covered.
- **Persistent operation.** Runs 24/7 in a tmux session with automatic restart on crash. Checkpoint-based so it never re-analyzes old events.
- **Threat enrichment.** Suspicious IPs checked against VirusTotal and GreyNoise. Unknown CVEs looked up in real time. All via MCP servers.
- **Smart triage.** Scores events 0-100, classifies CRITICAL/HIGH/MEDIUM/LOW. Only bothers you when it matters. No alert fatigue.
- **Push notifications.** Escalates to your phone via ntfy.sh. Swappable for Slack, PagerDuty, email, or any HTTP endpoint.
- **SIEM-agnostic architecture.** Ships with Splunk queries. Community can contribute Elastic, Wazuh, or any other SIEM query pack.
- **Compliance templates.** Fill-in-the-blank DPIA, Incident Response Plan, DPA, ROPA, and AI Transparency Statement. Actual legal structure, not boilerplate.
- **Military-flavored personality.** Optional operator persona that communicates like a SOC analyst, not a chatbot.

## Quickstart

```bash
# 1. Clone
git clone https://github.com/JoseLugo-AI/sentinel-soc-agent.git
cd sentinel-soc-agent

# 2. Configure secrets
cp docs/secrets-example.env ~/.sentinel-secrets
chmod 600 ~/.sentinel-secrets
# Edit ~/.sentinel-secrets with your Splunk URL, tokens, etc.

# 3. Install MCP servers (see mcp/README.md for details)
# splunk-siem, virustotal, greynoise, cve-intel

# 4. Customize the agent
# Edit agent/CLAUDE.md - set your environment, paths, notification topic
# Edit rules/gdpr.md - set your customer data directory patterns

# 5. Start Sentinel
tmux new-session -d -s sentinel 'bash scripts/supervisor.sh'
```

See [docs/setup.md](docs/setup.md) for the full setup guide with verification steps.

## Architecture

```
+-----------------------------------------------------------+
|                    Windows 11 Host                         |
|  +----------+  +----------+  +-----------------------+    |
|  |  Sysmon  |  | Splunk   |  | CrowdStrike (optional)|   |
|  | (events) |--|Enterprise|--| Falcon sensor          |   |
|  +----------+  +----+-----+  +-----------+-----------+    |
|                     | :8089 REST API      | Event Stream  |
+---------------------+--------------------+----------------+
                      |                     |
+---------------------+--------------------+----------------+
|                  WSL2 Ubuntu              |                |
|                     |                     |                |
|  +------------------+------------------+  |                |
|  |         Claude Code Agent           |  |                |
|  |  +------------+ +----------------+  |  |                |
|  |  | CLAUDE.md  | | heartbeat.md   |  |  |                |
|  |  | (brain)    | | (loop control) |  |  |                |
|  |  +------------+ +----------------+  |  |                |
|  |  +--------------------------------+ |  |                |
|  |  | MCP Servers                    | |  |                |
|  |  | splunk-siem | virustotal |     | |  |                |
|  |  | greynoise   | cve-intel        | |  |                |
|  |  +--------------------------------+ |  |                |
|  +-----------------+------------------+   |                |
|                    |                      |                |
|  +-----------------+--+ +-+--------------+-------------+  |
|  |  supervisor.sh     | | crowdstrike-to-splunk.py     |  |
|  |  (tmux, restart)   | | (Falcon -> Splunk HEC)      |  |
|  +--------------------+ +-----------------------------+   |
|                    |                                      |
|              +-----+-----+                                |
|              |  ntfy.sh  |--- Push to phone/Slack/webhook |
|              +-----------+                                |
+-----------------------------------------------------------+
```

## Requirements

| Component | Minimum | Notes |
|-----------|---------|-------|
| Claude Code | Latest | With active Anthropic API key |
| Splunk Enterprise | 9.x+ | Free license works (500MB/day). Enterprise for token auth. |
| Sysmon | 15.x+ | With a logging config (e.g., [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)) |
| Python | 3.10+ | For legacy engine and CrowdStrike forwarder |
| OS | Windows 11 + WSL2 (Ubuntu) | Primary target. Other setups may work. |
| ntfy.sh | Any | Free hosted or [self-hosted](https://docs.ntfy.sh/) |

**Optional:** CrowdStrike Falcon (commercial EDR), VirusTotal premium API key.

## Documentation

| Doc | Description |
|-----|-------------|
| [Setup Guide](docs/setup.md) | Full installation and configuration walkthrough |
| [Architecture](docs/architecture.md) | How Sentinel works: components, data flow, triage logic |
| [Customization](docs/customization.md) | Add rules, swap SIEMs, change personality, tune thresholds |
| [FAQ](docs/faq.md) | Common questions about cost, compatibility, and compliance |
| [MCP Servers](mcp/README.md) | Install and configure the threat intelligence MCP servers |

## Compliance Templates

Ready-to-use GDPR compliance document templates in [compliance/](compliance/):

| Template | GDPR Article | What It Covers |
|----------|-------------|----------------|
| [DPIA](compliance/dpia-template.md) | Art. 35 | Data Protection Impact Assessment for your AI/monitoring environment |
| [IR Plan](compliance/incident-response-plan.md) | Art. 33/34 | Incident detection, response, and breach notification procedures |
| [DPA](compliance/dpa-template.md) | Art. 28 | Client data processing agreement for consulting engagements |
| [ROPA](compliance/ropa-template.md) | Art. 30 | Record of processing activities |
| [AI Transparency](compliance/ai-transparency.md) | EU AI Act | AI system transparency statement |

Search for `[YOUR_` to find all placeholders that need to be filled in. See [compliance/README.md](compliance/README.md) for guidance.

## What's Inside

```
sentinel-soc-agent/
├── agent/           # The agent brain: CLAUDE.md, personality, heartbeat loop
├── rules/           # Detection rules + SIEM query packs
├── scripts/         # Supervisor, secrets loader, token rotation, legacy engine
├── mcp/             # MCP server configuration template + install guide
├── compliance/      # GDPR compliance document templates
├── dashboards/      # Splunk dashboard (dark theme, SOC overview)
├── examples/        # Minimal personality template for customization
└── docs/            # Setup, architecture, customization, FAQ
```

## Legacy Engine (v1)

[scripts/sentinel.py](scripts/sentinel.py) is the original rule-based Python script that preceded the Claude Code agent. Included for reference. It demonstrates the scoring logic in traditional code. The active agent is the Claude Code-powered system in `agent/`.

## Contributing

Contributions welcome, especially SIEM query packs for Elastic, Wazuh, and other platforms. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

The most impactful contribution: create `rules/queries/elastic.md` or `rules/queries/wazuh.md` following the [query file contract](docs/customization.md#adding-a-siem-backend).

## License

[Apache License 2.0](LICENSE)

Copyright 2026 Jose Lugo. See [NOTICE](NOTICE) for attribution requirements.

---

**Need commercial support?** Managed Sentinel deployments, custom compliance packs, and GDPR consulting available at [joselugo.de](https://joselugo.de).
