# FAQ

## Do I need a paid Splunk license?

No. The free Splunk Enterprise license supports up to 500MB/day of indexing, which is more than enough for a single workstation running Sysmon. You lose some features (alerting, authentication, distributed search), but the REST API and search capabilities work fine. The agent queries Splunk directly -- it does not depend on Splunk's built-in alerting.

## Can I use this without Claude Code?

No. The core agent requires Claude Code. The `scripts/sentinel.py` file is a legacy reference implementation that used hardcoded rules and static scoring. The entire point of this project is that an LLM reasons about security events instead of pattern-matching. Claude Code provides the agent runtime, MCP tool access, and the reasoning loop.

## Does this work on Linux or Mac?

It was designed for Windows 11 + WSL2 because that is where Sysmon runs. The architecture could be adapted:

- **Linux host:** Replace Sysmon with auditd or Falco. Write equivalent rules and a query pack for your audit log format. The agent, supervisor, and MCP servers all run natively on Linux.
- **Mac host:** Replace Sysmon with Endpoint Security framework logs or osquery. Same approach: different telemetry source, same agent reasoning.

The agent itself (Claude Code + MCP servers) runs on any platform that supports Claude Code. The platform-specific part is the telemetry source.

## How much does this cost to run?

- **Claude API usage:** Varies by activity. A quiet workstation with 48 heartbeats/day and mostly "all clear" cycles costs roughly $1-5/day in API tokens. Active investigation cycles (enrichment lookups, detailed reasoning) cost more. Monitor your Anthropic usage dashboard.
- **Splunk Enterprise:** Free (under 500MB/day license).
- **ntfy.sh:** Free (public server). Self-hosting is also free.
- **VirusTotal:** Free tier (4 lookups/minute, 500/day). Sufficient for a single workstation.
- **GreyNoise:** Free tier (10 lookups/day without an API key). Paid plans available for higher volume.

## Is CrowdStrike required?

No. CrowdStrike Falcon is an optional integration. If you have it installed, the `crowdstrike-to-splunk.py` forwarder can stream Falcon detections into Splunk for the agent to correlate. If you do not have it, the agent works entirely with Sysmon and Windows Event Log data.

## Can I use Elastic, Wazuh, or Microsoft Sentinel instead of Splunk?

Yes. The detection logic lives in the agent's reasoning (CLAUDE.md), not in SIEM-specific queries. To add a new SIEM backend:

1. Create a query pack at `rules/queries/<siem>.md` following the contract in the [customization guide](customization.md).
2. Install or configure an MCP server that can query your SIEM's API.
3. Update `agent/CLAUDE.md` to reference your SIEM and query pack.

Contributions of query packs for other SIEMs are welcome.

## Is this GDPR compliant by itself?

No. The templates, DPIA structure, detection rules, and compliance documents in this repo help you **structure** your compliance program. They are a starting point, not a finish line.

GDPR compliance requires:

- A completed DPIA (Data Protection Impact Assessment) reviewed by a qualified person.
- Documented technical and organizational measures (TOMs) that are actually implemented.
- A Record of Processing Activities (ROPA) under Article 30.
- Legal basis for any personal data processing the agent itself performs (it reads event logs that may contain usernames and IP addresses).
- Human judgment on risk assessment and proportionality.
- Legal review by someone qualified in EU data protection law.

The agent helps you monitor and detect. Compliance is a human responsibility.

## How do I update the agent?

Pull the latest changes and restart:

```bash
cd sentinel-soc-agent
git pull
# Review CHANGELOG.md for breaking changes
# Restart the supervisor
tmux kill-session -t sentinel
tmux new-session -d -s sentinel 'bash scripts/supervisor.sh'
```

Your local customizations live in `agent/CLAUDE.md`, `agent/PERSONALITY.md`, `baseline.csv`, and `~/.sentinel-secrets`. These are not overwritten by `git pull` since they are in `.gitignore` (secrets) or are meant to be user-edited.

## The agent keeps alerting on normal activity. How do I fix it?

Build your baseline. See the [customization guide](customization.md#building-your-baseline) for the process. The short version:

1. Let the agent run for 24-48 hours.
2. Review `triage.jsonl` for false positives.
3. Add normal patterns to `baseline.csv`.
4. Restart the agent.

Also check the known-good baseline section in `agent/CLAUDE.md` and add your standard applications there.

## Can multiple agents share the same Splunk instance?

Yes. Each agent should use its own scoped Splunk token (audience field set to the agent name) and its own triage log file. This prevents token cross-contamination and keeps triage histories separate.
