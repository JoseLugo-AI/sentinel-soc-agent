# Setup Guide

## Prerequisites

- **Claude Code** -- Latest version with an Anthropic API key. Install from [claude.ai/code](https://claude.ai/code).
- **Splunk Enterprise 9.x+** -- Free license is fine (500MB/day limit). Download from [splunk.com](https://www.splunk.com/en_us/download/splunk-enterprise.html). Install on the Windows host.
- **Sysmon 15.x+** -- Microsoft Sysinternals. Download from [learn.microsoft.com](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- **Python 3.10+** -- For optional scripts (CrowdStrike forwarder, legacy sentinel.py).
- **WSL2 Ubuntu** -- The agent runs here. Install via `wsl --install` on Windows 11.
- **ntfy.sh** -- Free push notification service. No account needed for the public server. Optionally self-host.

## 1. Clone the Repo

```bash
git clone https://github.com/YOUR_USERNAME/sentinel-soc-agent.git
cd sentinel-soc-agent
```

## 2. Configure Secrets

Create `~/.sentinel-secrets` with your credentials:

```bash
cat > ~/.sentinel-secrets << 'EOF'
SPLUNK_URL="https://your-splunk:8089"
SPLUNK_TOKEN="your-search-token"
SPLUNK_ADMIN_TOKEN="your-admin-token"  # For token rotation only
VIRUSTOTAL_API_KEY="your-vt-key"
NTFY_TOPIC="your-ntfy-topic"
NTFY_URL="https://ntfy.sh"
CUSTOMER_DATA_PATH="C:\Users\YourUser\Desktop\Work"
EOF
```

Lock down permissions:

```bash
chmod 600 ~/.sentinel-secrets
```

### Getting Your Tokens

- **Splunk token**: In Splunk Web, go to Settings > Tokens > New Token. Create one with the `search` capability for the agent, and optionally a second admin-scoped token for automated token rotation.
- **VirusTotal API key**: Free at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us). The free tier allows 4 lookups/minute.
- **ntfy topic**: Pick any unique string. No signup required on the public server.

## 3. Install MCP Servers

MCP (Model Context Protocol) servers give the agent direct access to Splunk, VirusTotal, GreyNoise, and CVE databases.

See [mcp/README.md](../mcp/README.md) for installation instructions for each server.

After installation, verify they are listed in your Claude Code MCP configuration (`.claude/settings.json` or `.mcp.json`).

## 4. Customize the Agent

Edit `agent/CLAUDE.md` to match your environment:

- **Splunk URL** -- Update the Splunk REST API endpoint if it differs from the default.
- **Customer data path** -- Set the path to your protected data directory (the GDPR "crown jewel").
- **ntfy topic** -- Set your notification topic name.
- **Baseline** -- Review and update the known-good process list to match your workstation's normal activity.
- **Detection rules** -- Review `rules/gdpr.md` and adjust thresholds and patterns for your use case.

Edit `agent/PERSONALITY.md` to set the agent's communication style, or use `examples/personality-minimal.md` as a starting point.

## 5. Set Up Splunk

### Create Indexes

In Splunk Web (Settings > Indexes > New Index):

1. Create index `sysmon` -- Receives Sysmon events.
2. Create index `wineventlog` -- Receives Windows Event Log events.

### Install Sysmon

Download and install Sysmon with the SwiftOnSecurity configuration:

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon

# Download SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile C:\Sysmon\sysmonconfig.xml

# Install
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

### Configure Splunk Inputs

Add Sysmon and Security event log inputs. In Splunk Web: Settings > Data Inputs > Local Event Log Collection > New:

- **Sysmon**: Log name `Microsoft-Windows-Sysmon/Operational`, index `sysmon`
- **Security**: Log name `Security`, index `wineventlog`

## 6. Start the Supervisor

The supervisor runs the agent in a tmux session and handles restarts:

```bash
tmux new-session -d -s sentinel 'bash scripts/supervisor.sh'
```

To attach and watch:

```bash
tmux attach -t sentinel
```

Detach with `Ctrl+B`, then `D`.

## 7. Verify Your Installation

Run through these checks to confirm everything is working.

### a. Splunk Connectivity

Test that the agent can reach Splunk and query data:

```bash
# Source your secrets
source ~/.sentinel-secrets

# Run a test query (adjust URL for your setup)
curl -k -H "Authorization: Bearer $SPLUNK_TOKEN" \
  "$SPLUNK_URL/services/search/jobs/export" \
  -d search="search index=sysmon | head 1" \
  -d output_mode=json
```

You should get a JSON response with at least one event. If Sysmon is freshly installed, generate some activity first (open a program, browse a website).

### b. MCP Server Health

Verify each MCP server responds. In a Claude Code session:

```
> Use the splunk-siem tool to run: index=sysmon | head 1
> Use the virustotal tool to check: 8.8.8.8
> Use the greynoise tool to check: 8.8.8.8
> Use the cve-intel tool to look up: CVE-2024-0001
```

Each should return data without errors.

### c. Notification Test

Send a test notification to confirm ntfy delivery:

```bash
source ~/.sentinel-secrets
curl -d "Sentinel test notification" "$NTFY_URL/$NTFY_TOPIC"
```

Check your phone or notification endpoint.

### d. Manual Trigger

Run an unusual process to test detection:

```powershell
# On Windows - this should generate a Sysmon event the agent notices
certutil -hashfile C:\Windows\notepad.exe SHA256
```

Wait for the next heartbeat cycle (up to 30 minutes) and check `triage.jsonl` for an entry.

### e. Placeholder Check

Ensure you replaced all template placeholders:

```bash
grep -r "\[YOUR_" agent/ compliance/ dashboards/ rules/
```

If any results appear, update those files with your actual values.
