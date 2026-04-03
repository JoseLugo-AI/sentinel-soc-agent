# MCP Server Setup

Sentinel uses four MCP (Model Context Protocol) servers to gather intelligence during each heartbeat cycle. This guide covers installation, configuration, and verification for each.

## Prerequisites

- Node.js 18+ and npm (for VirusTotal and GreyNoise servers)
- Python 3.10+ (for CVE Intel server)
- Go 1.21+ (only if building Splunk server from source)

## 1. splunk-siem

**What it does:** Executes SPL (Search Processing Language) queries against your Splunk instance. This is Sentinel's primary data source for process creation, network connections, file events, and GDPR-specific monitoring.

**Setup:**

Build from source or download the pre-built binary from the [mcp-server-splunk repository](https://github.com/YOUR-ORG/mcp-server-splunk). Place the binary in `./mcp-servers/splunk-siem/`.

```bash
mkdir -p mcp-servers/splunk-siem
# Option A: Download pre-built binary
# cp /path/to/downloaded/mcp-server-splunk ./mcp-servers/splunk-siem/

# Option B: Build from source
# cd mcp-servers/splunk-siem && go build -o mcp-server-splunk . && cd ../..
```

**Configuration:**

Set environment variables (or use `.env`):

```bash
export SPLUNK_URL="https://your-splunk-host:8089"
export SPLUNK_TOKEN="your-splunk-auth-token"
```

**Verify:**

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | SPLUNK_URL="$SPLUNK_URL" SPLUNK_TOKEN="$SPLUNK_TOKEN" ./mcp-servers/splunk-siem/mcp-server-splunk
```

You should see a JSON response listing available tools (e.g., `splunk_search`).

**Common issues:**
- `connection refused` — Splunk management port (8089) is not accessible from your machine. Check firewall rules.
- `401 Unauthorized` — Token is expired or invalid. Generate a new one in Splunk > Settings > Tokens.
- Self-signed cert errors — The server uses `-k` equivalent by default for self-signed Splunk certs.

---

## 2. virustotal

**What it does:** Checks IP addresses, file hashes, URLs, and domains against VirusTotal's threat intelligence database. Used to enrich suspicious findings during triage.

**Setup:**

No local installation needed. Runs via npx.

1. Get a free API key from [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Set the environment variable:

```bash
export VIRUSTOTAL_API_KEY="your-api-key-here"
```

**Verify:**

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | VIRUSTOTAL_API_KEY="$VIRUSTOTAL_API_KEY" npx -y @burtthecoder/mcp-virustotal
```

You should see tools like `vt_ip_lookup`, `vt_hash_lookup`, etc.

**Common issues:**
- `403 Forbidden` — API key is invalid or rate-limited. Free tier allows 4 requests/minute, 500/day.
- Slow first run — npx downloads the package on first use. Subsequent runs are cached.

---

## 3. greynoise

**What it does:** Determines whether an IP address is mass-scanning the internet (benign noise) or specifically targeting your infrastructure. Critical for filtering out scanner noise from real threats.

**Setup:**

No API key required for the Community (free) tier. Just run via npx.

```bash
# No configuration needed
npx -y mcp-greynoise
```

**Verify:**

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | npx -y mcp-greynoise
```

You should see tools like `greynoise_ip_lookup`.

**Rate limits:** Free tier allows 10 lookups per day. For higher volume, sign up at [greynoise.io](https://www.greynoise.io/) and set `GREYNOISE_API_KEY`.

**Common issues:**
- `429 Too Many Requests` — You've hit the daily limit. Wait 24 hours or upgrade to a paid plan.

---

## 4. cve-intel

**What it does:** Looks up CVE details from the National Vulnerability Database (NVD), CISA Known Exploited Vulnerabilities (KEV) catalog, and EPSS (Exploit Prediction Scoring System). No API key needed.

**Setup:**

```bash
cd mcp-servers/cve-intel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
deactivate
cd ../..
```

**Verify:**

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | ./mcp-servers/cve-intel/.venv/bin/python ./mcp-servers/cve-intel/server.py
```

You should see tools like `cve_lookup`, `kev_check`, `epss_score`.

**Common issues:**
- `ModuleNotFoundError` — The virtual environment wasn't activated during install, or `requirements.txt` is missing a dependency. Re-run pip install.
- Slow responses — NVD API can be slow. The server caches results locally.

---

## Putting It Together

1. Copy `.mcp.json.example` to `.mcp.json` in your project root
2. Set your environment variables (`SPLUNK_URL`, `SPLUNK_TOKEN`, `VIRUSTOTAL_API_KEY`)
3. Install all four servers as described above
4. Claude Code will automatically discover the MCP servers from `.mcp.json`

To test all servers at once, start a Claude Code session and ask Sentinel to run a heartbeat. It will report which MCP servers are online and which need attention.
