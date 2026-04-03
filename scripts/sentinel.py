#!/usr/bin/env python3
"""
Legacy v1 (reference only). See agent/CLAUDE.md for the active Claude Code agent.

Sentinel SOC Analyst Agent
Passive threat detection for Windows 11 + WSL2 environments.
Reads Splunk via REST API, triages alerts, escalates via ntfy.sh.
Understands Claude Code AI agent activity as normal baseline.
"""

import json
import csv
import os
import sys
import subprocess
import urllib3
import requests
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Suppress SSL warnings for localhost Splunk
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Config ──────────────────────────────────────────────────────────────────

SPLUNK_BASE = os.environ.get("SPLUNK_URL", "https://localhost:8089")
SPLUNK_USER = "admin"
SPLUNK_PASS_FILE = Path.home() / ".splunk_pass"

NTFY_URL = "https://ntfy.sh"
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "sentinel-alerts")

CUSTOMER_DATA_PATH = os.environ.get("CUSTOMER_DATA_PATH", r"C:\Users\YourUser\Desktop\Work")

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / f"sentinel-{datetime.now().strftime('%Y-%m-%d')}.log"

BASELINE_FILE = Path.home() / "sentinel" / "baseline.csv"
TRIAGE_LOG = Path.home() / "sentinel" / "triage.jsonl"

# ── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("sentinel")

# ── Splunk Client ───────────────────────────────────────────────────────────

class Splunk:
    def __init__(self):
        self.pw = SPLUNK_PASS_FILE.read_text().strip()
        self.splunk_bin = r'C:\Program Files\Splunk\bin\splunk.exe'
        self.output_file = r'C:\Tools\Sysmon\sentinel_query.csv'

    def search(self, spl: str, earliest: str = "-30m", latest: str = "now", max_results: int = 200) -> list[dict]:
        """Run search via elevated PowerShell script writing CSV to disk."""
        try:
            # Write a PS1 script that runs the query and outputs CSV
            spl_escaped = spl.replace('"', '""').replace("'", "''")
            script = (
                f'$r = & "{self.splunk_bin}" search '
                f'"{spl_escaped} earliest={earliest} latest={latest}" '
                f'-auth "admin:{self.pw}" -output csv -maxout {max_results} 2>&1\n'
                f'$r | Out-File "{self.output_file}" -Encoding utf8\n'
            )
            script_path = Path("/tmp/sentinel_query.ps1")
            script_path.write_text(script)

            # Run elevated
            wsl_script = f"\\\\wsl.localhost\\Ubuntu{script_path}"
            result = subprocess.run(
                [
                    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "-Command",
                    f"Start-Process powershell -Verb RunAs "
                    f"-ArgumentList '-ExecutionPolicy','Bypass','-File','{wsl_script}' "
                    f"-Wait"
                ],
                capture_output=True, text=True, timeout=45,
            )

            # Read CSV output from Windows
            csv_read = subprocess.run(
                ["/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "-Command", f"Get-Content '{self.output_file}'"],
                capture_output=True, text=True, timeout=10,
            )
            output = csv_read.stdout.strip()
            if not output:
                return []

            # Parse CSV - skip WARNING lines
            lines = [l for l in output.split("\n") if l.strip() and not l.startswith("WARNING") and "CategoryInfo" not in l and "FullyQualifiedErrorId" not in l and "server.conf" not in l and "At \\" not in l and "+  " not in l]
            if len(lines) < 2:
                return []

            # First valid line is header
            reader = csv.DictReader(lines)
            return list(reader)

        except subprocess.TimeoutExpired:
            log.error("Splunk search timed out")
            return []
        except Exception as e:
            log.error(f"Splunk search failed: {e}")
            return []

# ── Baseline ────────────────────────────────────────────────────────────────

# Known-good process chains for Claude Code / AI agents
KNOWN_GOOD_WSL_CHILDREN = {
    "powershell.exe", "cmd.exe", "conhost.exe", "netstat.exe",
    "findstr.exe", "icacls.exe", "wevtutil.exe", "msiexec.exe",
    "net.exe", "net1.exe", "sdbinst.exe", "wsl.exe", "wslhost.exe",
}

KNOWN_GOOD_NETWORK = {
    # ports
    "443", "80", "53", "22", "5353",
    # splunk
    "8000", "8089",
    # mission control + clawdbot
    "3000", "18789", "18791", "18792",
}

KNOWN_GOOD_NETWORK_PROCS = {
    "chrome.exe", "msedge.exe", "msedgewebview2.exe",
    "steamwebhelper.exe", "splunkd.exe", "svchost.exe",
    "Sysmon64.exe", "wsl.exe", "wslhost.exe",
    "MicrosoftEdgeUpdate.exe", "GoogleUpdate.exe",
}

CREDENTIAL_TOOLS = {
    "mimikatz", "procdump", "lazagne", "secretsdump",
    "gsecdump", "wce.exe", "rubeus", "sharphound",
    "bloodhound", "kerberoast",
}

C2_PATTERNS = [
    "nc -e", "ncat -e", "bash -i >& /dev",
    "-NoP -NonI -W Hidden", "IEX(", "Invoke-Expression",
    "Net.WebClient", "downloadstring", "certutil*urlcache",
    "bitsadmin*/transfer", "mshta http", "regsvr32 /s /n /u",
]

SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 8888, 9001, 9999, 12345, 31337}

# ── Threat Scoring ──────────────────────────────────────────────────────────

def score_process_event(ev: dict) -> tuple[int, list[str]]:
    """Score a Sysmon EventCode=1 process creation event. Returns (score, reasons)."""
    score = 0
    reasons = []

    image = ev.get("Image", "").lower()
    parent = ev.get("ParentImage", "").lower()
    cmdline = ev.get("CommandLine", "").lower()
    proc_name = image.rsplit("\\", 1)[-1] if "\\" in image else image

    # Credential theft tool → instant critical
    for tool in CREDENTIAL_TOOLS:
        if tool in image or tool in cmdline:
            return 100, [f"Credential theft tool: {tool}"]

    # C2 / reverse shell patterns
    for pat in C2_PATTERNS:
        if pat.lower() in cmdline:
            return 95, [f"C2/reverse shell pattern: {pat}"]

    # Is this a WSL child process? (expected Claude Code)
    is_wsl_child = "wsl.exe" in parent or "wslhost.exe" in parent
    if is_wsl_child and proc_name in KNOWN_GOOD_WSL_CHILDREN:
        return 0, ["Expected Claude Code activity"]

    # WSL spawned something unexpected
    if is_wsl_child and proc_name not in KNOWN_GOOD_WSL_CHILDREN:
        score += 40
        reasons.append(f"WSL spawned unexpected: {proc_name}")

    # Obfuscation indicators
    if "base64" in cmdline or "-enc " in cmdline or "-encodedcommand" in cmdline:
        score += 30
        reasons.append("Encoded/obfuscated command")

    # Process from unusual parent
    normal_parents = {"wsl.exe", "wslhost.exe", "explorer.exe", "svchost.exe",
                      "services.exe", "winlogon.exe", "cmd.exe", "powershell.exe"}
    parent_name = parent.rsplit("\\", 1)[-1] if "\\" in parent else parent
    if parent_name and parent_name not in normal_parents:
        score += 15
        reasons.append(f"Unusual parent: {parent_name}")

    # Executable in sensitive location
    if "system32" in image and not any(x in parent for x in ["services.exe", "svchost.exe", "winlogon.exe"]):
        score += 20
        reasons.append("Process from System32 with unusual parent")

    return min(score, 100), reasons


def score_network_event(ev: dict) -> tuple[int, list[str]]:
    """Score a Sysmon EventCode=3 network event."""
    score = 0
    reasons = []

    image = ev.get("Image", "").lower()
    dest_port = ev.get("DestinationPort", "")
    dest_ip = ev.get("DestinationIp", "")
    proc_name = image.rsplit("\\", 1)[-1] if "\\" in image else image

    # Known good process + known good port → skip
    if proc_name in KNOWN_GOOD_NETWORK_PROCS and dest_port in KNOWN_GOOD_NETWORK:
        return 0, ["Expected network activity"]

    # Suspicious port
    try:
        if int(dest_port) in SUSPICIOUS_PORTS:
            score += 50
            reasons.append(f"Suspicious port: {dest_port}")
    except (ValueError, TypeError):
        pass

    # Unknown process making network calls
    if proc_name not in KNOWN_GOOD_NETWORK_PROCS and dest_port not in KNOWN_GOOD_NETWORK:
        score += 25
        reasons.append(f"Unknown process {proc_name} → {dest_ip}:{dest_port}")

    return min(score, 100), reasons


def score_file_event(ev: dict) -> tuple[int, list[str]]:
    """Score a Sysmon EventCode=11 file creation event."""
    score = 0
    reasons = []

    image = ev.get("Image", "").lower()
    target = ev.get("TargetFilename", "").lower()
    proc_name = image.rsplit("\\", 1)[-1] if "\\" in image else image

    # Customer data directory access
    if "desktop\\work" in target:
        # From WSL/Claude Code → expected but log it
        if "wsl.exe" in image or "powershell.exe" in image:
            return 10, ["Claude Code accessing Work folder - expected but logged"]
        # From explorer → user manually, OK
        if "explorer.exe" in image:
            return 5, ["User accessing Work folder manually"]
        # Anything else → suspicious
        score += 60
        reasons.append(f"Unexpected process {proc_name} accessing customer data")

    # Executable dropped in sensitive location
    sensitive_exts = {".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".cmd"}
    if any(target.endswith(ext) for ext in sensitive_exts):
        if "system32" in target or "startup" in target or "\\temp\\" in target:
            score += 45
            reasons.append(f"Executable dropped in sensitive location: {target}")

    return min(score, 100), reasons

# ── GDPR-Specific Checks ───────────────────────────────────────────────────

def check_gdpr_file_access(splunk: Splunk) -> list[dict]:
    """Check Windows Security audit log for customer data access."""
    events = splunk.search(
        f'index=wineventlog EventCode=4663 ObjectName="*Desktop\\\\Work*"'
        f' | table _time SubjectUserName ProcessName ObjectName AccessMask',
        earliest="-30m",
    )
    alerts = []
    for ev in events:
        proc = ev.get("ProcessName", "").lower()
        obj = ev.get("ObjectName", "")
        # Skip empty/garbage results
        if not proc or not obj or proc == "?" or obj == "?":
            continue
        # Authorized processes
        if any(x in proc for x in ["wsl", "powershell", "cmd", "explorer", "splunk", "sysmon"]):
            continue
        alerts.append({
            "type": "GDPR_UNAUTHORIZED_ACCESS",
            "severity": "CRITICAL",
            "process": proc,
            "user": ev.get("SubjectUserName", "?"),
            "file": obj,
            "time": ev.get("_time", "?"),
            "reason": f"Unauthorized process accessed customer data: {proc}",
        })
    return alerts


def check_gdpr_data_outside_work(splunk: Splunk) -> list[dict]:
    """Check for customer data patterns created outside the Work folder."""
    events = splunk.search(
        'index=sysmon EventCode=11'
        ' (TargetFilename="*kunden*" OR TargetFilename="*client*" OR TargetFilename="*vertrag*"'
        '  OR TargetFilename="*rechnung*" OR TargetFilename="*invoice*" OR TargetFilename="*contract*"'
        '  OR TargetFilename="*DPIA*" OR TargetFilename="*ROPA*")'
        ' NOT TargetFilename="*Desktop\\\\Work*"'
        ' NOT TargetFilename="*splunk*"'
        ' | table _time Image TargetFilename User',
        earliest="-30m",
    )
    alerts = []
    for ev in events:
        target = ev.get("TargetFilename", "")
        image = ev.get("Image", "")
        # Skip empty/garbage results
        if not target or not image or target == "?" or image == "?":
            continue
        alerts.append({
            "type": "GDPR_DATA_OUTSIDE_SECURE_DIR",
            "severity": "HIGH",
            "process": image,
            "file": target,
            "user": ev.get("User", "?"),
            "time": ev.get("_time", "?"),
            "reason": f"Customer data pattern found outside Work folder: {target}",
        })
    return alerts

# ── Escalation ──────────────────────────────────────────────────────────────

def send_ntfy(title: str, message: str, priority: str = "default", tags: str = "warning"):
    """Send notification via ntfy.sh."""
    try:
        # Sanitize unicode characters that cause encoding issues
        clean_title = title.encode("ascii", "replace").decode("ascii")
        clean_msg = message.encode("ascii", "replace").decode("ascii")
        r = requests.post(
            f"{NTFY_URL}/{NTFY_TOPIC}",
            data=clean_msg,
            headers={
                "Title": clean_title,
                "Priority": priority,
                "Tags": tags,
            },
            timeout=10,
        )
        r.raise_for_status()
        log.info(f"ntfy sent: [{priority}] {clean_title}")
    except Exception as e:
        log.error(f"ntfy failed: {e}")


def escalate(alert: dict):
    """Route alert based on severity."""
    sev = alert["severity"]
    title = f"Sentinel: {sev} - {alert['type']}"
    body = (
        f"{alert['reason']}\n"
        f"Process: {alert.get('process', '?')}\n"
        f"User: {alert.get('user', '?')}\n"
        f"Time: {alert.get('time', '?')}"
    )

    if sev == "CRITICAL":
        send_ntfy(title, body, priority="urgent", tags="rotating_light")
    elif sev == "HIGH":
        send_ntfy(title, body, priority="high", tags="warning")
    # MEDIUM and LOW just get logged, no push


def log_triage(alert: dict):
    """Append triage result to JSONL log."""
    alert["triaged_at"] = datetime.now(timezone.utc).isoformat()
    try:
        with open(TRIAGE_LOG, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception as e:
        log.error(f"Failed to write triage log: {e}")

# ── Main Heartbeat ──────────────────────────────────────────────────────────

def heartbeat():
    """Single heartbeat cycle: fetch → score → triage → escalate."""
    log.info("=" * 50)
    log.info("SENTINEL HEARTBEAT")
    log.info("=" * 50)

    splunk = Splunk()
    stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "suppressed": 0}

    # ── 1. GDPR checks (highest priority) ──
    gdpr_access = check_gdpr_file_access(splunk)
    gdpr_outside = check_gdpr_data_outside_work(splunk)
    gdpr_alerts = gdpr_access + gdpr_outside

    for alert in gdpr_alerts:
        stats["total"] += 1
        stats["critical" if alert["severity"] == "CRITICAL" else "high"] += 1
        escalate(alert)
        log_triage(alert)
        log.warning(f"GDPR ALERT: {alert['reason']}")

    # ── 2. Process creation events ──
    proc_events = splunk.search(
        "index=sysmon EventCode=1 | fields Image ParentImage CommandLine User ProcessId _time",
        earliest="-30m",
    )
    for ev in proc_events:
        score, reasons = score_process_event(ev)
        stats["total"] += 1

        if score == 0:
            stats["suppressed"] += 1
            continue

        sev = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW"
        stats[sev.lower()] += 1

        alert = {
            "type": "PROCESS",
            "severity": sev,
            "score": score,
            "process": ev.get("Image", "?"),
            "parent": ev.get("ParentImage", "?"),
            "cmdline": ev.get("CommandLine", "?"),
            "user": ev.get("User", "?"),
            "time": ev.get("_time", "?"),
            "reason": "; ".join(reasons),
        }
        log_triage(alert)
        if sev in ("CRITICAL", "HIGH"):
            escalate(alert)
            log.warning(f"{sev}: {'; '.join(reasons)}")

    # ── 3. Network events ──
    net_events = splunk.search(
        "index=sysmon EventCode=3 | fields Image DestinationIp DestinationPort SourceIp _time",
        earliest="-30m",
    )
    for ev in net_events:
        score, reasons = score_network_event(ev)
        stats["total"] += 1

        if score == 0:
            stats["suppressed"] += 1
            continue

        sev = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW"
        stats[sev.lower()] += 1

        alert = {
            "type": "NETWORK",
            "severity": sev,
            "score": score,
            "process": ev.get("Image", "?"),
            "destination": f"{ev.get('DestinationIp', '?')}:{ev.get('DestinationPort', '?')}",
            "time": ev.get("_time", "?"),
            "reason": "; ".join(reasons),
        }
        log_triage(alert)
        if sev in ("CRITICAL", "HIGH"):
            escalate(alert)

    # ── 4. File events ──
    file_events = splunk.search(
        "index=sysmon EventCode=11 | fields Image TargetFilename User _time",
        earliest="-30m",
    )
    for ev in file_events:
        score, reasons = score_file_event(ev)
        stats["total"] += 1

        if score <= 5:
            stats["suppressed"] += 1
            continue

        sev = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW"
        stats[sev.lower()] += 1

        alert = {
            "type": "FILE",
            "severity": sev,
            "score": score,
            "process": ev.get("Image", "?"),
            "file": ev.get("TargetFilename", "?"),
            "user": ev.get("User", "?"),
            "time": ev.get("_time", "?"),
            "reason": "; ".join(reasons),
        }
        log_triage(alert)
        if sev in ("CRITICAL", "HIGH"):
            escalate(alert)

    # ── Summary ──
    status = "ALL CLEAR" if stats["critical"] == 0 and stats["high"] == 0 else "ACTION REQUIRED"
    log.info(f"Events: {stats['total']} | Suppressed: {stats['suppressed']} | "
             f"CRIT: {stats['critical']} HIGH: {stats['high']} MED: {stats['medium']} LOW: {stats['low']}")
    log.info(f"STATUS: {status}")
    log.info("=" * 50)

    # Send heartbeat confirmation if all clear
    if stats["critical"] == 0 and stats["high"] == 0:
        # Silent - don't spam the user
        pass
    else:
        # Summary push for any HIGH+ alerts
        send_ntfy(
            f"Sentinel: {stats['critical']} critical, {stats['high']} high",
            f"Review triage log at ~/sentinel/triage.jsonl",
            priority="high" if stats["critical"] > 0 else "default",
            tags="shield",
        )

    return stats


# ── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        heartbeat()
    except Exception as e:
        log.error(f"Sentinel failed: {e}", exc_info=True)
        send_ntfy("Sentinel CRASHED", str(e), priority="urgent", tags="skull")
        sys.exit(1)
