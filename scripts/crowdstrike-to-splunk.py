#!/usr/bin/env python3
"""CrowdStrike Falcon Event Stream → Splunk HEC forwarder.

Connects to the CrowdStrike FalconHose event stream and forwards events
to Splunk via HTTP Event Collector. Runs as a persistent service.

Usage:
    source ~/.sentinel-secrets && python3 crowdstrike-to-splunk.py
"""

import json
import os
import sys
import time
import signal
import logging
import requests
from datetime import datetime, timezone
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(Path(__file__).parent.parent / "crowdstrike-forwarder.log")),
    ],
)
log = logging.getLogger("cs-forwarder")

# --- Config from env ---
CS_CLIENT_ID = os.environ["CROWDSTRIKE_CLIENT_ID"]
CS_CLIENT_SECRET = os.environ["CROWDSTRIKE_CLIENT_SECRET"]
CS_BASE_URL = os.environ.get("CROWDSTRIKE_BASE_URL", "https://api.eu-1.crowdstrike.com")
SPLUNK_HEC_URL = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088")
SPLUNK_HEC_TOKEN = os.environ["SPLUNK_HEC_TOKEN"]
SPLUNK_INDEX = "sysmon"
SPLUNK_SOURCETYPE = "crowdstrike:falcon:event"

OFFSET_FILE = str(Path(__file__).parent.parent / "crowdstrike-stream-offset.txt")
APP_ID = "sentinel-splunk-forwarder"

# Event types worth forwarding (skip noisy audit events)
PRIORITY_EVENT_TYPES = {
    "DetectionSummaryEvent",
    "IncidentSummaryEvent",
    "AuthActivityAuditEvent",
    "UserActivityAuditEvent",
    "RemoteResponseSessionStartEvent",
    "RemoteResponseSessionEndEvent",
    "HashSpreadingEvent",
    "FirewallMatchEvent",
    "CSPMPolicyViolation",
}

# Always forward these regardless of type
ALWAYS_FORWARD_KEYWORDS = {
    "malware", "ransomware", "exploit", "credential", "lateral",
    "privilege", "exfiltration", "c2", "command-and-control",
}

running = True


def signal_handler(sig, frame):
    global running
    log.info("Shutdown signal received, closing stream...")
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def cs_get_token():
    """Get OAuth2 bearer token from CrowdStrike."""
    resp = requests.post(
        f"{CS_BASE_URL}/oauth2/token",
        data={"client_id": CS_CLIENT_ID, "client_secret": CS_CLIENT_SECRET},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp.raise_for_status()
    data = resp.json()
    log.info("CrowdStrike OAuth token acquired (expires in %ds)", data["expires_in"])
    return data["access_token"]


def cs_get_stream(token):
    """Get event stream URL and session token."""
    resp = requests.get(
        f"{CS_BASE_URL}/sensors/entities/datafeed/v2",
        params={"appId": APP_ID},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    data = resp.json()
    resource = data["resources"][0]
    return (
        resource["dataFeedURL"],
        resource["sessionToken"]["token"],
        resource["refreshActiveSessionURL"],
    )


def cs_refresh_stream(token, refresh_url):
    """Refresh the active stream session to keep it alive."""
    resp = requests.post(
        refresh_url,
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code == 200:
        log.debug("Stream session refreshed")
    else:
        log.warning("Stream refresh failed: %d", resp.status_code)


def load_offset():
    """Load last processed offset from disk."""
    try:
        with open(OFFSET_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def save_offset(offset):
    """Persist current offset to disk."""
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))


def should_forward(event):
    """Decide if an event is worth sending to Splunk."""
    event_type = event.get("metadata", {}).get("eventType", "")

    # Always forward priority event types
    if event_type in PRIORITY_EVENT_TYPES:
        return True

    # Check for security-relevant keywords in the event body
    event_str = json.dumps(event).lower()
    for keyword in ALWAYS_FORWARD_KEYWORDS:
        if keyword in event_str:
            return True

    # Skip noisy API audit events from our own polling
    if event_type == "APIActivityAuditEvent":
        return False

    # Forward unknown event types (better safe than sorry)
    if event_type and event_type not in ("APIActivityAuditEvent",):
        return True

    return False


def send_to_splunk(events):
    """Send a batch of events to Splunk HEC."""
    if not events:
        return

    payload = ""
    for event in events:
        ts = event.get("metadata", {}).get("eventCreationTime", 0) / 1000.0
        hec_event = {
            "time": ts,
            "index": SPLUNK_INDEX,
            "sourcetype": SPLUNK_SOURCETYPE,
            "source": "crowdstrike:falcon",
            "event": event,
        }
        payload += json.dumps(hec_event)

    resp = requests.post(
        f"{SPLUNK_HEC_URL}/services/collector/event",
        headers={
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json",
        },
        data=payload,
        verify=False,
    )

    if resp.status_code == 200:
        log.info("Sent %d events to Splunk", len(events))
    else:
        log.error("Splunk HEC error %d: %s", resp.status_code, resp.text)


def stream_events():
    """Main loop: connect to event stream and forward to Splunk."""
    global running

    cs_token = cs_get_token()
    token_time = time.time()
    stream_url, stream_token, refresh_url = cs_get_stream(cs_token)
    last_refresh = time.time()

    offset = load_offset()
    if offset > 0:
        stream_url += f"&offset={offset}"
        log.info("Resuming from offset %d", offset)

    log.info("Connecting to CrowdStrike Event Stream...")

    while running:
        try:
            # Refresh OAuth token every 25 minutes (expires at 30)
            if time.time() - token_time > 1500:
                cs_token = cs_get_token()
                token_time = time.time()

            # Refresh stream session every 25 minutes
            if time.time() - last_refresh > 1500:
                cs_refresh_stream(cs_token, refresh_url)
                last_refresh = time.time()

            with requests.get(
                stream_url,
                headers={
                    "Authorization": f"Token {stream_token}",
                    "Accept": "application/json",
                },
                stream=True,
                timeout=(10, 30),
            ) as resp:
                resp.raise_for_status()
                batch = []
                last_flush = time.time()

                for line in resp.iter_lines(decode_unicode=True):
                    if not running:
                        break
                    if not line:
                        # Flush on idle if we have queued events
                        if batch and (time.time() - last_flush > 5):
                            send_to_splunk(batch)
                            batch = []
                            last_flush = time.time()
                            save_offset(offset)
                        continue

                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    new_offset = event.get("metadata", {}).get("offset", offset)
                    event_type = event.get("metadata", {}).get("eventType", "unknown")

                    if should_forward(event):
                        batch.append(event)
                        log.info(
                            "Queued: %s (offset %d)", event_type, new_offset
                        )

                    offset = new_offset

                    # Flush batch every 10 events or on priority events
                    if len(batch) >= 10 or event_type in (
                        "DetectionSummaryEvent",
                        "IncidentSummaryEvent",
                    ):
                        send_to_splunk(batch)
                        batch = []
                        last_flush = time.time()
                        save_offset(offset)

                # Flush remaining on stream end
                if batch:
                    send_to_splunk(batch)
                    save_offset(offset)

        except requests.exceptions.Timeout:
            log.debug("Stream timeout (normal), reconnecting...")
            continue
        except requests.exceptions.ConnectionError as e:
            log.warning("Connection error: %s — retrying in 30s", e)
            time.sleep(30)
        except requests.exceptions.HTTPError as e:
            status = getattr(e.response, 'status_code', 0)
            if status in (401, 403, 406):
                log.warning("Auth/stream expired (%d) — re-authenticating and getting new stream", status)
                try:
                    cs_token = cs_get_token()
                    token_time = time.time()
                    stream_url_base, stream_token, refresh_url = cs_get_stream(cs_token)
                    last_refresh = time.time()
                    stream_url = stream_url_base + (f"&offset={offset}" if offset > 0 else "")
                    log.info("Re-established stream at offset %d", offset)
                except Exception as reauth_err:
                    log.error("Re-auth failed: %s — retrying in 60s", reauth_err)
                    time.sleep(60)
            else:
                log.error("HTTP error %d: %s — retrying in 60s", status, e)
                time.sleep(60)
        except Exception as e:
            log.error("Unexpected error: %s — retrying in 60s", e)
            time.sleep(60)

    save_offset(offset)
    log.info("Forwarder stopped. Last offset: %d", offset)


if __name__ == "__main__":
    log.info("CrowdStrike → Splunk forwarder starting")
    log.info("Filtering for: %s", ", ".join(sorted(PRIORITY_EVENT_TYPES)))
    stream_events()
