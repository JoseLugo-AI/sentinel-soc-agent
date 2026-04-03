# Splunk SPL Queries — Sentinel SOC Agent

> **Query File Contract:**
> This file defines the detection queries that the Sentinel agent runs during each heartbeat cycle.
> Each rule is a level-2 heading (`## Rule Name`) followed by a description, a fenced SPL code block,
> severity guidance, and false positive notes.
>
> The headings in this file are referenced by `CLAUDE.md` (Phase 1: Collect). Community contributors
> can create alternative query files for other SIEMs — e.g., `elastic.md`, `wazuh.md`, `sigma.md` —
> using the **same headings**. The agent loads whichever query file matches the configured SIEM backend.
>
> **Template variables:**
> - `${CUSTOMER_DATA_PATH}` — Path to the protected customer/client data directory (e.g., `C:\Data\Clients`)
> - `${CUSTOMER_DATA_KEYWORDS}` — Pipe-separated list of customer data filename patterns (default: `kunden|client|vertrag|rechnung|invoice|contract|DPIA|ROPA`)

---

## Process Creation

Captures all new process creation events from Sysmon. This is the foundation for detecting suspicious parent-child relationships, credential theft tools, and living-off-the-land binaries.

```spl
index=sysmon EventCode=1
| fields Image, ParentImage, CommandLine, User, ProcessId, _time
```

**Severity guidance:** Varies by context. Instant CRITICAL for known credential theft tools (mimikatz, procdump, lazagne, secretsdump, rubeus). HIGH for suspicious parent-child chains (e.g., `explorer.exe` -> `powershell.exe` with encoded commands). LOW for baseline processes.

**False positives:**
- `wsl.exe` -> `powershell.exe` -> `npm/git/node/python/code` is normal AI agent / dev activity
- `powershell.exe` spawned by `wsl.exe` with `-Command` flags is Claude executing Windows commands
- Splunk processes (`splunkd.exe`, `Sysmon64.exe`) are expected

---

## Network Connections

Captures outbound network connections logged by Sysmon. Used to detect C2 callbacks, data exfiltration, and connections to suspicious IPs/ports.

```spl
index=sysmon EventCode=3
| fields Image, DestinationIp, DestinationPort, SourceIp, _time
```

**Severity guidance:** CRITICAL for connections to known C2 ports (4444, 5555, 6666, 1337, 8888, 9001, 9999, 12345, 31337). HIGH for unknown external IPs on unusual ports. Enrich suspicious IPs with VirusTotal and GreyNoise before escalating.

**False positives:**
- Traffic to `api.anthropic.com`, `github.com`, `npmjs.org`, `registry.npmjs.org` on port 443
- Chrome/Edge on ports 443, 80, 53 (normal browsing)
- Internal traffic on local mission control ports (3000, 18789, 18791, 18792)

---

## File Creation

Captures all file creation events from Sysmon. Used to detect suspicious file drops, malware staging, and unauthorized data movement.

```spl
index=sysmon EventCode=11
| fields Image, TargetFilename, User, _time
```

**Severity guidance:** HIGH if file is created in temp/staging directories with customer data patterns. CRITICAL if file is dropped by a suspicious process or contains executable content in user directories.

**False positives:**
- Normal application temp files created and deleted within seconds
- OneDrive sync operations (authorized backup)
- IDE and build tool artifacts

---

## GDPR File Access Check

Monitors Windows Security audit events for access to the protected customer data directory. This is the primary GDPR tripwire.

```spl
index=wineventlog EventCode=4663
    (ObjectName="*${CUSTOMER_DATA_PATH}*")
| table _time, SubjectUserName, ProcessName, ObjectName, AccessMask
```

**Severity guidance:** Always HIGH minimum. CRITICAL if the accessing process is not in the authorized whitelist. Any unauthorized read of customer data is a potential GDPR Article 33 reportable incident.

**False positives:**
- The operator manually browsing files in Explorer (`explorer.exe`)
- Authorized AI agents processing customer documents via `wsl.exe`
- OneDrive sync processes (`OneDrive.exe`, `Microsoft.SharePoint.exe`) — authorized backup
- Endpoint protection agents scanning files

**Configuration note:** Replace `${CUSTOMER_DATA_PATH}` with your actual customer data directory. If you use multiple paths (e.g., local + cloud sync), add additional `ObjectName` clauses with OR.

---

## Customer Data Outside Secure Directory

Detects customer data files being created anywhere outside the designated secure directory. Uses filename keyword patterns to identify customer data regardless of location.

```spl
index=sysmon EventCode=11
    (TargetFilename="*kunden*" OR TargetFilename="*client*" OR TargetFilename="*vertrag*"
     OR TargetFilename="*rechnung*" OR TargetFilename="*invoice*" OR TargetFilename="*contract*"
     OR TargetFilename="*DPIA*" OR TargetFilename="*ROPA*")
    NOT TargetFilename="*${CUSTOMER_DATA_PATH}*"
    NOT TargetFilename="*splunk*"
```

**Severity guidance:** HIGH — customer data created outside the secure directory is always suspicious. Escalate to CRITICAL if the creating process is not authorized or if the destination is a removable/network path.

**False positives:**
- Splunk indexing its own data (excluded via `NOT *splunk*`)
- Template or sample files that happen to match keywords but contain no real PII
- Application logs that mention customer-related terms without containing actual data

**Configuration note:** Replace the keyword list with `${CUSTOMER_DATA_KEYWORDS}` appropriate for your environment. German terms (`kunden`, `vertrag`, `rechnung`) and English terms (`client`, `invoice`, `contract`) are included by default for bilingual environments. Add industry-specific terms as needed.

---

## Failed Logins

Monitors Windows Security events for failed authentication attempts. Detects brute force attacks, credential stuffing, and unauthorized access attempts.

```spl
index=wineventlog EventCode=4625
| stats count by TargetUserName, LogonType, _time
```

**Severity guidance:** MEDIUM for isolated failures (typos happen). HIGH for 5+ failures within 10 minutes against the same account. CRITICAL for 10+ failures or failures against multiple accounts (suggests automated attack).

**False positives:**
- NTLM auth failures from legacy services
- Schannel errors from certificate mismatches
- Locked-out service accounts retrying

**Logon type reference:**
- Type 2: Interactive (console)
- Type 3: Network (SMB, mapped drives)
- Type 7: Unlock
- Type 10: RemoteInteractive (RDP)
- Type 11: CachedInteractive

---

## CrowdStrike Falcon Alerts

*Optional — requires CrowdStrike Falcon with Splunk forwarder configured.*

Captures detection and incident events from CrowdStrike Falcon endpoint protection. These are pre-triaged by CrowdStrike's ML engine so they typically warrant immediate attention.

```spl
index=sysmon sourcetype="crowdstrike:falcon:event"
| spath event.metadata.eventType
| search event.metadata.eventType IN ("DetectionSummaryEvent", "IncidentSummaryEvent", "FirewallMatchEvent")
| table _time, event.metadata.eventType, event.event.*
```

**Severity guidance:** Map CrowdStrike severity directly — CrowdStrike Critical = Sentinel CRITICAL, CrowdStrike High = Sentinel HIGH. DetectionSummaryEvent is always HIGH minimum. IncidentSummaryEvent is always CRITICAL.

**False positives:**
- Low-confidence detections on known admin tools (PsExec used legitimately, etc.)
- Firewall match events for normal outbound traffic

---

## CrowdStrike Sensor Health

*Optional — requires CrowdStrike Falcon with Splunk forwarder configured.*

Monitors CrowdStrike sensor heartbeat. If no events are received within the expected interval, the sensor or forwarder may be down — which is itself a security concern (an attacker may have disabled endpoint protection).

```spl
index=sysmon sourcetype="crowdstrike:falcon:event"
    event.metadata.eventType="AuthActivityAuditEvent"
| stats latest(_time) as last_seen
| where last_seen < relative_time(now(), "-1h")
```

**Severity guidance:** HIGH if sensor is silent for 1+ hours during business hours. CRITICAL if silent for 2+ hours or if silence coincides with other suspicious activity (potential EDR evasion).

**False positives:**
- Planned maintenance windows
- System reboots (sensor takes a few minutes to reconnect)
- Splunk forwarder restart (brief gap in events)
