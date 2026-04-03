# GDPR Incident Response Plan

**[YOUR_BUSINESS]**
**Freiberufler / Sole Proprietor**
[YOUR_CITY], [YOUR_COUNTRY]

| Field | Value |
|-------|-------|
| Document Owner | [YOUR_NAME] |
| Version | 1.0 |
| Classification | INTERNAL -- CONFIDENTIAL |
| Effective Date | [DATE] |
| Next Review | [NEXT_REVIEW_DATE] (quarterly) |
| Legal Basis | GDPR Art. 33, Art. 34, Art. 5(1)(f) |

---

## 1. Purpose & Scope

### 1.1 Purpose

This plan establishes binding procedures for detecting, responding to, containing, and reporting personal data breaches and security incidents affecting [YOUR_BUSINESS]. It ensures compliance with GDPR Articles 33 and 34 and the accountability principle under Article 5(2).

### 1.2 Scope

This plan applies to:

- **All personal data** processed by [YOUR_BUSINESS], including client personal data, prospect data, and business contact information.
- **All processing environments:**
  - Windows 11 workstation (user: `[WINDOWS_USERNAME]`)
  - WSL2 Ubuntu environment (user: `[WSL_USERNAME]`)
  - Customer data directory: `C:\Users\[WINDOWS_USERNAME]\Desktop\Work` (migrating to OneDrive with BitLocker)
  - Cloud services: GitHub, Cloudflare Pages, Microsoft 365
  - AI agent infrastructure: [YOUR_AGENTS] (e.g., development agent, Sentinel SOC monitoring, strategy, content, intelligence)
  - Splunk Enterprise (local SIEM)
  - Communication channels: ntfy.sh, email, phone

### 1.3 Roles

| Role | Person | Contact |
|------|--------|---------|
| Data Controller / Incident Lead | [YOUR_NAME] | [YOUR_EMAIL] |
| Automated Detection | Sentinel (AI SOC Agent) | ntfy topic: `[YOUR_NTFY_TOPIC]` |
| Evidence Repository | Splunk Enterprise + triage.jsonl | localhost:8089 |

As a solo Freiberufler, [YOUR_NAME] is both the data controller and the sole incident responder. Sentinel, the AI SOC agent, serves as the automated detection and first-triage layer but cannot make legal decisions regarding breach notification.

---

## 2. Incident Classification

### 2.1 Security Incident vs. Personal Data Breach

| Term | Definition |
|------|------------|
| **Security Incident** | Any event that compromises the confidentiality, integrity, or availability of information systems. Not all security incidents are personal data breaches. |
| **Personal Data Breach** (GDPR Art. 4(12)) | A breach of security leading to the accidental or unlawful destruction, loss, alteration, unauthorized disclosure of, or access to, personal data transmitted, stored, or otherwise processed. |

A security incident becomes a notifiable personal data breach when personal data is confirmed or reasonably believed to have been compromised.

### 2.2 Severity Levels

These levels align with Sentinel's automated triage scoring.

#### CRITICAL (Score 80--100)

Confirmed or highly likely personal data breach requiring immediate action and probable supervisory authority notification.

**Examples:**
- Credential theft tools detected (mimikatz, procdump, lazagne, secretsdump)
- Customer data exfiltrated to USB, network share, or external IP
- Reverse shell or C2 connection established on the workstation
- Executable launched from within the customer data directory (`C:\Users\[WINDOWS_USERNAME]\Desktop\Work`)
- Ransomware indicators (mass file encryption in Work directory)

#### HIGH (Score 50--79)

Suspicious activity involving personal data that requires immediate investigation. May escalate to CRITICAL.

**Examples:**
- Unauthorized process reading customer data directory
- Customer data file patterns (kunden, client, vertrag, rechnung, invoice, contract, DPIA, ROPA) created outside the Work directory
- 50+ file access events in Work directory within 5 minutes (enumeration)
- Customer data appearing in browser cache or temp directories
- Failed login brute force (10+ EventCode 4625 in 5 minutes)

#### MEDIUM (Score 20--49)

Anomalous activity that does not directly involve personal data but warrants documentation and review.

**Examples:**
- Unknown process with no baseline match spawning child processes
- Outbound connection to unusual port from a known process
- Customer data file deletion by authorized process (potential accidental loss)
- PowerShell execution with encoded commands during business hours

#### LOW (Score 0--19)

Routine anomalies explained by normal operations. Logged but not escalated.

**Examples:**
- Claude Code spawning expected PowerShell/npm/git processes
- Splunk or Sysmon self-activity
- Normal browser connections on ports 80/443
- Baseline process operating within expected parameters

---

## 3. Detection

### 3.1 Detection Sources

| Source | Mechanism | Frequency |
|--------|-----------|-----------|
| Sentinel AI Agent | Automated Splunk queries + AI reasoning | Every 30 minutes (cron) |
| Splunk Saved Alerts | Threshold-based alerts on critical SPL queries | Real-time / scheduled |
| Manual Observation | [YOUR_NAME] notices unusual behavior | Ad hoc |
| External Notification | Client, partner, or third party reports an incident | Ad hoc |

### 3.2 Sentinel Heartbeat Queries (10 Detection Sources)

Sentinel executes the following SPL queries every 30 minutes:

| # | Query Target | Sysmon/WinEvent Code | Purpose |
|---|-------------|---------------------|---------|
| 1 | Process creation | EventCode=1 (Sysmon) | Detect unauthorized or suspicious process execution |
| 2 | Network connections | EventCode=3 (Sysmon) | Detect outbound connections to unknown IPs/ports |
| 3 | File creation | EventCode=11 (Sysmon) | Detect files created in suspicious locations |
| 4 | GDPR file access audit | EventCode=4663 (WinEventLog) | Monitor access to `C:\Users\[WINDOWS_USERNAME]\Desktop\Work` |
| 5 | Customer data outside Work | EventCode=11 (Sysmon) | Detect customer data patterns in unauthorized locations |
| 6 | Failed logins | EventCode=4625 (WinEventLog) | Detect brute force or credential stuffing |
| 7 | DNS queries | EventCode=22 (Sysmon) | Detect DNS to known malicious domains |
| 8 | Registry modifications | EventCode=13 (Sysmon) | Detect persistence mechanisms |
| 9 | File deletion | EventCode=23 (Sysmon) | Detect anti-forensics or data destruction |
| 10 | Process termination | EventCode=5 (Sysmon) | Detect security tool tampering |

### 3.3 GDPR-Specific Monitoring Rules

The following seven rules from Sentinel's GDPR rule set trigger automatic escalation:

| Rule | Trigger | Default Severity |
|------|---------|-----------------|
| Rule 1: Unauthorized Customer Data Read | Non-whitelisted process reads from Work directory | CRITICAL |
| Rule 2: Customer Data in Suspicious Location | Customer data indicators in Desktop, Temp, AppData, Downloads | HIGH / CRITICAL |
| Rule 3: Customer Data Copy to USB/Network | File copy with customer data pattern to removable or network storage | CRITICAL |
| Rule 4: Bulk Access to Customer Data | 50+ file access events in Work directory within 5 minutes | HIGH |
| Rule 5: Execution from Customer Data Directory | Any executable launched with parent in Work directory | CRITICAL |
| Rule 6: Customer Data in Browser Cache | Customer data file in Chrome/Edge cache or temp | HIGH |
| Rule 7: Customer Data Deletion | Customer data file deleted (potential anti-forensics) | MEDIUM / HIGH |

### 3.4 Enrichment Tools

When Sentinel detects a suspicious event, it enriches the finding using:

| Tool | Purpose |
|------|---------|
| VirusTotal | Check IP reputation, file hashes, URL/domain reputation |
| GreyNoise | Determine if an IP is mass-scanning or targeted |
| CVE Intel (NVD/CISA KEV/EPSS) | Look up referenced vulnerabilities |
| Process tree analysis | Reconstruct parent-child execution chain |
| Baseline comparison | Check against known-good process behavior |
| Triage history | Check triage.jsonl for prior false positives |

---

## 4. Response Timeline

All times are measured from the moment of detection. This timeline satisfies GDPR Art. 33(1), which requires notification to the supervisory authority "without undue delay and, where feasible, not later than 72 hours."

### Phase 1: Immediate Containment (0--1 hour)

| Step | Action | Responsible |
|------|--------|-------------|
| 1 | Sentinel sends CRITICAL/HIGH alert to phone via ntfy | Sentinel (automated) |
| 2 | Acknowledge the alert | [YOUR_NAME] |
| 3 | Isolate the affected process: kill PID, disable network adapter if needed | [YOUR_NAME] |
| 4 | Verify containment: confirm the threat process is terminated and no child processes persist | [YOUR_NAME] |
| 5 | Take initial screenshot/notes of the alert and Splunk dashboard | [YOUR_NAME] |
| 6 | If customer data confirmed involved: assume notifiable breach until proven otherwise | [YOUR_NAME] |

### Phase 2: Assessment & Evidence Preservation (1--4 hours)

| Step | Action | Responsible |
|------|--------|-------------|
| 7 | Export relevant Splunk events to CSV (see Section 8) | [YOUR_NAME] |
| 8 | Preserve triage.jsonl snapshot (copy with timestamp) | [YOUR_NAME] |
| 9 | Determine: Was personal data actually accessed, exfiltrated, altered, or destroyed? | [YOUR_NAME] |
| 10 | Identify categories and approximate number of affected data subjects | [YOUR_NAME] |
| 11 | Identify categories of personal data records affected | [YOUR_NAME] |
| 12 | Document initial findings in incident log (see template in Section 8.3) | [YOUR_NAME] |

### Phase 3: Full Investigation (4--24 hours)

| Step | Action | Responsible |
|------|--------|-------------|
| 13 | Full process tree reconstruction from Sysmon logs | [YOUR_NAME] + Sentinel |
| 14 | Network connection analysis: where did data go? | [YOUR_NAME] + Sentinel |
| 15 | VirusTotal/GreyNoise enrichment of all suspicious IPs, hashes, domains | Sentinel |
| 16 | Determine root cause and attack vector | [YOUR_NAME] |
| 17 | Assess risk to data subjects (likelihood and severity of impact) | [YOUR_NAME] |
| 18 | Decision: Is this a notifiable breach under Art. 33? | [YOUR_NAME] |
| 19 | Decision: Is this likely to result in high risk to data subjects (Art. 34)? | [YOUR_NAME] |

**Art. 33 notification is NOT required if:** the breach is unlikely to result in a risk to the rights and freedoms of natural persons. Document the reasoning if you decide not to notify.

### Phase 4: Supervisory Authority Notification (24--72 hours)

| Step | Action | Responsible |
|------|--------|-------------|
| 20 | Complete supervisory authority notification form (see Section 6.1) | [YOUR_NAME] |
| 21 | Submit to [YOUR_DPA] via online portal or email | [YOUR_NAME] |
| 22 | If full details are not yet available: submit preliminary notification and supplement later (Art. 33(4)) | [YOUR_NAME] |
| 23 | Log notification timestamp and reference number | [YOUR_NAME] |

### Phase 5: Data Subject Notification (72+ hours, if required)

| Step | Action | Responsible |
|------|--------|-------------|
| 24 | Determine if Art. 34 notification is required (high risk to rights and freedoms) | [YOUR_NAME] |
| 25 | Prepare data subject notification (see Section 6.2) | [YOUR_NAME] |
| 26 | Send notification to affected data subjects without undue delay | [YOUR_NAME] |
| 27 | Document all communications | [YOUR_NAME] |

**Art. 34 notification is NOT required if:**
- (a) Appropriate technical/organizational measures were applied (e.g., encryption) making data unintelligible
- (b) Subsequent measures ensure the high risk is no longer likely to materialize
- (c) It would involve disproportionate effort (use public communication instead)

---

## 5. Containment Procedures

### 5.1 Process Isolation

```powershell
# From WSL2, kill a Windows process by PID
powershell.exe -Command "Stop-Process -Id <PID> -Force"

# Kill by process name
powershell.exe -Command "Stop-Process -Name '<ProcessName>' -Force"

# Verify termination
powershell.exe -Command "Get-Process -Id <PID> -ErrorAction SilentlyContinue"
```

### 5.2 Network Isolation

```powershell
# Disable all network adapters (nuclear option)
powershell.exe -Command "Get-NetAdapter | Disable-NetAdapter -Confirm:$false"

# Block a specific outbound IP via Windows Firewall
powershell.exe -Command "New-NetFirewallRule -DisplayName 'Block Suspicious IP' -Direction Outbound -RemoteAddress <IP> -Action Block"

# Re-enable network after containment
powershell.exe -Command "Get-NetAdapter | Enable-NetAdapter -Confirm:$false"
```

### 5.3 Account Lockdown

```powershell
# Disable local account
powershell.exe -Command "Disable-LocalUser -Name '<Username>'"

# Force sign-out of all sessions
powershell.exe -Command "logoff <SessionID>"

# Change password immediately
powershell.exe -Command "Set-LocalUser -Name '[WINDOWS_USERNAME]' -Password (Read-Host -AsSecureString)"
```

### 5.4 Evidence Preservation (Immediate)

Before taking any remediation action that could destroy evidence:

1. **Export Splunk logs** (see Section 8)
2. **Copy triage.jsonl**: `cp ~/sentinel/triage.jsonl ~/sentinel/evidence/triage_$(date +%Y%m%d_%H%M%S).jsonl`
3. **Capture running processes**: `powershell.exe -Command "Get-Process | Export-Csv C:\Users\[WINDOWS_USERNAME]\Desktop\evidence_processes_$(Get-Date -Format yyyyMMdd_HHmmss).csv"`
4. **Capture network connections**: `powershell.exe -Command "Get-NetTCPConnection | Export-Csv C:\Users\[WINDOWS_USERNAME]\Desktop\evidence_connections_$(Get-Date -Format yyyyMMdd_HHmmss).csv"`
5. **Screenshot Splunk dashboard** via browser or Sentinel screenshot tool

---

## 6. Notification Templates

### 6.1 Supervisory Authority Notification (Art. 33)

This template contains all fields required by GDPR Art. 33(3). Adapt the language to match your supervisory authority's requirements.

---

**NOTIFICATION OF A PERSONAL DATA BREACH**
**pursuant to Art. 33 GDPR**

**To:**
[YOUR_DPA]
[YOUR_DPA_ADDRESS]
Email: [YOUR_DPA_EMAIL]
Online reporting: [YOUR_DPA_REPORTING_URL]

---

**1. Controller Details**

| Field | Value |
|-------|-------|
| Controller name | [YOUR_BUSINESS] |
| Address | [YOUR_ADDRESS] |
| Contact person | [YOUR_NAME] |
| Telephone | [YOUR_PHONE] |
| Email | [YOUR_EMAIL] |
| Data Protection Officer (DPO) | Not appointed (not required as sole proprietor) |

---

**2. Timeline**

| Field | Value |
|-------|-------|
| Date and time breach was discovered | ____-__-__ at __:__ |
| Date and time of the incident (if known) | ____-__-__ at __:__ |
| How was the breach discovered? | [ ] Sentinel SOC Agent (automated detection) / [ ] Manual observation / [ ] Third-party report / [ ] Other: __________ |

---

**3. Nature of the Breach**

| Type | Applicable? |
|------|-------------|
| Confidentiality breach (unauthorized access) | [ ] Yes / [ ] No |
| Integrity breach (unauthorized alteration) | [ ] Yes / [ ] No |
| Availability breach (data loss) | [ ] Yes / [ ] No |

**Incident Description:**

> _____________________________________________________________________________
> _____________________________________________________________________________
> _____________________________________________________________________________
> _____________________________________________________________________________

---

**4. Categories and Numbers Affected**

**4a. Categories and approximate number of affected individuals:**

| Category | Approximate Number |
|----------|-------------------|
| Clients | __________ |
| Client employees | __________ |
| Business contacts / prospects | __________ |
| Other: __________ | __________ |
| **Total** | __________ |

**4b. Categories and approximate number of affected data records:**

| Data Category | Approximate Number |
|---------------|-------------------|
| Name, address, contact details | __________ |
| Contract data | __________ |
| Invoice data | __________ |
| Tax data | __________ |
| DPIA / ROPA documents | __________ |
| Other: __________ | __________ |
| **Total** | __________ |

---

**5. Likely Consequences**

> _____________________________________________________________________________
> _____________________________________________________________________________
> _____________________________________________________________________________

**Risk Assessment:**

| Risk Level | Justification |
|------------|---------------|
| [ ] No risk | __________ |
| [ ] Risk | __________ |
| [ ] High risk (Art. 34 notification required) | __________ |

---

**6. Measures Taken / Proposed**

**Immediate measures taken:**

> - [ ] Affected process terminated (PID: __________)
> - [ ] Network isolated
> - [ ] Account locked
> - [ ] Evidence preserved
> - [ ] Other: __________

**Proposed measures:**

> - [ ] Password change for all affected accounts
> - [ ] Additional monitoring rules in Sentinel/Splunk
> - [ ] Review and update DPIA
> - [ ] Training / awareness
> - [ ] Other: __________

---

**7. Preliminary Notification**

| Field | Value |
|-------|-------|
| Is this a preliminary notification? | [ ] Yes / [ ] No |
| If yes, when will full information be provided? | ____-__-__ |

---

**Date:** ____-__-__
**Signature:** ________________________
**[YOUR_NAME], Owner / [YOUR_BUSINESS]**

---

### 6.2 Data Subject Notification (Art. 34)

Use this template when the breach is likely to result in a **high risk** to the rights and freedoms of affected individuals.

---

**Subject: Notification of a Personal Data Breach**

Dear __________,

In accordance with Article 34 of the General Data Protection Regulation (GDPR), I am informing you that a personal data breach has occurred at [YOUR_BUSINESS] that is likely to result in a high risk to your rights and freedoms.

**What happened?**

On ____-__-__ at approximately __:__, it was discovered that:

> _____________________________________________________________________________
> _____________________________________________________________________________

**What data was affected?**

> _____________________________________________________________________________

**What are the possible consequences?**

> _____________________________________________________________________________

**What measures have been taken?**

> _____________________________________________________________________________

**What can you do?**

> - _____________________________________________________________________________
> - _____________________________________________________________________________

**Contact for questions:**

[YOUR_NAME]
Email: [YOUR_EMAIL]
Phone: [YOUR_PHONE]

I regret this incident and am available for further information.

Sincerely,
[YOUR_NAME]
[YOUR_BUSINESS]

---

## 7. Supervisory Authority Contact

| Field | Details |
|-------|---------|
| Authority | [YOUR_DPA] |
| Jurisdiction | [YOUR_DPA_JURISDICTION] |
| Address | [YOUR_DPA_ADDRESS] |
| Telephone | [YOUR_DPA_PHONE] |
| Email | [YOUR_DPA_EMAIL] |
| Online Reporting | [YOUR_DPA_REPORTING_URL] |
| Data Breach Form | [YOUR_DPA_BREACH_FORM_URL] |
| Website | [YOUR_DPA_URL] |

**Notification deadline:** Without undue delay, not later than **72 hours** after becoming aware of the breach (Art. 33(1) GDPR).

**Note:** If notification is made after 72 hours, reasons for the delay must be provided (Art. 33(1) sentence 2).

---

## 8. Evidence Preservation

### 8.1 What to Preserve

| Evidence Type | Location | Preservation Method |
|--------------|----------|-------------------|
| Splunk event logs | localhost:8089 | Export to CSV (see 8.2) |
| Sentinel triage log | `~/sentinel/triage.jsonl` | Timestamped copy |
| Process trees | Sysmon EventCode=1 in Splunk | SPL export |
| Network connections | Sysmon EventCode=3 in Splunk | SPL export |
| File access audit logs | WinEventLog EventCode=4663 | SPL export |
| Running process snapshot | Live Windows system | `Get-Process` export |
| Network connection snapshot | Live Windows system | `Get-NetTCPConnection` export |
| Screenshots | Splunk dashboard / Sentinel alerts | PNG files with timestamps |
| Sentinel baseline | `~/sentinel/baseline.csv` | Copy for comparison |
| GDPR rules state | `~/sentinel/gdpr-rules.md` | Copy |

### 8.2 How to Export from Splunk

```bash
# From WSL2, export Splunk events for a time range via REST API
SPLUNK_PASS=$(cat ~/.splunk_pass)

# Export Sysmon process events for the incident window
curl -k -u admin:"$SPLUNK_PASS" \
  https://[YOUR_SPLUNK_IP]:8089/services/search/jobs/export \
  --data-urlencode "search=search index=sysmon earliest=\"YYYY-MM-DDThh:mm:ss\" latest=\"YYYY-MM-DDThh:mm:ss\"" \
  -d output_mode=csv \
  > ~/sentinel/evidence/splunk_export_$(date +%Y%m%d_%H%M%S).csv

# Export GDPR file access events
curl -k -u admin:"$SPLUNK_PASS" \
  https://[YOUR_SPLUNK_IP]:8089/services/search/jobs/export \
  --data-urlencode "search=search index=wineventlog EventCode=4663 ObjectName=\"*Desktop\\Work*\" earliest=\"YYYY-MM-DDThh:mm:ss\" latest=\"YYYY-MM-DDThh:mm:ss\"" \
  -d output_mode=csv \
  > ~/sentinel/evidence/gdpr_access_$(date +%Y%m%d_%H%M%S).csv
```

**Important:** Replace the `earliest` and `latest` timestamps with the actual incident window. Never include the Splunk password in any evidence file or notification.

### 8.3 Chain of Custody Documentation

For each piece of evidence, record:

| Field | Value |
|-------|-------|
| Evidence ID | INC-____-____ (e.g., INC-2026-0001-E01) |
| Description | __________ |
| Source | __________ |
| Collection timestamp (UTC) | ____-__-__T__:__:__Z |
| Collected by | [YOUR_NAME] |
| SHA-256 hash of file | __________ |
| Storage location | __________ |
| Access log | __________ |

```bash
# Generate SHA-256 hash for evidence files
sha256sum ~/sentinel/evidence/<filename>
```

### 8.4 Evidence Directory Setup

```bash
mkdir -p ~/sentinel/evidence
chmod 700 ~/sentinel/evidence
```

All evidence files should be stored in `~/sentinel/evidence/` with restricted permissions. Evidence must be retained for a minimum of **3 years** (or longer if legal proceedings are anticipated).

---

## 9. Post-Incident

### 9.1 Lessons Learned

Within **7 days** of incident closure, document:

1. **Root cause:** What vulnerability, misconfiguration, or human error caused the incident?
2. **Detection effectiveness:** How long between the incident and detection? Could Sentinel have caught it earlier?
3. **Response effectiveness:** Were the containment steps adequate? What could be improved?
4. **Gap analysis:** What monitoring rule, baseline entry, or procedure was missing?
5. **Remediation verification:** Has the root cause been fully addressed?

### 9.2 Sentinel Updates

After each incident:

- **Update `baseline.csv`** if new legitimate processes or behaviors were identified.
- **Update `gdpr-rules.md`** if new detection patterns were discovered.
- **Review and retune Splunk alerts** based on false positive/negative findings.
- **Update `triage.jsonl`** with final incident disposition and mark any false positives explicitly.
- **Adjust severity scoring** if the incident revealed miscalibration.

### 9.3 DPIA Revision

If the incident involved customer data or revealed a new risk to data subjects:

- Review and update the relevant Data Protection Impact Assessment.
- Document the incident as a realized risk in the DPIA risk register.
- Re-evaluate residual risk levels and update mitigation measures.

### 9.4 Client Communication

If a client's personal data was affected:

1. Notify the client **promptly and transparently**, separate from and in addition to any Art. 34 data subject notification.
2. Provide a factual summary: what happened, what data, what measures taken.
3. Offer to answer questions and provide support.
4. Document all client communications in the incident file.
5. If the client is a controller and you are processing data on their behalf (processor role): notify the client "without undue delay" per Art. 33(2) -- this may be faster than the 72-hour supervisory authority deadline.

---

## 10. Annual Testing & Maintenance

### 10.1 Quarterly Plan Review

Every **3 months**, review this plan for:

- [ ] Contact details still accurate (supervisory authority, your phone/email)
- [ ] Sentinel detection rules still aligned with current infrastructure
- [ ] Baseline.csv reflects current known-good processes
- [ ] Cloud services and AI agents list is current
- [ ] Notification templates still match supervisory authority requirements

### 10.2 Annual Tabletop Exercise

Once per year, conduct a tabletop exercise simulating a personal data breach:

**Scenario examples:**
- A malicious document opened from the Work folder launches PowerShell and exfiltrates client contracts to an external IP.
- Sentinel detects 200+ file access events in the Work directory from an unknown process at 03:00.
- A client reports that their contract data appeared on a paste site.
- Ransomware encrypts the Work directory and demands payment.

**Exercise checklist:**
- [ ] Sentinel detects the simulated event correctly
- [ ] ntfy notification arrives on your phone within 2 minutes
- [ ] You can locate and follow this incident response plan
- [ ] Supervisory authority notification template can be completed within 1 hour
- [ ] Evidence preservation steps are executed correctly
- [ ] Full timeline from detection to (simulated) notification under 72 hours

### 10.3 Sentinel False Positive Review

Monthly, review `triage.jsonl` for:

- Events that were escalated but turned out to be legitimate (add to baseline)
- Events that were suppressed but later found to be suspicious (tighten rules)
- Patterns that generate excessive noise (tune Splunk queries)
- New processes or services that need baseline entries

### 10.4 Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [DATE] | [YOUR_NAME] / Sentinel | Initial version |

---

## Appendix A: Quick Reference Card

**Print this page and keep it accessible.**

```
=============================================
  INCIDENT RESPONSE QUICK REFERENCE
  [YOUR_BUSINESS]
=============================================

1. CONTAIN
   - Kill suspicious process: Stop-Process -Id <PID> -Force
   - Isolate network if needed: Disable-NetAdapter

2. PRESERVE EVIDENCE
   - Export Splunk logs (see Section 8.2)
   - Copy triage.jsonl with timestamp
   - Screenshot everything

3. ASSESS
   - Was personal data accessed/exfiltrated?
   - How many data subjects affected?
   - What categories of data?

4. DECIDE: NOTIFY?
   - Risk to data subjects? --> YES: Notify [YOUR_DPA] within 72h
   - High risk? --> YES: Also notify data subjects (Art. 34)
   - No risk? --> Document reasoning, do NOT notify

5. NOTIFY [YOUR_DPA] (if required)
   - Online: [YOUR_DPA_REPORTING_URL]
   - Email: [YOUR_DPA_EMAIL]
   - Phone: [YOUR_DPA_PHONE]
   - DEADLINE: 72 HOURS from awareness

6. LOG EVERYTHING
   - ~/sentinel/evidence/
   - triage.jsonl
   - Chain of custody for all evidence files
=============================================
```

---

## Appendix B: Legal References

| Reference | Summary |
|-----------|---------|
| GDPR Art. 4(12) | Definition of personal data breach |
| GDPR Art. 5(1)(f) | Integrity and confidentiality principle |
| GDPR Art. 5(2) | Accountability principle |
| GDPR Art. 24 | Responsibility of the controller |
| GDPR Art. 32 | Security of processing |
| GDPR Art. 33 | Notification of breach to supervisory authority |
| GDPR Art. 34 | Communication of breach to data subject |
| GDPR Art. 83(4)(a) | Fines for Art. 33/34 violations: up to 10M EUR or 2% annual turnover |
| BDSG Section 42 | German criminal penalties for intentional data breaches |

---

**END OF DOCUMENT**

*This plan is a living document. It must be reviewed quarterly and updated whenever there is a material change to infrastructure, processing activities, or regulatory requirements.*
