# GDPR Monitoring Rules - Sentinel SOC Analyst

**Purpose:** Trigger immediate CRITICAL escalation when customer data is at risk.

**Principle:** Customer data (PII, invoices, contracts, SSN, email, phone) must be:
1. Read only by authorized processes (authorized AI agents, the operator's explicit action)
2. Written only to secure, documented directories
3. Never copied to USB, network shares, or external storage
4. Never accessed by browsers or unauthorized processes

---

## Rule 1: Unauthorized Customer Data Read

**Splunk Query:**
```spl
index=wineventlog EventCode=4663 ObjectName="*customer_data*"
| where NOT (ProcessName="*wsl.exe*" OR ProcessName="*claude*" OR ProcessName="*authorized*")
| stats count by ProcessName, SubjectUserName, ObjectName, AccessList, _time
| where count > 0
```

**Trigger:** Any file read from `${CUSTOMER_DATA_PATH}` by process NOT in whitelist

**Severity:** CRITICAL

**Example:**
- Process: `chrome.exe`
- File: `${CUSTOMER_DATA_PATH}\clients.xlsx`
- Action: Immediate notification channel + ntfy escalation

**Investigation Questions:**
1. Why did browser access customer data?
2. Was this the operator testing the security?
3. Are customer files stored in wrong location?

---

## Rule 2: Customer Data File Creation in Suspicious Location

**Splunk Query:**
```spl
index=sysmon EventCode=11 
(TargetFilename LIKE "*Desktop*" OR TargetFilename LIKE "*temp*" OR TargetFilename LIKE "*AppData*" OR TargetFilename LIKE "*Downloads*" OR TargetFilename LIKE "*USB*")
| search TargetFilename REGEX="(ssn|phone|email|pid|customer|invoice|contract|pii)"i
| fields ProcessID, ProcessName, User, TargetFilename, _time
```

**Trigger:** Any file with customer data indicators created outside secure directories

**Severity:** HIGH -> CRITICAL (if process is not authorized)

**Example:**
- Process: `powershell.exe`
- File: `C:\Users\<user>\Desktop\customer_invoice_2024.xlsx` (customer data pattern)
- Action: Investigate context (was the operator deliberately testing? Is this authorized export?)

**Investigation Questions:**
1. Was this an intentional export by the operator?
2. Is the file still there? (If deleted quickly, might be legitimate copy operation)
3. Does the process have audit trail showing authorization?

---

## Rule 3: Customer Data Copy to USB/Network

**Splunk Query:**
```spl
index=sysmon EventCode=11 
(TargetFilename REGEX="\\\\Device\\\\HarddiskVolume.*USB" OR TargetFilename REGEX="\\\\\\\\[^\\\\]+\\\\[^\\\\]+")
| search TargetFilename REGEX="(ssn|customer|invoice|contract|pii)"i
| fields ProcessID, ProcessName, User, TargetFilename, TargetObject, _time
```

**Trigger:** Any file copy of customer data to USB drive or network share

**Severity:** CRITICAL (potential data exfiltration)

**Example:**
- Process: `explorer.exe`
- Destination: `\Device\HarddiskVolume\USB_DRIVE\customer_data.zip`
- Action: Immediate CRITICAL escalation + investigate data loss

**Investigation Questions:**
1. Is the USB drive the operator's backup device?
2. How much data was copied? (1 file vs bulk exfil?)
3. Was this authorized? Check with the operator immediately.

---

## Rule 4: Bulk Access to Customer Data Directory

**Splunk Query:**
```spl
index=wineventlog EventCode=4663 ObjectName="*customer_data*" 
| stats count as access_count by ProcessName, SubjectUserName, Action
| where access_count > 50
```

**Trigger:** 50+ file access events in customer data directory within 5-minute window

**Severity:** HIGH (suggests directory scanning/enumeration)

**Example:**
- Process: `cmd.exe`
- Accesses: 120 reads in 3 minutes
- Pattern: Suggests `dir /s` or similar enumeration
- Action: Investigate (could be malware scanning for sensitive files)

**Investigation Questions:**
1. Is this process authorized to enumerate customer data?
2. Does the command line show enumeration tools (dir, findstr, etc.)?
3. Is data being exfiltrated or just scanned?

---

## Rule 5: Suspicious Execution in Customer Data Directory

**Splunk Query:**
```spl
index=sysmon EventCode=1 ParentImage="*customer_data*"
| fields ProcessID, ProcessName, CommandLine, ParentImage, User, _time
```

**Trigger:** Any executable launched with parent process in customer data directory

**Severity:** CRITICAL (code execution from customer data = suspicious)

**Example:**
- Parent: `${CUSTOMER_DATA_PATH}\innocent.xlsx` (embedded macro)
- Child: `powershell.exe`
- Action: Immediate CRITICAL escalation (likely malware)

**Investigation Questions:**
1. Did the operator open a suspicious document?
2. Are there macros in customer data files?
3. Is this lateral movement or initial compromise?

---

## Rule 6: Customer Data in Browser Cache/History

**Splunk Query:**
```spl
index=sysmon EventCode=11 
(TargetFilename LIKE "*AppData*Local*Chrome*" OR TargetFilename LIKE "*AppData*Local*Microsoft*Edge*" OR TargetFilename LIKE "*Temp*")
| search TargetFilename REGEX="(customer|invoice|ssn|contract|pii)"i
| fields ProcessID, ProcessName, TargetFilename, User, _time
```

**Trigger:** Customer data file created in browser cache or temp directory

**Severity:** HIGH (potential browser-based exfiltration)

**Example:**
- File: `C:\Users\<user>\AppData\Local\Temp\customer_invoice.pdf`
- Browser: Chrome started reading the file
- Action: Investigate if browser uploaded data to cloud

**Investigation Questions:**
1. Is customer data being uploaded to cloud services?
2. Did the operator intentionally upload to email/cloud?
3. Is browser extension exfiltrating data?

---

## Rule 7: Customer Data File Deletion (Anti-Forensics)

**Splunk Query:**
```spl
index=sysmon EventCode=23 TargetFilename="*customer_data*"
| fields ProcessID, ProcessName, User, TargetFilename, _time
```

**Trigger:** Customer data file deleted

**Severity:** MEDIUM -> HIGH (if process is suspicious)

**Example:**
- File: `${CUSTOMER_DATA_PATH}\contracts.xlsx`
- Process: `cipher.exe` (Windows file wiping tool)
- Action: Investigate (could be evidence destruction)

**Investigation Questions:**
1. Is the operator legitimately deleting old customer data?
2. Is process trying to destroy forensic evidence?
3. Check file system for undeleted copies?

---

## False Positive Suppressions

**These should NOT trigger GDPR alerts:**

1. **Authorized AI agents reading customer data legitimately**
   - Process: `wsl.exe` (parent)
   - Child: `python`, `node` (running document processor)
   - File: Customer invoice being processed
   - **Suppress:** Mark as "authorized_process" in baseline

2. **The operator manually opening files in Explorer**
   - Process: `explorer.exe`
   - File: Manual file browse in customer_data directory
   - **Suppress:** Normal user activity

3. **Backup software**
   - Process: Scheduled backup agent
   - Action: Copying files to backup location (documented)
   - **Suppress:** Add backup process to whitelist

4. **Temporary file operations**
   - File: Temporary copy created during processing
   - Duration: File deleted within seconds
   - **Suppress:** Log but don't escalate

---

## Implementation Checklist

**Before deploying GDPR rules:**

- [ ] Define `customer_data` directory location(s) — set `${CUSTOMER_DATA_PATH}` in your config
- [ ] List authorized processes (AI agents, specific Python scripts)
- [ ] List authorized users (operator, service accounts)
- [ ] Whitelist legitimate backup/export tools
- [ ] Document customer data file patterns (SSN format, invoice naming, etc.)
- [ ] Test rules on historical data (check for false positives)
- [ ] Set up CRITICAL escalation routing (notification channel + ntfy)
- [ ] Brief the operator on what triggers escalation
- [ ] Create incident response playbook for data breach scenarios

---

## Incident Response Playbook

**If GDPR alert triggers:**

1. **Immediate (< 1 minute):**
   - The operator receives CRITICAL alert
   - Document timestamp, process, file, user
   - Take screenshot of Splunk event

2. **Investigation (< 15 minutes):**
   - Check if the operator authorized the access
   - If YES: Document and close (add to audit trail)
   - If NO: Continue investigation

3. **If Unauthorized:**
   - Check process parent chain (where did it come from?)
   - Check if data was copied/exfiltrated (network logs)
   - Isolate process if malicious (kill PID)
   - Check file modification times (was data stolen?)

4. **Reporting:**
   - Log full incident to incident log
   - Document response timeline
   - Archive evidence (Splunk logs, screenshots)
   - Assess if GDPR breach notification needed

---

## Tuning Over Time

**Week 1-2:** Expect false positives
- Adjust whitelist as you learn normal patterns
- Document each false positive with reason

**Week 3-4:** Baseline stabilizes
- CRITICAL alerts should be real threats
- HIGH alerts might be anomalies

**Week 5+:** Production operation
- Update rules as new customer data types are added
- Review false positives monthly
- Test incident response quarterly

---

**Owner:** Sentinel SOC Analyst Agent  
**Status:** Template — configure `${CUSTOMER_DATA_PATH}` and authorized process list before deployment
