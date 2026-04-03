# Data Protection Impact Assessment (DPIA)
## [YOUR_BUSINESS] - Operational Environment

**Document ID:** DPIA-[YOUR_ID]-001
**Version:** 1.0
**Date:** [DATE]
**Assessor:** Sentinel (SOC Analyst Agent)
**Reviewed by:** [YOUR_NAME] (Data Controller)
**Legal basis:** Article 35 GDPR. Required due to systematic use of AI/automated processing of personal data, including profiling and monitoring
**Next review:** [NEXT_REVIEW_DATE] (quarterly) or upon significant change

---

## 1. Description of the Processing

### 1.1 Purpose
[YOUR_BUSINESS] provides GDPR-compliant AI consulting services to businesses (financial advisors, legal firms, tax consultants). The processing environment includes a workstation running multiple AI agents that assist with business operations, customer deliverables, security monitoring, and content creation.

### 1.2 Data Controller
- **Name:** [YOUR_NAME]
- **Business:** [YOUR_BUSINESS] (Freiberufler, registration pending [YOUR_TAX_OFFICE])
- **Location:** [YOUR_CITY], [YOUR_COUNTRY]
- **Contact:** [YOUR_WEBSITE]

### 1.3 Categories of Data Subjects
| Category | Data Types | Volume |
|----------|-----------|--------|
| Client contacts (prospects) | Name, email, company, position, phone | ~20-50 records |
| Client organizations | Company name, size, industry, compliance posture | ~20-50 records |
| Client employees (during engagements) | Names, roles, access to systems under audit | Per engagement |
| Client customer data (during processing) | Invoices, contracts, PII within client documents | Per engagement |
| Website visitors | IP (anonymized via Cloudflare), page views | Cloudflare analytics |
| [YOUR_NAME] (controller) | Business communications, credentials, workstation activity | Continuous |

### 1.4 Nature of Processing
- Storage of prospect/client contact data for business development
- Processing of client documents (invoices, contracts) through AI-assisted analysis pipelines
- Security monitoring of the workstation environment via Sysmon/Splunk/Sentinel
- AI-assisted content creation for marketing (LinkedIn, blog)
- Automated email and outreach tracking (currently paused)

---

## 2. System Architecture

### 2.1 Physical Environment
| Component | Description | Location |
|-----------|-------------|----------|
| Workstation | Windows 11 (username: [WINDOWS_USERNAME]) | [YOUR_NAME]'s office, [YOUR_CITY] |
| WSL2 | Ubuntu Linux (username: [WSL_USERNAME]) | Same machine |
| Encryption | BitLocker full-disk encryption | At rest |
| Network | Home network, Tailscale mesh VPN for remote access | [YOUR_CITY] |
| Backup | OneDrive (M365) via Known Folder Move. Desktop/Documents/Pictures auto-synced with 30-day versioning | Microsoft cloud (EU data boundary available) |

### 2.2 AI Agents
| Agent | Function | Data Access | Runs As |
|-------|----------|-------------|---------|
| **[Agent 1]** | Primary developer/engineer. Builds tools, deploys code, manages infrastructure | Full codebase, deployment credentials, Splunk (own token) | Claude Code (WSL), interactive + tmux |
| **Sentinel** | SOC analyst. Monitors workstation security via Splunk, triages alerts | Splunk event data (process, network, file telemetry), VirusTotal, GreyNoise. Read-only, no system changes | Claude Code (WSL), cron every 30 min |
| **[Agent 2]** | Business strategy. GTM planning, agent coordination, content review | Business strategy docs, prospect data (names/companies), content drafts | Claude Code (WSL), tmux session |
| **[Agent 3]** | Content creator. LinkedIn posts, blog articles | Content drafts, brand voice docs. NO access to prospect list or client data | Claude Code (WSL), tmux session |
| **[Agent 4]** | Market intelligence. Event scouting, competitor monitoring | Public web data, enrichment data (company info) | CLI agent |

### 2.3 Third-Party Processors (Sub-processors)
| Service | Data Processed | Region | Legal Basis | DPA Status |
|---------|---------------|--------|-------------|------------|
| **Anthropic (Claude API)** [VERIFY_CURRENT] | All agent prompts/responses. May include business context, prospect names, strategy | US (SOC 2 Type II) | Art. 6(1)(f) legitimate interest + SCCs | Anthropic DPA covers API usage |
| **Azure (Document Intelligence + OpenAI)** [VERIFY_CURRENT] | Client invoices/contracts. PII redacted before AI processing | EU (West Europe) | Art. 6(1)(b) contract performance | Microsoft DPA in place |
| **Cloudflare (Pages + CDN)** [VERIFY_CURRENT] | Website content, visitor IPs (anonymized) | EU/Global | Art. 6(1)(f) legitimate interest | Cloudflare DPA |
| **GitHub** [VERIFY_CURRENT] | Source code, no customer data in repos | US | Art. 6(1)(f) legitimate interest | GitHub DPA |
| **Mailgun** [VERIFY_CURRENT] | Email sending (currently paused) | EU region configured | Art. 6(1)(f) legitimate interest | Mailgun DPA |
| **VirusTotal** [VERIFY_CURRENT] | IP addresses, file hashes from security monitoring. No PII | US | Art. 6(1)(f) legitimate interest | Google/VirusTotal DPA |
| **GreyNoise** [VERIFY_CURRENT] | IP addresses from security monitoring. No PII | US | Art. 6(1)(f) legitimate interest | GreyNoise ToS |
| **ntfy.sh** [VERIFY_CURRENT] | Alert summaries (process names, file paths, no PII content) | EU (self-hosted option available) | Art. 6(1)(f) legitimate interest | Public service, no DPA |
| **Splunk Enterprise** | All workstation telemetry (process, network, file, login events) | Local only (localhost:8000/8089) | Art. 6(1)(f) legitimate interest | No cloud component, fully local |
| **ngrok** [VERIFY_CURRENT] | On-demand tunnel for demos ONLY (not permanent) | US | Art. 6(1)(f) legitimate interest | On-demand use only, no persistent exposure |

### 2.4 Data Flows

```
                                    INTERNET
                                       |
                    +------------------+------------------+
                    |                  |                   |
              Anthropic API      Azure (EU)          Cloudflare
              (Claude prompts)   (Doc Intelligence)  (Website)
                    |                  |                   |
                    +------------------+                   |
                    |    WSL2 (Ubuntu)                     |
                    |  +---------------------+            |
                    |  | [Agent 1] (dev)      |            |
                    |  | Sentinel (SOC)       |            |
                    |  | [Agent 2] (GTM)      |            |
                    |  | [Agent 3] (content)  |            |
                    |  | [Agent 4] (intel)    |            |
                    |  | Mission Control :3000|------------+
                    |  +--------+------------+            |
                    |           |                          |
                    |  +--------+------------+            |
                    |  | Windows 11           |            |
                    |  | Splunk (local)       |            |
                    |  | Sysmon (telemetry)   |            |
                    |  | C:\...\Desktop\Work  |<-- GDPR Protected
                    |  +---------------------+
                    |
              +-----+-----+
              | VirusTotal |
              | GreyNoise  |
              | GitHub     |
              +------------+
```

### 2.5 Customer Data Storage
| Location | Content | Protection |
|----------|---------|------------|
| `C:\Users\[WINDOWS_USERNAME]\Desktop\Work` | Client deliverables, contracts, invoices, DPIA docs | File audit logging (EventCode 4663), Sentinel monitoring, BitLocker |
| Azure Blob (KB bot) | Uploaded knowledge base documents | Azure encryption at rest, AAD auth, PII redacted before AI processing |
| `/home/[WSL_USERNAME]/clawd/` | Prospect tracker, outreach templates | File permissions (user-only) |
| Mission Control (localhost:3000) | Content pipeline, prospect network map | Session-based auth (bcrypt + httpOnly cookies), Tailscale access (no public URL) |

---

## 3. Necessity and Proportionality Assessment

### 3.1 Legal Basis for Each Processing Activity
| Activity | Legal Basis | Justification |
|----------|-------------|---------------|
| Prospect data collection | Art. 6(1)(f), legitimate interest | Business development for B2B consulting |
| Client document processing | Art. 6(1)(b), contract performance | Direct delivery of consulting services |
| Security monitoring (Splunk/Sentinel) | Art. 6(1)(f), legitimate interest | Protecting client data and business infrastructure |
| AI agent processing via Anthropic | Art. 6(1)(f), legitimate interest | Core tool for service delivery, proportionate to business need |
| Content creation/marketing | Art. 6(1)(f), legitimate interest | Business promotion via LinkedIn/blog |
| Website analytics | Art. 6(1)(f), legitimate interest | Cloudflare analytics, no cookies, IP anonymized |

### 3.2 Data Minimization
- **Invoice/contract processing:** PII is redacted BEFORE sending to Azure OpenAI. Only financial figures and structure are analyzed. Redaction covers names, addresses, VAT IDs, IBANs, BICs, emails, phones.
- **Sentinel alerts:** ntfy notifications contain process names and file paths only, never PII content from customer files.
- **AI agent prompts:** Agents operate on metadata and summaries. Content agent has no access to prospect lists or client data by design.

### 3.3 Storage Limitation
| Data Category | Retention | Deletion Method |
|---------------|-----------|-----------------|
| Prospect data | Until engagement closes or prospect opts out | Manual deletion from tracker + MC |
| Client deliverables | Duration of engagement + 10 years (German Handelsrecht SS257 HGB) | Secure deletion after retention period |
| Splunk telemetry | 50GB Sysmon / 20GB WinEventLog (rolling) | Automatic index rotation |
| Sentinel triage log | Indefinite (security audit trail) | Manual review quarterly |
| Website analytics | Cloudflare default (rolling) | Managed by Cloudflare |

### 3.4 Purpose Limitation
Each AI agent has a defined scope. Data isolation is enforced by:
- Separate Splunk auth tokens per agent (audience-scoped)
- Content agent explicitly excluded from prospect/client data access
- GDPR rules in Sentinel prevent customer data from appearing in notifications
- Azure PII redaction pipeline strips identifiers before AI analysis

---

## 4. Risk Assessment

### 4.1 Risk Matrix

| # | Risk | Likelihood | Impact | Inherent Risk | Mitigations | Residual Risk |
|---|------|-----------|--------|---------------|-------------|---------------|
| R1 | **Customer data exfiltration via compromised AI agent**: malicious prompt injection causes agent to copy client files to external service | Low | Critical | HIGH | Sentinel monitors file access to Work directory, GDPR rules auto-escalate, agents have no direct internet upload capability without CLI tools, Sysmon logs all process creation | MEDIUM |
| R2 | **Credentials leaked in process logs**: API tokens or passwords appear in command-line arguments captured by Sysmon | Medium | High | HIGH | Token-based auth (no passwords), secrets in env vars via `~/.sentinel-secrets` (chmod 600), `.mcp.json` uses `${VAR}` interpolation, gitignore protection | LOW |
| R3 | **Anthropic API data exposure**: Claude prompts containing business context processed in US | Medium | Medium | MEDIUM | Anthropic SOC 2 Type II, data not used for training (API terms), SCCs for EU-US transfer, no raw PII in prompts (redacted), legitimate interest documented | MEDIUM |
| R4 | **Single workstation = single point of failure**: machine theft, ransomware, or hardware failure | Low | Critical | HIGH | BitLocker encryption at rest, Sysmon + Splunk + Sentinel for detection, EDR pending, OneDrive backup with 30-day versioning (ransomware rollback) | LOW |
| R5 | **Mission Control accessible without authentication** | Low | Medium | MEDIUM | Session-based authentication, bcrypt password hash, 24h cookie expiry, WebSocket upgrade requires valid session, credentials in secure secrets file | LOW |
| R6 | **Shared tunnel exposure** | Low | Low | LOW | Tunnel no longer runs permanently, MC accessed via Tailscale (encrypted, authenticated), tunnel only spun up for demos | LOW |
| R7 | **AI agent hallucination in client deliverables**: incorrect GDPR advice generated by AI | Medium | High | HIGH | All client deliverables reviewed by [YOUR_NAME] (domain expert), AI used as assistant not autonomous decision-maker for client work, confidence indicators in outputs | MEDIUM |
| R8 | **Splunk license expiry**: trial started, dev license pending | High | Medium | MEDIUM | Dev license application submitted, fallback to free license (500MB/day) if denied | LOW |
| R9 | **Customer data in wrong folder**: files saved outside `C:\Users\[WINDOWS_USERNAME]\Desktop\Work` bypass monitoring | Medium | High | HIGH | Sentinel monitors for GDPR file patterns outside Work folder (Rule 2), 7 GDPR monitoring rules active, folder structure to be formalized | MEDIUM |
| R10 | **ntfy.sh as notification channel**: public service, alert metadata visible to service operator | Low | Low | LOW | Alerts contain no PII (process names and file paths only), self-hosted ntfy is available as upgrade path | LOW |
| R11 | **WSL2 network bridge**: WSL-to-Windows traffic traverses virtual network, potentially sniffable | Very Low | Medium | LOW | Traffic is local to machine, Splunk API uses HTTPS (port 8089), BitLocker protects at rest | LOW |
| R12 | **No formal incident response plan** | Low | Critical | MEDIUM | Sentinel provides detection, ntfy provides notification, formal IR plan with Art. 33/34 templates, evidence preservation procedures, post-incident review process | LOW |
| R13 | **Token expiry risk**: Splunk tokens expire periodically | Low | Medium | MEDIUM | Automated rotation script runs weekly via cron, self-heals using whichever token is still valid, ntfy alert if both expired | LOW |
| R14 | **No backup/disaster recovery** | Low | Medium | LOW | OneDrive Known Folder Move active, Desktop/Documents/Pictures auto-synced with version history, Microsoft DPA, BitLocker + cloud encryption | LOW |

### 4.2 Risk Heat Map

```
              Low Impact    Medium Impact    High Impact     Critical Impact
            +-------------+---------------+--------------+-----------------+
  High      |             |  R8           |              |                 |
  Likelihood|             |               |              |                 |
            +-------------+---------------+--------------+-----------------+
  Medium    |             |  R5, R9       |  R3, R7      |                 |
  Likelihood|             |               |              |                 |
            +-------------+---------------+--------------+-----------------+
  Low       |  R10, R11   | R6, R13, R14  |  R1, R2      |  R4             |
  Likelihood|             | R12           |              |                 |
            +-------------+---------------+--------------+-----------------+
  Very Low  |             |               |              |                 |
            +-------------+---------------+--------------+-----------------+

Note: R4 remains in Critical Impact/Low Likelihood due to single-workstation
architecture, but residual risk is LOW with cloud backup + BitLocker + Sentinel.
```

---

## 5. Identified Gaps and Required Actions

| # | Gap | Risk Ref | Priority | Action Required | Owner | Target Date |
|---|-----|----------|----------|-----------------|-------|-------------|
| G1 | **No offsite backup** | R4, R14 | CRITICAL | Enable cloud backup (e.g., OneDrive Known Folder Move) for Desktop including Work folder with versioning. | [YOUR_NAME] | [DATE] |
| G2 | **No incident response plan** | R12 | HIGH | Create formal IR plan with Art. 33/34 notification templates, containment procedures, evidence preservation | [YOUR_NAME] | [DATE] |
| G3 | **Mission Control has no authentication** | R5 | MEDIUM | Add session-based auth: bcrypt password, httpOnly cookies, WebSocket auth, login page | [YOUR_NAME] | [DATE] |
| G4 | **Customer data folder structure not formalized** | R9 | MEDIUM | Create standardized GDPR folder structure with per-client directories, naming conventions, and monitoring baseline | [YOUR_NAME] | [DATE] |
| G5 | **EDR not yet active** | R1, R4 | MEDIUM | Deploy endpoint detection and response (e.g., CrowdStrike Falcon Pro). EDR adds critical detection layer beyond Sysmon | [YOUR_NAME] | [DATE] |
| G6 | **Professional liability insurance not yet active** | N/A | HIGH | Professional liability insurance required before first paying client. Covers consulting errors, data breach claims | [YOUR_NAME] | Before first client |
| G7 | **No DPA template for own clients** | N/A | HIGH | Create Art. 28 DPA template covering sub-processors, TOMs, breach notification, return/deletion | [YOUR_NAME] | [DATE] |

---

## 6. Technical and Organizational Measures (TOMs)

### 6.1 Currently Implemented
| Measure | Article | Status |
|---------|---------|--------|
| Full-disk encryption (BitLocker) | Art. 32(1)(a), encryption | Active |
| Token-based authentication for Splunk (per-agent scoped) | Art. 32(1)(b), access control | Active |
| Automated token rotation (weekly check, 30-day cycle) | Art. 32(1)(b), access control | Active |
| Sysmon process/network/file monitoring | Art. 32(1)(d), testing & evaluation | Active |
| Splunk SIEM with 10 detection rules | Art. 32(1)(d), testing & evaluation | Active |
| Sentinel AI SOC analyst (30-min heartbeat) | Art. 32(1)(d), testing & evaluation | Active |
| 7 GDPR-specific monitoring rules for customer data | Art. 32(1)(d), testing & evaluation | Active |
| File audit logging on Work directory | Art. 32(1)(d), testing & evaluation | Active |
| PII redaction before AI processing (invoice/contract pipeline) | Art. 25, data protection by design | Active |
| Agent data isolation (content agent excluded from client data) | Art. 25, data protection by design | Active |
| Secrets management (env vars, chmod 600, no plaintext) | Art. 32(1)(b), access control | Active |
| Git secret prevention (global gitignore, .mcp.json excluded) | Art. 32(1)(b), access control | Active |
| OneDrive backup via Known Folder Move (30-day versioning) | Art. 32(1)(c), availability & resilience | Active |
| Splunk Web bound to localhost only | Art. 32(1)(b), access control | Active |
| Windows Firewall rule for WSL-to-Splunk (restricted subnet) | Art. 32(1)(b), access control | Active |
| ntfy notifications for CRITICAL/HIGH security events | Art. 33, breach notification support | Active |
| Triage logging with full audit trail | Art. 5(2), accountability | Active |
| Mission Control session auth (bcrypt + httpOnly cookies + WebSocket) | Art. 32(1)(b), access control | Active |
| MC access via Tailscale only (no public URL) | Art. 32(1)(b), access control | Active |
| Splunk KV store bound to localhost | Art. 32(1)(b), access control | Active |
| Sensitive file permissions (`.env`, tokens at chmod 600) | Art. 32(1)(b), access control | Active |
| Splunk admin password rotation + compromised log purge | Art. 32(1)(b), access control | Active |
| Sentinel baseline tuning (entries from telemetry analysis) | Art. 32(1)(d), testing & evaluation | Active |
| Quarterly DPIA review schedule (automated ntfy reminder) | Art. 5(2), accountability | Active |
| Windows security baseline scan with findings report | Art. 32(1)(d), testing & evaluation | Active |

### 6.2 Planned
| Measure | Target Date |
|---------|-------------|
| EDR (endpoint detection and response) | [DATE] |
| Professional liability insurance | Before first client |

---

## 7. Consultation

### 7.1 Supervisory Authority
The competent supervisory authority is:
**[YOUR_DPA]**
[YOUR_DPA_ADDRESS]
Tel: [YOUR_DPA_PHONE]
Email: [YOUR_DPA_EMAIL]
Website: [YOUR_DPA_URL]

Under Art. 36 GDPR, prior consultation with the supervisory authority is required if the DPIA indicates that processing would result in high risk that cannot be mitigated. Based on this assessment, the residual risks after mitigations are manageable, and prior consultation is **not required at this time**. This assessment should be revisited if:
- Customer data volume exceeds 1,000 data subjects
- Processing includes special categories of data (Art. 9)
- Automated decision-making with legal effects is introduced (Art. 22)

### 7.2 Data Subject Rights
[YOUR_BUSINESS] commits to honoring all data subject rights:
- **Access (Art. 15):** Prospect/client data retrievable from tracker, MC, and Work folder
- **Rectification (Art. 16):** Direct correction in source systems
- **Erasure (Art. 17):** Full deletion from tracker, MC, email, and Work folder
- **Portability (Art. 20):** Export in common formats (CSV, PDF)
- **Objection (Art. 21):** Immediate cessation of processing upon request

---

## 8. Conclusion

This environment demonstrates a strong security posture for a solo consultant operation, with notable strengths in:
- AI-powered continuous security monitoring (Sentinel + Splunk + Sysmon)
- Data minimization through PII redaction pipelines
- Agent isolation and scoped access controls
- Proactive credential management with automated rotation

**Remaining items before first paying client:**
1. **Professional liability insurance** (G6)
2. **EDR deployment** (G5)
3. **Resolve any open gaps** from the table in Section 5

**The processing may proceed** once blocking items are resolved. The environment demonstrates strong technical controls with active TOMs, AI-powered continuous monitoring, and comprehensive documentation.

---

## 9. Signatures

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Data Controller | [YOUR_NAME] | ________ | ________ |
| Assessor (Sentinel) | Sentinel SOC Agent | [DATE] | [Automated] |

---

## Appendix A: AI Agent Data Access Matrix

| Data Category | [Agent 1] | Sentinel | [Agent 2] | [Agent 3] | [Agent 4] |
|--------------|-----------|----------|-----------|-----------|-----------|
| Source code | Full | Read | None | None | None |
| Client files (Work folder) | Read/Write | Monitor only | None | None | None |
| Prospect list | None | None | Read | None | None |
| Splunk telemetry | Read (own token) | Read (own token) | None | None | None |
| Content drafts | Read/Write | None | Review | Write | None |
| API credentials | Manage | Read (own scope) | None | None | None |
| Website deployment | Full | None | None | None | None |
| Public web data | As needed | Enrichment (VT/GN) | None | None | Research |

## Appendix B: Sub-processor Register

| Processor | Service | Data Categories | Transfer Mechanism | DPA Date |
|-----------|---------|----------------|-------------------|----------|
| Anthropic [VERIFY_CURRENT] | Claude API | Business context, agent prompts | SCCs | Per API ToS |
| Microsoft Azure [VERIFY_CURRENT] | Document Intelligence, OpenAI | Redacted invoices/contracts | EU processing | Microsoft DPA |
| Cloudflare [VERIFY_CURRENT] | Website hosting, CDN | Anonymized visitor data | EU/US (adequacy) | Cloudflare DPA |
| GitHub [VERIFY_CURRENT] | Code hosting | Source code (no customer data) | SCCs | GitHub DPA |
| Mailgun [VERIFY_CURRENT] | Email delivery (paused) | Email addresses, content | EU region | Mailgun DPA |
| VirusTotal/Google [VERIFY_CURRENT] | Threat intelligence | IP addresses, file hashes | SCCs | Google DPA |

## Appendix C: Review Log

| Date | Reviewer | Changes | Version |
|------|----------|---------|---------|
| [DATE] | Sentinel | Initial DPIA | 1.0 |
