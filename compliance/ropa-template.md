# Verzeichnis von Verarbeitungstaetigkeiten (Art. 30 DSGVO)
# Record of Processing Activities (Art. 30 GDPR)

**Verantwortlicher / Controller:** [YOUR_FULL_LEGAL_NAME]
**Firma / Business:** [YOUR_BUSINESS]
**Anschrift / Address:** [YOUR_CITY], [YOUR_COUNTRY]
**Kontakt / Contact:** [YOUR_EMAIL]
**Datenschutzbeauftragter / DPO:** Not required (< 20 employees regularly processing personal data)

**Erstellt / Created:** [DATE]
**Version:** 1.0
**Naechste Ueberpruefung / Next Review:** [NEXT_REVIEW_DATE] (quarterly)

---

## 1. Client GDPR & AI Security Consulting

| Field | Details |
|-------|---------|
| **Processing activity** | Provision of IT security architecture, GDPR compliance, and AI security consulting services |
| **Purpose** | Fulfillment of consulting contracts: security audits, GDPR gap analyses, AI compliance assessments, DPIA creation, TOM documentation |
| **Legal basis** | Art. 6(1)(b), contract performance; Art. 6(1)(f), legitimate interest (security improvement) |
| **Categories of data subjects** | Client employees, client customers (indirectly, via document review) |
| **Categories of personal data** | Names, job titles, email addresses, organizational structure; client documents may contain customer PII (names, addresses, financial data, contract details) |
| **Recipients / Processors** | Anthropic (Claude API, US, SCCs) [VERIFY_CURRENT], Microsoft Azure (EU West Europe, DPA) [VERIFY_CURRENT], Microsoft OneDrive M365 (EU, DPA) [VERIFY_CURRENT] |
| **Third country transfers** | Anthropic Inc. (US), Standard Contractual Clauses; all client PII redacted before AI transmission via automated PII redaction pipeline |
| **Retention period** | Active engagement + 6 months post-completion; tax-relevant documents 10 years (AO SS147); deletion upon client request per DPA |
| **Technical & organizational measures** | BitLocker encryption, dedicated `Work` directory with file audit logging, PII redaction pipeline, token-based access control, Sysmon + Sentinel monitoring, OneDrive backup with 30-day versioning |

---

## 2. Prospect Research & Business Development

| Field | Details |
|-------|---------|
| **Processing activity** | Identification and research of potential clients for consulting services |
| **Purpose** | Legitimate business development via inbound marketing, events, referrals, and cold calling |
| **Legal basis** | Art. 6(1)(f), legitimate interest (business development with documented reason per prospect) |
| **Categories of data subjects** | Business contacts at prospective client organizations |
| **Categories of personal data** | Names, job titles, business email, business phone, company name, company size, industry |
| **Recipients / Processors** | None (processed locally) |
| **Third country transfers** | None |
| **Retention period** | 12 months from last contact; deleted if prospect objects or no engagement |
| **Technical & organizational measures** | Data stored locally on encrypted drive, access limited to controller, no bulk automated processing |

---

## 3. Website Operation & Analytics

| Field | Details |
|-------|---------|
| **Processing activity** | Hosting and operation of [YOUR_WEBSITE], including privacy-preserving analytics |
| **Purpose** | Online presence, service information, contact facilitation |
| **Legal basis** | Art. 6(1)(f), legitimate interest (business presence); Art. 6(1)(b), pre-contractual measures (contact form) |
| **Categories of data subjects** | Website visitors, contact form users |
| **Categories of personal data** | Anonymized IP addresses (server logs), browser type, OS, referrer; contact form: name, email, message content |
| **Recipients / Processors** | Cloudflare Inc. (Pages hosting, CDN, Web Analytics, EU-US Data Privacy Framework certified) [VERIFY_CURRENT]; Cal.com (EU instance, appointment booking) [VERIFY_CURRENT] |
| **Third country transfers** | Cloudflare (US), EU-US DPF; Google Fonts loaded from Google servers (EU-US DPF) |
| **Retention period** | Server logs: 30 days; contact form data: duration of correspondence + 6 months; analytics: aggregated, no personal data stored |
| **Technical & organizational measures** | Cloudflare Web Analytics (no cookies, no IP storage, no tracking); HTTPS enforced; no Google Analytics; no marketing pixels |

---

## 4. AI-Assisted Document Analysis

| Field | Details |
|-------|---------|
| **Processing activity** | Use of AI systems to analyze client documents for GDPR compliance, security gaps, and AI risk assessment |
| **Purpose** | Efficient and thorough analysis of client documentation as part of consulting engagements |
| **Legal basis** | Art. 6(1)(b), contract performance |
| **Categories of data subjects** | Individuals referenced in client documents (employees, customers, partners) |
| **Categories of personal data** | Potentially: names, addresses, financial data, contract terms, employment details. ALL redacted before AI processing |
| **Recipients / Processors** | Anthropic (Claude API, US, SCCs) [VERIFY_CURRENT]; Microsoft Azure OpenAI + Document Intelligence (EU West Europe, DPA) [VERIFY_CURRENT] |
| **Third country transfers** | Anthropic (US), SCCs; PII redacted before transmission; Azure processing stays in EU |
| **Retention period** | AI outputs retained for engagement duration + 6 months; AI providers: no training on business data per DPA terms |
| **Technical & organizational measures** | Automated PII redaction pipeline (detect, replace with placeholders, transmit redacted only, remap locally); human review of all AI outputs; no raw client data sent to AI services |

---

## 5. Security Monitoring (Sentinel SOC Agent)

| Field | Details |
|-------|---------|
| **Processing activity** | Automated monitoring of workstation for security threats, unauthorized access, and GDPR compliance violations |
| **Purpose** | Protection of client data, detection of security incidents, compliance with Art. 32 GDPR (security of processing) |
| **Legal basis** | Art. 6(1)(f), legitimate interest (security); Art. 6(1)(c), legal obligation (Art. 32 GDPR) |
| **Categories of data subjects** | System user (controller); potentially attackers (IP addresses in security logs) |
| **Categories of personal data** | Process execution logs, network connection metadata, file access events, login attempts, IP addresses |
| **Recipients / Processors** | Splunk Enterprise (local only, no cloud); Anthropic Claude API (US, SCCs, for AI-powered threat reasoning) [VERIFY_CURRENT]; VirusTotal (US, threat intelligence lookups, IP/hash only) [VERIFY_CURRENT]; GreyNoise (US, IP reputation, IP only) [VERIFY_CURRENT]; CrowdStrike (EU-1, endpoint protection) [VERIFY_CURRENT] |
| **Third country transfers** | Anthropic, VirusTotal, GreyNoise (US), SCCs / DPF; only metadata transmitted (IPs, file hashes, process names), never file contents or client data |
| **Retention period** | Splunk logs: per index capacity (sysmon 50GB, wineventlog 20GB); triage log: rolling 90 days; baseline: updated continuously |
| **Technical & organizational measures** | Token-based Splunk auth with weekly rotation, per-agent scoped tokens, Splunk Web firewalled to localhost + Tailscale, Sysmon with modular config, 7 GDPR-specific monitoring rules, automated escalation via ntfy.sh |

---

## 6. Email Communication

| Field | Details |
|-------|---------|
| **Processing activity** | Business email communication with clients, prospects, and partners |
| **Purpose** | Contract negotiation, service delivery, business correspondence |
| **Legal basis** | Art. 6(1)(b), contract performance; Art. 6(1)(f), legitimate interest (business communication) |
| **Categories of data subjects** | Clients, prospects, business partners |
| **Categories of personal data** | Name, email address, message content, attachments |
| **Recipients / Processors** | Email provider (per hosting setup) |
| **Third country transfers** | Per email provider terms |
| **Retention period** | Business correspondence: 6 years (HGB SS257); tax-relevant: 10 years (AO SS147) |
| **Technical & organizational measures** | TLS encryption in transit, device encryption at rest (BitLocker) |

---

## 7. Appointment Scheduling

| Field | Details |
|-------|---------|
| **Processing activity** | Online appointment booking for discovery calls and consultations |
| **Purpose** | Scheduling convenience for prospective and existing clients |
| **Legal basis** | Art. 6(1)(b), pre-contractual measures |
| **Categories of data subjects** | Prospective and existing clients |
| **Categories of personal data** | Name, email address, selected time slot, optional message |
| **Recipients / Processors** | Cal.com (EU instance) [VERIFY_CURRENT] |
| **Third country transfers** | None (EU processing) |
| **Retention period** | Appointment data: 6 months after appointment date |
| **Technical & organizational measures** | EU-hosted instance, HTTPS, minimal data collection |

---

## Sub-Processor Register

| Processor | Service | Location | Transfer Mechanism | Data Types |
|-----------|---------|----------|-------------------|------------|
| Anthropic Inc. [VERIFY_CURRENT] | Claude API (AI analysis + Sentinel reasoning) | US | SCCs | Redacted documents, security metadata |
| Microsoft Azure [VERIFY_CURRENT] | OpenAI + Document Intelligence | EU West Europe | DPA | Redacted client documents |
| Microsoft (OneDrive M365) [VERIFY_CURRENT] | Backup & file sync | EU | DPA | Client files (encrypted) |
| Cloudflare Inc. [VERIFY_CURRENT] | Website hosting, CDN, analytics | US (EU-US DPF) | DPF adequacy | Anonymized visitor data |
| Cal.com [VERIFY_CURRENT] | Appointment scheduling | EU | EU processing | Name, email, time slot |
| CrowdStrike [VERIFY_CURRENT] | Endpoint protection (Falcon) | EU-1 | DPA | Endpoint telemetry |
| VirusTotal (Google) [VERIFY_CURRENT] | Threat intelligence | US | DPF | IP addresses, file hashes |
| GreyNoise Intelligence [VERIFY_CURRENT] | IP reputation | US | DPF / SCCs | IP addresses |
| ntfy.sh [VERIFY_CURRENT] | Alert notifications | DE (self-hostable) | EU processing | Alert summaries (no PII) |

---

## Review Log

| Date | Version | Reviewer | Changes |
|------|---------|----------|---------|
| [DATE] | 1.0 | [YOUR_FULL_LEGAL_NAME] | Initial creation |

---

*This document fulfills the obligation under Art. 30(1) GDPR for controllers. It is maintained in the Sentinel compliance directory and reviewed quarterly.*
