# Compliance Templates

This directory contains GDPR and EU AI Act compliance document templates for organizations deploying AI-powered security monitoring. All templates are based on production-tested documents used in a real consulting environment.

## Templates

### 1. dpia-template.md — Data Protection Impact Assessment (Art. 35 GDPR)

**When you need it:** Required when your processing is "likely to result in a high risk to the rights and freedoms of natural persons" (Art. 35(1)). Using AI agents that process security telemetry, client documents, or prospect data qualifies.

**What it covers:**
- Full system architecture documentation (agents, data flows, sub-processors)
- Legal basis for each processing activity
- Risk assessment matrix with 15 risk scenarios and mitigations
- 26 technical and organizational measures (TOMs)
- Gap analysis with action tracking
- Supervisory authority consultation guidance
- AI agent data access matrix

### 2. incident-response-plan.md — Incident Response Plan (Art. 33/34 GDPR)

**When you need it:** Art. 33 requires notification to your supervisory authority within 72 hours of becoming aware of a personal data breach. You need documented procedures before an incident happens.

**What it covers:**
- Incident classification matrix (CRITICAL/HIGH/MEDIUM/LOW)
- Detection sources and GDPR-specific monitoring rules
- Response timeline from containment (0-1h) through notification (24-72h)
- Containment procedures (process isolation, network isolation, account lockdown)
- Supervisory authority notification template (bilingual DE/EN)
- Data subject notification template (Art. 34)
- Evidence preservation procedures with chain of custody
- Post-incident review process

### 3. dpa-template.md — Data Processing Agreement (Art. 28 GDPR)

**When you need it:** Required whenever you process personal data on behalf of a client (processor role). Must be signed before processing begins.

**What it covers:**
- Full Art. 28 compliant processor agreement (bilingual section headers)
- Sub-processor management with PII redaction pipeline documentation
- Technical and organizational measures annex (24 measures)
- Data transfer safeguards (SCCs for US-based AI providers)
- 24-hour breach notification commitment (exceeds GDPR's 72-hour requirement)
- Return and deletion procedures with German retention law references (HGB, AO)
- Liability and indemnification clauses

### 4. ropa-template.md — Record of Processing Activities (Art. 30 GDPR)

**When you need it:** Art. 30 requires controllers to maintain records of processing activities. While there's an exemption for organizations with fewer than 250 employees, it doesn't apply if processing is "not occasional" or includes special categories of data.

**What it covers:**
- 7 processing activity categories (client consulting, prospect research, website, AI analysis, security monitoring, email, scheduling)
- Sub-processor register with transfer mechanisms
- Retention periods aligned with German law (HGB SS257, AO SS147)
- Technical measures per processing activity

### 5. ai-transparency.md — AI Transparency Statement (EU AI Act)

**When you need it:** The EU AI Act requires transparency about AI system usage. Even if your AI systems are classified as general-purpose (not high-risk), deployers have transparency obligations under Art. 52.

**What it covers:**
- AI system inventory with risk classifications
- Purpose and limitations of each AI system
- PII redaction pipeline documentation
- Human oversight procedures ("human-in-the-loop")
- Data subject rights regarding AI processing
- EU AI Act deployer obligations
- Review schedule

## How to Use

1. **Search for placeholders:** All templates use `[YOUR_` prefix placeholders. Find and replace them all:

   ```bash
   grep -rn '\[YOUR_\|YOUR_\|VERIFY_CURRENT\|WINDOWS_USERNAME\|WSL_USERNAME' compliance/
   ```

2. **Common placeholders across all templates:**

   | Placeholder | Description | Example |
   |-------------|-------------|---------|
   | `[YOUR_NAME]` | Your full name | Jane Smith |
   | `[YOUR_FULL_LEGAL_NAME]` | Legal name for official documents | Jane Elizabeth Smith |
   | `[YOUR_BUSINESS]` | Your business/company name | Smith AI Consulting GmbH |
   | `[YOUR_CITY]` | Your city | Munich |
   | `[YOUR_COUNTRY]` | Your country | Germany |
   | `[YOUR_EMAIL]` | Your business email | jane@smithconsulting.de |
   | `[YOUR_PHONE]` | Your business phone | +49 89 1234567 |
   | `[YOUR_WEBSITE]` | Your website domain | smithconsulting.de |
   | `[YOUR_TAX_ID]` | Tax ID / USt-IdNr | DE123456789 |
   | `[YOUR_TAX_OFFICE]` | Your local Finanzamt | Finanzamt Muenchen |
   | `[YOUR_DPA]` | Your Data Protection Authority | Your supervisory authority name |
   | `[YOUR_SPLUNK_IP]` | Splunk host IP | 10.0.0.50 |
   | `[YOUR_LAN_IP]` | LAN IP address | 192.168.1.100 |
   | `[YOUR_HOSTNAME]` | Workstation hostname | WORKSTATION-01 |
   | `[WINDOWS_USERNAME]` | Windows user account name | jsmith |
   | `[WSL_USERNAME]` | WSL Linux username | jsmith |

3. **Review with legal counsel:** These templates are starting points based on real-world use. They are not legal advice. Have a qualified data protection professional or attorney review the completed documents before relying on them.

4. **Keep them updated:** GDPR compliance is ongoing. Set calendar reminders for the quarterly review dates noted in each template.

5. **Verify sub-processors:** Templates include example sub-processors (Anthropic, Microsoft, etc.). Review the `[VERIFY_CURRENT]` notes and update the list to match your actual sub-processor relationships.
