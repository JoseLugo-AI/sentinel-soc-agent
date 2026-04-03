# AI Transparency Statement
# KI-Transparenzerklaerung

**[YOUR_BUSINESS]**
**Effective / Gueltig ab:** [DATE]
**Version:** 1.0

---

## 1. Overview / Ueberblick

[YOUR_BUSINESS] uses artificial intelligence systems as tools to support the delivery of consulting services. This statement describes which AI systems are used, for what purposes, what safeguards are in place, and how human oversight is maintained.

[YOUR_BUSINESS] setzt Systeme der kuenstlichen Intelligenz als Werkzeuge zur Unterstuetzung der Beratungsleistungen ein. Diese Erklaerung beschreibt, welche KI-Systeme verwendet werden, zu welchen Zwecken, welche Schutzmassnahmen bestehen und wie die menschliche Aufsicht gewaehrleistet wird.

---

## 2. AI Systems in Use / Eingesetzte KI-Systeme

### 2.1 Anthropic Claude API

| Aspect | Details |
|--------|---------|
| **Provider** | Anthropic Inc., San Francisco, US [VERIFY_CURRENT] |
| **Purpose** | Document analysis, compliance gap identification, security architecture review, content drafting, threat reasoning (Sentinel SOC agent) |
| **AI type** | Large Language Model (LLM) — general-purpose text analysis and generation |
| **Risk classification (EU AI Act)** | General-purpose AI system (Art. 51 EU AI Act); NOT high-risk — no automated decisions about individuals, no biometric processing, no scoring of natural persons |
| **Data handling** | All client PII is redacted before transmission via automated pipeline. Anthropic does not train on business API data per their data processing terms. |
| **Transfer safeguard** | Standard Contractual Clauses (SCCs) for US transfer |

### 2.2 Microsoft Azure OpenAI Service

| Aspect | Details |
|--------|---------|
| **Provider** | Microsoft Corporation, Azure EU West Europe region [VERIFY_CURRENT] |
| **Purpose** | Document analysis and summarization for client engagements |
| **AI type** | Large Language Model (LLM) — text analysis |
| **Risk classification (EU AI Act)** | General-purpose AI system; NOT high-risk |
| **Data handling** | Processed in EU West Europe. Microsoft does not use customer data for model training. PII redacted before submission. |
| **Transfer safeguard** | EU processing (no third-country transfer) |

### 2.3 Microsoft Azure Document Intelligence

| Aspect | Details |
|--------|---------|
| **Provider** | Microsoft Corporation, Azure EU West Europe region [VERIFY_CURRENT] |
| **Purpose** | OCR and structured extraction from client documents (invoices, contracts, forms) |
| **AI type** | Document understanding / OCR model |
| **Risk classification (EU AI Act)** | General-purpose AI system; NOT high-risk |
| **Data handling** | EU processing. Output reviewed by human before use. |
| **Transfer safeguard** | EU processing (no third-country transfer) |

### 2.4 CrowdStrike Falcon (ML-based threat detection)

| Aspect | Details |
|--------|---------|
| **Provider** | CrowdStrike Inc., EU-1 cloud [VERIFY_CURRENT] |
| **Purpose** | Endpoint protection — malware detection, behavioral analysis |
| **AI type** | Machine learning models for threat classification |
| **Risk classification (EU AI Act)** | NOT high-risk — security tooling, no decisions about natural persons |
| **Data handling** | Endpoint telemetry processed in EU-1 region |
| **Transfer safeguard** | EU processing via EU-1 cloud instance |

---

## 3. How AI Is Used in Client Engagements / Einsatz von KI in Kundenprojekten

### 3.1 What AI Does

- **Analyzes** client-provided documents for GDPR compliance gaps, security vulnerabilities, and AI risk factors
- **Generates** draft reports, TOMs documentation, and DPIA frameworks based on analyzed data
- **Assists** with security architecture design and threat modeling
- **Monitors** the consulting workstation for security threats (Sentinel agent)

### 3.2 What AI Does NOT Do

- **Does NOT make decisions** about individuals — all AI output is advisory to the consultant
- **Does NOT process raw client PII** — automated redaction occurs before any AI interaction
- **Does NOT autonomously communicate** with clients — all client deliverables are reviewed and approved by [YOUR_NAME]
- **Does NOT replace** professional judgment — AI is a tool that supports, not substitutes, the consultant's expertise
- **Does NOT score, profile, or classify** natural persons

### 3.3 Human Oversight / Menschliche Aufsicht

Every AI-generated output goes through human review before it becomes part of a client deliverable:

1. **Input review:** [YOUR_NAME] selects which documents to analyze and verifies PII redaction
2. **Output review:** All AI analysis is reviewed for accuracy, completeness, and appropriateness
3. **Final approval:** [YOUR_NAME] signs off on every deliverable before client delivery
4. **Error correction:** Identified inaccuracies are corrected manually; AI does not self-correct in production

This constitutes "human-in-the-loop" oversight as referenced in the EU AI Act (Art. 14).

---

## 4. Data Protection Safeguards / Datenschutz-Sicherungsmassnahmen

### 4.1 PII Redaction Pipeline

Before any client document is submitted to an AI system:

1. **Detection:** Automated scan identifies personal data (names, addresses, financial identifiers, etc.)
2. **Replacement:** PII is replaced with neutral placeholders (e.g., `[PERSON_1]`, `[ADDRESS_1]`)
3. **Transmission:** Only the redacted version is sent to the AI provider
4. **Remapping:** Results are remapped to original data locally on the encrypted workstation

### 4.2 Technical Measures

- All client data stored on BitLocker-encrypted drives
- Dedicated `Work` directory with file-level audit logging (Windows Security Event 4663)
- AI API access via scoped, time-limited tokens with weekly rotation
- Sysmon + Sentinel agent monitoring for unauthorized data access
- OneDrive M365 backup with 30-day versioning
- No client data in AI training sets (confirmed per provider DPAs)

### 4.3 Contractual Measures

- Data Processing Agreements (Art. 28 GDPR) with all AI sub-processors
- Standard Contractual Clauses for US-based processors (Anthropic, VirusTotal, GreyNoise)
- EU processing for Azure services and CrowdStrike
- Client-specific DPAs available upon request

---

## 5. Limitations & Known Risks / Einschraenkungen und bekannte Risiken

### 5.1 AI Limitations

- **LLMs can produce inaccurate outputs** ("hallucinations") — this is mitigated by mandatory human review of all outputs
- **AI analysis is not legal advice** — consulting deliverables are professional assessments by the consultant, informed by but not generated by AI
- **Context limitations** — AI models have knowledge cutoff dates and may not reflect the latest regulatory changes; the consultant maintains current knowledge independently
- **Language nuance** — German legal terminology may be interpreted imprecisely by English-primary AI models; all German-language deliverables are reviewed for terminological accuracy

### 5.2 Residual Risks

- **PII redaction is not 100% guaranteed** — edge cases may exist; this is mitigated by the combination of automated detection + human review
- **AI provider data handling** — despite contractual prohibitions, technical verification of no-training claims is limited; mitigated by sending only redacted data

---

## 6. EU AI Act Compliance / EU-KI-Verordnung Konformitaet

### 6.1 Risk Classification

All AI systems used by [YOUR_BUSINESS] fall under the **general-purpose AI** category. None are classified as high-risk under Annex III of the EU AI Act because:

- No AI system makes or materially influences decisions about natural persons
- No biometric identification or categorization
- No social scoring or creditworthiness assessment
- No employment, education, or essential service gatekeeping decisions
- No law enforcement or migration applications

### 6.2 Obligations as Deployer

As an AI deployer (not provider), [YOUR_BUSINESS]:

- Maintains this transparency statement (Art. 52 transparency obligations)
- Ensures human oversight of all AI outputs (Art. 14)
- Documents AI use in the DPIA and ROPA
- Monitors AI systems for unexpected behavior or output quality degradation
- Will update this statement as the EU AI Act's provisions take full effect (August 2026 for general-purpose AI obligations)

---

## 7. Your Rights / Ihre Rechte

If you are a client or data subject affected by AI-assisted processing:

- **Right to information:** You may request details about how AI was used in processing your data
- **Right to human review:** You may request that any AI-generated analysis be reviewed (or re-done) entirely by a human
- **Right to object:** You may object to AI-assisted processing of your data; alternative manual processing will be provided at no additional cost
- **Right to explanation:** You may request an explanation of how AI contributed to any assessment or recommendation

Contact: [YOUR_EMAIL]

---

## 8. Review Schedule / Ueberpruefungsplan

| Review | Frequency | Next Due |
|--------|-----------|----------|
| AI system inventory update | Quarterly | [DATE] |
| Sub-processor review | Quarterly | [DATE] |
| EU AI Act compliance check | Semi-annually | [DATE] |
| Full statement revision | Annually | [DATE] |

---

## Review Log

| Date | Version | Reviewer | Changes |
|------|---------|----------|---------|
| [DATE] | 1.0 | [YOUR_FULL_LEGAL_NAME] | Initial creation |

---

*This statement is maintained alongside the DPIA, ROPA, and Incident Response Plan in the Sentinel compliance directory. It is also available to clients upon request and will be published on [YOUR_WEBSITE].*
