# Changelog

All notable changes to Sentinel SOC Agent will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-04-04

### Added
- Core agent brain (CLAUDE.md) with SOC procedures, triage logic, and GDPR rules
- Persistent heartbeat loop protocol
- Military-flavored operator personality (anonymized)
- SIEM-agnostic architecture with Splunk query pack
- GDPR detection rules (7 rules covering Art. 5, 32, 33)
- MCP server integration (Splunk, VirusTotal, GreyNoise, CVE-intel)
- Compliance templates: DPIA (Art. 35), IR Plan (Art. 33/34), DPA (Art. 28), ROPA (Art. 30), AI Transparency
- Splunk dashboard (SOC overview)
- Scripts: supervisor, secrets loader, token rotation, CrowdStrike forwarder
- Legacy v1 Python engine (reference only)
- Full documentation: setup guide, architecture, customization, FAQ
