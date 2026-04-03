# Contributing to Sentinel SOC Agent

Thanks for your interest in contributing. Sentinel is an open-source project and welcomes contributions from the community.

## License

This project uses the **Apache License 2.0**. By contributing, you agree that your contributions will be licensed under the same license (inbound = outbound).

## Developer Certificate of Origin (DCO)

All commits must include a `Signed-off-by` line certifying that you wrote the code (or have the right to submit it). This is the [Developer Certificate of Origin](https://developercertificate.org/).

Add it to your commits with:

```bash
git commit -s -m "feat: add Elastic query pack"
```

Or include the line manually:

```
Signed-off-by: Your Name <your@email.com>
```

## How to Contribute

### Reporting Issues

Open a GitHub issue with:
- What you expected to happen
- What actually happened
- Your environment (OS, Splunk version, Claude Code version)

### Pull Requests

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/elastic-queries`)
3. Make your changes
4. Ensure no PII is included (`grep -r "\[YOUR_" agent/ compliance/` should show placeholders, not real data)
5. Commit with DCO sign-off
6. Open a PR against `main`

All PRs are reviewed by the maintainer.

### Adding a SIEM Query Pack

This is the most valuable type of contribution. To add support for a new SIEM:

1. Create `rules/queries/<siem-name>.md` (e.g., `elastic.md`, `wazuh.md`)
2. **Use the exact same heading names** as `rules/queries/splunk.md` — the agent references rules by heading
3. Each rule: level-2 heading, brief description, fenced code block with the query
4. Include severity guidance and false positive notes where relevant

See [docs/customization.md](docs/customization.md) for the full query file contract.

### Adding Detection Rules

New detection rules go in `rules/gdpr.md` (for GDPR-specific rules) or a new file in `rules/` for other frameworks. Follow the existing format.

## Code Style

- Scripts follow existing patterns in the repo
- Markdown: ATX headings, fenced code blocks, one sentence per line in prose
- No linter enforced for v1 — just be consistent with what's there

## Questions?

Open a GitHub issue or discussion. For commercial support, see the [NOTICE](NOTICE) file.
