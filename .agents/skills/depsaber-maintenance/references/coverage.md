# DepSaber Coverage Reference

## Covered In v1

- npm, Yarn, pnpm, Bun, and pip project signals.
- GitHub Actions and generic CI initialization templates.
- Known offline IOCs for Axios, `plain-crypto-js`, TanStack Mini Shai-Hulud indicators, `mistralai`, `guardrails-ai`, and LiteLLM.
- Install-time lifecycle downloader detection in `package.json`.
- Python `.pth` startup execution detection.
- Missing JavaScript lockfiles, including `bun.lock` and `bun.lockb`.
- Non-deterministic CI installs for npm, Yarn, pnpm, Bun, and pip without hashes.
- npm and PyPI online publish-age checks when `--online` is enabled.
- Standard hardening blocks install scripts by default and uses age gates across npm, Yarn, pnpm, and Bun.

## Known Gaps

- Online registry metadata checks only cover npm and PyPI in v1.
- Cleanup is project-scoped and cannot prove host compromise remediation after malware execution.
- External intelligence feed hosting is not implemented; signed file and URL verification are implemented.
- Bun support is local in v1: lockfile scanning, CI install detection, and `bunfig.toml` hardening.
