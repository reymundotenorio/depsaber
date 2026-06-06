---
name: depsaber-threat-intel
description: Use when adding or updating DepSaber supply-chain attack intelligence, IOCs, compromised package versions, package-manager security guidance, signed feed rules, malicious fixtures, or README threat coverage.
---

# DepSaber Threat Intel

## Core Rules

Use current primary sources before changing intelligence: official package-manager docs, registry advisories, GitHub security advisories, vendor postmortems, or maintainer incident reports. Use Context7 for npm, pnpm, Yarn, Bun, pip, React/Vite, GitHub Actions, and other current tooling docs.

Keep intelligence precise. Do not add vague package names or speculative versions without a source and a detection path.

Update both embedded and source feed material when adding durable IOCs unless the feed source-of-truth changes intentionally.

Do not commit real credentials, private keys, registry tokens, cloud keys, or private feed signing keys. Malicious fixtures must use synthetic values, and token-shaped samples must be obviously fake and isolated under `testdata/`.

## Rule Workflow

Use `references/rule-checklist.md` for each new incident or rule.

Add tests and fixtures first. Cover at least one malicious fixture and one clean path when the rule could create false positives.

Update scanner logic, `internal/intel/feed.go`, `feed/base.json`, README attack coverage, and report viewer sample data when user-facing output changes.

For online checks, registry failures must remain warning-style findings unless a future strict mode explicitly changes that behavior.

Feed signing keys must stay outside the repository. Tests may generate Ed25519 keys in memory, but checked-in feeds must not include private signing material.

## Verification

Run targeted package tests for scanner, feed, and output changes, then full verification before closing:

```bash
HOME=/private/tmp GOTELEMETRY=off GOCACHE=/private/tmp/depsaber-go-cache go test ./internal/scanner ./internal/intel ./internal/output ./internal/report
HOME=/private/tmp GOTELEMETRY=off GOCACHE=/private/tmp/depsaber-go-cache go test ./...
git diff --check
```
