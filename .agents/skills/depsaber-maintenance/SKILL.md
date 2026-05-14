---
name: depsaber-maintenance
description: Use when changing DepSaber code, tests, docs, workflows, report viewer, release automation, package-manager hardening, schedule templates, cleanup behavior, or scanner behavior in /Users/Reymundo/Desktop/depsaber.
---

# DepSaber Maintenance

## Core Rules

Work from `/Users/Reymundo/Desktop/depsaber`. Do not recreate `/Users/Reymundo/Desktop/untitled folder` or any symlink to it.

Keep product text, docs, comments, fixtures, generated reports, UI copy, test names, and errors English-only.

Use Context7 before changing package-manager, framework, CLI, CI, or cloud-service configuration. For incident facts, prefer primary sources such as official docs, advisories, or postmortems.

Preserve DepSaber's safety model: `scan` and `report` are read-only; `harden`, `clean`, and `init` require `--apply`; daily routines must never run `clean` or `harden --apply` automatically.

## Change Workflow

Start with tests for behavior changes. Update fixtures, golden output, README, and generated templates in the same change when behavior or user-facing guidance changes.

Keep dependencies minimal. The Go core should remain a fast, portable binary; the web viewer should stay a static Vite app.

For package-manager hardening, verify npm, Yarn, pnpm, Bun, and pip unit differences before editing config output. See `references/coverage.md` when checking current coverage.

Group commits by category, for example scanner, hardening, web, docs, CI, feed, or skills.

## Verification

Run the relevant targeted tests first, then full verification before claiming completion:

```bash
HOME=/private/tmp GOTELEMETRY=off GOCACHE=/private/tmp/depsaber-go-cache go test ./...
HOME=/private/tmp GOTELEMETRY=off GOCACHE=/private/tmp/depsaber-go-cache go build -o bin/depsaber ./cmd/depsaber
cd web && npm test && npm run build && DEPLOY_TARGET=github-pages npm run build
git diff --check
```
