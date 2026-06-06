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

Do not commit credentials, private keys, real tokens, private signing keys, or personal environment files. Test fixtures must use synthetic values only.

## Change Workflow

Start with tests for behavior changes. Update fixtures, golden output, README, and generated templates in the same change when behavior or user-facing guidance changes.

Keep dependencies minimal. The Go core should remain a fast, portable binary; the web viewer should stay a static Vite app.

For package-manager hardening, verify npm, Yarn, pnpm, Bun, and pip unit differences before editing config output. See `references/coverage.md` when checking current coverage.

For README and web launch polish, lead with user value and first-run flow. Keep implementation details such as GitHub Pages, Vite, and static hosting secondary unless the user is configuring deployment.

Group commits by category, for example scanner, hardening, web, docs, CI, feed, or skills.

## Public Viewer And Release Rules

The public report viewer for this repository is `https://reymundotenorio.github.io/depsaber/`.

The viewer should clearly distinguish the bundled sample report from a locally loaded `.depsaber/report.json` file. Preserve visible report-source state such as `Sample report loaded`, `Load local report`, and the uploaded file name.

Use `import.meta.env.BASE_URL` for public assets and `DEPLOY_TARGET=github-pages npm run build` for Pages builds. For local Pages-path verification, use `npm run preview:pages`; plain Vite preview does not validate the `/depsaber/` mount path.

Never move or retag a published release tag. Use a new semantic version, such as a patch tag, for follow-up launch fixes.

## Sensitive Data Review

Before release closeout or public-site polish, scan tracked and non-ignored files for accidental sensitive data:

```bash
git ls-files | rg -n '(^|/)(\.env|.*\.(pem|p12|pfx|key)|id_rsa|id_ed25519|credentials|secrets|token)'
rg -n --hidden --glob '!.git/**' --glob '!web/node_modules/**' --glob '!web/dist/**' --glob '!bin/**' --glob '!.cache/**' -i '(password|secret|token|api[_ -]?key|auth[_ -]?token|private[_ -]?key|client[_ -]?secret|credential|BEGIN .*PRIVATE)'
rg -n --hidden --glob '!.git/**' --glob '!web/node_modules/**' --glob '!web/dist/**' --glob '!bin/**' --glob '!.cache/**' --pcre2 '(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{32,}|npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_\-]{20,}|-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----)'
```

Review matches instead of treating every match as a leak. Expected false positives include scanner remediations, GitHub Actions permission names, generated test keys created in memory, and deliberately risky fixtures under `testdata/`.

## Verification

Run the relevant targeted tests first, then full verification before claiming completion:

```bash
HOME=/private/tmp GOTELEMETRY=off GOCACHE=/private/tmp/depsaber-go-cache go test ./...
HOME=/private/tmp GOTELEMETRY=off GOCACHE=/private/tmp/depsaber-go-cache go build -o bin/depsaber ./cmd/depsaber
cd web && npm test && npm run build && DEPLOY_TARGET=github-pages npm run build
git diff --check
```
