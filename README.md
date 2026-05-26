# DepSaber

DepSaber is a local-first supply-chain radar for developers, AI-assisted coding workflows, and CI systems.

It scans dependency files, package-manager configuration, GitHub Actions workflows, and project artifacts for the patterns behind recent npm and PyPI compromises. The goal is practical defense before a known CVE or advisory reaches every scanner: know what changed, accept what is already known, and block the next risky change before install scripts run.

```bash
depsaber wizard
depsaber scan . --detail normal
depsaber baseline . --apply
depsaber scan . --baseline .depsaber/baseline.json --fail-on-new high
```

## Why This Exists

Recent supply-chain incidents keep repeating the same playbook:

- A maintainer account, publishing token, trusted CI path, or package release workflow is compromised.
- A malicious version lands in a public registry for a short window.
- Install-time or import-time code steals credentials, drops a second-stage payload, or pivots through CI.
- CI/CD expands the blast radius when privileged triggers, OIDC, shared caches, or broad permissions touch untrusted pull request code.

DepSaber focuses on the project-level controls teams can apply quickly: detect known bad versions, flag suspicious behavior, harden package managers and CI, quarantine regenerable dependency artifacts, and keep a daily read-only scan running on developer machines or any CI provider.

## What DepSaber Combines

DepSaber does not try to replace mature scanners such as Socket, OSV-Scanner, SafeDep vet, zizmor, OpenSSF Scorecard, or GitHub Dependency Review. It takes the most useful ideas for a small local tool:

- Behavior-first supply-chain signals, not only CVEs.
- Offline embedded intelligence for urgent IOCs.
- Local project cleanup with mandatory backups.
- Package-manager hardening templates that developers can apply immediately.
- CI trust-boundary checks inspired by recent GitHub Actions attack chains.
- Baseline and delta mode so CI can block new high-priority findings without failing on accepted legacy debt.
- Daily local and CI routines that never mutate a project automatically.
- An interactive wizard for first runs, baselines, delta scans, and report generation.
- A static GitHub Pages report viewer that can be shared without uploading source code.

## How DepSaber Is Different

Endpoint inventory scanners answer which developer machines currently show exposure to known packages, extensions, or tool metadata. DepSaber is intentionally narrower and more actionable: it works from an active repo or workspace, compares current findings to an accepted baseline, and helps teams decide what should block CI, what should be hardened, and what changed since the last accepted state.

Use DepSaber when you want a local repo guardrail: scan, baseline, report, harden package-manager settings, generate safer CI and schedule templates, and keep cleanup behind explicit review.

## Safety Model

`depsaber scan` is read-only.

`depsaber report` writes only the requested report file. `depsaber baseline`, `depsaber harden`, `depsaber clean`, and `depsaber init` require `--apply` before writing files. Apply mode creates backups before changing existing project files when existing files are modified.

`depsaber wizard` does not bypass the safety model. Scan and delta actions stay read-only, report generation writes only the requested JSON output, and baseline creation asks for explicit confirmation before calling apply mode.

DepSaber can clean project-level artifacts such as dependency folders, package-manager stores, generated caches, and virtual environments. It cannot guarantee full host compromise remediation after malware executed on a machine. If a credential stealer, RAT, or import-time payload may have run, rebuild the environment and rotate exposed secrets.

Daily automation never runs `clean` or `harden --apply` automatically in v1.

## Current Coverage

MVP v1 covers:

- npm, Yarn, pnpm, Bun, and pip projects.
- GitHub Actions workflow risk.
- Generic CI bootstrap templates for GitLab, CircleCI, Azure, and shell-based CI.
- Deterministic install examples for npm, Yarn, pnpm, Bun, and pip inside generated CI templates.
- Interactive guided CLI flow through `depsaber wizard`.
- Baseline and delta scans with `new`, `existing`, and `resolved` finding status.
- Daily local schedule templates for launchd, cron, systemd, and Windows Task Scheduler.
- Embedded intelligence for compromised Axios, `plain-crypto-js`, TanStack Mini Shai-Hulud indicators, `mistralai`, `guardrails-ai`, and LiteLLM releases.
- Behavioral detection for lifecycle downloaders, Python `.pth` execution, pip extra package indexes, floating dependency ranges, missing lockfiles including Bun locks, unpinned actions, unsafe `pull_request_target`, privileged untrusted checkout, broad permissions, unsafe OIDC, cache poisoning, and non-deterministic CI installs.

## Build

```bash
go build -o bin/depsaber ./cmd/depsaber
```

Build the web report viewer:

```bash
cd web
npm ci --ignore-scripts
npm run build
```

For GitHub Pages builds, Vite uses the repository base path:

```bash
cd web
DEPLOY_TARGET=github-pages npm run build
```

## Quick Start

For the first run, use the guided terminal flow:

```bash
depsaber wizard
```

The wizard asks for a project path, action, online checks, detail level, baseline path, and report path. It is meant for humans at a terminal; use the commands below for scripts and CI.

Scan the current project:

```bash
depsaber scan . --detail normal
```

Use less or more terminal detail:

```bash
depsaber scan . --detail summary
depsaber scan . --detail full --color always
```

Create an accepted baseline and fail later only on new high-priority findings:

```bash
depsaber baseline . --apply
depsaber scan . --baseline .depsaber/baseline.json --fail-on-new high
```

Generate a JSON report:

```bash
depsaber report . --out .depsaber/report.json --online --baseline .depsaber/baseline.json --fail-on-new high
```

Open the static report viewer:

```bash
cd web
npm run build
npm run preview
```

Then open the local Vite preview URL and load `.depsaber/report.json` through the file picker. The same viewer is built for GitHub Pages with `DEPLOY_TARGET=github-pages npm run build`.

Update embedded feed output:

```bash
depsaber update
```

External file or URL feeds must be signed. Set `DEPSABER_FEED_PUBLIC_KEY_BASE64` to the feed publisher's Ed25519 public key before using `depsaber update --source <file-or-url>`.

`--online` enables live npm and PyPI metadata checks. Very new releases are flagged against a 72-hour age gate. Registry failures become warning findings so scans continue when a registry is down or network access is unavailable.

## CLI

```bash
depsaber wizard
depsaber scan [path] --format text|json --detail summary|normal|full --color auto|always|never --online --baseline .depsaber/baseline.json --fail-on high|critical --fail-on-new high|critical
depsaber baseline [path] --apply --out .depsaber/baseline.json
depsaber update --source default|file|url
depsaber harden [path] --apply --policy standard|strict
depsaber clean [path] --apply --backup-dir .depsaber/backups
depsaber report [path] --out .depsaber/report.json --baseline .depsaber/baseline.json --fail-on-new high|critical
depsaber init schedule --target launchd|cron|systemd|windows-task --time 09:00 --apply
depsaber init ci --target github|gitlab|circleci|azure|generic --apply
```

## Baseline And Delta Mode

Use a baseline when a repo already has known medium-risk debt and CI should block only on new issues:

```bash
depsaber baseline . --apply
depsaber scan . --baseline .depsaber/baseline.json --fail-on-new high
```

`depsaber baseline` scans the project and writes accepted finding fingerprints to `.depsaber/baseline.json`. Later scans mark findings as `new` or `existing`, and report findings that disappeared as `resolved` in the JSON `baseline` summary. `--fail-on-new` requires `--baseline` and ignores accepted findings that are still present.

Text scans default to `--detail normal`, which prints counts, ecosystems with findings, top rule groups, and a short example list. Use `--detail summary` for CI logs and `--detail full` when you need evidence and remediation for every finding. Color is enabled automatically for interactive terminals; use `--color always` or `--color never` to override it.

Use the wizard when you want a friendlier path:

```bash
depsaber wizard
```

Choose `Create baseline` once to accept current findings, then choose `Delta scan` later to show only what changed against `.depsaber/baseline.json`.

## Daily Local Routine

Generate a local schedule template:

```bash
depsaber init schedule --target launchd --time 09:00 --apply
```

Recommended daily command:

```bash
depsaber update && depsaber scan . --online --baseline .depsaber/baseline.json --format json --fail-on-new high
```

Reports are intended to live under `.depsaber/reports/YYYY-MM-DD.json`.

## Public Report Viewer

The web viewer is a static Vite app under `web/`. It can be hosted on GitHub Pages without a backend because users load local `.depsaber/report.json` files through the browser file picker. The site uses Vite's base path so the sample report works both locally and under `/depsaber/` on GitHub Pages.

Local preview:

```bash
cd web
npm run build
npm run preview
```

GitHub Pages preview with the `/depsaber/` mount path:

```bash
cd web
DEPLOY_TARGET=github-pages npm run build
npm run preview:pages
```

GitHub Pages deployment is provided in `.github/workflows/pages.yml`:

- Builds only from `main` or manual dispatch.
- Uses `contents: read`, `pages: write`, and `id-token: write`.
- Pins all GitHub Actions to full commit SHAs.
- Builds `web/` and deploys `web/dist`.

For repository Pages, the public URL will be:

```text
https://<user-or-org>.github.io/depsaber/
```

## CI Setup

Generate a GitHub Actions template:

```bash
depsaber init ci --target github --apply
```

Generate a portable shell template for any CI provider:

```bash
depsaber init ci --target generic --apply
```

The GitHub template uses `pull_request`, not `pull_request_target`; defaults to `contents: read`; avoids `id-token: write`; sets `persist-credentials: false`; and pins checkout to a full commit SHA.

Generated CI templates also include commented deterministic install examples for project jobs:

- `npm ci --ignore-scripts`
- `pnpm install --frozen-lockfile`
- `yarn install --immutable`
- `bun ci`
- `python -m pip install --require-hashes --only-binary :all: -r requirements.txt`

DepSaber also ships its own GitHub workflows:

- `pages.yml` deploys the static report viewer to GitHub Pages.
- `release.yml` builds macOS, Linux, and Windows binaries when a `v*` tag is pushed.

The release workflow generates `checksums.txt` with SHA-256 checksums and publishes assets with `gh release create`.

## Hardening

Run hardening only when you are ready to write project files:

```bash
depsaber harden . --apply --policy standard
```

Standard policy writes practical defaults:

- npm `.npmrc`: `min-release-age=3`, `audit=true`, `ignore-scripts=true`
- Yarn `.yarnrc.yml`: `npmMinimalAgeGate: "3d"`, `checksumBehavior: "throw"`, `enableHardenedMode: true`, `enableScripts: false`
- pnpm `pnpm-workspace.yaml`: `minimumReleaseAge: 4320`, `blockExoticSubdeps: true`, `strictDepBuilds: true`
- Bun `bunfig.toml`: `[install] minimumReleaseAge = 259200`, `ignoreScripts = true`
- pip guidance: `.depsaber/pip-secure-installs.md` with `--require-hashes`, pinned requirements, and binary-only guidance

Strict policy increases the waiting period and adds trust downgrade controls:

- npm: `min-release-age=7`
- Yarn: `npmMinimalAgeGate: "7d"`
- pnpm: `minimumReleaseAge: 10080`, `trustPolicy: no-downgrade`
- Bun: `minimumReleaseAge = 604800`

The unit mismatch matters: npm `min-release-age` is days, pnpm `minimumReleaseAge` is minutes, Bun `minimumReleaseAge` is seconds, and Yarn accepts duration strings such as `"3d"` in `.yarnrc.yml`. pnpm 11 already defaults to a 1440-minute age gate plus safer dependency build defaults; DepSaber standard is stricter at 4320 minutes.

## Cleanup

Run cleanup only after reviewing findings:

```bash
depsaber clean . --apply --backup-dir .depsaber/backups
```

Cleanup quarantines regenerable project artifacts such as `node_modules`, `.venv`, `.yarn/cache`, and `.pnpm-store` inside `.depsaber/backups`.

## Install And Release

For local development:

```bash
go build -o bin/depsaber ./cmd/depsaber
```

Install a local `depsaber` command on your `PATH`:

```bash
./scripts/install-local.sh
depsaber scan . --format text
```

By default the installer writes to `$HOME/.local/bin/depsaber`. Set `DEPSABER_INSTALL_DIR` to choose a different install directory.

For releases, push a semantic tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds:

- `depsaber_<version>_darwin_amd64`
- `depsaber_<version>_darwin_arm64`
- `depsaber_<version>_linux_amd64`
- `depsaber_<version>_linux_arm64`
- `depsaber_<version>_windows_amd64.exe`
- `checksums.txt`

Future Homebrew support should point to the GitHub release binary and checksum. Do not add a tap until the release process has at least one published version.

## Intelligence Feed

`feed/base.json` is unsigned source material for the DepSaber intelligence feed. Hosted or file-based external feeds must be signed with Ed25519 and include:

- `version`
- `issuedAt`
- `expiresAt`
- `rules`
- `signature`

DepSaber rejects unsigned external feeds and expired signed feeds. Keep private signing keys outside this repository.

## Recent Attack Patterns DepSaber Targets

- Axios compromise: malicious Axios releases added `plain-crypto-js@4.2.1`, which executed a post-install loader and fetched a second-stage payload while normal app logic stayed unchanged.
- TanStack compromise: a `pull_request_target` workflow checked out untrusted PR code, poisoned a shared pnpm cache, and enabled OIDC trusted-publisher abuse to publish malicious `@tanstack/*` releases.
- Mini Shai-Hulud style npm/PyPI waves: install-time and import-time execution harvested GitHub, cloud, npm, SSH, and CI credentials, then attempted ecosystem propagation.
- Python import/startup execution: malicious packages can execute at import time or through `.pth` files, making virtual environment rebuilds and hashed installs important.

## Tests

```bash
GOCACHE="$(pwd)/.cache/go-build" go test ./...
cd web && npm test && npm run build
```

## MVP Acceptance

Before tagging an MVP release, run the full verification suite and smoke test the built binary against at least one real multi-project workspace:

```bash
HOME=/private/tmp GOTELEMETRY=off GOCACHE=/private/tmp/depsaber-go-cache go test ./...
HOME=/private/tmp GOTELEMETRY=off GOCACHE=/private/tmp/depsaber-go-cache go build -o /private/tmp/depsaber ./cmd/depsaber
cd web && npm test && npm run build && DEPLOY_TARGET=github-pages npm run build
git diff --check
```

Example read-only workspace smoke test:

```bash
/private/tmp/depsaber scan /path/to/frontend --format json > /private/tmp/depsaber-frontend.json
/private/tmp/depsaber scan /path/to/backend --format json > /private/tmp/depsaber-backend.json
/private/tmp/depsaber scan /path/to/playwright --format json > /private/tmp/depsaber-playwright.json
```

## Limitations

- Online registry checks are intentionally opt-in with `--online`.
- Online checks currently cover npm and PyPI publish-age metadata. Bun support is local in v1: lockfile scanning, CI install detection, and `bunfig.toml` hardening.
- MVP v1 does not replace endpoint detection, secret scanning, SBOM governance, or organization-level policy enforcement.
- Cleanup is project-scoped. If malware executed, assume host and credentials may be compromised until proven otherwise.
- External intelligence feeds require Ed25519 signatures; v1 includes source material and verification support but not a hosted feed service.

## Source References

- GitHub Actions secure use: https://docs.github.com/en/actions/reference/security/secure-use
- TanStack npm supply-chain compromise postmortem: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- TanStack GitHub security advisory: https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx
- Microsoft Axios compromise analysis: https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/
- pnpm supply-chain security: https://pnpm.io/supply-chain-security
- npm audit and signatures: https://docs.npmjs.com/cli/v11/commands/npm-audit/
- npm config `min-release-age`: https://docs.npmjs.com/cli/v11/using-npm/config/
- Yarn security settings: https://yarnpkg.com/features/security
- Bun install security settings: https://bun.sh/docs/pm/cli/install
- pip secure installs: https://pip.pypa.io/en/stable/topics/secure-installs/
