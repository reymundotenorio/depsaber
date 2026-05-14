package harden

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanRequiresApplyBeforeWritingHardeningFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"axios":"^1.6.0"}}`)
	writeFile(t, root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")

	result, err := New(Options{Root: root, Policy: "standard", Apply: false}).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Actions) == 0 {
		t.Fatal("expected planned hardening actions")
	}
	if _, err := os.Stat(filepath.Join(root, ".npmrc")); !os.IsNotExist(err) {
		t.Fatal("expected dry run to avoid writing .npmrc")
	}
}

func TestApplyWritesPackageManagerHardeningWithBackup(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"axios":"^1.6.0"}}`)
	writeFile(t, root, ".npmrc", "audit=true\n")
	writeFile(t, root, "yarn.lock", "# yarn lockfile\n")
	writeFile(t, root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	writeFile(t, root, "requirements.txt", "requests==2.32.0\n")

	result, err := New(Options{Root: root, Policy: "standard", Apply: true}).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Actions) == 0 {
		t.Fatal("expected applied hardening actions")
	}

	assertFileContains(t, filepath.Join(root, ".npmrc"), "min-release-age=3")
	assertFileContains(t, filepath.Join(root, ".yarnrc.yml"), `npmMinimalAgeGate: "3d"`)
	assertFileContains(t, filepath.Join(root, ".yarnrc.yml"), `checksumBehavior: "throw"`)
	assertFileContains(t, filepath.Join(root, "pnpm-workspace.yaml"), "minimumReleaseAge: 4320")
	assertFileContains(t, filepath.Join(root, "pnpm-workspace.yaml"), "blockExoticSubdeps: true")
	assertFileContains(t, filepath.Join(root, ".depsaber", "pip-secure-installs.md"), "Use `--require-hashes`")

	entries, err := os.ReadDir(filepath.Join(root, ".depsaber", "backups"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected hardening to create backups before writing")
	}
}

func TestStrictPolicyAddsScriptAndTrustControls(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"axios":"^1.6.0"}}`)
	writeFile(t, root, "yarn.lock", "# yarn lockfile\n")
	writeFile(t, root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")

	if _, err := New(Options{Root: root, Policy: "strict", Apply: true}).Run(); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(root, ".npmrc"), "min-release-age=7")
	assertFileContains(t, filepath.Join(root, ".npmrc"), "ignore-scripts=true")
	assertFileContains(t, filepath.Join(root, ".yarnrc.yml"), `npmMinimalAgeGate: "7d"`)
	assertFileContains(t, filepath.Join(root, ".yarnrc.yml"), "enableScripts: false")
	assertFileContains(t, filepath.Join(root, "pnpm-workspace.yaml"), "minimumReleaseAge: 10080")
	assertFileContains(t, filepath.Join(root, "pnpm-workspace.yaml"), "trustPolicy: no-downgrade")
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

func assertFileContains(t *testing.T, path, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), want) {
		t.Fatalf("expected %s to contain %q, got:\n%s", path, want, string(content))
	}
}
