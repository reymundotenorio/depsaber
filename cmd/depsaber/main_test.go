package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScanAcceptsPathBeforeFlags(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "package-lock.json", `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/axios": {"version": "1.14.1"}
  }
}`)

	var stdout bytes.Buffer
	if err := run([]string{"scan", root, "--format", "json"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("expected JSON output when flags follow path, got:\n%s", stdout.String())
	}
}

func TestScanSupportsTextDetailLevels(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "package.json", `{"dependencies":{"left-pad":"^1.3.0"}}`)

	var stdout bytes.Buffer
	if err := run([]string{"scan", root, "--detail", "summary"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	got := stdout.String()
	if !bytes.Contains([]byte(got), []byte("DepSaber scan summary")) {
		t.Fatalf("expected summary output, got:\n%s", got)
	}
	if bytes.Contains([]byte(got), []byte("Evidence:")) {
		t.Fatalf("summary output should be concise, got:\n%s", got)
	}
}

func TestVersionAndUsageUseDepSaberName(t *testing.T) {
	var versionOut bytes.Buffer
	if err := run([]string{"version"}, &versionOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := versionOut.String(); got != "depsaber 0.1.0\n" {
		t.Fatalf("unexpected version output: %q", got)
	}

	var usageOut bytes.Buffer
	if err := run([]string{"help"}, &usageOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := usageOut.String(); !bytes.Contains([]byte(got), []byte("DepSaber supply-chain shield")) || !bytes.Contains([]byte(got), []byte("depsaber scan")) || !bytes.Contains([]byte(got), []byte("depsaber wizard")) {
		t.Fatalf("usage should use DepSaber/depsaber branding, got:\n%s", got)
	}
}

func TestWizardRequiresInteractiveTerminal(t *testing.T) {
	err := run([]string{"wizard"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected wizard to require an interactive terminal")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("interactive terminal")) {
		t.Fatalf("expected interactive terminal error, got: %v", err)
	}
}

func TestWizardExecutesReadOnlyScan(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "package.json", `{"dependencies":{"left-pad":"^1.3.0"}}`)

	var stdout bytes.Buffer
	err := executeWizard(wizardAnswers{
		ProjectPath:  root,
		Action:       wizardActionScan,
		Detail:       "summary",
		BaselinePath: filepath.FromSlash(".depsaber/baseline.json"),
		ReportPath:   filepath.FromSlash(".depsaber/report.json"),
	}, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	if got := stdout.String(); !bytes.Contains([]byte(got), []byte("DepSaber wizard")) || !bytes.Contains([]byte(got), []byte("DepSaber scan summary")) {
		t.Fatalf("expected wizard scan output, got:\n%s", got)
	}
	if _, statErr := os.Stat(filepath.Join(root, ".depsaber", "baseline.json")); !os.IsNotExist(statErr) {
		t.Fatalf("wizard scan should not write a baseline: %v", statErr)
	}
}

func TestWizardBaselineRequiresConfirmation(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "package.json", `{"dependencies":{"left-pad":"^1.3.0"}}`)

	err := executeWizard(wizardAnswers{
		ProjectPath:  root,
		Action:       wizardActionBaseline,
		Detail:       "summary",
		BaselinePath: filepath.FromSlash(".depsaber/baseline.json"),
		ReportPath:   filepath.FromSlash(".depsaber/report.json"),
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected baseline action to require confirmation")
	}
	if _, statErr := os.Stat(filepath.Join(root, ".depsaber", "baseline.json")); !os.IsNotExist(statErr) {
		t.Fatalf("wizard baseline should not write without confirmation: %v", statErr)
	}
}

func TestUpdateWritesDepSaberFeedPath(t *testing.T) {
	root := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatal(err)
		}
	})
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	if err := run([]string{"update"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(root, ".depsaber", "feed.json")); err != nil {
		t.Fatalf("expected update to write .depsaber/feed.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".chainward", "feed.json")); !os.IsNotExist(err) {
		t.Fatalf("update should not write legacy .chainward/feed.json")
	}
}

func TestUpdateRejectsUnsignedExternalFeed(t *testing.T) {
	root := t.TempDir()
	feedPath := filepath.Join(root, "feed.json")
	if err := os.WriteFile(feedPath, []byte(`{"version":"external","issuedAt":"2026-05-13T00:00:00Z","expiresAt":"2026-06-13T00:00:00Z","rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	err := run([]string{"update", "--source", feedPath}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected unsigned external feed to be rejected")
	}
}

func TestBaselineRequiresApplyBeforeWriting(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "package.json", `{"dependencies":{"left-pad":"^1.3.0"}}`)

	err := run([]string{"baseline", root}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected baseline to require --apply")
	}
	if _, statErr := os.Stat(filepath.Join(root, ".depsaber", "baseline.json")); !os.IsNotExist(statErr) {
		t.Fatalf("baseline should not write without --apply: %v", statErr)
	}
}

func TestScanComparesAgainstBaselineAndFailsOnNewFindings(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "package.json", `{"dependencies":{"left-pad":"^1.3.0"}}`)
	writeTestFile(t, root, "package-lock.json", `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"left-pad": "^1.3.0"}},
    "node_modules/left-pad": {"version": "1.3.0"}
  }
}`)
	baselinePath := filepath.Join(root, ".depsaber", "baseline.json")

	var baselineOut bytes.Buffer
	if err := run([]string{"baseline", root, "--apply", "--out", baselinePath}, &baselineOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("expected baseline file: %v", err)
	}

	writeTestFile(t, root, "src/evil.pth", "import urllib.request\n")
	var scanOut bytes.Buffer
	err := run([]string{"scan", root, "--format", "json", "--baseline", baselinePath, "--fail-on-new", "high"}, &scanOut, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected new critical finding to fail --fail-on-new high")
	}

	var decoded struct {
		Findings []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"findings"`
		Baseline struct {
			New      int `json:"new"`
			Existing int `json:"existing"`
			Resolved int `json:"resolved"`
		} `json:"baseline"`
	}
	if err := json.Unmarshal(scanOut.Bytes(), &decoded); err != nil {
		t.Fatalf("expected JSON output, got:\n%s", scanOut.String())
	}
	if decoded.Baseline.New != 1 || decoded.Baseline.Existing == 0 || decoded.Baseline.Resolved != 0 {
		t.Fatalf("unexpected baseline summary: %#v", decoded.Baseline)
	}
	statuses := map[string]string{}
	for _, finding := range decoded.Findings {
		statuses[finding.ID] = finding.Status
	}
	if statuses["risk.pypi.pth-exec"] != "new" || statuses["risk.npm.floating-range"] != "existing" {
		t.Fatalf("unexpected finding statuses: %#v", statuses)
	}
}

func writeTestFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
