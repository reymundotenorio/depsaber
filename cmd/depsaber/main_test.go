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
	if got := usageOut.String(); !bytes.Contains([]byte(got), []byte("DepSaber supply-chain shield")) || !bytes.Contains([]byte(got), []byte("depsaber scan")) {
		t.Fatalf("usage should use DepSaber/depsaber branding, got:\n%s", got)
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
