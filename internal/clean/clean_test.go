package clean

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanDryRunDoesNotRemoveRegenerableArtifacts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "node_modules", "evil", "index.js"), "module.exports = 'evil'\n")

	result, err := New(Options{Root: root, Apply: false, BackupDir: filepath.Join(root, ".depsaber", "backups")}).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Actions) == 0 {
		t.Fatal("expected planned cleanup actions")
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules")); err != nil {
		t.Fatalf("expected dry run to keep node_modules: %v", err)
	}
}

func TestCleanApplyMovesArtifactsIntoBackup(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "node_modules", "evil", "index.js"), "module.exports = 'evil'\n")
	writeFile(t, filepath.Join(root, ".venv", "lib", "python", "site-packages", "evil.pth"), "import evil\n")

	result, err := New(Options{Root: root, Apply: true, BackupDir: filepath.Join(root, ".depsaber", "backups")}).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Actions) == 0 {
		t.Fatal("expected cleanup actions")
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules")); !os.IsNotExist(err) {
		t.Fatal("expected node_modules to be moved out of the project root")
	}
	if _, err := os.Stat(filepath.Join(root, ".venv")); !os.IsNotExist(err) {
		t.Fatal("expected .venv to be moved out of the project root")
	}
	if _, err := os.Stat(filepath.Join(root, ".depsaber", "backups")); err != nil {
		t.Fatalf("expected backup directory: %v", err)
	}
}

func TestCleanRejectsBackupDirectoryOutsideProject(t *testing.T) {
	root := t.TempDir()
	_, err := New(Options{Root: root, Apply: true, BackupDir: filepath.Join(os.TempDir(), "outside-depsaber-backup")}).Run()
	if err == nil {
		t.Fatal("expected backup directory outside the project to be rejected")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
