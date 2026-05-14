package clean

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/depsaber/depsaber/internal/report"
)

type Options struct {
	Root      string
	Apply     bool
	BackupDir string
}

type Result struct {
	Actions []report.Action
}

type Cleaner struct {
	options Options
}

func New(options Options) *Cleaner {
	return &Cleaner{options: options}
}

func (cleaner *Cleaner) Run() (Result, error) {
	root, err := filepath.Abs(cleaner.options.Root)
	if err != nil {
		return Result{}, err
	}
	backupDir := cleaner.options.BackupDir
	if backupDir == "" {
		backupDir = filepath.Join(root, ".depsaber", "backups")
	}
	backupDir, err = filepath.Abs(backupDir)
	if err != nil {
		return Result{}, err
	}
	if !isWithin(root, backupDir) {
		return Result{}, fmt.Errorf("backup directory must stay inside the project: %s", backupDir)
	}
	actions := cleaner.plan(root)
	if !cleaner.options.Apply {
		return Result{Actions: actions}, nil
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	for _, action := range actions {
		source := filepath.Join(root, filepath.FromSlash(action.File))
		if _, err := os.Stat(source); err != nil {
			continue
		}
		destination := filepath.Join(backupDir, stamp, filepath.FromSlash(action.File))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return Result{}, err
		}
		if err := os.Rename(source, destination); err != nil {
			return Result{}, err
		}
	}
	return Result{Actions: actions}, nil
}

func (cleaner *Cleaner) plan(root string) []report.Action {
	var actions []report.Action
	for _, rel := range []string{"node_modules", ".venv", ".yarn/cache", ".pnpm-store"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
			actions = append(actions, report.Action{
				ID:          "clean.project-artifact." + strings.ReplaceAll(rel, "/", "."),
				Title:       "Quarantine regenerable project artifact",
				File:        rel,
				Mode:        actionMode(cleaner.options.Apply),
				Description: "Move the artifact into .depsaber/backups so dependencies can be rebuilt from trusted sources.",
			})
		}
	}
	return actions
}

func isWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}

func actionMode(apply bool) string {
	if apply {
		return "applied"
	}
	return "planned"
}
