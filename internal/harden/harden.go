package harden

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/depsaber/depsaber/internal/report"
)

type Options struct {
	Root   string
	Policy string
	Apply  bool
}

type Result struct {
	Actions []report.Action
}

type Hardener struct {
	options Options
}

type profile struct {
	Name        string
	NPMDays     int
	YarnAge     string
	PNPMMinutes int
	Strict      bool
}

func New(options Options) *Hardener {
	if options.Policy == "" {
		options.Policy = "standard"
	}
	return &Hardener{options: options}
}

func (hardener *Hardener) Run() (Result, error) {
	root, err := filepath.Abs(hardener.options.Root)
	if err != nil {
		return Result{}, err
	}
	profile, err := hardeningProfile(hardener.options.Policy)
	if err != nil {
		return Result{}, err
	}
	actions := hardener.plan(root, profile)
	if !hardener.options.Apply {
		return Result{Actions: actions}, nil
	}
	for _, action := range actions {
		if err := hardener.apply(root, action, profile); err != nil {
			return Result{}, err
		}
	}
	return Result{Actions: actions}, nil
}

func (hardener *Hardener) plan(root string, profile profile) []report.Action {
	var actions []report.Action
	if exists(filepath.Join(root, "package.json")) || exists(filepath.Join(root, "package-lock.json")) {
		actions = append(actions, report.Action{
			ID:          "harden.npm.min-release-age",
			Title:       "Set npm minimum release age",
			File:        ".npmrc",
			Mode:        actionMode(hardener.options.Apply),
			Description: fmt.Sprintf("Add min-release-age=%d to reduce exposure to newly published malicious npm releases.", profile.NPMDays),
		})
	}
	if exists(filepath.Join(root, "yarn.lock")) {
		actions = append(actions, report.Action{
			ID:          "harden.yarn.safe-installs",
			Title:       "Set Yarn minimum release age and checksum behavior",
			File:        ".yarnrc.yml",
			Mode:        actionMode(hardener.options.Apply),
			Description: "Add npmMinimalAgeGate and checksumBehavior to make Yarn installs more resistant to fresh malicious releases and cache tampering.",
		})
	}
	if exists(filepath.Join(root, "pnpm-lock.yaml")) {
		actions = append(actions, report.Action{
			ID:          "harden.pnpm.minimum-release-age",
			Title:       "Set pnpm minimum release age",
			File:        "pnpm-workspace.yaml",
			Mode:        actionMode(hardener.options.Apply),
			Description: fmt.Sprintf("Add minimumReleaseAge: %d and block exotic transitive dependencies for pnpm projects.", profile.PNPMMinutes),
		})
	}
	if hasPythonRequirements(root) {
		actions = append(actions, report.Action{
			ID:          "harden.pip.hash-guidance",
			Title:       "Write pip secure install guidance",
			File:        ".depsaber/pip-secure-installs.md",
			Mode:        actionMode(hardener.options.Apply),
			Description: "Document pip hash-checking mode and pinned requirements expectations.",
		})
	}
	return actions
}

func (hardener *Hardener) apply(root string, action report.Action, profile profile) error {
	switch action.ID {
	case "harden.npm.min-release-age":
		lines := []string{fmt.Sprintf("min-release-age=%d", profile.NPMDays), "audit=true"}
		if profile.Strict {
			lines = append(lines, "ignore-scripts=true")
		}
		return upsertConfigLines(root, action.File, lines)
	case "harden.yarn.safe-installs":
		lines := []string{
			fmt.Sprintf(`npmMinimalAgeGate: "%s"`, profile.YarnAge),
			`checksumBehavior: "throw"`,
			"enableHardenedMode: true",
		}
		if profile.Strict {
			lines = append(lines, "enableScripts: false")
		}
		return upsertConfigLines(root, action.File, lines)
	case "harden.pnpm.minimum-release-age":
		lines := []string{
			fmt.Sprintf("minimumReleaseAge: %d", profile.PNPMMinutes),
			"blockExoticSubdeps: true",
		}
		if profile.Strict {
			lines = append(lines, "strictDepBuilds: true", "trustPolicy: no-downgrade")
		}
		return upsertConfigLines(root, action.File, lines)
	case "harden.pip.hash-guidance":
		return writeWithBackup(root, action.File, []byte("# pip secure install guidance\n\n"+
			"Use `--require-hashes` for production installs after generating a fully pinned requirements file. Prefer `--only-binary :all:` when your project can avoid source builds.\n\n"+
			"Recommended pattern:\n\n"+
			"```bash\n"+
			"python -m pip install --require-hashes --only-binary :all: -r requirements.txt\n"+
			"```\n\n"+
			"DepSaber writes this guidance instead of rewriting requirements automatically because adding hashes requires a trusted dependency resolution step.\n"))
	default:
		return fmt.Errorf("unknown hardening action: %s", action.ID)
	}
}

func upsertConfigLines(root, rel string, lines []string) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	content := ""
	if current, err := os.ReadFile(path); err == nil {
		content = string(current)
	}
	keys := map[string]bool{}
	for _, line := range lines {
		if key := configKey(line); key != "" {
			keys[key] = true
		}
	}
	var kept []string
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		key := configKey(line)
		if key != "" && keys[key] {
			continue
		}
		kept = append(kept, line)
	}
	next := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if next != "" {
		next += "\n"
	}
	for _, line := range lines {
		next += line + "\n"
	}
	return writeWithBackup(root, rel, []byte(next))
}

func writeWithBackup(root, rel string, content []byte) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := backupFile(root, rel); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o644)
}

func backupFile(root, rel string) error {
	source := filepath.Join(root, filepath.FromSlash(rel))
	if _, err := os.Stat(source); err != nil {
		return nil
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	destination := filepath.Join(root, ".depsaber", "backups", stamp, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	content, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, content, 0o644)
}

func hasPythonRequirements(root string) bool {
	matches, _ := filepath.Glob(filepath.Join(root, "requirements*.txt"))
	return len(matches) > 0 || exists(filepath.Join(root, "pyproject.toml")) || exists(filepath.Join(root, "poetry.lock")) || exists(filepath.Join(root, "uv.lock"))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func actionMode(apply bool) string {
	if apply {
		return "applied"
	}
	return "planned"
}

func hardeningProfile(policy string) (profile, error) {
	switch strings.ToLower(policy) {
	case "standard":
		return profile{Name: "standard", NPMDays: 3, YarnAge: "3d", PNPMMinutes: 4320}, nil
	case "strict":
		return profile{Name: "strict", NPMDays: 7, YarnAge: "7d", PNPMMinutes: 10080, Strict: true}, nil
	default:
		return profile{}, fmt.Errorf("unsupported hardening policy: %s", policy)
	}
}

func configKey(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	if key, _, ok := strings.Cut(trimmed, "="); ok {
		return strings.TrimSpace(key)
	}
	if key, _, ok := strings.Cut(trimmed, ":"); ok {
		return strings.TrimSpace(key)
	}
	return ""
}
