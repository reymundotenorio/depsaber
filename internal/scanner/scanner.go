package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/depsaber/depsaber/internal/intel"
	"github.com/depsaber/depsaber/internal/report"
)

type Options struct {
	Root            string
	Feed            intel.Feed
	Online          bool
	NPMRegistryURL  string
	PyPIRegistryURL string
	HTTPClient      *http.Client
}

type Scanner struct {
	root            string
	feed            intel.Feed
	online          bool
	npmRegistryURL  string
	pypiRegistryURL string
	httpClient      *http.Client
	now             func() time.Time
}

func New(options Options) *Scanner {
	feed := options.Feed
	if feed.Version == "" {
		feed = intel.BuiltinFeed()
	}
	npmRegistryURL := strings.TrimRight(options.NPMRegistryURL, "/")
	if npmRegistryURL == "" {
		npmRegistryURL = "https://registry.npmjs.org"
	}
	pypiRegistryURL := strings.TrimRight(options.PyPIRegistryURL, "/")
	if pypiRegistryURL == "" {
		pypiRegistryURL = "https://pypi.org"
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &Scanner{
		root:            options.Root,
		feed:            feed,
		online:          options.Online,
		npmRegistryURL:  npmRegistryURL,
		pypiRegistryURL: pypiRegistryURL,
		httpClient:      httpClient,
		now:             time.Now,
	}
}

func (scanner *Scanner) Scan() (report.Report, error) {
	root, err := filepath.Abs(scanner.root)
	if err != nil {
		return report.Report{}, err
	}
	result := report.Report{
		SchemaVersion: "1.0",
		ToolVersion:   "dev",
		GeneratedAt:   scanner.now().UTC(),
		Root:          root,
		FeedVersion:   scanner.feed.Version,
		FeedUpdatedAt: scanner.feed.IssuedAt,
		Findings:      []report.Finding{},
	}
	added := map[string]bool{}
	addFinding := func(finding report.Finding) {
		key := finding.ID + "\x00" + finding.File + "\x00" + finding.PackageName + "\x00" + finding.Version
		if added[key] {
			return
		}
		added[key] = true
		result.Findings = append(result.Findings, finding)
	}

	scanner.scanPackageJSON(root, addFinding)
	scanner.scanNPMLock(root, "package-lock.json", addFinding)
	scanner.scanTextLock(root, "yarn.lock", "npm", addFinding)
	scanner.scanTextLock(root, "pnpm-lock.yaml", "npm", addFinding)
	scanner.scanTextLock(root, "bun.lock", "npm", addFinding)
	scanner.scanRequirements(root, addFinding)
	scanner.scanPoetryLock(root, addFinding)
	scanner.scanPTHFiles(root, addFinding)
	scanner.scanWorkflows(root, addFinding)
	if scanner.online {
		scanner.scanOnlineMetadata(root, addFinding)
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Severity == result.Findings[j].Severity {
			return result.Findings[i].ID < result.Findings[j].ID
		}
		return severityRank(result.Findings[i].Severity) > severityRank(result.Findings[j].Severity)
	})
	return result, nil
}

func (scanner *Scanner) scanPackageJSON(root string, addFinding func(report.Finding)) {
	path := filepath.Join(root, "package.json")
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	rel := "package.json"
	var pkg struct {
		Scripts              map[string]string `json:"scripts"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		addFinding(report.Finding{
			ID:          "risk.npm.invalid-package-json",
			Title:       "package.json could not be parsed",
			Severity:    report.SeverityMedium,
			Confidence:  "high",
			Ecosystem:   "npm",
			File:        rel,
			Evidence:    err.Error(),
			Remediation: "Fix package.json so dependency and lifecycle-script checks can run reliably.",
		})
		return
	}
	if !hasJavaScriptLockfile(root) {
		addFinding(report.Finding{
			ID:          "risk.npm.missing-lockfile",
			Title:       "JavaScript project has no lockfile",
			Severity:    report.SeverityHigh,
			Confidence:  "high",
			Ecosystem:   "npm",
			File:        rel,
			Evidence:    "package.json exists without package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock, or bun.lockb",
			Remediation: "Commit a package-manager lockfile and use deterministic installs in CI.",
		})
	}
	for name, script := range pkg.Scripts {
		lower := strings.ToLower(script)
		if isLifecycleScript(name) && looksLikeNetworkShell(lower) {
			addFinding(report.Finding{
				ID:          "risk.npm.lifecycle-network-shell",
				Title:       "Lifecycle script executes network or shell loader behavior",
				Severity:    report.SeverityCritical,
				Confidence:  "medium",
				Ecosystem:   "npm",
				File:        rel,
				Evidence:    fmt.Sprintf("%s: %s", name, script),
				Remediation: "Remove network-loading lifecycle scripts or require a reviewed, pinned build step outside install hooks.",
			})
		}
	}
	for dep, version := range mergeDependencyMaps(pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies) {
		if isFloatingRange(version) {
			addFinding(report.Finding{
				ID:          "risk.npm.floating-range",
				Title:       "Dependency uses a floating version range",
				Severity:    report.SeverityMedium,
				Confidence:  "high",
				Ecosystem:   "npm",
				PackageName: dep,
				Version:     version,
				File:        rel,
				Evidence:    fmt.Sprintf("%s: %s", dep, version),
				Remediation: "Pin versions through a committed lockfile and require deterministic installs in CI.",
			})
		}
	}
}

func (scanner *Scanner) scanNPMLock(root, name string, addFinding func(report.Finding)) {
	path := filepath.Join(root, name)
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return
	}
	scanner.scanNPMLockIOCs(name, string(content), addFinding)
	for packagePath, item := range lock.Packages {
		if item.Version == "" || !strings.Contains(packagePath, "node_modules/") {
			continue
		}
		packageName := packagePath[strings.LastIndex(packagePath, "node_modules/")+len("node_modules/"):]
		scanner.addKnownPackageFinding("npm", packageName, item.Version, name, addFinding)
	}
	for packageName, item := range lock.Dependencies {
		scanner.addKnownPackageFinding("npm", packageName, item.Version, name, addFinding)
	}
}

func (scanner *Scanner) scanNPMLockIOCs(name, content string, addFinding func(report.Finding)) {
	lower := strings.ToLower(content)
	if strings.Contains(lower, "@tanstack/setup") || strings.Contains(lower, "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c") || strings.Contains(lower, "router_init.js") {
		addFinding(report.Finding{
			ID:          "risk.npm.tanstack-optional-dependency-ioc",
			Title:       "TanStack Mini Shai-Hulud optional dependency indicator found",
			Severity:    report.SeverityCritical,
			Confidence:  "high",
			Ecosystem:   "npm",
			File:        name,
			Evidence:    "@tanstack/setup or orphan git dependency indicator",
			Remediation: "Treat the install environment as compromised, remove the affected dependency state, reinstall from a clean lockfile, and rotate exposed credentials.",
			References:  []string{"https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx"},
		})
	}
}

func (scanner *Scanner) scanTextLock(root, name, ecosystem string, addFinding func(report.Finding)) {
	path := filepath.Join(root, name)
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	text := string(content)
	for _, rule := range scanner.feed.Rules {
		if rule.Ecosystem != ecosystem {
			continue
		}
		for _, version := range rule.Versions {
			if strings.Contains(text, rule.PackageName) && strings.Contains(text, version) {
				scanner.addKnownPackageFinding(ecosystem, rule.PackageName, version, name, addFinding)
			}
		}
	}
}

func (scanner *Scanner) scanRequirements(root string, addFinding func(report.Finding)) {
	matches, _ := filepath.Glob(filepath.Join(root, "requirements*.txt"))
	for _, path := range matches {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		rel := relPath(root, path)
		for _, line := range strings.Split(string(content), "\n") {
			name, version, ok := parsePinnedRequirement(line)
			if ok {
				scanner.addKnownPackageFinding("pip", name, version, rel, addFinding)
			}
		}
	}
}

func (scanner *Scanner) scanPoetryLock(root string, addFinding func(report.Finding)) {
	path := filepath.Join(root, "poetry.lock")
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	name := ""
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		}
		if strings.HasPrefix(line, "version = ") && name != "" {
			version := strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
			scanner.addKnownPackageFinding("pip", name, version, "poetry.lock", addFinding)
			name = ""
		}
	}
}

func (scanner *Scanner) scanPTHFiles(root string, addFinding func(report.Finding)) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pth") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		lower := strings.ToLower(string(content))
		if strings.Contains(lower, "import ") && (strings.Contains(lower, "urllib") || strings.Contains(lower, "subprocess") || strings.Contains(lower, "os.system") || strings.Contains(lower, "http://") || strings.Contains(lower, "https://")) {
			addFinding(report.Finding{
				ID:          "risk.pypi.pth-exec",
				Title:       "Python .pth file executes code during interpreter startup",
				Severity:    report.SeverityCritical,
				Confidence:  "medium",
				Ecosystem:   "pip",
				File:        relPath(root, path),
				Evidence:    firstLine(string(content)),
				Remediation: "Remove unexpected .pth executable code and rebuild the virtual environment from trusted, hashed requirements.",
			})
		}
		return nil
	})
}

func (scanner *Scanner) scanWorkflows(root string, addFinding func(report.Finding)) {
	workflowRoot := filepath.Join(root, ".github", "workflows")
	_ = filepath.WalkDir(workflowRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !(strings.HasSuffix(entry.Name(), ".yml") || strings.HasSuffix(entry.Name(), ".yaml")) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		scanner.scanWorkflowContent(root, path, string(content), addFinding)
		return nil
	})
}

func (scanner *Scanner) scanWorkflowContent(root, path, content string, addFinding func(report.Finding)) {
	rel := relPath(root, path)
	lower := strings.ToLower(content)
	if strings.Contains(lower, "pull_request_target") {
		addFinding(report.Finding{
			ID:          "risk.github.pull-request-target",
			Title:       "Workflow uses pull_request_target",
			Severity:    report.SeverityHigh,
			Confidence:  "high",
			Ecosystem:   "github-actions",
			File:        rel,
			Evidence:    "pull_request_target",
			Remediation: "Use pull_request for untrusted code, or split privileged release automation into a separate trusted workflow.",
		})
	}
	if strings.Contains(lower, "actions/checkout") && strings.Contains(lower, "pull_request_target") && checksOutUntrustedPullRequestRef(lower) {
		addFinding(report.Finding{
			ID:          "risk.github.untrusted-checkout",
			Title:       "Privileged workflow checks out untrusted pull request code",
			Severity:    report.SeverityCritical,
			Confidence:  "high",
			Ecosystem:   "github-actions",
			File:        rel,
			Evidence:    "actions/checkout reads a pull request ref under pull_request_target",
			Remediation: "Never run untrusted pull request code with write tokens or repository secrets.",
		})
	}
	if strings.Contains(lower, "permissions: write-all") || (strings.Contains(lower, "contents: write") && !isTrustedReleaseWorkflow(lower)) {
		addFinding(report.Finding{
			ID:          "risk.github.broad-permissions",
			Title:       "Workflow grants broad token permissions",
			Severity:    report.SeverityHigh,
			Confidence:  "high",
			Ecosystem:   "github-actions",
			File:        rel,
			Evidence:    "write-all or contents: write",
			Remediation: "Default to contents: read and grant write scopes only to trusted release jobs.",
		})
	}
	if strings.Contains(lower, "id-token: write") && !strings.Contains(lower, "release") && !strings.Contains(lower, "publish") && !strings.Contains(lower, "deploy") {
		addFinding(report.Finding{
			ID:          "risk.github.unsafe-oidc",
			Title:       "OIDC token permission is enabled outside a release or deploy job",
			Severity:    report.SeverityHigh,
			Confidence:  "medium",
			Ecosystem:   "github-actions",
			File:        rel,
			Evidence:    "id-token: write",
			Remediation: "Grant id-token: write only to trusted jobs that exchange OIDC tokens with a constrained cloud role.",
		})
	}
	if hasUnpinnedAction(content) {
		addFinding(report.Finding{
			ID:          "risk.github.unpinned-action",
			Title:       "Workflow action is not pinned to a full commit SHA",
			Severity:    report.SeverityMedium,
			Confidence:  "high",
			Ecosystem:   "github-actions",
			File:        rel,
			Evidence:    "uses: owner/action@tag",
			Remediation: "Pin third-party actions to a reviewed 40-character commit SHA.",
		})
	}
	if strings.Contains(lower, "actions/cache") && (strings.Contains(lower, "github.ref") || strings.Contains(lower, "pull_request")) {
		addFinding(report.Finding{
			ID:          "risk.github.cache-poisoning",
			Title:       "Workflow cache key can cross trust boundaries",
			Severity:    report.SeverityHigh,
			Confidence:  "medium",
			Ecosystem:   "github-actions",
			File:        rel,
			Evidence:    "actions/cache with PR or ref-derived key",
			Remediation: "Separate trusted and untrusted cache scopes and never restore untrusted dependency caches in privileged jobs.",
		})
	}
	if hasNondeterministicInstall(lower) {
		addFinding(report.Finding{
			ID:          "risk.github.nondeterministic-install",
			Title:       "Workflow uses a non-deterministic install command",
			Severity:    report.SeverityMedium,
			Confidence:  "high",
			Ecosystem:   "github-actions",
			File:        rel,
			Evidence:    "install command without frozen lockfile or hash enforcement",
			Remediation: "Use npm ci, yarn install --immutable, pnpm install --frozen-lockfile, bun install --frozen-lockfile, or pip install --require-hashes.",
		})
	}
}

func (scanner *Scanner) addKnownPackageFinding(ecosystem, name, version, file string, addFinding func(report.Finding)) {
	rule, ok := intel.MatchPackage(scanner.feed, ecosystem, name, version)
	if !ok {
		return
	}
	severity := report.Severity(rule.Severity)
	if severity == "" {
		severity = report.SeverityCritical
	}
	addFinding(report.Finding{
		ID:          rule.ID,
		Title:       rule.Title,
		Severity:    severity,
		Confidence:  "high",
		Ecosystem:   ecosystem,
		PackageName: name,
		Version:     version,
		File:        file,
		Evidence:    fmt.Sprintf("%s@%s", name, version),
		Remediation: rule.Remediation,
		References:  rule.References,
	})
}

func parsePinnedRequirement(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "==") {
		return "", "", false
	}
	parts := strings.SplitN(line, "==", 2)
	name := strings.ToLower(strings.TrimSpace(parts[0]))
	version := strings.TrimSpace(strings.Split(parts[1], " ")[0])
	return name, version, name != "" && version != ""
}

func mergeDependencyMaps(maps ...map[string]string) map[string]string {
	merged := map[string]string{}
	for _, source := range maps {
		for key, value := range source {
			merged[key] = value
		}
	}
	return merged
}

func isLifecycleScript(name string) bool {
	switch name {
	case "preinstall", "install", "postinstall", "prepare", "prepublish", "prepack", "postpack":
		return true
	default:
		return false
	}
}

func looksLikeNetworkShell(script string) bool {
	network := strings.Contains(script, "http://") || strings.Contains(script, "https://") || strings.Contains(script, "curl ") || strings.Contains(script, "wget ") || strings.Contains(script, "invoke-webrequest")
	shell := strings.Contains(script, " bash") || strings.Contains(script, "|bash") || strings.Contains(script, "| bash") || strings.Contains(script, " sh") || strings.Contains(script, "powershell") || strings.Contains(script, "node -e")
	return network && shell
}

func isFloatingRange(version string) bool {
	version = strings.TrimSpace(version)
	return version == "*" || version == "latest" || strings.HasPrefix(version, "^") || strings.HasPrefix(version, "~") || strings.HasPrefix(version, ">") || strings.Contains(version, "x")
}

func hasUnpinnedAction(content string) bool {
	re := regexp.MustCompile(`(?m)uses:\s*[^@\s]+@([^\s]+)`)
	for _, match := range re.FindAllStringSubmatch(content, -1) {
		ref := strings.Trim(match[1], `"'`)
		if !regexp.MustCompile(`^[0-9a-fA-F]{40}$`).MatchString(ref) {
			return true
		}
	}
	return false
}

func checksOutUntrustedPullRequestRef(content string) bool {
	return strings.Contains(content, "github.event.pull_request.head.sha") ||
		strings.Contains(content, "github.event.pull_request.head.ref") ||
		strings.Contains(content, "refs/pull/${{ github.event.pull_request.number }}/merge") ||
		strings.Contains(content, "refs/pull/${{github.event.pull_request.number}}/merge")
}

func isTrustedReleaseWorkflow(content string) bool {
	if strings.Contains(content, "pull_request") {
		return false
	}
	return strings.Contains(content, "tags:") ||
		strings.Contains(content, "release:") ||
		strings.Contains(content, "gh release create")
}

func hasNondeterministicInstall(content string) bool {
	return strings.Contains(content, "npm install") ||
		strings.Contains(content, "yarn install\n") ||
		strings.Contains(content, "pnpm install\n") ||
		(strings.Contains(content, "bun install") && !strings.Contains(content, "bun install --frozen-lockfile")) ||
		(strings.Contains(content, "pip install -r") && !strings.Contains(content, "--require-hashes"))
}

func hasJavaScriptLockfile(root string) bool {
	for _, name := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"} {
		if exists(filepath.Join(root, name)) {
			return true
		}
	}
	return false
}

func severityRank(severity report.Severity) int {
	switch severity {
	case report.SeverityCritical:
		return 5
	case report.SeverityHigh:
		return 4
	case report.SeverityMedium:
		return 3
	case report.SeverityLow:
		return 2
	default:
		return 1
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

func firstLine(value string) string {
	line, _, _ := strings.Cut(value, "\n")
	if len(line) > 180 {
		return line[:180] + "..."
	}
	return line
}
