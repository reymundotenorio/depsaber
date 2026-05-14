package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/depsaber/depsaber/internal/report"
)

const onlineReleaseAgeGate = 72 * time.Hour

type onlinePackage struct {
	Ecosystem string
	Name      string
	Version   string
	File      string
}

func (scanner *Scanner) scanOnlineMetadata(root string, addFinding func(report.Finding)) {
	for _, pkg := range scanner.collectOnlinePackages(root) {
		switch pkg.Ecosystem {
		case "npm":
			publishedAt, err := scanner.fetchNPMReleaseTime(pkg.Name, pkg.Version)
			scanner.addOnlineReleaseFinding(pkg, publishedAt, err, addFinding)
		case "pip":
			publishedAt, err := scanner.fetchPyPIReleaseTime(pkg.Name, pkg.Version)
			scanner.addOnlineReleaseFinding(pkg, publishedAt, err, addFinding)
		}
	}
}

func (scanner *Scanner) addOnlineReleaseFinding(pkg onlinePackage, publishedAt time.Time, err error, addFinding func(report.Finding)) {
	if err != nil {
		addFinding(report.Finding{
			ID:          "warning.online.registry-unavailable",
			Title:       "Online registry metadata could not be checked",
			Severity:    report.SeverityInfo,
			Confidence:  "medium",
			Ecosystem:   pkg.Ecosystem,
			PackageName: pkg.Name,
			Version:     pkg.Version,
			File:        pkg.File,
			Evidence:    err.Error(),
			Remediation: "Retry with network access before trusting freshness-sensitive dependency changes.",
		})
		return
	}
	if scanner.now().UTC().Sub(publishedAt.UTC()) >= onlineReleaseAgeGate {
		return
	}
	ruleEcosystem := pkg.Ecosystem
	if ruleEcosystem == "pip" {
		ruleEcosystem = "pypi"
	}
	addFinding(report.Finding{
		ID:          fmt.Sprintf("risk.%s.very-new-release", ruleEcosystem),
		Title:       "Dependency version is very new in the package registry",
		Severity:    report.SeverityMedium,
		Confidence:  "medium",
		Ecosystem:   pkg.Ecosystem,
		PackageName: pkg.Name,
		Version:     pkg.Version,
		File:        pkg.File,
		Evidence:    fmt.Sprintf("%s@%s was published at %s", pkg.Name, pkg.Version, publishedAt.UTC().Format(time.RFC3339)),
		Remediation: "Delay adoption until the release clears the age gate, or require explicit review and provenance verification.",
	})
}

func (scanner *Scanner) fetchNPMReleaseTime(name, version string) (time.Time, error) {
	requestURL := scanner.npmRegistryURL + "/" + url.PathEscape(name)
	response, err := scanner.httpClient.Get(requestURL)
	if err != nil {
		return time.Time{}, fmt.Errorf("npm metadata request failed for %s@%s: %w", name, version, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return time.Time{}, fmt.Errorf("npm metadata request failed for %s@%s: %s", name, version, response.Status)
	}
	var metadata struct {
		Time map[string]string `json:"time"`
	}
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		return time.Time{}, fmt.Errorf("npm metadata could not be parsed for %s@%s: %w", name, version, err)
	}
	value := metadata.Time[version]
	if value == "" {
		return time.Time{}, fmt.Errorf("npm metadata has no publish time for %s@%s", name, version)
	}
	publishedAt, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("npm publish time could not be parsed for %s@%s: %w", name, version, err)
	}
	return publishedAt, nil
}

func (scanner *Scanner) fetchPyPIReleaseTime(name, version string) (time.Time, error) {
	requestURL := fmt.Sprintf("%s/pypi/%s/%s/json", scanner.pypiRegistryURL, url.PathEscape(name), url.PathEscape(version))
	response, err := scanner.httpClient.Get(requestURL)
	if err != nil {
		return time.Time{}, fmt.Errorf("PyPI metadata request failed for %s==%s: %w", name, version, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return time.Time{}, fmt.Errorf("PyPI metadata request failed for %s==%s: %s", name, version, response.Status)
	}
	var metadata struct {
		URLs []struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"urls"`
	}
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		return time.Time{}, fmt.Errorf("PyPI metadata could not be parsed for %s==%s: %w", name, version, err)
	}
	var newest time.Time
	for _, file := range metadata.URLs {
		if file.UploadTime == "" {
			continue
		}
		publishedAt, err := time.Parse(time.RFC3339Nano, file.UploadTime)
		if err != nil {
			return time.Time{}, fmt.Errorf("PyPI upload time could not be parsed for %s==%s: %w", name, version, err)
		}
		if publishedAt.After(newest) {
			newest = publishedAt
		}
	}
	if newest.IsZero() {
		return time.Time{}, fmt.Errorf("PyPI metadata has no upload time for %s==%s", name, version)
	}
	return newest, nil
}

func (scanner *Scanner) collectOnlinePackages(root string) []onlinePackage {
	var packages []onlinePackage
	packages = append(packages, collectNPMLockPackages(root, "package-lock.json")...)
	packages = append(packages, collectPinnedRequirements(root)...)
	packages = append(packages, collectPoetryPackages(root)...)
	return dedupeOnlinePackages(packages)
}

func collectNPMLockPackages(root, name string) []onlinePackage {
	content, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		return nil
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
		return nil
	}
	var packages []onlinePackage
	for packagePath, item := range lock.Packages {
		if item.Version == "" || !strings.Contains(packagePath, "node_modules/") {
			continue
		}
		packageName := packagePath[strings.LastIndex(packagePath, "node_modules/")+len("node_modules/"):]
		packages = append(packages, onlinePackage{Ecosystem: "npm", Name: packageName, Version: item.Version, File: name})
	}
	for packageName, item := range lock.Dependencies {
		if item.Version == "" {
			continue
		}
		packages = append(packages, onlinePackage{Ecosystem: "npm", Name: packageName, Version: item.Version, File: name})
	}
	return packages
}

func collectPinnedRequirements(root string) []onlinePackage {
	matches, _ := filepath.Glob(filepath.Join(root, "requirements*.txt"))
	var packages []onlinePackage
	for _, path := range matches {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(content), "\n") {
			name, version, ok := parsePinnedRequirement(line)
			if !ok {
				continue
			}
			packages = append(packages, onlinePackage{Ecosystem: "pip", Name: name, Version: version, File: relPath(root, path)})
		}
	}
	return packages
}

func collectPoetryPackages(root string) []onlinePackage {
	content, err := os.ReadFile(filepath.Join(root, "poetry.lock"))
	if err != nil {
		return nil
	}
	var packages []onlinePackage
	name := ""
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		}
		if strings.HasPrefix(line, "version = ") && name != "" {
			version := strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
			packages = append(packages, onlinePackage{Ecosystem: "pip", Name: name, Version: version, File: "poetry.lock"})
			name = ""
		}
	}
	return packages
}

func dedupeOnlinePackages(packages []onlinePackage) []onlinePackage {
	seen := map[string]bool{}
	var deduped []onlinePackage
	for _, pkg := range packages {
		key := pkg.Ecosystem + "\x00" + pkg.Name + "\x00" + pkg.Version + "\x00" + pkg.File
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, pkg)
	}
	return deduped
}
