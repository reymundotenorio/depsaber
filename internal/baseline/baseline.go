package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/depsaber/depsaber/internal/report"
)

type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	ToolVersion   string    `json:"toolVersion"`
	GeneratedAt   time.Time `json:"generatedAt"`
	Root          string    `json:"root"`
	FeedVersion   string    `json:"feedVersion"`
	Findings      []Entry   `json:"findings"`
}

type Entry struct {
	Fingerprint string          `json:"fingerprint"`
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Severity    report.Severity `json:"severity"`
	Confidence  string          `json:"confidence"`
	Ecosystem   string          `json:"ecosystem"`
	PackageName string          `json:"package,omitempty"`
	Version     string          `json:"version,omitempty"`
	File        string          `json:"file"`
	Evidence    string          `json:"evidence"`
	Remediation string          `json:"remediation"`
}

func NewSnapshot(input report.Report) Snapshot {
	snapshot := Snapshot{
		SchemaVersion: "1.0",
		ToolVersion:   input.ToolVersion,
		GeneratedAt:   input.GeneratedAt,
		Root:          input.Root,
		FeedVersion:   input.FeedVersion,
		Findings:      make([]Entry, 0, len(input.Findings)),
	}
	for _, finding := range input.Findings {
		snapshot.Findings = append(snapshot.Findings, entryFromFinding(finding))
	}
	sort.Slice(snapshot.Findings, func(i, j int) bool {
		return snapshot.Findings[i].Fingerprint < snapshot.Findings[j].Fingerprint
	})
	return snapshot
}

func Apply(input *report.Report, snapshot Snapshot, path string) {
	accepted := map[string]Entry{}
	for _, entry := range snapshot.Findings {
		accepted[entry.Fingerprint] = entry
	}
	current := map[string]bool{}
	summary := report.BaselineSummary{
		Path:             path,
		NewBySeverity:    map[report.Severity]int{},
		ResolvedFindings: []report.Finding{},
	}
	for index := range input.Findings {
		fingerprint := FindingFingerprint(input.Findings[index])
		current[fingerprint] = true
		if _, ok := accepted[fingerprint]; ok {
			input.Findings[index].Status = "existing"
			summary.Existing++
			continue
		}
		input.Findings[index].Status = "new"
		summary.New++
		summary.NewBySeverity[input.Findings[index].Severity]++
	}
	for _, entry := range snapshot.Findings {
		if current[entry.Fingerprint] {
			continue
		}
		resolved := findingFromEntry(entry)
		resolved.Status = "resolved"
		summary.ResolvedFindings = append(summary.ResolvedFindings, resolved)
		summary.Resolved++
	}
	sort.Slice(summary.ResolvedFindings, func(i, j int) bool {
		if summary.ResolvedFindings[i].Severity == summary.ResolvedFindings[j].Severity {
			return summary.ResolvedFindings[i].ID < summary.ResolvedFindings[j].ID
		}
		return severityRank(summary.ResolvedFindings[i].Severity) > severityRank(summary.ResolvedFindings[j].Severity)
	})
	if len(summary.NewBySeverity) == 0 {
		summary.NewBySeverity = nil
	}
	if len(summary.ResolvedFindings) == 0 {
		summary.ResolvedFindings = nil
	}
	input.Baseline = &summary
}

func FindingFingerprint(finding report.Finding) string {
	parts := []string{
		finding.ID,
		strings.ToLower(finding.Ecosystem),
		strings.ToLower(finding.PackageName),
		finding.Version,
		finding.File,
		finding.Evidence,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func entryFromFinding(finding report.Finding) Entry {
	return Entry{
		Fingerprint: FindingFingerprint(finding),
		ID:          finding.ID,
		Title:       finding.Title,
		Severity:    finding.Severity,
		Confidence:  finding.Confidence,
		Ecosystem:   finding.Ecosystem,
		PackageName: finding.PackageName,
		Version:     finding.Version,
		File:        finding.File,
		Evidence:    finding.Evidence,
		Remediation: finding.Remediation,
	}
}

func findingFromEntry(entry Entry) report.Finding {
	return report.Finding{
		ID:          entry.ID,
		Title:       entry.Title,
		Severity:    entry.Severity,
		Confidence:  entry.Confidence,
		Ecosystem:   entry.Ecosystem,
		PackageName: entry.PackageName,
		Version:     entry.Version,
		File:        entry.File,
		Evidence:    entry.Evidence,
		Remediation: entry.Remediation,
	}
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
