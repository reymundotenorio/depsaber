package baseline

import (
	"testing"
	"time"

	"github.com/depsaber/depsaber/internal/report"
)

func TestSnapshotUsesStableFindingFingerprints(t *testing.T) {
	finding := testFinding("risk.npm.floating-range", report.SeverityMedium, "package.json", "left-pad: ^1.3.0")
	first := FindingFingerprint(finding)
	second := FindingFingerprint(finding)
	if first == "" || first != second {
		t.Fatalf("expected stable fingerprint, got %q and %q", first, second)
	}
}

func TestApplyMarksNewExistingAndResolvedFindings(t *testing.T) {
	existing := testFinding("risk.npm.floating-range", report.SeverityMedium, "package.json", "left-pad: ^1.3.0")
	resolved := testFinding("risk.github.unpinned-action", report.SeverityMedium, ".github/workflows/ci.yml", "uses: owner/action@tag")
	snapshot := NewSnapshot(report.Report{
		SchemaVersion: "1.0",
		ToolVersion:   "dev",
		GeneratedAt:   time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
		Root:          "/repo",
		FeedVersion:   "builtin",
		Findings:      []report.Finding{existing, resolved},
	})
	newFinding := testFinding("risk.pypi.pth-exec", report.SeverityCritical, "src/evil.pth", "import urllib")
	current := report.Report{Findings: []report.Finding{existing, newFinding}}

	Apply(&current, snapshot, ".depsaber/baseline.json")

	if current.Baseline == nil {
		t.Fatal("expected baseline summary")
	}
	if current.Baseline.New != 1 || current.Baseline.Existing != 1 || current.Baseline.Resolved != 1 {
		t.Fatalf("unexpected summary: %#v", current.Baseline)
	}
	if current.Findings[0].Status != "existing" || current.Findings[1].Status != "new" {
		t.Fatalf("unexpected finding statuses: %#v", current.Findings)
	}
	if len(current.Baseline.ResolvedFindings) != 1 || current.Baseline.ResolvedFindings[0].Status != "resolved" {
		t.Fatalf("expected one resolved finding, got %#v", current.Baseline.ResolvedFindings)
	}
	if current.Baseline.NewBySeverity[report.SeverityCritical] != 1 {
		t.Fatalf("expected critical new severity count, got %#v", current.Baseline.NewBySeverity)
	}
}

func testFinding(id string, severity report.Severity, file, evidence string) report.Finding {
	return report.Finding{
		ID:          id,
		Title:       id,
		Severity:    severity,
		Confidence:  "high",
		Ecosystem:   "npm",
		PackageName: "left-pad",
		Version:     "1.3.0",
		File:        file,
		Evidence:    evidence,
		Remediation: "Fix the finding.",
	}
}
