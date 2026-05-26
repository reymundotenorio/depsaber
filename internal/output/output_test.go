package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/depsaber/depsaber/internal/report"
)

func TestJSONReportIncludesStableContractFields(t *testing.T) {
	input := report.Report{
		SchemaVersion: "1.0",
		ToolVersion:   "dev",
		GeneratedAt:   time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC),
		Root:          "/repo",
		FeedVersion:   "builtin",
		Findings: []report.Finding{{
			ID:          "malicious.npm.axios",
			Title:       "Known compromised Axios release",
			Severity:    report.SeverityCritical,
			Confidence:  "high",
			Ecosystem:   "npm",
			PackageName: "axios",
			Version:     "1.14.1",
			File:        "package-lock.json",
			Evidence:    "axios@1.14.1",
			Remediation: "Remove the compromised release.",
		}},
	}

	rendered, err := JSON(input)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(rendered), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["schemaVersion"] != "1.0" {
		t.Fatalf("missing schema version in JSON: %s", rendered)
	}
}

func TestTextReportHighlightsSeverityAndRemediation(t *testing.T) {
	input := report.Report{
		Findings: []report.Finding{{
			ID:          "risk.github.pull-request-target",
			Title:       "Risky pull_request_target workflow",
			Severity:    report.SeverityHigh,
			Ecosystem:   "github-actions",
			File:        ".github/workflows/ci.yml",
			Evidence:    "on: pull_request_target",
			Remediation: "Use pull_request for untrusted code.",
		}},
	}

	rendered := Text(input)
	for _, want := range []string{"HIGH", "risk.github.pull-request-target", "Use pull_request"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected text report to contain %q, got:\n%s", want, rendered)
		}
	}
}

func TestTextReportIncludesBaselineComparison(t *testing.T) {
	input := report.Report{
		Findings: []report.Finding{{
			ID:          "risk.pypi.pth-exec",
			Title:       "Python .pth file executes code during interpreter startup",
			Status:      "new",
			Severity:    report.SeverityCritical,
			Ecosystem:   "pip",
			File:        "src/evil.pth",
			Evidence:    "import urllib",
			Remediation: "Rebuild the virtual environment.",
		}},
		Baseline: &report.BaselineSummary{
			Path:     ".depsaber/baseline.json",
			New:      1,
			Existing: 2,
			Resolved: 3,
		},
	}

	rendered := Text(input)
	for _, want := range []string{"Baseline comparison: 1 new, 2 existing, 3 resolved", "[NEW CRITICAL]"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected text report to contain %q, got:\n%s", want, rendered)
		}
	}
}
