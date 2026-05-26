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

func TestTextSummaryDetailShowsCountsWithoutEvidenceNoise(t *testing.T) {
	input := report.Report{Findings: []report.Finding{
		{
			ID:          "risk.npm.floating-range",
			Title:       "Dependency uses a floating version range",
			Severity:    report.SeverityMedium,
			Ecosystem:   "npm",
			File:        "package.json",
			Evidence:    "left-pad: ^1.3.0",
			Remediation: "Pin versions.",
		},
		{
			ID:          "risk.pypi.extra-index-url",
			Title:       "Requirements file uses an extra package index",
			Severity:    report.SeverityLow,
			Ecosystem:   "pip",
			File:        "requirements.txt",
			Evidence:    "--extra-index-url https://test.pypi.org/simple/",
			Remediation: "Review package index configuration.",
		},
	}}

	rendered := TextWithOptions(input, TextOptions{Detail: DetailSummary})
	for _, want := range []string{
		"DepSaber scan summary",
		"Severity: critical 0, high 0, medium 1, low 1, info 0",
		"Ecosystems with findings: npm 1, pip 1",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected summary to contain %q, got:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "Evidence:") {
		t.Fatalf("summary detail should not include evidence, got:\n%s", rendered)
	}
}

func TestTextNormalDetailGroupsAndLimitsFindings(t *testing.T) {
	input := report.Report{Findings: []report.Finding{
		{ID: "risk.npm.floating-range", Title: "Dependency uses a floating version range", Severity: report.SeverityMedium, Ecosystem: "npm", File: "package.json", Evidence: "a: ^1.0.0", Remediation: "Pin versions."},
		{ID: "risk.npm.floating-range", Title: "Dependency uses a floating version range", Severity: report.SeverityMedium, Ecosystem: "npm", File: "package.json", Evidence: "b: ^1.0.0", Remediation: "Pin versions."},
		{ID: "risk.npm.floating-range", Title: "Dependency uses a floating version range", Severity: report.SeverityMedium, Ecosystem: "npm", File: "package.json", Evidence: "c: ^1.0.0", Remediation: "Pin versions."},
	}}

	rendered := TextWithOptions(input, TextOptions{Detail: DetailNormal, Limit: 2})
	for _, want := range []string{
		"Top finding types:",
		"risk.npm.floating-range: 3",
		"Examples:",
		"1 more finding(s) hidden. Use --detail full to show everything.",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected normal detail to contain %q, got:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "Remediation:") {
		t.Fatalf("normal detail should stay compact, got:\n%s", rendered)
	}
}

func TestTextFullDetailCanUseANSIColors(t *testing.T) {
	input := report.Report{Findings: []report.Finding{{
		ID:          "risk.github.pull-request-target",
		Title:       "Workflow uses pull_request_target",
		Severity:    report.SeverityHigh,
		Ecosystem:   "github-actions",
		File:        ".github/workflows/ci.yml",
		Evidence:    "pull_request_target",
		Remediation: "Use pull_request.",
	}}}

	rendered := TextWithOptions(input, TextOptions{Detail: DetailFull, Color: true})
	if !strings.Contains(rendered, "\x1b[") {
		t.Fatalf("expected ANSI color codes, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Remediation: Use pull_request.") {
		t.Fatalf("full detail should include remediation, got:\n%s", rendered)
	}
}
