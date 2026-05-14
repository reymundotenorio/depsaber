package scanner

import (
	"testing"

	"github.com/depsaber/depsaber/internal/report"
)

func assertFinding(t *testing.T, findings []report.Finding, id string) {
	t.Helper()
	for _, finding := range findings {
		if finding.ID == id {
			return
		}
	}
	t.Fatalf("expected finding %q, got %#v", id, findings)
}

func assertNoFinding(t *testing.T, findings []report.Finding, id string) {
	t.Helper()
	for _, finding := range findings {
		if finding.ID == id {
			t.Fatalf("did not expect finding %q, got %#v", id, findings)
		}
	}
}
