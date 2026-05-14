package initgen

import (
	"strings"
	"testing"
)

func TestScheduleTemplatesRunReadOnlyDailyScan(t *testing.T) {
	template, err := GenerateSchedule(ScheduleOptions{Target: "cron", ProjectPath: "/repo", Time: "09:00"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(template.Content, "depsaber update && depsaber scan /repo --online --format json --fail-on high") {
		t.Fatalf("expected daily scan command, got:\n%s", template.Content)
	}
	if strings.Contains(template.Content, "clean") || strings.Contains(template.Content, "harden --apply") {
		t.Fatalf("daily routine must not auto-clean or auto-harden:\n%s", template.Content)
	}
}

func TestGitHubCITemplateUsesSafeDefaults(t *testing.T) {
	template, err := GenerateCI(CIOptions{Target: "github"})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"on:",
		"schedule:",
		"pull_request:",
		"permissions:",
		"contents: read",
		"depsaber update",
		"depsaber scan . --online --format json --fail-on high",
	} {
		if !strings.Contains(template.Content, required) {
			t.Fatalf("expected GitHub template to contain %q, got:\n%s", required, template.Content)
		}
	}
	for _, forbidden := range []string{"pull_request_target", "id-token: write", "write-all"} {
		if strings.Contains(template.Content, forbidden) {
			t.Fatalf("GitHub template contains unsafe default %q:\n%s", forbidden, template.Content)
		}
	}
}

func TestGenericCITemplateWorksOutsideGitHub(t *testing.T) {
	template, err := GenerateCI(CIOptions{Target: "generic"})
	if err != nil {
		t.Fatal(err)
	}
	if template.Path != ".depsaber/ci/depsaber-scan.sh" {
		t.Fatalf("unexpected generic CI path: %s", template.Path)
	}
	if !strings.Contains(template.Content, "depsaber update") || !strings.Contains(template.Content, "depsaber scan . --online") {
		t.Fatalf("expected generic CI shell commands, got:\n%s", template.Content)
	}
}
