package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestGitHubPagesWorkflowUsesSafePinnedActions(t *testing.T) {
	content := readWorkflow(t, "pages.yml")

	for _, forbidden := range []string{"pull_request_target", "write-all", "contents: write"} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("pages workflow must not contain %q:\n%s", forbidden, content)
		}
	}
	for _, required := range []string{
		"contents: read",
		"pages: write",
		"id-token: write",
		"path: web/dist",
		"npm ci",
		"npm run build",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("pages workflow should contain %q:\n%s", required, content)
		}
	}
	assertActionsPinned(t, content)
}

func TestReleaseWorkflowBuildsMatrixAndChecksums(t *testing.T) {
	content := readWorkflow(t, "release.yml")

	for _, required := range []string{
		"GOOS=darwin GOARCH=amd64",
		"GOOS=darwin GOARCH=arm64",
		"GOOS=linux GOARCH=amd64",
		"GOOS=linux GOARCH=arm64",
		"GOOS=windows GOARCH=amd64",
		"shasum -a 256",
		"checksums.txt",
		"gh release create",
		"contents: write",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("release workflow should contain %q:\n%s", required, content)
		}
	}
	assertActionsPinned(t, content)
}

func readWorkflow(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func assertActionsPinned(t *testing.T, content string) {
	t.Helper()
	actionRef := regexp.MustCompile(`uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@([^\s]+)`)
	for _, match := range actionRef.FindAllStringSubmatch(content, -1) {
		ref := strings.Trim(match[1], `"'`)
		if !regexp.MustCompile(`^[0-9a-fA-F]{40}$`).MatchString(ref) {
			t.Fatalf("action reference is not pinned to a full commit SHA: %s", match[0])
		}
	}
}
