package feedfiles

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/depsaber/depsaber/internal/intel"
)

func TestFeedSourceFileUsesSignedFeedShape(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "feed", "base.json"))
	if err != nil {
		t.Fatal(err)
	}
	var feed intel.Feed
	if err := json.Unmarshal(content, &feed); err != nil {
		t.Fatal(err)
	}
	if feed.Version == "" || feed.IssuedAt.IsZero() || feed.ExpiresAt.IsZero() {
		t.Fatalf("feed source must include version, issuedAt, and expiresAt: %+v", feed)
	}
	if len(feed.Rules) == 0 {
		t.Fatal("feed source must include at least one rule")
	}
	if feed.Signature != "" {
		t.Fatal("feed/base.json should be unsigned source material; signing output adds signature")
	}
}

func TestFeedSigningDocumentationExists(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "feed", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, required := range []string{"Ed25519", "DEPSABER_FEED_PUBLIC_KEY_BASE64", "expiresAt", "signature"} {
		if !strings.Contains(text, required) {
			t.Fatalf("feed README should mention %q:\n%s", required, text)
		}
	}
}
