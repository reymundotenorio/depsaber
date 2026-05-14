package intel

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func TestVerifySignedFeedAcceptsValidSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	feed := Feed{
		Version:   "2026.05.13",
		IssuedAt:  time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC),
		Rules: []Rule{{
			ID:          "malicious.npm.axios",
			Ecosystem:   "npm",
			PackageName: "axios",
			Versions:    []string{"1.14.1"},
			Severity:    "critical",
			Title:       "Known compromised Axios release",
			Remediation: "Remove the compromised release and reinstall from a trusted lockfile.",
		}},
	}
	payload, err := CanonicalPayload(feed)
	if err != nil {
		t.Fatal(err)
	}
	feed.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))

	verified, err := VerifySignedFeed(feed, publicKey, time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("expected valid feed, got error: %v", err)
	}
	if verified.Version != "2026.05.13" {
		t.Fatalf("unexpected feed version: %s", verified.Version)
	}
}

func TestVerifySignedFeedRejectsInvalidSignature(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	feed := Feed{
		Version:   "2026.05.13",
		IssuedAt:  time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC),
		Rules:     []Rule{{ID: "malicious.npm.axios", Ecosystem: "npm", PackageName: "axios", Versions: []string{"1.14.1"}}},
		Signature: base64.StdEncoding.EncodeToString([]byte("not a valid signature")),
	}

	if _, err := VerifySignedFeed(feed, publicKey, time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected invalid signature to be rejected")
	}
}

func TestVerifySignedFeedRejectsExpiredFeed(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	feed := Feed{
		Version:   "2026.04.01",
		IssuedAt:  time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
		Rules:     []Rule{{ID: "malicious.pypi.litellm", Ecosystem: "pip", PackageName: "litellm", Versions: []string{"1.82.7"}}},
	}
	payload, err := CanonicalPayload(feed)
	if err != nil {
		t.Fatal(err)
	}
	feed.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))

	if _, err := VerifySignedFeed(feed, publicKey, time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected expired feed to be rejected")
	}
}
