package intel

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type Rule struct {
	ID          string   `json:"id"`
	Ecosystem   string   `json:"ecosystem"`
	PackageName string   `json:"package"`
	Versions    []string `json:"versions"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
}

type Feed struct {
	Version   string    `json:"version"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Rules     []Rule    `json:"rules"`
	Signature string    `json:"signature,omitempty"`
}

type canonicalFeed struct {
	Version   string    `json:"version"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Rules     []Rule    `json:"rules"`
}

func BuiltinFeed() Feed {
	return Feed{
		Version:   "builtin-2026.05.13",
		IssuedAt:  time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2027, 5, 13, 0, 0, 0, 0, time.UTC),
		Rules: []Rule{
			{
				ID:          "malicious.npm.axios",
				Ecosystem:   "npm",
				PackageName: "axios",
				Versions:    []string{"1.14.1", "0.30.4"},
				Severity:    "critical",
				Title:       "Known compromised Axios release",
				Remediation: "Remove the compromised Axios release, clear regenerated dependency artifacts, rotate exposed secrets, and reinstall from a trusted lockfile.",
				References:  []string{"https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/"},
			},
			{
				ID:          "malicious.npm.plain-crypto-js",
				Ecosystem:   "npm",
				PackageName: "plain-crypto-js",
				Versions:    []string{"4.2.1"},
				Severity:    "critical",
				Title:       "Known malicious plain-crypto-js release",
				Remediation: "Remove the malicious release, inspect lifecycle execution logs, and rotate credentials available to the install environment.",
				References:  []string{"https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/"},
			},
			{
				ID:          "malicious.npm.tanstack-mini-shai-hulud",
				Ecosystem:   "npm",
				PackageName: "@tanstack/*",
				Versions: []string{
					"0.0.4", "0.0.7", "0.0.47", "0.0.50",
					"1.154.12", "1.154.15",
					"1.161.9", "1.161.10", "1.161.11", "1.161.12", "1.161.13", "1.161.14",
					"1.166.12", "1.166.15", "1.166.16", "1.166.18", "1.166.19", "1.166.38", "1.166.41", "1.166.44", "1.166.45", "1.166.46", "1.166.47", "1.166.48", "1.166.49", "1.166.50", "1.166.51", "1.166.53", "1.166.54", "1.166.55", "1.166.56", "1.166.57", "1.166.58",
					"1.167.6", "1.167.9", "1.167.33", "1.167.36", "1.167.38", "1.167.41", "1.167.61", "1.167.64", "1.167.65", "1.167.68", "1.167.71",
					"1.168.3", "1.168.5", "1.168.6", "1.168.8",
					"1.169.5", "1.169.8", "1.169.23", "1.169.26",
				},
				Severity:    "critical",
				Title:       "Known TanStack Mini Shai-Hulud affected release",
				Remediation: "Remove the affected @tanstack release, reinstall from a clean lockfile, review CI install logs, and rotate credentials available to the developer or CI environment.",
				References:  []string{"https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx", "https://tanstack.com/blog/npm-supply-chain-compromise-postmortem"},
			},
			{
				ID:          "malicious.pypi.mistralai",
				Ecosystem:   "pip",
				PackageName: "mistralai",
				Versions:    []string{"2.4.6"},
				Severity:    "critical",
				Title:       "Known malicious mistralai release",
				Remediation: "Remove the compromised release, rebuild the virtual environment, and rotate credentials exposed during import or install.",
				References:  []string{"https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/"},
			},
			{
				ID:          "malicious.pypi.guardrails-ai",
				Ecosystem:   "pip",
				PackageName: "guardrails-ai",
				Versions:    []string{"0.10.1"},
				Severity:    "critical",
				Title:       "Known malicious guardrails-ai release",
				Remediation: "Remove the compromised release, rebuild the virtual environment, and rotate credentials exposed during import or install.",
				References:  []string{"https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/"},
			},
			{
				ID:          "malicious.pypi.litellm",
				Ecosystem:   "pip",
				PackageName: "litellm",
				Versions:    []string{"1.82.7", "1.82.8"},
				Severity:    "critical",
				Title:       "Known compromised LiteLLM release",
				Remediation: "Remove the compromised release, rebuild the virtual environment, and rotate credentials exposed during import or install.",
			},
		},
	}
}

func CanonicalPayload(feed Feed) ([]byte, error) {
	payload := canonicalFeed{
		Version:   feed.Version,
		IssuedAt:  feed.IssuedAt.UTC(),
		ExpiresAt: feed.ExpiresAt.UTC(),
		Rules:     feed.Rules,
	}
	return json.Marshal(payload)
}

func VerifySignedFeed(feed Feed, publicKey ed25519.PublicKey, now time.Time) (Feed, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Feed{}, fmt.Errorf("invalid public key length: %d", len(publicKey))
	}
	if feed.Signature == "" {
		return Feed{}, errors.New("feed signature is required")
	}
	signature, err := base64.StdEncoding.DecodeString(feed.Signature)
	if err != nil {
		return Feed{}, fmt.Errorf("decode feed signature: %w", err)
	}
	payload, err := CanonicalPayload(feed)
	if err != nil {
		return Feed{}, err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return Feed{}, errors.New("feed signature verification failed")
	}
	if !feed.ExpiresAt.IsZero() && now.After(feed.ExpiresAt) {
		return Feed{}, fmt.Errorf("feed expired at %s", feed.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return feed, nil
}

func MatchPackage(feed Feed, ecosystem, packageName, version string) (Rule, bool) {
	for _, rule := range feed.Rules {
		if rule.Ecosystem == ecosystem && packageMatches(rule.PackageName, packageName) && slices.Contains(rule.Versions, version) {
			return rule, true
		}
	}
	return Rule{}, false
}

func packageMatches(pattern, packageName string) bool {
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(packageName, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == packageName
}
