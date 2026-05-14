package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/depsaber/depsaber/internal/intel"
)

func TestOnlineScanDetectsVeryNewNPMRelease(t *testing.T) {
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	client := fakeHTTPClient(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/left-pad" {
			t.Fatalf("unexpected npm metadata path: %s", request.URL.Path)
		}
		return jsonResponse(http.StatusOK, fmt.Sprintf(`{"time":{"1.3.0":"%s"}}`, now.Add(-2*time.Hour).Format(time.RFC3339))), nil
	})

	root := t.TempDir()
	writeFile(t, root, "package-lock.json", `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/left-pad": {"version": "1.3.0"}
  }
}`)

	scanner := New(Options{Root: root, Feed: intel.BuiltinFeed(), Online: true, NPMRegistryURL: "https://registry.test", HTTPClient: client})
	scanner.now = func() time.Time { return now }
	report, err := scanner.Scan()
	if err != nil {
		t.Fatal(err)
	}

	assertFinding(t, report.Findings, "risk.npm.very-new-release")
}

func TestOnlineScanDetectsVeryNewPyPIRelease(t *testing.T) {
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	client := fakeHTTPClient(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/pypi/requests/2.32.0/json" {
			t.Fatalf("unexpected PyPI metadata path: %s", request.URL.Path)
		}
		return jsonResponse(http.StatusOK, fmt.Sprintf(`{"urls":[{"upload_time_iso_8601":"%s"}]}`, now.Add(-30*time.Minute).Format("2006-01-02T15:04:05.000000Z"))), nil
	})

	root := t.TempDir()
	writeFile(t, root, "requirements.txt", "requests==2.32.0\n")

	scanner := New(Options{Root: root, Feed: intel.BuiltinFeed(), Online: true, PyPIRegistryURL: "https://pypi.test", HTTPClient: client})
	scanner.now = func() time.Time { return now }
	report, err := scanner.Scan()
	if err != nil {
		t.Fatal(err)
	}

	assertFinding(t, report.Findings, "risk.pypi.very-new-release")
}

func TestOnlineScanWarnsAndContinuesWhenRegistryFails(t *testing.T) {
	client := fakeHTTPClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadGateway, `{"error":"registry unavailable"}`), nil
	})

	root := t.TempDir()
	writeFile(t, root, "package-lock.json", `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/left-pad": {"version": "1.3.0"}
  }
}`)

	report, err := New(Options{Root: root, Feed: intel.BuiltinFeed(), Online: true, NPMRegistryURL: "https://registry.test", HTTPClient: client}).Scan()
	if err != nil {
		t.Fatal(err)
	}

	assertFinding(t, report.Findings, "warning.online.registry-unavailable")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func fakeHTTPClient(fn roundTripFunc) *http.Client {
	return &http.Client{Transport: fn}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
