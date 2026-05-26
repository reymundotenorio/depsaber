package report

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Status      string   `json:"status,omitempty"`
	Confidence  string   `json:"confidence"`
	Ecosystem   string   `json:"ecosystem"`
	PackageName string   `json:"package,omitempty"`
	Version     string   `json:"version,omitempty"`
	File        string   `json:"file"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
}

type BaselineSummary struct {
	Path             string           `json:"path"`
	New              int              `json:"new"`
	Existing         int              `json:"existing"`
	Resolved         int              `json:"resolved"`
	NewBySeverity    map[Severity]int `json:"newBySeverity,omitempty"`
	ResolvedFindings []Finding        `json:"resolvedFindings,omitempty"`
}

type Action struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	File        string `json:"file,omitempty"`
	Mode        string `json:"mode"`
	Description string `json:"description"`
}

type Report struct {
	SchemaVersion string           `json:"schemaVersion"`
	ToolVersion   string           `json:"toolVersion"`
	GeneratedAt   time.Time        `json:"generatedAt"`
	Root          string           `json:"root"`
	Online        bool             `json:"online"`
	FeedVersion   string           `json:"feedVersion"`
	FeedUpdatedAt time.Time        `json:"feedUpdatedAt"`
	Findings      []Finding        `json:"findings"`
	Baseline      *BaselineSummary `json:"baseline,omitempty"`
	Actions       []Action         `json:"actions,omitempty"`
}
