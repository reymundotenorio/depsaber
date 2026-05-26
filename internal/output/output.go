package output

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/depsaber/depsaber/internal/report"
)

type TextDetail string

const (
	DetailSummary TextDetail = "summary"
	DetailNormal  TextDetail = "normal"
	DetailFull    TextDetail = "full"
)

type TextOptions struct {
	Detail TextDetail
	Color  bool
	Limit  int
}

func JSON(input report.Report) (string, error) {
	rendered, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return "", err
	}
	return string(rendered) + "\n", nil
}

func Text(input report.Report) string {
	return TextWithOptions(input, TextOptions{Detail: DetailFull})
}

func TextWithOptions(input report.Report, options TextOptions) string {
	if options.Detail == "" {
		options.Detail = DetailNormal
	}
	if options.Limit <= 0 {
		options.Limit = 12
	}
	switch options.Detail {
	case DetailSummary:
		return textSummary(input, options)
	case DetailNormal:
		return textNormal(input, options)
	case DetailFull:
		return textFull(input, options)
	default:
		return textNormal(input, options)
	}
}

func textSummary(input report.Report, options TextOptions) string {
	var builder strings.Builder
	builder.WriteString("DepSaber scan summary\n")
	writeSummary(&builder, input)
	if input.Baseline != nil && input.Baseline.New == 0 {
		builder.WriteString("No new findings versus baseline.\n")
	}
	return builder.String()
}

func textNormal(input report.Report, options TextOptions) string {
	var builder strings.Builder
	builder.WriteString("DepSaber scan summary\n")
	writeSummary(&builder, input)
	if len(input.Findings) == 0 {
		return builder.String()
	}
	writeTopFindingTypes(&builder, input.Findings)
	visible := findingsForNormal(input.Findings, input.Baseline != nil)
	if len(visible) == 0 {
		builder.WriteString("No new findings to show. Use --detail full to include accepted existing findings.\n")
		return builder.String()
	}
	if len(visible) > options.Limit {
		visible = visible[:options.Limit]
	}
	builder.WriteString("\nExamples:\n")
	for _, finding := range visible {
		fmt.Fprintf(&builder, "- %s %s %s", findingLabel(finding, options), finding.ID, finding.File)
		if finding.PackageName != "" {
			fmt.Fprintf(&builder, " %s@%s", finding.PackageName, finding.Version)
		}
		fmt.Fprintf(&builder, "\n")
	}
	hidden := len(findingsForNormal(input.Findings, input.Baseline != nil)) - len(visible)
	if hidden > 0 {
		fmt.Fprintf(&builder, "%d more finding(s) hidden. Use --detail full to show everything.\n", hidden)
	} else {
		builder.WriteString("Use --detail full for evidence and remediation.\n")
	}
	return builder.String()
}

func textFull(input report.Report, options TextOptions) string {
	var builder strings.Builder
	if len(input.Findings) == 0 {
		builder.WriteString("DepSaber found no supply-chain findings.\n")
		if input.Baseline != nil {
			fmt.Fprintf(&builder, "Baseline comparison: %d new, %d existing, %d resolved.\n", input.Baseline.New, input.Baseline.Existing, input.Baseline.Resolved)
		}
		return builder.String()
	}
	fmt.Fprintf(&builder, "DepSaber found %d supply-chain finding(s).\n", len(input.Findings))
	if input.Baseline != nil {
		fmt.Fprintf(&builder, "Baseline comparison: %d new, %d existing, %d resolved.\n", input.Baseline.New, input.Baseline.Existing, input.Baseline.Resolved)
	}
	builder.WriteString("\n")
	for _, finding := range input.Findings {
		fmt.Fprintf(&builder, "%s %s\n", findingLabel(finding, options), finding.Title)
		fmt.Fprintf(&builder, "ID: %s\n", finding.ID)
		fmt.Fprintf(&builder, "Ecosystem: %s\n", finding.Ecosystem)
		if finding.PackageName != "" {
			fmt.Fprintf(&builder, "Package: %s@%s\n", finding.PackageName, finding.Version)
		}
		fmt.Fprintf(&builder, "File: %s\n", finding.File)
		fmt.Fprintf(&builder, "Evidence: %s\n", finding.Evidence)
		fmt.Fprintf(&builder, "Remediation: %s\n\n", finding.Remediation)
	}
	return builder.String()
}

func writeSummary(builder *strings.Builder, input report.Report) {
	counts := severityCounts(input.Findings)
	fmt.Fprintf(builder, "Findings: %d total\n", len(input.Findings))
	fmt.Fprintf(builder, "Severity: critical %d, high %d, medium %d, low %d, info %d\n",
		counts[report.SeverityCritical],
		counts[report.SeverityHigh],
		counts[report.SeverityMedium],
		counts[report.SeverityLow],
		counts[report.SeverityInfo],
	)
	ecosystems := ecosystemCounts(input.Findings)
	if len(ecosystems) == 0 {
		builder.WriteString("Ecosystems with findings: none\n")
	} else {
		builder.WriteString("Ecosystems with findings: ")
		for index, item := range ecosystems {
			if index > 0 {
				builder.WriteString(", ")
			}
			fmt.Fprintf(builder, "%s %d", item.Name, item.Count)
		}
		builder.WriteString("\n")
	}
	if input.Baseline != nil {
		fmt.Fprintf(builder, "Baseline: %d new, %d existing, %d resolved\n", input.Baseline.New, input.Baseline.Existing, input.Baseline.Resolved)
	}
	builder.WriteString("\n")
}

func writeTopFindingTypes(builder *strings.Builder, findings []report.Finding) {
	if len(findings) == 0 {
		return
	}
	groups := findingTypeCounts(findings)
	builder.WriteString("Top finding types:\n")
	limit := len(groups)
	if limit > 5 {
		limit = 5
	}
	for _, group := range groups[:limit] {
		fmt.Fprintf(builder, "- %s: %d %s\n", group.ID, group.Count, group.Severity)
	}
}

func findingsForNormal(findings []report.Finding, hasBaseline bool) []report.Finding {
	if !hasBaseline {
		return findings
	}
	var visible []report.Finding
	for _, finding := range findings {
		if finding.Status == "new" {
			visible = append(visible, finding)
		}
	}
	return visible
}

func findingLabel(finding report.Finding, options TextOptions) string {
	label := strings.ToUpper(string(finding.Severity))
	if finding.Status != "" {
		label = strings.ToUpper(finding.Status) + " " + label
	}
	label = "[" + label + "]"
	if !options.Color {
		return label
	}
	return colorForSeverity(finding.Severity) + label + "\x1b[0m"
}

func colorForSeverity(severity report.Severity) string {
	switch severity {
	case report.SeverityCritical:
		return "\x1b[31;1m"
	case report.SeverityHigh:
		return "\x1b[33;1m"
	case report.SeverityMedium:
		return "\x1b[35m"
	case report.SeverityLow:
		return "\x1b[36m"
	case report.SeverityInfo:
		return "\x1b[37m"
	default:
		return ""
	}
}

func severityCounts(findings []report.Finding) map[report.Severity]int {
	counts := map[report.Severity]int{
		report.SeverityCritical: 0,
		report.SeverityHigh:     0,
		report.SeverityMedium:   0,
		report.SeverityLow:      0,
		report.SeverityInfo:     0,
	}
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	return counts
}

type countItem struct {
	Name     string
	ID       string
	Severity report.Severity
	Count    int
}

func ecosystemCounts(findings []report.Finding) []countItem {
	counts := map[string]int{}
	for _, finding := range findings {
		counts[finding.Ecosystem]++
	}
	items := make([]countItem, 0, len(counts))
	for name, count := range counts {
		items = append(items, countItem{Name: name, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Name < items[j].Name
		}
		return items[i].Count > items[j].Count
	})
	return items
}

func findingTypeCounts(findings []report.Finding) []countItem {
	counts := map[string]countItem{}
	for _, finding := range findings {
		item := counts[finding.ID]
		item.ID = finding.ID
		item.Severity = finding.Severity
		item.Count++
		counts[finding.ID] = item
	}
	items := make([]countItem, 0, len(counts))
	for _, item := range counts {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return severityRank(items[i].Severity) > severityRank(items[j].Severity)
		}
		return items[i].Count > items[j].Count
	})
	return items
}

func severityRank(severity report.Severity) int {
	switch severity {
	case report.SeverityCritical:
		return 5
	case report.SeverityHigh:
		return 4
	case report.SeverityMedium:
		return 3
	case report.SeverityLow:
		return 2
	case report.SeverityInfo:
		return 1
	default:
		return 0
	}
}
