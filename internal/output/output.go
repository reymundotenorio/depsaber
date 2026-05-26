package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/depsaber/depsaber/internal/report"
)

func JSON(input report.Report) (string, error) {
	rendered, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return "", err
	}
	return string(rendered) + "\n", nil
}

func Text(input report.Report) string {
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
		label := strings.ToUpper(string(finding.Severity))
		if finding.Status != "" {
			label = strings.ToUpper(finding.Status) + " " + label
		}
		fmt.Fprintf(&builder, "[%s] %s\n", label, finding.Title)
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
