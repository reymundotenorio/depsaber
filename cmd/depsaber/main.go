package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/depsaber/depsaber/internal/baseline"
	"github.com/depsaber/depsaber/internal/clean"
	"github.com/depsaber/depsaber/internal/harden"
	"github.com/depsaber/depsaber/internal/initgen"
	"github.com/depsaber/depsaber/internal/intel"
	"github.com/depsaber/depsaber/internal/output"
	"github.com/depsaber/depsaber/internal/report"
	"github.com/depsaber/depsaber/internal/scanner"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "depsaber:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout)
	case "report":
		return runReport(args[1:], stdout)
	case "baseline":
		return runBaseline(args[1:], stdout)
	case "harden":
		return runHarden(args[1:], stdout)
	case "clean":
		return runClean(args[1:], stdout)
	case "init":
		return runInit(args[1:], stdout)
	case "update":
		return runUpdate(args[1:], stdout)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "depsaber %s\n", version)
		return nil
	case "help", "--help", "-h":
		printUsage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runScan(args []string, stdout io.Writer) error {
	root, flagArgs, err := splitOptionalPath(args, map[string]bool{"format": true, "fail-on": true, "baseline": true, "fail-on-new": true})
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	format := flags.String("format", "text", "output format: text or json")
	online := flags.Bool("online", false, "enable live registry metadata checks")
	failOn := flags.String("fail-on", "", "exit with failure on severity: high or critical")
	baselinePath := flags.String("baseline", "", "compare findings against a DepSaber baseline file")
	failOnNew := flags.String("fail-on-new", "", "exit with failure on new finding severity: high or critical")
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	result, err := scanner.New(scanner.Options{Root: root, Feed: intel.BuiltinFeed(), Online: *online}).Scan()
	if err != nil {
		return err
	}
	result.ToolVersion = version
	result.Online = *online
	if err := applyBaselineIfRequested(&result, *baselinePath); err != nil {
		return err
	}
	rendered, err := render(result, *format)
	if err != nil {
		return err
	}
	fmt.Fprint(stdout, rendered)
	if err := failIfNewNeeded(result, *failOnNew); err != nil {
		return err
	}
	return failIfNeeded(result, *failOn)
}

func runReport(args []string, stdout io.Writer) error {
	root, flagArgs, err := splitOptionalPath(args, map[string]bool{"out": true, "fail-on": true, "baseline": true, "fail-on-new": true})
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	out := flags.String("out", ".depsaber/report.json", "report output path")
	online := flags.Bool("online", false, "enable live registry metadata checks")
	failOn := flags.String("fail-on", "", "exit with failure on severity: high or critical")
	baselinePath := flags.String("baseline", "", "compare findings against a DepSaber baseline file")
	failOnNew := flags.String("fail-on-new", "", "exit with failure on new finding severity: high or critical")
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	result, err := scanner.New(scanner.Options{Root: root, Feed: intel.BuiltinFeed(), Online: *online}).Scan()
	if err != nil {
		return err
	}
	result.ToolVersion = version
	result.Online = *online
	if err := applyBaselineIfRequested(&result, *baselinePath); err != nil {
		return err
	}
	rendered, err := output.JSON(result)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(rendered), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Report written to %s\n", *out)
	if err := failIfNewNeeded(result, *failOnNew); err != nil {
		return err
	}
	return failIfNeeded(result, *failOn)
}

func runBaseline(args []string, stdout io.Writer) error {
	root, flagArgs, err := splitOptionalPath(args, map[string]bool{"out": true})
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("baseline", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	out := flags.String("out", ".depsaber/baseline.json", "baseline output path")
	online := flags.Bool("online", false, "enable live registry metadata checks")
	apply := flags.Bool("apply", false, "write the baseline file")
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if !*apply {
		return errors.New("baseline writes files only when --apply is provided")
	}
	result, err := scanner.New(scanner.Options{Root: root, Feed: intel.BuiltinFeed(), Online: *online}).Scan()
	if err != nil {
		return err
	}
	result.ToolVersion = version
	result.Online = *online
	snapshot := baseline.NewSnapshot(result)
	rendered, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	outPath, err := resolveProjectOutputPath(root, *out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, append(rendered, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Baseline written to %s (%d finding(s)).\n", outPath, len(snapshot.Findings))
	return nil
}

func runHarden(args []string, stdout io.Writer) error {
	root, flagArgs, err := splitOptionalPath(args, map[string]bool{"policy": true})
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("harden", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	apply := flags.Bool("apply", false, "apply hardening changes")
	policy := flags.String("policy", "standard", "hardening policy: standard or strict")
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if !*apply {
		return errors.New("harden is read-only unless --apply is provided")
	}
	result, err := harden.New(harden.Options{Root: root, Policy: *policy, Apply: *apply}).Run()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Applied %d hardening action(s).\n", len(result.Actions))
	return nil
}

func runClean(args []string, stdout io.Writer) error {
	root, flagArgs, err := splitOptionalPath(args, map[string]bool{"backup-dir": true})
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("clean", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	apply := flags.Bool("apply", false, "apply cleanup changes")
	backupDir := flags.String("backup-dir", ".depsaber/backups", "backup directory inside the project")
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if !*apply {
		return errors.New("clean is read-only unless --apply is provided")
	}
	if !filepath.IsAbs(*backupDir) {
		*backupDir = filepath.Join(root, *backupDir)
	}
	result, err := clean.New(clean.Options{Root: root, Apply: *apply, BackupDir: *backupDir}).Run()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Quarantined %d project artifact(s).\n", len(result.Actions))
	return nil
}

func runInit(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("init requires a subcommand: schedule or ci")
	}
	switch args[0] {
	case "schedule":
		return runInitSchedule(args[1:], stdout)
	case "ci":
		return runInitCI(args[1:], stdout)
	default:
		return fmt.Errorf("unknown init subcommand %q", args[0])
	}
}

func runInitSchedule(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("init schedule", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	target := flags.String("target", "cron", "schedule target: launchd, cron, systemd, or windows-task")
	runAt := flags.String("time", "09:00", "daily run time in HH:MM")
	apply := flags.Bool("apply", false, "write the schedule template")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*apply {
		return errors.New("init schedule writes files only when --apply is provided")
	}
	projectPath, err := os.Getwd()
	if err != nil {
		return err
	}
	template, err := initgen.GenerateSchedule(initgen.ScheduleOptions{Target: *target, ProjectPath: projectPath, Time: *runAt})
	if err != nil {
		return err
	}
	if err := writeTemplate(template); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Schedule template written to %s\n", template.Path)
	return nil
}

func runInitCI(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("init ci", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	target := flags.String("target", "github", "CI target: github, gitlab, circleci, azure, or generic")
	apply := flags.Bool("apply", false, "write the CI template")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*apply {
		return errors.New("init ci writes files only when --apply is provided")
	}
	template, err := initgen.GenerateCI(initgen.CIOptions{Target: *target})
	if err != nil {
		return err
	}
	if err := writeTemplate(template); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "CI template written to %s\n", template.Path)
	return nil
}

func runUpdate(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	source := flags.String("source", "default", "feed source: default, file path, or URL")
	if err := flags.Parse(args); err != nil {
		return err
	}
	feed := intel.BuiltinFeed()
	if *source != "default" {
		loaded, err := loadFeed(*source)
		if err != nil {
			return err
		}
		feed = loaded
	}
	rendered, err := json.MarshalIndent(feed, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(".depsaber", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(".depsaber/feed.json", append(rendered, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Feed %s written to .depsaber/feed.json\n", feed.Version)
	return nil
}

func loadFeed(source string) (intel.Feed, error) {
	var content []byte
	var err error
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		client := http.Client{Timeout: 15 * time.Second}
		response, err := client.Get(source)
		if err != nil {
			return intel.Feed{}, err
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode > 299 {
			return intel.Feed{}, fmt.Errorf("feed download failed with status %s", response.Status)
		}
		content, err = io.ReadAll(response.Body)
	} else {
		content, err = os.ReadFile(source)
	}
	if err != nil {
		return intel.Feed{}, err
	}
	var feed intel.Feed
	if err := json.Unmarshal(content, &feed); err != nil {
		return intel.Feed{}, err
	}
	if feed.Version == "" {
		return intel.Feed{}, errors.New("feed version is required")
	}
	if feed.Signature == "" {
		return intel.Feed{}, errors.New("external feeds must be signed")
	}
	publicKeyText := os.Getenv("DEPSABER_FEED_PUBLIC_KEY_BASE64")
	if publicKeyText == "" {
		return intel.Feed{}, errors.New("DEPSABER_FEED_PUBLIC_KEY_BASE64 is required to verify external feeds")
	}
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyText)
	if err != nil {
		return intel.Feed{}, fmt.Errorf("decode feed public key: %w", err)
	}
	return intel.VerifySignedFeed(feed, ed25519.PublicKey(publicKey), time.Now().UTC())
}

func applyBaselineIfRequested(result *report.Report, path string) error {
	if path == "" {
		return nil
	}
	snapshot, err := loadBaseline(path)
	if err != nil {
		return err
	}
	baseline.Apply(result, snapshot, path)
	return nil
}

func loadBaseline(path string) (baseline.Snapshot, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return baseline.Snapshot{}, err
	}
	var snapshot baseline.Snapshot
	if err := json.Unmarshal(content, &snapshot); err != nil {
		return baseline.Snapshot{}, err
	}
	if snapshot.SchemaVersion == "" {
		return baseline.Snapshot{}, errors.New("baseline schemaVersion is required")
	}
	return snapshot, nil
}

func render(result report.Report, format string) (string, error) {
	switch format {
	case "text":
		return output.Text(result), nil
	case "json":
		return output.JSON(result)
	default:
		return "", fmt.Errorf("unsupported format %q", format)
	}
}

func failIfNewNeeded(result report.Report, threshold string) error {
	if threshold == "" {
		return nil
	}
	if result.Baseline == nil {
		return errors.New("--fail-on-new requires --baseline")
	}
	minimum, err := parseSeverity(threshold)
	if err != nil {
		return err
	}
	for _, finding := range result.Findings {
		if finding.Status == "new" && severityRank(finding.Severity) >= severityRank(minimum) {
			return fmt.Errorf("new finding %s meets fail-on-new threshold %s", finding.ID, threshold)
		}
	}
	return nil
}

func failIfNeeded(result report.Report, threshold string) error {
	if threshold == "" {
		return nil
	}
	minimum, err := parseSeverity(threshold)
	if err != nil {
		return err
	}
	for _, finding := range result.Findings {
		if severityRank(finding.Severity) >= severityRank(minimum) {
			return fmt.Errorf("finding %s meets fail-on threshold %s", finding.ID, threshold)
		}
	}
	return nil
}

func parseSeverity(value string) (report.Severity, error) {
	switch strings.ToLower(value) {
	case "critical":
		return report.SeverityCritical, nil
	case "high":
		return report.SeverityHigh, nil
	default:
		return "", fmt.Errorf("unsupported fail-on severity %q", value)
	}
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
	default:
		return 1
	}
}

func writeTemplate(template initgen.Template) error {
	if err := os.MkdirAll(filepath.Dir(template.Path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(template.Path, []byte(template.Content), 0o644)
}

func resolveProjectOutputPath(root, out string) (string, error) {
	if filepath.IsAbs(out) {
		return out, nil
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.Join(absoluteRoot, filepath.FromSlash(out)), nil
}

func splitOptionalPath(args []string, valueFlags map[string]bool) (string, []string, error) {
	root := "."
	pathSet := false
	flagArgs := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			name := strings.TrimLeft(arg, "-")
			if before, _, ok := strings.Cut(name, "="); ok {
				name = before
			}
			if valueFlags[name] && !strings.Contains(arg, "=") {
				if index+1 >= len(args) {
					return "", nil, fmt.Errorf("flag %s requires a value", arg)
				}
				index++
				flagArgs = append(flagArgs, args[index])
			}
			continue
		}
		if pathSet {
			return "", nil, fmt.Errorf("unexpected extra path argument %q", arg)
		}
		root = arg
		pathSet = true
	}
	return root, flagArgs, nil
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, `DepSaber supply-chain shield

Usage:
  depsaber scan [path] --format text|json --online --baseline .depsaber/baseline.json --fail-on high|critical --fail-on-new high|critical
  depsaber baseline [path] --apply --out .depsaber/baseline.json
  depsaber update --source default|file|url
  depsaber harden [path] --apply --policy standard|strict
  depsaber clean [path] --apply --backup-dir .depsaber/backups
  depsaber report [path] --out .depsaber/report.json --baseline .depsaber/baseline.json --fail-on-new high|critical
  depsaber init schedule --target launchd|cron|systemd|windows-task --time 09:00 --apply
  depsaber init ci --target github|gitlab|circleci|azure|generic --apply

Scan is read-only. Baseline, hardening, cleanup, and init commands require --apply before writing files.`)
}
