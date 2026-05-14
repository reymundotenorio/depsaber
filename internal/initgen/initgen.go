package initgen

import (
	"fmt"
	"path/filepath"
	"strings"
)

type Template struct {
	Path    string
	Content string
}

type ScheduleOptions struct {
	Target      string
	ProjectPath string
	Time        string
}

type CIOptions struct {
	Target string
}

func GenerateSchedule(options ScheduleOptions) (Template, error) {
	if options.ProjectPath == "" {
		options.ProjectPath = "."
	}
	if options.Time == "" {
		options.Time = "09:00"
	}
	hour, minute, err := splitTime(options.Time)
	if err != nil {
		return Template{}, err
	}
	command := fmt.Sprintf("mkdir -p .depsaber/reports && depsaber update && depsaber scan %s --online --format json --fail-on high", shellPath(options.ProjectPath))
	switch options.Target {
	case "cron":
		return Template{
			Path: ".depsaber/schedules/depsaber.cron",
			Content: fmt.Sprintf(`# DepSaber daily read-only supply-chain scan.
%s %s * * * cd %s && %s > .depsaber/reports/$(date +\%%F).json
`, minute, hour, shellPath(options.ProjectPath), command),
		}, nil
	case "launchd":
		return Template{
			Path: ".depsaber/schedules/com.depsaber.daily.plist",
			Content: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.depsaber.daily</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-lc</string>
    <string>cd %s && %s > .depsaber/reports/$(date +%%F).json</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>%s</integer>
    <key>Minute</key><integer>%s</integer>
  </dict>
</dict>
</plist>
`, shellPath(options.ProjectPath), command, hour, minute),
		}, nil
	case "systemd":
		return Template{
			Path: ".depsaber/schedules/depsaber-daily.timer",
			Content: fmt.Sprintf(`[Unit]
Description=Run DepSaber daily

[Timer]
OnCalendar=*-*-* %s:%s:00
Persistent=true

[Install]
WantedBy=timers.target

# Service:
# [Service]
# WorkingDirectory=%s
# ExecStart=/bin/sh -lc '%s > .depsaber/reports/$(date +%%F).json'
`, hour, minute, options.ProjectPath, command),
		}, nil
	case "windows-task":
		return Template{
			Path: ".depsaber/schedules/depsaber-windows-task.xml",
			Content: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>DepSaber daily read-only supply-chain scan</Description></RegistrationInfo>
  <Triggers><CalendarTrigger><StartBoundary>2026-05-13T%s:%s:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>
  <Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>-NoProfile -Command "cd '%s'; New-Item -ItemType Directory -Force .depsaber/reports; %s | Out-File .depsaber/reports/$(Get-Date -Format yyyy-MM-dd).json"</Arguments></Exec></Actions>
</Task>
`, hour, minute, options.ProjectPath, command),
		}, nil
	default:
		return Template{}, fmt.Errorf("unsupported schedule target: %s", options.Target)
	}
}

func GenerateCI(options CIOptions) (Template, error) {
	switch options.Target {
	case "github":
		return Template{Path: ".github/workflows/depsaber.yml", Content: `name: DepSaber

on:
  pull_request:
  schedule:
    - cron: "0 9 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
      - name: Run DepSaber
        run: |
          mkdir -p .depsaber
          depsaber update
          depsaber scan . --online --format json --fail-on high > .depsaber/report.json
`}, nil
	case "gitlab":
		return Template{Path: ".gitlab-ci.yml", Content: `depsaber:
  stage: test
  script:
    - depsaber update
    - depsaber scan . --online --format json --fail-on high > .depsaber/report.json
  artifacts:
    when: always
    paths:
      - .depsaber/report.json
`}, nil
	case "circleci":
		return Template{Path: ".circleci/config.yml", Content: `version: 2.1
jobs:
  depsaber:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run: mkdir -p .depsaber
      - run: depsaber update
      - run: depsaber scan . --online --format json --fail-on high > .depsaber/report.json
workflows:
  depsaber:
    jobs:
      - depsaber
`}, nil
	case "azure":
		return Template{Path: "azure-pipelines.yml", Content: `trigger:
  - main

schedules:
  - cron: "0 9 * * *"
    displayName: Daily DepSaber scan
    branches:
      include:
        - main

steps:
  - script: |
      mkdir -p .depsaber
      depsaber update
      depsaber scan . --online --format json --fail-on high > .depsaber/report.json
    displayName: Run DepSaber
`}, nil
	case "generic":
		return Template{Path: ".depsaber/ci/depsaber-scan.sh", Content: `#!/usr/bin/env sh
set -eu

mkdir -p .depsaber
depsaber update
depsaber scan . --online --format json --fail-on high > .depsaber/report.json
`}, nil
	default:
		return Template{}, fmt.Errorf("unsupported CI target: %s", options.Target)
	}
}

func splitTime(value string) (string, string, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || len(parts[0]) != 2 || len(parts[1]) != 2 {
		return "", "", fmt.Errorf("time must use HH:MM format")
	}
	return parts[0], parts[1], nil
}

func shellPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return path
}
