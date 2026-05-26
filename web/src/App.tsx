import { useEffect, useMemo, useState } from "react";

type Severity = "info" | "low" | "medium" | "high" | "critical";

type Finding = {
  id: string;
  title: string;
  severity: Severity;
  status?: "new" | "existing" | "resolved";
  confidence: string;
  ecosystem: string;
  package?: string;
  version?: string;
  file: string;
  evidence: string;
  remediation: string;
  references?: string[];
};

type DepSaberReport = {
  schemaVersion: string;
  toolVersion: string;
  generatedAt: string;
  root: string;
  online: boolean;
  feedVersion: string;
  findings: Finding[];
  baseline?: {
    path: string;
    new: number;
    existing: number;
    resolved: number;
    newBySeverity?: Partial<Record<Severity, number>>;
    resolvedFindings?: Finding[];
  };
};

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

const commandRows = [
  {
    label: "Guided first run",
    command: "depsaber wizard",
    note: "Pick a workspace, choose scan or baseline, and generate a report without memorizing flags.",
  },
  {
    label: "Quiet CI gate",
    command: "depsaber scan . --baseline .depsaber/baseline.json --fail-on-new high --detail summary",
    note: "Fail only on new high-priority findings instead of inherited dependency debt.",
  },
  {
    label: "Pages report",
    command: "depsaber report . --out .depsaber/report.json --online",
    note: "Create a local JSON report that this static GitHub Pages viewer can open.",
  },
];

const launchSteps = [
  ["01", "Scan locally", "Run the wizard or a read-only scan in the repo you already use."],
  ["02", "Accept reality", "Create a baseline so old medium-risk noise does not hide new attacks."],
  ["03", "Gate changes", "Block new high-priority findings in CI and publish reports for review."],
];

export default function App() {
  const [report, setReport] = useState<DepSaberReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${import.meta.env.BASE_URL}sample-report.json`)
      .then((response) => {
        if (!response.ok) {
          throw new Error(`Sample report failed to load: ${response.status}`);
        }
        return response.json() as Promise<DepSaberReport>;
      })
      .then(setReport)
      .catch((loadError: unknown) => {
        setError(loadError instanceof Error ? loadError.message : "Sample report failed to load.");
      });
  }, []);

  const counts = useMemo(() => {
    const next = new Map<Severity, number>();
    for (const severity of severityOrder) {
      next.set(severity, 0);
    }
    for (const finding of report?.findings ?? []) {
      next.set(finding.severity, (next.get(finding.severity) ?? 0) + 1);
    }
    return next;
  }, [report]);

  const reportMeta = useMemo(() => {
    if (!report) {
      return {
        current: 0,
        newCount: 0,
        resolved: 0,
        priority: 0,
        generated: "Loading sample report",
      };
    }
    const priority = report.baseline
      ? (report.baseline.newBySeverity?.critical ?? 0) + (report.baseline.newBySeverity?.high ?? 0)
      : (counts.get("critical") ?? 0) + (counts.get("high") ?? 0);
    return {
      current: report.findings.length,
      newCount: report.baseline?.new ?? 0,
      resolved: report.baseline?.resolved ?? 0,
      priority,
      generated: new Date(report.generatedAt).toLocaleString(),
    };
  }, [counts, report]);

  function loadReportFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result)) as DepSaberReport;
        setReport(parsed);
        setError(null);
      } catch {
        setError("The selected file is not a valid DepSaber JSON report.");
      }
    };
    reader.readAsText(file);
  }

  return (
    <main className="siteShell">
      <nav className="topbar" aria-label="Primary">
        <a className="brand" href="#top" aria-label="DepSaber home">
          <span className="brandMark" aria-hidden="true" />
          <span>DepSaber</span>
        </a>
        <div className="navLinks">
          <a href="#quickstart">CLI</a>
          <a href="#viewer">Report</a>
          <a href="#pages">GitHub Pages</a>
        </div>
      </nav>

      <section className="hero" id="top">
        <div className="heroCopy">
          <p className="eyebrow">Local-first supply-chain radar</p>
          <h1>DepSaber</h1>
          <p className="heroLead">Know what changed before install scripts run.</p>
          <p className="heroText">
            A fast Go CLI and static report console for npm, Yarn, pnpm, Bun, pip, and GitHub Actions.
            Scan locally, accept a baseline, and fail CI only when new high-priority risk appears.
          </p>
          <div className="heroActions" aria-label="Primary actions">
            <a className="primaryAction" href="#quickstart">Run the CLI</a>
            <a className="secondaryAction" href="#viewer">Open report console</a>
          </div>
        </div>

        <aside className="terminalHero" aria-label="DepSaber terminal preview">
          <div className="terminalTop">
            <span />
            <span />
            <span />
          </div>
          <pre>{`$ depsaber scan . --detail normal
DepSaber scan summary
Findings: 7 total
Severity: critical 0, high 0, medium 6, low 1, info 0
Ecosystems with findings: npm 6, pip 1

Top finding types
- risk.npm.floating-range: 6 medium
- risk.pypi.extra-index-url: 1 low

$ depsaber wizard
? Project path  .
? Action        Delta scan`}</pre>
          <div className="saberBeam" aria-hidden="true" />
        </aside>
      </section>

      <section className="signalRow" aria-label="Current sample report signals">
        <article>
          <span>Current</span>
          <strong>{reportMeta.current}</strong>
        </article>
        <article>
          <span>New</span>
          <strong>{reportMeta.newCount}</strong>
        </article>
        <article>
          <span>Resolved</span>
          <strong>{reportMeta.resolved}</strong>
        </article>
        <article>
          <span>Priority</span>
          <strong>{reportMeta.priority}</strong>
        </article>
      </section>

      <section className="sectionGrid" id="quickstart">
        <div>
          <p className="eyebrow">Launch sequence</p>
          <h2>From first run to useful gate in one terminal.</h2>
        </div>
        <div className="sequenceList">
          {launchSteps.map(([step, title, copy]) => (
            <article className="sequenceItem" key={step}>
              <span>{step}</span>
              <div>
                <h3>{title}</h3>
                <p>{copy}</p>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="commandBoard" aria-label="Recommended commands">
        {commandRows.map((row) => (
          <article className="commandCard" key={row.label}>
            <span>{row.label}</span>
            <code>{row.command}</code>
            <p>{row.note}</p>
          </article>
        ))}
      </section>

      {error ? <div className="error">{error}</div> : null}

      <section className="reportConsole" id="viewer">
        <div className="consoleHeader">
          <div>
            <p className="eyebrow">Report console</p>
            <h2>Load a local .depsaber/report.json file.</h2>
          </div>
          <label className="uploadButton">
            <span>Load report JSON</span>
            <input
              type="file"
              accept="application/json,.json"
              onChange={(event) => {
                const file = event.currentTarget.files?.[0];
                if (file) {
                  loadReportFile(file);
                }
              }}
            />
          </label>
        </div>

        <div className="consoleMeta">
          <span>Tool {report?.toolVersion ?? "0.1.0"}</span>
          <span>Feed {report?.feedVersion ?? "loading"}</span>
          <span>{report?.online ? "Online checks on" : "Offline sample"}</span>
          <span>{reportMeta.generated}</span>
        </div>

        <div className="severityGrid" aria-label="Severity counts">
          {severityOrder.map((severity) => (
            <article className={`severityTile severity-${severity}`} key={severity}>
              <span>{severity}</span>
              <strong>{counts.get(severity) ?? 0}</strong>
            </article>
          ))}
        </div>

        <div className="findingList">
          {(report?.findings ?? []).map((finding) => (
            <article className="finding" key={`${finding.id}-${finding.file}-${finding.package ?? ""}`}>
              <div className="findingTop">
                <span className={`statusBadge severity-${finding.severity}`}>
                  {finding.status ? `${finding.status} ${finding.severity}` : finding.severity}
                </span>
                <strong>{finding.title}</strong>
              </div>
              <div className="findingData">
                <div>
                  <span>Rule</span>
                  <strong>{finding.id}</strong>
                </div>
                <div>
                  <span>Target</span>
                  <strong>{finding.package ? `${finding.package}@${finding.version}` : finding.ecosystem}</strong>
                </div>
                <div>
                  <span>File</span>
                  <strong>{finding.file}</strong>
                </div>
                <div>
                  <span>Evidence</span>
                  <strong>{finding.evidence}</strong>
                </div>
              </div>
              <p>{finding.remediation}</p>
              {finding.references?.length ? (
                <div className="references">
                  {finding.references.map((reference, index) => (
                    <a href={reference} key={reference} target="_blank" rel="noreferrer">
                      Source {index + 1}
                    </a>
                  ))}
                </div>
              ) : null}
            </article>
          ))}
        </div>
      </section>

      <section className="pagesBand" id="pages">
        <div>
          <p className="eyebrow">GitHub Pages</p>
          <h2>Static site, local data, no backend.</h2>
        </div>
        <p>
          The viewer runs as a static Vite build. GitHub Pages hosts the interface, and teams load their
          own report JSON through the browser file picker so source code and dependency data stay local.
        </p>
        <code>DEPLOY_TARGET=github-pages npm run build</code>
      </section>
    </main>
  );
}
