import { useEffect, useMemo, useState } from "react";

type Severity = "info" | "low" | "medium" | "high" | "critical";

type Finding = {
  id: string;
  title: string;
  severity: Severity;
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
};

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function App() {
  const [report, setReport] = useState<DepSaberReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/sample-report.json")
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
  const priorityCount = (counts.get("critical") ?? 0) + (counts.get("high") ?? 0);

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
    <main className="shell">
      <section className="hero">
        <div className="heroText">
          <p className="eyebrow">DepSaber MVP v1</p>
          <h1>Neon-grade defense for dependency supply chains.</h1>
          <p className="heroCopy">
            Load a local <code>.depsaber/report.json</code> from the Go scanner. Nothing leaves your
            machine, and every finding maps to a concrete action for safer installs, workflows, and
            daily routines.
          </p>
          <div className="commandStrip" aria-label="recommended command">
            <span>Daily read-only routine</span>
            <code>depsaber update && depsaber scan . --online --format json --fail-on high</code>
          </div>
        </div>
        <aside className="controlDeck" aria-label="report controls">
          <div className="saberMark">
            <span />
            <span />
            <span />
          </div>
          <strong>{priorityCount}</strong>
          <p>high-priority finding(s)</p>
          <label className="upload">
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
        </aside>
      </section>

      {error ? <div className="error">{error}</div> : null}

      <section className="cards" aria-label="severity summary">
        {severityOrder.map((severity) => (
          <article className={`card ${severity}`} key={severity}>
            <span>{severity}</span>
            <strong>{counts.get(severity) ?? 0}</strong>
          </article>
        ))}
      </section>

      <section className="stance" aria-label="DepSaber protection model">
        <article>
          <span>01</span>
          <h2>Detect early</h2>
          <p>Known IOCs, lifecycle droppers, Python startup execution, floating ranges, and CI trust-boundary mistakes.</p>
        </article>
        <article>
          <span>02</span>
          <h2>Harden safely</h2>
          <p>Age gates, immutable installs, signature/provenance guidance, pinned actions, and least-privilege workflow templates.</p>
        </article>
        <article>
          <span>03</span>
          <h2>Clean carefully</h2>
          <p>Project artifacts are quarantined with backups. Host compromise response still requires rebuilds and secret rotation.</p>
        </article>
      </section>

      <section className="panel">
        <div className="panelHeader">
          <div>
            <p className="eyebrow">Report</p>
            <h2>Supply-chain findings</h2>
          </div>
          <p>{report ? `${report.findings.length} finding(s) from feed ${report.feedVersion}` : "Loading sample report..."}</p>
        </div>

        <div className="findingList">
          {(report?.findings ?? []).map((finding) => (
            <article className="finding" key={`${finding.id}-${finding.file}-${finding.package ?? ""}`}>
              <div className="findingTop">
                <span className={`badge ${finding.severity}`}>{finding.severity}</span>
                <strong>{finding.title}</strong>
              </div>
              <dl>
                <div>
                  <dt>Rule</dt>
                  <dd>{finding.id}</dd>
                </div>
                <div>
                  <dt>Target</dt>
                  <dd>
                    {finding.package ? `${finding.package}@${finding.version}` : finding.ecosystem}
                  </dd>
                </div>
                <div>
                  <dt>File</dt>
                  <dd>{finding.file}</dd>
                </div>
                <div>
                  <dt>Evidence</dt>
                  <dd>{finding.evidence}</dd>
                </div>
              </dl>
              <p className="remediation">{finding.remediation}</p>
              {finding.references?.length ? (
                <div className="references">
                  {finding.references.map((reference) => (
                    <a href={reference} key={reference} target="_blank" rel="noreferrer">
                      Source
                    </a>
                  ))}
                </div>
              ) : null}
            </article>
          ))}
        </div>
      </section>

      <section className="daily">
        <p className="eyebrow">Daily protection</p>
        <h2>Run DepSaber locally or in any CI provider.</h2>
        <p>
          The recommended routine is read-only: <code>depsaber update && depsaber scan . --online --format json --fail-on high</code>.
          Cleanup and hardening never run automatically in v1; they require explicit <code>--apply</code>.
        </p>
      </section>
    </main>
  );
}
