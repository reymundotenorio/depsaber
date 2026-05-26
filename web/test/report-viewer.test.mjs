import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const appSource = readFileSync(resolve("src/App.tsx"), "utf8");
const viteConfig = readFileSync(resolve("vite.config.ts"), "utf8");
const sampleReport = JSON.parse(readFileSync(resolve("public/sample-report.json"), "utf8"));

assert.equal(sampleReport.schemaVersion, "1.0");
assert.ok(Array.isArray(sampleReport.findings));
assert.equal(sampleReport.baseline.new, 2);
assert.ok(sampleReport.findings.some((finding) => finding.id === "risk.github.pull-request-target"));
assert.match(appSource, /DepSaber MVP v1/);
assert.match(appSource, /Supply-chain findings/);
assert.match(appSource, /Daily protection/);
assert.match(appSource, /resolved/);
assert.match(appSource, /severity/i);
assert.match(appSource, /\.depsaber\/report\.json/);
assert.match(viteConfig, /DEPLOY_TARGET/);
assert.match(viteConfig, /\/depsaber\//);
