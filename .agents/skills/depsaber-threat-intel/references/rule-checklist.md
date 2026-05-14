# Threat Rule Checklist

For each new supply-chain incident or IOC, capture:

- Source URLs: advisory, postmortem, vendor analysis, registry page, or official docs.
- Ecosystem and package identity: exact package name, normalized casing, and affected versions.
- Attack stage: install-time script, import-time code, CI credential exposure, lockfile poisoning, typosquat, dependency confusion, or registry trust downgrade.
- Detection path: package lock, requirements file, poetry lock, workflow YAML, package-manager config, source artifact, or online metadata.
- Severity and confidence: explain whether the signal is a known compromised artifact or a behavioral risk.
- Remediation text: project cleanup, lockfile regeneration, age gate, script blocking, credential rotation, or CI hardening.
- Tests: malicious fixture, clean fixture, golden text or JSON output when output changes.
- Feed handling: update `internal/intel/feed.go`, `feed/base.json`, signed feed tests, and freshness expectations when applicable.
- Documentation: update README current coverage, recent attack patterns, limitations, and source references.
