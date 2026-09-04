# Changelog

All notable changes to VulnScope are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-04

First public release. VulnScope was developed privately over roughly 230 commits;
this entry describes what that adds up to rather than replaying it commit by
commit.

### Scanning

- **274 built-in rules** across 37 languages, each tagged with a CWE, an OWASP
  Top 10 category, a confidence level, and a concrete fix.
- **Deterministic data-flow (taint) analysis.** Traces user-controlled input from
  a source (request, `argv`, `stdin`) through variable assignments to a dangerous
  sink, and reports the complete `source → … → sink` path with every step
  openable in the code. Interprocedural within a file, and cross-file for
  end-to-end flows. Sanitiser-aware: escaping, parameterization, or an allowlist
  along the path breaks the flow and suppresses the finding.
- **Compromise indicators.** A dedicated category for what an attacker leaves
  behind rather than what a developer got wrong: PHP web shells, reverse shells,
  PowerShell download cradles, and packed payloads.
- **55 secret detectors** with entropy checking, so placeholders such as
  `your-api-key-here` never reach the report. Values are masked everywhere.
- **Dependency CVEs via OSV.dev** for npm, PyPI and crates manifests and
  lockfiles, with CVSS-derived severity and a 7-day on-disk cache.
- **13 external scanners** integrated when present on the machine (Semgrep,
  Bandit, Ruff, Gitleaks, TruffleHog, Trivy, Checkov, gosec, Grype, Hadolint,
  osv-scanner, cargo-audit, npm audit), normalised into one format and
  deduplicated against the built-in findings.
- **Custom rules** with a live preview, stored outside the app bundle and
  importable/exportable as a set.

### Triage and reporting

- **Security score** — one defensible number weighting each finding by severity
  and by whether the taint engine proved it reachable. Deterministic and fully
  attributable; no model, no opaque scoring.
- **Attack paths on the dashboard**, sorted by danger, each opening the finding.
- **Baseline comparison** against the previous scan of the same target, with
  findings identified by a line-number-independent fingerprint so reformatting
  does not invalidate the history or silently void suppressions.
- **Suppressions** in a project-local `.vulnscope-ignore`, with a mandatory
  reason, versioned alongside the code rather than hidden in app settings.
- **Git blame attribution** — who last touched the offending line, enabling a
  per-author breakdown in the report. Skipped where it would lie (untracked
  files, and similar).
- **Eight export formats**: JSON, SARIF 2.1.0, Markdown, CSV (formula-injection
  guarded), Excel, HTML, print-ready PDF, and 1C-loadable XML. Filtered export is
  available for the triaged subset, and says so in the document.
- **1C integration** — project and staff registry import, and an XML export the
  system loads unattended.

### Interface

- Custom title bar, resizable panels that persist across launches, a command
  palette, and fully rebindable keyboard shortcuts with conflict detection.
- **Accessibility**: WCAG 2.2 AA contrast verified by an audit across every
  theme, colour-vision simulation for severity colours, interface zoom to 250%,
  reduced motion, and live regions on the scan progress.
- **Russian and English** throughout, including the entire rule catalogue, with
  completeness enforced by an audit rather than by review.
- 18 themes, every colour from a single token file, exportable as JSON.
- Virtualised code viewer so a 24,000-line bundle does not freeze the window.

### Privacy

- All analysis runs locally. The only outbound request is to OSV.dev with package
  names and versions — never code — and only when the CVE check is enabled.
  Offline mode removes even that.
- Scanner telemetry and provider-side verification of discovered secrets are
  forced off.
- Nothing is downloaded or executed on the user's behalf; installing an external
  scanner remains a command you run yourself.

### Engineering

- 288 backend tests, Clippy clean with `-D warnings`.
- Eight audit scripts guarding failure modes that code review cannot see:
  contrast, localization completeness, SARIF shape, score maths, 1C XML shape,
  Excel workbook shape, CSS token references, and settings wiring.
- CI runs the frontend suite on Ubuntu, the backend on Windows (which is what it
  ships on), and dependency advisories on both ecosystems.

[1.0.0]: https://github.com/mintyextremum/vulnscope/releases/tag/v1.0.0
