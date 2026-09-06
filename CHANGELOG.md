# Changelog

All notable changes to VulnScope are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-09-04

Mostly corrections. Two of them are false negatives in the data-flow engine —
findings it saw and discarded — which matters more than a feature would: a
scanner that stays quiet is trusted, and that trust was misplaced.

### Fixed

- **Sanitisers are scoped to the sink category they actually protect.** One
  shared pattern used to clear taint for all eight categories at once, so an HTML
  escaper silenced a live SQL injection:

  ```python
  safe = html.escape(request.args.get('id'))
  cur.execute('SELECT * FROM t WHERE id = ' + safe)
  ```

  `escapeshellarg` now covers command injection only, `htmlspecialchars` XSS
  only, parameterisation SQL and NoSQL, `filepath.Clean` path traversal. Numeric
  coercions and allowlists still clear everything, honestly — nothing survives
  `int()`. Ambiguous wording (`escape`, `sanitize`, `encode`, `quote`) keeps the
  old blanket behaviour: the scope is unknowable from the name, and guessing
  would trade false negatives for false positives.
- **A sanitiser applied directly to a source no longer loses the flow.**
  `safe = html.escape(request.args.get('id'))` has no intermediate variable to
  carry, which is the shape most real code takes.
- **PHP is traced by the data-flow engine at all.** Every sink pattern was
  written for JavaScript and Python, and five of the eight categories matched
  nothing in PHP. SQL required a literal dot, which PHP never produces — it uses
  `->`, bare `mysqli_*`/`pg_*` functions, and Laravel's `DB::` facade. Added
  across the categories: `echo`/`print_r`/`var_dump`/`<?=` (XSS), the cURL family
  and `fsockopen` (SSRF), `header('Location: …')` (open redirect),
  `file_get_contents`/`include`/`require` and friends (path traversal, including
  local and remote file inclusion), `unserialize`/`create_function`/
  `call_user_func` (code execution), and WordPress `$wpdb` getters.
- `html.escape` and `cgi.escape` were only ever matched by the generic bucket and
  so cleared every category.
- The OSV client introduced itself as `VulnScope/0.1` long after 1.0.0 shipped.
  It now reads the version from the crate.

### Added

- **Update notification.** Once per launch VulnScope asks the releases feed for
  the latest version number and shows a dismissible bar when a newer one exists.
  It downloads nothing and runs nothing — you open the link yourself. There is
  deliberately no self-updater: one needs a signing key whose leak would mean
  arbitrary code on every install, which is the supply-chain risk this tool
  refuses to take elsewhere. It has its own setting, and offline mode overrules
  it.
- `npm run audit:i18n` now covers the data-flow heuristics. `Heuristic` is a
  separate struct from `Rule` and was never collected, so a new one could ship
  showing Russian in the English interface while the check that exists to prevent
  exactly that reported everything green.

### Changed

- Dependency updates are no longer opened on a schedule; Dependabot is left on
  security advisories only. `npm audit` and `cargo audit` still run on every push.
- The privacy statement in both READMEs and in `SECURITY.md` now documents two
  outbound requests instead of one. Any third is a valid vulnerability report.

### Security

- `h2` raised to 0.4.19, closing RUSTSEC-2026-0258 (unbounded empty DATA frames).
  It ships, via reqwest.
- `browserslist`, `nanoid` and `postcss` raised past their advisories. Build
  tooling only — none of it reaches a released binary.

### Engineering

- 311 backend tests, up from 288.

[1.1.0]: https://github.com/mintyextremum/vulnscope/releases/tag/v1.1.0

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
