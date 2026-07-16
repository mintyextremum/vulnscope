# VulnScope

*[Русская версия](README.md)*

A desktop app for auditing code security. It scans local projects and public
repositories written in Rust, Python, JavaScript/TypeScript, React and more,
finding dangerous constructs, secrets in source, and known CVEs in dependencies.

All analysis runs on your machine. The only outbound request is to
[OSV.dev](https://osv.dev) with a list of package names and versions (never your
code) — and only when the CVE check is enabled.

## What it finds

**Code — 153 built-in rules** across 38 languages: command and SQL injection, XSS
(including `dangerouslySetInnerHTML`), unsafe deserialization (`pickle`,
`yaml.load`), disabled TLS verification, weak cryptography, path traversal,
`unsafe` pitfalls in Rust, and misconfigurations in Dockerfiles, GitHub
Actions. Every finding is tagged with a CWE and an OWASP Top 10 category and
comes with a concrete fix.

**Secrets — 13 patterns**: AWS keys, private keys (RSA/EC/OpenSSH/PGP), Slack,
Stripe, Google, Telegram, OpenAI/Anthropic keys, database connection strings,
hardcoded passwords, JWTs. Secret values are **masked** everywhere — in the UI
and in every export — so the report never leaks the thing it found.

**Dependencies — known CVEs** via OSV.dev for npm, PyPI, crates.io, Go modules
and more, with CVSS scoring and a 7-day local cache.

**Optional external scanners** — semgrep, bandit, cargo-audit, gitleaks,
osv-scanner, trivy, hadolint, ruff, trufflehog, npm audit. They augment the
built-in rules and install through your own package manager (a security scanner
should never download and run binaries itself).

## While the scan runs

The scan screen shows a pipeline of stages — done, in progress, ahead — built
from that run's options, so a stage that will not run is never shown waiting.
The percentage appears only where it is meaningful (reading files); on the OSV
query and external scanners a spinning arc with the stage name replaces it,
because "100%" there would mean "done" while work is still happening.

## Compare with the last scan, suppress findings

Each scan of a target stores a snapshot, and the next one shows the delta — how
many are new, fixed, unchanged. A finding is identified by a fingerprint (rule
id + path + code with whitespace collapsed, **not** the line number), so
inserting a line above it does not mark everything as "fixed and new again".

A false positive or an accepted risk is hidden with **Suppress** — a reason is
required. Entries live in `.vulnscope-ignore` **inside the project**, versioned
with the code and visible in review. Suppressed findings stay in the list with a
badge but drop out of the counts; suppression is never counted as "fixed".

## Export

The report exports to five formats: **JSON** (full data), **SARIF 2.1.0** (for
GitHub code scanning and CI dashboards — with rule dedup, severity mapping and
stable fingerprints), **Markdown** (a readable report for a PR, issue, or chat),
**CSV** (one row per finding for sorting and triage in a spreadsheet, with a
formula-injection guard), and **HTML** (a single self-contained file you open in
a browser or print to PDF). All of them follow the language on screen. The
Markdown report can also be copied straight to the clipboard (`Ctrl+K` → Copy
report) to paste into a PR or chat without a save dialog.

## Accessibility

Contrast is measured, not claimed: `npm run audit:contrast` checks WCAG 2.2 AA
for the 29 pairs the UI actually paints across all four themes, and runs the
severity colours through simulations of three colour-vision deficiencies. The
ink on any fill is computed from the fill's luminance, so a chosen accent never
leaves unreadable text.

A dedicated **Accessibility** tab collects: interface zoom (80–250%, via `zoom`
so nothing overlaps at 200%), reduce motion, hide the background glow, always
show focus, spell out severity next to counts, underline links, and larger hit
targets. The scan screen is a `role="progressbar"` with a polite live region
that announces milestones (not every frame), and the dashboard announces the
result summary.

## Language

The interface switches between Russian and English under
`Ctrl+,` → Appearance → Language; the change applies instantly and is stored in
`settings.json`. The whole shell **and** the built-in rule catalogue (finding
titles, descriptions, fixes) are translated.

## Themes

Every colour comes from one token file (`src/theme.css`) — nothing is hardcoded
in a component, syntax highlighting included. Four presets (Night, Midnight, Day,
Contrast); any token is editable under `Ctrl+,` → Appearance → Show all colors,
applied live. Themes export and import as `.vulnscope-theme.json`.

## Build

```
npm install
npm run tauri dev      # run
npm run tauri build    # bundle
```

Rust + Tauri 2 core, React + TypeScript webview. Tests: `cargo test` in
`src-tauri/`, `npm run audit:contrast` for the theme audit.

## How it works

The scan walks the tree with the `ignore` crate (respecting `.gitignore`),
skipping binaries by extension **and** content (NUL bytes in the first 8 KB),
minified bundles, and vendor directories. Rules are prefiltered with a
`RegexSet` and matched in parallel with rayon. Dependency manifests are parsed
and queried against OSV.dev in parallel waves with a disk cache. External
scanners run as separate processes and their output is parsed from real captured
runs.

Performance on a real load: ~10,000 files / 1.1M lines / 48 MB in ~18 s.
