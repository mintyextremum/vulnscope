# VulnScope

[![checks](https://github.com/mintyextremum/vulnscope/actions/workflows/checks.yml/badge.svg)](https://github.com/mintyextremum/vulnscope/actions/workflows/checks.yml)

*[Русская версия](README.md)*

A desktop app for auditing code security. It scans local projects and public
repositories written in Rust, Python, JavaScript/TypeScript, React and more,
finding dangerous constructs, secrets in source, and known CVEs in dependencies.

All analysis runs on your machine. The only outbound request is to
[OSV.dev](https://osv.dev) with a list of package names and versions (never your
code) — and only when the CVE check is enabled.

## What it finds

**Code — 167 built-in rules** across 38 languages: command, SQL and NoSQL
injection, XSS and SSTI, open redirects, unsafe deserialization (`pickle`,
`yaml.load`, SnakeYAML, `binary_to_term`), disabled TLS and SSH host-key
verification, weak cryptography, path traversal and Zip Slip, JWT verification
bypass, `xp_cmdshell` and file operations in SQL, `unsafe` pitfalls in Rust, and
misconfigurations in Dockerfiles, GitHub Actions, Terraform and nginx. Every
finding is tagged with a CWE and an OWASP Top 10 category and comes with a fix.

| Language | Rules |
|---|---|
| JavaScript / TypeScript / React | 29 |
| Python | 26 |
| Java / Kotlin | 12 |
| Rust | 10 |
| PHP | 10 |
| Go | 10 |
| C# | 8 |
| Terraform | 7 |
| Ruby | 7 |
| Dockerfile | 6 |
| C / C++ | 6 |
| Swift | 4 |
| SQL | 4 |
| Nginx | 4 |
| Kubernetes | 4 |
| GitHub Actions | 4 |
| Scala / Elixir | 3 each |
| Shell / PowerShell / Perl / Lua | 2 each |
| Vue / Svelte | 1 each |

Languages are detected by extension and filename — Vue, Svelte, GraphQL, SQL and
others are recognised and counted in the statistics even where no rules target
them yet.

The full catalogue, with descriptions and fixes, opens in the app under **Rules**
(`Ctrl+R`).

**Your own rules.** **Custom** (`Ctrl+E`) opens an editor: regular expression,
severity, languages, CWE/OWASP and the fix text. A live preview runs the rule
against your own sample before you save it, showing which lines were dropped by
"do not fire if it contains". Custom rules work exactly like built-in ones — same
comment and test-file handling. They live in `%APPDATA%/vulnscope/rules.json` and
the set can be imported and exported.

**Secrets — 19 detectors**: AWS keys, GitHub/GitLab/Slack/npm/PyPI tokens, Stripe,
Google and SendGrid keys, Shopify and DigitalOcean tokens, private keys, database
connection strings, JWTs. Values are checked for entropy, so `your-api-key-here`
and similar placeholders never reach the report. Secret values are **masked**
everywhere — in the UI and in every export — so the raw value never leaves the
file.

**Dependencies — CVEs via OSV.dev.** Parses `package.json`, `package-lock.json`,
`requirements.txt`, `pyproject.toml`, `Cargo.toml`, `Cargo.lock`. A lockfile wins
over a manifest: it has the exact versions. Severity is computed from the CVSS
vector, and responses are cached for 7 days — re-scanning the same project works
offline.

**External scanners (optional).** If `semgrep`, `bandit`, `cargo-audit` or
`gitleaks` are installed, their findings are picked up and normalised into the
same shape. The app is fully usable without them, but coverage is noticeably
wider with them — 197 findings instead of 155 on the test project.

| Tool | What it adds | Install |
|---|---|---|
| Semgrep | Thousands of dataflow-aware rules for 30+ languages | `pipx install semgrep` |
| Bandit | Deeper AST-based Python analysis | `pipx install bandit` |
| Ruff | Fast Python linter, bandit's security rules | `pipx install ruff` |
| cargo-audit | RustSec advisories for crates | `cargo install cargo-audit --locked` |
| Gitleaks | 150+ secret patterns | `scoop install gitleaks` |
| TruffleHog | 800+ detectors, verifies whether a key is live | `scoop install trufflehog` |
| osv-scanner | The official OSV scanner: more ecosystems | `scoop install osv-scanner` |
| Trivy | Dependency and IaC vulnerabilities, plus misconfig | `scoop install trivy` |
| Hadolint | Dockerfile linter by syntax, not by pattern | `scoop install hadolint` |
| npm audit | npm dependency audit | ships with Node.js |

Two more — **Checkov** and **govulncheck** — can be installed from the app, but
their output is not parsed yet. They are honestly marked "not wired up", excluded
from the counter, and never run.

The **External scanners** card shows the exact command and lets you copy it, but
**downloads and runs nothing itself**: a security scanner that fetches and
executes binaries becomes the very supply-chain threat it exists to find. After
installing, press **Check again**.

**Deduplication.** OSV aggregates several databases (GHSA, PYSEC, RUSTSEC), so one
vulnerability arrives as several records sharing a CVE; with cargo-audit they
overlap again. Records about the same package-version that share at least one
identifier collapse into one — with the union of their CVE/CWE ids and the worst
severity. On the test project that removes ~40% of the duplicates.

## What it doesn't analyze

Binaries (`.exe`, `.dll`, `.so`, `.pyc`), media, archives, minified bundles and
files over 2 MB. Binaries are detected by content as well as extension — NUL bytes
in the first 8 KB give one away whatever it is called. Everything skipped is listed
on the **Skipped** tab with its reason: a clean report should be honest, not clean
because of what it quietly ignored.

`node_modules`, `venv`, `target` and similar directories are skipped by default —
you would not fix findings in someone else's code anyway. The **Include
dependencies** checkbox turns that off.

## While the scan runs

The scan screen shows a pipeline of stages — done, in progress, ahead — built from
that run's options, so a stage that will not run is never shown waiting. This is
not decoration: scanning code takes milliseconds while an OSV query takes seconds,
and without the pipeline the pause reads as a freeze.

The percentage appears only where it is meaningful (reading files); on the OSV
query and external scanners a spinning arc with the stage name replaces it,
because every file is already read and "100%" would mean "done" while a minute of
work remains. The elapsed clock ticks on its own rather than waiting for events.

**Cancel** really stops the work: a running scanner is killed (`kill_on_drop`)
instead of finishing — cancelling during semgrep used to hang for minutes. An
interrupted run is always marked cancelled even if it collected findings: a report
that looks complete is the worst thing a security scanner can produce.

External scanners are probed once per session and cached: every scan used to begin
by spawning 12 `--version` processes, with the screen sitting on "Preparing" and
zeros throughout. **Check again** re-probes.

## Compare with the last scan

Each scan of a target stores a snapshot, and the next one shows the delta — how
many are new, fixed, unchanged. New findings are marked in the list: on a big
project the number that matters is not the total but what you added today.

A finding is identified by a fingerprint: a hash of the rule id, the path and the
code itself with whitespace collapsed — **without the line number**. An import
added at the top shifts the whole file; counting by line would make every finding
"fixed" and instantly "new again", and every suppression would silently drop.
Reformatting leaves the fingerprint intact for the same reason.

The first scan of a target says plainly that there is nothing to compare against,
rather than "0 new".

## Suppressing findings

A false positive or an accepted risk is hidden with **Suppress** — a reason is
**required**: a suppression without an explanation is indistinguishable from
hiding a problem, and in six months nobody will remember why it is quiet here. You
can silence one finding or every finding of a rule in a file.

Entries live in `.vulnscope-ignore` **inside the project**, not in the app's
settings: it is a decision about this code, so it is versioned with it, travels
with a clone, and shows up in review. The format is JSON with the fingerprint,
rule, path and reason.

Suppressed findings do not disappear: they stay in the list with a badge and a
**Restore** button, but drop out of the counts — the count answers "what needs
attention". A suppression is never counted as "fixed": silencing is not repairing.
A corrupt `.vulnscope-ignore` does not cancel the scan or silently disable
suppressions — the app warns and scans without them.

## Export

The report exports to five formats: **JSON** (full data), **SARIF 2.1.0** (for
GitHub code scanning and CI dashboards — with rule dedup, severity mapping and
stable fingerprints), **Markdown** (a readable report for a PR, issue, or chat),
**CSV** (one row per finding for sorting and triage in a spreadsheet, with a
formula-injection guard), and **HTML** (a single self-contained file you open in a
browser or print to PDF). All of them follow the language on screen, and the secret
stays masked in every one. The Markdown report can also be copied straight to the
clipboard (`Ctrl+K` → Copy report) to paste into a PR or chat without a save
dialog.

A single finding is copied by the **Copy** button on its card: the severity
heading, `file:line`, the rule, CWE/OWASP, the description, the code snippet in a
highlighted fence, and the fix. No need to copy the whole report to share one
finding — and the format is shared with the report, so the two cannot drift apart.

## Interface

A window with no OS frame: the title bar is ours, and panels are separated by a
change of surface and a shadow rather than lines. The file tree and findings list
resize by dragging and remember their width across launches. Screens cross-fade;
all animation stops under `prefers-reduced-motion`.

Above the findings list is a search over title, path, category, CWE, CVE, rule id
and code — you can search exactly what the row shows. The title is matched in its
translation too, so search works on what you see in English. Next to it are the
**new only** and **suppressed** toggles, each appearing only when it has something
to show. The panel always says how many findings are hidden and resets the filters
in one click: a list emptied by a filter looks too much like a clean project, so it
says so plainly instead of showing a green shield. A file picked in the tree
narrows the list too — it shows as a chip with a ×, so the narrowing is never
invisible.

| Keys | Action |
|---|---|
| `Ctrl+K` | Command palette |
| `Ctrl+R` | Rule catalogue |
| `Ctrl+E` | Custom rules |
| `Ctrl+,` | Settings |
| `Ctrl+N` | New scan |
| `Ctrl+S` | Export report |
| `1`–`4` | Tabs: overview / findings / code / skipped |
| `J`, `K`, `↑`, `↓` | Move between findings |
| `Enter` | Open the finding in code |
| `Esc` | Close the palette, catalogue or settings |

**Every shortcut is rebindable** in settings (`Ctrl+,`): click a combo and type
your own, Backspace clears it. Conflicts are highlighted — two actions on one key
means one of them silently will not fire.

## Accessibility

Contrast is measured, not claimed: `npm run audit:contrast` checks WCAG 2.2 AA for
the 29 pairs the UI actually paints across all four themes, and runs the severity
colours through simulations of three colour-vision deficiencies. The ink on any
fill is computed from the fill's luminance, so a chosen accent never leaves
unreadable text.

A dedicated **Accessibility** tab collects: interface zoom (80–250%, via `zoom` so
nothing overlaps at 200%), reduce motion, hide the background glow, always show
focus, spell out severity next to counts, underline links, and larger hit targets.
The scan screen is a `role="progressbar"` with a polite live region that announces
milestones (not every frame), and the dashboard announces the result summary.

## Language

The interface switches between Russian and English under `Ctrl+,` → Appearance →
Language; the change applies instantly and is stored in `settings.json`. The whole
shell **and** the built-in rule catalogue (finding titles, descriptions, fixes) are
translated.

Localization is gettext-style (`src/i18n.tsx`): the key is the Russian string
itself, the `EN` dictionary provides the translation, and a missing key falls back
to the source. That keeps the Russian text readable right in the JSX. Interpolation
uses `{name}` placeholders so a value lands in the right place under a different
word order; spoken counts decline by number.

The fallback is convenient but silent — a forgotten key does not break the build,
it just shows Russian in the English UI, and only someone who switches the language
would notice. So completeness is checked on its own: `npm run audit:i18n` collects
strings from every place they reach the UI and fails on any the dictionary lacks:

| Source | What is collected |
|---|---|
| `src/**` | literal `t(...)` / `tr(...)` arguments |
| `rules.rs`, `secrets.rs` | each rule's `title`, `description`, `recommendation`, `category` |
| `model.rs` | the `sourceLabel`, `reasonLabel`, `phaseLabel` match arms |

So neither a new rule nor a new scan phase can ship untranslated. Strings with no
Cyrillic in them (`Path traversal`, `Semgrep`, `document.write()`) are skipped:
falling back to the source already gives the right English.

## Themes

Every colour comes from one token file (`src/theme.css`) — nothing is hardcoded in
a component, syntax highlighting included. Four presets (Night, Midnight, Day,
Contrast); any token is editable under `Ctrl+,` → Appearance → Show all colors,
applied live. Themes export and import as `.vulnscope-theme.json`.

## Settings

`Ctrl+,` — scan limits (file size, the "minified" threshold, findings per file),
OSV request TTL and concurrency, rule behaviour, what is enabled by default, the
accent colour, interface density and the highlighting cut-off. Values are clamped
to sane ranges on the backend: `maxFileSizeMb = 0` would mean "skip every file" and
a report that looks clean.

Settings live in `%APPDATA%/vulnscope/settings.json`.

Design tokens are in `src/theme.css`: one 4-pixel spacing scale, a scale of
surfaces instead of borders, typography on fixed steps.

## Install

Prebuilt bundles are in `src-tauri/target/release/bundle/`:

- `nsis/VulnScope_0.1.0_x64-setup.exe` — installer, 7.7 MB
- `msi/VulnScope_0.1.0_x64_en-US.msi` — MSI package, 9.5 MB

## Development

Needs Node 18+ and Rust 1.75+.

```bash
npm install
npm run tauri dev     # run with hot reload
npm run tauri build   # build the installers
```

Backend tests (193):

```bash
cd src-tauri && cargo test
```

Checks: `npm run audit:contrast` for the theme audit, `npm run audit:i18n` for
localization completeness. CI runs both on every push, plus `npm run build`,
`cargo clippy -- -D warnings`, and `npm audit` / `cargo audit` over our own
dependencies.

## How it works

A Rust core, a React + TypeScript interface, all inside Tauri 2.

| Module | Purpose |
|---|---|
| `walk.rs` | Walking files, rejecting binaries, detecting the language |
| `rules.rs` | The rule engine and the catalogue of 167 rules |
| `secrets.rs` | Secret detection with an entropy check |
| `deps.rs` | Parsing dependency manifests |
| `osv.rs` | OSV.dev client, CVSS scoring, on-disk cache |
| `external.rs` | Running external scanners and normalising their output |
| `git.rs` | Cloning repositories |
| `scanner.rs` | Orchestration, progress, ETA, cancellation |

**Performance.** Rules are prefiltered through a `RegexSet`: a file only pays for
the patterns that actually matched somewhere. The walk is parallelised with rayon —
~2100 files/s, 10k files and 1.1M lines in 18 s. OSV queries go in waves of 16 in
parallel (sequential was 9× slower).

The code viewer is **virtualised**: only the visible window of lines lives in the
DOM rather than the whole file, or a 24,000-line bundle would freeze the window.
Syntax highlighting switches off past 6000 lines — highlight.js runs on the main
thread, and colouring a bundle costs more than it is worth.

## Accuracy

Rules are built on regular expressions, not dataflow analysis. That means some
findings need a human look — each carries a confidence ("High confidence" / "Needs
review"). Commented-out code is ignored, noisy rules are suppressed in test files,
and `unless_contains` drops a match when the guard is visible next to it
(`DOMPurify.sanitize`, `yaml.SafeLoader`). The tool helps you find suspicious
places faster — it does not replace review.
