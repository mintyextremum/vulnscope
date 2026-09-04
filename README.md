<div align="center">

# VulnScope

**A desktop security scanner that runs entirely on your machine.**

274 static-analysis rules, a deterministic data-flow engine, 55 secret detectors,
and CVE lookup — for local projects and public repositories.

[![checks](https://github.com/mintyextremum/vulnscope/actions/workflows/checks.yml/badge.svg)](https://github.com/mintyextremum/vulnscope/actions/workflows/checks.yml)
[![release](https://img.shields.io/github/v/release/mintyextremum/vulnscope?color=5b8def)](https://github.com/mintyextremum/vulnscope/releases/latest)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![platform](https://img.shields.io/badge/platform-Windows-lightgrey)](https://github.com/mintyextremum/vulnscope/releases/latest)

*[Русская версия](README.ru.md)*

<img src="docs/images/01-dashboard.png" alt="VulnScope dashboard: security score, riskiest files, and scan statistics" width="900">

</div>

---

## What this is

Point VulnScope at a folder or a GitHub URL and it gives you an annotated report:
dangerous constructs in the code, secrets committed to the source, and known CVEs
in the dependencies — each with a CWE, an OWASP Top 10 category, a confidence
level, and a concrete fix.

**Analysis happens on your computer.** The only request that ever leaves is to
[OSV.dev](https://osv.dev), carrying a list of package names and versions — never
your code — and only when the CVE check is enabled. Offline mode removes even
that. Telemetry and provider-side verification of discovered secrets are forced
off and cannot be switched on.

## Install

Download the latest installer from the
**[releases page](https://github.com/mintyextremum/vulnscope/releases/latest)**:

| File | What it is |
|---|---|
| `VulnScope_1.0.0_x64-setup.exe` | NSIS installer — the usual choice |
| `VulnScope_1.0.0_x64_en-US.msi` | MSI package, for deployment via group policy |

Windows 10 or 11, 64-bit. Nothing else to install: WebView2 ships with Windows 11
and current Windows 10, and VulnScope bundles no runtime of its own.

Windows will show a SmartScreen warning on first run, because these builds are not
code-signed — a certificate costs more than this project earns. Choose **More
info → Run anyway**, or build it yourself from source (see
[Development](#development)).

> **Building from source is the other supported path.** macOS and Linux are not
> released today: the code compiles cross-platform, but it has only ever been
> tested on Windows, so publishing untested binaries would be dishonest.

## Contents

- [What it finds](#what-it-finds)
  - [Rules](#code--274-built-in-rules) · [Data-flow analysis](#data-flow-analysis-the-flagship) · [Compromise indicators](#compromise-indicators) · [Secrets](#secrets--55-detectors) · [Dependencies](#dependencies--cves-via-osvdev) · [External scanners](#external-scanners-optional)
- [What it doesn't analyze](#what-it-doesnt-analyze)
- [Working through the results](#working-through-the-results)
  - [Security score](#security-score) · [While the scan runs](#while-the-scan-runs) · [Comparing scans](#comparing-with-the-last-scan) · [Suppressing](#suppressing-findings) · [Accountability](#accountability)
- [Export](#export)
- [Interface](#interface) · [Accessibility](#accessibility) · [Language](#language) · [Themes](#themes) · [Settings](#settings)
- [Development](#development) · [How it works](#how-it-works) · [Accuracy and limits](#accuracy-and-limits)
- [Contributing](#contributing) · [Security](#security) · [License](#license)

---

## What it finds

### Code — 274 built-in rules

Across 37 languages: command, SQL, NoSQL, LDAP, XPath, JNDI and template
injection (SSTI, SpEL), XSS, prototype pollution, unsafe reflection
(`Class.forName`, `constantize`), path traversal, open redirects, unsafe
deserialization (`pickle`, `yaml.load`, SnakeYAML, `XMLDecoder`, XStream, Jackson
default typing, Json.NET `TypeNameHandling`, `binary_to_term`), XXE, code
execution via ScriptEngine/Groovy, disabled TLS and SSH host-key verification,
weak cryptography (ECB, hardcoded key, zero IV), non-constant-time secret
comparison, mass assignment, Zip Slip, JWT verification bypass, a hardcoded
`SECRET_KEY`, `xp_cmdshell` and file operations in SQL, `unsafe` pitfalls in Rust,
and misconfigurations in Dockerfiles, GitHub Actions, Terraform, nginx and
Kubernetes (privileges, host namespaces, dangerous capabilities).

| Language | Rules |  | Language | Rules |
|---|---|---|---|---|
| Python | 39 | | Nginx | 5 |
| JavaScript / TypeScript / React | 36 | | SQL | 4 |
| Java / Kotlin | 30 | | Shell | 4 |
| Terraform | 28 | | PowerShell | 4 |
| PHP | 17 | | Elixir | 4 |
| Ruby | 14 | | Scala | 3 |
| C# | 14 | | Perl | 3 |
| Go | 13 | | Ansible | 3 |
| Kubernetes | 11 | | Lua | 2 |
| Rust | 10 | | Vue | 1 |
| Dockerfile | 10 | | Svelte | 1 |
| Swift · GitHub Actions · C/C++ | 6 each | | | |

Languages are detected by extension and filename, so Vue, Svelte, GraphQL, SQL and
others are recognised and counted in the statistics even where no rules target
them yet. The full catalogue, with descriptions and fixes, opens in the app under
**Rules** (`Ctrl+R`).

**Your own rules.** **Custom** (`Ctrl+E`) opens an editor: regular expression,
severity, languages, CWE/OWASP and the fix text. A live preview runs the rule
against your own sample before you save it, showing which lines were dropped by
"do not fire if it contains". Custom rules work exactly like built-in ones — same
comment and test-file handling. They live in `%APPDATA%/vulnscope/rules.json`, and
the set can be imported and exported.

### Data-flow analysis (the flagship)

A deterministic engine that does not just look for a dangerous call on a line, but
answers the question that actually matters: **does user data reach it?**

It traces input — a request, `argv`, `stdin` — through variable assignments to a
dangerous sink (OS commands, SQL, file operations, outbound requests, `eval`) and
reports the whole **source → variable → sink** path, with every step openable in
the code. Tracking is interprocedural within a file and follows flows across files
end to end.

If escaping, parameterization, or an allowlist sits along the way, the flow is
considered broken and nothing is reported. This catches multi-line vulnerabilities
that line-by-line rules cannot see, and every finding is self-verifiable: the exact
route is visible. No AI, no black boxes — the same input always produces the same
answer.

<div align="center">
<img src="docs/images/02-findings.png" alt="Findings list with the file tree, a selected finding, its code, fix, and CWE/OWASP classification" width="900">
</div>

### Compromise indicators

A dedicated category catches not "risky patterns" but what an attacker leaves
behind: PHP web shells (`eval($_POST[...])`, a function called by name from the
request, packed `eval(base64_decode(...))`), reverse shells (`/dev/tcp/…`,
netcat/mkfifo, `pty.spawn` onto a socket), PowerShell download cradles
(`IEX (…).DownloadString`), and packed payloads (`eval(atob(…))`,
`exec(base64.b64decode(…))`).

These are flagged **critical** with high confidence: ordinary code does not do
this, and a live web shell in the tree means the machine is already owned.

### Secrets — 55 detectors

AWS and Azure Storage keys; GitHub, GitLab (including runner and pipeline-trigger),
Slack (including incoming webhook), npm, PyPI, Discord, Twilio, Mailgun, Square,
Hugging Face, Postman, Databricks, New Relic, Notion, Atlassian, Linear, Doppler,
PlanetScale, HashiCorp Vault, Grafana, Dropbox, Terraform Cloud, Firebase, Adobe,
Asana, Mailchimp, SonarQube, Figma, Airtable, Docker Hub, RubyGems and Pulumi
tokens; Stripe (including webhook secret), Google and SendGrid keys; Shopify and
DigitalOcean tokens; Sentry DSNs; private keys; database connection strings; JWTs.

Values are checked for entropy, so `your-api-key-here` and similar placeholders
never reach the report. **The secret is masked everywhere** — in the interface and
in every export — so the raw value never leaves the file. A test walks the real
pipeline to prove it.

### Dependencies — CVEs via OSV.dev

Parses `package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml`,
`Cargo.toml` and `Cargo.lock`. A lockfile wins over a manifest, because it has the
exact versions. Severity is computed from the CVSS vector, and responses are cached
for 7 days — re-scanning the same project works offline.

**Deduplication.** OSV aggregates several databases (GHSA, PYSEC, RUSTSEC), so one
vulnerability arrives as several records sharing a CVE; with cargo-audit they
overlap again. Records about the same package-version that share at least one
identifier collapse into one, with the union of their CVE/CWE ids and the worst
severity. On the test project that removes about 40% of the duplicates.

### External scanners (optional)

If these are installed on the machine, their findings are picked up and normalised
into the same shape. VulnScope is fully usable without them — but with them,
coverage is noticeably wider: 197 findings instead of 155 on the test project.

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
| Checkov | Thousands of Terraform, CloudFormation, Kubernetes and Helm checks | `pipx install checkov` |
| gosec | Deeper AST-based Go security analysis | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| Grype | Dependency vulnerabilities from lockfiles and SBOMs | `scoop install grype` |
| Hadolint | Dockerfile linter by syntax, not by pattern | `scoop install hadolint` |
| npm audit | npm dependency audit | ships with Node.js |

When several tools — and the built-in rules — flag **the same line with the same
CWE**, the findings collapse into one that lists every engine that agreed, so a
single command injection is not shown three times.

The **External scanners** card shows the exact command and lets you copy it, but
**downloads and runs nothing itself**. A security scanner that fetches and executes
binaries becomes the very supply-chain threat it exists to find. After installing,
press **Check again**.

> **govulncheck** can be installed from the app, but its output is not parsed yet.
> It is honestly marked "not wired up", excluded from the counter, and never run.

## What it doesn't analyze

Binaries (`.exe`, `.dll`, `.so`, `.pyc`), media, archives, minified bundles, and
files over 2 MB. Binaries are detected by content as well as by extension — NUL
bytes in the first 8 KB give one away whatever it is called.

Everything skipped is listed on the **Skipped** tab with its reason. A clean report
should be honest, not clean because of what it quietly ignored.

`node_modules`, `venv`, `target` and similar directories are skipped by default —
you would not fix findings in someone else's code anyway. The **Include
dependencies** checkbox turns that off.

## Working through the results

### Security score

One number for the whole report, on a 0–100 scale with a letter grade. Each finding
subtracts points weighted by severity and — the part that sets it apart — by
whether the data-flow engine proved it **reachable** from untrusted input. A
reachable critical is worse than an isolated one, and the score says so.

It is deterministic and fully attributable: the same report always yields the same
score, and every point traces to a factor shown in the breakdown. The dashboard
also lists **attack paths** sorted by danger, each opening the finding behind it.

### While the scan runs

The scan screen shows a pipeline of stages — done, in progress, ahead — built from
that run's options, so a stage that will not run is never shown waiting. This is
not decoration: scanning code takes milliseconds while an OSV query takes seconds,
and without the pipeline the pause reads as a freeze.

The percentage appears only where it is meaningful (reading files). On the OSV query
and external scanners, a spinning arc with the stage name replaces it, because every
file has already been read and "100%" would mean "done" while a minute of work
remains.

**Cancel** really stops the work: a running scanner is killed rather than left to
finish. An interrupted run is always marked cancelled even if it collected
findings — a report that looks complete is the worst thing a security scanner can
produce.

### Comparing with the last scan

Each scan of a target stores a snapshot, and the next one shows the delta: how many
findings are new, fixed, unchanged. On a big project the number that matters is not
the total but what you added today.

A finding is identified by a fingerprint — a hash of the rule id, the path, and the
code with whitespace collapsed, **without the line number**. An import added at the
top shifts the whole file; counting by line would mark every finding "fixed" and
instantly "new again", and would silently void every suppression. Reformatting
leaves the fingerprint intact for the same reason.

The first scan of a target says plainly that there is nothing to compare against,
rather than reporting "0 new".

### Suppressing findings

A false positive or an accepted risk is hidden with **Suppress**, and a reason is
**required**: a suppression without an explanation is indistinguishable from hiding
a problem, and in six months nobody will remember why it is quiet here.

Entries live in `.vulnscope-ignore` **inside the project**, not in the app's
settings. It is a decision about this code, so it is versioned with it, travels
with a clone, and shows up in review.

Suppressed findings do not disappear: they stay in the list with a badge and a
**Restore** button, but drop out of the counts — the count answers "what needs
attention". A suppression is never counted as "fixed": silencing is not repairing.
A corrupt `.vulnscope-ignore` does not cancel the scan or silently disable
suppressions; the app warns and scans without them.

### Accountability

Findings can be annotated from `git blame` with who last touched the offending
line, in which commit, and when — turning a finding into an assignable work item.
The report and the exports then break results down per author, and the findings
list can be filtered by one.

Attribution is deliberately skipped where it would lie, such as on files git does
not track. When a staff registry has been imported, git authors are mapped onto
real people by e-mail first, then by name.

## Export

Eight formats, all following the language on screen, all keeping secrets masked:

| Format | For |
|---|---|
| **JSON** | The complete data |
| **SARIF 2.1.0** | GitHub code scanning and CI dashboards — rule dedup, severity mapping, stable fingerprints, and the traced data-flow path |
| **Markdown** | A readable report for a PR, an issue, or chat |
| **CSV** | One row per finding for triage in a spreadsheet, with a formula-injection guard |
| **Excel** | A real multi-sheet workbook |
| **HTML** | A single self-contained file to open in a browser |
| **PDF** | A print-ready report with metrics and per-author breakdown |
| **XML (1C)** | Loads unattended into 1C, with a project and staff registry |

The Markdown report can be copied straight to the clipboard (`Ctrl+K` → Copy
report) without a save dialog. A single finding is copied by the **Copy** button on
its card: severity heading, `file:line`, rule, CWE/OWASP, description, the snippet
in a highlighted fence, and the fix.

When the list is narrowed by filters, the palette offers **filtered export**
(Markdown, CSV, HTML) for handing the triaged subset to your team. The document
says so honestly — "a selection of N of M findings from the full report" — with its
summary recomputed to match its contents. JSON and SARIF deliberately stay
full-report only: JSON is the complete data by definition, and a partial SARIF
upload would make code scanning close every alert absent from it as fixed.

## Interface

A window with no OS frame: the title bar is ours, and panels are separated by a
change of surface and a shadow rather than lines. The file tree and findings list
resize by dragging and remember their width across launches. All animation stops
under `prefers-reduced-motion`.

Above the findings list is a search over title, path, category, CWE, CVE, rule id
and code — you can search exactly what the row shows. The title is matched in its
translation too, so search works on what you see in English. The panel always says
how many findings are hidden and resets the filters in one click: a list emptied by
a filter looks too much like a clean project, so it says so plainly instead of
showing a green shield.

The viewer shows the code, but fixing it happens in an editor — so a button next to
the path reveals the file in the system file manager. Set an editor command in the
settings (say, `code -g {file}:{line}`) and a second button opens the finding right
in it, at the line. Which editor is your call: the command is configured with
placeholders, not baked into the app.

| Keys | Action |
|---|---|
| `Ctrl+K` | Command palette |
| `Ctrl+R` | Rule catalogue |
| `Ctrl+E` | Custom rules |
| `Ctrl+,` | Settings |
| `Ctrl+N` | New scan |
| `Ctrl+Shift+R` | Re-scan the same target |
| `Ctrl+S` | Export report |
| `1`–`4` | Tabs: overview / findings / code / skipped |
| `J`, `K`, `↑`, `↓` | Move between findings |
| `Enter` | Open the finding in code |
| `Esc` | Close the palette, catalogue or settings |

**Every shortcut is rebindable** in settings: click a combo and type your own,
Backspace clears it. Conflicts are highlighted — two actions on one key means one
of them silently will not fire.

## Accessibility

Contrast is measured, not claimed: `npm run audit:contrast` checks WCAG 2.2 AA for
the pairs the UI actually paints across every theme, and runs the severity colours
through simulations of three colour-vision deficiencies. The ink on any fill is
computed from that fill's luminance, so a chosen accent never leaves unreadable
text.

A dedicated **Accessibility** tab collects: interface zoom (80–250%, via `zoom` so
nothing overlaps at 200%), reduce motion, hide the background glow, always show
focus, spell out severity next to counts, underline links, and larger hit targets.
The scan screen is a `role="progressbar"` with a polite live region that announces
milestones rather than every frame.

## Language

The interface switches between Russian and English under `Ctrl+,` → Appearance →
Language, instantly. The whole shell **and** the built-in rule catalogue — finding
titles, descriptions, fixes — are translated.

Localization is gettext-style ([`src/i18n.tsx`](src/i18n.tsx)): the key is the
Russian string itself, and a missing key falls back to the source. That fallback is
convenient but silent — a forgotten key does not break the build, it just shows
Russian in the English UI. So completeness is checked on its own:
`npm run audit:i18n` collects strings from every place they reach the UI and fails
on any the dictionary lacks. Neither a new rule nor a new scan phase can ship
untranslated.

## Themes

Every colour comes from one token file ([`src/theme.css`](src/theme.css)) — nothing
is hardcoded in a component, syntax highlighting included. **18 presets** (Night,
Midnight, Day, Contrast, Forest, Ocean, Amethyst, Graphite, Paper, Mist, Sunset,
Arctic, Sepia, Neon, Lavender, Peach and two light variants); any token is editable
under `Ctrl+,` → Appearance → Show all colors, applied live. Themes export and
import as `.vulnscope-theme.json`.

## Settings

`Ctrl+,` — scan limits (file size, the "minified" threshold, findings per file),
OSV request TTL and concurrency, rule behaviour, what is enabled by default, the
accent colour, interface density, and the highlighting cut-off. Values are clamped
to sane ranges on the backend: `maxFileSizeMb = 0` would mean "skip every file" and
a report that looks clean.

Settings live in `%APPDATA%/vulnscope/settings.json`.

## Development

Needs **Node 18+** and **Rust 1.77+**. On Windows you also need the MSVC build
tools.

```bash
npm install
npm run tauri dev     # run with hot reload
npm run tauri build   # build the installers
```

Run everything CI runs, in one command:

```bash
npm run check:all
```

That covers a TypeScript typecheck, eight audit scripts, a production build, the
288 backend tests, and Clippy with warnings denied.

Each audit script exists because something shipped broken in a way review did not
catch — contrast, localization completeness, SARIF shape, score maths, 1C XML
shape, Excel workbook shape, CSS token references, and whether every setting is
actually read by something. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a
rule or a translation.

## How it works

A Rust core, a React + TypeScript interface, all inside Tauri 2.

| Module | Purpose |
|---|---|
| `walk.rs` | Walking files, rejecting binaries, detecting the language |
| `rules.rs` | The rule engine and the catalogue of 274 rules |
| `taint.rs` | The data-flow engine: sources, sinks, sanitisers, paths |
| `secrets.rs` | Secret detection with an entropy check |
| `deps.rs` | Parsing dependency manifests |
| `osv.rs` | OSV.dev client, CVSS scoring, on-disk cache |
| `external.rs` | Running external scanners and normalising their output |
| `baseline.rs` | Fingerprints, scan-to-scan comparison, suppressions |
| `blame.rs` | `git blame` attribution for findings |
| `userrules.rs` | User-defined rules |
| `git.rs` | Cloning repositories |
| `pkgmgr.rs`, `proc.rs` | Locating and spawning external tools |
| `settings.rs` | Settings, validation, keybindings |
| `scanner.rs` | Orchestration, progress, ETA, cancellation |

**Performance.** Rules are prefiltered through a `RegexSet`, so a file only pays for
the patterns that actually matched somewhere. The walk is parallelised with rayon —
about 2100 files/s, or 10k files and 1.1M lines in 18 seconds. OSV queries go in
waves of 16 in parallel; sequential was 9× slower.

The code viewer is **virtualised**: only the visible window of lines lives in the
DOM, or a 24,000-line bundle would freeze the window. Syntax highlighting switches
off past 6000 lines, because highlight.js runs on the main thread and colouring a
bundle costs more than it is worth.

## Accuracy and limits

VulnScope uses two engines with different guarantees, and it tells you which one
found what.

**Pattern rules** are regular expressions. They see one line at a time, so some
findings need a human look — each carries a confidence badge ("High confidence" /
"Needs review"). Commented-out code is ignored, noisy rules are suppressed in test
files, and `unless_contains` drops a match when a guard is visible next to it
(`DOMPurify.sanitize`, `yaml.SafeLoader`).

**The data-flow engine** is stronger: it reports a finding only when it can show
the path from an untrusted source to a dangerous sink, and it shows you that path.
It is deliberately conservative rather than a full compiler — identifier-level
tracking within a line window, sanitiser-aware — which keeps it deterministic and
every finding checkable by eye.

Neither engine is complete. A scanner that finds nothing is not proof that there is
nothing to find, and neither replaces review — the point is to get you to the
suspicious places faster.

## Contributing

Pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers the setup, the
check suite, and walkthroughs for the two most common contributions: adding a
detection rule and adding a translation.

Bug reports are just as useful — especially a false positive or a missed detection
with a minimal code sample, which becomes a regression test.

## Security

To report a vulnerability **in VulnScope itself**, please use
[private vulnerability reporting](https://github.com/mintyextremum/vulnscope/security/advisories/new)
rather than a public issue. [SECURITY.md](SECURITY.md) sets out what is in scope
and the design commitments the project intends to hold.

A missed vulnerability or a false positive in *scanned* code is a detection bug —
open a normal issue for those.

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for third-party components.
