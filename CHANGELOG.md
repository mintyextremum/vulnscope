# Changelog

All notable changes to VulnScope are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-10-21 · Thunderbolt

A major release. The data-flow engine now reads statements instead of lines and
understands functions and framework parameters in every language it covers; the
security score was rebuilt so that its verdict is one you can defend, and it now
comes with a plan that says what to fix first; the dashboard was redesigned around
those two answers. It also closes a security hole that every 1.x release had.

### Security

- **A scanned folder could run a command through git.** The blame step, on by
  default since 1.0, ran `git ls-files` and `git blame` inside the scanned folder,
  and both execute the program named in that folder's `.git/config` under
  `core.fsmonitor`. A folder carrying its own `.git` — an unpacked archive of
  someone else's project, say — therefore ran its author's command the moment it
  was scanned. Every process VulnScope starts now receives `core.fsmonitor=false`
  through `GIT_CONFIG_COUNT`, which outranks the repository's config and reaches
  grandchildren too (Semgrep lists files with git); git calls into a scanned folder
  also run hardened, and blame runs without textconv drivers. A test reproduces
  the attack against the real git, with an unprotected control run, so it checks
  what git actually does. This is now design commitment 5 in SECURITY.md.
- `vite` raised to 7.3.7, closing GHSA-698v-4r3x-3vcv, GHSA-r825-w8mm-5pxw and
  GHSA-587h-7wmj-h5pm (its bundled `launch-editor`: missing `%` escaping and
  argument confusion on Windows, an existence check that could be bypassed). The
  development server only — it does not enter a released binary.
- The HTTP stack behind the two outbound requests (OSV.dev and the update check)
  updated within semver: `rustls` 0.23.46, `rustls-webpki` 0.103.16,
  `webpki-roots` 1.0.10 and `quinn-proto` 0.11.19, closing RUSTSEC-2026-0338 to
  -0342, -0346 to -0349, -0381 and -0382; the yanked `chacha20` 0.10.1 is
  replaced by 0.10.2.

### Added

- **The engine reads statements.** A query split over three lines, arguments in a
  column, a call chain with a leading dot, a template literal spanning lines — all
  are joined into one statement, and the finding still points at the real line.
- **Functions in Java, C#, Kotlin, Scala, Ruby, Elixir and Perl**, alongside
  Python, JavaScript/TypeScript, PHP and Go: one method's variables no longer leak
  into the next, and calls to helpers resolve through their summaries.
- **Framework parameters are sources.** `@RequestParam`/`@PathVariable` in
  Spring, JAX-RS, `[FromQuery]`/`[FromBody]` in ASP.NET, `@Query`/`@Body` in
  NestJS, `Query()`/`Annotated[…]` and route paths in FastAPI and Flask. Such
  handlers were skipped before the engine read a line, having no `request` in
  them. A path parameter typed `int`, `uuid` and the like is not a source.
- **Destructuring and unpacking** — `const { id } = req.query`, Python and Ruby
  tuple unpacking, Go's `value, err :=` — give every bound name the right-hand
  side's taint.
- **Score 2.0.**
  - The worst finding sets honest limits: only high and critical findings can
    reach F; a critical vulnerability keeps the score at C or below, one reachable
    from input at D or below. F without a critical reads "serious risks".
  - Findings are grouped by root cause — a rule, a package version, or for traced
    flows the kind of sink — and repeats weigh less each time (n of them weigh
    like 1 + log₂ n).
  - A finding from a low-confidence rule weighs half, a medium one three quarters.
- **Fix plan** on the dashboard, in the printed report and in the Markdown, HTML
  and Excel exports: the causes whose fixes raise the score the most, greedily,
  with the score and grade after each step. A fix changes the whole line, so a
  step also clears other rules' findings on the same lines; for a package it names
  the highest version any of its advisories needs.
- **"Why this score?"** opens the arithmetic: each severity's share of the risk,
  the repeat discount, the multipliers, the limit and the score without it.
- **Collapse repeats** in the findings list: one row per root cause with ×N, and
  the other places listed in the finding's detail.
- **Changes only (BETA)**: scan only the files changed since the last commit. The
  cross-file pre-pass still reads the whole project; the scan neither compares
  with nor writes to the history, and its score is the score of the changes.
- The code tab opens on the riskiest files, each at its worst line.
- What's new, shown once after an update; the version badge in the title bar
  brings it back.
- **An app icon of its own.** The executable, the taskbar and the window carried
  the stock Tauri logo, and the installer NSIS's generic one; all of them now
  show the shield-and-lock mark from the title bar, rendered from the same
  Material Symbols glyph.

### Changed

- **The dashboard** leads with the score card and the fix plan side by side,
  then attack paths and the riskiest files (now with each file's share of the
  project's risk), then one card for the change since the last scan. The six
  number tiles and the separate severity card repeated what the header already
  showed and are replaced by a compact "About the scan" at the end.
- **Traced data flows are marked reachable.** Only pattern findings lying on a
  flow were marked before, so the management report said "0 reachable" next to a
  list of attack paths and the exports said "Reachable: No" on the flagship's own
  findings. The history's reachable count rises accordingly from this version on.
- Every traced flow is titled with what it reaches ("SQL injection · …").
- Icons are Material Symbols **Rounded**, and follow Material 3's convention: a
  glyph fills when its control is the active one — the current tab, a toggle that
  is on, the selected finding. Dashboard sections carry their icon in a tinted
  chip, coloured by the kind of risk they are about.
- The severity pills above the dashboard count what the dashboard counts —
  confirmed findings — and a click opens the findings of that severity.

### Fixed

- `.env` was shown as `env.` and `.env:3` as `env:3.`: paths truncated from the
  left were also reordered by the bidi algorithm. Six places.
- Every fresh report opened the Findings tab narrowed to the first finding's file
  ("1/5").
- A suppressed finding made a fresh report read "26/27" and "1 hidden", with a
  reset that could not bring it back.
- Skip reasons on the Skipped tab were not translated, and two sentences were
  written straight into the markup, half Russian in the English interface.
- Settings stayed on "Loading settings…" forever when reading them failed; a
  failed save now rolls back with a message instead of showing a value the
  scanner would not use.
- The command palette stretched to its full height with three commands; "Reset
  filters" there left the reachable toggle, the author and the file in place.
- Excel's summary sheet counted severities including BETA while its total and its
  findings sheet did not.
- The help screen claimed 38 languages; there are 37.

### Performance

- The engine is faster than 1.3.0 despite doing more: 2.22 s against 2.36 s on
  3,122 files from `node_modules` (best of five), with identical findings — zero
  new false positives. A line with nothing tainted and no source is now skipped
  outright, and text without quotes or slashes skips the literal scanner.

### Engineering

- 351 backend tests, up from 328.
- The score audit checks the limits, the repeat discount, confidence and
  monotonicity on thousands of random reports, and replays every fix plan —
  removing findings the way a fix would — to check each promised score.
- The localization audit now also catches text written directly into JSX, the
  score's labels, and the release note.
- `npm run dev` in a plain browser runs against a simulated backend built on
  Tauri's IPC mock, with a demo project covering every surface of the interface.
  It works around a bug in `@tauri-apps/api` 2.11's mock (unlisten sends
  `eventId`, the mock reads `id`).

[2.0.0]: https://github.com/mintyextremum/vulnscope/releases/tag/v2.0.0

## [1.3.0] — 2026-10-07

The remaining heuristic languages join the data-flow engine, and three findings
that carried the wrong category are corrected. A wrong category is worse than a
missing finding: it hands the reader someone else's CWE and advice that does not
apply.

### Added

- **Data-flow coverage for Ruby, Go, Scala and Elixir.** Probing them the way the
  JVM was probed found eleven of twenty-one ordinary idioms producing nothing:
  Rails reaches a database through its query builder, Go through the `*Context`
  methods, Elixir through Ecto, and none of that looked like a sink.
  - **Ruby** — `find_by_sql` and the raw-SQL builder calls (`where`, `order`,
    `group`, `having` with a string), the metaprogramming entry points
    (`public_send`, `instance_eval`, `class_eval`, `ERB.new`), and the `raw`
    view helper.
  - **Go** — `database/sql` in full (`QueryRow`, the `*Context` variants,
    `NamedExec`), the `os` writers, and `template.HTML`.
  - **Scala and Elixir** — Anorm's `SQL(…)`, `Ecto.Adapters.SQL.query`,
    `System.cmd` and `:os.cmd`.

### Fixed

- **`db.Exec` in Go was reported as command injection.** The command sink
  matched `exec` even with a dot in front, and that heuristic is listed before
  SQL, so a Go SQL injection arrived with CWE-78 and the advice "pass the command
  as an argument list". `exec` now counts only with nothing dotted before it; Go
  is told apart by case (`.Exec`) and PHP by its arrow (`->exec`).
- **`regex.exec(input)` in JavaScript was reported as command injection** — a
  name collision and nothing more. A regular-expression match is now neither a
  command nor code execution.
- **Rendering a Go template was reported as SQL injection.** `execute` matched
  regardless of case, so every `tpl.Execute(w, data)` carrying user data became
  an injection. The sink list now spells the lowercase DB-API/JDBC form, and
  .NET's capitalised entry points are named individually.
- Argument parsing gave up when a sink pattern ended in a quote rather than a
  parenthesis, which is what tells `where('name = …')` with raw SQL from
  `where('name', value)` with a bound one.

### Changed

- The rule deciding which argument carries the query text is no longer a list of
  PHP driver prefixes but a rule about shape: a connection, context or repository
  is a bare handle (`$db`, `ctx`, `Repo`), while a query is a literal or a
  concatenation. When the first argument is a handle and the second is not a
  collection, both count. That covers Go's `*Context` methods and Ecto, which the
  list would not have, and still excludes bind parameters — they follow the query
  and arrive as a collection.

### Security

- `source-map-js` raised to 1.2.2, closing GHSA-68fv-2mgg-jv7q (event-loop denial
  of service through indexed source-map section offsets). Build tooling, reached
  through postcss — it does not enter a released binary.

### Deliberately not added

Ruby's `send` (it is also `res.send` in Express and `socket.send`), Go's
`w.Write` and `fmt.Fprintf` (indistinguishable from writing to a file or a
buffer), and Scala's postfix `"cmd".!`. The first two are pinned by tests.

### Engineering

- 328 backend tests, up from 324.

[1.3.0]: https://github.com/mintyextremum/vulnscope/releases/tag/v1.3.0

## [1.2.0] — 2026-09-19

Java, Kotlin and C# join the data-flow engine — and, to make that worth
shipping, the engine learns that a string literal is not code. The second part
fixes false positives in every language, not only the new ones.

### Added

- **Data-flow coverage for Java, Kotlin and C#.** A probe of twelve ordinary
  vulnerabilities — `executeQuery`, `new File`, `Process.Start`,
  `getWriter().write` and the like — found every one of them invisible, although
  the catalogue carries 44 rules for these languages. The sources were fine: the
  engine tracked the input and simply had no sink to report it at. Now covered:
  - **JVM** — JDBC (`executeQuery`, `executeUpdate`, `addBatch`, and
    `prepareStatement`, since concatenating into it is still injection),
    JPA/Hibernate queries, Spring's `JdbcTemplate`, `RestTemplate` and SpEL,
    `java.io` and NIO file access, the servlet writer, `URL.openStream`, and Java
    deserialisation (`readObject`).
  - **.NET** — ADO.NET command constructors, EF Core's raw-SQL methods,
    `Process.Start`, `System.IO`, `Response.Write`, Razor and Blazor raw HTML,
    and `HttpClient`.
  - Sanitisers for both, scoped like the rest: `HtmlEncode` and the OWASP Java
    Encoder clear XSS only; `FilenameUtils.getName` and `Path.GetFileName` clear
    path traversal only; `Uri.EscapeDataString` clears redirects and XSS.

### Fixed

- **A column name is no longer read as a variable.** `cur.execute("SELECT …
  WHERE id = 1")` was reported as SQL injection whenever a tainted variable
  happened to be called `id` — in every language. On Java it would have flagged
  every correctly written `prepareStatement("… WHERE id = ?")`. String contents
  are now masked when the engine asks which variables a line uses, while
  interpolation is kept, because interpolation is the main road to injection:
  `${…}`, `#{…}`, `{…}` behind an `f` or `$` prefix, and `$name`.
- **A bind parameter is no longer read as an injection.** `cur.execute(sql,
  (id,))`, `db.query(sql, [id])` and `jdbc.queryForObject(sql, T, id)` are the
  *fix* for SQL injection, and all of them put the value on the sink line. For
  SQL sinks only the argument carrying the query text now counts.
- **Typed declarations no longer end the trail.** The engine recognised a fixed
  list of declared types, so `URL url = …`, `List<String> xs = …`, C#'s
  lowercase `string`, and every annotated declaration — `const id: string =
  req.query.id`, which is ordinary TypeScript — silently stopped propagation.
  This was a false negative in TypeScript and Python as much as in Java.
- A comma inside a string literal split a call argument in two, so
  `helper("a, b", x)` saw `x` in the wrong position and the interprocedural pass
  matched the wrong parameter.
- The word "escape" inside a message string counted as a call to an escaper and
  cleared the taint.

### Security

- `rustls` raised to 0.23.45, closing RUSTSEC-2026-0285 (TLS 1.3 handshake
  messages accepted across encryption-level boundaries). It ships: it carries
  both of VulnScope's outbound HTTPS requests, to OSV.dev and to the releases
  feed.

### Deliberately not added

Each of these would have made a category less trustworthy, and each is pinned
by a test: a bare `.println(` (it would take `System.out.println` — console
output, not XSS), `new URL(` (constructing a URL fetches nothing, and in
JavaScript it is everyday parsing), `GetAsync` (a caching and repository verb as
much as an HTTP one), .NET `.Deserialize(` (System.Text.Json is safe), and
`FromSqlInterpolated` (EF Core parameterises it itself).

### Engineering

- 324 backend tests, up from 311. The test for the canonical safe forms was
  checked against the engine with the fixes disabled: without them, the JDBC
  `PreparedStatement` is reported as SQL injection.

[1.2.0]: https://github.com/mintyextremum/vulnscope/releases/tag/v1.2.0

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
