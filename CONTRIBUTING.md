# Contributing to VulnScope

Thanks for taking the time. This document covers how to get the project running,
what the checks expect from a change, and how to add the two things people most
often want to add: a detection rule and a translation.

## Getting set up

You need **Node 18+** and **Rust 1.77+**. On Windows you also need the MSVC build
tools and WebView2 (WebView2 ships with Windows 11 and current Windows 10).

```bash
npm install
npm run tauri dev
```

`tauri dev` starts Vite on port 1420 and builds the Rust core. The first build
takes a few minutes; later ones are incremental.

## Before you open a pull request

Run the full suite. It is one command and it is the same thing CI runs:

```bash
npm run check:all
```

That expands to a TypeScript typecheck, eight audit scripts, a production build,
the Rust test suite, and Clippy with warnings denied. If it passes locally it
passes in CI, with one exception: the backend job runs on Windows, so a change
touching process spawning or path handling should be tested there.

The audit scripts are not ceremony — each exists because something shipped broken
in a way that review did not catch:

| Command | Guards against |
|---|---|
| `npm run audit:contrast` | Unreadable text: WCAG 2.2 AA across all themes, plus colour-vision simulations |
| `npm run audit:i18n` | A string reaching the UI with no English translation |
| `npm run audit:sarif` | A SARIF export GitHub code scanning would reject |
| `npm run audit:score` | Wrong maths behind the dashboard's headline number |
| `npm run audit:xml1c` | Malformed or unescaped 1C XML that fails silently on import |
| `npm run audit:excel` | A SpreadsheetML workbook Excel refuses to open |
| `npm run audit:cssvars` | A misspelled design token, which drops the whole declaration |
| `npm run audit:settings` | A setting that saves and animates but nothing reads |

If you add a feature with a failure mode that review cannot see, consider adding
an audit for it. That is the house style.

## Adding a detection rule

Rules live in [`src-tauri/src/rules.rs`](src-tauri/src/rules.rs) as entries in the
`RULES` array. Add one at the end of its language's section and give it the next
free id in that language's range (`VS-PY-041`, `VS-GO-015`, and so on).

```rust
Rule {
    id: "VS-PY-041",
    title: "Короткий заголовок находки",
    description: "Что именно опасно и почему — на русском, это исходный язык.",
    recommendation: "Что сделать вместо этого, конкретно.",
    severity: Severity::High,
    confidence: Confidence::Medium,
    category: "Инъекция команд",
    languages: PY,
    pattern: r"\bdangerous_call\s*\(",
    unless_contains: &["safe_wrapper"],
    cwe: &["CWE-78"],
    owasp: Some(OWASP_INJECTION),
    references: &["https://cwe.mitre.org/data/definitions/78.html"],
    skip_in_tests: true,
},
```

Four things the checks will hold you to:

1. **The `regex` crate has no lookaround.** "Match X unless Y is nearby" is
   expressed with `unless_contains`, not a negative lookahead. A pattern that
   does not compile fails `every_rule_pattern_compiles`.
2. **Russian is the source language.** `title`, `description`, `recommendation`
   and `category` are written in Russian, and every one of them needs an entry in
   the `EN` dictionary in [`src/i18n.tsx`](src/i18n.tsx). `npm run audit:i18n`
   fails otherwise — a rule with no translation shows up as Russian text in the
   English interface, which nobody notices until they switch languages.
3. **Add a test.** Rules carry their own tests at the bottom of `rules.rs`. Assert
   that the rule fires on a vulnerable sample, and — where the rule has a guard —
   that it stays quiet on the safe form:

   ```rust
   #[test]
   fn finds_the_thing() {
       let bad = "dangerous_call(user_input)\n";
       assert!(hit_ids(bad, Language::Python, "app.py").contains(&"VS-PY-041"));

       let good = "safe_wrapper(dangerous_call(user_input))\n";
       assert!(!hit_ids(good, Language::Python, "app.py").contains(&"VS-PY-041"));
   }
   ```

4. **Set `confidence` honestly.** `Confidence::High` means the match is a finding
   on its own. If a human has to look at it to decide, it is `Medium`. A scanner
   loses its audience faster to confident noise than to a missed finding.

`skip_in_tests: true` suppresses the rule inside test files, where dangerous
constructs are often deliberate. Use it for anything that would otherwise light up
a test suite.

## Adding or fixing a translation

The dictionary is gettext-style: the key is the Russian string itself, and a
missing key silently falls back to Russian rather than failing. That is what
`npm run audit:i18n` exists to catch. To add translations, run the audit — it
prints exactly which keys are missing and where each one comes from.

Strings with no Cyrillic in them (`Path traversal`, `Semgrep`, `document.write()`)
are deliberately skipped: the fallback already produces the right English.

## Style

- **Rust:** `cargo fmt` before committing; Clippy runs with `-D warnings`.
- **TypeScript:** the existing code is the guide. No formatter is enforced.
- **Colours:** never hardcode one. Every colour comes from a token in
  [`src/theme.css`](src/theme.css); `audit:cssvars` enforces this.
- **Comments:** explain *why*, not *what*. The codebase leans on this heavily —
  most comments record the bug that motivated the code. Please keep that up.

## Commits and pull requests

Commit messages in this repository are written in Russian, in the imperative, and
describe the effect rather than the file touched ("Фикс: отменённый скан не
попадает в недавние проекты"). English is fine too — clarity matters more than
the language.

Open pull requests against `main`. Describe what changes for the user and, if the
change fixes something, what the broken behaviour was. If it touches detection,
say what it now finds or stops finding, and on what sample.

## Reporting bugs

Open an issue with the OS, the VulnScope version, and what you expected versus
what happened. For a detection problem, a minimal code sample is worth more than
anything else — it becomes the regression test.

Security vulnerabilities in VulnScope itself go through
[SECURITY.md](SECURITY.md), not the public issue tracker.
