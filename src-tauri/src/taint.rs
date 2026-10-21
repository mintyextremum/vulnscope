//! Deterministic, explainable data-flow (taint) analysis — the project's own
//! flagship engine.
//!
//! Pattern rules answer "is there a dangerous call on this line?". This answers
//! the harder, more valuable question: "does *user-controlled data* actually
//! reach that call?". It tracks tainted variables across lines within a file —
//! a value read from a request/argv/stdin taints a variable, the taint
//! propagates through assignments, and reaching a dangerous sink produces a
//! finding that carries the full **source → … → sink** path.
//!
//! It is intentionally simple and conservative rather than a full compiler:
//! single file, identifier-level tracking, a line window, and sanitiser-aware
//! untainting. That keeps it deterministic and every finding self-verifiable —
//! the reviewer sees the exact chain — which is the whole selling point over a
//! grep-style scanner. No AI, no heurist­ic guesswork.

use crate::model::{Language, Severity};
use crate::rules;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// How far a source and its sink may sit apart. Scopes are bounded by function
/// signatures, which every heuristic language now has, so this only has to stop
/// a runaway in a very long top-level script. It used to be 80 — the only fence
/// between methods in languages without scoping — and a legacy function longer
/// than that lost every flow that crossed its middle.
const WINDOW: u32 = 400;
/// Cap findings per file so a pathological file cannot flood the report.
const MAX_FLOWS: usize = 20;
/// How many times to recompute function summaries. Each pass lets a call learn
/// its callee's freshly-computed behaviour; the cap terminates on recursion.
const MAX_SUMMARY_ITERS: usize = 5;

#[derive(Debug, Clone, PartialEq)]
pub enum FlowRole {
    /// Where user-controlled data enters.
    Source,
    /// A variable assignment that carries the taint forward.
    Propagation,
    /// The tainted value is handed to a user-defined function as an argument —
    /// the step where the flow crosses a function boundary.
    Call,
    /// The dangerous call the tainted data reaches.
    Sink,
}

#[derive(Debug, Clone)]
pub struct FlowStep {
    pub line: u32,
    pub code: String,
    pub role: FlowRole,
    /// The file this step is in, when it differs from the file being analyzed —
    /// set only on a sink reached across a file boundary. `None` means "the same
    /// file", which every step is until the flow crosses into a callee elsewhere.
    pub file: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TaintFlow {
    pub category: &'static str,
    pub cwe: &'static [&'static str],
    pub severity: Severity,
    /// Ordered: source first, sink last.
    pub steps: Vec<FlowStep>,
}

impl TaintFlow {
    #[allow(dead_code)] // used in tests and by callers that inspect the path
    pub fn source_line(&self) -> u32 {
        self.steps.first().map(|s| s.line).unwrap_or(0)
    }
    #[allow(dead_code)]
    pub fn sink_line(&self) -> u32 {
        self.steps.last().map(|s| s.line).unwrap_or(0)
    }

    /// Where the untrusted data enters, classified from the source line — so a
    /// finding says "from an HTTP request" or "from a CLI argument" rather than
    /// a generic "user input". This is what a real attack path starts at.
    pub fn entry_kind(&self) -> &'static str {
        let code = self.steps.first().map(|s| s.code.as_str()).unwrap_or("");
        classify_entry(code)
    }
}

/// A Russian label for where untrusted data enters, from the source line.
fn classify_entry(code: &str) -> &'static str {
    // A bound handler parameter or a route path is request data by definition,
    // whatever the parameter happens to be called — `@RequestParam String input`
    // is not standard input.
    if PARAM_SOURCE_RE.is_match(code) || ROUTE_RE.is_match(code) {
        return "HTTP-запрос";
    }
    let c = code.to_lowercase();
    if c.contains("argv") || c.contains("sys.argv") {
        "аргумент командной строки"
    } else if c.contains("getenv")
        || c.contains("process.env")
        || c.contains("os.environ")
        || c.contains("std::env")
        || c.contains("environment")
    {
        "переменная окружения"
    } else if c.contains("stdin")
        || c.contains("readline")
        || c.contains("console.read")
        || contains_word(&c, "input")
    {
        "стандартный ввод"
    } else if c.contains("location.")
        || c.contains("urlsearchparams")
        || c.contains("document.url")
        || c.contains("referrer")
        || c.contains("window.name")
    {
        // Browser-side sources: the attacker controls them through the URL the
        // victim opens, which deserves its own label — "HTTP request" would
        // point the reviewer at the wrong side of the wire.
        "адрес страницы (DOM)"
    } else if c.contains("req")
        || c.contains("request")
        || c.contains("param")
        || c.contains("body")
        || c.contains("cookie")
        || c.contains("form")
        || c.contains("payload")
        || c.contains("query")
        || c.contains("getheader")
        || c.contains("mux.vars")
        || c.contains("$_get")
        || c.contains("$_post")
        || c.contains("$_request")
        || c.contains("$_cookie")
        || c.contains("$_files")
        || c.contains("$_server")
        || c.contains("filter_input")
        || c.contains("fieldstorage")
        || c.contains("php://input")
    {
        "HTTP-запрос"
    } else {
        "пользовательский ввод"
    }
}

/// Shared user-input source pattern (same one the heuristics use).
static SOURCE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(rules::HEURISTICS[0].taint).expect("bad taint source pattern"));

// Sink categories, as spelled by the heuristics in `rules.rs`. Kept as
// constants so a sanitiser's scope cannot drift from the category it claims to
// neutralise — `sanitiser_scopes_name_real_categories` asserts every one of
// these appears in HEURISTICS.
const CAT_CMD: &str = "Инъекция команд";
const CAT_SQL: &str = "SQL-инъекция";
const CAT_NOSQL: &str = "NoSQL-инъекция";
const CAT_PATH: &str = "Path traversal";
const CAT_XSS: &str = "XSS";
const CAT_CODE: &str = "Выполнение кода";
const CAT_REDIRECT: &str = "Открытый редирект";
const CAT_SSRF: &str = "SSRF";

/// What a sanitiser actually protects against.
///
/// The distinction matters more than it looks. `htmlspecialchars` makes a value
/// safe to print into HTML and does nothing whatsoever for SQL: treating it as a
/// blanket clearance means
///
/// ```python
/// safe = html.escape(request.args.get('id'))
/// cur.execute('SELECT * FROM t WHERE id = ' + safe)
/// ```
///
/// is silently dropped — a real injection the engine saw and discarded. A false
/// negative here is the worst kind the flagship can produce: the reviewer is
/// told the path was checked.
enum Scope {
    /// Neutralises the value entirely — a parsed integer or an allowlisted
    /// choice cannot carry a payload for any sink.
    Everything,
    /// Neutralises only these sink categories.
    Only(&'static [&'static str]),
}

/// Sanitisers whose scope is well understood, checked before the generic terms
/// below. Order matters only in that a match here suppresses the generic pass;
/// several entries may match, and their categories are unioned.
static SCOPED_SANITIZERS: Lazy<Vec<(Regex, &'static [&'static str])>> = Lazy::new(|| {
    let table: &[(&str, Scope)] = &[
        // Shell quoting: safe to hand to a shell, still hostile in SQL or HTML.
        (r"escapeshellarg|escapeshellcmd|shlex\.quote|pipes\.quote", Scope::Only(&[CAT_CMD])),
        // HTML/XSS sanitisers. `strip_tags` removes markup and nothing else.
        (
            // `html_?encode` is .NET's HttpUtility/WebUtility/AntiXss HtmlEncode;
            // `forhtml` is the OWASP Java Encoder (`Encode.forHtml`,
            // `forHtmlAttribute`, `forHtmlContent`). Without them both fell to the
            // generic `encode` bucket and cleared SQL taint along with XSS.
            r"htmlspecialchars|htmlentities|bleach\.clean|strip_tags|escape_?html|html[._]?escape|cgi\.escape|sanitize_?html|dompurify\.sanitize|html_?encode|encode\.forhtml",
            Scope::Only(&[CAT_XSS]),
        ),
        // Parameterisation is the SQL/NoSQL answer; it says nothing about a path
        // or a shell.
        (
            r"parameteriz|prepared?_?statement|bindparam|bind_param|placeholder|real_escape_string|pg_escape|quote_ident|addslashes",
            Scope::Only(&[CAT_SQL, CAT_NOSQL]),
        ),
        // Path canonicalisation: stops `..`, stops nothing else.
        (
            // Apache Commons `FilenameUtils.getName` and .NET `Path.GetFileName`
            // drop every directory component, the same guarantee as `basename`.
            r"filepath\.clean|secure_filename|os\.path\.basename|\bbasename\s*\(|werkzeug\.utils\.secure_filename|filenameutils\.getname|path\.getfilename",
            Scope::Only(&[CAT_PATH]),
        ),
        // URL-component encoding keeps a value inside one URL field, which is
        // what an open redirect abuses. It does not stop SSRF: a fully encoded
        // attacker host is still that host.
        // `escapedatastring` is .NET's `Uri.EscapeDataString`, the
        // encodeURIComponent of that world.
        (
            r"encodeuricomponent|urlencode|url_encode|quote_plus|escapedatastring",
            Scope::Only(&[CAT_REDIRECT, CAT_XSS]),
        ),
        // LDAP filter escaping — no taint category of its own today, so it
        // clears nothing rather than pretending to cover one.
        (r"escape_filter_chars|filterencode|encodevalue", Scope::Only(&[])),
        // Numeric and boolean coercions: the result cannot carry a payload of
        // any kind, so this genuinely is a blanket clearance.
        (
            r"strconv\.(?:Atoi|ParseInt|ParseFloat|ParseBool)|\bint\s*\(|\binteger\s*\(|parseint|\bnumber\s*\(|\bto_i\b|::from_str|parsefloat",
            Scope::Everything,
        ),
        // An allowlist replaces the value with one the code already trusts.
        (r"whitelist|allowlist", Scope::Everything),
    ];
    table
        .iter()
        .map(|(pat, scope)| {
            let cats: &'static [&'static str] = match scope {
                Scope::Everything => ALL_CATEGORIES,
                Scope::Only(c) => c,
            };
            (
                Regex::new(&format!("(?i){pat}")).expect("bad scoped sanitizer pattern"),
                cats,
            )
        })
        .collect()
});

/// Every sink category the engine knows. Used as the clearance set for
/// sanitisers that genuinely neutralise a value for all of them.
const ALL_CATEGORIES: &[&str] =
    &[CAT_CMD, CAT_SQL, CAT_NOSQL, CAT_PATH, CAT_XSS, CAT_CODE, CAT_REDIRECT, CAT_SSRF];

/// Broad, ambiguous wording — `escape(`, `sanitize(`, `encode(`, `quote(`. The
/// intent is protective but the target is unknowable from the name alone, so
/// these keep the old blanket behaviour rather than guessing a scope and
/// inventing findings. Only consulted when no scoped sanitiser above matched,
/// otherwise `escapeshellarg` would match bare `escape` and widen itself back to
/// everything.
static GENERIC_SANITIZER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:escape|sanitiz|encode|quote)").expect("bad generic sanitizer pattern")
});

/// The categories `rhs` neutralises, or `None` when it sanitises nothing.
fn sanitized_categories(rhs: &str) -> Option<BTreeSet<&'static str>> {
    let mut cats: BTreeSet<&'static str> = BTreeSet::new();
    let mut matched = false;
    for (re, categories) in SCOPED_SANITIZERS.iter() {
        if re.is_match(rhs) {
            matched = true;
            cats.extend(categories.iter().copied());
        }
    }
    if matched {
        return Some(cats);
    }
    if GENERIC_SANITIZER_RE.is_match(rhs) {
        return Some(ALL_CATEGORIES.iter().copied().collect());
    }
    None
}

/// Compiled sink patterns for every heuristic, paired with its metadata.
struct CompiledSink {
    re: Regex,
    category: &'static str,
    cwe: &'static [&'static str],
    severity: Severity,
    langs: &'static [Language],
}

static SINKS: Lazy<Vec<CompiledSink>> = Lazy::new(|| {
    rules::HEURISTICS
        .iter()
        .map(|h| CompiledSink {
            re: Regex::new(h.sink).expect("bad heuristic sink pattern"),
            category: h.category,
            cwe: h.cwe,
            severity: h.severity,
            langs: h.languages,
        })
        .collect()
});

/// An assignment `lhs = rhs`, tolerant of common type/keyword prefixes and of
/// the many assignment spellings across languages, while rejecting comparisons
/// (`==`, `<=`, `!=`) — the regex engine has no look-behind, so the `[^=]` after
/// `=` and the leading anchor carry that weight.
///
/// Declared types were once a fixed list (`String`, `int`, …), so any other
/// type made the line invisible as an assignment and the taint stopped there:
/// `URL url = new URL(u)`, `List<String> xs = …`, C#'s lowercase `string`, and
/// every annotated declaration — `const id: string = req.query.id`, which is
/// simply how TypeScript is written. Both shapes are now accepted generically.
static ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        // Declaration keywords and primitives, as before.
        r"^\s*(?:(?:let|const|var|val|my|final|auto|public|private|protected|static|String|int|long|short|float|double|bool|boolean|char|def|func|fn|dim|set)\s+)*",
        // A type before the name: `URL url`, `List<String> xs`, `byte[] b`,
        // `string? s`. Generics may nest; they can never contain `=` or `;`.
        r"(?:[A-Za-z_][\w.]*(?:<[^=;]*?>)?(?:\[\])*\??\s+)?",
        r"(\$?[A-Za-z_][\w]*)",
        // An annotation after the name: TypeScript `id: string`, Kotlin
        // `url: URL`, Python `x: int`. A type is at least one character, so
        // Go's `:=` never reads as an empty annotation.
        r"\s*(?::\s*[\w.<>\[\],|? ]+?\s*)?",
        r"(?::?=|:=|<-)\s*([^=].*)$",
    ))
    .expect("bad assignment pattern")
});

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Whole-identifier containment: `user` matches `user` but not `username`.
fn contains_word(hay: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let bytes = hay.as_bytes();
    let mut from = 0;
    while let Some(pos) = hay[from..].find(word) {
        let start = from + pos;
        let end = start + word.len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// The line with string-literal contents blanked out and interpolation kept.
///
/// A variable's name inside a string literal is text, not a reference.
/// `"SELECT * FROM t WHERE id = ?"` names the column `id`; reading that as the
/// tainted variable `id` reported the canonical *safe* query as an injection,
/// in every language, and would have done so for every correctly written JDBC
/// call the moment Java sinks were added.
///
/// Interpolation is the main road to injection, so it survives: `${…}` and
/// `#{…}` (JS templates, Kotlin, Groovy, Scala, Ruby), `{…}` behind an f-string
/// or a C# `$` prefix, and `$name` (PHP, Perl, Kotlin, Scala, Groovy).
///
/// Only for deciding which variables a line *references* and whether a
/// sanitiser is *called*. Sink and source patterns still read the raw line:
/// `header("Location: …")` and `php://input` live inside strings by nature.
fn mask_strings(s: &str) -> String {
    scan_text(s, ScanOpts { strings: true, aligned: false }).0
}

/// [`mask_strings`] plus whether the text ends inside a string allowed to run
/// onto the next line — what the statement joiner needs.
fn scan_strings(s: &str) -> (String, bool) {
    scan_text(s, ScanOpts { strings: true, aligned: false })
}

/// The text with only regex-literal contents blanked. Sources are matched on
/// this: a source pattern can legitimately sit inside a string (`php://input`,
/// `$_SERVER['HTTP_…']`) but never inside a regular expression — and
/// `match: /@(return|param)/` was read as a request parameter.
fn mask_regex(s: &str) -> String {
    scan_text(s, ScanOpts { strings: false, aligned: true }).0
}

/// What a scan blanks out.
#[derive(Clone, Copy)]
struct ScanOpts {
    /// String-literal contents (interpolation always stays, as code).
    strings: bool,
    /// One output character per input character: `$name` is not doubled. Needed
    /// to ask whether a given position is code.
    aligned: bool,
}

/// The scanner behind every masking helper. Regex literals are always blanked;
/// string contents when asked. Also reports whether the text ends inside a
/// string allowed to span lines — a backtick template or raw string, or a
/// Python triple-quoted string.
///
/// Triple quotes are one delimiter: treating `"""` as an empty string followed
/// by an opening quote lost the `f` prefix, so the `{id}` inside
/// `f"""SELECT … {id}"""` was masked away as plain text.
///
/// A `/` opens a regex literal only where an operand is expected — after
/// `( , = : [ ! & | ? { } ; ~` or at the start — and only when it closes on the
/// same line. `a / b` stays a division in every language, and without this a
/// `//` inside `/^https?:\/\//` read as a comment and cut the statement short.
fn scan_text(s: &str, o: ScanOpts) -> (String, bool) {
    // No quote and no slash: no literal can start, the text is all code.
    if !s.contains(['"', '\'', '`', '/']) {
        return (s.to_string(), false);
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut open_multiline = false;
    let mut last_code: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let quote = chars[i];
        if quote == '/' {
            let next = chars.get(i + 1).copied();
            if next != Some('/') && next != Some('*') && regex_may_start(last_code) {
                if let Some(close) = regex_end(&chars, i + 1) {
                    out.push('/');
                    for _ in i + 1..close {
                        out.push(' ');
                    }
                    out.push('/');
                    i = close + 1;
                    last_code = Some('/');
                    continue;
                }
            }
        }
        if quote != '"' && quote != '\'' && quote != '`' {
            out.push(quote);
            if !quote.is_whitespace() {
                last_code = Some(quote);
            }
            i += 1;
            continue;
        }
        let braces = interpolating_prefix(&chars[..i]);
        let triple = chars.get(i + 1) == Some(&quote) && chars.get(i + 2) == Some(&quote);
        let width = if triple { 3 } else { 1 };
        for _ in 0..width {
            out.push(quote);
        }
        i += width;
        let closes_at = |k: usize| -> bool {
            if triple {
                chars.get(k) == Some(&quote)
                    && chars.get(k + 1) == Some(&quote)
                    && chars.get(k + 2) == Some(&quote)
            } else {
                chars.get(k) == Some(&quote)
            }
        };
        let mut closed = false;
        while i < chars.len() {
            if closes_at(i) {
                closed = true;
                break;
            }
            let ch = chars[i];
            let next = chars.get(i + 1).copied();
            if ch == '\\' {
                // An escape consumes the next character, quote included.
                if o.strings {
                    out.push(' ');
                    if next.is_some() {
                        out.push(' ');
                    }
                } else {
                    out.push(ch);
                    if let Some(n) = next {
                        out.push(n);
                    }
                }
                i += 2;
                continue;
            }
            if braces && ch == '{' && next == Some('{') {
                // `{{` is an escaped literal brace in an f-string or C# `$"…"`.
                // Consuming only the first would leave the second looking like
                // an interpolation opener, and `{{id}}` would read as `{id}`.
                out.push_str(if o.strings { "  " } else { "{{" });
                i += 2;
                continue;
            }
            let lead_in = (ch == '$' || ch == '#') && next == Some('{');
            if lead_in || (braces && ch == '{') {
                // Keep the balanced `{…}`, with its `$`/`#`, verbatim.
                if lead_in {
                    out.push(ch);
                    i += 1;
                }
                let mut depth = 0;
                while i < chars.len() {
                    let c = chars[i];
                    out.push(c);
                    i += 1;
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                continue;
            }
            if ch == '$' && next.is_some_and(|n| n.is_ascii_alphabetic() || n == '_') {
                // `$name` is emitted twice when not aligned: as `$name` for PHP
                // and Perl, whose variables carry the sigil, and as bare `name`
                // for Kotlin, Scala and Groovy, whose do not. No language has
                // both spellings of one variable, so neither reading can match
                // the wrong one.
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                let name: String = chars[i + 1..j].iter().collect();
                out.push('$');
                out.push_str(&name);
                if o.strings && !o.aligned {
                    out.push(' ');
                    out.push_str(&name);
                }
                i = j;
                continue;
            }
            out.push(if o.strings { ' ' } else { ch });
            i += 1;
        }
        if closed {
            for _ in 0..width {
                out.push(quote);
            }
            i += width;
        } else if triple || quote == '`' {
            open_multiline = true;
        }
        last_code = Some(quote);
    }
    (out, open_multiline)
}

fn regex_may_start(prev: Option<char>) -> bool {
    // Spelled as a match: `Option::is_none_or` needs Rust 1.82, and the crate
    // promises 1.77.
    match prev {
        None => true,
        Some(p) => "(,=:[!&|?{};~".contains(p),
    }
}

/// Where the regex literal whose body starts at `from` closes: the next
/// unescaped `/` outside a `[…]` class. `None` — not a regex after all.
fn regex_end(chars: &[char], from: usize) -> Option<usize> {
    let mut class = false;
    let mut i = from;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                i += 2;
                continue;
            }
            '[' => class = true,
            ']' => class = false,
            '/' if !class => return (i > from).then_some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// The first match of `re` that begins in code. A sink written inside a string
/// or a regex literal is text — the log line `"calling system("` is not a call
/// to `system`. Only the match's first non-blank character is tested, so
/// `header("Location: …")`, whose second half lives in a string by nature,
/// still counts.
fn first_match_in_code<'t>(text: &'t str, re: &Regex) -> Option<regex::Match<'t>> {
    let mut found = re.find_iter(text).peekable();
    found.peek()?;
    let code: Vec<char> = scan_text(text, ScanOpts { strings: true, aligned: true }).0.chars().collect();
    found.find(|m| {
        let lead = m.as_str().chars().take_while(|c| c.is_whitespace()).count();
        let ci = text[..m.start()].chars().count() + lead;
        match (text[m.start()..].chars().nth(lead), code.get(ci)) {
            (Some(orig), Some(masked)) => orig == *masked,
            _ => false,
        }
    })
}

/// Longest statement the joiner assembles. A runaway — a parenthesis the scan
/// misread — stops here instead of swallowing the rest of the file.
const MAX_JOIN: usize = 40;

/// Physical lines folded into logical statements.
///
/// The engine reads one line at a time, and formatters do not write one
/// statement per line: black, prettier and gofmt all break a long call, so
/// `cur.execute(` sat on one line and the tainted `+ uid` on the next, and
/// neither line alone was a flow. Every probe of a formatted call came back
/// empty.
///
/// A statement continues while a parenthesis or bracket is open (and, in
/// Python, a brace — there it is never a block), while a backtick or
/// triple-quoted string is open, after a trailing `\`, after a trailing binary
/// operator, or when the next line opens a fluent chain with `.`. The joined
/// text goes on the statement's first line and its other lines become empty, so
/// every index, function range and reported line number stays where it was.
fn join_continuations<'a>(lines: &[&'a str], lang: Language) -> Vec<std::borrow::Cow<'a, str>> {
    use std::borrow::Cow;
    let n = lines.len();
    let mut out: Vec<Cow<'a, str>> = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        if rules::is_comment_line(lines[i], lang) {
            out.push(Cow::Borrowed(lines[i]));
            i += 1;
            continue;
        }
        // Most lines are complete statements: they are borrowed, not copied.
        if i + 1 >= n || !continues(lines[i], lines[i + 1], lang) {
            out.push(Cow::Borrowed(lines[i]));
            i += 1;
            continue;
        }
        let mut joined = lines[i].trim_end().to_string();
        let mut j = i;
        while j + 1 < n && j + 1 - i < MAX_JOIN && continues(&joined, lines[j + 1], lang) {
            j += 1;
            let next = lines[j].trim();
            if !next.is_empty() {
                joined.push(' ');
                joined.push_str(next);
            }
        }
        out.push(Cow::Owned(joined));
        out.extend((i + 1..=j).map(|_| Cow::Borrowed("")));
        i = j + 1;
    }
    out
}

/// Whether the statement in `joined` runs on into `next`.
fn continues(joined: &str, next: &str, lang: Language) -> bool {
    // Fast path: most lines are complete statements. With brackets balanced by
    // a raw count, no multi-line string opener, no trailing operator and no
    // continuation leading the next line, nothing can continue, and the string
    // scan is skipped. A raw count can be fooled only by a string holding an
    // unbalanced bracket — that costs a join, the behaviour before joining
    // existed, and never produces a wrong one.
    let python = lang == Language::Python;
    let raw_depth: i32 = joined
        .chars()
        .map(|c| match c {
            '(' | '[' => 1,
            ')' | ']' => -1,
            '{' if python => 1,
            '}' if python => -1,
            _ => 0,
        })
        .sum();
    let tail = joined.trim_end();
    let lead = next.trim_start();
    let maybe = raw_depth != 0
        || joined.contains('`')
        || joined.contains("\"\"\"")
        || joined.contains("'''")
        || tail.ends_with(|c: char| "+=>\\.&|-".contains(c))
        || lead.starts_with(|c: char| ".+&|?".contains(c));
    if !maybe {
        return false;
    }
    let (code, open_string) = scan_strings(joined);
    if open_string {
        return true;
    }
    let code = strip_trailing_comment(&code, lang);
    let mut depth = 0i32;
    for c in code.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            '{' if python => depth += 1,
            '}' if python => depth -= 1,
            _ => {}
        }
    }
    let t = code.trim_end();
    // A line ending in `{` opens a block. Joining across it folded a whole
    // callback into one line — `app.get('/u', (req, res) => {` keeps its
    // parenthesis open until `});`, so every Express handler, every `describe`
    // and every promise chain became a single statement and nothing inside it
    // was an assignment any more. Python is the exception: there a brace is
    // always a dict or a set.
    if !python && t.ends_with('{') {
        return false;
    }
    if depth > 0 {
        return true;
    }
    if t.is_empty() {
        return false;
    }
    if t.ends_with('\\') || ends_with_operator(t) {
        return true;
    }
    // A line opening with `.` or `?.` continues a fluent chain; a leading
    // binary operator continues an expression split before it.
    let nt = next.trim_start();
    (nt.starts_with('.') && !nt.starts_with(".."))
        || nt.starts_with("?.")
        || nt.starts_with("+ ")
        || nt.starts_with("&& ")
        || nt.starts_with("|| ")
}

/// A binary operator no statement can end on. `++` is a statement on its own,
/// a trailing `.` after a digit is a float literal, `..` a range or spread,
/// and `?` is left out because Ruby and Elixir name predicates with it. A
/// trailing `,` is left out too: inside a call or an array the open bracket
/// already continues the statement, and anywhere else it is the member of an
/// object literal — joining those folded a whole grammar table into one line.
fn ends_with_operator(t: &str) -> bool {
    if t.ends_with("++") || t.ends_with("--") {
        return false;
    }
    if t.ends_with("&&") || t.ends_with("||") || t.ends_with("=>") || t.ends_with("->") {
        return true;
    }
    match t.chars().last() {
        Some('+') | Some('=') => true,
        Some('.') => {
            let prev = t.chars().rev().nth(1);
            !t.ends_with("..") && prev.is_some_and(|p| !p.is_ascii_digit())
        }
        _ => false,
    }
}

/// `code` (already string-masked) without a trailing line comment, so an
/// operator or bracket inside the comment cannot extend the statement. `//`
/// is not a comment in Python (floor division) or Perl (defined-or); `#` is
/// not one in the C family, and `#{` is Ruby interpolation.
fn strip_trailing_comment(code: &str, lang: Language) -> &str {
    let hash = matches!(
        lang,
        Language::Python | Language::Ruby | Language::Perl | Language::Elixir | Language::Php
    );
    let slashes = !matches!(lang, Language::Python | Language::Perl);
    let bytes = code.as_bytes();
    for (k, &b) in bytes.iter().enumerate() {
        if slashes && b == b'/' && bytes.get(k + 1) == Some(&b'/') {
            return &code[..k];
        }
        if hash && b == b'#' && bytes.get(k + 1) != Some(&b'{') {
            return &code[..k];
        }
    }
    code
}

/// Whether a string opening right after `before` takes `{…}` interpolation: a
/// Python f-string (`f`, `rf`, `fr`, any case) or a C# interpolated string
/// (`$`, `$@`, `@$`). The prefix has to stand alone — `buf"` is no f-string.
fn interpolating_prefix(before: &[char]) -> bool {
    let mut k = before.len();
    let mut prefix = String::new();
    while k > 0 && prefix.len() < 3 {
        let c = before[k - 1];
        if c.is_ascii_alphabetic() || c == '$' || c == '@' {
            prefix.insert(0, c);
            k -= 1;
        } else {
            break;
        }
    }
    if k > 0 && (before[k - 1].is_ascii_alphanumeric() || before[k - 1] == '_') {
        return false;
    }
    matches!(prefix.to_ascii_lowercase().as_str(), "f" | "rf" | "fr" | "$" | "$@" | "@$")
}

/// The top-level arguments of the call whose `(` sits just before `from`, or
/// `None` when the closing parenthesis is not on this line.
fn call_args_from(text: &str, from: usize) -> Option<Vec<String>> {
    let tail = text.get(from..)?;
    let mut depth = 1i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in tail.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(split_top_commas(&tail[..idx]));
                }
            }
            _ => {}
        }
    }
    None
}

/// For a SQL sink, the part of the line that is *query text*.
///
/// The difference between SQL injection and a parameterised query is exactly
/// whether the value went into the query or beside it:
///
/// ```text
/// cur.execute("SELECT … WHERE id = " + id)        # injection
/// cur.execute("SELECT … WHERE id = %s", (id,))    # parameterised
/// ```
///
/// Both put `id` on the sink line, so the whole-line check reported the safe
/// form too — for DB-API, mysql2, pg, JdbcTemplate and EF Core alike, whose
/// bind parameters all follow the query. Only the query argument counts: the
/// first one, or the first two for PHP's procedural drivers, which take the
/// connection first (`mysqli_query($link, $sql)`) — except the old
/// `mysql_query($sql, $link)`, which the pair covers too. A call whose closing
/// parenthesis is on another line falls back to the whole line: missing a
/// bind parameter is the cheaper mistake than missing an injection.
fn sql_query_text<'a>(text: &'a str, m: regex::Match<'a>) -> std::borrow::Cow<'a, str> {
    // The argument list opens at the last parenthesis inside the match, not
    // necessarily at its end: `.where('` carries the opening quote that tells a
    // raw-SQL builder call from a bound one.
    let Some(paren) = m.as_str().rfind('(') else {
        return std::borrow::Cow::Borrowed(text);
    };
    let Some(args) = call_args_from(text, m.start() + paren + 1) else {
        return std::borrow::Cow::Borrowed(text);
    };
    // The query is the first argument, unless something plainer comes first. A
    // connection, a context or a repository is a bare handle — `$db`, `ctx`,
    // `Repo` — while a query is a literal, a concatenation, or a variable
    // holding one. When argument one is a handle, argument two counts as well,
    // which is what `mysqli_query($link, $sql)`, `db.QueryContext(ctx, sql)`
    // and `Ecto.Adapters.SQL.query(Repo, sql)` all need. This replaced a list
    // of driver prefixes that would have had to grow for every ecosystem.
    //
    // Bind parameters can never qualify: they follow the query and arrive as a
    // collection, so `cur.execute(sql, (id,))` still stops at `sql`.
    let take = if args.len() > 1 && is_bare_handle(&args[0]) && !is_collection(&args[1]) {
        2
    } else {
        1
    };
    std::borrow::Cow::Owned(args.into_iter().take(take).collect::<Vec<_>>().join(","))
}

/// A bare handle: letters, digits and the punctuation that spells a path to one
/// (`_ $ . : & *`). No quotes, no operators, no call of its own — so `conn`,
/// `$db`, `ctx` and `Ecto.Repo` qualify, and `"SELECT …" + id` does not.
fn is_bare_handle(arg: &str) -> bool {
    let t = arg.trim();
    !t.is_empty()
        && t.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '$' | '.' | ':' | '&' | '*'))
}

/// A tuple, list, array or map literal — the shape bind parameters arrive in.
fn is_collection(arg: &str) -> bool {
    let t = arg.trim_start();
    t.starts_with('(')
        || t.starts_with('[')
        || t.starts_with('{')
        || t.starts_with("new ")
        || t.starts_with("map[")
        || t.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("array("))
}

/// The chain that made a variable tainted, from its source to the latest step.
#[derive(Clone)]
struct TaintVar {
    steps: Vec<FlowStep>,
    /// When the taint originally came from a function parameter (during summary
    /// computation) rather than a real source, which parameter — by index. This
    /// is what lets a call site learn "argument in slot `i` reaches a sink".
    origin_param: Option<usize>,
    /// Sink categories this value has already been made safe for. A value that
    /// went through `htmlspecialchars` is harmless in HTML and unchanged
    /// everywhere else, so the clearance travels with the value instead of
    /// deleting it.
    cleared: BTreeSet<&'static str>,
}

impl TaintVar {
    fn source_line(&self) -> u32 {
        self.steps.first().map(|s| s.line).unwrap_or(0)
    }

    /// Whether this value is still dangerous for `category`.
    fn dangerous_for(&self, category: &str) -> bool {
        !self.cleared.contains(category)
    }
}

/// A user-defined function found in the file: its name, the variable names of
/// its parameters (as used in the body), the signature line and the body range.
struct Func {
    name: String,
    params: Vec<String>,
    sig: usize,
    body: std::ops::Range<usize>,
}

/// A dangerous call a parameter reaches inside a function, carried up so a caller
/// can show the sink that its argument ends up at.
#[derive(Clone, PartialEq)]
pub(crate) struct SinkHit {
    line: u32,
    code: String,
    category: &'static str,
    cwe: &'static [&'static str],
    severity: Severity,
    /// The file the sink lives in, set when this summary was exported from
    /// another file so a cross-file flow can point at the right place.
    file: Option<String>,
}

/// What a function does to its parameters, computed once and reused at every
/// call site: which parameters reach a sink, and which flow into its return.
/// Exported per file so a caller elsewhere can resolve a call across the
/// boundary — the cross-file layer of the flagship engine.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct Summary {
    sink_params: BTreeMap<usize, SinkHit>,
    return_params: BTreeSet<usize>,
}

/// A tainted value reaching a sink: the steps to append to its chain, the sink's
/// metadata, and the variable whose chain to extend.
struct Reached<'a> {
    tail: Vec<FlowStep>,
    category: &'static str,
    cwe: &'static [&'static str],
    severity: Severity,
    var: &'a TaintVar,
}

/// The callback a sink reach invokes: the reaching variable, the sink's
/// metadata, and the tail steps (a `Sink`, or a `Call` then a `Sink`).
type OnSink<'a> =
    dyn FnMut(&TaintVar, &'static str, &'static [&'static str], Severity, Vec<FlowStep>) + 'a;

/// Every heuristic language now gets function scoping and interprocedural
/// tracing. Most define functions with a keyword (`def`, `function`, `func`,
/// `fun`, `sub`), so a definition can never be mistaken for a call. Java and C#
/// lead with a type instead, which is why they were left out — and why, until
/// now, a variable tainted in one method could meet a sink in the next, with
/// only an 80-line window between them. They are admitted on a stricter test:
/// a return type that is not a statement keyword, and nothing after the
/// parameter list but a block, `throws`, `=>` or a C# `where` clause. A call
/// statement ends in `;` or an operator and fails it.
pub(crate) fn scoped(lang: Language) -> bool {
    matches!(
        lang,
        Language::Python
            | Language::JavaScript
            | Language::TypeScript
            | Language::Jsx
            | Language::Tsx
            | Language::Go
            | Language::Php
            | Language::Java
            | Language::Kotlin
            | Language::CSharp
            | Language::Scala
            | Language::Ruby
            | Language::Elixir
            | Language::Perl
    )
}

/// What may follow a parameter list for the line to be a definition.
#[derive(Clone, Copy)]
enum Tail {
    /// Anything — the head is keyword-led already.
    Any,
    /// A JS arrow: `=>` after an optional return annotation.
    Arrow,
    /// A JS/TS method: a block after an optional return annotation.
    Block,
    /// A Java/C# member: optional `throws`, then a block, `=>`, a `where`
    /// clause, a `: base(…)` chain, or nothing at all (Allman style).
    Member,
}

struct SigHead {
    re: Regex,
    tail: Tail,
}

fn heads(src: &[(&str, Tail)]) -> Vec<SigHead> {
    src.iter()
        .map(|(p, tail)| SigHead {
            re: Regex::new(p).expect("bad signature pattern"),
            tail: *tail,
        })
        .collect()
}

/// Signature heads per language. Group `name` is the function; a head that
/// ends on `(` has its parameter list read by balance, not by `[^)]*` — which
/// stopped at the first `)` and lost every parameter after
/// `@RequestParam(name = "id")` or `def f(x=g())`.
static PY_HEADS: Lazy<Vec<SigHead>> =
    Lazy::new(|| heads(&[(r"^\s*(?:async\s+)?def\s+(?P<name>\w+)\s*\(", Tail::Any)]));

static JS_HEADS: Lazy<Vec<SigHead>> = Lazy::new(|| {
    heads(&[
        (r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(?P<name>\w+)\s*(?:<[^>(]*>)?\s*\(", Tail::Any),
        (r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>\w+)\s*(?::[^=]+)?=\s*(?:async\s+)?\(", Tail::Arrow),
        (r"^\s*(?:(?:public|private|protected|static|readonly|override)\s+)*(?P<name>\w+)\s*(?::[^=]+)?=\s*(?:async\s+)?\(", Tail::Arrow),
        // Class and object methods. Without a keyword, so a block must follow;
        // `if (…) {` and friends are rejected by name.
        (r"^\s*(?:(?:public|private|protected|static|async|override|get|set)\s+)*\*?\s*(?P<name>\w+)\s*(?:<[^>(]*>)?\s*\(", Tail::Block),
    ])
});

static PHP_HEADS: Lazy<Vec<SigHead>> = Lazy::new(|| {
    heads(&[(
        r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s*&?\s*(?P<name>\w+)\s*\(",
        Tail::Any,
    )])
});

static GO_HEADS: Lazy<Vec<SigHead>> = Lazy::new(|| {
    heads(&[(r"^\s*func\s+(?:\([^)]*\)\s*)?(?P<name>\w+)\s*(?:\[[^\]]*\])?\s*\(", Tail::Any)])
});

static JVM_HEADS: Lazy<Vec<SigHead>> = Lazy::new(|| {
    heads(&[
        (
            r"^\s*(?:@\w+(?:\([^)]*\))?\s+|\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|final|abstract|synchronized|native|default|async|override|virtual|sealed|extern|unsafe|partial|readonly|new|strictfp)\s+)*(?:<[^>]+>\s+)?(?P<rt>[\w.]+(?:<[^()]*>)?(?:\[\])*\??)\s+(?P<name>\w+)\s*(?:<[^>()]*>)?\s*\(",
            Tail::Member,
        ),
        // Constructors: an access modifier and a capitalised name, no type.
        (
            r"^\s*(?:@\w+(?:\([^)]*\))?\s+|\[[^\]]*\]\s*)*(?:public|private|protected|internal)\s+(?P<name>[A-Z]\w*)\s*\(",
            Tail::Member,
        ),
    ])
});

static KOTLIN_HEADS: Lazy<Vec<SigHead>> = Lazy::new(|| {
    heads(&[(
        r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|internal|override|open|suspend|inline|operator|infix|tailrec|abstract|final|external)\s+)*fun\s+(?:<[^>]+>\s*)?(?:[\w.]+\.)?(?P<name>\w+)\s*\(",
        Tail::Any,
    )])
});

static SCALA_HEADS: Lazy<Vec<SigHead>> = Lazy::new(|| {
    heads(&[
        (r"^\s*(?:(?:override|private|protected|final|implicit|inline|lazy)\s+)*def\s+(?P<name>\w+)\s*(?:\[[^\]]*\])?\s*\(", Tail::Any),
        (r"^\s*(?:(?:override|private|protected|final|implicit|inline|lazy)\s+)*def\s+(?P<name>\w+)", Tail::Any),
    ])
});

static RUBY_HEADS: Lazy<Vec<SigHead>> = Lazy::new(|| {
    heads(&[
        (r"^\s*def\s+(?:self\.)?(?P<name>\w+[?!]?)\s*\(", Tail::Any),
        (r"^\s*def\s+(?:self\.)?(?P<name>\w+[?!]?)", Tail::Any),
    ])
});

static ELIXIR_HEADS: Lazy<Vec<SigHead>> = Lazy::new(|| {
    heads(&[
        (r"^\s*defp?\s+(?P<name>\w+[?!]?)\s*\(", Tail::Any),
        (r"^\s*defp?\s+(?P<name>\w+[?!]?)", Tail::Any),
    ])
});

static PERL_HEADS: Lazy<Vec<SigHead>> =
    Lazy::new(|| heads(&[(r"^\s*sub\s+(?P<name>\w+)", Tail::Any)]));

fn heads_for(lang: Language) -> &'static [SigHead] {
    match lang {
        Language::Python => &PY_HEADS,
        Language::JavaScript | Language::TypeScript | Language::Jsx | Language::Tsx => &JS_HEADS,
        Language::Php => &PHP_HEADS,
        Language::Go => &GO_HEADS,
        Language::Java | Language::CSharp => &JVM_HEADS,
        Language::Kotlin => &KOTLIN_HEADS,
        Language::Scala => &SCALA_HEADS,
        Language::Ruby => &RUBY_HEADS,
        Language::Elixir => &ELIXIR_HEADS,
        Language::Perl => &PERL_HEADS,
        _ => &[],
    }
}

/// Words that open a statement, never a definition, wherever a name is read.
const CONTROL: &[&str] = &[
    "if", "for", "while", "switch", "catch", "return", "new", "throw", "else", "using", "lock",
    "foreach", "fixed", "synchronized", "try", "do", "when", "typeof", "sizeof", "nameof",
    "function", "with", "await", "yield", "case", "default", "base", "this", "super", "assert",
    "elif", "unless", "until", "match",
];

/// Words that can stand where a Java/C# return type would, and make the line a
/// statement: `return foo(x)`, `new Foo(x)`, `await bar(y)`.
const RT_CONTROL: &[&str] = &[
    "return", "new", "throw", "else", "await", "yield", "case", "using", "lock", "goto", "delete",
    "typeof", "in", "is", "as", "if", "do", "var", "assert", "sizeof", "out", "ref", "let", "const",
];

/// The return annotation may hold `>` — `: Promise<User> =>` is the commonest
/// shape there is — so only `=` ends it, which is where `=>` begins.
static ARROW_TAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(?::[^=]+)?\s*=>").expect("bad arrow tail"));
static BLOCK_TAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(?::[^{;=]+)?\s*\{").expect("bad block tail"));
static MEMBER_TAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:throws\s+[\w.,\s]+?)?\s*(?:\{.*|=>.*|where\s.*|:\s*(?:base|this)\s*\(.*)?$")
        .expect("bad member tail")
});

fn tail_ok(tail: Tail, rest: &str) -> bool {
    match tail {
        Tail::Any => true,
        Tail::Arrow => ARROW_TAIL.is_match(rest),
        Tail::Block => BLOCK_TAIL.is_match(rest),
        Tail::Member => MEMBER_TAIL.is_match(rest),
    }
}

/// The text inside the parenthesis that opens just before `from`, and the
/// index right after its closing partner — quote-aware, so a `)` in a default
/// string does not end the list. `None` when it does not close on this line.
fn paren_group(text: &str, from: usize) -> Option<(&str, usize)> {
    let tail = text.get(from..)?;
    let mut depth = 1i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in tail.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&tail[..idx], from + idx + ch.len_utf8()));
                }
            }
            _ => {}
        }
    }
    None
}

/// A call `name(args)` anywhere in a line: the callee name and the raw argument
/// list. Used to resolve a call against the file's own functions.
static CALL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\w+)\s*\(([^)]*)\)").expect("bad call pattern"));

/// `(name, params)` if this line begins a function definition, else `None`.
fn signature_of(text: &str, lang: Language) -> Option<(String, String)> {
    for head in heads_for(lang) {
        let Some(c) = head.re.captures(text) else { continue };
        let Some(name) = c.name("name").map(|m| m.as_str()) else { continue };
        if CONTROL.contains(&name) {
            continue;
        }
        if c.name("rt").is_some_and(|rt| RT_CONTROL.contains(&rt.as_str())) {
            continue;
        }
        let end = c.get(0).map_or(0, |m| m.end());
        let (params, rest) = if text[..end].ends_with('(') {
            match paren_group(text, end) {
                Some((inner, after)) => (inner.to_string(), &text[after..]),
                // The list does not close on this logical line: whatever this
                // is, the joiner could not assemble it as a definition.
                None => continue,
            }
        } else if lang == Language::Ruby {
            // `def show params, obj` — Ruby needs no parentheses.
            let list = text[end..].split(['#', ';']).next().unwrap_or("").trim();
            (list.to_string(), "")
        } else {
            (String::new(), &text[end..])
        };
        if !tail_ok(head.tail, rest) {
            continue;
        }
        return Some((name.to_string(), params));
    }
    None
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The body line range of the function whose signature is at `sig`. Python,
/// Ruby and Elixir are delimited by indentation (`end` sits at the signature's
/// own indent); the brace languages by balancing `{}`, counted on string-masked
/// text so a `"{"` literal cannot shift the end. A heuristic that at worst clips
/// the body, never invents a flow.
fn body_range(lines: &[&str], sig: usize, lang: Language) -> std::ops::Range<usize> {
    let n = lines.len();
    let indented = match lang {
        Language::Python | Language::Ruby | Language::Elixir => true,
        // Braced, or — since Scala 3 — indented: whichever the signature uses.
        Language::Scala => !mask_strings(lines[sig]).contains('{'),
        _ => false,
    };
    if indented {
        let indent = indent_of(lines[sig]);
        let mut j = sig + 1;
        while j < n {
            let l = lines[j];
            if l.trim().is_empty() {
                j += 1;
                continue;
            }
            if indent_of(l) <= indent {
                break;
            }
            j += 1;
        }
        return (sig + 1)..j;
    }
    // The block opens on the signature line or — Allman style, the norm in C#
    // and PSR-12 PHP — alone at the start of the next one. A signature with
    // neither (an abstract or interface method, a Kotlin or C# expression body)
    // has no block and an empty body. It used to run to the end of the file, so
    // every later function's sinks were credited to it.
    let mut start = sig;
    if brace_delta(lines[sig]).1 == 0 {
        let mut k = sig + 1;
        while k < n && lines[k].trim().is_empty() {
            k += 1;
        }
        if k < n && lines[k].trim_start().starts_with('{') {
            start = k;
        } else {
            return (sig + 1)..(sig + 1);
        }
    }
    let mut depth: i32 = 0;
    let mut opened = false;
    let mut j = start;
    while j < n {
        let (delta, opens) = brace_delta(lines[j]);
        depth += delta;
        opened |= opens > 0;
        if opened && depth <= 0 {
            return (sig + 1)..(j + 1);
        }
        j += 1;
    }
    (sig + 1)..n
}

/// The net `{`/`}` balance of a line and how many it opens, ignoring braces in
/// string and regex literals. Masking is the expensive part, and a line with no
/// quote and no slash cannot contain a literal, so it is counted raw. Function
/// bodies nest, so every line is counted once per enclosing function — this
/// check is what keeps that cheap.
fn brace_delta(line: &str) -> (i32, i32) {
    let count = |text: &str| {
        let mut delta = 0;
        let mut opens = 0;
        for ch in text.chars() {
            if ch == '{' {
                delta += 1;
                opens += 1;
            } else if ch == '}' {
                delta -= 1;
            }
        }
        (delta, opens)
    };
    if line.contains(['"', '\'', '`', '/']) {
        count(&mask_strings(line))
    } else {
        count(line)
    }
}

/// Extracts each parameter's variable name from a raw parameter list, tolerant
/// of type annotations on either side and of PHP's `$`. A mis-parse yields a
/// name that never matches a use in the body, so it silently produces no flow
/// rather than a wrong one.
fn param_names(params: &str, lang: Language) -> Vec<String> {
    split_top_commas(params)
        .into_iter()
        .filter_map(|raw| param_name(&raw, lang))
        .collect()
}

/// One parameter's variable name. Annotations and attributes go first —
/// `@RequestParam(name = "id") String id` would otherwise split on the `=`
/// inside the annotation and lose the name entirely.
fn param_name(raw: &str, lang: Language) -> Option<String> {
    let stripped = strip_decorations(raw, lang);
    let p = before_top_level_eq(&stripped).trim();
    if p.is_empty() {
        return None;
    }
    if lang == Language::Php {
        // `$name`, optionally with a type before it.
        let idx = p.find('$')?;
        let rest = &p[idx + 1..];
        let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        return (!name.is_empty()).then(|| format!("${name}"));
    }
    // `name: Type` (TypeScript, Kotlin, Scala, Python, Ruby keywords): the name
    // is the last word before the colon — after a `vararg` or `implicit`.
    if let Some(colon) = p.find(':') {
        return last_ident(&p[..colon]);
    }
    // Java and C# write `Type name`; Go, JS, Python and Ruby put the name first.
    if matches!(lang, Language::Java | Language::CSharp) {
        return last_ident(p);
    }
    first_ident(p)
}

static ANNOTATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"@\w+(?:\.\w+)*(?:\s*\((?:[^()]|\([^()]*\))*\))?").expect("bad annotation pattern")
});
static ATTRIBUTE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\[[^\]]*\]").expect("bad attribute pattern"));

fn strip_decorations(raw: &str, lang: Language) -> String {
    if lang == Language::Php {
        return raw.to_string();
    }
    let s = ANNOTATION_RE.replace_all(raw, " ");
    if lang == Language::CSharp {
        ATTRIBUTE_RE.replace_all(&s, " ").into_owned()
    } else {
        s.into_owned()
    }
}

/// `s` up to its first `=` that is not inside brackets or a string — the
/// default value of a parameter, but not the `=` inside `f(a=b)`.
fn before_top_level_eq(s: &str) -> &str {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for (idx, ch) in s.char_indices() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => quote = Some(ch),
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            '=' if depth <= 0 => return &s[..idx],
            _ => {}
        }
    }
    s
}

fn last_ident(s: &str) -> Option<String> {
    idents_in(s).into_iter().last()
}

fn first_ident(s: &str) -> Option<String> {
    idents_in(s).into_iter().next()
}

/// Every identifier-shaped token in `s`, in order.
fn idents_in(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '$' {
            cur.push(ch);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Splits an argument or parameter list on commas that are not nested inside
/// parentheses, brackets or braces, so `f(a, g(b, c), d)` yields three parts.
fn split_top_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    // A comma or bracket inside a string literal is text. Splitting on it used
    // to shift every later argument by one — `helper("a, b", x)` put `x` in the
    // third slot — so the interprocedural pass matched the wrong parameter.
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in s.chars() {
        if let Some(q) = quote {
            cur.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => {
                quote = Some(ch);
                cur.push(ch);
            }
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => out.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Finds every function definition in the file (only for scoped languages).
fn functions(lines: &[&str], lang: Language) -> Vec<Func> {
    if !scoped(lang) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if rules::is_comment_line(line, lang) {
            continue;
        }
        if let Some((name, params)) = signature_of(line, lang) {
            out.push(Func {
                name,
                params: param_names(&params, lang),
                sig: i,
                body: body_range(lines, i, lang),
            });
        }
    }
    out
}

/// Binds `lhs` to whatever `rhs` carries: a narrowed taint after a sanitiser,
/// a fresh one from a source, a callee's returned taint, a propagated one, or
/// nothing at all.
#[allow(clippy::too_many_arguments)]
fn assign(
    lhs: String,
    rhs: &str,
    line: u32,
    code: &str,
    tainted: &mut HashMap<String, TaintVar>,
    funcs_by_name: &HashMap<String, usize>,
    summaries: &[Summary],
    externals: &HashMap<String, Summary>,
) {
    // A sanitiser is a call and a variable is a reference — neither is the
    // text of a string. `msg = "failed to escape: " + id` used to count
    // as sanitising `id`, because the word sat inside the literal.
    let code_rhs = mask_strings(rhs);
    if let Some(cats) = sanitized_categories(&code_rhs) {
        // The value is safe for `cats` and unchanged for everything else, so
        // the taint is narrowed rather than dropped. Carrying the underlying
        // chain forward is what lets a later SQL sink still report a flow
        // that only ever passed an HTML escaper.
        // The value being sanitised is either a variable already tracked or
        // — far more common in real code — a source written inline, as in
        // `$safe = htmlspecialchars($_GET['id'])`. Both must survive the
        // narrowing, or the partially-sanitised flow is lost exactly where
        // it matters most.
        let carried = tainted
            .iter()
            .filter(|(name, _)| contains_word(&code_rhs, name))
            .map(|(_, v)| v.clone())
            .min_by_key(|v| v.source_line())
            .map(|mut v| {
                v.steps.push(FlowStep {
                    line,
                    code: code.to_string(),
                    role: FlowRole::Propagation,
                    file: None,
                });
                v
            })
            .or_else(|| {
                (SOURCE_RE.is_match(rhs) && SOURCE_RE.is_match(&mask_regex(rhs))).then(|| TaintVar {
                    steps: vec![FlowStep {
                        line,
                        code: code.to_string(),
                        role: FlowRole::Source,
                        file: None,
                    }],
                    origin_param: None,
                    cleared: BTreeSet::new(),
                })
            });
        match carried {
            Some(mut v) => {
                v.cleared.extend(cats);
                if ALL_CATEGORIES.iter().all(|c| v.cleared.contains(c)) {
                    // Nothing left to report on: drop it, so the map does
                    // not grow with values that can never sink again.
                    tainted.remove(&lhs);
                } else {
                    tainted.insert(lhs, v);
                }
            }
            // A sanitiser applied to something untracked introduces nothing.
            None => {
                tainted.remove(&lhs);
            }
        }
    } else if SOURCE_RE.is_match(rhs) && SOURCE_RE.is_match(&mask_regex(rhs)) {
        tainted.insert(
            lhs,
            TaintVar {
                steps: vec![FlowStep { line, code: code.to_string(), role: FlowRole::Source, file: None }],
                origin_param: None,
                cleared: BTreeSet::new(),
            },
        );
    } else if let Some(effect) =
        resolve_call(rhs, line, code, tainted, funcs_by_name, summaries, externals)
    {
        // The rhs passes a tainted value to a function defined in this file,
        // so its summary — not a surface substring match — decides the taint.
        // This is what makes a user-defined sanitiser actually clear taint.
        match effect {
            CallEffect::Returns(v) => tainted.insert(lhs, v),
            CallEffect::Consumed => tainted.remove(&lhs),
        };
    } else if let Some(mut v) = tainted
        .iter()
        .filter(|(name, _)| contains_word(&code_rhs, name))
        .map(|(_, v)| v.clone())
        .min_by_key(|v| v.source_line())
    {
        v.steps.push(FlowStep { line, code: code.to_string(), role: FlowRole::Propagation, file: None });
        tainted.insert(lhs, v);
    } else {
        tainted.remove(&lhs);
    }
}

/// JS/TS object destructuring: `const { id, name: alias, ...rest } = req.query`.
static DESTRUCT_OBJ_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:export\s+)?(?:const|let|var)\s*\{([^}]*)\}\s*(?::[^=]+)?=\s*([^=].*)$")
        .expect("bad object-destructuring pattern")
});
/// JS/TS array destructuring: `const [a, , b] = …`.
static DESTRUCT_ARR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:const|let|var)\s*\[([^\]]*)\]\s*=\s*([^=].*)$")
        .expect("bad array-destructuring pattern")
});
/// A bare name list: Python and Ruby unpacking, Go's `body, err := …`.
static NAME_LIST_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:var\s+)?((?:\*?[A-Za-z_]\w*\s*,\s*)+\*?[A-Za-z_]\w*)\s*(?::=|=)\s*([^=].*)$")
        .expect("bad name-list pattern")
});

/// Names bound by a multiple assignment, and its right-hand side. A Go error or
/// `ok` flag and the blank `_` never carry the value, so they are left out.
fn multi_assign(text: &str) -> Option<(Vec<String>, &str)> {
    let (pattern, caps) = if let Some(c) = DESTRUCT_OBJ_RE.captures(text) {
        ("obj", c)
    } else if let Some(c) = DESTRUCT_ARR_RE.captures(text) {
        ("arr", c)
    } else {
        ("list", NAME_LIST_RE.captures(text)?)
    };
    let inner = caps.get(1)?.as_str();
    let rhs = caps.get(2)?.as_str();
    let names: Vec<String> = split_top_commas(inner)
        .into_iter()
        .filter_map(|part| {
            let part = part.trim().trim_start_matches("...").trim_start_matches('*');
            let part = before_top_level_eq(part).trim();
            if pattern == "obj" {
                if let Some(colon) = part.find(':') {
                    // `key: alias` binds the alias; a nested pattern is skipped.
                    let alias = part[colon + 1..].trim();
                    if alias.starts_with('{') || alias.starts_with('[') {
                        return None;
                    }
                    return first_ident(alias);
                }
            }
            first_ident(part)
        })
        .filter(|n| !matches!(n.as_str(), "_" | "err" | "ok"))
        .collect();
    (!names.is_empty()).then_some((names, rhs))
}

/// Processes one line of code against the current taint map: checks whether a
/// tainted value reaches a sink here (directly or by being passed to a function
/// that sinks it), then updates the map for an assignment. `on_sink` and
/// `on_return` let the two callers — the summary pass and the main trace — react
/// differently to the same analysis.
#[allow(clippy::too_many_arguments)]
fn process_line(
    text: &str,
    line: u32,
    sinks: &[&CompiledSink],
    funcs_by_name: &HashMap<String, usize>,
    summaries: &[Summary],
    externals: &HashMap<String, Summary>,
    tainted: &mut HashMap<String, TaintVar>,
    on_sink: &mut OnSink,
    on_return: &mut dyn FnMut(&TaintVar),
) {
    // With nothing tainted, every sink, call and propagation below needs a
    // tracked value and finds none: the only thing a line can still do is
    // introduce a source. Most lines of most files are in that state, and an
    // assignment's right-hand side is part of the line, so testing the whole
    // line for a source is a safe filter.
    if tainted.is_empty() && !SOURCE_RE.is_match(text) {
        return;
    }
    let trimmed = text.trim();
    let code: String = trimmed.chars().take(200).collect();

    // 1) A tainted value reaching a sink on this line — the map is read before
    //    the assignment below, so `x = sink(x)` uses the old `x`.
    let mut sunk = false;

    // 1a) Direct sink: a dangerous call on this very line.
    for s in sinks {
        let Some(sink_match) = first_match_in_code(text, &s.re) else {
            continue;
        };
        // Only values still dangerous *for this sink's category* count. A value
        // that passed an HTML escaper is skipped at an XSS sink and still
        // reported at a SQL one — the whole point of scoping sanitisers.
        //
        // For SQL, only the query text: a value passed beside the query as a
        // bind parameter is the fix, not the bug.
        let scope = if s.category == CAT_SQL {
            sql_query_text(text, sink_match)
        } else {
            std::borrow::Cow::Borrowed(text)
        };
        let best = earliest_referenced_for(tainted, &scope, line, s.category);
        if let Some(v) = best {
            on_sink(
                v,
                s.category,
                s.cwe,
                s.severity,
                vec![FlowStep { line, code: code.clone(), role: FlowRole::Sink, file: None }],
            );
            sunk = true;
            break;
        }
    }

    // 1b) Interprocedural sink: the tainted value is passed to a function that
    //     sinks that argument. The chain gains a call step and the callee's sink.
    if !sunk {
        if let Some(r) =
            call_reaches_sink(text, line, &code, tainted, funcs_by_name, summaries, externals)
        {
            on_sink(r.var, r.category, r.cwe, r.severity, r.tail);
            sunk = true;
        }
    }
    let _ = sunk;

    // 2) Assignment: introduce, propagate through a variable or a returning
    //    call, or clear the taint. Several names bound at once — destructuring,
    //    unpacking, Go's `value, err :=` — each take the right-hand side's taint.
    if let Some((names, rhs)) = multi_assign(text) {
        for name in names {
            assign(name, rhs, line, &code, tainted, funcs_by_name, summaries, externals);
        }
        return;
    }
    if let Some(caps) = ASSIGN_RE.captures(text) {
        let lhs = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if lhs.is_empty() {
            return;
        }
        assign(lhs, rhs, line, &code, tainted, funcs_by_name, summaries, externals);
        return;
    }

    // 3) `return <expr>` carrying a tainted value — only the summary pass cares.
    //    A value wrapped in a sanitiser on the way out is no longer dangerous
    //    *for what that sanitiser covers*. A function returning
    //    `htmlspecialchars($x)` is an HTML escaper, not a general-purpose one,
    //    so it keeps returning taint for SQL and the rest.
    if let Some(rest) = return_expr(trimmed) {
        match sanitized_categories(&mask_strings(rest)) {
            Some(cats) if ALL_CATEGORIES.iter().all(|c| cats.contains(c)) => {}
            Some(cats) => {
                if let Some(v) = earliest_referenced(tainted, rest, line) {
                    let mut narrowed = v.clone();
                    narrowed.cleared.extend(cats);
                    on_return(&narrowed);
                }
            }
            None => {
                if let Some(v) = earliest_referenced(tainted, rest, line) {
                    on_return(v);
                }
            }
        }
    }
}

/// The earliest-sourced tainted variable referenced in `text`, within the
/// window — the clearest chain to show.
fn earliest_referenced<'a>(
    tainted: &'a HashMap<String, TaintVar>,
    text: &str,
    line: u32,
) -> Option<&'a TaintVar> {
    earliest_matching(tainted, text, line, |_| true)
}

/// As `earliest_referenced`, but ignoring values already made safe for
/// `category`. Used at a sink, where the category is known.
fn earliest_referenced_for<'a>(
    tainted: &'a HashMap<String, TaintVar>,
    text: &str,
    line: u32,
    category: &str,
) -> Option<&'a TaintVar> {
    earliest_matching(tainted, text, line, |v| v.dangerous_for(category))
}

fn earliest_matching<'a>(
    tainted: &'a HashMap<String, TaintVar>,
    text: &str,
    line: u32,
    accept: impl Fn(&TaintVar) -> bool,
) -> Option<&'a TaintVar> {
    // Every "does this line use the variable" question goes through here, so
    // this is the one place string contents stop counting as references.
    let text = mask_strings(text);
    let mut best: Option<&TaintVar> = None;
    for (name, v) in tainted {
        if contains_word(&text, name)
            && line.saturating_sub(v.source_line()) <= WINDOW
            && accept(v)
            && best.map(|b| v.source_line() < b.source_line()).unwrap_or(true)
        {
            best = Some(v);
        }
    }
    best
}

/// Resolves a called name to a summary: a function defined in this file wins,
/// otherwise one exported by another file (the cross-file layer).
fn lookup_summary<'a>(
    name: &str,
    funcs_by_name: &HashMap<String, usize>,
    summaries: &'a [Summary],
    externals: &'a HashMap<String, Summary>,
) -> Option<&'a Summary> {
    if let Some(&fi) = funcs_by_name.get(name) {
        return summaries.get(fi);
    }
    externals.get(name)
}

/// If a call on this line hands a tainted argument to a function that sinks that
/// argument, returns the tail steps (call + sink), the sink metadata, and the
/// argument's taint chain. The callee may live in this file or another one, in
/// which case the sink step carries that file.
fn call_reaches_sink<'a>(
    text: &str,
    line: u32,
    code: &str,
    tainted: &'a HashMap<String, TaintVar>,
    funcs_by_name: &HashMap<String, usize>,
    summaries: &[Summary],
    externals: &HashMap<String, Summary>,
) -> Option<Reached<'a>> {
    for c in CALL_RE.captures_iter(text) {
        let name = &c[1];
        let Some(summary) = lookup_summary(name, funcs_by_name, summaries, externals) else {
            continue;
        };
        if summary.sink_params.is_empty() {
            continue;
        }
        for (i, arg) in split_top_commas(&c[2]).into_iter().enumerate() {
            let Some(hit) = summary.sink_params.get(&i) else { continue };
            // The callee's sink category is known here, so a value already made
            // safe for it must not be reported through the call either.
            if let Some(v) = earliest_referenced_for(tainted, &arg, line, hit.category) {
                return Some(Reached {
                    tail: vec![
                        FlowStep { line, code: code.to_string(), role: FlowRole::Call, file: None },
                        FlowStep {
                            line: hit.line,
                            code: hit.code.clone(),
                            role: FlowRole::Sink,
                            file: hit.file.clone(),
                        },
                    ],
                    category: hit.category,
                    cwe: hit.cwe,
                    severity: hit.severity,
                    var: v,
                });
            }
        }
    }
    None
}

/// What a file-local call on the rhs does to a tainted argument.
enum CallEffect {
    /// The callee returns the tainted argument; carry the chain (with a call
    /// step) into the assignment target.
    Returns(TaintVar),
    /// The callee takes a tainted argument but returns nothing tainted — the
    /// value is consumed, so the target is clean. This is how a user-defined
    /// sanitiser breaks a flow.
    Consumed,
}

/// Resolves what happens when the rhs passes a tainted value to a function
/// defined in this file or exported by another. `None` means no such call
/// touches a tainted value, so the caller falls back to plain propagation.
fn resolve_call(
    rhs: &str,
    line: u32,
    code: &str,
    tainted: &HashMap<String, TaintVar>,
    funcs_by_name: &HashMap<String, usize>,
    summaries: &[Summary],
    externals: &HashMap<String, Summary>,
) -> Option<CallEffect> {
    let mut consumed = false;
    for c in CALL_RE.captures_iter(rhs) {
        let name = &c[1];
        let Some(summary) = lookup_summary(name, funcs_by_name, summaries, externals) else {
            continue;
        };
        for (i, arg) in split_top_commas(&c[2]).into_iter().enumerate() {
            let Some(v) = earliest_referenced(tainted, &arg, line) else { continue };
            if summary.return_params.contains(&i) {
                let mut carried = v.clone();
                carried.steps.push(FlowStep {
                    line,
                    code: code.to_string(),
                    role: FlowRole::Call,
                    file: None,
                });
                return Some(CallEffect::Returns(carried));
            }
            // A tainted value went into a helper that does not return it:
            // remember, in case nothing else returns it.
            consumed = true;
        }
    }
    consumed.then_some(CallEffect::Consumed)
}

/// The expression of a `return` statement, if this line is one.
fn return_expr(trimmed: &str) -> Option<&str> {
    let rest = trimmed.strip_prefix("return")?;
    // Must be a keyword, not an identifier like `returned`.
    if rest.starts_with(|c: char| c.is_alphanumeric() || c == '_') {
        return None;
    }
    Some(rest.trim().trim_end_matches(';'))
}

/// Computes a function's summary: seed its parameters as tainted, trace the
/// body, and record which parameters reach a sink or a return.
fn summarize(
    lines: &[&str],
    f: &Func,
    lang: Language,
    sinks: &[&CompiledSink],
    funcs_by_name: &HashMap<String, usize>,
    summaries: &[Summary],
) -> Summary {
    let mut tainted: HashMap<String, TaintVar> = HashMap::new();
    for (i, p) in f.params.iter().enumerate() {
        if p.is_empty() {
            continue;
        }
        tainted.insert(
            p.clone(),
            TaintVar {
                steps: vec![FlowStep {
                    line: (f.sig + 1) as u32,
                    code: String::new(),
                    role: FlowRole::Source,
                    file: None,
                }],
                origin_param: Some(i),
                cleared: BTreeSet::new(),
            },
        );
    }
    // Summaries are computed intra-file: a function's own body plus calls to
    // functions in the same file. Cross-file resolution happens only at the
    // top-level trace, keeping the export a self-contained fact about one file.
    let no_externals: HashMap<String, Summary> = HashMap::new();

    let mut out = Summary::default();
    for idx in f.body.clone() {
        if idx >= lines.len() {
            break;
        }
        let text = lines[idx].trim_end_matches('\r');
        let trimmed = text.trim();
        if trimmed.is_empty() || rules::is_comment_line(text, lang) {
            continue;
        }
        let line = (idx + 1) as u32;
        let mut on_sink = |v: &TaintVar,
                           category: &'static str,
                           cwe: &'static [&'static str],
                           severity: Severity,
                           tail: Vec<FlowStep>| {
            if let Some(pi) = v.origin_param {
                let sink = tail.last().cloned().unwrap_or(FlowStep {
                    line,
                    code: trimmed.chars().take(200).collect(),
                    role: FlowRole::Sink,
                    file: None,
                });
                out.sink_params.entry(pi).or_insert(SinkHit {
                    line: sink.line,
                    code: sink.code,
                    category,
                    cwe,
                    severity,
                    // Filled in with the file when this summary is exported.
                    file: sink.file,
                });
            }
        };
        let mut on_return = |v: &TaintVar| {
            if let Some(pi) = v.origin_param {
                out.return_params.insert(pi);
            }
        };
        process_line(
            text,
            line,
            sinks,
            funcs_by_name,
            summaries,
            &no_externals,
            &mut tainted,
            &mut on_sink,
            &mut on_return,
        );
    }
    out
}

/// The public functions a file exports for cross-file tracing: name → summary,
/// with the summary's sink pointing at this file. Only functions that actually
/// sink or return a parameter are worth exporting.
pub(crate) fn collect_exports(content: &str, lang: Language, rel: &str) -> Vec<(String, Summary)> {
    if !scoped(lang) {
        return Vec::new();
    }
    let sinks: Vec<&CompiledSink> = SINKS.iter().filter(|s| s.langs.contains(&lang)).collect();
    if sinks.is_empty() {
        return Vec::new();
    }
    let raw: Vec<&str> = content.lines().map(|l| l.trim_end_matches('\r')).collect();
    let logical = join_continuations(&raw, lang);
    let lines: Vec<&str> = logical.iter().map(|l| l.as_ref()).collect();
    let funcs = functions(&lines, lang);
    let funcs_by_name: HashMap<String, usize> =
        funcs.iter().enumerate().map(|(i, f)| (f.name.clone(), i)).collect();

    // Same fixpoint as the main analysis, so an exported summary reflects the
    // helper's full intra-file behaviour.
    let mut summaries = vec![Summary::default(); funcs.len()];
    for _ in 0..MAX_SUMMARY_ITERS {
        let mut changed = false;
        for (fi, f) in funcs.iter().enumerate() {
            let s = summarize(&lines, f, lang, &sinks, &funcs_by_name, &summaries);
            if s != summaries[fi] {
                summaries[fi] = s;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    funcs
        .into_iter()
        .zip(summaries)
        .filter_map(|(f, mut s)| {
            if s.sink_params.is_empty() && s.return_params.is_empty() {
                return None;
            }
            // Stamp the file onto each sink so a caller elsewhere can point at it.
            for hit in s.sink_params.values_mut() {
                hit.file = Some(rel.to_string());
            }
            Some((f.name, s))
        })
        .collect()
}

/// Request data bound straight to a handler argument. A framework that does
/// the binding never calls anything a line-based source pattern can see —
/// `request.getParameter` simply does not appear in a Spring controller — so
/// every modern handler looked clean however its argument was used.
static PARAM_SOURCE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        // Spring MVC and JAX-RS.
        r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|MatrixVariable|RequestPart|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|BeanParam)\b",
        // ASP.NET Core model binding.
        r"|\[\s*From(?:Query|Route|Body|Form|Header)\b",
        // NestJS.
        r"|@(?:Query|Param|Body|Headers|Req)\s*\(",
        // FastAPI, as a default or inside `Annotated[...]`.
        r"|=\s*(?:Query|Path|Body|Form|Header|Cookie|File)\s*\(",
        r"|Annotated\s*\[[^\]]*\b(?:Query|Path|Body|Form|Header|Cookie|File)\s*\(",
    ))
    .expect("bad parameter-source pattern")
});

/// A Flask or FastAPI route decorator and its path.
static ROUTE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*@[\w.]+\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(\s*[rbuf]?["']([^"']*)["']"#)
        .expect("bad route pattern")
});
static FLASK_VAR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"<(?:(\w+):)?(\w+)>").expect("bad flask placeholder"));
static FASTAPI_VAR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\{(\w+)(?::\w+)?\}").expect("bad fastapi placeholder"));

/// Path placeholders of a route decorator on this line: `(name, converter)`.
fn route_placeholders(text: &str) -> Option<Vec<(String, Option<String>)>> {
    let path = ROUTE_RE.captures(text)?.get(1)?.as_str();
    let mut out: Vec<(String, Option<String>)> = FLASK_VAR_RE
        .captures_iter(path)
        .map(|c| (c[2].to_string(), c.get(1).map(|m| m.as_str().to_string())))
        .collect();
    out.extend(FASTAPI_VAR_RE.captures_iter(path).map(|c| (c[1].to_string(), None)));
    Some(out)
}

/// A path segment parsed into a number or an id cannot carry a payload:
/// Flask's `<int:id>` and FastAPI's `id: int` reject anything else before the
/// handler runs.
const SAFE_PATH_TYPES: &[&str] =
    &["int", "float", "bool", "uuid", "UUID", "uuid.UUID", "datetime", "date", "Decimal"];

fn annotated_type(raw: &str) -> Option<&str> {
    let before_default = before_top_level_eq(raw);
    let colon = before_default.find(':')?;
    Some(before_default[colon + 1..].trim())
}

/// The handler parameters that carry request data, by name.
fn parameter_sources(params: &str, routes: &[(String, Option<String>)], lang: Language) -> Vec<String> {
    split_top_commas(params)
        .into_iter()
        .filter_map(|raw| {
            let name = param_name(&raw, lang)?;
            if PARAM_SOURCE_RE.is_match(&raw) {
                return Some(name);
            }
            let (_, converter) = routes.iter().find(|(n, _)| *n == name)?;
            if converter.as_deref().is_some_and(|c| SAFE_PATH_TYPES.contains(&c)) {
                return None;
            }
            if annotated_type(&raw).is_some_and(|t| SAFE_PATH_TYPES.contains(&t)) {
                return None;
            }
            Some(name)
        })
        .collect()
}

/// Traces user-controlled data through `content` and returns every source→sink
/// flow found, following calls into the file's own functions. Deterministic:
/// the same input always yields the same flows. The single-file entry point;
/// the scanner uses [`analyze_with`] to also resolve calls across files.
#[allow(dead_code)] // intra-file public entry, exercised by the unit tests
pub fn analyze(content: &str, lang: Language) -> Vec<TaintFlow> {
    analyze_with(content, lang, &HashMap::new())
}

/// As [`analyze`], but also resolves calls to functions exported by other files
/// (`externals`: name → summary), producing flows that cross a file boundary.
pub(crate) fn analyze_with(
    content: &str,
    lang: Language,
    externals: &HashMap<String, Summary>,
) -> Vec<TaintFlow> {
    // Cheap gate: no source indicator anywhere → nothing to trace. A handler
    // whose input arrives as a bound parameter carries no `request` at all, so
    // the parameter annotations and route decorators count as indicators too —
    // without them a Spring controller was skipped before it was read.
    if !rules::content_has_taint(content)
        && !PARAM_SOURCE_RE.is_match(content)
        && !ROUTE_RE.is_match(content)
    {
        return Vec::new();
    }

    let sinks: Vec<&CompiledSink> = SINKS.iter().filter(|s| s.langs.contains(&lang)).collect();
    if sinks.is_empty() {
        return Vec::new();
    }

    let raw: Vec<&str> = content.lines().map(|l| l.trim_end_matches('\r')).collect();
    let logical = join_continuations(&raw, lang);
    let lines: Vec<&str> = logical.iter().map(|l| l.as_ref()).collect();

    // Function summaries, resolved to a fixpoint so a helper that calls another
    // helper still learns the whole chain regardless of definition order. The
    // iteration cap keeps it terminating on mutual recursion.
    let funcs = functions(&lines, lang);
    let funcs_by_name: HashMap<String, usize> =
        funcs.iter().enumerate().map(|(i, f)| (f.name.clone(), i)).collect();
    let mut summaries = vec![Summary::default(); funcs.len()];
    if !funcs.is_empty() {
        for _ in 0..MAX_SUMMARY_ITERS {
            let mut changed = false;
            for (fi, f) in funcs.iter().enumerate() {
                let s = summarize(&lines, f, lang, &sinks, &funcs_by_name, &summaries);
                if s != summaries[fi] {
                    summaries[fi] = s;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    // Main trace: walk every line, clearing the taint map at each function
    // signature so one function's variables never bleed into the next.
    let mut tainted: HashMap<String, TaintVar> = HashMap::new();
    let mut flows: Vec<TaintFlow> = Vec::new();
    // Path placeholders of the route decorator above the next `def`, and the
    // decorator itself — it becomes part of the source step, so the finding
    // shows which URL feeds the parameter.
    let mut routes: Vec<(String, Option<String>)> = Vec::new();
    let mut route_text = String::new();

    for (idx, &text) in lines.iter().enumerate() {
        if flows.len() >= MAX_FLOWS {
            break;
        }
        let trimmed = text.trim();
        if trimmed.is_empty() || rules::is_comment_line(text, lang) {
            continue;
        }
        if scoped(lang) {
            if let Some((_, params)) = signature_of(text, lang) {
                tainted.clear();
                let sig_code: String = trimmed.chars().take(200).collect();
                let code = if route_text.is_empty() {
                    sig_code
                } else {
                    format!("{route_text} {sig_code}").chars().take(200).collect()
                };
                for name in parameter_sources(&params, &routes, lang) {
                    tainted.insert(
                        name,
                        TaintVar {
                            steps: vec![FlowStep {
                                line: (idx + 1) as u32,
                                code: code.clone(),
                                role: FlowRole::Source,
                                file: None,
                            }],
                            origin_param: None,
                            cleared: BTreeSet::new(),
                        },
                    );
                }
                routes.clear();
                route_text.clear();
                continue;
            }
            if lang == Language::Python {
                if let Some(found) = route_placeholders(text) {
                    routes = found;
                    route_text = trimmed.to_string();
                }
            }
        }
        let line = (idx + 1) as u32;
        let mut on_sink = |v: &TaintVar,
                           category: &'static str,
                           cwe: &'static [&'static str],
                           severity: Severity,
                           tail: Vec<FlowStep>| {
            // The main trace only ever holds real-source taint (params are never
            // seeded here), so every sink it sees is a genuine source→sink flow.
            if v.origin_param.is_some() {
                return;
            }
            let mut steps = v.steps.clone();
            steps.extend(tail);
            flows.push(TaintFlow { category, cwe, severity, steps });
        };
        let mut on_return = |_: &TaintVar| {};
        process_line(
            text,
            line,
            &sinks,
            &funcs_by_name,
            &summaries,
            externals,
            &mut tainted,
            &mut on_sink,
            &mut on_return,
        );
    }

    flows
}

// ---------------------------------------------------- sensitive-data leakage

/// A value that looks like a secret or credential — the *source* of a leak flow.
/// Word-anchored so `secret_count` is not mistaken for a secret.
static SECRET_SOURCE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(?:pass(?:word|wd|phrase)|secret|tokens?|api[_-]?keys?|apikeys?|private[_-]?keys?|credentials?|access[_-]?keys?|client[_-]?secrets?|auth[_-]?tokens?|session[_-]?keys?|bearer)\b",
    )
    .expect("bad secret source pattern")
});

/// A place a value escapes to where a secret must never go: logs, the HTTP
/// response, or an outbound request.
static LEAK_SINK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:console\.(?:log|info|warn|error|debug)|System\.(?:out|err)|\bprint(?:ln|f)?\s*\(|\blog(?:ger)?\.(?:info|debug|warn(?:ing)?|error|trace)|\blogging\.(?:info|debug|warning|error)|\bfmt\.(?:Print|Sprint)\w*|\bputs\b|(?:res|response|reply)\.(?:send|write|json|end)\s*\(|\brender\s*\(|requests\.(?:post|put)\s*\(|\bfetch\s*\(|axios\.)",
    )
    .expect("bad leak sink pattern")
});

/// A value that has been redacted, masked or hashed is safe to log — no leak.
static SECRET_REDACT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(redact|mask|\*{3,}|sha1|sha256|sha512|\bmd5|bcrypt|scrypt|argon2|\bhash|hmac|encrypt|hexdigest|obfuscat|\bx{3,}\b)",
    )
    .expect("bad redact pattern")
});

/// Traces a *secret* value from where it is read to a place it leaks — a log
/// line, the HTTP response, or an outbound call. The other half of data-flow:
/// the injection pass asks "does untrusted input reach a dangerous call?", this
/// asks "does a credential reach somewhere it will be exposed?" (CWE-532/200).
///
/// Intra-function and conservative: a value only counts as secret when it is
/// read from a secret-named source, and a redaction/hash on the way clears it.
pub fn analyze_leaks(content: &str, lang: Language) -> Vec<TaintFlow> {
    // Cheap gate: no secret-shaped token anywhere → nothing to trace.
    if !SECRET_SOURCE_RE.is_match(content) {
        return Vec::new();
    }
    let raw: Vec<&str> = content.lines().map(|l| l.trim_end_matches('\r')).collect();
    let logical = join_continuations(&raw, lang);
    let lines: Vec<&str> = logical.iter().map(|l| l.as_ref()).collect();
    let mut tainted: HashMap<String, TaintVar> = HashMap::new();
    let mut flows: Vec<TaintFlow> = Vec::new();

    for (idx, &text) in lines.iter().enumerate() {
        if flows.len() >= MAX_FLOWS {
            break;
        }
        let trimmed = text.trim();
        if trimmed.is_empty() || rules::is_comment_line(text, lang) {
            continue;
        }
        if scoped(lang) && signature_of(text, lang).is_some() {
            tainted.clear();
            continue;
        }
        let line = (idx + 1) as u32;
        let code: String = trimmed.chars().take(200).collect();

        // Does a secret reach a leak sink on this line?
        if LEAK_SINK_RE.is_match(text) && !SECRET_REDACT_RE.is_match(text) {
            let sink_step = FlowStep { line, code: code.clone(), role: FlowRole::Sink, file: None };
            if let Some(v) = earliest_referenced(&tainted, text, line) {
                let mut steps = v.steps.clone();
                steps.push(sink_step);
                flows.push(leak_flow(steps));
                continue;
            }
            // Inline: the secret is read and leaked on the very same line.
            if SECRET_SOURCE_RE.is_match(text) {
                flows.push(leak_flow(vec![
                    FlowStep { line, code: code.clone(), role: FlowRole::Source, file: None },
                    sink_step,
                ]));
                continue;
            }
        }

        // Assignment: introduce, propagate or clear the secret taint.
        if let Some(caps) = ASSIGN_RE.captures(text) {
            let lhs = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if lhs.is_empty() {
                continue;
            }
            if SECRET_REDACT_RE.is_match(rhs) {
                tainted.remove(&lhs);
            } else if SECRET_SOURCE_RE.is_match(&lhs) || SECRET_SOURCE_RE.is_match(rhs) {
                tainted.insert(
                    lhs,
                    TaintVar {
                        steps: vec![FlowStep { line, code, role: FlowRole::Source, file: None }],
                        origin_param: None,
                        cleared: BTreeSet::new(),
                    },
                );
            } else if let Some(mut v) = tainted
                .iter()
                .filter(|(name, _)| contains_word(rhs, name))
                .map(|(_, v)| v.clone())
                .min_by_key(|v| v.source_line())
            {
                v.steps.push(FlowStep { line, code, role: FlowRole::Propagation, file: None });
                tainted.insert(lhs, v);
            } else {
                tainted.remove(&lhs);
            }
        }
    }

    flows
}

fn leak_flow(steps: Vec<FlowStep>) -> TaintFlow {
    TaintFlow {
        category: "Утечка чувствительных данных",
        cwe: &["CWE-532", "CWE-200"],
        severity: Severity::Medium,
        steps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traces_multiline_command_injection() {
        let code = "\
import os
def run(request):
    cmd = request.args.get('cmd')
    full = cmd + ' --verbose'
    os.system(full)
";
        let flows = analyze(code, Language::Python);
        assert_eq!(flows.len(), 1, "one flow expected: {flows:?}");
        let f = &flows[0];
        assert_eq!(f.category, "Инъекция команд");
        // source (cmd = request...), propagation (full = cmd...), sink (os.system)
        assert_eq!(f.steps.len(), 3);
        assert_eq!(f.steps[0].role, FlowRole::Source);
        assert_eq!(f.steps[1].role, FlowRole::Propagation);
        assert_eq!(f.steps[2].role, FlowRole::Sink);
        assert_eq!(f.source_line(), 3);
        assert_eq!(f.sink_line(), 5);
    }

    #[test]
    fn sanitised_value_is_not_reported() {
        let code = "\
import os, shlex
def run(request):
    cmd = request.args.get('cmd')
    safe = shlex.quote(cmd)
    os.system(safe)
";
        assert!(analyze(code, Language::Python).is_empty());
    }

    #[test]
    fn clean_reassignment_clears_taint() {
        let code = "\
def run(request):
    x = request.args.get('q')
    x = 'constant'
    os.system(x)
";
        assert!(analyze(code, Language::Python).is_empty());
    }

    #[test]
    fn untainted_variable_reaching_sink_is_ignored() {
        let code = "\
def run():
    cmd = 'ls -la'
    os.system(cmd)
";
        assert!(analyze(code, Language::Python).is_empty());
    }

    #[test]
    fn word_boundary_avoids_partial_matches() {
        assert!(contains_word("os.system(user)", "user"));
        assert!(!contains_word("os.system(username)", "user"));
        assert!(contains_word("a = user + 1", "user"));
    }

    /// The window is a fence against runaways in very long top-level scripts.
    /// It used to be 80 lines; with function scoping in every heuristic
    /// language it no longer has to stand between methods, so a long legacy
    /// function keeps its flows.
    #[test]
    fn out_of_window_flow_is_dropped() {
        let flow_at = |gap: u32| {
            let mut code = String::from("cmd = request.args.get('q')\n");
            for _ in 0..gap {
                code.push_str("noop = 1\n");
            }
            code.push_str("os.system(cmd)\n");
            analyze(&code, Language::Python)
        };
        assert!(flow_at(WINDOW + 10).is_empty(), "beyond the window");
        assert!(!flow_at(120).is_empty(), "120 lines apart used to be lost at 80");
    }

    #[test]
    fn traces_sql_flow_in_js() {
        let code = "\
function handler(req, res) {
  const name = req.query.name;
  const q = \"SELECT * FROM users WHERE n = '\" + name + \"'\";
  db.query(q);
}
";
        let flows = analyze(code, Language::JavaScript);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].category, "SQL-инъекция");
    }

    // ---------------------------------------------------------- interprocedural

    #[test]
    fn taint_does_not_bleed_across_functions() {
        // `cmd` is user input in one function and a constant in another. Without
        // function-scoping the two would merge and the constant would look
        // tainted — the false positive scoping fixes.
        let code = "\
def safe():
    cmd = 'ls -la'
    os.system(cmd)

def unsafe(request):
    other = request.args.get('q')
";
        assert!(analyze(code, Language::Python).is_empty());
    }

    #[test]
    fn traces_through_a_sinking_helper() {
        // Source in the caller, sink inside the callee: the flow has to cross the
        // function boundary via the argument.
        let code = "\
def run(request):
    cmd = request.args.get('cmd')
    danger(cmd)

def danger(x):
    os.system(x)
";
        let flows = analyze(code, Language::Python);
        assert_eq!(flows.len(), 1, "one cross-function flow expected: {flows:?}");
        let f = &flows[0];
        assert_eq!(f.category, "Инъекция команд");
        // source (cmd = request), call (danger(cmd)), sink (os.system) in callee
        assert_eq!(f.steps.iter().map(|s| &s.role).collect::<Vec<_>>(), vec![
            &FlowRole::Source,
            &FlowRole::Call,
            &FlowRole::Sink
        ]);
        assert_eq!(f.sink_line(), 6, "sink line is inside the callee");
    }

    #[test]
    fn traces_through_a_returning_helper() {
        // The helper returns its argument unchanged; taint has to survive the
        // round trip and reach the sink in the caller. (Named `wrap`, not
        // `passthru` — the latter is literally a shell-exec sink.)
        let code = "\
def wrap(x):
    return x + '!'

def run(request):
    raw = request.args.get('q')
    y = wrap(raw)
    os.system(y)
";
        let flows = analyze(code, Language::Python);
        assert_eq!(flows.len(), 1, "flow through a returning helper expected: {flows:?}");
        assert!(flows[0].steps.iter().any(|s| s.role == FlowRole::Call));
        assert_eq!(flows[0].steps.last().unwrap().role, FlowRole::Sink);
    }

    #[test]
    fn sanitising_helper_breaks_the_flow() {
        // The helper encodes its argument, so what comes back is safe: no flow.
        let code = "\
def clean(x):
    return escape(x)

def run(request):
    raw = request.args.get('q')
    y = clean(raw)
    os.system(y)
";
        assert!(analyze(code, Language::Python).is_empty(), "sanitising helper must break the flow");
    }

    #[test]
    fn helper_called_with_constant_is_not_flagged() {
        // The helper sinks its parameter, but the caller passes a constant, so
        // there is nothing user-controlled to report.
        let code = "\
def danger(x):
    os.system(x)

def run():
    danger('ls -la')
";
        assert!(analyze(code, Language::Python).is_empty());
    }

    #[test]
    fn traces_xss_into_inner_html() {
        let code = "\
function show(req) {
  const name = req.query.name;
  document.getElementById('x').innerHTML = name;
}
";
        let flows = analyze(code, Language::JavaScript);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].category, "XSS");
    }

    /// Werkzeug's secure_filename strips path separators and traversal — a
    /// filename through it must not read as path traversal.
    #[test]
    fn secure_filename_breaks_path_traversal() {
        let code = "\
def download(request):
    name = secure_filename(request.args.get('f'))
    return open('/data/' + name)
";
        assert!(analyze(code, Language::Python).is_empty(), "secure_filename should sanitize");
    }

    /// bleach.clean removes dangerous HTML — a value through it is not XSS.
    #[test]
    fn bleach_clean_breaks_xss() {
        let code = "\
function show(req) {
  const raw = req.query.bio;
  const safe = bleach.clean(raw);
  el.innerHTML = safe;
}
";
        assert!(analyze(code, Language::JavaScript).is_empty(), "bleach.clean should sanitize");
    }

    // ------------------------------------------------- Thunderbolt engine

    fn sql(code: &str, lang: Language) -> bool {
        analyze(code, lang).iter().any(|f| f.category == "SQL-инъекция")
    }

    /// Formatters break long calls; a flow split across them is still a flow.
    /// Every one of these came back empty before statements were joined.
    #[test]
    fn formatted_calls_are_one_statement() {
        let cases: &[(&str, Language, &str)] = &[
            ("black", Language::Python,
             "def a(request, cur):\n    uid = request.args.get('id')\n    cur.execute(\n        \"SELECT * FROM t WHERE id = \" + uid\n    )\n"),
            ("prettier template", Language::JavaScript,
             "function a(req, db) {\n  const id = req.query.id;\n  db.query(\n    `SELECT * FROM t WHERE id = ${id}`\n  );\n}\n"),
            ("parenthesised assignment", Language::Python,
             "def a(request, cur):\n    q = (\n        \"SELECT * FROM t WHERE id = \" + request.args.get('id')\n    )\n    cur.execute(q)\n"),
            ("trailing +", Language::Java,
             "void a(HttpServletRequest request, Statement stmt) throws Exception {\n  String sql = \"SELECT * FROM t WHERE id = \" +\n      request.getParameter(\"id\");\n  stmt.executeQuery(sql);\n}\n"),
            ("fluent chain", Language::JavaScript,
             "function a(req, knex) {\n  const id = req.query.id;\n  return knex\n    .raw(\"SELECT * FROM t WHERE id = \" + id);\n}\n"),
            ("triple-quoted f-string", Language::Python,
             "def a(request, cur):\n    uid = request.args.get('id')\n    cur.execute(f\"\"\"\n        SELECT * FROM t\n        WHERE id = {uid}\n    \"\"\")\n"),
        ];
        for (name, lang, code) in cases {
            assert!(sql(code, *lang), "{name}: a formatted call lost its flow");
        }
    }

    /// A line ending in `{` opens a block. Joining across it once folded every
    /// Express handler into a single statement, and the assignment inside the
    /// callback stopped being one.
    #[test]
    fn callback_bodies_keep_their_statements() {
        let express = "\
app.get('/u', (req, res) => {
  const id = req.query.id;
  db.query(\"SELECT * FROM t WHERE id = \" + id);
});
";
        assert!(sql(express, Language::JavaScript), "Express handler body");

        let promise = "\
function a(req, db) {
  load().then((row) => {
    const id = req.query.id;
    db.query(\"SELECT * FROM t WHERE id = \" + id);
  });
}
";
        assert!(sql(promise, Language::JavaScript), "promise callback body");
    }

    #[test]
    fn joiner_leaves_complete_statements_alone() {
        let joined = |src: &str, lang: Language| -> Vec<String> {
            let lines: Vec<&str> = src.lines().collect();
            join_continuations(&lines, lang).into_iter().map(|l| l.into_owned()).collect()
        };
        // `i++` is a statement, not a dangling `+`.
        assert_eq!(joined("i++\nfoo()", Language::Go)[1], "foo()");
        // Ruby blocks end in `|x|`; predicates end in `?`.
        assert_eq!(joined("items.each do |x|\n  run(x)\nend", Language::Ruby)[1], "  run(x)");
        assert_eq!(joined("if user.admin?\n  grant\nend", Language::Ruby)[1], "  grant");
        // A float literal ends in `.`.
        assert_eq!(joined("x = 1.\ny = 2", Language::Python)[1], "y = 2");
        // A comment's trailing comma or parenthesis does not swallow code.
        assert_eq!(joined("// note, see (here\nfoo()", Language::JavaScript)[1], "foo()");
        assert_eq!(joined("x = 1  # see (here\ny = 2", Language::Python)[1], "y = 2");
        // Line numbers survive: the statement sits on its first line.
        let j = joined("a(\n  b,\n  c\n)\nd()", Language::JavaScript);
        assert_eq!(j[0], "a( b, c )");
        assert!(j[1].is_empty() && j[2].is_empty() && j[3].is_empty());
        assert_eq!(j[4], "d()");
    }

    /// Request data bound straight to a handler argument, in each framework.
    #[test]
    fn bound_parameters_are_sources() {
        let cases: &[(&str, Language, &str)] = &[
            ("Spring @RequestParam", Language::Java,
             "@GetMapping(\"/u\")\npublic String a(@RequestParam(name = \"id\") String id, Statement stmt) throws Exception {\n  stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id);\n  return \"ok\";\n}\n"),
            ("Spring @PathVariable", Language::Java,
             "@GetMapping(\"/u/{id}\")\npublic String a(@PathVariable String id, Statement stmt) throws Exception {\n  stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id);\n  return \"ok\";\n}\n"),
            ("JAX-RS @QueryParam", Language::Java,
             "@GET\npublic Response a(@QueryParam(\"id\") String id, Statement stmt) throws Exception {\n  stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id);\n  return null;\n}\n"),
            ("Kotlin Spring", Language::Kotlin,
             "@GetMapping(\"/u\")\nfun a(@RequestParam id: String, stmt: Statement): String {\n  stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id)\n  return \"ok\"\n}\n"),
            ("ASP.NET [FromQuery]", Language::CSharp,
             "public IActionResult A([FromQuery] string id, SqlConnection conn)\n{\n  var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = \" + id, conn);\n  return Ok();\n}\n"),
            ("ASP.NET [FromRoute]", Language::CSharp,
             "public IActionResult A([FromRoute] string id, SqlConnection conn) {\n  var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = \" + id, conn);\n  return Ok();\n}\n"),
            ("NestJS @Query", Language::TypeScript,
             "async find(@Query('id') id: string) {\n  return this.db.query(\"SELECT * FROM t WHERE id = \" + id);\n}\n"),
            ("FastAPI Query()", Language::Python,
             "@app.get('/u')\ndef a(id: str = Query(...), cur=Depends(db)):\n    cur.execute(\"SELECT * FROM t WHERE id = \" + id)\n"),
            ("FastAPI Annotated", Language::Python,
             "@app.get('/u')\ndef a(id: Annotated[str, Query()], cur=Depends(db)):\n    cur.execute(\"SELECT * FROM t WHERE id = \" + id)\n"),
            ("FastAPI path", Language::Python,
             "@app.get('/u/{id}')\ndef a(id: str, cur=Depends(db)):\n    cur.execute(\"SELECT * FROM t WHERE id = \" + id)\n"),
            ("Flask route", Language::Python,
             "@app.route('/u/<id>')\ndef a(id):\n    cur.execute(\"SELECT * FROM t WHERE id = \" + id)\n"),
        ];
        for (name, lang, code) in cases {
            assert!(sql(code, *lang), "{name}: a bound parameter was not a source");
        }
    }

    /// The finding says where the data came from — a bound parameter is an
    /// HTTP request whatever it is called.
    #[test]
    fn bound_parameters_are_labelled_http() {
        let code = "@GetMapping(\"/u\")\npublic String a(@RequestParam String input, Statement stmt) throws Exception {\n  stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + input);\n  return \"ok\";\n}\n";
        let flows = analyze(code, Language::Java);
        assert_eq!(flows.first().map(|f| f.entry_kind()), Some("HTTP-запрос"));
    }

    /// A path segment converted to a number before the handler runs carries no
    /// payload, and a parameter no route mentions is not request data.
    #[test]
    fn typed_and_unbound_parameters_are_not_sources() {
        let cases: &[(&str, &str)] = &[
            ("Flask <int:id>", "@app.route('/u/<int:id>')\ndef a(id):\n    cur.execute(\"SELECT * FROM t WHERE id = \" + str(id))\n"),
            ("FastAPI id: int", "@app.get('/u/{id}')\ndef a(id: int, cur=Depends(db)):\n    cur.execute(\"SELECT * FROM t WHERE id = \" + str(id))\n"),
            ("unrouted helper", "def helper(id, cur):\n    cur.execute(\"SELECT * FROM t WHERE id = \" + id)\n"),
            ("FastAPI Depends", "@app.get('/u')\ndef a(cur=Depends(db), id: str = Depends(current_id)):\n    cur.execute(\"SELECT * FROM t WHERE id = \" + id)\n"),
        ];
        for (name, code) in cases {
            assert!(!sql(code, Language::Python), "{name} was treated as request data");
        }
    }

    /// Methods are scopes now in every heuristic language: a variable tainted in
    /// one method is not the variable of the same name in the next.
    #[test]
    fn methods_are_scopes_in_every_language() {
        let cases: &[(&str, Language, &str)] = &[
            ("Java", Language::Java,
             "void a(HttpServletRequest request) {\n  String id = request.getParameter(\"id\");\n  log(id);\n}\n\nvoid b(Statement stmt, String id) throws Exception {\n  stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id);\n}\n"),
            ("C# Allman", Language::CSharp,
             "public void A(HttpRequest Request)\n{\n  var id = Request.Query[\"id\"];\n  Log(id);\n}\n\npublic void B(SqlConnection conn, string id)\n{\n  var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = \" + id, conn);\n}\n"),
            ("Kotlin", Language::Kotlin,
             "fun a(request: HttpServletRequest) {\n  val id = request.getParameter(\"id\")\n  log(id)\n}\n\nfun b(stmt: Statement, id: String) {\n  stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id)\n}\n"),
            ("Ruby", Language::Ruby,
             "def a(params)\n  id = params[:id]\n  log(id)\nend\n\ndef b(id)\n  User.find_by_sql(\"SELECT * FROM users WHERE id = #{id}\")\nend\n"),
        ];
        for (name, lang, code) in cases {
            assert!(!sql(code, *lang), "{name}: taint leaked from one method into the next");
        }
    }

    /// With functions found, a helper that sinks its argument is traced from the
    /// caller — interprocedural analysis reaches the JVM, .NET and Ruby.
    #[test]
    fn helpers_are_followed_in_jvm_dotnet_and_ruby() {
        let cases: &[(&str, Language, &str)] = &[
            ("Java", Language::Java,
             "void find(Statement stmt, String id) throws Exception {\n  stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id);\n}\n\nvoid handle(HttpServletRequest request, Statement stmt) throws Exception {\n  String id = request.getParameter(\"id\");\n  find(stmt, id);\n}\n"),
            ("C#", Language::CSharp,
             "private void Find(SqlConnection conn, string id)\n{\n  var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = \" + id, conn);\n}\n\npublic void Handle(HttpRequest Request, SqlConnection conn)\n{\n  var id = Request.Query[\"id\"];\n  Find(conn, id);\n}\n"),
            ("Ruby", Language::Ruby,
             "def find(id)\n  User.find_by_sql(\"SELECT * FROM users WHERE id = #{id}\")\nend\n\ndef show(params)\n  id = params[:id]\n  find(id)\nend\n"),
        ];
        for (name, lang, code) in cases {
            assert!(sql(code, *lang), "{name}: the helper's sink was not reached");
        }
    }

    /// Java and C# lead with a type, so a call must never read as a definition:
    /// that would clear the taint mid-method and lose the flow.
    #[test]
    fn jvm_calls_are_not_definitions() {
        for line in [
            "return foo(x);",
            "new Foo(x);",
            "await Bar(y);",
            "else if (x) {",
            "Foo.bar(x);",
            "int y = foo(x);",
            "throw new IllegalStateException(e);",
            "assert check(x);",
            "var cmd = new SqlCommand(sql, conn);",
            "if (x) {",
            "foreach (var x in xs) {",
            "using (var c = Open()) {",
            "public record Point(int X, int Y);",
        ] {
            assert!(signature_of(line, Language::Java).is_none(), "Java read a call as a definition: {line}");
            assert!(signature_of(line, Language::CSharp).is_none(), "C# read a call as a definition: {line}");
        }
        for (line, name) in [
            ("public String a(@RequestParam(name = \"id\") String id) throws Exception {", "a"),
            ("void run()", "run"),
            ("public <T> T get(Class<T> type) {", "get"),
            ("public Map<String, List<Integer>> index() {", "index"),
            ("public UserService(UserRepository repo) {", "UserService"),
            ("int Add(int a, int b) => a + b;", "Add"),
            ("public async Task<IActionResult> Get([FromQuery] string id)", "Get"),
            ("@Override public void close() {", "close"),
        ] {
            let got = signature_of(line, Language::Java)
                .or_else(|| signature_of(line, Language::CSharp))
                .map(|(n, _)| n);
            assert_eq!(got.as_deref(), Some(name), "missed definition: {line}");
        }
    }

    /// JavaScript calls that end in a block are callbacks, not methods.
    #[test]
    fn js_callbacks_are_not_methods() {
        for line in [
            "app.get('/u', (req, res) => {",
            "describe('x', () => {",
            "useEffect(() => {",
            "if (ready) {",
            "for (const x of xs) {",
            "items.forEach((x) => {",
        ] {
            assert!(signature_of(line, Language::JavaScript).is_none(), "{line}");
        }
        for (line, name) in [
            ("async find(req, res) {", "find"),
            ("handle = async (req) => {", "handle"),
            ("export const load = (id: string): Promise<User> => {", "load"),
            ("constructor(private readonly db: Db) {", "constructor"),
        ] {
            assert_eq!(signature_of(line, Language::TypeScript).map(|(n, _)| n).as_deref(), Some(name), "{line}");
        }
    }

    /// A signature with no block has an empty body. It used to run to the end of
    /// the file, crediting every later function's sinks to an abstract method.
    #[test]
    fn signatures_without_a_block_have_empty_bodies() {
        let java = ["abstract void f(String id);", "void g(String x) {", "  run(x);", "}"];
        assert_eq!(body_range(&java, 0, Language::Java), 1..1);
        assert_eq!(body_range(&java, 1, Language::Java), 2..4);

        let kotlin = ["fun f(x: Int) = x + 1", "fun g() {", "  h()", "}"];
        assert_eq!(body_range(&kotlin, 0, Language::Kotlin), 1..1);

        let csharp = ["public void A()", "{", "  B();", "}", "public void C() {}"];
        assert_eq!(body_range(&csharp, 0, Language::CSharp), 1..4, "Allman brace on the next line");

        let ruby = ["def a(x)", "  b(x)", "end", "def c", "end"];
        assert_eq!(body_range(&ruby, 0, Language::Ruby), 1..2);
    }

    #[test]
    fn destructuring_and_unpacking_carry_taint() {
        let cases: &[(&str, Language, &str)] = &[
            ("JS object", Language::JavaScript,
             "function a(req, db) {\n  const { id } = req.query;\n  db.query(\"SELECT * FROM t WHERE id = \" + id);\n}\n"),
            ("JS alias", Language::JavaScript,
             "function a(req, db) {\n  const { id: userId, ...rest } = req.params;\n  db.query(\"SELECT * FROM t WHERE id = \" + userId);\n}\n"),
            ("JS array", Language::JavaScript,
             "function a(req, db) {\n  const [first, second] = req.body.ids;\n  db.query(\"SELECT * FROM t WHERE id = \" + second);\n}\n"),
            ("Python unpacking", Language::Python,
             "def a(request, cur):\n    a, b = request.args.get('a'), request.args.get('b')\n    cur.execute(\"SELECT * FROM t WHERE id = \" + b)\n"),
            ("Go value, err", Language::Go,
             "func h(r *http.Request, db *sql.DB) {\n\tbody, err := io.ReadAll(r.Body)\n\tdb.Query(\"SELECT * FROM t WHERE x = \" + string(body))\n}\n"),
            ("Ruby parallel", Language::Ruby,
             "def show(params)\n  a, b = params[:a], params[:b]\n  User.find_by_sql(\"SELECT * FROM users WHERE id = #{b}\")\nend\n"),
        ];
        for (name, lang, code) in cases {
            assert!(sql(code, *lang), "{name}: the destructured name lost its taint");
        }
    }

    #[test]
    fn multiple_assignment_skips_error_and_blank_names() {
        let (names, rhs) = multi_assign("body, err := io.ReadAll(r.Body)").expect("Go pair");
        assert_eq!(names, vec!["body".to_string()]);
        assert_eq!(rhs, "io.ReadAll(r.Body)");
        let (names, _) = multi_assign("_, ok := m[k]").unwrap_or_default();
        assert!(names.is_empty(), "blank and ok bind nothing");
        assert!(multi_assign("a == b").is_none());
        assert!(multi_assign("for a, b in pairs:").is_none());
    }

    #[test]
    fn parameter_names_follow_each_language() {
        for (raw, lang, want) in [
            ("@RequestParam(name = \"id\") String id", Language::Java, "id"),
            ("final List<String> names", Language::Java, "names"),
            ("[FromQuery] string id = \"x\"", Language::CSharp, "id"),
            ("@RequestParam id: String", Language::Kotlin, "id"),
            ("vararg ids: Int", Language::Kotlin, "ids"),
            ("@Query('id') id: string", Language::TypeScript, "id"),
            ("id: str = Query(...)", Language::Python, "id"),
            ("id string", Language::Go, "id"),
            ("id:", Language::Ruby, "id"),
            ("implicit ec: ExecutionContext", Language::Scala, "ec"),
        ] {
            assert_eq!(param_name(raw, lang).as_deref(), Some(want), "{raw}");
        }
    }

    /// Found by running the engine over 3,122 files of real JavaScript: a
    /// highlight.js grammar produced a path-traversal "flow" out of four
    /// unrelated defects, each pinned below.
    #[test]
    fn regex_literals_are_not_code() {
        // `//` inside a regex is not a comment, and its parentheses are text.
        let m = mask_strings("url.replace(/^https?:\\/\\//, '')");
        assert!(!m.contains("//"), "{m}");
        assert_eq!(m.matches('(').count(), m.matches(')').count(), "{m}");
        // Division stays division, in every language.
        assert_eq!(mask_strings("x = a / b / c"), "x = a / b / c");
        assert_eq!(mask_strings("y = (a + b) / 2"), "y = (a + b) / 2");
        // A URL regex inside a call must not keep the statement open.
        let lines = ["s = url.replace(/^https?:\\/\\//, '');", "db.query(q);"];
        let joined = join_continuations(&lines, Language::JavaScript);
        assert_eq!(joined[1], "db.query(q);", "joined past a regex literal");
    }

    #[test]
    fn sources_inside_regex_literals_do_not_count() {
        let code = "\
function a(db) {
  const re = /@(return|param)/;
  db.query(\"SELECT * FROM t WHERE x = \" + re);
}
";
        assert!(!sql(code, Language::JavaScript), "a regex mentioning `param` became request data");
    }

    #[test]
    fn sinks_inside_strings_are_text() {
        let code = "\
def a(request, log):
    host = request.args.get('h')
    log.info(\"calling system(\" + host + \")\")
";
        assert!(analyze(code, Language::Python).is_empty(), "a log message is not a command");

        // A sink half-inside a string by nature still counts.
        let php = "\
<?php
function go() {
  $next = $_GET['next'];
  header(\"Location: \" . $next);
}
";
        assert!(
            analyze(php, Language::Php).iter().any(|f| f.category == "Открытый редирект"),
            "header('Location: …') begins in code"
        );
    }

    #[test]
    fn object_literal_members_stay_separate() {
        let lines = ["const o = {", "  a: req.query.a,", "  b: 2,", "};"];
        let joined = join_continuations(&lines, Language::JavaScript);
        assert_eq!(joined[1], "  a: req.query.a,");
        assert_eq!(joined[2], "  b: 2,");
    }

    #[test]
    fn include_needs_a_path() {
        let js = "\
function a(req) {
  const id = req.query.id;
  const modes = [INCLUDE, id];
}
";
        assert!(analyze(js, Language::JavaScript).is_empty(), "a constant named INCLUDE is not inclusion");

        let php = "\
<?php
function render() {
  $page = $_GET['page'];
  include $page . '.php';
}
";
        assert!(
            analyze(php, Language::Php).iter().any(|f| f.category == "Path traversal"),
            "PHP inclusion of a variable is still found"
        );
    }

    // ------------------------------------------- Ruby, Go, Scala and Elixir

    /// The rest of the heuristic languages, probed the same way the JVM was.
    /// Rails reaches a database through its query builder, Go through the
    /// `*Context` methods, Elixir through Ecto — none of which looked like a
    /// sink, so eleven of twenty-one ordinary idioms produced nothing at all.
    #[test]
    fn ruby_go_scala_elixir_are_traced() {
        let cases: &[(&str, &str, Language, &str)] = &[
            ("SQL-инъекция", "ActiveRecord where", Language::Ruby,
             "def show(params)\n  name = params[:name]\n  User.where(\"name = '#{name}'\")\nend\n"),
            ("SQL-инъекция", "find_by_sql", Language::Ruby,
             "def show(params)\n  id = params[:id]\n  User.find_by_sql(\"SELECT * FROM users WHERE id = #{id}\")\nend\n"),
            ("SQL-инъекция", "order clause", Language::Ruby,
             "def show(params)\n  col = params[:sort]\n  User.order(\"#{col} ASC\")\nend\n"),
            ("Выполнение кода", "public_send", Language::Ruby,
             "def call(params, obj)\n  m = params[:m]\n  obj.public_send(m)\nend\n"),
            ("Выполнение кода", "instance_eval", Language::Ruby,
             "def call(params, obj)\n  code = params[:code]\n  obj.instance_eval(code)\nend\n"),
            ("Выполнение кода", "ERB template", Language::Ruby,
             "def render(params)\n  tpl = params[:tpl]\n  ERB.new(tpl).result(binding)\nend\n"),
            ("XSS", "raw helper", Language::Ruby,
             "def show(params)\n  bio = params[:bio]\n  raw(bio)\nend\n"),
            ("SQL-инъекция", "database/sql QueryRow", Language::Go,
             "func h(r *http.Request, db *sql.DB) {\n\tid := r.URL.Query().Get(\"id\")\n\tdb.QueryRow(\"SELECT * FROM t WHERE id = \" + id)\n}\n"),
            ("SQL-инъекция", "context variant", Language::Go,
             "func h(r *http.Request, db *sql.DB) {\n\tid := r.URL.Query().Get(\"id\")\n\tdb.QueryContext(ctx, \"SELECT * FROM t WHERE id = \" + id)\n}\n"),
            ("Path traversal", "os.WriteFile", Language::Go,
             "func h(r *http.Request) {\n\tf := r.URL.Query().Get(\"f\")\n\tos.WriteFile(\"/data/\" + f, b, 0644)\n}\n"),
            ("XSS", "template.HTML", Language::Go,
             "func h(w http.ResponseWriter, r *http.Request) {\n\tn := r.URL.Query().Get(\"n\")\n\ttpl.Execute(w, template.HTML(n))\n}\n"),
            ("SQL-инъекция", "Anorm", Language::Scala,
             "def show(request: Request) = {\n  val id = request.getQueryString(\"id\").get\n  SQL(\"SELECT * FROM t WHERE id = \" + id)\n}\n"),
            ("Инъекция команд", "System.cmd", Language::Elixir,
             "def run(params) do\n  host = params[\"host\"]\n  System.cmd(\"ping\", [host])\nend\n"),
            ("SQL-инъекция", "Ecto raw query", Language::Elixir,
             "def show(params) do\n  id = params[\"id\"]\n  Ecto.Adapters.SQL.query(Repo, \"SELECT * FROM t WHERE id = \" <> id)\nend\n"),
        ];
        let mut missed = Vec::new();
        for (want, name, lang, code) in cases {
            if !analyze(code, *lang).iter().any(|f| f.category == *want) {
                missed.push(format!("{name} ({lang:?}) — expected {want}"));
            }
        }
        assert!(missed.is_empty(), "not traced:\n  {}", missed.join("\n  "));
    }

    /// `exec` after a dot is not a shell. Go's `db.Exec` is a query and
    /// JavaScript's `regex.exec` is a regular expression, yet both matched the
    /// command sink — and because that heuristic is listed first, a Go SQL
    /// injection was reported as command injection, with the wrong CWE and the
    /// wrong advice ("pass the command as an argument list").
    #[test]
    fn dotted_exec_is_neither_a_command_nor_code() {
        let go = "\
func h(r *http.Request, db *sql.DB) {
\tid := r.URL.Query().Get(\"id\")
\tdb.Exec(\"DELETE FROM t WHERE id = \" + id)
}
";
        let cats: Vec<&str> = analyze(go, Language::Go).iter().map(|f| f.category).collect();
        assert!(cats.contains(&"SQL-инъекция"), "db.Exec is a query, got {cats:?}");
        assert!(!cats.contains(&"Инъекция команд"), "db.Exec is not a shell, got {cats:?}");

        let js = "\
function a(req) {
  const input = req.query.q;
  const m = /^a/.exec(input);
}
";
        assert!(
            analyze(js, Language::JavaScript).is_empty(),
            "a regex match is not an execution sink"
        );
    }

    /// Go renders templates with `tpl.Execute(w, data)`. Matching `execute`
    /// regardless of case turned every Go template render carrying user data
    /// into a SQL injection; the list now spells the lowercase DB-API/JDBC
    /// form, and .NET's capitalised entry points are named individually.
    #[test]
    fn go_template_render_is_not_a_query() {
        let code = "func h(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get(\"name\")
	tpl.Execute(w, name)
}
";
        assert!(
            !analyze(code, Language::Go).iter().any(|f| f.category == "SQL-инъекция"),
            "rendering a template is not a query"
        );
    }

    /// A query builder that binds its value is the safe form, in every
    /// ecosystem. The first argument is a column name, not the query.
    #[test]
    fn query_builder_bound_values_stay_quiet() {
        let knex = "\
function a(req, knex) {
  const name = req.query.name;
  knex('users').where('name', name);
}
";
        assert!(
            !analyze(knex, Language::JavaScript).iter().any(|f| f.category == "SQL-инъекция"),
            "a bound builder value is not an injection"
        );

        let ruby = "\
def show(params)
  name = params[:name]
  User.where(name: name)
end
";
        assert!(
            !analyze(ruby, Language::Ruby).iter().any(|f| f.category == "SQL-инъекция"),
            "hash conditions are not an injection"
        );
    }

    // ------------------------------------------------------------ JVM and .NET

    /// Java, Kotlin and C# carry 44 catalogue rules between them, yet not one
    /// ordinary injection in them reached a data-flow finding: the sink patterns
    /// were written for Python and JavaScript. Sources were fine — the engine
    /// saw the input and tracked it, then had nowhere to report it.
    #[test]
    fn jvm_and_dotnet_injections_are_traced() {
        let cases: &[(&str, &str, Language, &str)] = &[
            ("SQL-инъекция", "JDBC executeQuery", Language::Java,
             "void a(HttpServletRequest request, Statement stmt) throws Exception {\n  String id = request.getParameter(\"id\");\n  stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id);\n}\n"),
            ("SQL-инъекция", "prepareStatement is not magic", Language::Java,
             "void a(HttpServletRequest request, Connection conn) throws Exception {\n  String id = request.getParameter(\"id\");\n  PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM t WHERE id = \" + id);\n}\n"),
            ("SQL-инъекция", "JPA createQuery", Language::Java,
             "void a(HttpServletRequest request, EntityManager em) {\n  String n = request.getParameter(\"n\");\n  em.createQuery(\"FROM User WHERE name = '\" + n + \"'\");\n}\n"),
            ("SQL-инъекция", "Kotlin concatenation", Language::Kotlin,
             "fun a(request: HttpServletRequest, stmt: Statement) {\n  val id = request.getParameter(\"id\")\n  stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id)\n}\n"),
            ("SQL-инъекция", "Kotlin string template", Language::Kotlin,
             "fun a(request: HttpServletRequest, stmt: Statement) {\n  val id = request.getParameter(\"id\")\n  stmt.executeQuery(\"SELECT * FROM t WHERE id = $id\")\n}\n"),
            ("SQL-инъекция", "ADO.NET SqlCommand", Language::CSharp,
             "void A(HttpRequest Request, SqlConnection conn) {\n  var id = Request.Query[\"id\"];\n  var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = \" + id, conn);\n}\n"),
            ("SQL-инъекция", "C# interpolated string", Language::CSharp,
             "void A(HttpRequest Request, SqlConnection conn) {\n  var id = Request.Query[\"id\"];\n  var cmd = new SqlCommand($\"SELECT * FROM t WHERE id = {id}\", conn);\n}\n"),
            ("SQL-инъекция", "EF Core FromSqlRaw", Language::CSharp,
             "void A(HttpRequest Request, AppDb db) {\n  var id = Request.Query[\"id\"];\n  var u = db.Users.FromSqlRaw(\"SELECT * FROM Users WHERE Id = \" + id);\n}\n"),
            ("Path traversal", "java.io.File", Language::Java,
             "void a(HttpServletRequest request) {\n  String f = request.getParameter(\"f\");\n  File file = new File(\"/data/\" + f);\n}\n"),
            ("Path traversal", "Kotlin bare File(", Language::Kotlin,
             "fun a(request: HttpServletRequest) {\n  val f = request.getParameter(\"f\")\n  val file = File(\"/data/\" + f)\n}\n"),
            ("Path traversal", "NIO Files", Language::Java,
             "void a(HttpServletRequest request) throws Exception {\n  String f = request.getParameter(\"f\");\n  byte[] b = Files.readAllBytes(Path.of(f));\n}\n"),
            ("Path traversal", ".NET File.ReadAllText", Language::CSharp,
             "void A(HttpRequest Request) {\n  var f = Request.Query[\"f\"];\n  var text = File.ReadAllText(f);\n}\n"),
            ("XSS", "servlet writer", Language::Java,
             "void a(HttpServletRequest request, HttpServletResponse response) throws Exception {\n  String n = request.getParameter(\"n\");\n  response.getWriter().write(\"<p>\" + n);\n}\n"),
            ("XSS", "Response.Write", Language::CSharp,
             "void A(HttpRequest Request) {\n  var n = Request.Query[\"n\"];\n  Response.Write(\"<p>\" + n);\n}\n"),
            ("SSRF", "URL.openStream", Language::Java,
             "void a(HttpServletRequest request) throws Exception {\n  String u = request.getParameter(\"u\");\n  URL url = new URL(u);\n  InputStream s = url.openStream();\n}\n"),
            ("SSRF", "RestTemplate", Language::Java,
             "void a(HttpServletRequest request, RestTemplate rest) {\n  String u = request.getParameter(\"u\");\n  String b = rest.getForObject(u, String.class);\n}\n"),
            ("SSRF", "HttpClient", Language::CSharp,
             "async Task A(HttpRequest Request, HttpClient client) {\n  var u = Request.Query[\"u\"];\n  var body = await client.GetStringAsync(u);\n}\n"),
            ("Инъекция команд", "Process.Start", Language::CSharp,
             "void A(HttpRequest Request) {\n  var c = Request.Query[\"c\"];\n  Process.Start(\"cmd.exe\", \"/c \" + c);\n}\n"),
            ("Выполнение кода", "Java deserialisation", Language::Java,
             "void a(HttpServletRequest request) throws Exception {\n  ObjectInputStream in = new ObjectInputStream(request.getInputStream());\n  Object o = in.readObject();\n}\n"),
            ("Выполнение кода", "SpEL", Language::Java,
             "void a(HttpServletRequest request, ExpressionParser parser) {\n  String e = request.getParameter(\"e\");\n  Object v = parser.parseExpression(e).getValue();\n}\n"),
        ];
        let mut missed = Vec::new();
        for (want, name, lang, code) in cases {
            if !analyze(code, *lang).iter().any(|f| f.category == *want) {
                missed.push(format!("{name} ({lang:?}) — expected {want}"));
            }
        }
        assert!(missed.is_empty(), "not traced:\n  {}", missed.join("\n  "));
    }

    /// A declared type used to end the trail: any type outside a fixed list made
    /// the line invisible as an assignment. That silently disabled propagation
    /// for most real Java and C#, and for every annotated TypeScript or Python
    /// declaration — not a JVM problem at all, just the one that exposed it.
    #[test]
    fn typed_declarations_carry_taint() {
        let cases: &[(&str, Language, &str)] = &[
            ("TypeScript annotation", Language::TypeScript,
             "function a(req, db) {\n  const id: string = req.query.id as string;\n  db.query(\"SELECT * FROM t WHERE id = \" + id);\n}\n"),
            ("C# lowercase string", Language::CSharp,
             "void A(HttpRequest Request, SqlConnection conn) {\n  string id = Request.Query[\"id\"];\n  var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = \" + id, conn);\n}\n"),
            ("Python annotation", Language::Python,
             "def a(request, cur):\n    uid: str = request.args.get('id')\n    cur.execute(\"SELECT * FROM t WHERE id = \" + uid)\n"),
            ("Java class-typed intermediate", Language::Java,
             "void a(HttpServletRequest request, Statement stmt) throws Exception {\n  String id = request.getParameter(\"id\");\n  StringBuilder sql = new StringBuilder(\"SELECT * FROM t WHERE id = \").append(id);\n  stmt.executeQuery(sql.toString());\n}\n"),
        ];
        for (name, lang, code) in cases {
            assert!(
                analyze(code, *lang).iter().any(|f| f.category == "SQL-инъекция"),
                "{name}: the typed declaration dropped the taint"
            );
        }
    }

    /// Every ecosystem's canonical *safe* form. Each of these would have been an
    /// injection finding had the sinks been added without string masking and
    /// bind-parameter awareness — the column is literally named `id`, like the
    /// variable, and Spring passes the value on the very same line.
    #[test]
    fn jvm_and_dotnet_safe_forms_stay_quiet() {
        let cases: &[(&str, Language, &str)] = &[
            ("JDBC PreparedStatement", Language::Java,
             "void a(HttpServletRequest request, Connection conn) throws Exception {\n  String id = request.getParameter(\"id\");\n  PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM t WHERE id = ?\");\n  ps.setString(1, id);\n  ps.executeQuery();\n}\n"),
            ("Spring JdbcTemplate bind argument", Language::Java,
             "void a(HttpServletRequest request, JdbcTemplate jdbc) {\n  String id = request.getParameter(\"id\");\n  String n = jdbc.queryForObject(\"SELECT n FROM t WHERE id = ?\", String.class, id);\n}\n"),
            ("ADO.NET parameters", Language::CSharp,
             "void A(HttpRequest Request, SqlConnection conn) {\n  var id = Request.Query[\"id\"];\n  var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = @id\", conn);\n  cmd.Parameters.AddWithValue(\"@id\", id);\n}\n"),
            ("EF Core FromSqlInterpolated", Language::CSharp,
             "void A(HttpRequest Request, AppDb db) {\n  var id = Request.Query[\"id\"];\n  var u = db.Users.FromSqlInterpolated($\"SELECT * FROM Users WHERE Id = {id}\");\n}\n"),
        ];
        for (name, lang, code) in cases {
            let sql: Vec<_> =
                analyze(code, *lang).into_iter().filter(|f| f.category == "SQL-инъекция").collect();
            assert!(sql.is_empty(), "{name} reported as SQL injection");
        }
    }

    /// Console output is not a response. `System.out.println` is the JVM's
    /// `print`, and reporting it as XSS would discredit the category.
    #[test]
    fn jvm_console_output_is_not_xss() {
        let code = "\
public static void main(String[] args) {
  String name = args[0];
  System.out.println(name);
}
";
        assert!(!analyze(code, Language::Java).iter().any(|f| f.category == "XSS"));
    }

    /// Sanitiser scoping reaches .NET and the OWASP Java Encoder: an HTML
    /// encoder clears XSS and nothing else.
    #[test]
    fn dotnet_and_jvm_html_encoders_are_scoped() {
        let xss = "\
void A(HttpRequest Request) {
  var safe = HttpUtility.HtmlEncode(Request.Query[\"n\"]);
  Response.Write(\"<p>\" + safe);
}
";
        assert!(
            !analyze(xss, Language::CSharp).iter().any(|f| f.category == "XSS"),
            "HtmlEncode should clear XSS"
        );

        let sql = "\
void A(HttpRequest Request, SqlConnection conn) {
  var safe = HttpUtility.HtmlEncode(Request.Query[\"id\"]);
  var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = \" + safe, conn);
}
";
        assert!(
            analyze(sql, Language::CSharp).iter().any(|f| f.category == "SQL-инъекция"),
            "HtmlEncode must not clear SQL taint"
        );

        let java = "\
void a(HttpServletRequest request, HttpServletResponse response) throws Exception {
  String safe = Encode.forHtml(request.getParameter(\"n\"));
  response.getWriter().write(\"<p>\" + safe);
}
";
        assert!(
            !analyze(java, Language::Java).iter().any(|f| f.category == "XSS"),
            "Encode.forHtml should clear XSS"
        );
    }

    // ---------------------------------------------------- strings are not code

    #[test]
    fn mask_blanks_literals_and_keeps_interpolation() {
        // Plain literal: the column name disappears, the code around it stays.
        let m = mask_strings("cur.execute(\"SELECT * FROM t WHERE id = ?\")");
        assert!(m.starts_with("cur.execute(\""));
        assert!(!contains_word(&m, "id"), "column name must not survive: {m}");

        // Each interpolation form keeps the variable visible.
        for (line, var) in [
            ("q = `SELECT ${id}`", "id"),            // JS template
            ("q = f\"SELECT {id}\"", "id"),          // Python f-string
            ("q = $\"SELECT {id}\"", "id"),          // C# interpolated
            ("q = \"SELECT #{id}\"", "id"),          // Ruby
            ("val q = \"SELECT ${id}\"", "id"),      // Kotlin braces
            ("val q = \"SELECT $id\"", "id"),        // Kotlin bare
            ("$q = \"SELECT $id\";", "$id"),         // PHP
        ] {
            assert!(contains_word(&mask_strings(line), var), "{var} lost in {line}");
        }
    }

    /// `{…}` interpolates only behind an f/`$` prefix: in a plain string it is
    /// text (MessageFormat, JSON), and `{{` is an escaped brace in an f-string.
    #[test]
    fn braces_interpolate_only_behind_a_prefix() {
        assert!(!contains_word(&mask_strings("m = \"hello {id}\""), "id"));
        assert!(!contains_word(&mask_strings("m = f\"hello {{id}}\""), "id"));
        assert!(!contains_word(&mask_strings("buf\"{id}\""), "id"), "buf is not an f prefix");
    }

    #[test]
    fn escaped_quotes_do_not_end_the_literal() {
        let m = mask_strings(r#"s = "say \"id\" now" + id"#);
        // Exactly one `id` survives: the concatenated variable, not the quoted word.
        assert_eq!(m.matches("id").count(), 1, "{m}");
    }

    /// The false positive this change exists for: `id` named only as a column.
    #[test]
    fn column_name_in_a_literal_is_not_a_flow() {
        let py = "\
def a(request, cur):
    id = request.args.get('id')
    cur.execute(\"SELECT * FROM t WHERE id = 1\")
";
        assert!(analyze(py, Language::Python).is_empty(), "column name read as the variable");

        let js = "\
function a(req, db) {
  const id = req.query.id;
  db.query(\"SELECT * FROM t WHERE id = ?\", [1]);
}
";
        assert!(analyze(js, Language::JavaScript).is_empty(), "column name read as the variable");
    }

    /// The canonical safe form in each ecosystem passes the value *beside* the
    /// query. That is the fix for SQL injection and must not be reported as one.
    #[test]
    fn bind_parameters_are_not_sql_injection() {
        let cases: &[(&str, Language)] = &[
            ("def a(request, cur):\n    id = request.args.get('id')\n    cur.execute(\"SELECT * FROM t WHERE id = %s\", (id,))\n", Language::Python),
            ("function a(req, db) {\n  const id = req.query.id;\n  db.query(\"SELECT * FROM t WHERE id = ?\", [id]);\n}\n", Language::JavaScript),
            ("<?php\nfunction a($c) {\n  $id = $_GET['id'];\n  pg_query_params($c, 'SELECT * FROM t WHERE id = $1', array($id));\n}\n", Language::Php),
        ];
        for (code, lang) in cases {
            let sql: Vec<_> = analyze(code, *lang).into_iter().filter(|f| f.category == "SQL-инъекция").collect();
            assert!(sql.is_empty(), "bind parameter reported as injection in {lang:?}:\n{code}");
        }
    }

    /// Narrowing to the query argument must not cost a single real injection.
    #[test]
    fn injection_in_the_query_argument_is_still_found() {
        let cases: &[(&str, Language)] = &[
            ("def a(request, cur):\n    id = request.args.get('id')\n    cur.execute(\"SELECT * FROM t WHERE id = \" + id, ())\n", Language::Python),
            ("def a(request, cur):\n    id = request.args.get('id')\n    cur.execute(f\"SELECT * FROM t WHERE id = {id}\")\n", Language::Python),
            ("function a(req, db) {\n  const id = req.query.id;\n  db.query(`SELECT * FROM t WHERE id = ${id}`, []);\n}\n", Language::JavaScript),
            // PHP procedural takes the connection first; the query is argument two.
            ("<?php\nfunction a($db) {\n  $name = $_POST['name'];\n  mysqli_query($db, \"SELECT * FROM t WHERE name = '$name'\");\n}\n", Language::Php),
        ];
        for (code, lang) in cases {
            assert!(
                analyze(code, *lang).iter().any(|f| f.category == "SQL-инъекция"),
                "real injection lost in {lang:?}:\n{code}"
            );
        }
    }

    /// A comma inside a string used to split an argument in two and shift every
    /// later one — `helper("a, b", x)` saw `x` in the wrong slot.
    #[test]
    fn commas_inside_strings_do_not_split_arguments() {
        assert_eq!(split_top_commas(r#""a, b", x"#).len(), 2);
        assert_eq!(split_top_commas(r#"'(', x"#).len(), 2);
        assert_eq!(split_top_commas(r#""say \"a, b\"", x"#).len(), 2);
    }

    /// The word "escape" inside a message is not a call to an escaper.
    #[test]
    fn sanitizer_words_inside_strings_do_not_sanitize() {
        let code = "\
def a(request, cur):
    id = request.args.get('id')
    q = \"escape failed for \" + id
    cur.execute(q)
";
        assert!(
            analyze(code, Language::Python).iter().any(|f| f.category == "SQL-инъекция"),
            "a string mentioning 'escape' cleared the taint"
        );
    }

    /// PHP prints straight to the response — `echo` is where most PHP XSS
    /// actually happens, and the DOM-shaped patterns never saw it.
    #[test]
    fn php_echo_is_an_xss_sink() {
        let code = "<?php
function show() {
  $name = $_GET['name'];
  echo \"<p>Hello $name</p>\";
}
";
        assert!(
            analyze(code, Language::Php).iter().any(|f| f.category == "XSS"),
            "echo of user input must be XSS"
        );
    }

    /// The reason `print` and `printf` are not in the pattern: they are ordinary
    /// console output in four of the heuristic languages. A CLI script printing
    /// its argument is not cross-site scripting, and reporting it as such would
    /// discredit the whole category.
    #[test]
    fn console_print_in_other_languages_is_not_xss() {
        let py = "import sys
def main():
    name = sys.argv[1]
    print(name)
";
        assert!(
            !analyze(py, Language::Python).iter().any(|f| f.category == "XSS"),
            "Python print() must not be reported as XSS"
        );

        let rb = "def main
  name = ARGV[0]
  print name
end
";
        assert!(
            !analyze(rb, Language::Ruby).iter().any(|f| f.category == "XSS"),
            "Ruby print must not be reported as XSS"
        );
    }

    /// PHP makes outbound requests through cURL, and the URL lands at
    /// `curl_setopt`, not at `curl_exec`.
    #[test]
    fn php_curl_is_an_ssrf_sink() {
        let code = "<?php
function fetch() {
  $url = $_GET['url'];
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $url);
}
";
        assert!(
            analyze(code, Language::Php).iter().any(|f| f.category == "SSRF"),
            "curl_setopt with a tainted URL must be SSRF"
        );
    }

    /// PHP redirects by emitting a Location header.
    #[test]
    fn php_location_header_is_an_open_redirect() {
        let code = "<?php
function go() {
  $next = $_GET['next'];
  header(\"Location: \" . $next);
}
";
        assert!(
            analyze(code, Language::Php).iter().any(|f| f.category == "Открытый редирект"),
            "header('Location: ...') must be an open redirect sink"
        );
    }

    /// A tainted path in `include` is local/remote file inclusion — the most
    /// damaging shape this category takes, and a keyword rather than a call.
    #[test]
    fn php_include_is_a_path_traversal_sink() {
        let code = "<?php
function render() {
  $page = $_GET['page'];
  include $page . '.php';
}
";
        assert!(
            analyze(code, Language::Php).iter().any(|f| f.category == "Path traversal"),
            "include of user input must be path traversal"
        );
    }

    /// PHP object injection: unserialize on attacker data runs magic methods.
    #[test]
    fn php_unserialize_is_a_code_execution_sink() {
        let code = "<?php
function load() {
  $blob = $_POST['data'];
  $obj = unserialize($blob);
}
";
        assert!(
            analyze(code, Language::Php).iter().any(|f| f.category == "Выполнение кода"),
            "unserialize of user input must be code execution"
        );
    }

    /// PHP reaches a database through `->`, through bare mysqli/pgsql
    /// functions, and through Laravel's `DB::` facade. The sink pattern used to
    /// require a literal dot, so every one of these was invisible: SQL
    /// injection in PHP simply was not traced.
    #[test]
    fn php_pdo_arrow_call_is_a_sql_sink() {
        let code = "<?php
function show($pdo) {
  $id = $_GET['id'];
  $pdo->query(\"SELECT * FROM users WHERE id = $id\");
}
";
        let flows = analyze(code, Language::Php);
        assert!(
            flows.iter().any(|f| f.category == "SQL-инъекция"),
            "$pdo->query must be a SQL sink, got {:?}",
            flows.iter().map(|f| f.category).collect::<Vec<_>>()
        );
    }

    #[test]
    fn php_bare_mysqli_function_is_a_sql_sink() {
        let code = "<?php
function show($db) {
  $name = $_POST['name'];
  mysqli_query($db, \"SELECT * FROM users WHERE name = '$name'\");
}
";
        assert!(
            analyze(code, Language::Php).iter().any(|f| f.category == "SQL-инъекция"),
            "mysqli_query must be a SQL sink"
        );
    }

    /// WordPress is a large share of PHP in the wild and never calls `query`
    /// directly for reads.
    #[test]
    fn wordpress_wpdb_getters_are_sql_sinks() {
        let code = "<?php
function show($wpdb) {
  $id = $_GET['id'];
  $row = $wpdb->get_results(\"SELECT * FROM wp_posts WHERE ID = $id\");
}
";
        assert!(
            analyze(code, Language::Php).iter().any(|f| f.category == "SQL-инъекция"),
            "$wpdb->get_results must be a SQL sink"
        );
    }

    #[test]
    fn laravel_db_facade_is_a_sql_sink() {
        let code = "<?php
function show() {
  $id = $_GET['id'];
  DB::select(\"SELECT * FROM users WHERE id = $id\");
}
";
        assert!(
            analyze(code, Language::Php).iter().any(|f| f.category == "SQL-инъекция"),
            "DB::select must be a SQL sink"
        );
    }

    /// Widening the sink must not cost the guard: a parameterised PHP query is
    /// still not a finding.
    #[test]
    fn php_parameterised_query_stays_quiet() {
        let code = "<?php
function show($pdo) {
  $id = $_GET['id'];
  $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
  $stmt->bindParam(1, $id);
}
";
        assert!(
            !analyze(code, Language::Php).iter().any(|f| f.category == "SQL-инъекция"),
            "bindParam should clear SQL taint"
        );
    }

    /// The bug this whole scoping change exists for: an HTML escaper made the
    /// engine drop a live SQL injection. `htmlspecialchars` encodes `< > & " '`
    /// for markup and leaves the value hostile to a query, so the flow must
    /// still be reported — with the SQL category, not XSS.
    #[test]
    fn html_escaper_does_not_clear_sql_injection() {
        let code = "def show(request, cur):
    safe = html.escape(request.args.get('id'))
    cur.execute('SELECT * FROM t WHERE id = ' + safe)
";
        let flows = analyze(code, Language::Python);
        assert!(
            flows.iter().any(|f| f.category == "SQL-инъекция"),
            "htmlspecialchars must not clear SQL taint, got {:?}",
            flows.iter().map(|f| f.category).collect::<Vec<_>>()
        );
    }

    /// The other half of the same rule: within its own category the escaper
    /// still works, or scoping would have traded one false result for another.
    #[test]
    fn html_escaper_still_clears_xss() {
        let code = "function show(req) {
  const safe = htmlspecialchars(req.query.bio);
  el.innerHTML = safe;
}
";
        assert!(
            !analyze(code, Language::JavaScript).iter().any(|f| f.category == "XSS"),
            "htmlspecialchars should still clear XSS"
        );
    }

    /// Shell quoting is the mirror image: safe to hand to a shell, still a
    /// payload in a query.
    #[test]
    fn shell_quoting_is_scoped_to_commands() {
        let cmd = "import subprocess
def run(request):
    arg = shlex.quote(request.args.get('f'))
    subprocess.run('ls ' + arg, shell=True)
";
        assert!(
            !analyze(cmd, Language::Python).iter().any(|f| f.category == "Инъекция команд"),
            "shlex.quote should clear command injection"
        );

        let sql = "def run(request, cur):
    arg = shlex.quote(request.args.get('id'))
    cur.execute('SELECT * FROM t WHERE id = ' + arg)
";
        assert!(
            analyze(sql, Language::Python).iter().any(|f| f.category == "SQL-инъекция"),
            "shlex.quote must not clear SQL taint"
        );
    }

    /// A numeric coercion is the one honest blanket clearance: an integer
    /// cannot carry a payload for any sink, so it clears every category.
    #[test]
    fn numeric_coercion_clears_every_category() {
        let code = "def run(request, cur):
    n = int(request.args.get('n'))
    cur.execute('SELECT * FROM t WHERE id = ' + n)
    subprocess.run('head -n ' + n, shell=True)
";
        assert!(analyze(code, Language::Python).is_empty(), "int() should clear everything");
    }

    /// The scopes name categories as free-form strings; a typo or a renamed
    /// heuristic would silently stop clearing anything. This ties them to the
    /// catalogue so the mismatch fails here instead of in the field.
    #[test]
    fn sanitizer_scopes_name_real_categories() {
        let known: Vec<&str> = rules::HEURISTICS.iter().map(|h| h.category).collect();
        for cat in ALL_CATEGORIES {
            assert!(
                known.contains(cat),
                "category {cat:?} is not produced by any heuristic; scopes would never match"
            );
        }
    }

    /// Go's strconv.Atoi turns input into an int — no injection payload survives.
    #[test]
    fn strconv_atoi_breaks_command_injection() {
        let code = "\
func handler(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get(\"n\"))
	out, _ := exec.Command(\"sh\", \"-c\", fmt.Sprintf(\"head -n %d f\", n)).Output()
	w.Write(out)
}
";
        assert!(analyze(code, Language::Go).is_empty(), "strconv.Atoi should sanitize");
    }

    /// MongoDB's $where runs JavaScript on the DB server — user input in it is
    /// NoSQL injection / server-side code execution, its own category (CWE-943).
    #[test]
    fn traces_nosql_where_injection() {
        let code = "\
function find(req) {
  const term = req.query.term;
  return db.users.find({ $where: 'this.name == \\'' + term + '\\'' });
}
";
        let flows = analyze(code, Language::JavaScript);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].category, "NoSQL-инъекция");
    }

    /// Django's mark_safe() disables auto-escaping — feeding request data
    /// through it is XSS, and the taint engine must treat it as a sink, not
    /// mistake "safe" in the name for a sanitizer.
    #[test]
    fn traces_xss_through_mark_safe() {
        let code = "\
def view(request):
    name = request.GET.get('name')
    return mark_safe('<b>' + name + '</b>')
";
        let flows = analyze(code, Language::Python);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].category, "XSS");
    }

    /// Flask/Jinja markupsafe.Markup() is the same trap on the Flask side.
    #[test]
    fn traces_xss_through_markup() {
        let code = "\
def view(request):
    bio = request.form['bio']
    html = Markup('<p>%s</p>' % bio)
    return html
";
        let flows = analyze(code, Language::Python);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].category, "XSS");
    }

    #[test]
    fn escaped_value_is_not_xss() {
        let code = "\
function show(req) {
  const name = req.query.name;
  const safe = escape(name);
  el.innerHTML = safe;
}
";
        assert!(analyze(code, Language::JavaScript).is_empty());
    }

    #[test]
    fn traces_secret_to_a_log() {
        let code = "\
def login(user):
    password = user.get_password()
    logger.info('login attempt: ' + password)
";
        let flows = analyze_leaks(code, Language::Python);
        assert_eq!(flows.len(), 1, "one leak flow expected: {flows:?}");
        assert_eq!(flows[0].category, "Утечка чувствительных данных");
        assert_eq!(flows[0].steps.last().unwrap().role, FlowRole::Sink);
    }

    #[test]
    fn redacted_secret_is_not_a_leak() {
        let code = "\
def login(user):
    password = user.get_password()
    safe = mask(password)
    logger.info(safe)
";
        assert!(analyze_leaks(code, Language::Python).is_empty());
    }

    #[test]
    fn non_secret_variable_is_not_a_leak() {
        let code = "\
def show(user):
    name = user.name
    console.log(name)
";
        assert!(analyze_leaks(code, Language::Python).is_empty());
    }

    #[test]
    fn secret_hashed_before_logging_is_safe() {
        // Reading into a secret-named var, but logging its hash — not the value.
        let code = "\
token = get_token()
log.debug('token digest ' + sha256(token))
";
        assert!(analyze_leaks(code, Language::Python).is_empty());
    }

    #[test]
    fn classifies_the_entry_point() {
        assert_eq!(classify_entry("cmd = request.args.get('c')"), "HTTP-запрос");
        assert_eq!(classify_entry("name = sys.argv[1]"), "аргумент командной строки");
        assert_eq!(classify_entry("token = os.environ.get('T')"), "переменная окружения");
        assert_eq!(classify_entry("line = input()"), "стандартный ввод");
        assert_eq!(classify_entry("x = something_unknown()"), "пользовательский ввод");
        // Framework- and platform-specific sources get the right label too.
        assert_eq!(classify_entry("name := r.URL.Query().Get(\"n\")"), "HTTP-запрос");
        assert_eq!(classify_entry("$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];"), "HTTP-запрос");
        assert_eq!(classify_entry("const q = new URLSearchParams(location.search)"), "адрес страницы (DOM)");
        assert_eq!(classify_entry("var frag = location.hash.slice(1)"), "адрес страницы (DOM)");
    }

    /// Go's net/http accessors are sources and exec.Command is a sink — the
    /// bread-and-butter Go command injection must trace end to end.
    #[test]
    fn traces_go_query_to_exec_command() {
        let code = "\
func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get(\"name\")
	out, _ := exec.Command(\"sh\", \"-c\", \"ping \"+name).Output()
	w.Write(out)
}
";
        let flows = analyze(code, Language::Go);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].category, "Инъекция команд");
        assert_eq!(flows[0].entry_kind(), "HTTP-запрос");
    }

    /// DOM XSS: the classic location.search → innerHTML flow, entirely in the
    /// browser. The entry label must say the URL is the attacker's handle.
    #[test]
    fn traces_dom_xss_from_location_search() {
        let code = "\
function render() {
  const q = new URLSearchParams(location.search).get('q');
  document.getElementById('out').innerHTML = q;
}
";
        let flows = analyze(code, Language::JavaScript);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].category, "XSS");
        assert_eq!(flows[0].entry_kind(), "адрес страницы (DOM)");
    }

    /// Only the attacker-shaped subset of $_SERVER is a source: HTTP_* headers
    /// yes, server-controlled keys like DOCUMENT_ROOT no.
    #[test]
    fn php_server_headers_are_sources_but_document_root_is_not() {
        let hot = "\
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
system(\"logger \" . $ip);
";
        let flows = analyze(hot, Language::Php);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].category, "Инъекция команд");

        let cold = "\
$root = $_SERVER['DOCUMENT_ROOT'];
system(\"du -s \" . $root);
";
        assert!(analyze(cold, Language::Php).is_empty(), "DOCUMENT_ROOT is not attacker input");
    }

    /// cgi.FieldStorage() is the source even though the variable is just `form`.
    #[test]
    fn traces_python_fieldstorage_to_command() {
        let code = "\
form = cgi.FieldStorage()
name = form.getvalue('name')
os.system('ping ' + name)
";
        let flows = analyze(code, Language::Python);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].category, "Инъекция команд");
    }

    #[test]
    fn flow_reports_its_entry_kind() {
        let code = "\
def run(request):
    cmd = request.args.get('cmd')
    os.system(cmd)
";
        let flows = analyze(code, Language::Python);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].entry_kind(), "HTTP-запрос");
    }

    #[test]
    fn traces_across_a_file_boundary() {
        // The sink lives in another file's helper. Exporting that file's summary
        // and feeding it as an external lets the caller's flow cross the boundary.
        let helper = "\
def execute(value):
    os.system(value)
";
        let exports: std::collections::HashMap<String, Summary> =
            collect_exports(helper, Language::Python, "helpers.py").into_iter().collect();
        assert!(exports.contains_key("execute"), "helper should export a sinking summary");

        let caller = "\
def run(request):
    cmd = request.args.get('cmd')
    execute(cmd)
";
        let flows = analyze_with(caller, Language::Python, &exports);
        assert_eq!(flows.len(), 1, "one cross-file flow expected: {flows:?}");
        let f = &flows[0];
        assert_eq!(f.category, "Инъекция команд");
        let sink = f.steps.last().unwrap();
        assert_eq!(sink.role, FlowRole::Sink);
        assert_eq!(sink.file.as_deref(), Some("helpers.py"), "sink step must carry the callee file");
        assert!(f.steps.iter().any(|s| s.role == FlowRole::Call));
    }

    #[test]
    fn no_cross_file_flow_without_the_export() {
        // Same caller, but with no external summary: the unknown call is opaque,
        // so nothing is reported. Cross-file needs the pre-pass to have run.
        let caller = "\
def run(request):
    cmd = request.args.get('cmd')
    execute(cmd)
";
        assert!(analyze(caller, Language::Python).is_empty());
    }

    #[test]
    fn traces_open_redirect() {
        let code = "\
def go(request):
    target = request.args.get('next')
    return redirect(target)
";
        let flows = analyze(code, Language::Python);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].category, "Открытый редирект");
    }

    #[test]
    fn traces_through_a_helper_in_js() {
        let code = "\
function run(req) {
  const name = req.query.name;
  sink(name);
}
function sink(v) {
  db.query(v);
}
";
        let flows = analyze(code, Language::JavaScript);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].category, "SQL-инъекция");
        assert!(flows[0].steps.iter().any(|s| s.role == FlowRole::Call));
    }
}
