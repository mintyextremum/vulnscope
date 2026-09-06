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

/// How far a source and its sink may sit apart. Most functions are well under
/// this; the cap stops a long file from chaining unrelated code across scopes.
const WINDOW: u32 = 80;
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
            r"htmlspecialchars|htmlentities|bleach\.clean|strip_tags|escape_?html|html[._]?escape|cgi\.escape|sanitize_?html|dompurify\.sanitize",
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
            r"filepath\.clean|secure_filename|os\.path\.basename|\bbasename\s*\(|werkzeug\.utils\.secure_filename",
            Scope::Only(&[CAT_PATH]),
        ),
        // URL-component encoding keeps a value inside one URL field, which is
        // what an open redirect abuses. It does not stop SSRF: a fully encoded
        // attacker host is still that host.
        (r"encodeuricomponent|urlencode|url_encode|quote_plus", Scope::Only(&[CAT_REDIRECT, CAT_XSS])),
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
static ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^\s*(?:(?:let|const|var|val|my|final|auto|public|private|protected|static|String|int|long|short|float|double|bool|boolean|char|def|func|fn|dim|set)\s+)*(\$?[A-Za-z_][\w]*)\s*(?::?=|:=|<-)\s*([^=].*)$",
    )
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

/// Only these languages get function-scoping and interprocedural tracing: their
/// signatures are keyword-led (`def`/`function`/`func`) or an arrow assignment,
/// so a definition can never be mistaken for a call. Everything else keeps the
/// original whole-file behaviour — a smaller claim, but never a false one.
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
    )
}

/// Signature matchers, tried per line. Each captures (name, params). Kept
/// keyword-anchored so a call like `run(x)` is never read as a definition.
static SIGNATURES: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        // Python / any `def name(...)`.
        r"^\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)",
        // JS / TS / PHP `function name(...)`.
        r"^\s*(?:export\s+)?(?:public\s+|private\s+|protected\s+|static\s+)*(?:async\s+)?function\s*\*?\s*(\w+)\s*\(([^)]*)\)",
        // Go `func name(...)`, optional receiver.
        r"^\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(([^)]*)\)",
        // JS / TS arrow assigned to a name.
        r"^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("bad signature pattern"))
    .collect()
});

/// A call `name(args)` anywhere in a line: the callee name and the raw argument
/// list. Used to resolve a call against the file's own functions.
static CALL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\w+)\s*\(([^)]*)\)").expect("bad call pattern"));

/// `(name, params)` if this line begins a function definition, else `None`.
fn signature_of(text: &str) -> Option<(String, String)> {
    for re in SIGNATURES.iter() {
        if let Some(c) = re.captures(text) {
            return Some((c[1].to_string(), c.get(2).map_or("", |m| m.as_str()).to_string()));
        }
    }
    None
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The body line range of the function whose signature is at `sig`. Python is
/// delimited by indentation; the brace languages by balancing `{}` from the
/// signature. Brace counting ignores strings and comments — a heuristic that at
/// worst clips the body, never invents a flow.
fn body_range(lines: &[&str], sig: usize, lang: Language) -> std::ops::Range<usize> {
    let n = lines.len();
    if lang == Language::Python {
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
    // Brace languages: run to the line that closes the opening brace.
    let mut depth: i32 = 0;
    let mut opened = false;
    let mut j = sig;
    while j < n {
        for ch in lines[j].chars() {
            if ch == '{' {
                depth += 1;
                opened = true;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        if opened && depth <= 0 {
            return (sig + 1)..(j + 1);
        }
        j += 1;
    }
    (sig + 1)..n
}

/// Extracts each parameter's variable name from a raw parameter list, tolerant
/// of type annotations on either side and of PHP's `$`. A mis-parse yields a
/// name that never matches a use in the body, so it silently produces no flow
/// rather than a wrong one.
fn param_names(params: &str, lang: Language) -> Vec<String> {
    split_top_commas(params)
        .into_iter()
        .filter_map(|p| {
            let p = p.split('=').next().unwrap_or("").trim();
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
            // `name: Type` (TS): the name is before the colon.
            if let Some(colon) = p.find(':') {
                return first_ident(&p[..colon]);
            }
            // Across the scoped languages the variable name comes first: Go is
            // `name type`, and JS/Python parameters are a bare identifier. (The
            // C-family `type name` order is not among the scoped languages.)
            first_ident(p)
        })
        .collect()
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
    for ch in s.chars() {
        match ch {
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
        if let Some((name, params)) = signature_of(line) {
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
    let trimmed = text.trim();
    let code: String = trimmed.chars().take(200).collect();

    // 1) A tainted value reaching a sink on this line — the map is read before
    //    the assignment below, so `x = sink(x)` uses the old `x`.
    let mut sunk = false;

    // 1a) Direct sink: a dangerous call on this very line.
    for s in sinks {
        if !s.re.is_match(text) {
            continue;
        }
        // Only values still dangerous *for this sink's category* count. A value
        // that passed an HTML escaper is skipped at an XSS sink and still
        // reported at a SQL one — the whole point of scoping sanitisers.
        let best = earliest_referenced_for(tainted, text, line, s.category);
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
    //    call, or clear the taint.
    if let Some(caps) = ASSIGN_RE.captures(text) {
        let lhs = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if lhs.is_empty() {
            return;
        }
        if let Some(cats) = sanitized_categories(rhs) {
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
                .filter(|(name, _)| contains_word(rhs, name))
                .map(|(_, v)| v.clone())
                .min_by_key(|v| v.source_line())
                .map(|mut v| {
                    v.steps.push(FlowStep {
                        line,
                        code: code.clone(),
                        role: FlowRole::Propagation,
                        file: None,
                    });
                    v
                })
                .or_else(|| {
                    SOURCE_RE.is_match(rhs).then(|| TaintVar {
                        steps: vec![FlowStep {
                            line,
                            code: code.clone(),
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
        } else if SOURCE_RE.is_match(rhs) {
            tainted.insert(
                lhs,
                TaintVar {
                    steps: vec![FlowStep { line, code, role: FlowRole::Source, file: None }],
                    origin_param: None,
                    cleared: BTreeSet::new(),
                },
            );
        } else if let Some(effect) =
            resolve_call(rhs, line, &code, tainted, funcs_by_name, summaries, externals)
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
            .filter(|(name, _)| contains_word(rhs, name))
            .map(|(_, v)| v.clone())
            .min_by_key(|v| v.source_line())
        {
            v.steps.push(FlowStep { line, code, role: FlowRole::Propagation, file: None });
            tainted.insert(lhs, v);
        } else {
            tainted.remove(&lhs);
        }
        return;
    }

    // 3) `return <expr>` carrying a tainted value — only the summary pass cares.
    //    A value wrapped in a sanitiser on the way out is no longer dangerous
    //    *for what that sanitiser covers*. A function returning
    //    `htmlspecialchars($x)` is an HTML escaper, not a general-purpose one,
    //    so it keeps returning taint for SQL and the rest.
    if let Some(rest) = return_expr(trimmed) {
        match sanitized_categories(rest) {
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
    let mut best: Option<&TaintVar> = None;
    for (name, v) in tainted {
        if contains_word(text, name)
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
    let lines: Vec<&str> = content.lines().map(|l| l.trim_end_matches('\r')).collect();
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
    // Cheap gate: no source indicator anywhere → nothing to trace.
    if !rules::content_has_taint(content) {
        return Vec::new();
    }

    let sinks: Vec<&CompiledSink> = SINKS.iter().filter(|s| s.langs.contains(&lang)).collect();
    if sinks.is_empty() {
        return Vec::new();
    }

    let lines: Vec<&str> = content.lines().map(|l| l.trim_end_matches('\r')).collect();

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

    for (idx, &text) in lines.iter().enumerate() {
        if flows.len() >= MAX_FLOWS {
            break;
        }
        let trimmed = text.trim();
        if trimmed.is_empty() || rules::is_comment_line(text, lang) {
            continue;
        }
        if scoped(lang) && signature_of(text).is_some() {
            tainted.clear();
            continue;
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
    let lines: Vec<&str> = content.lines().map(|l| l.trim_end_matches('\r')).collect();
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
        if scoped(lang) && signature_of(text).is_some() {
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

    #[test]
    fn out_of_window_flow_is_dropped() {
        let mut code = String::from("cmd = request.args.get('q')\n");
        for _ in 0..90 {
            code.push_str("noop = 1\n");
        }
        code.push_str("os.system(cmd)\n");
        assert!(analyze(&code, Language::Python).is_empty());
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
