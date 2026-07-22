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
}

/// Shared user-input source pattern (same one the heuristics use).
static SOURCE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(rules::HEURISTICS[0].taint).expect("bad taint source pattern"));

/// A value that has passed through one of these is no longer trusted-dangerous:
/// escaping, encoding, parameterisation, allowlisting, or a numeric coercion.
static SANITIZER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(?:escape|sanitiz|encode|quote|parameteriz|prepared?statement|bindparam|placeholder|whitelist|allowlist|escapeshellarg|escapeshellcmd|htmlspecialchars|htmlentities|shlex\.quote|escape_filter_chars|filterencode|encodevalue|filepath\.clean|basename|int\s*\(|integer\s*\(|parseint|number\s*\(|to_i\b|::from_str)",
    )
    .expect("bad sanitizer pattern")
});

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
}

impl TaintVar {
    fn source_line(&self) -> u32 {
        self.steps.first().map(|s| s.line).unwrap_or(0)
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
struct SinkHit {
    line: u32,
    code: String,
    category: &'static str,
    cwe: &'static [&'static str],
    severity: Severity,
}

/// What a function does to its parameters, computed once and reused at every
/// call site: which parameters reach a sink, and which flow into its return.
#[derive(Clone, Default, PartialEq)]
struct Summary {
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
fn scoped(lang: Language) -> bool {
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
        let best = earliest_referenced(tainted, text, line);
        if let Some(v) = best {
            on_sink(
                v,
                s.category,
                s.cwe,
                s.severity,
                vec![FlowStep { line, code: code.clone(), role: FlowRole::Sink }],
            );
            sunk = true;
            break;
        }
    }

    // 1b) Interprocedural sink: the tainted value is passed to a function that
    //     sinks that argument. The chain gains a call step and the callee's sink.
    if !sunk {
        if let Some(r) = call_reaches_sink(text, line, &code, tainted, funcs_by_name, summaries) {
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
        if SANITIZER_RE.is_match(rhs) {
            tainted.remove(&lhs);
        } else if SOURCE_RE.is_match(rhs) {
            tainted.insert(
                lhs,
                TaintVar {
                    steps: vec![FlowStep { line, code, role: FlowRole::Source }],
                    origin_param: None,
                },
            );
        } else if let Some(effect) =
            resolve_call(rhs, line, &code, tainted, funcs_by_name, summaries)
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
            v.steps.push(FlowStep { line, code, role: FlowRole::Propagation });
            tainted.insert(lhs, v);
        } else {
            tainted.remove(&lhs);
        }
        return;
    }

    // 3) `return <expr>` carrying a tainted value — only the summary pass cares.
    //    A value wrapped in a sanitiser on the way out is no longer dangerous,
    //    so the function does not count as returning taint.
    if let Some(rest) = return_expr(trimmed) {
        if !SANITIZER_RE.is_match(rest) {
            if let Some(v) = earliest_referenced(tainted, rest, line) {
                on_return(v);
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
    let mut best: Option<&TaintVar> = None;
    for (name, v) in tainted {
        if contains_word(text, name)
            && line.saturating_sub(v.source_line()) <= WINDOW
            && best.map(|b| v.source_line() < b.source_line()).unwrap_or(true)
        {
            best = Some(v);
        }
    }
    best
}

/// If a call on this line hands a tainted argument to a function that sinks that
/// argument, returns the tail steps (call + sink), the sink metadata, and the
/// argument's taint chain.
fn call_reaches_sink<'a>(
    text: &str,
    line: u32,
    code: &str,
    tainted: &'a HashMap<String, TaintVar>,
    funcs_by_name: &HashMap<String, usize>,
    summaries: &[Summary],
) -> Option<Reached<'a>> {
    for c in CALL_RE.captures_iter(text) {
        let name = &c[1];
        let Some(&fi) = funcs_by_name.get(name) else { continue };
        let summary = &summaries[fi];
        if summary.sink_params.is_empty() {
            continue;
        }
        for (i, arg) in split_top_commas(&c[2]).into_iter().enumerate() {
            let Some(hit) = summary.sink_params.get(&i) else { continue };
            if let Some(v) = earliest_referenced(tainted, &arg, line) {
                return Some(Reached {
                    tail: vec![
                        FlowStep { line, code: code.to_string(), role: FlowRole::Call },
                        FlowStep { line: hit.line, code: hit.code.clone(), role: FlowRole::Sink },
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
/// defined in this file. `None` means no such call touches a tainted value, so
/// the caller falls back to plain variable propagation.
fn resolve_call(
    rhs: &str,
    line: u32,
    code: &str,
    tainted: &HashMap<String, TaintVar>,
    funcs_by_name: &HashMap<String, usize>,
    summaries: &[Summary],
) -> Option<CallEffect> {
    let mut consumed = false;
    for c in CALL_RE.captures_iter(rhs) {
        let name = &c[1];
        let Some(&fi) = funcs_by_name.get(name) else { continue };
        let summary = &summaries[fi];
        for (i, arg) in split_top_commas(&c[2]).into_iter().enumerate() {
            let Some(v) = earliest_referenced(tainted, &arg, line) else { continue };
            if summary.return_params.contains(&i) {
                let mut carried = v.clone();
                carried.steps.push(FlowStep { line, code: code.to_string(), role: FlowRole::Call });
                return Some(CallEffect::Returns(carried));
            }
            // A tainted value went into a file-local helper that does not return
            // it: remember, in case nothing else returns it.
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
                }],
                origin_param: Some(i),
            },
        );
    }

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
                });
                out.sink_params.entry(pi).or_insert(SinkHit {
                    line: sink.line,
                    code: sink.code,
                    category,
                    cwe,
                    severity,
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
            &mut tainted,
            &mut on_sink,
            &mut on_return,
        );
    }
    out
}

/// Traces user-controlled data through `content` and returns every source→sink
/// flow found, following calls into the file's own functions. Deterministic:
/// the same input always yields the same flows.
pub fn analyze(content: &str, lang: Language) -> Vec<TaintFlow> {
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
            &mut tainted,
            &mut on_sink,
            &mut on_return,
        );
    }

    flows
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
