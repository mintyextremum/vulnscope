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
use std::collections::HashMap;

/// How far a source and its sink may sit apart. Most functions are well under
/// this; the cap stops a long file from chaining unrelated code across scopes.
const WINDOW: u32 = 80;
/// Cap findings per file so a pathological file cannot flood the report.
const MAX_FLOWS: usize = 20;

#[derive(Debug, Clone, PartialEq)]
pub enum FlowRole {
    /// Where user-controlled data enters.
    Source,
    /// A variable assignment that carries the taint forward.
    Propagation,
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
}

impl TaintVar {
    fn source_line(&self) -> u32 {
        self.steps.first().map(|s| s.line).unwrap_or(0)
    }
}

/// Traces user-controlled data through `content` and returns every source→sink
/// flow found. Deterministic: the same input always yields the same flows.
pub fn analyze(content: &str, lang: Language) -> Vec<TaintFlow> {
    // Cheap gate: no source indicator anywhere → nothing to trace.
    if !rules::content_has_taint(content) {
        return Vec::new();
    }

    let sinks: Vec<&CompiledSink> = SINKS.iter().filter(|s| s.langs.contains(&lang)).collect();
    if sinks.is_empty() {
        return Vec::new();
    }

    let mut tainted: HashMap<String, TaintVar> = HashMap::new();
    let mut flows: Vec<TaintFlow> = Vec::new();

    for (idx, raw) in content.lines().enumerate() {
        if flows.len() >= MAX_FLOWS {
            break;
        }
        let line = (idx + 1) as u32;
        let text = raw.trim_end_matches('\r');
        let trimmed = text.trim();
        if trimmed.is_empty() || rules::is_comment_line(text, lang) {
            continue;
        }

        // 1) Does a tracked tainted variable reach a dangerous sink on this line?
        for s in &sinks {
            if !s.re.is_match(text) {
                continue;
            }
            // The earliest-sourced tainted variable referenced here, within the
            // window, gives the clearest chain. The name lives in the map key.
            let mut best: Option<&TaintVar> = None;
            for (name, v) in &tainted {
                if contains_word(text, name)
                    && line.saturating_sub(v.source_line()) <= WINDOW
                    && best.map(|b| v.source_line() < b.source_line()).unwrap_or(true)
                {
                    best = Some(v);
                }
            }
            if let Some(v) = best {
                let mut steps = v.steps.clone();
                steps.push(FlowStep {
                    line,
                    code: trimmed.chars().take(200).collect(),
                    role: FlowRole::Sink,
                });
                flows.push(TaintFlow {
                    category: s.category,
                    cwe: s.cwe,
                    severity: s.severity,
                    steps,
                });
                break; // one flow per sink line is enough signal
            }
        }

        // 2) Assignment: introduce, propagate, or clear taint.
        if let Some(caps) = ASSIGN_RE.captures(text) {
            let lhs = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if lhs.is_empty() {
                continue;
            }

            if SANITIZER_RE.is_match(rhs) {
                // Reassigned from a sanitised value: no longer dangerous.
                tainted.remove(&lhs);
            } else if SOURCE_RE.is_match(rhs) {
                tainted.insert(
                    lhs,
                    TaintVar {
                        steps: vec![FlowStep {
                            line,
                            code: trimmed.chars().take(200).collect(),
                            role: FlowRole::Source,
                        }],
                    },
                );
            } else {
                // Propagation: does the rhs reference an already-tainted var?
                let carried = tainted
                    .iter()
                    .filter(|(name, _)| contains_word(rhs, name))
                    .map(|(_, v)| v.clone())
                    .min_by_key(|v| v.source_line());
                match carried {
                    Some(mut v) => {
                        v.steps.push(FlowStep {
                            line,
                            code: trimmed.chars().take(200).collect(),
                            role: FlowRole::Propagation,
                        });
                        tainted.insert(lhs, v);
                    }
                    None => {
                        // Reassigned to clean data: drop any prior taint.
                        tainted.remove(&lhs);
                    }
                }
            }
        }
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
}
