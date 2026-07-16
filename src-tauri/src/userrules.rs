use crate::model::{Confidence, Language, Severity};
use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A rule written by the user.
///
/// Deliberately mirrors the built-in `Rule` shape so both go through the same
/// matcher: a custom rule that behaves differently from a built-in one would be
/// a trap. Stored as JSON in the config dir so it can be version-controlled and
/// shared between machines.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserRule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub recommendation: String,
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    #[serde(default = "default_category")]
    pub category: String,
    /// Language ids; empty means "every text file".
    #[serde(default)]
    pub languages: Vec<String>,
    pub pattern: String,
    #[serde(default)]
    pub unless_contains: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub owasp: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub skip_in_tests: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_confidence() -> Confidence {
    Confidence::Medium
}

fn default_category() -> String {
    "Своё правило".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UserRuleFile {
    #[serde(default)]
    pub rules: Vec<UserRule>,
}

/// Where user rules live. Kept next to the app config rather than in the cache,
/// because losing them to a cache clear would be a nasty surprise.
pub fn rules_path() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("не удалось определить каталог конфигурации")?
        .join("vulnscope");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("rules.json"))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationIssue {
    pub field: String,
    pub message: String,
}

/// Checks a rule the user is editing. Returns every problem at once rather than
/// the first: fixing errors one reload at a time is miserable.
pub fn validate(rule: &UserRule, existing_ids: &[String]) -> Vec<ValidationIssue> {
    let mut out = Vec::new();

    let id = rule.id.trim();
    if id.is_empty() {
        out.push(ValidationIssue {
            field: "id".into(),
            message: "Идентификатор обязателен".into(),
        });
    } else if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        out.push(ValidationIssue {
            field: "id".into(),
            message: "Только латиница, цифры, дефис и подчёркивание".into(),
        });
    } else if id.starts_with("VS-") {
        // The VS- prefix marks built-ins; letting a user shadow one would make
        // findings impossible to trace back to their source.
        out.push(ValidationIssue {
            field: "id".into(),
            message: "Префикс VS- занят встроенными правилами. Возьмите свой, например MY-001".into(),
        });
    } else if existing_ids.iter().any(|e| e == id) {
        out.push(ValidationIssue {
            field: "id".into(),
            message: "Правило с таким идентификатором уже есть".into(),
        });
    }

    if rule.title.trim().is_empty() {
        out.push(ValidationIssue {
            field: "title".into(),
            message: "Название обязательно".into(),
        });
    }

    if rule.pattern.trim().is_empty() {
        out.push(ValidationIssue {
            field: "pattern".into(),
            message: "Регулярное выражение обязательно".into(),
        });
    } else if let Err(e) = Regex::new(&rule.pattern) {
        // The regex crate's errors are multi-line and precise; pass them
        // through rather than replacing them with something vaguer.
        out.push(ValidationIssue {
            field: "pattern".into(),
            message: format!("Некорректное выражение: {e}"),
        });
    } else if rule.pattern.trim() == ".*" || rule.pattern.trim() == ".+" {
        out.push(ValidationIssue {
            field: "pattern".into(),
            message: "Такое выражение совпадёт с каждой строкой — правило будет бесполезным".into(),
        });
    }

    for lang in &rule.languages {
        if Language::from_id(lang).is_none() {
            out.push(ValidationIssue {
                field: "languages".into(),
                message: format!("Неизвестный язык: {lang}"),
            });
        }
    }

    out
}

/// Result of trying a rule against a sample, for the editor's live preview.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleTestResult {
    pub ok: bool,
    pub error: Option<String>,
    pub matches: Vec<TestMatch>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestMatch {
    pub line: u32,
    pub text: String,
    pub matched: String,
    /// True when `unless_contains` suppressed an otherwise-matching line. Shown
    /// so the user can see *why* their sample did not fire.
    pub suppressed: bool,
}

pub fn test_pattern(rule: &UserRule, sample: &str) -> RuleTestResult {
    let re = match Regex::new(&rule.pattern) {
        Ok(r) => r,
        Err(e) => {
            return RuleTestResult {
                ok: false,
                error: Some(e.to_string()),
                matches: Vec::new(),
            }
        }
    };

    let mut matches = Vec::new();
    for (i, line) in sample.lines().enumerate() {
        if let Some(m) = re.find(line) {
            let hay = line.to_ascii_lowercase();
            let suppressed = rule
                .unless_contains
                .iter()
                .any(|n| !n.is_empty() && hay.contains(&n.to_ascii_lowercase()));
            matches.push(TestMatch {
                line: (i + 1) as u32,
                text: line.to_string(),
                matched: m.as_str().to_string(),
                suppressed,
            });
        }
    }

    RuleTestResult {
        ok: true,
        error: None,
        matches,
    }
}

pub fn load() -> Result<Vec<UserRule>> {
    let path = rules_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("не удалось прочитать {}", path.display()))?;
    let file: UserRuleFile =
        serde_json::from_str(&raw).context("файл правил повреждён или имеет неверный формат")?;
    Ok(file.rules)
}

pub fn save(rules: &[UserRule]) -> Result<()> {
    let path = rules_path()?;
    let file = UserRuleFile {
        rules: rules.to_vec(),
    };
    let json = serde_json::to_string_pretty(&file)?;
    std::fs::write(&path, json).with_context(|| format!("не удалось записать {}", path.display()))?;
    Ok(())
}

/// A user rule with its pattern compiled once, ready for the scan.
pub struct CompiledUserRule {
    pub rule: UserRule,
    pub regex: Regex,
    pub languages: Vec<Language>,
}

/// Compiles the enabled rules, dropping any that fail.
///
/// A broken rule must not abort the scan: the user edited a file by hand, and
/// the honest outcome is "these N rules were skipped, here is why" rather than
/// an error screen with no findings at all.
pub fn compile(rules: &[UserRule]) -> (Vec<CompiledUserRule>, Vec<String>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();

    for rule in rules.iter().filter(|r| r.enabled) {
        match Regex::new(&rule.pattern) {
            Ok(regex) => {
                let languages: Vec<Language> =
                    rule.languages.iter().filter_map(|l| Language::from_id(l)).collect();
                out.push(CompiledUserRule {
                    rule: rule.clone(),
                    regex,
                    languages,
                });
            }
            Err(e) => warnings.push(format!(
                "Своё правило {} пропущено: некорректное выражение ({})",
                rule.id,
                e.to_string().lines().next().unwrap_or("ошибка разбора")
            )),
        }
    }

    (out, warnings)
}

impl CompiledUserRule {
    /// Empty `languages` means the rule applies everywhere.
    pub fn applies_to(&self, lang: Language) -> bool {
        self.languages.is_empty() || self.languages.contains(&lang)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, pattern: &str) -> UserRule {
        UserRule {
            id: id.into(),
            title: "Тест".into(),
            description: String::new(),
            recommendation: String::new(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            category: "Своё".into(),
            languages: vec![],
            pattern: pattern.into(),
            unless_contains: vec![],
            cwe: vec![],
            owasp: None,
            references: vec![],
            skip_in_tests: false,
            enabled: true,
        }
    }

    #[test]
    fn accepts_a_well_formed_rule() {
        assert!(validate(&rule("MY-001", r"eval\("), &[]).is_empty());
    }

    #[test]
    fn rejects_a_broken_regex_and_says_why() {
        let issues = validate(&rule("MY-001", r"(unclosed"), &[]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].field, "pattern");
        assert!(issues[0].message.contains("Некорректное выражение"));
    }

    #[test]
    fn rejects_shadowing_a_builtin_id() {
        let issues = validate(&rule("VS-PY-001", r"x"), &[]);
        assert!(issues.iter().any(|i| i.field == "id" && i.message.contains("VS-")));
    }

    #[test]
    fn rejects_duplicate_id() {
        let issues = validate(&rule("MY-001", r"x"), &["MY-001".to_string()]);
        assert!(issues.iter().any(|i| i.field == "id"));
    }

    #[test]
    fn rejects_a_catch_all_pattern() {
        let issues = validate(&rule("MY-001", ".*"), &[]);
        assert!(issues.iter().any(|i| i.message.contains("каждой строкой")));
    }

    #[test]
    fn rejects_unknown_language() {
        let mut r = rule("MY-001", "x");
        r.languages = vec!["python".into(), "cobol".into()];
        let issues = validate(&r, &[]);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("cobol"));
    }

    #[test]
    fn reports_every_problem_at_once() {
        let mut r = rule("", "(bad");
        r.title = String::new();
        let issues = validate(&r, &[]);
        // id + title + pattern — fixing them one reload at a time is miserable.
        assert_eq!(issues.len(), 3);
    }

    #[test]
    fn test_pattern_reports_line_and_match() {
        let r = rule("MY-001", r"eval\s*\(");
        let out = test_pattern(&r, "safe()\neval( x )\nother\n");
        assert!(out.ok);
        assert_eq!(out.matches.len(), 1);
        assert_eq!(out.matches[0].line, 2);
        assert_eq!(out.matches[0].matched, "eval(");
        assert!(!out.matches[0].suppressed);
    }

    #[test]
    fn test_pattern_shows_suppression_rather_than_hiding_it() {
        let mut r = rule("MY-001", r"eval\s*\(");
        r.unless_contains = vec!["// ok".into()];
        let out = test_pattern(&r, "eval( x ) // ok\n");
        // The line must still be listed, flagged as suppressed, so the user can
        // see why their sample produced nothing.
        assert_eq!(out.matches.len(), 1);
        assert!(out.matches[0].suppressed);
    }

    #[test]
    fn test_pattern_surfaces_regex_errors() {
        let out = test_pattern(&rule("MY-001", "(bad"), "x");
        assert!(!out.ok);
        assert!(out.error.is_some());
    }

    #[test]
    fn compile_skips_broken_rules_without_dropping_good_ones() {
        let rules = vec![rule("MY-001", r"eval\("), rule("MY-002", "(bad")];
        let (compiled, warnings) = compile(&rules);
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].rule.id, "MY-001");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("MY-002"));
    }

    #[test]
    fn compile_skips_disabled_rules() {
        let mut r = rule("MY-001", "x");
        r.enabled = false;
        assert!(compile(&[r]).0.is_empty());
    }

    #[test]
    fn rule_without_languages_applies_everywhere() {
        let (compiled, _) = compile(&[rule("MY-001", "x")]);
        assert!(compiled[0].applies_to(Language::Rust));
        assert!(compiled[0].applies_to(Language::Yaml));
    }

    #[test]
    fn rule_with_languages_is_limited_to_them() {
        let mut r = rule("MY-001", "x");
        r.languages = vec!["python".into()];
        let (compiled, _) = compile(&[r]);
        assert!(compiled[0].applies_to(Language::Python));
        assert!(!compiled[0].applies_to(Language::Rust));
    }

    #[test]
    fn round_trips_through_json() {
        let rules = vec![rule("MY-001", r"eval\(")];
        let json = serde_json::to_string(&UserRuleFile {
            rules: rules.clone(),
        })
        .unwrap();
        let back: UserRuleFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rules.len(), 1);
        assert_eq!(back.rules[0].id, "MY-001");
        assert_eq!(back.rules[0].pattern, r"eval\(");
    }

    #[test]
    fn minimal_json_fills_in_defaults() {
        // Hand-written rule files should not need every field.
        let json = r#"{"rules":[{"id":"MY-1","title":"t","severity":"high","pattern":"x"}]}"#;
        let file: UserRuleFile = serde_json::from_str(json).unwrap();
        let r = &file.rules[0];
        assert!(r.enabled);
        assert_eq!(r.confidence, Confidence::Medium);
        assert_eq!(r.category, "Своё правило");
    }
}
