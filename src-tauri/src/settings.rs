use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Everything the user can tune, persisted next to their rules.
///
/// Every field has a `#[serde(default)]` so a config written by an older build
/// still loads: a settings file that fails to parse would silently reset the
/// user's whole setup, which is worse than an unknown key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    // ---- scanning limits ------------------------------------------------
    /// Files above this are skipped. Generated data, not hand-written source.
    pub max_file_size_mb: u32,
    /// Lines longer than this mark a file as minified.
    pub minified_line_len: u32,
    /// Findings kept per file, so one runaway regex cannot flood the report.
    pub max_findings_per_file: u32,

    // ---- defaults for the scan form -------------------------------------
    pub default_respect_gitignore: bool,
    pub default_include_vendor: bool,
    pub default_check_secrets: bool,
    pub default_check_dependencies: bool,

    // ---- OSV ------------------------------------------------------------
    /// Days a cached advisory stays fresh.
    pub osv_cache_days: u32,
    /// Parallel advisory fetches.
    pub osv_concurrency: u32,

    // ---- appearance -----------------------------------------------------
    /// UI language: "ru" | "en". The built-in rule catalogue stays in its
    /// source language regardless; this switches the application shell.
    #[serde(default = "default_language")]
    pub language: String,
    pub accent: String,
    /// Which preset the theme started from, so the editor can show it.
    #[serde(default)]
    pub theme_preset: String,
    /// Design-token overrides: token id (without `--`) → CSS colour. Only the
    /// tokens that differ from the preset are kept, so a token added to the app
    /// later still gets its default here rather than an old frozen value.
    #[serde(default)]
    pub theme: std::collections::BTreeMap<String, String>,
    /// "comfortable" | "compact"
    pub density: String,

    // ---- accessibility --------------------------------------------------
    // Grouped here rather than scattered through "appearance": these are not
    // taste, they are what makes the app usable for someone.
    /// Kept outside the a11y block for compatibility: it shipped first.
    pub reduce_motion: bool,
    /// Interface zoom in percent (WCAG 2.2 §1.4.4 asks for 200% without loss
    /// of content; we allow more than that).
    #[serde(default = "default_ui_scale")]
    pub a11y_ui_scale: u32,
    /// Draw the focus ring for mouse clicks too, not only keyboard traversal.
    #[serde(default)]
    pub a11y_always_focus: bool,
    /// Turn off the drifting background lights.
    #[serde(default)]
    pub a11y_no_ambient: bool,
    /// Spell the severity out next to every count and badge, so severity never
    /// depends on telling colours apart.
    #[serde(default)]
    pub a11y_severity_text: bool,
    /// Underline links, so they are not identified by colour alone (§1.4.1).
    #[serde(default)]
    pub a11y_underline_links: bool,
    /// Enlarge hit areas to at least 24×24 CSS px (§2.5.8).
    #[serde(default)]
    pub a11y_big_targets: bool,
    /// Syntax highlighting is skipped above this many lines.
    pub max_highlight_lines: u32,

    // ---- behaviour ------------------------------------------------------
    /// Suppress noisy rules inside test files.
    pub skip_noisy_in_tests: bool,
    /// Ignore matches on lines that are entirely a comment.
    pub ignore_comments: bool,

    /// Action id -> key combo, e.g. "palette" -> "mod+k".
    pub keybinds: std::collections::BTreeMap<String, String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            max_file_size_mb: 2,
            minified_line_len: 2000,
            max_findings_per_file: 200,
            default_respect_gitignore: true,
            default_include_vendor: false,
            default_check_secrets: true,
            default_check_dependencies: true,
            osv_cache_days: 7,
            osv_concurrency: 16,
            language: default_language(),
            accent: "#5b8def".to_string(),
            theme_preset: "night".to_string(),
            theme: Default::default(),
            density: "comfortable".to_string(),
            reduce_motion: false,
            a11y_ui_scale: default_ui_scale(),
            a11y_always_focus: false,
            a11y_no_ambient: false,
            a11y_severity_text: false,
            a11y_underline_links: false,
            a11y_big_targets: false,
            max_highlight_lines: 6000,
            skip_noisy_in_tests: true,
            ignore_comments: true,
            keybinds: default_keybinds(),
        }
    }
}

fn default_ui_scale() -> u32 {
    100
}

fn default_language() -> String {
    "ru".to_string()
}

/// The shipped bindings. Kept here rather than in the frontend so the settings
/// screen and the actual handlers can never disagree about what exists.
pub fn default_keybinds() -> std::collections::BTreeMap<String, String> {
    [
        ("palette", "mod+k"),
        ("rules", "mod+r"),
        ("myRules", "mod+e"),
        ("settings", "mod+,"),
        ("newScan", "mod+n"),
        ("rescan", "mod+shift+r"),
        ("export", "mod+s"),
        ("tabOverview", "1"),
        ("tabFindings", "2"),
        ("tabCode", "3"),
        ("tabSkipped", "4"),
        ("nextFinding", "j"),
        ("prevFinding", "k"),
        ("openInCode", "enter"),
        ("focusSearch", "/"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// Human-readable label for each bindable action, for the settings screen.
pub fn action_labels() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("palette", "Командная палитра", "Навигация"),
        ("rules", "Каталог правил", "Навигация"),
        ("myRules", "Свои правила", "Навигация"),
        ("settings", "Настройки", "Навигация"),
        ("newScan", "Новое сканирование", "Сканирование"),
        ("rescan", "Пересканировать", "Сканирование"),
        ("export", "Экспорт отчёта", "Сканирование"),
        ("tabOverview", "Вкладка «Обзор»", "Вкладки"),
        ("tabFindings", "Вкладка «Находки»", "Вкладки"),
        ("tabCode", "Вкладка «Код»", "Вкладки"),
        ("tabSkipped", "Вкладка «Пропущено»", "Вкладки"),
        ("nextFinding", "Следующая находка", "Находки"),
        ("prevFinding", "Предыдущая находка", "Находки"),
        ("openInCode", "Открыть находку в коде", "Находки"),
        ("focusSearch", "Поиск по файлам", "Находки"),
    ]
}

pub fn settings_path() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("не удалось определить каталог конфигурации")?
        .join("vulnscope");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("settings.json"))
}

pub fn load() -> Settings {
    // A corrupt or partial file must not block startup: fall back to defaults
    // rather than refusing to run.
    let Ok(path) = settings_path() else {
        return Settings::default();
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Settings::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save(s: &Settings) -> Result<()> {
    let path = settings_path()?;
    let json = serde_json::to_string_pretty(s)?;
    std::fs::write(&path, json).with_context(|| format!("не удалось записать {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeybindConflict {
    pub action: String,
    pub other_action: String,
    pub combo: String,
}

/// Finds bindings assigned to more than one action.
///
/// Two actions on one combo means one of them silently never fires, which is
/// the kind of thing a user blames on the app being broken.
pub fn find_conflicts(binds: &std::collections::BTreeMap<String, String>) -> Vec<KeybindConflict> {
    let mut out = Vec::new();
    let entries: Vec<(&String, &String)> = binds.iter().collect();

    for (i, (action, combo)) in entries.iter().enumerate() {
        if combo.trim().is_empty() {
            continue;
        }
        for (other_action, other_combo) in entries.iter().skip(i + 1) {
            if combo.eq_ignore_ascii_case(other_combo) {
                out.push(KeybindConflict {
                    action: (*action).clone(),
                    other_action: (*other_action).clone(),
                    combo: (*combo).clone(),
                });
            }
        }
    }
    out
}

/// Clamps values that would break the scanner if taken literally.
///
/// The settings screen is a text field away from `maxFileSizeMb = 0`, which
/// would silently skip every file and report a clean project.
pub fn sanitize(mut s: Settings) -> Settings {
    s.max_file_size_mb = s.max_file_size_mb.clamp(1, 64);
    s.minified_line_len = s.minified_line_len.clamp(200, 100_000);
    s.max_findings_per_file = s.max_findings_per_file.clamp(10, 5_000);
    s.osv_cache_days = s.osv_cache_days.clamp(0, 365);
    s.osv_concurrency = s.osv_concurrency.clamp(1, 64);
    s.max_highlight_lines = s.max_highlight_lines.clamp(0, 200_000);
    if !matches!(s.density.as_str(), "comfortable" | "compact") {
        s.density = "comfortable".into();
    }
    // Upper bound well past the 200% WCAG asks for; the lower bound stops a
    // hand-edited file from shrinking the UI into unreadability.
    s.a11y_ui_scale = s.a11y_ui_scale.clamp(80, 250);
    if !matches!(s.language.as_str(), "ru" | "en") {
        s.language = "ru".into();
    }
    if !s.accent.starts_with('#') || s.accent.len() != 7 {
        s.accent = "#5b8def".into();
    }

    // The theme comes from a hand-editable file and travels between machines as
    // an exported file, so nothing here is trusted. Anything that is not a
    // plain colour is dropped rather than handed to the stylesheet: a value
    // like `url(https://…)` would turn a local-only scanner into one that
    // fetches from the network just by loading a shared theme.
    s.theme.retain(|id, value| is_token_id(id) && is_color(value));
    if s.theme.len() > MAX_THEME_TOKENS {
        let keep: Vec<String> = s.theme.keys().take(MAX_THEME_TOKENS).cloned().collect();
        s.theme.retain(|k, _| keep.contains(k));
    }
    if !s.theme_preset.is_empty() && !is_token_id(&s.theme_preset) {
        s.theme_preset = String::new();
    }
    s
}

/// Generous but finite: the app defines ~60 tokens, and a file claiming
/// thousands is either broken or hostile.
const MAX_THEME_TOKENS: usize = 200;

/// Token ids map to CSS custom properties, so keep them to the shape the app
/// actually uses.
fn is_token_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 40
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// True for the colour syntaxes the editor can round-trip: hex and the
/// rgb/hsl functions. Deliberately not a full CSS colour parser — the point is
/// to exclude everything that is not literally a colour.
fn is_color(v: &str) -> bool {
    let s = v.trim();
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    if let Some(hex) = s.strip_prefix('#') {
        return matches!(hex.len(), 3 | 4 | 6 | 8) && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    let lower = s.to_ascii_lowercase();
    let is_fn = ["rgb(", "rgba(", "hsl(", "hsla("]
        .iter()
        .any(|p| lower.starts_with(p));
    if !is_fn || !lower.ends_with(')') {
        return false;
    }
    // Inside the parentheses only numbers and separators may appear; this is
    // what keeps `url(...)`, nested functions and comments out.
    let inner = &lower[lower.find('(').unwrap() + 1..lower.len() - 1];
    !inner.is_empty()
        && inner
            .chars()
            .all(|c| c.is_ascii_digit() || " .,%/-+".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_keeps_real_colours() {
        for v in ["#fff", "#ff5470", "#ff547080", "rgb(1,2,3)", "rgba(255, 84, 112, 0.11)", "hsl(210 40% 50%)"] {
            assert!(is_color(v), "должен приниматься: {v}");
        }
    }

    #[test]
    fn theme_rejects_anything_that_is_not_a_colour() {
        // url() is the one that matters: a shared theme must not be able to
        // make a local-only scanner fetch from the network.
        for v in [
            "url(https://evil.example/x.png)",
            "red; background: url(http://x/y)",
            "var(--a)",
            "rgb(1,2,3) url(x)",
            "#gg0011",
            "expression(alert(1))",
            "image-set('x.png')",
            "",
        ] {
            assert!(!is_color(v), "должен отбрасываться: {v}");
        }
    }

    #[test]
    fn sanitize_drops_hostile_theme_entries_and_keeps_good_ones() {
        let mut s = Settings::default();
        s.theme.insert("a".into(), "#5b8def".into());
        s.theme.insert("s-1".into(), "url(http://evil/x)".into());
        s.theme.insert("Плохой Ключ".into(), "#fff".into());
        let s = sanitize(s);
        assert_eq!(s.theme.get("a").map(String::as_str), Some("#5b8def"));
        assert!(!s.theme.contains_key("s-1"), "url() должен быть выброшен");
        assert!(!s.theme.contains_key("Плохой Ключ"));
    }

    #[test]
    fn ui_scale_is_clamped_to_a_usable_range() {
        let mut s = Settings::default();
        s.a11y_ui_scale = 5; // a hand-edited file could shrink the UI away
        assert_eq!(sanitize(s).a11y_ui_scale, 80);
        let mut s = Settings::default();
        s.a11y_ui_scale = 9999;
        assert_eq!(sanitize(s).a11y_ui_scale, 250);
    }

    #[test]
    fn defaults_are_self_consistent() {
        let s = Settings::default();
        assert_eq!(s, sanitize(s.clone()));
        assert!(find_conflicts(&s.keybinds).is_empty(), "shipped binds collide");
    }

    #[test]
    fn every_default_bind_has_a_label() {
        let labels: Vec<&str> = action_labels().iter().map(|(id, _, _)| *id).collect();
        for id in default_keybinds().keys() {
            assert!(labels.contains(&id.as_str()), "no label for action {id}");
        }
        // And the reverse: a label with no binding is a dead row in the UI.
        for (id, _, _) in action_labels() {
            assert!(default_keybinds().contains_key(id), "no bind for label {id}");
        }
    }

    #[test]
    fn detects_a_duplicate_binding() {
        let mut b = default_keybinds();
        b.insert("rules".into(), "mod+k".into()); // same as palette
        let c = find_conflicts(&b);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].combo, "mod+k");
    }

    #[test]
    fn empty_binding_is_not_a_conflict() {
        let mut b = default_keybinds();
        b.insert("rules".into(), String::new());
        b.insert("myRules".into(), String::new());
        assert!(find_conflicts(&b).is_empty());
    }

    #[test]
    fn sanitize_rejects_a_zero_file_size() {
        // Taken literally this skips every file and reports a clean project.
        let s = Settings {
            max_file_size_mb: 0,
            ..Default::default()
        };
        assert_eq!(sanitize(s).max_file_size_mb, 1);
    }

    #[test]
    fn sanitize_caps_absurd_values() {
        let s = Settings {
            max_file_size_mb: 9999,
            osv_concurrency: 5000,
            max_findings_per_file: 1,
            ..Default::default()
        };
        let out = sanitize(s);
        assert_eq!(out.max_file_size_mb, 64);
        assert_eq!(out.osv_concurrency, 64);
        assert_eq!(out.max_findings_per_file, 10);
    }

    #[test]
    fn sanitize_repairs_bad_appearance_values() {
        let s = Settings {
            density: "enormous".into(),
            accent: "not-a-colour".into(),
            ..Default::default()
        };
        let out = sanitize(s);
        assert_eq!(out.density, "comfortable");
        assert_eq!(out.accent, "#5b8def");
    }

    #[test]
    fn partial_config_from_an_older_build_still_loads() {
        // Only one key set; everything else must fall back to its default.
        let json = r#"{"osvCacheDays": 30}"#;
        let s: Settings = serde_json::from_str(json).unwrap();
        assert_eq!(s.osv_cache_days, 30);
        assert_eq!(s.max_file_size_mb, 2);
        assert!(s.default_check_secrets);
        assert!(!s.keybinds.is_empty());
    }

    #[test]
    fn round_trips_through_json() {
        let mut s = Settings::default();
        s.osv_concurrency = 8;
        s.keybinds.insert("palette".into(), "mod+p".into());
        let back: Settings = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.osv_concurrency, 8);
        assert_eq!(back.keybinds["palette"], "mod+p");
    }
}

// Needed by the defaults test; comparing whole structs beats field-by-field.
impl PartialEq for Settings {
    fn eq(&self, o: &Self) -> bool {
        serde_json::to_string(self).ok() == serde_json::to_string(o).ok()
    }
}
