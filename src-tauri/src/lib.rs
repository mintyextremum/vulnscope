mod baseline;
mod blame;
mod deps;
mod external;
mod git;
mod model;
mod osv;
mod pkgmgr;
mod rules;
mod scanner;
mod secrets;
mod settings;
mod taint;
mod userrules;
mod walk;

use model::ScanReport;
use scanner::{ScanOptions, ScanState, ToolsInfo};
use std::sync::atomic::Ordering;
use tauri::{AppHandle, State};

/// Reports which optional external scanners are installed, so the UI can offer
/// them rather than failing at scan time.
#[tauri::command]
/// `force` re-probes instead of using the cached answer — that is what the
/// "Проверить снова" button is for, e.g. after installing something by hand.
async fn get_tools(force: Option<bool>) -> ToolsInfo {
    if force.unwrap_or(false) {
        external::invalidate_tool_cache();
    }
    scanner::tools_info().await
}

/// The built-in rule catalogue, for the "Rules" screen.
#[tauri::command]
fn get_rules() -> Vec<serde_json::Value> {
    rules::RULES
        .iter()
        .map(|r| {
            let extra = rules::extra_for(r.id);
            serde_json::json!({
                "id": r.id,
                "title": r.title,
                "description": r.description,
                "recommendation": r.recommendation,
                "severity": r.severity,
                "confidence": r.confidence,
                "category": r.category,
                "languages": r.languages.iter().map(|l| l.label()).collect::<Vec<_>>(),
                "cwe": r.cwe,
                "owasp": r.owasp,
                "references": r.references,
                "exploit": extra.map(|e| e.exploit),
                "impact": extra.map(|e| e.impact).unwrap_or(&[]),
                "fixCode": extra.map(|e| e.fix_code),
            })
        })
        .chain(secrets::SECRET_RULES.iter().map(|r| {
            serde_json::json!({
                "id": r.id,
                "title": r.title,
                "description": r.description,
                "recommendation": r.recommendation,
                "severity": r.severity,
                "confidence": r.confidence,
                "category": "Секрет в коде",
                // Not "Все": that string is also the reset button in the
                // language filter, and the two would collide.
                "languages": ["Любой файл"],
                "cwe": r.cwe,
                "owasp": "A07:2021 – Identification and Authentication Failures",
                "references": Vec::<&str>::new(),
            })
        }))
        .collect()
}

#[tauri::command]
async fn start_scan(
    app: AppHandle,
    state: State<'_, ScanState>,
    options: ScanOptions,
) -> Result<ScanReport, String> {
    // Clear any cancel left over from a previous run, or this scan would abort
    // immediately.
    let cancel = state.cancel.clone();
    cancel.store(false, Ordering::Relaxed);

    let scan_id = format!("scan-{}", chrono::Utc::now().timestamp_millis());
    let tools = scanner::tools_info().await.tools;

    scanner::run_scan(app.clone(), scan_id.clone(), options, cancel, tools)
        .await
        .map_err(|e| {
            // Tell the UI the run is over, so a failure mid-scan does not leave
            // the progress view spinning on its last event.
            scanner::emit_failed(&app, &scan_id);
            e.to_string()
        })
}

#[tauri::command]
fn cancel_scan(state: State<'_, ScanState>) {
    state.cancel.store(true, Ordering::Relaxed);
}

/// Reads a file from a completed scan for the code viewer. Restricted to the
/// scan root so the UI can never be tricked into reading arbitrary disk paths.
#[tauri::command]
fn read_source(root: String, relative: String) -> Result<String, String> {
    let root = std::path::Path::new(&root)
        .canonicalize()
        .map_err(|e| format!("некорректный корень сканирования: {e}"))?;
    let target = root
        .join(&relative)
        .canonicalize()
        .map_err(|e| format!("файл не найден: {e}"))?;

    if !target.starts_with(&root) {
        return Err("путь вне каталога сканирования".to_string());
    }

    let bytes = std::fs::read(&target).map_err(|e| format!("не удалось прочитать файл: {e}"))?;
    if bytes.len() > 5 * 1024 * 1024 {
        return Err("файл слишком большой для просмотра".to_string());
    }
    String::from_utf8(bytes).map_err(|_| "файл не является текстом UTF-8".to_string())
}

/// Re-checks a single file after the user edits it in the findings catalogue.
///
/// Writes the new content (path-guarded to the scan root, exactly like
/// `read_source`), re-runs the built-in rules, secret and data-flow analysis on
/// it, and returns the findings that remain — so the UI can mark the ones that
/// disappeared as fixed and turn them green. The file must already exist inside
/// the scan root: this edits what was scanned, it never creates new paths.
#[tauri::command]
fn recheck_file(
    root: String,
    relative: String,
    content: String,
    check_secrets: bool,
    experimental: bool,
    dataflow: bool,
) -> Result<Vec<model::Finding>, String> {
    let root = std::path::Path::new(&root)
        .canonicalize()
        .map_err(|e| format!("некорректный корень сканирования: {e}"))?;
    let target = root
        .join(&relative)
        .canonicalize()
        .map_err(|e| format!("файл не найден: {e}"))?;

    if !target.starts_with(&root) {
        return Err("путь вне каталога сканирования".to_string());
    }
    if content.len() > 5 * 1024 * 1024 {
        return Err("файл слишком большой для проверки".to_string());
    }

    std::fs::write(&target, content.as_bytes())
        .map_err(|e| format!("не удалось сохранить файл: {e}"))?;

    let cfg = settings::load();
    Ok(scanner::recheck_file(
        &root,
        &target,
        &relative,
        check_secrets,
        experimental,
        dataflow,
        cfg.max_findings_per_file as usize,
    ))
}

/// Writes the report to a path the user picked in the save dialog.
#[tauri::command]
fn save_report(path: String, json: String) -> Result<(), String> {
    std::fs::write(&path, json).map_err(|e| format!("не удалось сохранить отчёт: {e}"))
}

// ------------------------------------------------------------- user rules

#[tauri::command]
fn get_user_rules() -> Result<Vec<userrules::UserRule>, String> {
    userrules::load().map_err(|e| e.to_string())
}

/// Validates before writing, so a rule that cannot compile never reaches disk
/// and the next scan cannot be broken by the editor.
#[tauri::command]
fn save_user_rule(rule: userrules::UserRule) -> Result<Vec<userrules::ValidationIssue>, String> {
    let mut rules = userrules::load().map_err(|e| e.to_string())?;
    let editing = rules.iter().position(|r| r.id == rule.id);

    let other_ids: Vec<String> = rules
        .iter()
        .enumerate()
        .filter(|(i, _)| Some(*i) != editing)
        .map(|(_, r)| r.id.clone())
        .collect();

    let issues = userrules::validate(&rule, &other_ids);
    if !issues.is_empty() {
        return Ok(issues);
    }

    match editing {
        Some(i) => rules[i] = rule,
        None => rules.push(rule),
    }
    userrules::save(&rules).map_err(|e| e.to_string())?;
    Ok(Vec::new())
}

#[tauri::command]
fn delete_user_rule(id: String) -> Result<(), String> {
    let mut rules = userrules::load().map_err(|e| e.to_string())?;
    rules.retain(|r| r.id != id);
    userrules::save(&rules).map_err(|e| e.to_string())
}

#[tauri::command]
fn set_user_rule_enabled(id: String, enabled: bool) -> Result<(), String> {
    let mut rules = userrules::load().map_err(|e| e.to_string())?;
    if let Some(r) = rules.iter_mut().find(|r| r.id == id) {
        r.enabled = enabled;
    }
    userrules::save(&rules).map_err(|e| e.to_string())
}

/// Runs a rule against a sample without saving it, for the editor's preview.
#[tauri::command]
fn test_user_rule(rule: userrules::UserRule, sample: String) -> userrules::RuleTestResult {
    userrules::test_pattern(&rule, &sample)
}

#[tauri::command]
fn get_user_rules_path() -> Result<String, String> {
    userrules::rules_path()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
}

/// Merges an exported rule set into the current one. Existing ids are replaced,
/// so re-importing an updated set behaves like an update rather than a clash.
#[tauri::command]
fn import_user_rules(json: String) -> Result<usize, String> {
    let file: userrules::UserRuleFile =
        serde_json::from_str(&json).map_err(|e| format!("не удалось разобрать файл: {e}"))?;

    let mut rules = userrules::load().map_err(|e| e.to_string())?;
    let mut added = 0;

    for incoming in file.rules {
        let others: Vec<String> = rules
            .iter()
            .filter(|r| r.id != incoming.id)
            .map(|r| r.id.clone())
            .collect();
        let issues = userrules::validate(&incoming, &others);
        if !issues.is_empty() {
            return Err(format!(
                "Правило {} некорректно: {}",
                incoming.id, issues[0].message
            ));
        }
        match rules.iter().position(|r| r.id == incoming.id) {
            Some(i) => rules[i] = incoming,
            None => rules.push(incoming),
        }
        added += 1;
    }

    userrules::save(&rules).map_err(|e| e.to_string())?;
    Ok(added)
}

// ------------------------------------------------------------ trend history

/// The scan-history series for a target, oldest first — powers the trend chart
/// in the report. Empty until a project has been scanned at least once.
#[tauri::command]
fn get_scan_history(root: String) -> Vec<baseline::HistoryPoint> {
    baseline::load_history(std::path::Path::new(&root))
}

// ------------------------------------------------------------ suppression

#[tauri::command]
fn get_suppressions(root: String) -> Vec<baseline::Suppression> {
    baseline::load_ignores(std::path::Path::new(&root)).0
}

/// Adds a suppression to the project's .vulnscope-ignore.
///
/// A reason is mandatory: a silenced finding with no stated reason is
/// indistinguishable from someone hiding a real problem from review.
#[tauri::command]
fn suppress_finding(
    root: String,
    fingerprint: String,
    rule_id: String,
    file: String,
    whole_file: bool,
    reason: String,
) -> Result<(), String> {
    if reason.trim().is_empty() {
        return Err("Укажите причину — без неё подавление невозможно отличить от сокрытия проблемы".into());
    }

    let dir = std::path::Path::new(&root);
    let (mut items, _) = baseline::load_ignores(dir);

    // Re-suppressing the same thing updates the reason rather than duplicating.
    items.retain(|s| {
        if whole_file {
            !(s.whole_file && s.rule_id == rule_id && s.file == file)
        } else {
            s.fingerprint != fingerprint
        }
    });

    items.push(baseline::Suppression {
        fingerprint: if whole_file { String::new() } else { fingerprint },
        rule_id,
        file,
        whole_file,
        reason: reason.trim().to_string(),
        created_at: chrono::Utc::now().format("%Y-%m-%d").to_string(),
    });

    baseline::save_ignores(dir, &items).map_err(|e| e.to_string())
}

#[tauri::command]
fn unsuppress_finding(root: String, fingerprint: String, rule_id: String, file: String) -> Result<(), String> {
    let dir = std::path::Path::new(&root);
    let (mut items, _) = baseline::load_ignores(dir);
    items.retain(|s| {
        if s.whole_file {
            !(s.rule_id == rule_id && s.file == file)
        } else {
            s.fingerprint != fingerprint
        }
    });
    baseline::save_ignores(dir, &items).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_ignore_path(root: String) -> String {
    baseline::ignore_path(std::path::Path::new(&root))
        .to_string_lossy()
        .to_string()
}

// -------------------------------------------------------------- installing

#[tauri::command]
async fn get_package_managers() -> Vec<pkgmgr::PkgMgrStatus> {
    pkgmgr::detect().await
}

/// Installs a scanner through a package manager.
///
/// The (tool, manager) pair is looked up in our own catalogue and the argv is
/// built from it — the frontend cannot pass an arbitrary package name or
/// command through. That keeps this from becoming "run whatever you're told",
/// which is exactly the weakness this app reports on.
#[tauri::command]
async fn install_tool(tool: external::Tool, manager: String) -> pkgmgr::InstallResult {
    let Some((_, package)) = tool
        .install_options()
        .iter()
        .find(|(m, _)| *m == manager)
    else {
        return pkgmgr::InstallResult {
            ok: false,
            command: String::new(),
            output: format!("{} нельзя установить через {manager}", tool.label()),
        };
    };

    let Some(mgr) = pkgmgr::PkgMgr::ALL.iter().find(|m| m.id() == manager) else {
        return pkgmgr::InstallResult {
            ok: false,
            command: String::new(),
            output: format!("неизвестный пакетный менеджер: {manager}"),
        };
    };

    let argv = mgr.install_argv(package);
    let result = pkgmgr::install(&argv[0], &argv[1..]).await;
    // Whatever the outcome, what is installed may have changed: a cached
    // "не установлен" would survive a successful install and quietly keep the
    // tool out of every scan.
    external::invalidate_tool_cache();
    result
}

// ---------------------------------------------------------------- settings

#[tauri::command]
fn get_settings() -> settings::Settings {
    settings::load()
}

/// Opens a finding in the editor the user configured (`editor_command` in the
/// settings, with `{file}`/`{line}` placeholders). The command comes from the
/// user's own config on their own machine; argv goes to the OS directly, no
/// shell. The executable is resolved through PATHEXT because editor launchers
/// on Windows are `.cmd` shims (`code`, `subl`) that CreateProcess alone
/// cannot start.
#[tauri::command]
fn open_in_editor(path: String, line: u32) -> Result<(), String> {
    let template = settings::load().editor_command;
    if template.trim().is_empty() {
        return Err("Команда редактора не задана — укажите её в настройках".into());
    }
    let argv = settings::editor_argv(&template, &path, line);
    let Some(program) = argv.first() else {
        return Err("Команда редактора пуста".into());
    };
    let resolved = pkgmgr::resolve_program(program)
        .ok_or_else(|| format!("Редактор не найден: {program}"))?;
    std::process::Command::new(resolved)
        .args(&argv[1..])
        .spawn()
        .map_err(|e| format!("Не удалось запустить редактор: {e}"))?;
    Ok(())
}

/// Clamps before writing, so a value typed into the settings screen can never
/// leave the scanner in a state where it silently checks nothing.
#[tauri::command]
fn save_settings(settings: settings::Settings) -> Result<settings::Settings, String> {
    let clean = settings::sanitize(settings);
    settings::save(&clean).map_err(|e| e.to_string())?;
    Ok(clean)
}

#[tauri::command]
fn reset_settings() -> Result<settings::Settings, String> {
    let d = settings::Settings::default();
    settings::save(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

/// The bindable actions, with labels and groups, so the settings screen cannot
/// drift from what the app actually handles.
#[tauri::command]
fn get_keybind_actions() -> Vec<serde_json::Value> {
    settings::action_labels()
        .into_iter()
        .map(|(id, label, group)| serde_json::json!({ "id": id, "label": label, "group": group }))
        .collect()
}

#[tauri::command]
fn check_keybind_conflicts(
    keybinds: std::collections::BTreeMap<String, String>,
) -> Vec<settings::KeybindConflict> {
    settings::find_conflicts(&keybinds)
}

#[tauri::command]
fn get_settings_path() -> Result<String, String> {
    settings::settings_path()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
}

/// The language list the rule editor offers, so it can never drift from what
/// the engine actually recognises.
#[tauri::command]
fn get_languages() -> Vec<serde_json::Value> {
    model::Language::ALL
        .iter()
        .map(|l| serde_json::json!({ "id": l.id(), "label": l.label() }))
        .collect()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanState::default())
        .invoke_handler(tauri::generate_handler![
            get_tools,
            get_rules,
            start_scan,
            cancel_scan,
            read_source,
            recheck_file,
            save_report,
            get_user_rules,
            save_user_rule,
            delete_user_rule,
            set_user_rule_enabled,
            test_user_rule,
            get_user_rules_path,
            import_user_rules,
            get_languages,
            get_package_managers,
            install_tool,
            get_settings,
            save_settings,
            reset_settings,
            open_in_editor,
            get_keybind_actions,
            check_keybind_conflicts,
            get_settings_path,
            get_scan_history,
            get_suppressions,
            suppress_finding,
            unsuppress_finding,
            get_ignore_path
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
