use crate::model::{Confidence, Finding, FindingSource, PackageInfo, Severity};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

/// External scanners are optional: we use them when present, and their absence
/// is reported to the user rather than silently lowering coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tool {
    Semgrep,
    Bandit,
    CargoAudit,
    Gitleaks,
    OsvScanner,
    Trivy,
    Checkov,
    Hadolint,
    Ruff,
    Govulncheck,
    Trufflehog,
    NpmAudit,
}

impl Tool {
    pub const ALL: &'static [Tool] = &[
        Tool::Semgrep,
        Tool::Bandit,
        Tool::CargoAudit,
        Tool::Gitleaks,
        Tool::OsvScanner,
        Tool::Trivy,
        Tool::Checkov,
        Tool::Hadolint,
        Tool::Ruff,
        Tool::Govulncheck,
        Tool::Trufflehog,
        Tool::NpmAudit,
    ];

    pub fn binary(self) -> &'static str {
        match self {
            Tool::Semgrep => "semgrep",
            Tool::Bandit => "bandit",
            Tool::CargoAudit => "cargo",
            Tool::Gitleaks => "gitleaks",
            Tool::OsvScanner => "osv-scanner",
            Tool::Trivy => "trivy",
            Tool::Checkov => "checkov",
            Tool::Hadolint => "hadolint",
            Tool::Ruff => "ruff",
            Tool::Govulncheck => "govulncheck",
            Tool::Trufflehog => "trufflehog",
            Tool::NpmAudit => "npm",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tool::Semgrep => "Semgrep",
            Tool::Bandit => "Bandit",
            Tool::CargoAudit => "cargo-audit",
            Tool::Gitleaks => "Gitleaks",
            Tool::OsvScanner => "osv-scanner",
            Tool::Trivy => "Trivy",
            Tool::Checkov => "Checkov",
            Tool::Hadolint => "Hadolint",
            Tool::Ruff => "Ruff",
            Tool::Govulncheck => "govulncheck",
            Tool::Trufflehog => "TruffleHog",
            Tool::NpmAudit => "npm audit",
        }
    }

    /// Install options, best first. Each is (package manager id, package name).
    /// The UI offers only the ones whose manager is actually present.
    pub fn install_options(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Tool::Semgrep => &[("pipx", "semgrep"), ("pip", "semgrep"), ("brew", "semgrep")],
            Tool::Bandit => &[("pipx", "bandit"), ("pip", "bandit"), ("brew", "bandit")],
            Tool::CargoAudit => &[("cargo", "cargo-audit")],
            Tool::Gitleaks => &[
                ("scoop", "gitleaks"),
                ("brew", "gitleaks"),
                ("winget", "Gitleaks.Gitleaks"),
                ("go", "github.com/gitleaks/gitleaks/v8@latest"),
            ],
            Tool::OsvScanner => &[
                ("scoop", "osv-scanner"),
                ("brew", "osv-scanner"),
                ("go", "github.com/google/osv-scanner/cmd/osv-scanner@latest"),
            ],
            Tool::Trivy => &[("scoop", "trivy"), ("brew", "trivy"), ("winget", "AquaSecurity.Trivy")],
            Tool::Checkov => &[("pipx", "checkov"), ("pip", "checkov"), ("brew", "checkov")],
            Tool::Hadolint => &[
                ("scoop", "hadolint"),
                ("brew", "hadolint"),
                ("winget", "hadolint.hadolint"),
            ],
            Tool::Ruff => &[("pipx", "ruff"), ("pip", "ruff"), ("brew", "ruff")],
            Tool::Govulncheck => &[("go", "golang.org/x/vuln/cmd/govulncheck@latest")],
            Tool::Trufflehog => &[
                ("scoop", "trufflehog"),
                ("brew", "trufflehog"),
                ("go", "github.com/trufflesecurity/trufflehog/v3@latest"),
            ],
            // Ships with Node; there is nothing separate to install.
            Tool::NpmAudit => &[],
        }
    }

    /// The command shown when no supported package manager is present.
    pub fn install_hint(self) -> &'static str {
        match self {
            Tool::Semgrep => "pipx install semgrep",
            Tool::Bandit => "pipx install bandit",
            Tool::CargoAudit => "cargo install cargo-audit --locked",
            Tool::Gitleaks => "scoop install gitleaks",
            Tool::OsvScanner => "scoop install osv-scanner",
            Tool::Trivy => "scoop install trivy",
            Tool::Checkov => "pipx install checkov",
            Tool::Hadolint => "scoop install hadolint",
            Tool::Ruff => "pipx install ruff",
            Tool::Govulncheck => "go install golang.org/x/vuln/cmd/govulncheck@latest",
            Tool::Trufflehog => "scoop install trufflehog",
            Tool::NpmAudit => "поставляется вместе с Node.js",
        }
    }

    /// The project's own page. Every install option points at software the user
    /// can inspect before trusting it.
    pub fn docs_url(self) -> &'static str {
        match self {
            Tool::Semgrep => "https://semgrep.dev/docs/getting-started/quickstart",
            Tool::Bandit => "https://bandit.readthedocs.io/en/latest/start.html",
            Tool::CargoAudit => "https://github.com/rustsec/rustsec/tree/main/cargo-audit",
            Tool::Gitleaks => "https://github.com/gitleaks/gitleaks#installing",
            Tool::OsvScanner => "https://google.github.io/osv-scanner/installation/",
            Tool::Trivy => "https://trivy.dev/latest/getting-started/installation/",
            Tool::Checkov => "https://www.checkov.io/1.Welcome/Quick%20Start.html",
            Tool::Hadolint => "https://github.com/hadolint/hadolint#install",
            Tool::Ruff => "https://docs.astral.sh/ruff/installation/",
            Tool::Govulncheck => "https://go.dev/doc/tutorial/govulncheck",
            Tool::Trufflehog => "https://github.com/trufflesecurity/trufflehog#floppy_disk-installation",
            Tool::NpmAudit => "https://docs.npmjs.com/cli/commands/npm-audit",
        }
    }

    /// What this tool adds that the built-in rules do not.
    pub fn adds(self) -> &'static str {
        match self {
            Tool::Semgrep => "Тысячи правил с анализом потока данных для 30+ языков",
            Tool::Bandit => "Углублённый анализ Python по AST, а не по регулярным выражениям",
            Tool::CargoAudit => "Advisory базы RustSec для крейтов из Cargo.lock",
            Tool::Gitleaks => "Более 150 паттернов секретов и проверка истории git",
            Tool::OsvScanner => "Официальный сканер OSV: больше экосистем, чем разбирает наш парсер",
            Tool::Trivy => "Уязвимости в образах, зависимостях и IaC, плюс лицензии",
            Tool::Checkov => "Тысячи проверок Terraform, CloudFormation, Kubernetes и Helm",
            Tool::Hadolint => "Линтер Dockerfile: разбирает синтаксис, а не ищет по шаблону",
            Tool::Ruff => "Быстрый линтер Python, включая правила безопасности из bandit",
            Tool::Govulncheck => "Официальная база уязвимостей Go с проверкой достижимости кода",
            Tool::Trufflehog => "800+ детекторов секретов с проверкой, живой ли ключ",
            Tool::NpmAudit => "Аудит npm-зависимостей встроенными средствами Node",
        }
    }

    /// The language or ecosystem this tool covers, for grouping in the UI.
    pub fn scope(self) -> &'static str {
        match self {
            Tool::Semgrep => "Много языков",
            Tool::Bandit | Tool::Ruff => "Python",
            Tool::CargoAudit => "Rust",
            Tool::Govulncheck => "Go",
            Tool::NpmAudit => "JavaScript",
            Tool::Gitleaks | Tool::Trufflehog => "Секреты",
            Tool::OsvScanner | Tool::Trivy => "Зависимости",
            Tool::Checkov | Tool::Hadolint => "Инфраструктура",
        }
    }

    fn version_args(self) -> &'static [&'static str] {
        match self {
            Tool::CargoAudit => &["audit", "--version"],
            Tool::Govulncheck => &["-version"],
            Tool::Trivy | Tool::Trufflehog | Tool::OsvScanner => &["--version"],
            _ => &["--version"],
        }
    }

    /// True once the tool is wired into `run_available`. The others are detected
    /// and installable, but their output is not parsed yet — offering them as
    /// runnable would silently do nothing.
    pub fn integrated(self) -> bool {
        matches!(
            self,
            Tool::Semgrep
                | Tool::Bandit
                | Tool::CargoAudit
                | Tool::Gitleaks
                | Tool::OsvScanner
                | Tool::Hadolint
                | Tool::Ruff
                | Tool::Trivy
                | Tool::Trufflehog
                | Tool::NpmAudit
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolStatus {
    pub tool: Tool,
    pub label: String,
    pub available: bool,
    pub version: Option<String>,
    pub install_hint: String,
    pub docs_url: String,
    pub adds: String,
    pub scope: String,
    /// False when the tool can be installed and detected but its output is not
    /// parsed yet. Surfaced so the UI never implies a scan uses it when it does not.
    pub integrated: bool,
    /// Install routes whose package manager exists on this machine.
    pub install_options: Vec<InstallOption>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallOption {
    pub manager: String,
    pub manager_label: String,
    pub package: String,
    /// The exact argv, joined for display. Shown before anything runs.
    pub command: String,
    pub available: bool,
}

/// Asks one tool for its version. Deliberately knows nothing about package
/// managers, so it can run while those are still being probed.
async fn probe_version(tool: Tool) -> Option<String> {
    // Resolve through PATHEXT: npm and friends are .cmd shims on Windows and
    // Command::new would not find them.
    let exe = crate::pkgmgr::resolve_program(tool.binary());
    let result = match &exe {
        Some(path) => {
            tokio::time::timeout(
                Duration::from_secs(10),
                tokio::process::Command::new(path)
                    .args(tool.version_args())
                    .stdin(Stdio::null())
                    .output(),
            )
            .await
        }
        None => Ok(Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not on PATH",
        ))),
    };

    match result {
        Ok(Ok(out)) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            text.lines()
                .next()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
        }
        _ => None,
    }
}

fn build_status(tool: Tool, version: Option<String>, managers: &[crate::pkgmgr::PkgMgrStatus]) -> ToolStatus {
    let install_options = tool
        .install_options()
        .iter()
        .filter_map(|(mgr_id, pkg)| {
            let m = crate::pkgmgr::PkgMgr::ALL.iter().find(|m| m.id() == *mgr_id)?;
            let status = managers.iter().find(|s| s.id == *mgr_id);
            Some(InstallOption {
                manager: mgr_id.to_string(),
                manager_label: m.label().to_string(),
                package: pkg.to_string(),
                command: m.install_argv(pkg).join(" "),
                available: status.map(|s| s.available).unwrap_or(false),
            })
        })
        .collect();

    ToolStatus {
        tool,
        label: tool.label().to_string(),
        available: version.is_some(),
        version,
        install_hint: tool.install_hint().to_string(),
        docs_url: tool.docs_url().to_string(),
        adds: tool.adds().to_string(),
        scope: tool.scope().to_string(),
        integrated: tool.integrated(),
        install_options,
    }
}

/// Probes every supported tool. Package managers are detected first so each
/// tool can report which install routes actually exist on this machine.
/// Probing every tool means spawning a process per tool and waiting for each to
/// print its version — seconds on Windows. The answer cannot change while the
/// app runs unless we install something, so it is cached: a scan used to pay
/// this cost up front, showing a frozen "Подготовка" with no progress at all
/// before any work began.
static TOOL_CACHE: OnceLock<RwLock<Option<Vec<ToolStatus>>>> = OnceLock::new();

fn tool_cache() -> &'static RwLock<Option<Vec<ToolStatus>>> {
    TOOL_CACHE.get_or_init(|| RwLock::new(None))
}

/// Drops the cached probe. Call after anything that can change what is
/// installed, or the app will keep reporting a freshly installed tool missing.
pub fn invalidate_tool_cache() {
    *tool_cache().write().unwrap() = None;
}

pub async fn detect_tools() -> Vec<ToolStatus> {
    // Scoped so the lock is never held across an await.
    if let Some(cached) = tool_cache().read().unwrap().clone() {
        return cached;
    }
    let fresh = probe_tools().await;
    *tool_cache().write().unwrap() = Some(fresh.clone());
    fresh
}

/// Probes for real, ignoring the cache.
///
/// All twelve at once: sequentially this took 6.3 s on a normal Windows box —
/// six seconds of a setup screen with no scanner list, on every cold start.
pub async fn probe_tools() -> Vec<ToolStatus> {
    // Versions and package managers are independent questions, so they are
    // asked at the same time. Waiting for the managers first cost ~1.7 s on top
    // of the slowest tool for nothing.
    let versions = async {
        let mut set = tokio::task::JoinSet::new();
        for (i, &t) in Tool::ALL.iter().enumerate() {
            set.spawn(async move { (i, probe_version(t).await) });
        }
        // Reassembled by index: the catalogue order is what the UI shows, and
        // it must not depend on which process exits first.
        let mut slots: Vec<Option<String>> = (0..Tool::ALL.len()).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            if let Ok((i, v)) = joined {
                slots[i] = v;
            }
        }
        slots
    };

    let (versions, managers) = tokio::join!(versions, crate::pkgmgr::detect());

    Tool::ALL
        .iter()
        .zip(versions)
        .map(|(&t, v)| build_status(t, v, &managers))
        .collect()
}

fn mk_id(prefix: &str, file: &str, line: u32, rule: &str) -> String {
    format!("{prefix}:{file}:{line}:{rule}")
}

/// Normalises a path from a tool's output into the same form the rest of the
/// report uses: relative to the scan root, forward slashes, no `./` prefix.
///
/// The tools disagree: semgrep and bandit emit paths relative to their working
/// directory with backslashes on Windows (`.\backend\app.py`), gitleaks emits
/// forward slashes, and any of them may emit an absolute path. Without this,
/// findings carry paths that never match `FileSummary::path`, so they silently
/// fail to attach to the file tree and the code viewer.
fn rel(root: &Path, path: &str) -> String {
    let p = Path::new(path);
    let stripped = p.strip_prefix(root).unwrap_or(p);

    let normalised = stripped.to_string_lossy().replace('\\', "/");
    let trimmed = normalised
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string();

    if trimmed.is_empty() {
        normalised
    } else {
        trimmed
    }
}

// ------------------------------------------------------------------ Semgrep

#[derive(Deserialize)]
struct SemgrepOutput {
    #[serde(default)]
    results: Vec<SemgrepResult>,
}

#[derive(Deserialize)]
struct SemgrepResult {
    check_id: String,
    path: String,
    start: SemgrepPos,
    end: SemgrepPos,
    extra: SemgrepExtra,
}

#[derive(Deserialize)]
struct SemgrepPos {
    line: u32,
    #[serde(default)]
    col: u32,
}

#[derive(Deserialize)]
struct SemgrepExtra {
    #[serde(default)]
    message: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    lines: String,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

fn semgrep_metadata_list(meta: &Option<serde_json::Value>, key: &str) -> Vec<String> {
    let Some(m) = meta else { return Vec::new() };
    let Some(v) = m.get(key) else { return Vec::new() };
    match v {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

pub fn parse_semgrep(json: &str, root: &Path) -> Vec<Finding> {
    let Ok(out) = serde_json::from_str::<SemgrepOutput>(json) else {
        return Vec::new();
    };

    out.results
        .into_iter()
        .map(|r| {
            let file = rel(root, &r.path);
            let cwe = semgrep_metadata_list(&r.extra.metadata, "cwe");
            let owasp = semgrep_metadata_list(&r.extra.metadata, "owasp")
                .into_iter()
                .next();
            let references = semgrep_metadata_list(&r.extra.metadata, "references");

            Finding {
                id: mk_id("semgrep", &file, r.start.line, &r.check_id),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: r.check_id.clone(),
                title: r
                    .extra
                    .message
                    .lines()
                    .next()
                    .unwrap_or(&r.check_id)
                    .chars()
                    .take(140)
                    .collect(),
                description: r.extra.message.clone(),
                recommendation: "Подробности и способ исправления — в описании правила Semgrep."
                    .to_string(),
                severity: Severity::from_label(&r.extra.severity),
                confidence: Confidence::Medium,
                source: FindingSource::Semgrep,
                source_label: FindingSource::Semgrep.label().to_string(),
                category: "Semgrep".to_string(),
                file,
                line: r.start.line,
                end_line: r.end.line.max(r.start.line),
                column: r.start.col,
                end_column: r.end.col,
                snippet: r.extra.lines.clone(),
                snippet_start_line: r.start.line,
                cwe,
                owasp,
                cve: Vec::new(),
                references,
                package: None,
            }
        })
        .collect()
}

// ------------------------------------------------------------------- Bandit

#[derive(Deserialize)]
struct BanditOutput {
    #[serde(default)]
    results: Vec<BanditResult>,
}

#[derive(Deserialize)]
struct BanditResult {
    filename: String,
    line_number: u32,
    /// Bandit reports the span as a list of line numbers, not an end line.
    #[serde(default)]
    line_range: Vec<u32>,
    test_id: String,
    test_name: String,
    issue_text: String,
    issue_severity: String,
    issue_confidence: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    issue_cwe: Option<BanditCwe>,
    #[serde(default)]
    more_info: Option<String>,
}

#[derive(Deserialize)]
struct BanditCwe {
    #[serde(default)]
    id: Option<serde_json::Value>,
}

/// Bandit prefixes every snippet line with its line number ("8 import os").
/// Our viewer renders its own gutter, so leaving them in shows the number twice.
fn strip_bandit_line_numbers(code: &str) -> String {
    code.lines()
        .map(|line| match line.split_once(' ') {
            Some((head, rest)) if !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit()) => {
                rest
            }
            _ => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn parse_bandit(json: &str, root: &Path) -> Vec<Finding> {
    let Ok(out) = serde_json::from_str::<BanditOutput>(json) else {
        return Vec::new();
    };

    out.results
        .into_iter()
        .map(|r| {
            let file = rel(root, &r.filename);
            let cwe = r
                .issue_cwe
                .as_ref()
                .and_then(|c| c.id.as_ref())
                .map(|id| {
                    let n = id.as_u64().map(|v| v.to_string()).unwrap_or_else(|| {
                        id.as_str().unwrap_or("").to_string()
                    });
                    vec![format!("CWE-{n}")]
                })
                .unwrap_or_default();

            Finding {
                id: mk_id("bandit", &file, r.line_number, &r.test_id),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: r.test_id.clone(),
                title: r.test_name.clone(),
                description: r.issue_text.clone(),
                recommendation: r
                    .more_info
                    .clone()
                    .map(|u| format!("Документация Bandit: {u}"))
                    .unwrap_or_else(|| "См. документацию Bandit по этому тесту.".to_string()),
                severity: Severity::from_label(&r.issue_severity),
                confidence: match r.issue_confidence.to_ascii_uppercase().as_str() {
                    "HIGH" => Confidence::High,
                    "LOW" => Confidence::Low,
                    _ => Confidence::Medium,
                },
                source: FindingSource::Bandit,
                source_label: FindingSource::Bandit.label().to_string(),
                category: "Bandit".to_string(),
                file,
                line: r.line_number,
                end_line: r.line_range.iter().copied().max().unwrap_or(r.line_number),
                column: 0,
                end_column: 0,
                snippet: strip_bandit_line_numbers(&r.code),
                // The snippet starts at the first line of the reported range,
                // which can precede the flagged line itself.
                snippet_start_line: r
                    .line_range
                    .iter()
                    .copied()
                    .min()
                    .unwrap_or(r.line_number),
                cwe,
                owasp: None,
                cve: Vec::new(),
                references: r.more_info.into_iter().collect(),
                package: None,
            }
        })
        .collect()
}

// -------------------------------------------------------------- cargo-audit

#[derive(Deserialize)]
struct CargoAuditOutput {
    #[serde(default)]
    vulnerabilities: CargoAuditVulns,
}

#[derive(Deserialize, Default)]
struct CargoAuditVulns {
    #[serde(default)]
    list: Vec<CargoAuditVuln>,
}

#[derive(Deserialize)]
struct CargoAuditVuln {
    advisory: CargoAdvisory,
    package: CargoPackage,
    #[serde(default)]
    versions: Option<CargoVersions>,
}

#[derive(Deserialize)]
struct CargoAdvisory {
    id: String,
    title: String,
    description: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    categories: Vec<String>,
    /// RustSec ships a CVSS v3 vector for most advisories.
    #[serde(default)]
    cvss: Option<String>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
}

#[derive(Deserialize)]
struct CargoVersions {
    #[serde(default)]
    patched: Vec<String>,
}

pub fn parse_cargo_audit(json: &str, manifest: &str) -> Vec<Finding> {
    let Ok(out) = serde_json::from_str::<CargoAuditOutput>(json) else {
        return Vec::new();
    };

    out.vulnerabilities
        .list
        .into_iter()
        .map(|v| {
            let cve: Vec<String> = v
                .advisory
                .aliases
                .iter()
                .filter(|a| a.starts_with("CVE-"))
                .cloned()
                .collect();
            // Patched versions are requirement strings like ">=0.2.23"; the
            // operator would read as "до версии >=0.2.23 или новее".
            let fixed = v
                .versions
                .as_ref()
                .and_then(|ver| ver.patched.first())
                .map(|p| p.trim_start_matches(['>', '=', '^', '~', ' ']).to_string())
                .filter(|p| !p.is_empty());

            Finding {
                id: format!("cargo-audit:{}:{}", v.package.name, v.advisory.id),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: v.advisory.id.clone(),
                title: format!("{}: {}", v.package.name, v.advisory.title),
                description: v.advisory.description.chars().take(1200).collect(),
                recommendation: match &fixed {
                    Some(f) => format!("Обновите {} до версии {} или новее.", v.package.name, f),
                    None => format!(
                        "Исправленной версии нет. Рассмотрите замену крейта {}.",
                        v.package.name
                    ),
                },
                // Prefer the advisory's own CVSS vector. Only the minority of
                // advisories without one fall back to a fixed severity.
                severity: v
                    .advisory
                    .cvss
                    .as_deref()
                    .and_then(crate::osv::cvss_base_score)
                    .map(Severity::from_cvss)
                    .unwrap_or(Severity::High),
                confidence: Confidence::High,
                source: FindingSource::CargoAudit,
                source_label: FindingSource::CargoAudit.label().to_string(),
                category: v
                    .advisory
                    .categories
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Уязвимая зависимость".to_string()),
                file: manifest.to_string(),
                line: 0,
                end_line: 0,
                column: 0,
                end_column: 0,
                snippet: format!("{} = \"{}\"", v.package.name, v.package.version),
                snippet_start_line: 0,
                cwe: Vec::new(),
                owasp: Some("A06:2021 – Vulnerable and Outdated Components".to_string()),
                cve,
                references: v.advisory.url.into_iter().collect(),
                package: Some(PackageInfo {
                    name: v.package.name,
                    version: v.package.version,
                    ecosystem: "crates.io".to_string(),
                    fixed_version: fixed,
                }),
            }
        })
        .collect()
}

// ----------------------------------------------------------------- Gitleaks

#[derive(Deserialize)]
struct GitleaksFinding {
    #[serde(rename = "RuleID", default)]
    rule_id: String,
    #[serde(rename = "Description", default)]
    description: String,
    #[serde(rename = "File", default)]
    file: String,
    #[serde(rename = "StartLine", default)]
    start_line: u32,
    #[serde(rename = "EndLine", default)]
    end_line: u32,
    #[serde(rename = "Match", default)]
    match_text: String,
}

pub fn parse_gitleaks(json: &str, root: &Path) -> Vec<Finding> {
    let Ok(items) = serde_json::from_str::<Vec<GitleaksFinding>>(json) else {
        return Vec::new();
    };

    items
        .into_iter()
        .map(|g| {
            let file = rel(root, &g.file);
            Finding {
                id: mk_id("gitleaks", &file, g.start_line, &g.rule_id),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: g.rule_id.clone(),
                title: format!("Секрет в коде: {}", g.rule_id),
                description: g.description.clone(),
                recommendation: "Отзовите секрет и перевыпустите его. Уберите значение из кода и из истории git."
                    .to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                source: FindingSource::Gitleaks,
                source_label: FindingSource::Gitleaks.label().to_string(),
                category: "Секрет в коде".to_string(),
                file,
                line: g.start_line,
                end_line: g.end_line.max(g.start_line),
                column: 0,
                end_column: 0,
                // Never echo the raw secret back into the report.
                snippet: format!("{}…", g.match_text.chars().take(6).collect::<String>()),
                snippet_start_line: g.start_line,
                cwe: vec!["CWE-798".to_string()],
                owasp: Some("A07:2021 – Identification and Authentication Failures".to_string()),
                cve: Vec::new(),
                references: Vec::new(),
                package: None,
            }
        })
        .collect()
}

// ---------------------------------------------------------------- hadolint

#[derive(Deserialize)]
struct HadolintFinding {
    code: String,
    #[serde(default)]
    column: u32,
    file: String,
    level: String,
    line: u32,
    message: String,
}

pub fn parse_hadolint(json: &str, root: &Path) -> Vec<Finding> {
    let Ok(items) = serde_json::from_str::<Vec<HadolintFinding>>(json) else {
        return Vec::new();
    };

    items
        .into_iter()
        .map(|h| {
            let file = rel(root, &h.file);
            Finding {
                id: mk_id("hadolint", &file, h.line, &h.code),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: h.code.clone(),
                title: h.message.chars().take(140).collect(),
                description: h.message.clone(),
                recommendation: format!(
                    "Правило Hadolint {}: https://github.com/hadolint/hadolint/wiki/{}",
                    h.code, h.code
                ),
                // Hadolint's "info"/"style" are lint nits, not vulnerabilities.
                severity: match h.level.as_str() {
                    "error" => Severity::High,
                    "warning" => Severity::Medium,
                    "info" => Severity::Low,
                    _ => Severity::Info,
                },
                confidence: Confidence::High,
                source: FindingSource::Hadolint,
                source_label: FindingSource::Hadolint.label().to_string(),
                category: "Dockerfile".to_string(),
                file,
                line: h.line,
                end_line: h.line,
                column: h.column,
                end_column: 0,
                snippet: String::new(),
                snippet_start_line: h.line,
                cwe: Vec::new(),
                owasp: Some("A05:2021 – Security Misconfiguration".to_string()),
                cve: Vec::new(),
                references: vec![format!("https://github.com/hadolint/hadolint/wiki/{}", h.code)],
                package: None,
            }
        })
        .collect()
}

// -------------------------------------------------------------------- ruff

#[derive(Deserialize)]
struct RuffFinding {
    #[serde(default)]
    code: Option<String>,
    filename: String,
    location: RuffPos,
    end_location: RuffPos,
    message: String,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Deserialize)]
struct RuffPos {
    row: u32,
    #[serde(default)]
    column: u32,
}

/// Keeps only ruff's security rules.
///
/// Ruff is primarily a style linter; reporting its 42 formatting opinions as
/// security findings would bury the real ones. The `S` prefix is its port of
/// bandit's checks.
pub fn parse_ruff(json: &str, root: &Path) -> Vec<Finding> {
    let Ok(items) = serde_json::from_str::<Vec<RuffFinding>>(json) else {
        return Vec::new();
    };

    items
        .into_iter()
        .filter(|r| r.code.as_deref().map(|c| c.starts_with('S')).unwrap_or(false))
        .map(|r| {
            let file = rel(root, &r.filename);
            let code = r.code.clone().unwrap_or_default();
            Finding {
                id: mk_id("ruff", &file, r.location.row, &code),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: code.clone(),
                title: r.message.chars().take(140).collect(),
                description: r.message.clone(),
                recommendation: r
                    .url
                    .clone()
                    .map(|u| format!("Описание правила: {u}"))
                    .unwrap_or_else(|| "См. документацию Ruff по этому правилу.".to_string()),
                // Ruff's own "severity" is always "error"; its S-rules map to
                // bandit checks whose real weight varies, so stay conservative.
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                source: FindingSource::Ruff,
                source_label: FindingSource::Ruff.label().to_string(),
                category: "Python".to_string(),
                file,
                line: r.location.row,
                end_line: r.end_location.row.max(r.location.row),
                column: r.location.column,
                end_column: r.end_location.column,
                snippet: String::new(),
                snippet_start_line: r.location.row,
                cwe: Vec::new(),
                owasp: None,
                cve: Vec::new(),
                references: r.url.into_iter().collect(),
                package: None,
            }
        })
        .collect()
}

// ------------------------------------------------------------- osv-scanner

#[derive(Deserialize)]
struct OsvScannerOut {
    #[serde(default)]
    results: Vec<OsvScannerResult>,
}

#[derive(Deserialize)]
struct OsvScannerResult {
    source: OsvSource,
    #[serde(default)]
    packages: Vec<OsvScannerPackage>,
}

#[derive(Deserialize)]
struct OsvSource {
    #[serde(default)]
    path: String,
}

#[derive(Deserialize)]
struct OsvScannerPackage {
    package: OsvScannerPkgInfo,
    #[serde(default)]
    vulnerabilities: Vec<OsvScannerVuln>,
    #[serde(default)]
    groups: Vec<OsvScannerGroup>,
}

#[derive(Deserialize)]
struct OsvScannerPkgInfo {
    name: String,
    version: String,
    #[serde(default)]
    ecosystem: String,
}

#[derive(Deserialize)]
struct OsvScannerVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Deserialize)]
struct OsvScannerGroup {
    #[serde(default)]
    ids: Vec<String>,
    /// A CVSS *score* as a string here, unlike the OSV API which gives a vector.
    #[serde(default)]
    max_severity: String,
}

pub fn parse_osv_scanner(json: &str, root: &Path) -> Vec<Finding> {
    let Ok(out) = serde_json::from_str::<OsvScannerOut>(json) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    for result in out.results {
        let file = rel(root, &result.source.path);

        for pkg in result.packages {
            for vuln in &pkg.vulnerabilities {
                // The scanner reports severity per *group* of aliased ids, not
                // per vulnerability, so find the group this one belongs to.
                let score: Option<f32> = pkg
                    .groups
                    .iter()
                    .find(|g| g.ids.contains(&vuln.id))
                    .and_then(|g| g.max_severity.parse::<f32>().ok());

                let cve: Vec<String> = vuln
                    .aliases
                    .iter()
                    .filter(|a| a.starts_with("CVE-"))
                    .cloned()
                    .collect();
                let display = cve.first().cloned().unwrap_or_else(|| vuln.id.clone());

                findings.push(Finding {
                    id: format!("osv-scanner:{}:{}:{}", pkg.package.name, pkg.package.version, vuln.id),
                    fingerprint: String::new(),
                    suppressed: false,
                    suppression_reason: None,
                    is_new: false,
                    rule_id: vuln.id.clone(),
                    title: format!("{} {} — {}", pkg.package.name, pkg.package.version, display),
                    description: if vuln.summary.is_empty() {
                        vuln.details.chars().take(800).collect()
                    } else {
                        vuln.summary.clone()
                    },
                    recommendation: format!(
                        "Обновите {} до версии без {}. Подробности: https://osv.dev/vulnerability/{}",
                        pkg.package.name, vuln.id, vuln.id
                    ),
                    severity: score.map(Severity::from_cvss).unwrap_or(Severity::Medium),
                    confidence: Confidence::High,
                    source: FindingSource::OsvScanner,
                    source_label: FindingSource::OsvScanner.label().to_string(),
                    category: "Уязвимая зависимость".to_string(),
                    file: file.clone(),
                    line: 0,
                    end_line: 0,
                    column: 0,
                    end_column: 0,
                    snippet: format!("{} {}", pkg.package.name, pkg.package.version),
                    snippet_start_line: 0,
                    cwe: Vec::new(),
                    owasp: Some("A06:2021 – Vulnerable and Outdated Components".to_string()),
                    cve,
                    references: vec![format!("https://osv.dev/vulnerability/{}", vuln.id)],
                    package: Some(PackageInfo {
                        name: pkg.package.name.clone(),
                        version: pkg.package.version.clone(),
                        ecosystem: pkg.package.ecosystem.clone(),
                        fixed_version: None,
                    }),
                });
            }
        }
    }

    findings
}

// ------------------------------------------------------------- trufflehog

#[derive(Deserialize)]
struct ThFinding {
    #[serde(rename = "DetectorName", default)]
    detector: String,
    #[serde(rename = "DetectorDescription", default)]
    description: String,
    #[serde(rename = "Verified", default)]
    verified: bool,
    #[serde(rename = "SourceMetadata", default)]
    meta: Option<ThMeta>,
}

#[derive(Deserialize)]
struct ThMeta {
    #[serde(rename = "Data", default)]
    data: Option<ThData>,
}

#[derive(Deserialize)]
struct ThData {
    #[serde(rename = "Filesystem", default)]
    filesystem: Option<ThFile>,
}

#[derive(Deserialize)]
struct ThFile {
    #[serde(default)]
    file: String,
    #[serde(default)]
    line: u32,
}

/// TruffleHog streams one JSON object per line rather than a JSON array, so it
/// cannot be parsed in one go.
pub fn parse_trufflehog(output: &str, root: &Path) -> Vec<Finding> {
    output
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .filter_map(|line| serde_json::from_str::<ThFinding>(line).ok())
        .filter_map(|t| {
            let fs = t.meta.as_ref()?.data.as_ref()?.filesystem.as_ref()?;
            let file = rel(root, &fs.file);
            let line_no = fs.line.max(1);

            Some(Finding {
                id: format!("trufflehog:{}:{}:{}", file, line_no, t.detector),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: format!("TRUFFLEHOG-{}", t.detector.to_uppercase()),
                title: if t.verified {
                    format!("Действующий секрет: {} (ключ проверен и работает)", t.detector)
                } else {
                    format!("Секрет в коде: {}", t.detector)
                },
                description: if t.description.is_empty() {
                    format!("TruffleHog распознал учётные данные {}.", t.detector)
                } else {
                    t.description.clone()
                },
                recommendation: "Отзовите секрет и выпустите новый. Уберите значение из кода и из истории git."
                    .to_string(),
                // A verified secret is one TruffleHog successfully authenticated
                // with: it is live, not a guess.
                severity: if t.verified { Severity::Critical } else { Severity::High },
                confidence: if t.verified { Confidence::High } else { Confidence::Medium },
                source: FindingSource::Trufflehog,
                source_label: FindingSource::Trufflehog.label().to_string(),
                category: "Секрет в коде".to_string(),
                file,
                line: line_no,
                end_line: line_no,
                column: 0,
                end_column: 0,
                // Never echo the value: `Raw` holds the live credential.
                snippet: String::new(),
                snippet_start_line: line_no,
                cwe: vec!["CWE-798".to_string()],
                owasp: Some("A07:2021 – Identification and Authentication Failures".to_string()),
                cve: Vec::new(),
                references: Vec::new(),
                package: None,
            })
        })
        .collect()
}

// ------------------------------------------------------------- npm audit

#[derive(Deserialize)]
struct NpmAudit {
    #[serde(default)]
    vulnerabilities: std::collections::BTreeMap<String, NpmVuln>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NpmVuln {
    name: String,
    severity: String,
    #[serde(default)]
    range: String,
    #[serde(default)]
    via: Vec<serde_json::Value>,
    /// `fixAvailable` in the JSON: false when there is no fix, an object with
    /// name/version when there is.
    #[serde(default)]
    fix_available: serde_json::Value,
}

pub fn parse_npm_audit(json: &str, manifest: &str) -> Vec<Finding> {
    let Ok(out) = serde_json::from_str::<NpmAudit>(json) else {
        return Vec::new();
    };

    out.vulnerabilities
        .into_values()
        .filter_map(|v| {
            // `via` mixes advisory objects with plain strings naming the
            // transitive package that pulled the problem in. Only the objects
            // carry a CVE, title and URL.
            let adv = v.via.iter().find(|x| x.is_object())?;
            let title = adv.get("title")?.as_str()?.to_string();
            let url = adv.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string();
            let ghsa = url.rsplit('/').next().unwrap_or("").to_string();

            let cwe: Vec<String> = adv
                .get("cwe")
                .and_then(|c| c.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let score = adv
                .get("cvss")
                .and_then(|c| c.get("score"))
                .and_then(|s| s.as_f64())
                .map(|s| s as f32);

            let fixed = v
                .fix_available
                .get("version")
                .and_then(|x| x.as_str())
                .map(String::from);

            Some(Finding {
                id: format!("npm-audit:{}:{}", v.name, ghsa),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: if ghsa.is_empty() { "npm-audit".into() } else { ghsa.clone() },
                title: format!("{} {} — {}", v.name, v.range, title),
                description: title.clone(),
                recommendation: match &fixed {
                    Some(f) => format!("Обновите {} до версии {}.", v.name, f),
                    None => format!(
                        "Исправленной версии нет. Проверьте {url} и рассмотрите замену {}.",
                        v.name
                    ),
                },
                // npm's own label is coarse; prefer the advisory's CVSS score.
                severity: score
                    .map(Severity::from_cvss)
                    .unwrap_or_else(|| Severity::from_label(&v.severity)),
                confidence: Confidence::High,
                source: FindingSource::NpmAudit,
                source_label: FindingSource::NpmAudit.label().to_string(),
                category: "Уязвимая зависимость".to_string(),
                file: manifest.to_string(),
                line: 0,
                end_line: 0,
                column: 0,
                end_column: 0,
                snippet: format!("{} {}", v.name, v.range),
                snippet_start_line: 0,
                cwe,
                owasp: Some("A06:2021 – Vulnerable and Outdated Components".to_string()),
                cve: Vec::new(),
                references: if url.is_empty() { vec![] } else { vec![url] },
                package: Some(PackageInfo {
                    name: v.name.clone(),
                    version: v.range.clone(),
                    ecosystem: "npm".to_string(),
                    fixed_version: fixed,
                }),
            })
        })
        .collect()
}

// ------------------------------------------------------------------ trivy

#[derive(Deserialize)]
struct TrivyOut {
    #[serde(rename = "Results", default)]
    results: Vec<TrivyResult>,
}

#[derive(Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target", default)]
    target: String,
    #[serde(rename = "Vulnerabilities", default)]
    vulnerabilities: Vec<TrivyVuln>,
    #[serde(rename = "Misconfigurations", default)]
    misconfigurations: Vec<TrivyMisconf>,
}

#[derive(Deserialize)]
struct TrivyVuln {
    #[serde(rename = "VulnerabilityID")]
    id: String,
    #[serde(rename = "PkgName", default)]
    pkg: String,
    #[serde(rename = "InstalledVersion", default)]
    installed: String,
    #[serde(rename = "FixedVersion", default)]
    fixed: String,
    #[serde(rename = "Severity", default)]
    severity: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Description", default)]
    description: String,
    #[serde(rename = "CweIDs", default)]
    cwe: Vec<String>,
    #[serde(rename = "PrimaryURL", default)]
    url: String,
}

#[derive(Deserialize)]
struct TrivyMisconf {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Description", default)]
    description: String,
    #[serde(rename = "Resolution", default)]
    resolution: String,
    #[serde(rename = "Severity", default)]
    severity: String,
    #[serde(rename = "PrimaryURL", default)]
    url: String,
    #[serde(rename = "CauseMetadata", default)]
    cause: Option<TrivyCause>,
}

#[derive(Deserialize)]
struct TrivyCause {
    #[serde(rename = "StartLine", default)]
    start_line: u32,
    #[serde(rename = "EndLine", default)]
    end_line: u32,
}

pub fn parse_trivy(json: &str, root: &Path) -> Vec<Finding> {
    let Ok(out) = serde_json::from_str::<TrivyOut>(json) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    for r in out.results {
        let file = rel(root, &r.target);

        for v in r.vulnerabilities {
            let cve = if v.id.starts_with("CVE-") {
                vec![v.id.clone()]
            } else {
                Vec::new()
            };
            findings.push(Finding {
                id: format!("trivy:{}:{}:{}", v.pkg, v.installed, v.id),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: v.id.clone(),
                title: format!("{} {} — {}", v.pkg, v.installed, v.id),
                description: if v.title.is_empty() {
                    v.description.chars().take(800).collect()
                } else {
                    v.title.clone()
                },
                recommendation: if v.fixed.is_empty() {
                    format!("Исправленной версии нет. Подробности: {}", v.url)
                } else {
                    // Trivy lists every patched branch, e.g. "1.11.23, 2.1.11, 2.2.4".
                    format!("Обновите {} до одной из версий: {}", v.pkg, v.fixed)
                },
                severity: Severity::from_label(&v.severity),
                confidence: Confidence::High,
                source: FindingSource::Trivy,
                source_label: FindingSource::Trivy.label().to_string(),
                category: "Уязвимая зависимость".to_string(),
                file: file.clone(),
                line: 0,
                end_line: 0,
                column: 0,
                end_column: 0,
                snippet: format!("{} {}", v.pkg, v.installed),
                snippet_start_line: 0,
                cwe: v.cwe,
                owasp: Some("A06:2021 – Vulnerable and Outdated Components".to_string()),
                cve,
                references: if v.url.is_empty() { vec![] } else { vec![v.url] },
                package: Some(PackageInfo {
                    name: v.pkg,
                    version: v.installed,
                    ecosystem: String::new(),
                    fixed_version: if v.fixed.is_empty() { None } else { Some(v.fixed) },
                }),
            });
        }

        for m in r.misconfigurations {
            let line = m.cause.as_ref().map(|c| c.start_line).unwrap_or(0);
            findings.push(Finding {
                id: format!("trivy:{}:{}:{}", file, line, m.id),
                fingerprint: String::new(),
                suppressed: false,
                suppression_reason: None,
                is_new: false,
                rule_id: m.id.clone(),
                title: m.title.clone(),
                description: m.description.clone(),
                recommendation: if m.resolution.is_empty() {
                    format!("Подробности: {}", m.url)
                } else {
                    m.resolution.clone()
                },
                severity: Severity::from_label(&m.severity),
                confidence: Confidence::High,
                source: FindingSource::Trivy,
                source_label: FindingSource::Trivy.label().to_string(),
                category: "Инфраструктура".to_string(),
                file: file.clone(),
                line,
                end_line: m.cause.as_ref().map(|c| c.end_line).unwrap_or(line).max(line),
                column: 0,
                end_column: 0,
                snippet: String::new(),
                snippet_start_line: line,
                cwe: Vec::new(),
                owasp: Some("A05:2021 – Security Misconfiguration".to_string()),
                cve: Vec::new(),
                references: if m.url.is_empty() { vec![] } else { vec![m.url] },
                package: None,
            });
        }
    }

    findings
}

// -------------------------------------------------------------------- runner

/// Runs a tool and returns its stdout. External tools signal "findings exist"
/// with a non-zero exit code, so exit status alone cannot mean failure.
/// Marker for a run the user cancelled, so the caller can stop the loop instead
/// of reporting it as a tool failure.
pub const CANCELLED: &str = "__cancelled__";

/// Polls the cancel flag; resolves once it is set.
async fn cancelled(cancel: &AtomicBool) -> () {
    while !cancel.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

async fn run_tool(
    program: &str,
    args: &[&str],
    cwd: &Path,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<String, String> {
    let Some(exe) = crate::pkgmgr::resolve_program(program) else {
        return Err(format!("{program} не найден в PATH"));
    };

    let mut cmd = tokio::process::Command::new(&exe);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        // Load-bearing for cancellation: dropping the output future drops the
        // child, and only with this does that also kill the process. Without it
        // "Отменить" left semgrep chewing on the repo for another minute while
        // the UI pretended the scan had stopped.
        .kill_on_drop(true);

    let result = tokio::select! {
        r = tokio::time::timeout(timeout, cmd.output()) => r,
        _ = cancelled(cancel) => return Err(CANCELLED.to_string()),
    };

    match result {
        Ok(Ok(out)) => Ok(String::from_utf8_lossy(&out.stdout).to_string()),
        Ok(Err(e)) => Err(format!("не удалось запустить {program}: {e}")),
        Err(_) => Err(format!(
            "{program} превысил лимит времени ({} с) и был прерван",
            timeout.as_secs()
        )),
    }
}

pub struct ExternalResult {
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
    pub engines: Vec<String>,
}

/// Runs the enabled tools that are actually installed.
///
/// `cargo_lockfiles` holds every Cargo.lock found during discovery, as paths
/// relative to `root`. A Rust crate frequently sits in a subdirectory of a
/// polyglot repository, so looking only at the root would silently skip
/// cargo-audit on exactly the projects that need it.
pub async fn run_available(
    root: &Path,
    statuses: &[ToolStatus],
    enabled: &[Tool],
    cargo_lockfiles: &[String],
    dockerfiles: &[String],
    npm_lockfiles: &[String],
    cancel: &AtomicBool,
) -> ExternalResult {
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    let mut engines = Vec::new();
    let timeout = Duration::from_secs(300);

    for status in statuses {
        if !status.available || !enabled.contains(&status.tool) {
            continue;
        }
        // Between tools as well as inside them: one scanner may have finished
        // while the user was already waiting for the run to stop.
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        let outcome = match status.tool {
            Tool::Semgrep => run_tool(
                "semgrep",
                &["scan", "--config=auto", "--json", "--quiet", "--no-git-ignore", "."],
                root,
                timeout,
                cancel,
            )
            .await
            .map(|o| parse_semgrep(&o, root)),

            Tool::Bandit => run_tool("bandit", &["-r", ".", "-f", "json", "-q"], root, timeout, cancel)
                .await
                .map(|o| parse_bandit(&o, root)),

            Tool::CargoAudit => {
                if cargo_lockfiles.is_empty() {
                    continue; // no Rust lockfile anywhere: nothing for it to do
                }
                let mut all = Vec::new();
                let mut failure = None;
                for lock in cargo_lockfiles {
                    let abs = root.join(lock);
                    match run_tool(
                        "cargo",
                        &["audit", "--json", "--file", &abs.to_string_lossy()],
                        root,
                        timeout,
                        cancel,
                    )
                    .await
                    {
                        Ok(out) => all.extend(parse_cargo_audit(&out, lock)),
                        Err(e) => failure = Some(e),
                    }
                }
                match failure {
                    // Report the error only if nothing at all came back.
                    Some(e) if all.is_empty() => Err(e),
                    _ => Ok(all),
                }
            }

            Tool::Gitleaks => run_tool(
                "gitleaks",
                &["detect", "--no-git", "--report-format", "json", "--report-path", "-"],
                root,
                timeout,
                cancel,
            )
            .await
            .map(|o| parse_gitleaks(&o, root)),

            Tool::OsvScanner => run_tool(
                "osv-scanner",
                &["scan", "source", "--format", "json", "--recursive", "."],
                root,
                timeout,
                cancel,
            )
            .await
            .map(|o| parse_osv_scanner(&o, root)),

            Tool::Hadolint => {
                // Hadolint takes files, not a directory, so feed it the
                // Dockerfiles discovery already found.
                if dockerfiles.is_empty() {
                    continue;
                }
                let mut args = vec!["-f".to_string(), "json".to_string()];
                args.extend(dockerfiles.iter().cloned());
                let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                run_tool("hadolint", &argv, root, timeout, cancel)
                    .await
                    .map(|o| parse_hadolint(&o, root))
            }

            Tool::Ruff => run_tool(
                "ruff",
                &["check", "--output-format", "json", "--select", "S", "--quiet", "."],
                root,
                timeout,
                cancel,
            )
            .await
            .map(|o| parse_ruff(&o, root)),

            Tool::Trivy => run_tool(
                "trivy",
                &["fs", "--format", "json", "--scanners", "vuln,secret,misconfig", "--quiet", "."],
                root,
                timeout,
                cancel,
            )
            .await
            .map(|o| parse_trivy(&o, root)),

            Tool::Trufflehog => run_tool(
                "trufflehog",
                &["filesystem", ".", "--json", "--no-update"],
                root,
                timeout,
                cancel,
            )
            .await
            .map(|o| parse_trufflehog(&o, root)),

            Tool::NpmAudit => {
                // npm audit needs a lockfile; without one it errors out rather
                // than reporting nothing.
                let Some(lock) = npm_lockfiles.first() else {
                    continue;
                };
                let dir = root.join(lock).parent().map(|p| p.to_path_buf()).unwrap_or_else(|| root.to_path_buf());
                run_tool("npm", &["audit", "--json"], &dir, timeout, cancel)
                    .await
                    .map(|o| parse_npm_audit(&o, lock))
            }

            // Detected and installable, but their output is not parsed yet.
            // `integrated()` keeps them out of the runnable set, so reaching
            // here means the UI let something through — skip rather than
            // pretend the scan used them.
            Tool::Checkov | Tool::Govulncheck => continue,
        };

        match outcome {
            Ok(mut f) => {
                engines.push(status.label.clone());
                findings.append(&mut f);
            }
            // A cancelled tool is not a broken tool: the scan is being torn
            // down, and "semgrep: __cancelled__" in the report would be noise.
            Err(e) if e == CANCELLED => break,
            Err(e) => warnings.push(format!("{}: {}", status.label, e)),
        }
    }

    ExternalResult {
        findings,
        warnings,
        engines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> &'static Path {
        Path::new("/proj")
    }

    #[test]
    fn parses_semgrep_json() {
        let json = r#"{"results":[{
            "check_id":"python.lang.security.audit.dangerous-system-call",
            "path":"/proj/app.py",
            "start":{"line":12,"col":5},
            "end":{"line":12,"col":30},
            "extra":{
                "message":"Detected subprocess with shell=True",
                "severity":"ERROR",
                "lines":"subprocess.run(cmd, shell=True)",
                "metadata":{"cwe":["CWE-78: OS Command Injection"],"owasp":"A03:2021","references":["https://x"]}
            }
        }]}"#;
        let f = parse_semgrep(json, root());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].file, "app.py");
        assert_eq!(f[0].line, 12);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].cwe, vec!["CWE-78: OS Command Injection"]);
        assert_eq!(f[0].owasp.as_deref(), Some("A03:2021"));
    }

    #[test]
    fn parses_bandit_json() {
        let json = r#"{"results":[{
            "filename":"/proj/app.py",
            "line_number":7,
            "end_line_number":7,
            "test_id":"B602",
            "test_name":"subprocess_popen_with_shell_equals_true",
            "issue_text":"subprocess call with shell=True identified.",
            "issue_severity":"HIGH",
            "issue_confidence":"HIGH",
            "code":"subprocess.run(cmd, shell=True)",
            "issue_cwe":{"id":78,"link":"https://cwe.mitre.org/data/definitions/78.html"},
            "more_info":"https://bandit.readthedocs.io/"
        }]}"#;
        let f = parse_bandit(json, root());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "B602");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].confidence, Confidence::High);
        assert_eq!(f[0].cwe, vec!["CWE-78"]);
    }

    #[test]
    fn parses_cargo_audit_json() {
        let json = r#"{"vulnerabilities":{"found":true,"count":1,"list":[{
            "advisory":{
                "id":"RUSTSEC-2021-0079",
                "title":"Integer overflow in hyper",
                "description":"hyper had an integer overflow.",
                "aliases":["CVE-2021-32714"],
                "url":"https://rustsec.org/advisories/RUSTSEC-2021-0079",
                "categories":["memory-corruption"]
            },
            "package":{"name":"hyper","version":"0.14.7"},
            "versions":{"patched":[">=0.14.10"],"unaffected":[]}
        }]}}"#;
        let f = parse_cargo_audit(json, "Cargo.lock");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cve, vec!["CVE-2021-32714"]);
        assert!(f[0].recommendation.contains("0.14.10"));
        let pkg = f[0].package.as_ref().unwrap();
        assert_eq!(pkg.name, "hyper");
        assert_eq!(pkg.ecosystem, "crates.io");
    }

    #[test]
    fn gitleaks_output_never_echoes_the_raw_secret() {
        let json = r#"[{
            "RuleID":"aws-access-token",
            "Description":"AWS Access Token",
            "File":"/proj/config.py",
            "StartLine":3,
            "EndLine":3,
            "Match":"AKIAQYZ4W7RJ2NBKV6LC"
        }]"#;
        let f = parse_gitleaks(json, root());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].file, "config.py");
        assert!(!f[0].snippet.contains("AKIAQYZ4W7RJ2NBKV6LC"));
        assert!(f[0].snippet.starts_with("AKIAQY"));
    }

    #[test]
    fn parses_real_hadolint_output() {
        // Captured from: hadolint -f json Dockerfile
        let json = r#"[{
            "code": "DL3007",
            "column": 1,
            "file": "Dockerfile",
            "level": "warning",
            "line": 1,
            "message": "Using latest is prone to errors if the image will ever update. Pin the version explicitly to a release tag"
        }]"#;
        let f = parse_hadolint(json, Path::new("D:/Project/testbed"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "DL3007");
        assert_eq!(f[0].file, "Dockerfile");
        assert_eq!(f[0].line, 1);
        assert_eq!(f[0].severity, Severity::Medium); // warning
    }

    #[test]
    fn hadolint_style_notes_are_not_reported_as_vulnerabilities() {
        let json = r#"[{"code":"DL3059","column":1,"file":"Dockerfile","level":"info","line":3,"message":"x"},
                       {"code":"SC2086","column":1,"file":"Dockerfile","level":"style","line":4,"message":"y"}]"#;
        let f = parse_hadolint(json, Path::new("D:/x"));
        assert_eq!(f[0].severity, Severity::Low);
        assert_eq!(f[1].severity, Severity::Info);
    }

    #[test]
    fn parses_real_ruff_output_and_keeps_only_security_rules() {
        // Captured from: ruff check --output-format json
        let json = r#"[
            {
                "cell": null,
                "code": "S105",
                "end_location": {"column": 67, "row": 20},
                "filename": "D:\\Project\\testbed\\backend\\app.py",
                "fix": null,
                "location": {"column": 25, "row": 20},
                "message": "Possible hardcoded password assigned to: \"AWS_SECRET_ACCESS_KEY\"",
                "name": "hardcoded-password-string",
                "noqa_row": 20,
                "severity": "error",
                "url": "https://docs.astral.sh/ruff/rules/hardcoded-password-string"
            },
            {
                "cell": null,
                "code": "E501",
                "end_location": {"column": 100, "row": 5},
                "filename": "D:\\Project\\testbed\\backend\\app.py",
                "fix": null,
                "location": {"column": 89, "row": 5},
                "message": "Line too long",
                "name": "line-too-long",
                "noqa_row": 5,
                "severity": "error",
                "url": null
            }
        ]"#;
        let f = parse_ruff(json, Path::new("D:/Project/testbed"));
        // Ruff is mostly a style linter; only its S-rules are security.
        assert_eq!(f.len(), 1, "style rule leaked into security findings");
        assert_eq!(f[0].rule_id, "S105");
        assert_eq!(f[0].file, "backend/app.py");
        assert_eq!(f[0].line, 20);
    }

    #[test]
    fn parses_real_osv_scanner_output() {
        // Captured from: osv-scanner scan source --format json --recursive .
        let json = r#"{"results":[{
            "source": {"path": "D:/Project/testbed/backend/requirements.txt", "type": "lockfile"},
            "packages": [{
                "package": {"name": "django", "version": "2.2.0", "ecosystem": "PyPI"},
                "vulnerabilities": [{
                    "id": "PYSEC-2019-10",
                    "summary": "Django SQL injection",
                    "details": "long details",
                    "aliases": ["CVE-2019-12781", "GHSA-6c7v-2f49-8h26"]
                }],
                "groups": [{
                    "ids": ["PYSEC-2019-10", "GHSA-6c7v-2f49-8h26"],
                    "aliases": ["CVE-2019-12781", "GHSA-6c7v-2f49-8h26", "PYSEC-2019-10"],
                    "max_severity": "6.9"
                }]
            }]
        }]}"#;
        let f = parse_osv_scanner(json, Path::new("D:/Project/testbed"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].file, "backend/requirements.txt");
        assert_eq!(f[0].cve, vec!["CVE-2019-12781"]);
        // Unlike the OSV API, the scanner gives a score, not a vector: 6.9 = Medium.
        assert_eq!(f[0].severity, Severity::Medium);
        let pkg = f[0].package.as_ref().unwrap();
        assert_eq!(pkg.name, "django");
        assert_eq!(pkg.ecosystem, "PyPI");
    }

    #[test]
    fn osv_scanner_severity_comes_from_the_matching_group() {
        // Severity is reported per group of aliased ids, not per vulnerability;
        // picking the wrong group would mislabel the finding.
        let json = r#"{"results":[{
            "source": {"path": "req.txt"},
            "packages": [{
                "package": {"name": "p", "version": "1", "ecosystem": "PyPI"},
                "vulnerabilities": [
                    {"id": "A-1", "summary": "a", "aliases": []},
                    {"id": "B-2", "summary": "b", "aliases": []}
                ],
                "groups": [
                    {"ids": ["A-1"], "max_severity": "9.8"},
                    {"ids": ["B-2"], "max_severity": "3.1"}
                ]
            }]
        }]}"#;
        let f = parse_osv_scanner(json, Path::new("D:/x"));
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[1].severity, Severity::Low);
    }

    #[test]
    fn parses_real_trufflehog_ndjson() {
        // Captured from: trufflehog filesystem . --json
        // Note: one object per line, not a JSON array.
        let out = r#"{"DetectorName":"Postgres","DetectorDescription":"Postgres credentials","Verified":false,"Raw":"postgresql://admin:hunter2@db:5432/prod","SourceMetadata":{"Data":{"Filesystem":{"file":"backend\\app.py","line":19}}}}
{"DetectorName":"Github","DetectorDescription":"GitHub token","Verified":true,"Raw":"ghp_realtoken","SourceMetadata":{"Data":{"Filesystem":{"file":"frontend/src/Profile.jsx","line":6}}}}"#;
        let f = parse_trufflehog(out, Path::new("D:/Project/testbed"));
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].file, "backend/app.py");
        assert_eq!(f[0].line, 19);
        assert_eq!(f[0].severity, Severity::High);

        // A verified secret is one TruffleHog authenticated with — it is live.
        assert_eq!(f[1].severity, Severity::Critical);
        assert!(f[1].title.contains("проверен"));

        // `Raw` holds the live credential and must never reach the report.
        for x in &f {
            let blob = format!("{} {} {}", x.snippet, x.title, x.description);
            assert!(!blob.contains("hunter2"), "raw secret leaked: {blob}");
            assert!(!blob.contains("ghp_realtoken"), "raw token leaked: {blob}");
        }
    }

    #[test]
    fn parses_real_npm_audit_output() {
        // Captured from: npm audit --json
        let json = r#"{"auditReportVersion":2,"vulnerabilities":{
            "axios": {
                "name": "axios",
                "severity": "high",
                "isDirect": true,
                "range": "<=0.31.1",
                "nodes": ["node_modules/axios"],
                "effects": [],
                "fixAvailable": {"name": "axios", "version": "0.21.4", "isSemVerMajor": false},
                "via": [{
                    "source": 1090049,
                    "name": "axios",
                    "dependency": "axios",
                    "title": "Axios vulnerable to Server-Side Request Forgery",
                    "url": "https://github.com/advisories/GHSA-4w2v-q235-vp99",
                    "severity": "moderate",
                    "cwe": ["CWE-918"],
                    "cvss": {"score": 5.9, "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}
                }]
            }
        }}"#;
        let f = parse_npm_audit(json, "frontend/package-lock.json");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "GHSA-4w2v-q235-vp99");
        assert_eq!(f[0].cwe, vec!["CWE-918"]);
        // The advisory's CVSS (5.9) must win over npm's coarser "high" label.
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].recommendation.contains("0.21.4"));
    }

    #[test]
    fn npm_audit_ignores_string_entries_in_via() {
        // `via` mixes advisory objects with plain package names for transitive
        // problems; only the objects carry an advisory.
        let json = r#"{"vulnerabilities":{
            "a": {"name":"a","severity":"high","range":"*","via":["b"],"fixAvailable":false}
        }}"#;
        assert!(parse_npm_audit(json, "package-lock.json").is_empty());
    }

    #[test]
    fn parses_real_trivy_output() {
        // Captured from: trivy fs --format json --scanners vuln,secret,misconfig
        let json = r#"{"Results":[{
            "Target": "backend/requirements.txt",
            "Class": "lang-pkgs",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2019-14234",
                "PkgName": "Django",
                "InstalledVersion": "2.2.0",
                "FixedVersion": "1.11.23, 2.1.11, 2.2.4",
                "Severity": "CRITICAL",
                "Title": "Django: SQL injection possibility in key and index lookups",
                "Description": "long text",
                "CweIDs": ["CWE-89"],
                "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-14234"
            }]
        }]}"#;
        let f = parse_trivy(json, Path::new("D:/Project/testbed"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cve, vec!["CVE-2019-14234"]);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].cwe, vec!["CWE-89"]);
        // Trivy lists every patched branch, not a single version.
        assert!(f[0].recommendation.contains("1.11.23, 2.1.11, 2.2.4"));
    }

    #[test]
    fn parses_trivy_misconfigurations_with_line_numbers() {
        let json = r#"{"Results":[{
            "Target": "Dockerfile",
            "Class": "config",
            "Misconfigurations": [{
                "ID": "DS002",
                "Title": "Image user should not be root",
                "Description": "Running containers with root is a bad practice",
                "Resolution": "Add USER to the Dockerfile",
                "Severity": "HIGH",
                "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
                "CauseMetadata": {"StartLine": 2, "EndLine": 2}
            }]
        }]}"#;
        let f = parse_trivy(json, Path::new("D:/x"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].line, 2);
        assert_eq!(f[0].category, "Инфраструктура");
        assert!(f[0].recommendation.contains("USER"));
    }

    #[test]
    fn malformed_tool_output_yields_nothing_rather_than_panicking() {
        assert!(parse_semgrep("not json", root()).is_empty());
        assert!(parse_bandit("", root()).is_empty());
        assert!(parse_cargo_audit("{}", "Cargo.lock").is_empty());
        assert!(parse_gitleaks("null", root()).is_empty());
    }

    #[test]
    fn absolute_paths_are_made_relative_to_scan_root() {
        let json = r#"{"results":[{"check_id":"r","path":"/proj/src/deep/a.py",
            "start":{"line":1,"col":1},"end":{"line":1,"col":2},
            "extra":{"message":"m","severity":"WARNING","lines":"x"}}]}"#;
        let f = parse_semgrep(json, root());
        assert_eq!(f[0].file, "src/deep/a.py");
    }

    // ---------------------------------------------------------------------
    // The samples below are verbatim excerpts of what the real tools printed
    // when run against the test project, not hand-written guesses at their
    // schema. Several parser bugs only surfaced once these were captured.
    // ---------------------------------------------------------------------

    #[test]
    fn normalises_every_path_shape_the_tools_emit() {
        let r = Path::new("D:/Project/testbed");
        // bandit: relative, backslashes, "./" prefix
        assert_eq!(rel(r, ".\\backend\\app.py"), "backend/app.py");
        // semgrep: relative, backslashes, leading dot-directory
        assert_eq!(rel(r, ".github\\workflows\\ci.yml"), ".github/workflows/ci.yml");
        // gitleaks: relative, forward slashes
        assert_eq!(rel(r, "frontend/src/Profile.jsx"), "frontend/src/Profile.jsx");
        // any tool may emit an absolute path
        assert_eq!(rel(r, "D:/Project/testbed/core/src/main.rs"), "core/src/main.rs");
    }

    #[test]
    fn parses_real_bandit_output() {
        // Captured from: bandit -r . -f json -q
        let json = r#"{"results":[{
            "code": "8 import os\n9 import pickle\n10 import random\n",
            "col_offset": 0,
            "end_col_offset": 13,
            "filename": ".\\backend\\app.py",
            "issue_confidence": "HIGH",
            "issue_cwe": {"id": 502, "link": "https://cwe.mitre.org/data/definitions/502.html"},
            "issue_severity": "LOW",
            "issue_text": "Consider possible security implications associated with pickle module.",
            "line_number": 9,
            "line_range": [9],
            "more_info": "https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b403-import-pickle",
            "test_id": "B403",
            "test_name": "blacklist"
        }]}"#;
        let f = parse_bandit(json, Path::new("D:/Project/testbed"));
        assert_eq!(f.len(), 1);
        // The "./" prefix and backslashes must be gone, or the finding never
        // attaches to its file in the tree.
        assert_eq!(f[0].file, "backend/app.py");
        assert_eq!(f[0].line, 9);
        assert_eq!(f[0].end_line, 9);
        assert_eq!(f[0].cwe, vec!["CWE-502"]);
        assert_eq!(f[0].severity, Severity::Low);
        // Bandit's own line-number prefixes must not reach our gutter.
        assert_eq!(f[0].snippet, "import os\nimport pickle\nimport random");
        assert_eq!(f[0].snippet_start_line, 9);
    }

    #[test]
    fn bandit_multi_line_range_sets_span_from_line_range() {
        let json = r#"{"results":[{
            "code": "30 def f():\n31     pass\n",
            "filename": ".\\a.py",
            "issue_confidence": "MEDIUM",
            "issue_severity": "MEDIUM",
            "issue_text": "x",
            "line_number": 30,
            "line_range": [30, 31, 32],
            "test_id": "B101",
            "test_name": "assert_used"
        }]}"#;
        let f = parse_bandit(json, Path::new("D:/x"));
        assert_eq!(f[0].line, 30);
        assert_eq!(f[0].end_line, 32);
        assert_eq!(f[0].snippet_start_line, 30);
    }

    #[test]
    fn parses_real_semgrep_output() {
        // Captured from: semgrep scan --config=auto --json --quiet
        let json = r#"{"results":[{
            "check_id": "yaml.github-actions.security.pull-request-target-code-checkout.pull-request-target-code-checkout",
            "path": ".github\\workflows\\ci.yml",
            "start": {"line": 9, "col": 9, "offset": 118},
            "end": {"line": 9, "col": 34, "offset": 143},
            "extra": {
                "engine_kind": "OSS",
                "fingerprint": "abc",
                "lines": "        ref: ${{ github.event.pull_request.head.sha }}",
                "message": "Using `pull_request_target` with an explicit checkout is dangerous.",
                "severity": "WARNING",
                "validation_state": "NO_VALIDATOR",
                "metadata": {
                    "category": "security",
                    "confidence": "HIGH",
                    "cwe": ["CWE-1357: Reliance on Insufficiently Trustworthy Component", "CWE-353: Missing Support for Integrity Check"],
                    "owasp": ["A08:2021 - Software and Data Integrity Failures", "A08:2025 - Software and Data Integrity Failures"],
                    "references": ["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"],
                    "technology": ["github-actions"]
                }
            }
        }]}"#;
        let f = parse_semgrep(json, Path::new("D:/Project/testbed"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].file, ".github/workflows/ci.yml");
        assert_eq!(f[0].line, 9);
        assert_eq!(f[0].severity, Severity::Medium); // WARNING
        assert_eq!(f[0].cwe.len(), 2);
        // metadata.owasp is a list; we surface the first entry.
        assert_eq!(
            f[0].owasp.as_deref(),
            Some("A08:2021 - Software and Data Integrity Failures")
        );
    }

    #[test]
    fn parses_real_cargo_audit_output_and_uses_its_cvss() {
        // Captured from: cargo audit --json (time 0.1.44)
        let json = r#"{"vulnerabilities":{"found":true,"count":1,"list":[{
            "advisory": {
                "id": "RUSTSEC-2020-0071",
                "title": "Potential segfault in the time crate",
                "description": "Unix-like operating systems may segfault due to dereferencing a dangling pointer.",
                "aliases": ["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"],
                "url": "https://github.com/time-rs/time/issues/293",
                "categories": ["code-execution", "memory-corruption"],
                "cvss": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "withdrawn": null
            },
            "package": {"name": "time", "version": "0.1.44", "source": "registry+https://github.com/rust-lang/crates.io-index", "checksum": null},
            "versions": {"patched": [">=0.2.23"], "unaffected": ["=0.2.0"]},
            "affected": null
        }]}}"#;
        let f = parse_cargo_audit(json, "Cargo.lock");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cve, vec!["CVE-2020-26235"]);
        // This vector scores 5.5, so a blanket "High" would misreport it.
        assert_eq!(f[0].severity, Severity::Medium);
        // The ">=" operator must not leak into the recommendation text.
        assert!(
            f[0].recommendation.contains("0.2.23") && !f[0].recommendation.contains(">="),
            "got: {}",
            f[0].recommendation
        );
        assert_eq!(f[0].package.as_ref().unwrap().fixed_version.as_deref(), Some("0.2.23"));
    }

    #[test]
    fn cargo_audit_without_cvss_falls_back_to_high() {
        let json = r#"{"vulnerabilities":{"count":1,"list":[{
            "advisory": {"id":"RUSTSEC-0000-0000","title":"t","description":"d","aliases":[],"categories":[]},
            "package": {"name":"p","version":"1.0.0"},
            "versions": {"patched":[]}
        }]}}"#;
        let f = parse_cargo_audit(json, "Cargo.lock");
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].recommendation.contains("Исправленной версии нет"));
    }

    #[test]
    fn parses_real_gitleaks_output() {
        // Captured from: gitleaks detect --no-git --report-format json
        let json = r#"[{
            "RuleID": "github-pat",
            "Description": "Uncovered a GitHub Personal Access Token.",
            "StartLine": 6,
            "EndLine": 6,
            "StartColumn": 24,
            "EndColumn": 63,
            "Match": "ghp_kJ8m2NpQ4rT7sV1wXy3zAb6cDe9fGh0iJk2L",
            "Secret": "ghp_kJ8m2NpQ4rT7sV1wXy3zAb6cDe9fGh0iJk2L",
            "File": "frontend/src/Profile.jsx",
            "Entropy": 5.071928,
            "Tags": [],
            "Fingerprint": "frontend/src/Profile.jsx:github-pat:6"
        }]"#;
        let f = parse_gitleaks(json, Path::new("D:/Project/testbed"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].file, "frontend/src/Profile.jsx");
        assert_eq!(f[0].line, 6);
        // The raw token must never survive into the report.
        assert!(!f[0].snippet.contains("kJ8m2NpQ4rT7sV1wXy3zAb6cDe9fGh0iJk2L"));
    }
}
