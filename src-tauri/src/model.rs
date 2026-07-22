use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Maps a CVSS v3 base score onto our severity ladder.
    pub fn from_cvss(score: f32) -> Severity {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn from_label(label: &str) -> Severity {
        match label.to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" | "error" => Severity::High,
            "moderate" | "medium" | "warning" => Severity::Medium,
            "low" | "note" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Jsx,
    Tsx,
    Go,
    Java,
    Kotlin,
    Scala,
    Php,
    Ruby,
    CSharp,
    C,
    Cpp,
    Swift,
    Shell,
    PowerShell,
    Perl,
    Lua,
    Elixir,
    Sql,
    Html,
    Vue,
    Svelte,
    Yaml,
    Json,
    Toml,
    Xml,
    Ini,
    Dockerfile,
    Terraform,
    Kubernetes,
    GraphQL,
    Env,
    Nginx,
    Makefile,
    Other,
}

impl Language {
    pub fn from_path(path: &std::path::Path) -> Language {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // Filename-driven types, checked before extensions because several of
        // these have no extension at all.
        if name == "dockerfile" || name.starts_with("dockerfile.") || name.ends_with(".dockerfile") {
            return Language::Dockerfile;
        }
        if name == ".env" || name.starts_with(".env.") {
            return Language::Env;
        }
        if name == "makefile" || name == "gnumakefile" || name.ends_with(".mk") {
            return Language::Makefile;
        }
        if name == "nginx.conf" || name.ends_with(".nginx") {
            return Language::Nginx;
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // Kubernetes manifests are YAML but need their own rules, and telling
        // them apart by name is the only cheap signal available here.
        if matches!(ext.as_str(), "yml" | "yaml")
            && (name.contains("deployment")
                || name.contains("statefulset")
                || name.contains("daemonset")
                || name.contains("pod")
                || name.contains("k8s")
                || name.contains("kube"))
        {
            return Language::Kubernetes;
        }

        match ext.as_str() {
            "rs" => Language::Rust,
            "py" | "pyw" | "pyi" => Language::Python,
            "js" | "mjs" | "cjs" => Language::JavaScript,
            "ts" | "mts" | "cts" => Language::TypeScript,
            "jsx" => Language::Jsx,
            "tsx" => Language::Tsx,
            "go" => Language::Go,
            "java" => Language::Java,
            "kt" | "kts" => Language::Kotlin,
            "scala" | "sc" => Language::Scala,
            "php" | "phtml" | "php3" | "php4" | "php5" | "phps" => Language::Php,
            "rb" | "rake" | "gemspec" => Language::Ruby,
            "cs" | "csx" => Language::CSharp,
            "c" | "h" => Language::C,
            "cc" | "cpp" | "cxx" | "c++" | "hpp" | "hxx" | "hh" | "ipp" => Language::Cpp,
            "swift" => Language::Swift,
            "sh" | "bash" | "zsh" | "ksh" | "ash" => Language::Shell,
            "ps1" | "psm1" | "psd1" => Language::PowerShell,
            "pl" | "pm" | "t" => Language::Perl,
            "lua" => Language::Lua,
            "ex" | "exs" => Language::Elixir,
            "sql" | "psql" | "mysql" => Language::Sql,
            "html" | "htm" | "xhtml" => Language::Html,
            "vue" => Language::Vue,
            "svelte" => Language::Svelte,
            "yml" | "yaml" => Language::Yaml,
            "json" | "jsonc" | "json5" => Language::Json,
            "toml" => Language::Toml,
            "xml" | "xsd" | "xsl" | "plist" => Language::Xml,
            "ini" | "cfg" | "conf" | "properties" => Language::Ini,
            "tf" | "tfvars" | "hcl" => Language::Terraform,
            "graphql" | "gql" => Language::GraphQL,
            _ => Language::Other,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Language::Rust => "Rust",
            Language::Python => "Python",
            Language::JavaScript => "JavaScript",
            Language::TypeScript => "TypeScript",
            Language::Jsx => "JSX",
            Language::Tsx => "TSX",
            Language::Go => "Go",
            Language::Java => "Java",
            Language::Kotlin => "Kotlin",
            Language::Scala => "Scala",
            Language::Php => "PHP",
            Language::Ruby => "Ruby",
            Language::CSharp => "C#",
            Language::C => "C",
            Language::Cpp => "C++",
            Language::Swift => "Swift",
            Language::Shell => "Shell",
            Language::PowerShell => "PowerShell",
            Language::Perl => "Perl",
            Language::Lua => "Lua",
            Language::Elixir => "Elixir",
            Language::Sql => "SQL",
            Language::Html => "HTML",
            Language::Vue => "Vue",
            Language::Svelte => "Svelte",
            Language::Yaml => "YAML",
            Language::Json => "JSON",
            Language::Toml => "TOML",
            Language::Xml => "XML",
            Language::Ini => "Config",
            Language::Dockerfile => "Dockerfile",
            Language::Terraform => "Terraform",
            Language::Kubernetes => "Kubernetes",
            Language::GraphQL => "GraphQL",
            Language::Env => "Env",
            Language::Nginx => "Nginx",
            Language::Makefile => "Makefile",
            Language::Other => "Other",
        }
    }

    /// Every language the engine can label, for the rule editor's picker.
    pub const ALL: &'static [Language] = &[
        Language::Rust,
        Language::Python,
        Language::JavaScript,
        Language::TypeScript,
        Language::Jsx,
        Language::Tsx,
        Language::Go,
        Language::Java,
        Language::Kotlin,
        Language::Scala,
        Language::Php,
        Language::Ruby,
        Language::CSharp,
        Language::C,
        Language::Cpp,
        Language::Swift,
        Language::Shell,
        Language::PowerShell,
        Language::Perl,
        Language::Lua,
        Language::Elixir,
        Language::Sql,
        Language::Html,
        Language::Vue,
        Language::Svelte,
        Language::Yaml,
        Language::Json,
        Language::Toml,
        Language::Xml,
        Language::Ini,
        Language::Dockerfile,
        Language::Terraform,
        Language::Kubernetes,
        Language::GraphQL,
        Language::Env,
        Language::Nginx,
        Language::Makefile,
        Language::Other,
    ];

    /// Parses the serialised form used in user rule files.
    pub fn from_id(s: &str) -> Option<Language> {
        let want = s.trim().to_ascii_lowercase();
        Language::ALL.iter().copied().find(|l| l.id() == want)
    }

    /// Stable lowercase identifier, matching the serde representation.
    pub fn id(self) -> &'static str {
        match self {
            Language::Rust => "rust",
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::TypeScript => "typescript",
            Language::Jsx => "jsx",
            Language::Tsx => "tsx",
            Language::Go => "go",
            Language::Java => "java",
            Language::Kotlin => "kotlin",
            Language::Scala => "scala",
            Language::Php => "php",
            Language::Ruby => "ruby",
            Language::CSharp => "csharp",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::Swift => "swift",
            Language::Shell => "shell",
            Language::PowerShell => "powershell",
            Language::Perl => "perl",
            Language::Lua => "lua",
            Language::Elixir => "elixir",
            Language::Sql => "sql",
            Language::Html => "html",
            Language::Vue => "vue",
            Language::Svelte => "svelte",
            Language::Yaml => "yaml",
            Language::Json => "json",
            Language::Toml => "toml",
            Language::Xml => "xml",
            Language::Ini => "ini",
            Language::Dockerfile => "dockerfile",
            Language::Terraform => "terraform",
            Language::Kubernetes => "kubernetes",
            Language::GraphQL => "graphql",
            Language::Env => "env",
            Language::Nginx => "nginx",
            Language::Makefile => "makefile",
            Language::Other => "other",
        }
    }
}

/// Where a finding came from, so the UI can badge it and users can tell
/// built-in heuristics apart from third-party tool output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSource {
    Builtin,
    Custom,
    Secrets,
    Osv,
    Semgrep,
    Bandit,
    CargoAudit,
    Gitleaks,
    NpmAudit,
    OsvScanner,
    Hadolint,
    Ruff,
    Trivy,
    Trufflehog,
    Checkov,
    Gosec,
    Grype,
}

impl FindingSource {
    pub fn label(self) -> &'static str {
        match self {
            FindingSource::Builtin => "Встроенные правила",
            FindingSource::Custom => "Своё правило",
            FindingSource::Secrets => "Поиск секретов",
            FindingSource::Osv => "OSV.dev",
            FindingSource::Semgrep => "Semgrep",
            FindingSource::Bandit => "Bandit",
            FindingSource::CargoAudit => "cargo-audit",
            FindingSource::Gitleaks => "Gitleaks",
            FindingSource::NpmAudit => "npm audit",
            FindingSource::OsvScanner => "osv-scanner",
            FindingSource::Hadolint => "Hadolint",
            FindingSource::Ruff => "Ruff",
            FindingSource::Trivy => "Trivy",
            FindingSource::Trufflehog => "TruffleHog",
            FindingSource::Checkov => "Checkov",
            FindingSource::Gosec => "gosec",
            FindingSource::Grype => "Grype",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    /// Stable identity across scans; see `baseline::fingerprint`. Empty until
    /// the scanner assigns it.
    #[serde(default)]
    pub fingerprint: String,
    /// True when this finding is listed in the project's .vulnscope-ignore.
    #[serde(default)]
    pub suppressed: bool,
    /// Why it was suppressed, shown so a silenced finding is never a mystery.
    #[serde(default)]
    pub suppression_reason: Option<String>,
    /// True when absent from the previous scan of this target.
    #[serde(default)]
    pub is_new: bool,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub source: FindingSource,
    pub source_label: String,
    pub category: String,

    /// Path relative to the scan root, using forward slashes.
    pub file: String,
    pub line: u32,
    pub end_line: u32,
    pub column: u32,
    pub end_column: u32,
    /// The offending line plus a little context, for the code preview.
    pub snippet: String,
    pub snippet_start_line: u32,

    pub cwe: Vec<String>,
    pub owasp: Option<String>,
    pub cve: Vec<String>,
    pub references: Vec<String>,

    /// Extra developer-facing detail (exploitation example, consequences,
    /// concrete fix, sink corroboration) attached to select high-value findings.
    #[serde(default)]
    pub extra: Option<FindingExtra>,

    /// Set for dependency findings only.
    pub package: Option<PackageInfo>,
}

/// Actionable detail beyond the base rule text, populated for select rules.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FindingExtra {
    /// Concrete attacker input and its effect on the query/logic.
    #[serde(default)]
    pub exploit: Option<String>,
    /// Bullet-point consequences, most severe first.
    #[serde(default)]
    pub impact: Vec<String>,
    /// A ready-to-paste remediation snippet, more concrete than the prose fix.
    #[serde(default)]
    pub fix_code: Option<String>,
    /// True when a corroborating sink was found in the same file, which raised
    /// this finding's confidence above the rule's baseline.
    #[serde(default)]
    pub corroborated: bool,
    /// True for experimental (BETA) heuristic findings: a *suspected* issue the
    /// precise rule catalogue did not catch, surfaced for review rather than as
    /// a confirmed defect.
    #[serde(default)]
    pub experimental: bool,
    /// True for a synthesized "dangerous combination": several suspected issues
    /// in one file that amplify each other into a likely exploit chain.
    #[serde(default)]
    pub combination: bool,
    /// The individual issues this combination links, each with its own line and
    /// source code, so the reviewer sees every link of the chain.
    #[serde(default)]
    pub combine_spots: Vec<CombineSpot>,
    /// A traced data-flow path (source → propagation → sink) for findings from
    /// the taint engine. Each spot's `category` holds the step's role label.
    #[serde(default)]
    pub flow: Vec<CombineSpot>,
    /// True when this finding sits on a data-flow path the taint engine traced
    /// from untrusted input — i.e. it is reachable by an attacker, not just
    /// present. Drives prioritisation and the security score.
    #[serde(default)]
    pub on_data_path: bool,
    /// For a data-flow finding, where the untrusted data enters — "HTTP-запрос",
    /// "аргумент командной строки", etc. Powers the attack-paths panel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
}

/// One link of a dangerous combination: a category, the line it sits on, and
/// the source of that line.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CombineSpot {
    pub category: String,
    pub line: u32,
    pub code: String,
    /// The file this step is in, when it differs from the finding's own file —
    /// set on a data-flow step that crossed into a callee in another file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub fixed_version: Option<String>,
}

/// A file we deliberately did not analyse, and why. Surfaced in the UI so the
/// user can see coverage rather than silently trusting a clean result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedFile {
    pub path: String,
    pub reason: SkipReason,
    pub reason_label: String,
    pub size: u64,
}

impl SkippedFile {
    pub fn new(path: String, reason: SkipReason, size: u64) -> SkippedFile {
        SkippedFile {
            path,
            reason,
            reason_label: reason.label().to_string(),
            size,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SkipReason {
    /// Compiled artefact or other non-source binary: .exe, .dll, .so, .bin, ...
    BinaryExtension,
    /// Extension looked fine but the bytes are not text (NUL bytes / invalid UTF-8).
    BinaryContent,
    Media,
    Archive,
    TooLarge,
    Minified,
    VendorDirectory,
    LockfileOnly,
    ReadError,
}

impl SkipReason {
    pub fn label(self) -> &'static str {
        match self {
            SkipReason::BinaryExtension => "Бинарный файл (нечего анализировать)",
            SkipReason::BinaryContent => "Содержимое не является текстом",
            SkipReason::Media => "Медиафайл",
            SkipReason::Archive => "Архив",
            SkipReason::TooLarge => "Файл слишком большой",
            SkipReason::Minified => "Минифицированный или сгенерированный код",
            SkipReason::VendorDirectory => "Сторонние зависимости (vendor)",
            SkipReason::LockfileOnly => "Lock-файл: проверен только на CVE",
            SkipReason::ReadError => "Не удалось прочитать файл",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl SeverityCounts {
    pub fn add(&mut self, s: Severity) {
        match s {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }

    pub fn total(&self) -> u32 {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// Per-file rollup that drives the red markers in the file tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSummary {
    pub path: String,
    pub language: Language,
    pub language_label: String,
    pub size: u64,
    pub lines: u32,
    pub counts: SeverityCounts,
    pub max_severity: Option<Severity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub id: String,
    pub root: String,
    pub target_label: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,

    /// True when the user stopped the scan. An empty finding list then means
    /// "not checked", not "nothing found" — the UI must not present it as clean.
    pub cancelled: bool,

    /// What changed since the previous scan of this target.
    pub delta: crate::baseline::ScanDelta,
    /// Suppressed findings are excluded from `counts` but kept here, so a
    /// silenced problem is auditable rather than invisible.
    pub suppressed_count: u32,

    pub findings: Vec<Finding>,
    pub files: Vec<FileSummary>,
    pub skipped: Vec<SkippedFile>,

    pub counts: SeverityCounts,
    pub files_scanned: u32,
    pub files_skipped: u32,
    pub lines_scanned: u64,
    pub bytes_scanned: u64,

    pub languages: Vec<LanguageStat>,
    pub dependencies_checked: u32,
    pub engines_used: Vec<String>,
    /// Non-fatal problems worth showing (OSV offline, tool crashed, ...).
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LanguageStat {
    pub language: Language,
    pub label: String,
    pub files: u32,
    pub lines: u64,
}

/// Streamed to the UI during a scan to drive the progress bar and ETA.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub scan_id: String,
    pub phase: ScanPhase,
    pub phase_label: String,
    pub current_file: String,
    pub processed: u32,
    pub total: u32,
    pub findings_so_far: u32,
    pub elapsed_ms: u64,
    /// `None` until we have enough samples to extrapolate honestly.
    pub eta_ms: Option<u64>,
    pub files_per_sec: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanPhase {
    Preparing,
    Cloning,
    Discovering,
    ScanningCode,
    ResolvingDependencies,
    QueryingOsv,
    RunningExternalTools,
    Finalizing,
    Done,
    Cancelled,
    Failed,
}

impl ScanPhase {
    pub fn label(self) -> &'static str {
        match self {
            ScanPhase::Preparing => "Подготовка",
            ScanPhase::Cloning => "Клонирование репозитория",
            ScanPhase::Discovering => "Поиск файлов",
            ScanPhase::ScanningCode => "Анализ кода",
            ScanPhase::ResolvingDependencies => "Разбор зависимостей",
            ScanPhase::QueryingOsv => "Запрос базы CVE (OSV.dev)",
            ScanPhase::RunningExternalTools => "Внешние сканеры",
            ScanPhase::Finalizing => "Формирование отчёта",
            ScanPhase::Done => "Готово",
            ScanPhase::Cancelled => "Отменено",
            ScanPhase::Failed => "Ошибка",
        }
    }
}
