import type {
  Finding,
  ScanReport,
  Severity,
  Confidence,
  FindingSource,
  AppSettings,
} from "./types";

/**
 * A sample report for previewing the results UI outside Tauri.
 *
 * The real report only exists after a backend scan, so the whole results
 * surface — dashboard, findings, code, skipped — is invisible in a plain
 * browser during frontend work. This fixture fills that gap. It is loaded only
 * when `import.meta.env.DEV` is set and Tauri is absent, so it never reaches a
 * production bundle. Titles are real catalogue strings, so the English
 * translation renders too.
 */

function finding(f: Partial<Finding> & Pick<Finding, "ruleId" | "title" | "severity" | "file" | "line">): Finding {
  return {
    id: f.id ?? f.ruleId + ":" + f.file + ":" + f.line,
    fingerprint: f.fingerprint ?? f.ruleId + "@" + f.file,
    suppressed: false,
    suppressionReason: null,
    isNew: false,
    description: "",
    recommendation: "",
    confidence: "high" as Confidence,
    source: "builtin" as FindingSource,
    sourceLabel: "Сканирование кода",
    category: "Инъекция команд",
    endLine: f.line ?? 0,
    column: 0,
    endColumn: 0,
    snippet: "",
    snippetStartLine: f.line ?? 0,
    cwe: [],
    owasp: null,
    cve: [],
    references: [],
    package: null,
    ...f,
  };
}

const findings: Finding[] = [
  finding({
    ruleId: "VS-PY-003",
    title: "subprocess с shell=True",
    description: "shell=True запускает команду через системный шелл, поэтому метасимволы в аргументах интерпретируются. Подстановка пользовательских данных даёт инъекцию команд.",
    recommendation: "Уберите shell=True и передавайте команду списком аргументов: subprocess.run([\"ls\", \"-l\", path]).",
    severity: "critical",
    category: "Инъекция команд",
    file: "app/tasks.py",
    line: 42,
    endLine: 42,
    cwe: ["CWE-78"],
    owasp: "A03:2021 – Injection",
    snippet: "    subprocess.run(cmd, shell=True)",
    snippetStartLine: 42,
    isNew: true,
  }),
  finding({
    ruleId: "VS-SEC-003",
    title: "GitHub Personal Access Token",
    description: "Токен GitHub даёт доступ к репозиториям владельца в объёме своих scope.",
    recommendation: "Отзовите токен в Settings → Developer settings.",
    severity: "critical",
    source: "secrets",
    sourceLabel: "Поиск секретов",
    category: "Секрет в коде",
    file: ".env",
    line: 3,
    endLine: 3,
    cwe: ["CWE-798"],
    snippet: "GITHUB_TOKEN=ghp_****************************",
    snippetStartLine: 3,
    isNew: true,
  }),
  finding({
    ruleId: "VS-JS-004",
    title: "Присваивание в innerHTML / outerHTML",
    description: "Запись в innerHTML вставляет строку как HTML. Если в неё попадают данные пользователя — это XSS.",
    recommendation: "Используйте textContent или очищайте разметку через DOMPurify.",
    severity: "high",
    sourceLabel: "Сканирование кода",
    category: "XSS",
    file: "web/render.js",
    line: 88,
    endLine: 88,
    cwe: ["CWE-79"],
    owasp: "A03:2021 – Injection",
    snippet: "  el.innerHTML = user.bio",
    snippetStartLine: 88,
  }),
  finding({
    ruleId: "VS-GO-004",
    title: "Слабый хеш (MD5/SHA-1)",
    description: "MD5 и SHA-1 уязвимы к коллизиям и не годятся для подписей и проверки целостности.",
    recommendation: "Используйте sha256.New().",
    severity: "medium",
    sourceLabel: "Сканирование кода",
    category: "Криптография",
    file: "internal/auth/hash.go",
    line: 15,
    endLine: 15,
    cwe: ["CWE-327"],
    snippet: "\th := md5.New()",
    snippetStartLine: 15,
  }),
  finding({
    ruleId: "VS-TF-004",
    title: "Секрет в открытом виде в конфигурации",
    description: "Пароли и ключи в .tf попадают в репозиторий и в state-файл.",
    recommendation: "Используйте переменные с sensitive = true.",
    severity: "low",
    sourceLabel: "Сканирование кода",
    category: "Секрет в коде",
    file: "infra/main.tf",
    line: 27,
    endLine: 27,
    cwe: ["CWE-798"],
    snippet: "  password = \"hunter2\"",
    snippetStartLine: 27,
  }),
];

const counts = { critical: 2, high: 1, medium: 1, low: 1, info: 0 };

function fileSummary(path: string, language: string, label: string, lines: number, c: Partial<typeof counts>, maxSev: Severity | null) {
  return {
    path,
    language,
    languageLabel: label,
    size: lines * 32,
    lines,
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, ...c },
    maxSeverity: maxSev,
  };
}

export const DEMO_REPORT: ScanReport = {
  id: "demo-1",
  root: "D:/Project/demo-app",
  targetLabel: "demo-app",
  startedAt: new Date(Date.now() - 4200).toISOString(),
  finishedAt: new Date().toISOString(),
  durationMs: 4200,
  cancelled: false,
  delta: {
    previousScanAt: new Date(Date.now() - 86400000).toISOString(),
    newCount: 2,
    fixedCount: 1,
    unchangedCount: 3,
    fixed: [
      { fingerprint: "old-1", ruleId: "VS-PY-001", title: "Вызов eval() с динамическими данными", file: "app/legacy.py", severity: "high" },
    ],
    newBySeverity: { critical: 2 },
  },
  suppressedCount: 1,
  findings,
  files: [
    fileSummary("app/tasks.py", "python", "Python", 210, { critical: 1 }, "critical"),
    fileSummary(".env", "env", "Env", 8, { critical: 1 }, "critical"),
    fileSummary("web/render.js", "javascript", "JavaScript", 140, { high: 1 }, "high"),
    fileSummary("internal/auth/hash.go", "go", "Go", 60, { medium: 1 }, "medium"),
    fileSummary("infra/main.tf", "terraform", "Terraform", 45, { low: 1 }, "low"),
  ],
  skipped: [
    { path: "node_modules/react/index.js", reason: "vendor", reasonLabel: "Вендор-директория", size: 4200 },
    { path: "assets/logo.png", reason: "binary", reasonLabel: "Бинарный файл", size: 88000 },
  ],
  counts,
  filesScanned: 214,
  filesSkipped: 1320,
  linesScanned: 41230,
  bytesScanned: 1_320_000,
  languages: [
    { language: "python", label: "Python", files: 96, lines: 18400 },
    { language: "javascript", label: "JavaScript", files: 74, lines: 15200 },
    { language: "go", label: "Go", files: 28, lines: 5400 },
    { language: "terraform", label: "Terraform", files: 16, lines: 2230 },
  ],
  dependenciesChecked: 312,
  enginesUsed: ["Встроенные правила", "Поиск секретов", "OSV.dev"],
  warnings: [],
};

/**
 * Settings for the same preview: parts of the UI only render with settings
 * loaded (the open-in-editor button keys off editorCommand), and outside Tauri
 * get_settings rejects, leaving them invisible forever. Mirrors the backend
 * defaults.
 */
export const DEMO_SETTINGS: AppSettings = {
  maxFileSizeMb: 2,
  minifiedLineLen: 2000,
  maxFindingsPerFile: 200,
  defaultRespectGitignore: true,
  defaultIncludeVendor: false,
  defaultCheckSecrets: true,
  defaultCheckDependencies: true,
  osvCacheDays: 7,
  osvConcurrency: 16,
  language: "ru",
  accent: "#5b8def",
  themePreset: "night",
  theme: {},
  density: "comfortable",
  reduceMotion: false,
  a11yUiScale: 100,
  a11yAlwaysFocus: false,
  a11yNoAmbient: false,
  a11ySeverityText: false,
  a11yUnderlineLinks: false,
  a11yBigTargets: false,
  maxHighlightLines: 6000,
  skipNoisyInTests: true,
  ignoreComments: true,
  followSymlinks: false,
  maxDepth: 0,
  excludeGlobs: "",
  enableBlame: true,
  blameMaxFiles: 800,
  offline: false,
  externalTimeoutSecs: 300,
  historyCap: 60,
  reportOrg: "",
  defaultExportFormat: "json",
  codeFontSize: 13,
  tabWidth: 4,
  wrapCodeLines: false,
  editorCommand: "code -g {file}:{line}",
  keybinds: {},
};
