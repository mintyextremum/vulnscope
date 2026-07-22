export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "low" | "medium" | "high";

export interface AppSettings {
  maxFileSizeMb: number;
  minifiedLineLen: number;
  maxFindingsPerFile: number;
  defaultRespectGitignore: boolean;
  defaultIncludeVendor: boolean;
  defaultCheckSecrets: boolean;
  defaultCheckDependencies: boolean;
  osvCacheDays: number;
  osvConcurrency: number;
  /** UI language: "ru" | "en". */
  language: string;
  accent: string;
  /** Id of the preset the theme is based on; see theme-tokens.ts. */
  themePreset: string;
  /** Token id (without `--`) → CSS colour. Only what differs from the preset. */
  theme: Record<string, string>;
  density: string;
  reduceMotion: boolean;
  /** Interface zoom, percent. */
  a11yUiScale: number;
  a11yAlwaysFocus: boolean;
  a11yNoAmbient: boolean;
  a11ySeverityText: boolean;
  a11yUnderlineLinks: boolean;
  a11yBigTargets: boolean;
  maxHighlightLines: number;
  skipNoisyInTests: boolean;
  ignoreComments: boolean;
  /** Editor command with {file}/{line} placeholders; empty disables the button. */
  editorCommand: string;
  /** Action id -> key combo, e.g. "palette" -> "mod+k". */
  keybinds: Record<string, string>;
}

export interface KeybindAction {
  id: string;
  label: string;
  group: string;
}

export interface KeybindConflict {
  action: string;
  otherAction: string;
  combo: string;
}

export interface UserRule {
  id: string;
  title: string;
  description: string;
  recommendation: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  /** Language ids; empty means every text file. */
  languages: string[];
  pattern: string;
  unlessContains: string[];
  cwe: string[];
  owasp: string | null;
  references: string[];
  skipInTests: boolean;
  enabled: boolean;
}

export interface ValidationIssue {
  field: string;
  message: string;
}

export interface TestMatch {
  line: number;
  text: string;
  matched: string;
  /** True when `unlessContains` suppressed an otherwise-matching line. */
  suppressed: boolean;
}

export interface RuleTestResult {
  ok: boolean;
  error: string | null;
  matches: TestMatch[];
}

export interface LanguageOption {
  id: string;
  label: string;
}

export type FindingSource =
  | "builtin"
  | "custom"
  | "secrets"
  | "osv"
  | "semgrep"
  | "bandit"
  | "cargoaudit"
  | "gitleaks"
  | "npmaudit"
  | "checkov"
  | "gosec"
  | "grype";

export interface PackageInfo {
  name: string;
  version: string;
  ecosystem: string;
  fixedVersion: string | null;
}

export interface ScanDelta {
  /** null on the first scan of a target: "0 new" would be a lie. */
  previousScanAt: string | null;
  newCount: number;
  fixedCount: number;
  unchangedCount: number;
  fixed: FixedFinding[];
  newBySeverity: Record<string, number>;
}

export interface FixedFinding {
  fingerprint: string;
  ruleId: string;
  title: string;
  file: string;
  severity: Severity;
}

export interface Suppression {
  fingerprint: string;
  ruleId: string;
  file: string;
  wholeFile: boolean;
  reason: string;
  createdAt: string;
}

export interface Finding {
  id: string;
  /** Stable identity across scans; survives line shifts and reindentation. */
  fingerprint: string;
  suppressed: boolean;
  suppressionReason: string | null;
  isNew: boolean;
  ruleId: string;
  title: string;
  description: string;
  recommendation: string;
  severity: Severity;
  confidence: Confidence;
  source: FindingSource;
  sourceLabel: string;
  category: string;
  file: string;
  line: number;
  endLine: number;
  column: number;
  endColumn: number;
  snippet: string;
  snippetStartLine: number;
  cwe: string[];
  owasp: string | null;
  cve: string[];
  references: string[];
  extra?: FindingExtra | null;
  package: PackageInfo | null;
}

/** Actionable detail beyond the base rule text, present on select findings. */
export interface FindingExtra {
  exploit: string | null;
  impact: string[];
  fixCode: string | null;
  /** A corroborating sink was found in the same file, raising confidence. */
  corroborated: boolean;
  /** Experimental (BETA) heuristic finding: a suspected issue for review. */
  experimental?: boolean;
  /** A synthesized "dangerous combination": several suspected issues that
   * amplify each other into a likely exploit chain. */
  combination?: boolean;
  /** The individual issues this combination links, each with its own line and
   * source code. */
  combineSpots?: CombineSpot[];
  /** A traced data-flow path (source → propagation → sink). Each spot's
   * `category` holds the step's role label. */
  flow?: CombineSpot[];
  /** This finding sits on a data-flow path the taint engine traced from
   * untrusted input — reachable by an attacker, not merely present. */
  onDataPath?: boolean;
  /** For a data-flow finding, where the untrusted data enters (a Russian label
   * like "HTTP-запрос"), translated at the call site. */
  entry?: string | null;
}

/** One link of a dangerous combination or a data-flow step. */
export interface CombineSpot {
  category: string;
  line: number;
  code: string;
  /** Set on a data-flow step that crossed into a callee in another file; the
   *  step then points there instead of at the finding's own file. */
  file?: string | null;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface FileSummary {
  path: string;
  language: string;
  languageLabel: string;
  size: number;
  lines: number;
  counts: SeverityCounts;
  maxSeverity: Severity | null;
}

export interface SkippedFile {
  path: string;
  reason: string;
  reasonLabel: string;
  size: number;
}

export interface LanguageStat {
  language: string;
  label: string;
  files: number;
  lines: number;
}

export interface ScanReport {
  id: string;
  root: string;
  targetLabel: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  /** True when the user stopped the scan: an empty result means "not checked". */
  cancelled: boolean;
  delta: ScanDelta;
  suppressedCount: number;
  findings: Finding[];
  files: FileSummary[];
  skipped: SkippedFile[];
  counts: SeverityCounts;
  filesScanned: number;
  filesSkipped: number;
  linesScanned: number;
  bytesScanned: number;
  languages: LanguageStat[];
  dependenciesChecked: number;
  enginesUsed: string[];
  warnings: string[];
}

export type ScanPhase =
  | "preparing"
  | "cloning"
  | "discovering"
  | "scanningCode"
  | "scanningSecrets"
  | "resolvingDependencies"
  | "queryingOsv"
  | "runningExternalTools"
  | "finalizing"
  | "done"
  | "cancelled"
  | "failed";

export interface ScanProgress {
  scanId: string;
  phase: ScanPhase;
  phaseLabel: string;
  currentFile: string;
  processed: number;
  total: number;
  findingsSoFar: number;
  elapsedMs: number;
  etaMs: number | null;
  filesPerSec: number;
}

export type ToolId =
  | "semgrep"
  | "bandit"
  | "cargo-audit"
  | "gitleaks"
  | "osv-scanner"
  | "trivy"
  | "checkov"
  | "gosec"
  | "grype"
  | "hadolint"
  | "ruff"
  | "govulncheck"
  | "trufflehog"
  | "npm-audit";

export interface InstallOption {
  manager: string;
  managerLabel: string;
  package: string;
  /** The exact argv, joined for display. Shown before anything runs. */
  command: string;
  available: boolean;
}

export interface ToolStatus {
  tool: ToolId;
  label: string;
  available: boolean;
  version: string | null;
  installHint: string;
  docsUrl: string;
  adds: string;
  scope: string;
  /** False when the tool can be installed but its output is not parsed yet. */
  integrated: boolean;
  installOptions: InstallOption[];
}

export interface PkgMgrStatus {
  id: string;
  label: string;
  available: boolean;
  version: string | null;
}

export interface InstallResult {
  ok: boolean;
  command: string;
  output: string;
}

export interface ToolsInfo {
  tools: ToolStatus[];
  gitAvailable: boolean;
}

export interface ScanOptions {
  target: string;
  isRepo: boolean;
  respectGitignore: boolean;
  includeVendor: boolean;
  checkSecrets: boolean;
  checkDependencies: boolean;
  experimental: boolean;
  dataflow: boolean;
  externalTools: ToolId[];
}

export interface RuleInfo {
  id: string;
  title: string;
  description: string;
  recommendation: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  languages: string[];
  cwe: string[];
  owasp: string | null;
  references: string[];
  exploit?: string | null;
  impact?: string[];
  fixCode?: string | null;
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Short severity words for badges.
 *
 * The tree badge carries severity as colour only — which fails WCAG 1.4.1 for
 * anyone who cannot separate those hues. This label is always in the DOM (so a
 * screen reader reads "Крит 24" instead of just "24") and the accessibility
 * switch makes it visible.
 */
export const SEVERITY_SHORT: Record<Severity, string> = {
  critical: "Крит",
  high: "Выс",
  medium: "Сред",
  low: "Низ",
  info: "Инфо",
};

/**
 * Severity words for a spoken count, e.g. "найдено 24 критических".
 *
 * `one` is the form after a number ending in 1 (but not 11); `many` is the
 * genitive plural used everywhere else. The visible labels are nominative
 * ("Критическая") and read wrong after a number.
 */
export const SEVERITY_COUNTED: Record<Severity, { one: string; many: string }> = {
  critical: { one: "критическая", many: "критических" },
  high: { one: "высокая", many: "высоких" },
  medium: { one: "средняя", many: "средних" },
  low: { one: "низкая", many: "низких" },
  info: { one: "информационная", many: "информационных" },
};

/** Picks the Russian form for `n` of `severity`. */
export function severityCounted(n: number, severity: Severity): string {
  const form = SEVERITY_COUNTED[severity];
  const one = n % 10 === 1 && n % 100 !== 11;
  return `${n} ${one ? form.one : form.many}`;
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
  info: "Информация",
};

/** Material Symbols ligature names per severity. */
export const SEVERITY_SYMBOL: Record<Severity, string> = {
  critical: "dangerous",
  high: "error",
  medium: "warning",
  low: "info",
  info: "lightbulb",
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: "Высокая точность",
  medium: "Средняя точность",
  low: "Требует проверки",
};
