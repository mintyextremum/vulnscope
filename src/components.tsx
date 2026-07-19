import { useEffect, useMemo, useRef, useState } from "react";
import hljs from "highlight.js/lib/common";
import { invoke } from "@tauri-apps/api/core";
import { useVirtual } from "./ui";
import { findingToMarkdown } from "./markdown";
import { useT, Lang } from "./i18n";
import {
  Finding,
  FileSummary,
  Severity,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  SEVERITY_SHORT,
  SEVERITY_SYMBOL,
  CONFIDENCE_LABEL,
} from "./types";

/** Row height in the code viewer. Must match .vline in App.css: the virtual
 * window positions rows by arithmetic, so a mismatch shows up as drift. */
const VIEWER_ROW_H = 21;

/** Row height in the findings list, including its gap. The virtual window
 * positions rows by arithmetic, so this must match what .finding-item renders. */
const FINDING_ROW_H = 96;

/** Filter state for the findings list, owned by App so the command palette and
 * the panel drive the same thing. `total` is the unfiltered count: the panel
 * needs it to say how much it is hiding. */
export interface FindingFilters {
  total: number;
  newCount: number;
  suppressedCount: number;
  query: string;
  setQuery: (v: string) => void;
  onlyNew: boolean;
  setOnlyNew: (v: boolean) => void;
  showSuppressed: boolean;
  setShowSuppressed: (v: boolean) => void;
  /** Path the list is narrowed to via the tree, or null for the whole report. */
  file: string | null;
  clearFile: () => void;
  reset: () => void;
}

export function Icon({
  name,
  className = "",
  style,
}: {
  name: string;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    // aria-hidden always: the glyph is a Material Symbols ligature, so a screen
    // reader would otherwise read the token ("content_copy", "expand_more") as
    // words. Icons here are decorative — every one sits beside a text label, or
    // its button carries an aria-label. An icon that must be announced needs a
    // labelled control around it, not an exception here.
    <span className={`material-symbols-outlined ${className}`} style={style} aria-hidden="true">
      {name}
    </span>
  );
}

/**
 * A polite live region that speaks `message` to a screen reader.
 *
 * It mounts empty and fills in an effect on purpose: a live region only
 * announces *changes* made after it is already in the DOM, so rendering the
 * text on the first pass would be silent. That subtlety is exactly why the
 * scan-result summary needs a component and not a plain `aria-live` div.
 */
export function Announce({ message }: { message: string }) {
  const [text, setText] = useState("");
  useEffect(() => {
    // Runs after the empty region is committed, so the reader hears the change.
    setText(message);
  }, [message]);
  return (
    <div className="sr-only" role="status" aria-live="polite">
      {text}
    </div>
  );
}

/**
 * Language for the plain formatters below. They are called in dozens of places
 * without a hook, so instead of threading the language through every call site,
 * App sets it once whenever the setting changes (see setFormatLang). Pure
 * display formatting — no React state depends on it beyond the re-render App
 * already triggers on a settings change.
 */
let _fmtLang: Lang = "ru";
export function setFormatLang(l: Lang) {
  _fmtLang = l;
}

export function formatDuration(ms: number): string {
  const u = _fmtLang === "en" ? ["ms", "s", "min"] : ["мс", "с", "мин"];
  if (ms < 1000) return `${Math.round(ms)} ${u[0]}`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} ${u[1]}`;
  // Round to whole seconds *first*: rounding the remainder on its own turns
  // 179.6s into "2 мин 60 с".
  const total = Math.round(s);
  return `${Math.floor(total / 60)} ${u[2]} ${total % 60} ${u[1]}`;
}

export function formatBytes(n: number): string {
  const u = _fmtLang === "en" ? ["B", "KB", "MB"] : ["Б", "КБ", "МБ"];
  if (n < 1024) return `${n} ${u[0]}`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} ${u[1]}`;
  return `${(n / 1024 / 1024).toFixed(1)} ${u[2]}`;
}

export function formatNumber(n: number): string {
  return n.toLocaleString(_fmtLang === "en" ? "en-US" : "ru-RU");
}

/** Maps a file extension to a Material Symbol, so the tree reads at a glance. */
function fileIcon(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  const name = path.split("/").pop()?.toLowerCase() ?? "";
  if (name === "package.json" || name === "cargo.toml" || name.startsWith("requirements"))
    return "inventory_2";
  if (name.startsWith("dockerfile")) return "deployed_code";
  if (["yml", "yaml"].includes(ext)) return "settings";
  if (["json", "toml"].includes(ext)) return "data_object";
  if (["md", "txt"].includes(ext)) return "description";
  if (["sh", "bash", "ps1"].includes(ext)) return "terminal";
  return "code";
}

// ------------------------------------------------------------------- tree

interface TreeDir {
  name: string;
  path: string;
  dirs: Map<string, TreeDir>;
  files: FileSummary[];
  worst: Severity | null;
  total: number;
}

function worseOf(a: Severity | null, b: Severity | null): Severity | null {
  if (!a) return b;
  if (!b) return a;
  return SEVERITY_ORDER.indexOf(a) <= SEVERITY_ORDER.indexOf(b) ? a : b;
}

function buildTree(files: FileSummary[]): TreeDir {
  const root: TreeDir = {
    name: "",
    path: "",
    dirs: new Map(),
    files: [],
    worst: null,
    total: 0,
  };

  for (const f of files) {
    const parts = f.path.split("/");
    const fileName = parts.pop()!;
    let node = root;
    let acc = "";

    for (const part of parts) {
      acc = acc ? `${acc}/${part}` : part;
      if (!node.dirs.has(part)) {
        node.dirs.set(part, {
          name: part,
          path: acc,
          dirs: new Map(),
          files: [],
          worst: null,
          total: 0,
        });
      }
      node = node.dirs.get(part)!;
    }
    node.files.push({ ...f, path: f.path, languageLabel: f.languageLabel } as FileSummary);
    // Keep the display name available without re-splitting on every render.
    (node.files[node.files.length - 1] as any).displayName = fileName;
  }

  // Roll severity up so a collapsed folder still shows that something is wrong
  // inside it.
  const rollup = (node: TreeDir): void => {
    for (const d of node.dirs.values()) {
      rollup(d);
      node.worst = worseOf(node.worst, d.worst);
      node.total += d.total;
    }
    for (const f of node.files) {
      node.worst = worseOf(node.worst, f.maxSeverity);
      node.total += f.counts.critical + f.counts.high + f.counts.medium + f.counts.low + f.counts.info;
    }
  };
  rollup(root);
  return root;
}

function sevClass(s: Severity | null): string {
  return s ? `has-${s}` : "";
}

function TreeDirRow({
  dir,
  depth,
  selected,
  onSelect,
  expanded,
  toggle,
}: {
  dir: TreeDir;
  depth: number;
  selected: string | null;
  onSelect: (p: string) => void;
  expanded: Set<string>;
  toggle: (p: string) => void;
}) {
  const open = expanded.has(dir.path);
  const sortedDirs = useMemo(
    () => [...dir.dirs.values()].sort((a, b) => a.name.localeCompare(b.name)),
    [dir]
  );
  const sortedFiles = useMemo(
    () =>
      [...dir.files].sort((a, b) => {
        const av = a.maxSeverity ? SEVERITY_ORDER.indexOf(a.maxSeverity) : 99;
        const bv = b.maxSeverity ? SEVERITY_ORDER.indexOf(b.maxSeverity) : 99;
        return av - bv || a.path.localeCompare(b.path);
      }),
    [dir]
  );

  return (
    <>
      {dir.path !== "" && (
        <div
          className={`tree-node ${sevClass(dir.worst)}`}
          style={{ paddingLeft: 10 + depth * 13 }}
          onClick={() => toggle(dir.path)}
        >
          <Icon name="chevron_right" className={`twisty ${open ? "open" : ""}`} />
          <Icon name={open ? "folder_open" : "folder"} className="ficon" />
          <span className="fname">{dir.name}</span>
          {dir.worst && (
            <span className={`tree-badge ${dir.worst}`}>
              <span className="sev-word">{SEVERITY_SHORT[dir.worst]}</span>
              {dir.total}
            </span>
          )}
        </div>
      )}
      {(open || dir.path === "") && (
        <>
          {sortedDirs.map((d) => (
            <TreeDirRow
              key={d.path}
              dir={d}
              depth={dir.path === "" ? depth : depth + 1}
              selected={selected}
              onSelect={onSelect}
              expanded={expanded}
              toggle={toggle}
            />
          ))}
          {sortedFiles.map((f) => (
            <div
              key={f.path}
              className={`tree-node ${sevClass(f.maxSeverity)} ${
                selected === f.path ? "selected" : ""
              }`}
              style={{ paddingLeft: 10 + (dir.path === "" ? depth : depth + 1) * 13 + 16 }}
              onClick={() => onSelect(f.path)}
              title={f.path}
            >
              <Icon name={fileIcon(f.path)} className="ficon" />
              <span className="fname">{(f as any).displayName ?? f.path}</span>
              {f.maxSeverity && (
                <span className={`tree-badge ${f.maxSeverity}`}>
                  <span className="sev-word">{SEVERITY_SHORT[f.maxSeverity]}</span>
                  {f.counts.critical + f.counts.high + f.counts.medium + f.counts.low + f.counts.info}
                </span>
              )}
            </div>
          ))}
        </>
      )}
    </>
  );
}

export function FileTree({
  files,
  selected,
  onSelect,
  width,
}: {
  files: FileSummary[];
  selected: string | null;
  onSelect: (p: string) => void;
  width: number;
}) {
  const t = useT();
  const [query, setQuery] = useState("");
  const [onlyIssues, setOnlyIssues] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const filtered = useMemo(() => {
    let out = files;
    if (onlyIssues) out = out.filter((f) => f.maxSeverity !== null);
    if (query.trim()) {
      const q = query.toLowerCase();
      out = out.filter((f) => f.path.toLowerCase().includes(q));
    }
    return out;
  }, [files, onlyIssues, query]);

  const tree = useMemo(() => buildTree(filtered), [filtered]);

  // Auto-expand every directory: with the "issues only" filter on, the tree is
  // small and a collapsed root would hide the point of the screen.
  useEffect(() => {
    const paths = new Set<string>();
    const walk = (d: TreeDir) => {
      if (d.path) paths.add(d.path);
      d.dirs.forEach(walk);
    };
    walk(tree);
    setExpanded(paths);
  }, [tree]);

  const toggle = (p: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(p)) next.delete(p);
      else next.add(p);
      return next;
    });
  };

  return (
    <div className="tree-panel" style={{ width }}>
      <div className="panel-head">
        <Icon name="account_tree" />
        {t("Файлы")}
        <span className="count">{filtered.length}</span>
      </div>
      <div className="search-box">
        <Icon name="search" />
        <input
          placeholder={t("Поиск по пути…")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>
      <div className="tree-filter">
        <label className={`opt ${onlyIssues ? "checked" : ""}`} style={{ padding: "6px 8px" }}>
          <input
            type="checkbox"
            checked={onlyIssues}
            onChange={(e) => setOnlyIssues(e.target.checked)}
          />
          <span className="opt-box">
            <Icon name="check" />
          </span>
          <span className="opt-text">
            <strong style={{ fontSize: 12 }}>{t("Только с находками")}</strong>
          </span>
        </label>
      </div>
      <div className="tree">
        {filtered.length === 0 ? (
          <div className="tree-empty">
            {query ? t("Ничего не найдено") : t("Нет файлов с находками")}
          </div>
        ) : (
          <TreeDirRow
            dir={tree}
            depth={0}
            selected={selected}
            onSelect={onSelect}
            expanded={expanded}
            toggle={toggle}
          />
        )}
      </div>
    </div>
  );
}

// --------------------------------------------------------------- findings

export function FindingList({
  findings,
  selected,
  onSelect,
  width,
  filters,
}: {
  findings: Finding[];
  selected: string | null;
  onSelect: (f: Finding) => void;
  width: number;
  filters: FindingFilters;
}) {
  const t = useT();
  const listRef = useRef<HTMLDivElement>(null);
  const win = useVirtual(listRef, findings.length, FINDING_ROW_H, 6);

  // Keyboard navigation moves the selection; the list must follow it. With
  // virtualisation the selected row may not be mounted, so scroll by
  // arithmetic rather than querying the DOM for it.
  useEffect(() => {
    if (!selected) return;
    const el = listRef.current;
    if (!el) return;
    const i = findings.findIndex((f) => f.id === selected);
    if (i < 0) return;

    const top = i * FINDING_ROW_H;
    const bottom = top + FINDING_ROW_H;
    // Only scroll when the row is actually out of view: nudging on every
    // selection makes the list jitter while stepping through with j/k.
    if (top < el.scrollTop) {
      el.scrollTo({ top });
    } else if (bottom > el.scrollTop + el.clientHeight) {
      el.scrollTo({ top: bottom - el.clientHeight });
    }
  }, [selected, findings]);

  const hidden = filters.total - findings.length;

  return (
    <div className="list-panel" style={{ width }}>
      <div className="panel-head">
        <Icon name="bug_report" />
        {t("Находки")}
        <span className="count">{findings.length}</span>
        {hidden > 0 && (
          <button className="head-link" onClick={filters.reset} title={t("Сбросить фильтры")}>
            <Icon name="filter_alt_off" />
            {t("скрыто {n}", { n: hidden })}
          </button>
        )}
      </div>

      <div className="list-filters">
        <div className="lf-search">
          <Icon name="search" />
          <input
            value={filters.query}
            onChange={(e) => filters.setQuery(e.target.value)}
            placeholder={t("Поиск: название, путь, категория, CWE, CVE, код")}
          />
          {filters.query && (
            <button className="lf-clear" onClick={() => filters.setQuery("")} title={t("Очистить")}>
              <Icon name="close" />
            </button>
          )}
        </div>
        <div className="lf-toggles">
          {/* Picking a file in the tree narrows this list. That is deliberate,
              but it used to be invisible: the list just showed fewer findings
              with nothing saying why or how to get back. */}
          {filters.file && (
            <button
              className="chip on chip-file"
              onClick={filters.clearFile}
              title={`${filters.file} — ${t("показать находки во всех файлах")}`}
            >
              <Icon name="description" />
              {filters.file.split(/[\\/]/).pop()}
              <Icon name="close" />
            </button>
          )}
          {filters.newCount > 0 && (
            <button
              className={`chip ${filters.onlyNew ? "on" : ""}`}
              onClick={() => filters.setOnlyNew(!filters.onlyNew)}
            >
              <Icon name="fiber_new" />
              {t("Только новые")}
              <span className="chip-n">{filters.newCount}</span>
            </button>
          )}
          {filters.suppressedCount > 0 && (
            <button
              className={`chip ${filters.showSuppressed ? "on" : ""}`}
              onClick={() => filters.setShowSuppressed(!filters.showSuppressed)}
            >
              <Icon name={filters.showSuppressed ? "visibility" : "visibility_off"} />
              {t("Подавленные")}
              <span className="chip-n">{filters.suppressedCount}</span>
            </button>
          )}
        </div>
      </div>

      <div className="finding-list" ref={listRef}>
        {findings.length === 0 ? (
          // A filtered-to-empty list looks exactly like a clean project. Say
          // which one it is, and offer the way back.
          hidden > 0 ? (
            <div className="list-empty filtered">
              <Icon name="filter_alt" />
              <p>{t("Под фильтры ничего не подошло")}</p>
              <button className="btn btn-ghost" onClick={filters.reset}>
                {t("Сбросить фильтры")}
              </button>
            </div>
          ) : (
            <div className="list-empty">
              <Icon name="verified_user" />
              <p>{t("Здесь ничего не найдено")}</p>
            </div>
          )
        ) : (
          <div style={{ height: win.totalHeight, position: "relative" }}>
          <div style={{ transform: `translateY(${win.offsetY}px)` }}>
          {findings.slice(win.start, win.end).map((f, i) => (
            <div
              key={f.id}
              data-fid={f.id}
              className={`finding-item ${f.severity} ${selected === f.id ? "selected" : ""}`}
              onClick={() => onSelect(f)}
              // Stagger only the first rows: past that it is just latency.
              style={{
                height: FINDING_ROW_H - 4,
                animationDelay: win.start + i < 12 ? `${(win.start + i) * 22}ms` : "0ms",
              }}
            >
              <div className={`fi-top ${f.severity}`}>
                <Icon name={SEVERITY_SYMBOL[f.severity]} />
                <div className="fi-title">{t(f.title)}</div>
              </div>
              <div className="fi-loc" title={`${f.file}:${f.line}`}>
                {f.file}
                {f.line > 0 ? `:${f.line}` : ""}
              </div>
              <div className="fi-tags">
                {f.extra?.combination && (
                  <span className="tag combo" title={t("Опасная связка возможных уязвимостей")}>
                    <Icon name="account_tree" />
                    {t("СВЯЗКА")}
                  </span>
                )}
                {f.extra?.experimental && <span className="tag beta">BETA</span>}
                {f.isNew && <span className="tag is-new">{t("новое")}</span>}
                {f.suppressed && <span className="tag muted">{t("подавлено")}</span>}
                {f.cve.slice(0, 2).map((c) => (
                  <span key={c} className="tag cve">
                    {c}
                  </span>
                ))}
                {f.cwe.slice(0, 2).map((c) => (
                  <span key={c} className="tag cwe">
                    {c.split(":")[0]}
                  </span>
                ))}
                <span className="tag">{f.ruleId}</span>
              </div>
            </div>
          ))}
          </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ----------------------------------------------------------- code helpers

function highlight(code: string, language: string): string {
  try {
    const lang = hljs.getLanguage(language) ? language : undefined;
    return lang
      ? hljs.highlight(code, { language: lang, ignoreIllegals: true }).value
      : hljs.highlightAuto(code).value;
  } catch {
    return escapeHtml(code);
  }
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function hljsLang(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    rs: "rust",
    py: "python",
    js: "javascript",
    mjs: "javascript",
    cjs: "javascript",
    jsx: "javascript",
    ts: "typescript",
    tsx: "typescript",
    json: "json",
    toml: "ini",
    yml: "yaml",
    yaml: "yaml",
    sh: "bash",
    bash: "bash",
    go: "go",
    java: "java",
    php: "php",
    rb: "ruby",
    html: "xml",
  };
  return map[ext] ?? "plaintext";
}

/**
 * Above this, syntax highlighting costs more than it is worth: highlight.js walks
 * the whole file on the main thread, and a 200k-line bundle in node_modules would
 * block the window for seconds to colourise code nobody reads line by line.
 */
const MAX_HIGHLIGHT_LINES = 6000;

/**
 * Highlights a whole block, then splits into lines. Splitting first would break
 * multi-line tokens (block comments, template strings) and corrupt the markup.
 */
function highlightLines(code: string, language: string): string[] {
  const plain = code.split("\n");
  if (plain.length > MAX_HIGHLIGHT_LINES) {
    return plain.map(escapeHtml);
  }

  const html = highlight(code, language);
  const lines = html.split("\n");
  // hljs can leave a span open across a newline; re-balance per line so each
  // row is valid standalone HTML.
  const out: string[] = [];
  let open: string[] = [];
  for (const line of lines) {
    const prefix = open.map((c) => `<span class="${c}">`).join("");
    const re = /<span class="([^"]*)">|<\/span>/g;
    let m: RegExpExecArray | null;
    const stack = [...open];
    while ((m = re.exec(line))) {
      if (m[1]) stack.push(m[1]);
      else stack.pop();
    }
    const suffix = "</span>".repeat(stack.length);
    out.push(prefix + line + suffix);
    open = stack;
  }
  return out;
}

export function CodeSnippet({ finding }: { finding: Finding }) {
  const lines = useMemo(
    () => highlightLines(finding.snippet, hljsLang(finding.file)),
    [finding]
  );

  return (
    <div className="code-block">
      <div className="code-head">
        <Icon name="code_blocks" />
        {finding.file}
        {finding.line > 0 ? `:${finding.line}` : ""}
      </div>
      <div className="code-lines">
        {lines.map((html, i) => {
          const lineNo = finding.snippetStartLine + i;
          const isHit = lineNo >= finding.line && lineNo <= finding.endLine;
          return (
            <div key={i} className={`code-line ${isHit ? "hit" : ""}`}>
              <span className="ln">{lineNo > 0 ? lineNo : ""}</span>
              <span className="lc" dangerouslySetInnerHTML={{ __html: html }} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function CodeViewer({
  root,
  path,
  findings,
  focusLine,
}: {
  root: string;
  path: string;
  findings: Finding[];
  focusLine: number | null;
}) {
  const t = useT();
  const [content, setContent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    setContent(null);
    setError(null);
    invoke<string>("read_source", { root, relative: path })
      .then((c) => !cancelled && setContent(c))
      .catch((e) => !cancelled && setError(String(e)));
    return () => {
      cancelled = true;
    };
  }, [root, path]);

  const lines = useMemo(
    () => (content === null ? [] : highlightLines(content, hljsLang(path))),
    [content, path]
  );

  /** Line numbers that carry a finding, and the worst severity on each. */
  const hits = useMemo(() => {
    const m = new Map<number, Severity>();
    for (const f of findings) {
      for (let l = f.line; l <= Math.max(f.line, f.endLine); l++) {
        const prev = m.get(l);
        m.set(l, prev ? (worseOf(prev, f.severity) as Severity) : f.severity);
      }
    }
    return m;
  }, [findings]);

  const win = useVirtual(bodyRef, lines.length, VIEWER_ROW_H);

  // With virtualisation the target row may not exist in the DOM yet, so scroll
  // by arithmetic instead of querying for it.
  useEffect(() => {
    if (focusLine === null || content === null) return;
    const el = bodyRef.current;
    if (!el) return;
    const target = (focusLine - 1) * VIEWER_ROW_H - el.clientHeight / 2;
    el.scrollTo({ top: Math.max(0, target), behavior: "smooth" });
  }, [focusLine, content]);

  if (error) {
    return (
      <div className="viewer-error">
        <Icon name="error" />
        <span>{error}</span>
      </div>
    );
  }

  if (content === null) {
    return (
      <div className="viewer-loading">
        <Icon name="progress_activity" className="spin" />
        <span>{t("Загрузка файла…")}</span>
      </div>
    );
  }

  return (
    <div className="viewer">
      <div className="viewer-head">
        <Icon name={fileIcon(path)} style={{ color: "var(--t-3)" }} />
        <span className="viewer-path" title={path}>
          {path}
        </span>
        <span className="meta-chip">
          <Icon name="numbers" />
          {t("{n} строк", { n: formatNumber(lines.length) })}
        </span>
        {hits.size > 0 && (
          <span className="meta-chip" style={{ color: "var(--crit)" }}>
            <Icon name="report" />
            {t("{n} отмечено", { n: hits.size })}
          </span>
        )}
      </div>
      <div className="viewer-body" ref={bodyRef}>
        <div style={{ height: win.totalHeight, position: "relative" }}>
          <div style={{ transform: `translateY(${win.offsetY}px)` }}>
            {lines.slice(win.start, win.end).map((html, i) => {
              const lineNo = win.start + i + 1;
              const hit = hits.get(lineNo);
              return (
                <div
                  key={lineNo}
                  data-line={lineNo}
                  className={`vline ${hit ? "hit" : ""} ${focusLine === lineNo ? "focus" : ""}`}
                  style={{ height: VIEWER_ROW_H }}
                >
                  <span className="ln">{lineNo}</span>
                  <span className="lc" dangerouslySetInnerHTML={{ __html: html }} />
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ detail

export function FindingDetail({
  finding,
  onOpenFile,
  root,
  onSuppressionChanged,
  editorCommand = "",
}: {
  finding: Finding | null;
  onOpenFile: (path: string, line: number) => void;
  root: string;
  onSuppressionChanged: () => void;
  /** The configured editor command; empty hides the open-in-editor button. */
  editorCommand?: string;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [wholeFile, setWholeFile] = useState(false);
  const [open, setOpen] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [copyState, setCopyState] = useState<"idle" | "ok" | "fail">("idle");
  const [editorErr, setEditorErr] = useState<string | null>(null);

  useEffect(() => {
    setOpen(false);
    setReason("");
    setWholeFile(false);
    setErr(null);
    setCopyState("idle");
    setEditorErr(null);
  }, [finding?.id]);

  /**
   * Reports on the button itself, both ways. `err` below belongs to the suppress
   * form and only renders while it is open, so routing a copy failure there left
   * the user clicking Copy and seeing nothing at all.
   */
  const copyFinding = async () => {
    if (!finding) return;
    try {
      await navigator.clipboard.writeText(findingToMarkdown(finding, t, true));
      setCopyState("ok");
    } catch {
      setCopyState("fail");
    }
    setTimeout(() => setCopyState("idle"), 2000);
  };

  const suppress = async () => {
    if (!finding) return;
    try {
      await invoke("suppress_finding", {
        root,
        fingerprint: finding.fingerprint,
        ruleId: finding.ruleId,
        file: finding.file,
        wholeFile,
        reason,
      });
      setOpen(false);
      onSuppressionChanged();
    } catch (e) {
      setErr(String(e));
    }
  };

  const unsuppress = async () => {
    if (!finding) return;
    await invoke("unsuppress_finding", {
      root,
      fingerprint: finding.fingerprint,
      ruleId: finding.ruleId,
      file: finding.file,
    }).catch((e) => setErr(String(e)));
    onSuppressionChanged();
  };
  if (!finding) {
    return (
      <div className="detail-empty">
        <Icon name="ads_click" />
        <span>{t("Выберите находку, чтобы увидеть детали")}</span>
      </div>
    );
  }

  const openRef = (url: string) => {
    invoke("plugin:opener|open_url", { url }).catch(() => {});
  };

  return (
    <div className="detail-scroll">
      <div className="detail-head">
        <div className="detail-badges">
          <div className={`detail-sev ${finding.severity}`}>
            <Icon name={SEVERITY_SYMBOL[finding.severity]} />
            {t(SEVERITY_LABEL[finding.severity])}
          </div>
          {finding.extra?.experimental && (
            <span
              className="tag beta"
              title={t(
                "Экспериментальная эвристика: возможная уязвимость, которую не поймали точные правила. Требует ручной проверки.",
              )}
            >
              BETA
            </span>
          )}
          {finding.extra?.combination && (
            <span
              className="tag combo"
              title={t("Несколько возможных уязвимостей в одном файле, усиливающих друг друга.")}
            >
              <Icon name="account_tree" />
              {t("СВЯЗКА")}
            </span>
          )}
          {finding.isNew && (
            <span className="tag is-new" title={t("Не было в предыдущем сканировании")}>
              {t("новое")}
            </span>
          )}
          <div style={{ flex: 1 }} />
          {/* Copying the whole report to share one finding is absurd, and this is
              the usual next step: paste it into a ticket or a chat. */}
          <button
            className="btn btn-ghost btn-sm"
            onClick={copyFinding}
            title={t("Скопировать находку как Markdown — для тикета или чата")}
          >
            <Icon
              name={copyState === "ok" ? "check" : copyState === "fail" ? "error" : "content_copy"}
            />
            {copyState === "ok"
              ? t("Скопировано")
              : copyState === "fail"
              ? t("Не удалось")
              : t("Копировать")}
          </button>
          {finding.suppressed ? (
            <button className="btn btn-ghost btn-sm" onClick={unsuppress}>
              <Icon name="visibility" />
              {t("Вернуть")}
            </button>
          ) : (
            <button className="btn btn-ghost btn-sm" onClick={() => setOpen(!open)}>
              <Icon name="visibility_off" />
              {t("Подавить")}
            </button>
          )}
        </div>

        {finding.suppressed && finding.suppressionReason && (
          <div className="supp-note">
            <Icon name="visibility_off" />
            {t("Подавлено: {reason}", { reason: finding.suppressionReason })}
          </div>
        )}

        {open && (
          <div className="supp-form">
            <div className="field-note" style={{ marginBottom: 8 }}>
              {t("Запись попадёт в")} <code>.vulnscope-ignore</code> в проекте — она версионируется
              вместе с кодом и видна на ревью.
            </div>
            <input
              className="input"
              placeholder={t("Причина: почему это не проблема")}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && reason.trim() && suppress()}
              autoFocus
            />
            <label className={`opt ${wholeFile ? "checked" : ""}`} style={{ marginTop: 8 }}>
              <input
                type="checkbox"
                checked={wholeFile}
                onChange={(e) => setWholeFile(e.target.checked)}
              />
              <span className="opt-box">
                <Icon name="check" />
              </span>
              <span className="opt-text">
                <strong>{t("Все находки этого правила в файле")}</strong>
                <span>{t("А не только эту одну")}</span>
              </span>
            </label>
            {err && (
              <div className="field-error" style={{ marginTop: 8 }}>
                <Icon name="error" />
                {err}
              </div>
            )}
            <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
              <button className="btn btn-primary btn-sm" disabled={!reason.trim()} onClick={suppress}>
                <Icon name="check" />
                {t("Подавить")}
              </button>
              <button className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>
                {t("Отмена")}
              </button>
            </div>
          </div>
        )}
        <div className="detail-title">{t(finding.title)}</div>
        <div className="detail-loc-row">
          <div className="detail-loc" onClick={() => onOpenFile(finding.file, finding.line)}>
            <Icon name="open_in_new" />
            <span>
              {finding.file}
              {finding.line > 0 ? `:${finding.line}` : ""}
            </span>
          </div>
          {/* The viewer shows the code, but fixing it happens in an editor — and
              the path there starts at the file itself. The opener plugin
              highlights it in the system file manager. */}
          <button
            className="loc-reveal"
            onClick={() =>
              invoke("plugin:opener|reveal_item_in_dir", {
                paths: [`${root}/${finding.file}`],
              }).catch(() => {})
            }
            title={t("Показать файл в проводнике")}
            aria-label={t("Показать файл в проводнике")}
          >
            <Icon name="folder_open" />
          </button>
          {/* One step further when the user configured their editor: jump
              straight to the line. Failure flips the icon and carries the
              backend's message in the tooltip — an icon-only button has
              nowhere else to put it. */}
          {editorCommand.trim() !== "" && (
            <button
              className="loc-reveal"
              onClick={() =>
                invoke("open_in_editor", {
                  path: `${root}/${finding.file}`,
                  line: finding.line,
                })
                  .then(() => setEditorErr(null))
                  .catch((e) => setEditorErr(String(e)))
              }
              title={editorErr ?? t("Открыть в редакторе на этой строке")}
              aria-label={t("Открыть в редакторе на этой строке")}
            >
              <Icon name={editorErr ? "error" : "edit"} />
            </button>
          )}
        </div>
      </div>

      <div className="detail-body">
        <div className="detail-section">
          <h3>
            <Icon name="info" />{t("В чём проблема")}</h3>
          <p>{t(finding.description)}</p>
        </div>

        {finding.extra?.combination && finding.extra.combines && finding.extra.combines.length > 0 && (
          <div className="detail-section">
            <h3>
              <Icon name="account_tree" />
              {t("Связанные места")}
            </h3>
            <ul className="combines-list">
              {finding.extra.combines.map((c, i) => (
                <li key={i}>{c}</li>
              ))}
            </ul>
          </div>
        )}

        {finding.extra?.exploit && (
          <div className="detail-section">
            <h3>
              <Icon name="bug_report" />
              {t("Пример эксплуатации")}
            </h3>
            <div className="exploit-box">{t(finding.extra.exploit)}</div>
          </div>
        )}

        {finding.extra && finding.extra.impact.length > 0 && (
          <div className="detail-section">
            <h3>
              <Icon name="warning" />
              {t("Возможные последствия")}
            </h3>
            <ul className="impact-list">
              {finding.extra.impact.map((c, i) => (
                <li key={i}>{t(c)}</li>
              ))}
            </ul>
          </div>
        )}

        {finding.snippet && (
          <div className="detail-section">
            <h3>
              <Icon name="code" />
              {t("Код")}
            </h3>
            <CodeSnippet finding={finding} />
          </div>
        )}

        <div className="detail-section">
          <h3>
            <Icon name="build" />{t("Как исправить")}</h3>
          <div className="fix-box">
            <p>{t(finding.recommendation)}</p>
          </div>
          {finding.extra?.fixCode && (
            <pre className="fix-code">
              <code>{finding.extra.fixCode}</code>
            </pre>
          )}
        </div>

        <div className="detail-section">
          <h3>
            <Icon name="label" />
            {t("Классификация")}
          </h3>
          <div className="meta-grid">
            <div className="meta-item">
              <div className="meta-key">{t("Правило")}</div>
              <div className="meta-val">{finding.ruleId}</div>
            </div>
            <div className="meta-item">
              <div className="meta-key">{t("Источник")}</div>
              <div className="meta-val">{t(finding.sourceLabel)}</div>
            </div>
            <div className="meta-item">
              <div className="meta-key">{t("Категория")}</div>
              <div className="meta-val">{t(finding.category)}</div>
            </div>
            <div className="meta-item">
              <div className="meta-key">{t("Достоверность")}</div>
              <div className="meta-val">
                {t(CONFIDENCE_LABEL[finding.confidence])}
                {finding.extra?.corroborated && (
                  <span
                    className="corroborated-badge"
                    title={t(
                      "В этом же файле найден вызов-приёмник, подтверждающий использование данных — достоверность повышена.",
                    )}
                  >
                    <Icon name="verified" />
                    {t("подтверждено sink")}
                  </span>
                )}
              </div>
            </div>
            {finding.cwe.length > 0 && (
              <div className="meta-item">
                <div className="meta-key">CWE</div>
                <div className="meta-val cwe-links">
                  {finding.cwe.map((c) => {
                    const num = c.replace(/\D/g, "");
                    return num ? (
                      <button
                        key={c}
                        className="cwe-link"
                        onClick={() => openRef(`https://cwe.mitre.org/data/definitions/${num}.html`)}
                        title={t("Открыть описание CWE на cwe.mitre.org")}
                      >
                        {c}
                        <Icon name="open_in_new" />
                      </button>
                    ) : (
                      <span key={c}>{c}</span>
                    );
                  })}
                </div>
              </div>
            )}
            {finding.owasp && (
              <div className="meta-item">
                <div className="meta-key">OWASP Top 10</div>
                <div className="meta-val">{finding.owasp}</div>
              </div>
            )}
            {finding.cve.length > 0 && (
              <div className="meta-item">
                <div className="meta-key">CVE</div>
                <div className="meta-val" style={{ color: "var(--crit)" }}>
                  {finding.cve.join(", ")}
                </div>
              </div>
            )}
            {finding.package && (
              <>
                <div className="meta-item">
                  <div className="meta-key">{t("Пакет")}</div>
                  <div className="meta-val">
                    {finding.package.name} {finding.package.version}
                  </div>
                </div>
                <div className="meta-item">
                  <div className="meta-key">{t("Исправлено в")}</div>
                  <div className="meta-val" style={{ color: "var(--ok)" }}>
                    {finding.package.fixedVersion ?? t("нет исправления")}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>

        {finding.references.length > 0 && (
          <div className="detail-section">
            <h3>
              <Icon name="link" />
              {t("Ссылки")}
            </h3>
            {finding.references.map((r) => (
              <div key={r} className="ref-link" onClick={() => openRef(r)}>
                <Icon name="open_in_new" />
                {r}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ----------------------------------------------------------------- progress

/**
 * `indeterminate` is for the phases where the file count says nothing about the
 * work left: querying OSV or running an external scanner can take a minute
 * after every file has been read. Showing the resulting "100%" told the user
 * the scan was finished while it was still working.
 */
export function ProgressRing({
  percent,
  indeterminate = false,
  label,
}: {
  percent: number;
  indeterminate?: boolean;
  label?: string;
}) {
  const t = useT();
  const R = 70;
  const C = 2 * Math.PI * R;
  // A quarter-circle arc that spins: progress without a false promise.
  const offset = indeterminate ? C * 0.75 : C - (Math.min(100, Math.max(0, percent)) / 100) * C;

  return (
    <div
      className={`ring-wrap ${indeterminate ? "indet" : ""}`}
      // A real progressbar to assistive tech. Omitting aria-valuenow while
      // indeterminate is the ARIA way to say "working, amount unknown" — the
      // same thing the spinning arc says visually. The live region carries the
      // spoken detail, so the ring itself needs no label beyond its role.
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={indeterminate ? undefined : Math.round(percent)}
      aria-label={label ?? t("Прогресс сканирования")}
    >
      <svg className="ring" width="160" height="160" viewBox="0 0 160 160" aria-hidden="true">
        <defs>
          {/* The stylesheet references this by id; without the def the stroke
              silently fails to paint. */}
          <linearGradient id="ringGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#5b8def" />
            <stop offset="100%" stopColor="var(--a2)" />
          </linearGradient>
        </defs>
        <circle className="ring-bg" cx="80" cy="80" r={R} />
        <circle
          className="ring-fg"
          cx="80"
          cy="80"
          r={R}
          strokeDasharray={C}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="ring-label">
        {indeterminate ? (
          <div className="ring-note">{label ?? t("идёт работа")}</div>
        ) : (
          <div className="ring-pct">{Math.round(percent)}%</div>
        )}
      </div>
    </div>
  );
}

export function SeverityBar({
  label,
  value,
  max,
  kind,
}: {
  label: string;
  value: number;
  max: number;
  kind: string;
}) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <div className="bar-row">
      <div className="bar-label">{label}</div>
      <div className="bar-track">
        <div className={`bar-fill ${kind}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="bar-num">{formatNumber(value)}</div>
    </div>
  );
}
