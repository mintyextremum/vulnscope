import { useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import "./App.css";
import {
  Finding,
  ScanOptions,
  ScanPhase,
  ScanProgress,
  ScanReport,
  AppSettings,
  Severity,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  severityCounted,
  SEVERITY_SYMBOL,
  Staff1c,
  ToolId,
  ToolsInfo,
} from "./types";
import {
  Announce,
  CodeViewer,
  FileTree,
  FindingDetail,
  FindingFilters,
  FindingList,
  formatBytes,
  formatDuration,
  setFormatLang,
  formatNumber,
  Icon,
  ProgressRing,
  SeverityBar,
} from "./components";
import { applyTheme } from "./theme-tokens";
import { toSarif } from "./sarif";
import { computeScore, type SecurityScore, type Grade } from "./score";
import { toMarkdown } from "./markdown";
import { toCsv } from "./csv";
import { toExcel } from "./excel";
import { toHtml } from "./html";
import { toXml1C } from "./xml1c";
import { LangContext, Lang, useT, translate, TFn } from "./i18n";
import { RulesScreen } from "./Rules";
import { HelpScreen } from "./Help";
import { ReportScreen } from "./Report";
import { RuleEditor } from "./RuleEditor";
import { SettingsScreen } from "./Settings";
import { Titlebar } from "./Titlebar";
import { ToolsCard, ToolsLoading } from "./Tools";
import {
  Command,
  CommandPalette,
  Resizer,
  useHotkeys,
  useStoredWidth,
  ViewTransition,
} from "./ui";

type Screen = "setup" | "scanning" | "results" | "rules" | "myrules" | "settings" | "help" | "report";

/** An audit target imported from a 1C project registry. */
interface Project1c {
  name: string;
  path: string;
  repo: string;
  owner: string;
}
type ResultTab = "overview" | "findings" | "beta" | "code" | "skipped";

const TABS: ResultTab[] = ["overview", "findings", "beta", "code", "skipped"];

export default function App() {
  const [screen, setScreen] = useState<Screen>("setup");
  /** Where to return from the rules catalogue. */
  const [prevScreen, setPrevScreen] = useState<Screen>("setup");
  const [tab, setTab] = useState<ResultTab>("overview");

  // The last target is remembered so re-scanning the same project is just
  // launch → Enter, instead of pasting the path every time.
  const [mode, setMode] = useState<"local" | "repo">(() =>
    localStorage.getItem("vs.mode") === "repo" ? "repo" : "local"
  );
  const [localPath, setLocalPath] = useState(() => localStorage.getItem("vs.localPath") ?? "");
  const [repoUrl, setRepoUrl] = useState(() => localStorage.getItem("vs.repoUrl") ?? "");
  const [tools, setTools] = useState<ToolsInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [respectGitignore, setRespectGitignore] = useState(true);
  const [includeVendor, setIncludeVendor] = useState(false);
  const [checkSecrets, setCheckSecrets] = useState(true);
  const [checkDependencies, setCheckDependencies] = useState(true);
  const [experimental, setExperimental] = useState(
    () => localStorage.getItem("vs.experimental") !== "0",
  );
  const [dataflow, setDataflow] = useState(
    () => localStorage.getItem("vs.dataflow") !== "0",
  );
  const [enabledTools, setEnabledTools] = useState<Set<ToolId>>(new Set());

  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);

  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [findingQuery, setFindingQuery] = useState("");
  const [onlyNew, setOnlyNew] = useState(false);
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  // Triage by who last touched the line (git blame). Set from the author chip in
  // a finding's detail; null means "everyone".
  const [authorFilter, setAuthorFilter] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [focusLine, setFocusLine] = useState<number | null>(null);

  const [paletteOpen, setPaletteOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  // Fixed-position coords for the export menu: it lives in the titlebar, which
  // is inside `.app { overflow: clip }`, so an absolutely-positioned dropdown
  // gets clipped away. Positioning it `fixed` from the button's rect escapes it.
  const [exportPos, setExportPos] = useState<{ top: number; right: number }>({ top: 0, right: 0 });
  const [projects1c, setProjects1c] = useState<Project1c[]>([]);
  const [flash, setFlash] = useState<string | null>(null);
  const flashTimer = useRef<number | null>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [treeW, setTreeW] = useStoredWidth("vs.treeW", 280);
  const [listW, setListW] = useStoredWidth("vs.listW", 360);

  useEffect(() => {
    // Dev preview: outside Tauri the backend commands reject, so load a sample
    // report to make the results UI visible.
    //
    // The import is dynamic on purpose. A static one kept the fixture in the
    // production bundle even though this branch is dead there: the module builds
    // its findings by calling a helper, and rollup cannot prove those calls are
    // side-effect free, so it keeps them — strings and all. `import.meta.env.DEV`
    // is inlined as false, so the whole branch, this import included, is dropped.
    if (import.meta.env.DEV && !("__TAURI_INTERNALS__" in window)) {
      void import("./demo").then(({ DEMO_REPORT, DEMO_SETTINGS }) => {
        setReport(DEMO_REPORT);
        setSettings(DEMO_SETTINGS);
        setSelectedFinding(DEMO_REPORT.findings[0] ?? null);
        setSelectedFile(DEMO_REPORT.findings[0]?.file ?? null);
        setScreen("results");
      });
      return;
    }
    invoke<ToolsInfo>("get_tools")
      .then((info) => {
        setTools(info);
        // Restore the previous choice, but only for scanners that are still
        // installed and wired up: sending a since-removed tool to the scanner
        // would fail the whole run, and ticking nine boxes on every launch is
        // why they were all sitting unused.
        try {
          const saved = JSON.parse(localStorage.getItem("vs.tools") ?? "[]") as ToolId[];
          const usable = new Set(
            info.tools.filter((t) => t.available && t.integrated).map((t) => t.tool)
          );
          setEnabledTools(new Set(saved.filter((id) => usable.has(id))));
        } catch {
          /* a corrupt entry just means no restored selection */
        }
      })
      .catch(() => {});
    invoke<AppSettings>("get_settings").then(setSettings).catch(() => {});
  }, []);

  useEffect(() => {
    if (!tools) return; // never overwrite the saved set before it is restored
    localStorage.setItem("vs.tools", JSON.stringify([...enabledTools]));
  }, [enabledTools, tools]);

  // Remember the last target and mode across launches (see the state above).
  useEffect(() => {
    localStorage.setItem("vs.mode", mode);
    localStorage.setItem("vs.localPath", localPath);
    localStorage.setItem("vs.repoUrl", repoUrl);
  }, [mode, localPath, repoUrl]);

  // Appearance settings are applied by writing the tokens the stylesheet reads,
  // so there is one source of truth for colour and spacing.
  useEffect(() => {
    if (!settings) return;
    const root = document.documentElement;
    // The theme is the only source of colour. `accent` predates it and is now
    // just the `a` token under an old name — the settings screen keeps them in
    // step, and applying it separately here would let it silently override a
    // preset that deliberately picks its own accent.
    applyTheme(settings.themePreset, settings.theme);
    root.dataset.density = settings.density;
    root.dataset.reduceMotion = settings.reduceMotion ? "1" : "0";

    // Accessibility switches are data attributes on the root, so the stylesheet
    // stays the single place that decides what each one looks like.
    root.dataset.alwaysFocus = settings.a11yAlwaysFocus ? "1" : "0";
    root.dataset.noAmbient = settings.a11yNoAmbient ? "1" : "0";
    root.dataset.sevText = settings.a11ySeverityText ? "1" : "0";
    root.dataset.underlineLinks = settings.a11yUnderlineLinks ? "1" : "0";
    root.dataset.bigTargets = settings.a11yBigTargets ? "1" : "0";

    // `zoom` scales layout, not just glyphs, so nothing overlaps at 200% —
    // which is exactly what WCAG 1.4.4 asks for. An older build without the
    // field sends undefined; fall back rather than zooming to NaN.
    root.style.zoom = String((settings.a11yUiScale ?? 100) / 100);
    setFormatLang(settings.language === "en" ? "en" : "ru");
  }, [settings]);

  useEffect(() => {
    const un = listen<ScanProgress>("scan-progress", (e) => setProgress(e.payload));
    return () => {
      un.then((f) => f());
    };
  }, []);

  const pickFolder = async () => {
    const picked = await openDialog({ directory: true, multiple: false });
    if (typeof picked === "string") setLocalPath(picked);
  };

  const target = mode === "local" ? localPath : repoUrl;
  const canScan = target.trim().length > 0;

  // Computed here (not near the return) so the command palette useMemo below can
  // translate its labels. App sits above the provider it renders, so t is bound
  // to the local lang rather than read from context.
  const lang: Lang = settings?.language === "en" ? "en" : "ru";
  const t: TFn = (str, vars) => translate(lang, str, vars);

  /** Runs a scan against an explicit target, so a re-scan can reuse the last one. */
  const runScan = async (scanTarget: string, isRepo: boolean) => {
    setError(null);
    setProgress(null);
    setReport(null);
    setScreen("scanning");

    const options: ScanOptions = {
      target: scanTarget.trim(),
      isRepo,
      respectGitignore,
      includeVendor,
      checkSecrets,
      checkDependencies,
      experimental,
      dataflow,
      externalTools: [...enabledTools],
    };

    try {
      const r = await invoke<ScanReport>("start_scan", { options });
      setReport(r);
      setSelectedFinding(r.findings[0] ?? null);
      setSelectedFile(r.findings[0]?.file ?? null);
      setTab("overview");
      setScreen("results");
    } catch (e) {
      setError(String(e));
      setScreen("setup");
    }
  };

  const startScan = () => runScan(target, mode === "repo");

  /** The steps this scan will actually go through, from its own options. */
  const phasePlan = useMemo<ScanPhase[]>(() => {
    // "preparing" is a real step, not filler: the first progress event only
    // lands once setup is done, and without it the screen would show every step
    // waiting and nothing happening.
    const steps: ScanPhase[] = ["preparing"];
    if (mode === "repo") steps.push("cloning");
    steps.push("discovering", "scanningCode");
    if (checkDependencies) steps.push("resolvingDependencies", "queryingOsv");
    if (enabledTools.size > 0) steps.push("runningExternalTools");
    steps.push("finalizing");
    return steps;
  }, [mode, checkDependencies, enabledTools]);

  /** Re-runs the last scan so a suppression takes effect immediately. */
  const rescan = useCallback(() => {
    if (report) runScan(report.root, false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [report]);

  const cancelScan = () => {
    invoke("cancel_scan").catch(() => {});
  };

  const exportReport = async () => {
    if (!report) return;
    const path = await saveDialog({
      defaultPath: `vulnscope-${report.targetLabel.replace(/[^\w.-]/g, "_")}.json`,
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (!path) return;
    await invoke("save_report", {
      path,
      json: JSON.stringify(report, null, 2),
    }).catch((e) => setError(String(e)));
  };

  /** Exports the run as SARIF 2.1.0 so it can feed GitHub code scanning or CI. */
  const exportSarif = async () => {
    if (!report) return;
    const path = await saveDialog({
      defaultPath: `vulnscope-${report.targetLabel.replace(/[^\w.-]/g, "_")}.sarif`,
      filters: [{ name: "SARIF", extensions: ["sarif", "json"] }],
    });
    if (!path) return;
    await invoke("save_report", {
      path,
      json: JSON.stringify(toSarif(report, t), null, 2),
    }).catch((e) => setError(String(e)));
  };

  /** Exports a human-readable Markdown report, for a PR, issue, or chat. */
  const exportMarkdown = async () => {
    if (!report) return;
    const path = await saveDialog({
      defaultPath: `vulnscope-${report.targetLabel.replace(/[^\w.-]/g, "_")}.md`,
      filters: [{ name: "Markdown", extensions: ["md"] }],
    });
    if (!path) return;
    await invoke("save_report", { path, json: toMarkdown(report, t) }).catch((e) =>
      setError(String(e))
    );
  };

  /** The 1C staff registry (imported on setup), for mapping git authors onto
   *  responsible employees in the Excel and XML exports. */
  const loadStaff1c = (): Staff1c[] => {
    try {
      return JSON.parse(localStorage.getItem("vs.staff1c") ?? "[]");
    } catch {
      return [];
    }
  };

  /** Exports findings as a CSV table, for sorting and triage in a spreadsheet. */
  const exportCsv = async () => {
    if (!report) return;
    const path = await saveDialog({
      defaultPath: `vulnscope-${report.targetLabel.replace(/[^\w.-]/g, "_")}.csv`,
      filters: [{ name: "CSV", extensions: ["csv"] }],
    });
    if (!path) return;
    await invoke("save_report", { path, json: toCsv(report, t) }).catch((e) =>
      setError(String(e))
    );
  };

  /** Exports a multi-sheet Excel workbook (summary, findings, per-responsible). */
  const exportExcel = async () => {
    if (!report) return;
    const path = await saveDialog({
      defaultPath: `vulnscope-${report.targetLabel.replace(/[^\w.-]/g, "_")}.xls`,
      filters: [{ name: "Excel", extensions: ["xls"] }],
    });
    if (!path) return;
    await invoke("save_report", {
      path,
      json: toExcel(report, t, computeScore(report), loadStaff1c()),
    }).catch((e) => setError(String(e)));
  };

  /** Shows a brief confirmation toast (also announced to screen readers). */
  const showFlash = useCallback((msg: string) => {
    setFlash(msg);
    if (flashTimer.current) clearTimeout(flashTimer.current);
    flashTimer.current = window.setTimeout(() => setFlash(null), 2200);
  }, []);

  useEffect(() => () => {
    if (flashTimer.current) clearTimeout(flashTimer.current);
  }, []);

  /** Copies the Markdown report to the clipboard, to paste into a PR or chat. */
  const copyMarkdown = async () => {
    if (!report) return;
    try {
      await navigator.clipboard.writeText(toMarkdown(report, t));
      showFlash(t("Отчёт скопирован в буфер обмена"));
    } catch {
      // Clipboard can refuse (focus/permission); fall back to the Save dialog.
      showFlash(t("Не удалось скопировать — используйте экспорт в Markdown"));
    }
  };

  /**
   * Imports an audit-target registry that 1C exported: a list of projects to
   * scan, each a local path or a repo URL, with the responsible person. Closes
   * the loop — 1C decides what to audit, the scanner reads it and fills the
   * target. File-based XML, so it works with any 1C config that can write a file.
   *
   * Schema (Russian element names, so a 1C processing maps straight to it):
   *   <СписокПроектов><Проект>
   *     <Наименование>…</Наименование>
   *     <Путь>…</Путь> | <Репозиторий>https://…</Репозиторий>
   *     <Ответственный>…</Ответственный>
   *   </Проект>…</СписокПроектов>
   *
   * The same file (or a separate one) may carry the staff registry, which maps
   * git authors onto the people 1C holds responsible — that mapping powers the
   * per-responsible breakdown in the report:
   *   <СписокСотрудников><Сотрудник>
   *     <Имя>Иванова Мария Петровна</Имя>
   *     <Должность>Разработчик</Должность>
   *     <Email>maria@…</Email>          (повторяемый)
   *     <GitИмя>maria.ivanova</GitИмя>  (повторяемый)
   *   </Сотрудник>…</СписокСотрудников>
   */
  const import1c = async () => {
    const file = await openDialog({ multiple: false, filters: [{ name: "XML (1С)", extensions: ["xml"] }] });
    if (typeof file !== "string") return;
    try {
      // The backend reads the file (the webview has no filesystem of its own),
      // the same route rule/theme import takes.
      const raw = await invoke<string>("read_source", {
        root: file.replace(/[\\/][^\\/]+$/, ""),
        relative: file.split(/[\\/]/).pop() ?? "",
      });
      const doc = new DOMParser().parseFromString(raw, "application/xml");
      if (doc.querySelector("parsererror")) throw new Error(t("Файл не является корректным XML"));
      const text = (el: Element, tag: string) =>
        el.getElementsByTagName(tag)[0]?.textContent?.trim() ?? "";
      const projects: Project1c[] = Array.from(doc.getElementsByTagName("Проект"))
        .map((el) => ({
          name: text(el, "Наименование") || text(el, "Имя"),
          path: text(el, "Путь") || text(el, "Каталог"),
          repo: text(el, "Репозиторий") || text(el, "Ссылка"),
          owner: text(el, "Ответственный"),
        }))
        .filter((p) => p.path || p.repo);

      // The staff registry: every non-empty <Email>/<GitИмя> is a separate git
      // identity of the same person, so one employee can own several accounts.
      const texts = (el: Element, tag: string) =>
        Array.from(el.getElementsByTagName(tag))
          .map((x) => x.textContent?.trim() ?? "")
          .filter(Boolean);
      const staff: Staff1c[] = Array.from(doc.getElementsByTagName("Сотрудник"))
        .map((el) => ({
          name: text(el, "Имя") || text(el, "ФИО") || text(el, "Наименование"),
          role: text(el, "Должность"),
          emails: texts(el, "Email").concat(texts(el, "Почта")),
          aliases: texts(el, "GitИмя").concat(texts(el, "Псевдоним")),
        }))
        .filter((s) => s.name);

      if (projects.length === 0 && staff.length === 0) {
        setError(t("В файле нет ни проектов, ни сотрудников (ожидаются «Проект» или «Сотрудник»)."));
        return;
      }
      if (staff.length > 0) {
        localStorage.setItem("vs.staff1c", JSON.stringify(staff));
        showFlash(t("Реестр сотрудников из 1С: {n} чел.", { n: staff.length }));
      }
      setProjects1c(projects);
      setError(null);
    } catch (e) {
      setError(t("Не удалось прочитать файл 1С: {e}", { e: String(e) }));
    }
  };

  /** Fills the scan target from a project picked out of a 1C import. */
  const pick1cProject = (pr: Project1c) => {
    if (pr.repo) {
      setMode("repo");
      setRepoUrl(pr.repo);
    } else {
      setMode("local");
      setLocalPath(pr.path);
    }
    setProjects1c([]);
  };

  /** Exports a 1C:Enterprise-loadable XML, for corporate reporting in 1C. */
  const exportXml1C = async () => {
    if (!report) return;
    const path = await saveDialog({
      defaultPath: `vulnscope-${report.targetLabel.replace(/[^\w.-]/g, "_")}-1c.xml`,
      filters: [{ name: "XML (1С)", extensions: ["xml"] }],
    });
    if (!path) return;
    // The staff registry (imported from 1C on setup) maps git authors onto the
    // people 1C holds responsible, so the export can carry a per-person breakdown.
    await invoke("save_report", {
      path,
      json: toXml1C(report, t, computeScore(report), loadStaff1c()),
    }).catch((e) => setError(String(e)));
  };

  /** Exports a self-contained HTML report — open in a browser or print to PDF. */
  const exportHtml = async () => {
    if (!report) return;
    const path = await saveDialog({
      defaultPath: `vulnscope-${report.targetLabel.replace(/[^\w.-]/g, "_")}.html`,
      filters: [{ name: "HTML", extensions: ["html"] }],
    });
    if (!path) return;
    await invoke("save_report", { path, json: toHtml(report, t) }).catch((e) =>
      setError(String(e))
    );
  };

  /**
   * Everything except the severity filter and the file narrowing.
   *
   * Split out on both counts. The tree and the tab badges need to know what each
   * file *would* show, so folding the selected file in here would zero out every
   * other row in the tree. And the severity pills carry their own counts: run
   * the severity filter over those and picking "Критическая" would leave every
   * other pill at zero — the pills are how you pick.
   */
  const matchesNonSeverity = useCallback(
    (f: Finding) => {
      if (onlyNew && !f.isNew) return false;
      // Author narrowing keys on the raw git-blame author (what the detail chip
      // shows); findings without blame drop out while an author is selected.
      if (authorFilter && f.extra?.blame?.author !== authorFilter) return false;
      // Suppressed findings stay reachable but out of the way: the default list
      // answers "what needs attention", and the user already decided these do not.
      if (!showSuppressed && f.suppressed) return false;
      const q = findingQuery.trim().toLowerCase();
      if (q) {
        // Search what the row shows. CWE and the category are printed on every
        // finding, so typing one back has to work; and the title is rendered
        // translated, so matching only the Russian source made search useless in
        // English. Both forms are matched — in Russian they are the same string.
        const hay = [
          f.title,
          t(f.title),
          f.category,
          t(f.category),
          f.file,
          f.ruleId,
          f.snippet,
          f.owasp ?? "",
          ...f.cwe,
          ...f.cve,
        ];
        if (!hay.some((s) => s.toLowerCase().includes(q))) return false;
      }
      return true;
    },
    // `lang` rather than `t`: t is rebuilt every render, which would defeat the memo.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [onlyNew, showSuppressed, findingQuery, authorFilter, lang]
  );

  /** Every filter except the file narrowing. */
  const matchesFilters = useCallback(
    (f: Finding) =>
      (sevFilter.size === 0 || sevFilter.has(f.severity)) && matchesNonSeverity(f),
    [sevFilter, matchesNonSeverity]
  );

  /**
   * Pill counts for what is actually in view: the tab's own findings, the
   * selected file, and the non-severity filters — so the bar agrees with the
   * list under it instead of quoting project totals at it.
   *
   * Only on the tabs that have a list or a tree. The overview prints the scan's
   * own totals in the dashboard, and a different number in the bar directly
   * above it would simply read as a bug.
   */
  const sevPillCounts = useMemo((): Record<Severity, number> => {
    const empty = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    if (!report) return empty;
    const scoped = tab === "findings" || tab === "beta" || tab === "code";
    if (!scoped) return report.counts;
    const out = { ...empty };
    for (const f of report.findings) {
      if ((tab === "beta") !== !!f.extra?.experimental) continue;
      if (selectedFile && f.file !== selectedFile) continue;
      if (!matchesNonSeverity(f)) continue;
      out[f.severity]++;
    }
    return out;
  }, [report, tab, selectedFile, matchesNonSeverity]);

  /** True while anything is narrowing the list, so counts can say "N из M". */
  const anyFilterActive =
    sevFilter.size > 0 || onlyNew || showSuppressed || findingQuery.trim() !== "" || !!authorFilter;

  const filteredFindings = useMemo(() => {
    if (!report) return [];
    // Experimental (BETA) findings live on their own tab; the confirmed list
    // never mixes them in, and vice versa.
    let out = report.findings.filter((f) =>
      tab === "beta" ? f.extra?.experimental : !f.extra?.experimental
    );
    out = out.filter(matchesFilters);
    if (selectedFile && (tab === "findings" || tab === "beta"))
      out = out.filter((f) => f.file === selectedFile);
    return out;
  }, [report, selectedFile, tab, matchesFilters]);

  const fileFindings = useMemo(
    () => (report && selectedFile ? report.findings.filter((f) => f.file === selectedFile) : []),
    [report, selectedFile]
  );

  const confirmedCount = useMemo(
    () => (report ? report.findings.filter((f) => !f.extra?.experimental).length : 0),
    [report]
  );
  const betaCount = useMemo(
    () => (report ? report.findings.filter((f) => f.extra?.experimental).length : 0),
    [report]
  );

  // What each tab holds in the current view — the filters and the picked file
  // alike. The badges show this rather than the scan total, so narrowing is
  // visible from the tab strip instead of only inside it, and the whole results
  // header (pills, badges, list) describes one and the same view.
  const inCurrentView = useCallback(
    (f: Finding, wantBeta: boolean) =>
      !!f.extra?.experimental === wantBeta &&
      (!selectedFile || f.file === selectedFile) &&
      matchesFilters(f),
    [selectedFile, matchesFilters]
  );
  const shownConfirmed = useMemo(
    () => (report ? report.findings.filter((f) => inCurrentView(f, false)).length : 0),
    [report, inCurrentView]
  );
  const shownBeta = useMemo(
    () => (report ? report.findings.filter((f) => inCurrentView(f, true)).length : 0),
    [report, inCurrentView]
  );

  /**
   * File rows carrying the counts of what the filters actually leave, so
   * narrowing the list narrows the tree too instead of leaving the scan's
   * totals sitting there contradicting it.
   *
   * The file narrowing itself is deliberately not applied: the tree is how you
   * pick a file, and it has to keep showing the others.
   */
  const treeFiles = useMemo(() => {
    if (!report) return [];
    const isBeta = tab === "beta";
    // The finding tabs always need recomputing, filters or not: the scan's own
    // per-file counts include the BETA findings, and on the confirmed tab that
    // makes the tree disagree with both the pills and the list.
    const splitTab = tab === "findings" || tab === "beta";
    if (!anyFilterActive && !splitTab) return report.files;
    const per = new Map<string, Record<Severity, number>>();
    for (const f of report.findings) {
      // The code tab shows one tree for everything; the finding tabs are split.
      if (splitTab && !!f.extra?.experimental !== isBeta) continue;
      if (!matchesFilters(f)) continue;
      let c = per.get(f.file);
      if (!c) per.set(f.file, (c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }));
      c[f.severity]++;
    }
    return report.files.map((file) => {
      const counts = per.get(file.path) ?? {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };
      const maxSeverity = SEVERITY_ORDER.find((s) => counts[s] > 0) ?? null;
      return { ...file, counts, maxSeverity };
    });
  }, [report, tab, anyFilterActive, matchesFilters]);

  // A filter can hide the selected finding, leaving the detail panel showing
  // something the list no longer contains — including a suppressed one the user
  // just hid. Follow the list instead.
  useEffect(() => {
    if (tab !== "findings" && tab !== "beta") return;
    if (selectedFinding && filteredFindings.some((f) => f.id === selectedFinding.id)) return;
    setSelectedFinding(filteredFindings[0] ?? null);
  }, [filteredFindings, selectedFinding, tab]);

  const resetFilters = useCallback(() => {
    setSevFilter(new Set());
    setOnlyNew(false);
    setShowSuppressed(false);
    setFindingQuery("");
    setAuthorFilter(null);
    // The tree selection narrows the list too, so "reset filters" has to drop it
    // as well — otherwise the list stays a subset after the user asked for all.
    setSelectedFile(null);
  }, []);

  /**
   * The report reduced to what the findings list currently shows, for the
   * filtered export. Counts are recomputed so the document's own summary agrees
   * with its contents rather than with the full scan.
   */
  const filteredReport: ScanReport | null = useMemo(() => {
    if (!report) return null;
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of filteredFindings) if (!f.suppressed) counts[f.severity]++;
    return {
      ...report,
      findings: filteredFindings,
      counts,
      suppressedCount: filteredFindings.filter((f) => f.suppressed).length,
    };
  }, [report, filteredFindings]);

  /**
   * Exports what the list shows, not the whole report — for handing a triaged
   * subset to someone. Human formats only: JSON stays the full data by
   * definition, and a partial SARIF upload would make code scanning close every
   * alert absent from it as fixed. The document carries a note saying it is a
   * subset, so it cannot pass for the full report.
   */
  const exportFiltered = async (kind: "md" | "csv" | "html") => {
    if (!report || !filteredReport) return;
    const note = t("Отфильтрованная выборка: {n} из {total} находок полного отчёта.", {
      n: filteredReport.findings.length,
      total: report.findings.length,
    });
    const base = `vulnscope-${report.targetLabel.replace(/[^\w.-]/g, "_")}-filtered`;
    const cfg = {
      md: { ext: "md", name: "Markdown", body: () => toMarkdown(filteredReport, t, note) },
      csv: { ext: "csv", name: "CSV", body: () => toCsv(filteredReport, t) },
      html: { ext: "html", name: "HTML", body: () => toHtml(filteredReport, t, note) },
    }[kind];
    const path = await saveDialog({
      defaultPath: `${base}.${cfg.ext}`,
      filters: [{ name: cfg.name, extensions: [cfg.ext] }],
    });
    if (!path) return;
    await invoke("save_report", { path, json: cfg.body() }).catch((e) => setError(String(e)));
  };

  const toggleSev = useCallback((s: Severity) => {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }, []);

  const findingFilters: FindingFilters = useMemo(
    () => ({
      // What this tab holds before the filters run. The file selection is folded
      // in rather than treated as a filter — the tree is a separate control, and
      // counting it would claim "скрыто 160" the moment the user clicks a file —
      // but the BETA split is, or the ratio would be measured against findings
      // this tab never shows.
      total: report
        ? report.findings.filter((f) => {
            if ((tab === "beta") !== !!f.extra?.experimental) return false;
            if (selectedFile && (tab === "findings" || tab === "beta"))
              return f.file === selectedFile;
            return true;
          }).length
        : 0,
      newCount: report?.delta.newCount ?? 0,
      suppressedCount: report?.suppressedCount ?? 0,
      query: findingQuery,
      setQuery: setFindingQuery,
      onlyNew,
      setOnlyNew,
      showSuppressed,
      setShowSuppressed,
      sevFilter,
      toggleSev,
      file: tab === "findings" || tab === "beta" ? selectedFile : null,
      clearFile: () => setSelectedFile(null),
      author: authorFilter,
      clearAuthor: () => setAuthorFilter(null),
      reset: resetFilters,
    }),
    [report, selectedFile, tab, findingQuery, onlyNew, showSuppressed, sevFilter, toggleSev, authorFilter, resetFilters]
  );

  const openFileAt = useCallback((path: string, line: number) => {
    setSelectedFile(path);
    setFocusLine(line > 0 ? line : null);
    setTab("code");
  }, []);

  /** Folds a single-file re-check back into the report: the fresh findings for
   * that file replace the previous ones from the engines a re-check re-runs
   * (built-in, secrets, custom); external-tool and dependency findings are left
   * as they were. Fixed findings simply drop out — the green banner and toast
   * confirm the win — and counts are recomputed so the dashboard and tree stay
   * honest with what is really left. */
  const onRechecked = useCallback(
    (path: string, fresh: Finding[], fixed: string[]) => {
      setReport((prev) => {
        if (!prev) return prev;
        const RECHECKABLE = new Set(["builtin", "custom", "secrets"]);
        const kept = prev.findings.filter(
          (f) => f.file !== path || !RECHECKABLE.has(f.source)
        );
        const findings = [...kept, ...fresh];

        // Recompute severity counts (globally and per file) over what still
        // needs attention — suppressed findings stay out, matching the scan.
        const zero = (): Record<Severity, number> => ({
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        });
        const counts = zero();
        const perFile = new Map<string, Record<Severity, number>>();
        for (const f of findings) {
          if (f.suppressed) continue;
          counts[f.severity]++;
          let c = perFile.get(f.file);
          if (!c) perFile.set(f.file, (c = zero()));
          c[f.severity]++;
        }
        const files = prev.files.map((file) => {
          const use = perFile.get(file.path) ?? zero();
          const maxSeverity = SEVERITY_ORDER.find((s) => use[s] > 0) ?? null;
          return { ...file, counts: use, maxSeverity };
        });
        return { ...prev, findings, counts, files };
      });

      // Keep the current selection from pointing at a finding that no longer
      // exists, so the detail panel doesn't show a stale entry.
      if (fixed.length > 0) {
        setSelectedFinding((cur) =>
          cur && fixed.includes(cur.fingerprint) ? null : cur
        );
        showFlash(t("Исправлено находок: {n}", { n: fixed.length }));
      }
    },
    [showFlash, t]
  );

  /** Moves the selection within the currently filtered finding list. */
  const step = useCallback(
    (delta: number) => {
      if (filteredFindings.length === 0) return;
      const i = filteredFindings.findIndex((f) => f.id === selectedFinding?.id);
      const next = Math.min(
        filteredFindings.length - 1,
        Math.max(0, (i === -1 ? 0 : i) + delta)
      );
      setSelectedFinding(filteredFindings[next]);
    },
    [filteredFindings, selectedFinding]
  );

  /** Opens a secondary screen, remembering where to return to. */
  const SECONDARY: Screen[] = ["rules", "myrules", "settings", "help", "report"];
  const goto = useCallback(
    (target: Screen) => {
      // Hopping between secondary screens keeps the primary one to return to.
      setPrevScreen(SECONDARY.includes(screen) ? prevScreen : (screen as Screen));
      setScreen(target);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [screen, prevScreen]
  );

  const openRules = useCallback(() => goto("rules"), [goto]);
  const openSettings = useCallback(() => goto("settings"), [goto]);
  const openMyRules = useCallback(() => goto("myrules"), [goto]);
  const openHelp = useCallback(() => goto("help"), [goto]);

  const commands: Command[] = useMemo(
    () => [
      // The setup screen's own actions come first: the palette is advertised in
      // the titlebar, and it used to open on this screen offering three items,
      // none of which was the thing the screen exists to do.
      {
        id: "start-scan",
        label: t("Начать сканирование"),
        hint: canScan ? target : t("сначала укажите цель"),
        icon: "play_arrow",
        when: screen === "setup" && canScan,
        run: startScan,
      },
      {
        id: "pick-folder",
        label: t("Выбрать папку…"),
        hint: t("обзор диска"),
        icon: "folder_open",
        when: screen === "setup" && mode === "local",
        run: pickFolder,
      },
      {
        id: "mode-repo",
        label: mode === "repo" ? t("Сканировать локальную папку") : t("Сканировать репозиторий"),
        icon: mode === "repo" ? "folder" : "cloud_download",
        when: screen === "setup",
        run: () => setMode(mode === "repo" ? "local" : "repo"),
      },
      {
        id: "scan",
        label: t("Новое сканирование"),
        icon: "restart_alt",
        keys: "Ctrl N",
        when: screen === "results" || screen === "rules",
        run: () => setScreen("setup"),
      },
      {
        // The loop after a finding is fix → check. Going through the setup
        // screen to re-run the same target made that two steps for nothing.
        id: "rescan",
        label: t("Пересканировать"),
        hint: report?.targetLabel,
        icon: "refresh",
        keys: "Ctrl Shift R",
        when: screen === "results" && !!report,
        run: rescan,
      },
      {
        id: "rules",
        label: t("Каталог правил"),
        hint: t("встроенные"),
        icon: "rule",
        keys: "Ctrl R",
        when: screen !== "scanning",
        run: openRules,
      },
      {
        id: "settings",
        label: t("Настройки"),
        hint: t("лимиты, клавиши, вид"),
        icon: "tune",
        when: screen !== "scanning",
        run: openSettings,
      },
      {
        id: "myrules",
        label: t("Свои правила"),
        hint: t("создать и изменить"),
        icon: "edit_note",
        keys: "Ctrl E",
        when: screen !== "scanning",
        run: openMyRules,
      },
      {
        id: "export",
        label: t("Экспорт отчёта в JSON"),
        icon: "download",
        keys: "Ctrl S",
        when: screen === "results" && !!report,
        run: exportReport,
      },
      {
        id: "export-sarif",
        label: t("Экспорт в SARIF (для CI)"),
        hint: t("GitHub code scanning и др."),
        icon: "data_object",
        when: screen === "results" && !!report,
        run: exportSarif,
      },
      {
        id: "export-md",
        label: t("Экспорт в Markdown"),
        hint: t("для PR, issue или чата"),
        icon: "article",
        when: screen === "results" && !!report,
        run: exportMarkdown,
      },
      {
        id: "export-csv",
        label: t("Экспорт в CSV (для таблиц)"),
        hint: t("для сортировки и триажа"),
        icon: "table_view",
        when: screen === "results" && !!report,
        run: exportCsv,
      },
      {
        id: "export-excel",
        label: t("Экспорт в Excel (книга)"),
        hint: t("сводка, находки, ответственные"),
        icon: "table_view",
        when: screen === "results" && !!report,
        run: exportExcel,
      },
      {
        id: "export-html",
        label: t("Экспорт в HTML (для браузера)"),
        hint: t("открыть или напечатать в PDF"),
        icon: "html",
        when: screen === "results" && !!report,
        run: exportHtml,
      },
      // Exporting the triaged subset. Offered only while the list differs from
      // the full report, and only in the human formats: JSON is the full data by
      // definition, and a partial SARIF would close absent alerts as fixed.
      ...(["md", "csv", "html"] as const).map((kind) => ({
        id: `export-filtered-${kind}`,
        label: t(
          {
            md: "Экспорт отфильтрованного в Markdown",
            csv: "Экспорт отфильтрованного в CSV",
            html: "Экспорт отфильтрованного в HTML",
          }[kind]
        ),
        hint: report
          ? t("{n} из {total} находок", {
              n: filteredFindings.length,
              total: report.findings.length,
            })
          : undefined,
        icon: "filter_alt",
        when:
          screen === "results" &&
          !!report &&
          filteredFindings.length > 0 &&
          filteredFindings.length !== report.findings.length,
        run: () => exportFiltered(kind),
      })),
      {
        id: "copy-md",
        label: t("Скопировать отчёт (Markdown)"),
        hint: t("в буфер обмена — для PR или чата"),
        icon: "content_copy",
        when: screen === "results" && !!report,
        run: copyMarkdown,
      },
      {
        id: "cancel",
        label: t("Отменить сканирование"),
        icon: "stop_circle",
        when: screen === "scanning",
        run: cancelScan,
      },
      ...TABS.map((tb, i) => ({
        id: `tab-${tb}`,
        label: t("Вкладка: {name}", { name: t({ overview: t("Обзор"), findings: t("Находки"), beta: t("Экспериментальные"), code: t("Код"), skipped: t("Пропущено") }[tb]) }),
        icon: { overview: "dashboard", findings: "bug_report", beta: "science", code: "code", skipped: "block" }[tb],
        keys: String(i + 1),
        when: screen === "results",
        run: () => setTab(tb),
      })),
      {
        id: "only-new",
        label: onlyNew ? t("Показать все находки") : t("Показать только новые"),
        icon: "fiber_new",
        when: screen === "results" && (report?.delta.newCount ?? 0) > 0,
        run: () => setOnlyNew((v) => !v),
      },
      {
        id: "clear-filters",
        label: t("Сбросить фильтры"),
        icon: "filter_alt_off",
        when:
          screen === "results" &&
          (sevFilter.size > 0 || onlyNew || showSuppressed || findingQuery !== "" || !!selectedFile),
        run: () => {
          setSevFilter(new Set());
          setOnlyNew(false);
          setShowSuppressed(false);
          setFindingQuery("");
        },
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      screen,
      report,
      sevFilter,
      onlyNew,
      showSuppressed,
      findingQuery,
      selectedFile,
      mode,
      canScan,
      target,
      openRules,
      openMyRules,
      openSettings,
      exportReport,
      exportSarif,
      exportMarkdown,
      exportCsv,
      exportExcel,
      exportHtml,
      exportFiltered,
      filteredFindings,
      copyMarkdown,
      rescan,
    ]
  );

  /** Looks up an action's combo, so rebinding in settings takes effect at once. */
  const bind = useCallback(
    (action: string, fallback: string) => settings?.keybinds?.[action] ?? fallback,
    [settings]
  );

  const hotkeys = useMemo(() => {
    const map: Record<string, (e: KeyboardEvent) => void> = {};
    const on = (action: string, fallback: string, fn: (e: KeyboardEvent) => void) => {
      const combo = bind(action, fallback);
      // An empty combo means the user cleared the binding on purpose.
      if (combo) map[combo] = fn;
    };

    on("palette", "mod+k", (e) => {
      e.preventDefault();
      setPaletteOpen((v) => !v);
    });
    on("rules", "mod+r", (e) => {
      e.preventDefault();
      if (screen !== "scanning") openRules();
    });
    on("myRules", "mod+e", (e) => {
      e.preventDefault();
      if (screen !== "scanning") openMyRules();
    });
    on("settings", "mod+,", (e) => {
      e.preventDefault();
      if (screen !== "scanning") openSettings();
    });
    on("newScan", "mod+n", (e) => {
      e.preventDefault();
      if (screen === "results" || screen === "rules") setScreen("setup");
    });
    on("rescan", "mod+shift+r", (e) => {
      if (screen === "results" && report) {
        e.preventDefault();
        rescan();
      }
    });
    on("export", "mod+s", (e) => {
      if (screen === "results" && report) {
        e.preventDefault();
        exportReport();
      }
    });
    on("tabOverview", "1", () => screen === "results" && setTab("overview"));
    on("tabFindings", "2", () => screen === "results" && setTab("findings"));
    on("tabBeta", "3", () => screen === "results" && setTab("beta"));
    on("tabCode", "4", () => screen === "results" && setTab("code"));
    on("tabSkipped", "5", () => screen === "results" && setTab("skipped"));
    on("nextFinding", "j", () => screen === "results" && (tab === "findings" || tab === "beta") && step(1));
    on("prevFinding", "k", () => screen === "results" && (tab === "findings" || tab === "beta") && step(-1));
    on("openInCode", "enter", () => {
      if (screen === "results" && tab === "findings" && selectedFinding) {
        openFileAt(selectedFinding.file, selectedFinding.line);
      }
    });

    // Arrows mirror j/k without being rebindable: they are the discoverable
    // default and users expect them to just work.
    map["arrowdown"] = (e) => {
      if (screen === "results" && tab === "findings") {
        e.preventDefault();
        step(1);
      }
    };
    map["arrowup"] = (e) => {
      if (screen === "results" && tab === "findings") {
        e.preventDefault();
        step(-1);
      }
    };
    map["escape"] = () => {
      if (paletteOpen) setPaletteOpen(false);
      else if (screen === "rules" || screen === "myrules" || screen === "settings")
        setScreen(prevScreen);
    };

    return map;
  }, [
    bind,
    screen,
    tab,
    paletteOpen,
    prevScreen,
    report,
    selectedFinding,
    step,
    openRules,
    openMyRules,
    openSettings,
    openFileAt,
    exportReport,
    rescan,
  ]);

  useHotkeys(hotkeys, [hotkeys]);

  return (
    <LangContext.Provider value={lang}>
    <div className="app">
      {/* Ambient light behind everything. aria-hidden and pointer-events: none —
          it is scenery, not content. */}
      <div className="ambient" aria-hidden="true">
        <span className="amb amb-1" />
        <span className="amb amb-2" />
      </div>
      <Titlebar>
        {(screen === "setup" || screen === "results") && (
          <>
            <button
              className="btn btn-ghost btn-sm"
              onClick={openSettings}
              title={t("Настройки")}
              aria-label={t("Настройки")}
            >
              <Icon name="tune" />
            </button>
            <button className="btn btn-ghost btn-sm" onClick={openRules} title="Ctrl+R">
              <Icon name="rule" />
              {t("Правила")}
            </button>
            <button className="btn btn-ghost btn-sm" onClick={openMyRules} title="Ctrl+E">
              <Icon name="edit_note" />
              {t("Свои")}
            </button>
          </>
        )}
        {screen === "results" && report && (
          <>
            <div className="export-wrap">
              <button
                className="btn btn-ghost btn-sm"
                onClick={(e) => {
                  const r = e.currentTarget.getBoundingClientRect();
                  setExportPos({ top: r.bottom + 4, right: window.innerWidth - r.right });
                  setExportOpen((v) => !v);
                }}
                title="Ctrl+S"
                aria-haspopup="menu"
                aria-expanded={exportOpen}
              >
                <Icon name="download" />
                {t("Экспорт")}
                <Icon name="expand_more" className="export-caret" />
              </button>
              {exportOpen &&
                createPortal(
                  <>
                    <div className="export-scrim" onClick={() => setExportOpen(false)} />
                    <div
                      className="export-menu"
                      role="menu"
                      style={{ top: exportPos.top, right: exportPos.right }}
                    >
                      {(
                        [
                          ["summarize", t("Отчёт — печать в PDF"), () => goto("report")],
                          ["data_object", t("JSON — полные данные"), exportReport],
                          ["security", t("SARIF — для CI и code scanning"), exportSarif],
                          ["description", t("Markdown — для тикета или чата"), exportMarkdown],
                          ["table_chart", t("CSV — открыть в Excel"), exportCsv],
                          ["table_view", t("Excel — книга с листами и разбивкой"), exportExcel],
                          ["print", t("HTML — открыть и печатать в PDF"), exportHtml],
                          ["account_balance", t("XML для 1С — загрузка в отчётность"), exportXml1C],
                          ["content_copy", t("Скопировать Markdown"), copyMarkdown],
                        ] as const
                      ).map(([icon, label, fn]) => (
                        <button
                          key={label}
                          className="export-item"
                          role="menuitem"
                          onClick={() => {
                            setExportOpen(false);
                            fn();
                          }}
                        >
                          <Icon name={icon} />
                          {label}
                        </button>
                      ))}
                    </div>
                  </>,
                  document.body
                )}
            </div>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setScreen("setup")}
              title="Ctrl+N"
            >
              <Icon name="restart_alt" />
              {t("Новое сканирование")}
            </button>
          </>
        )}
        {screen === "scanning" && (
          <button className="btn btn-danger btn-sm" onClick={cancelScan}>
            <Icon name="stop_circle" />
            {t("Отменить")}
          </button>
        )}
        {screen !== "scanning" && (
          <button
            className="btn btn-ghost btn-sm"
            onClick={openHelp}
            title={t("Справка")}
            aria-label={t("Справка")}
          >
            <Icon name="help" />
          </button>
        )}
        <button
          className="btn btn-ghost btn-sm"
          onClick={() => setPaletteOpen(true)}
          title={t("Команды — Ctrl+K")}
          aria-label={t("Команды")}
        >
          <Icon name="terminal" />
          <kbd>Ctrl K</kbd>
        </button>
      </Titlebar>

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        commands={commands}
      />

      <ViewTransition view={screen === "results" ? `results-${tab}` : screen}>
      {screen === "setup" && (
        <SetupScreen
          mode={mode}
          setMode={setMode}
          localPath={localPath}
          setLocalPath={setLocalPath}
          repoUrl={repoUrl}
          setRepoUrl={setRepoUrl}
          pickFolder={pickFolder}
          tools={tools}
          setTools={setTools}
          error={error}
          respectGitignore={respectGitignore}
          setRespectGitignore={setRespectGitignore}
          includeVendor={includeVendor}
          setIncludeVendor={setIncludeVendor}
          checkSecrets={checkSecrets}
          setCheckSecrets={setCheckSecrets}
          checkDependencies={checkDependencies}
          setCheckDependencies={setCheckDependencies}
          experimental={experimental}
          setExperimental={setExperimental}
          dataflow={dataflow}
          setDataflow={setDataflow}
          enabledTools={enabledTools}
          setEnabledTools={setEnabledTools}
          canScan={canScan}
          startScan={startScan}
          import1c={import1c}
          projects1c={projects1c}
          pick1cProject={pick1cProject}
        />
      )}

      {screen === "help" && <HelpScreen onClose={() => setScreen(prevScreen)} />}

      {screen === "report" && report && (
        <ReportScreen report={report} onClose={() => setScreen(prevScreen)} />
      )}

      {screen === "rules" && <RulesScreen onClose={() => setScreen(prevScreen)} />}

      {screen === "myrules" && <RuleEditor onClose={() => setScreen(prevScreen)} />}

      {screen === "settings" && (
        <SettingsScreen onClose={() => setScreen(prevScreen)} onApplied={setSettings} />
      )}

      {screen === "scanning" && <ScanningScreen progress={progress} plan={phasePlan} />}

      {screen === "results" && report && (
        <>
          <div className="summary-bar">
            <div className="target-chip">
              <Icon name={report.root.includes("repos") ? "cloud_download" : "folder"} />
              {report.targetLabel}
            </div>
            <div className="sev-pills">
              {SEVERITY_ORDER.map((s) => {
                const n = sevPillCounts[s];
                const all = report.counts[s];
                // Say so when the pill is counting a narrowed view, or the
                // number silently stops meaning "in this project".
                const title =
                  n !== all
                    ? t("{sev}: {n} в текущей выборке, всего {all}", {
                        sev: t(SEVERITY_LABEL[s]),
                        n,
                        all,
                      })
                    : `${t(SEVERITY_LABEL[s])}: ${n}`;
                return (
                  <button
                    key={s}
                    className={`sev-pill ${s} ${n === 0 ? "zero" : ""} ${
                      sevFilter.has(s) ? "active" : ""
                    } ${n !== all ? "scoped" : ""}`}
                    onClick={() => toggleSev(s)}
                    title={title}
                  >
                    <Icon name={SEVERITY_SYMBOL[s]} />
                    {n}
                  </button>
                );
              })}
            </div>
            <div style={{ flex: 1 }} />
            <span className="meta-chip">
              <Icon name="timer" />
              {formatDuration(report.durationMs)}
            </span>
            <span className="meta-chip">
              <Icon name="description" />
              {t("{n} файлов", { n: formatNumber(report.filesScanned) })}
            </span>
            <span className="meta-chip">
              <Icon name="numbers" />
              {t("{n} строк", { n: formatNumber(report.linesScanned) })}
            </span>
          </div>

          <div className="subtabs">
            <button
              className={`subtab ${tab === "overview" ? "active" : ""}`}
              onClick={() => setTab("overview")}
            >
              <Icon name="dashboard" />
              {t("Обзор")}
            </button>
            <button
              className={`subtab ${tab === "findings" ? "active" : ""}`}
              onClick={() => setTab("findings")}
            >
              <Icon name="bug_report" />
              {t("Находки")}
              <span
                className={`count ${shownConfirmed !== confirmedCount ? "narrowed" : ""}`}
                title={
                  shownConfirmed !== confirmedCount
                    ? t("Под фильтры подходит {n} из {total}", {
                        n: shownConfirmed,
                        total: confirmedCount,
                      })
                    : undefined
                }
              >
                {shownConfirmed !== confirmedCount
                  ? `${shownConfirmed}/${confirmedCount}`
                  : confirmedCount}
              </span>
            </button>
            {betaCount > 0 && (
              <button
                className={`subtab subtab-beta ${tab === "beta" ? "active" : ""}`}
                onClick={() => setTab("beta")}
                title={t("Экспериментальные (BETA) находки — требуют ручной проверки")}
              >
                <Icon name="science" />
                {t("Экспериментальные")}
                <span className="tag beta">BETA</span>
                <span className={`count ${shownBeta !== betaCount ? "narrowed" : ""}`}>
                  {shownBeta !== betaCount ? `${shownBeta}/${betaCount}` : betaCount}
                </span>
              </button>
            )}
            <button
              className={`subtab ${tab === "code" ? "active" : ""}`}
              onClick={() => setTab("code")}
            >
              <Icon name="code" />
              {t("Код")}
            </button>
            <button
              className={`subtab ${tab === "skipped" ? "active" : ""}`}
              onClick={() => setTab("skipped")}
            >
              <Icon name="block" />
              {t("Пропущено")}
              <span className="count">{report.skipped.length}</span>
            </button>
          </div>

          {tab === "overview" && (
            <Overview
              report={report}
              onOpenFinding={(f) => {
                setSelectedFinding(f);
                setSelectedFile(null);
                setTab("findings");
              }}
            />
          )}

          {(tab === "findings" || tab === "beta") && (
            <div className="results">
              <FileTree
                width={treeW}
                files={treeFiles}
                selected={selectedFile}
                onSelect={(p) => setSelectedFile(selectedFile === p ? null : p)}
              />
              <Resizer width={treeW} setWidth={setTreeW} storageKey="vs.treeW" />
              <FindingList
                width={listW}
                findings={filteredFindings}
                selected={selectedFinding?.id ?? null}
                onSelect={setSelectedFinding}
                filters={findingFilters}
              />
              <Resizer
                width={listW}
                setWidth={setListW}
                min={260}
                max={620}
                storageKey="vs.listW"
              />
              <div className="detail-panel">
                <FindingDetail
                  finding={selectedFinding}
                  onOpenFile={openFileAt}
                  root={report.root}
                  onSuppressionChanged={rescan}
                  editorCommand={settings?.editorCommand ?? ""}
                  onFilterAuthor={(author) => {
                    setAuthorFilter(author);
                    setSelectedFile(null);
                    setTab("findings");
                  }}
                />
              </div>
            </div>
          )}

          {tab === "code" && (
            <div className="results">
              <FileTree
                width={treeW}
                files={treeFiles}
                selected={selectedFile}
                onSelect={(p) => {
                  setSelectedFile(p);
                  setFocusLine(null);
                }}
              />
              <Resizer width={treeW} setWidth={setTreeW} storageKey="vs.treeW" />
              <div className="detail-panel">
                {selectedFile ? (
                  <CodeViewer
                    root={report.root}
                    path={selectedFile}
                    findings={fileFindings}
                    focusLine={focusLine}
                    checkSecrets={checkSecrets}
                    experimental={experimental}
                    dataflow={dataflow}
                    onRechecked={onRechecked}
                  />
                ) : (
                  <div className="detail-empty">
                    <Icon name="code_off" />
                    <span>{t("Выберите файл слева")}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {tab === "skipped" && <SkippedView report={report} />}
        </>
      )}
      </ViewTransition>
      {flash && (
        <div className="toast" role="status" aria-live="polite">
          <Icon name="check_circle" />
          {flash}
        </div>
      )}
    </div>
    </LangContext.Provider>
  );
}

// ------------------------------------------------------------------ setup

interface SetupProps {
  mode: "local" | "repo";
  setMode: (m: "local" | "repo") => void;
  localPath: string;
  setLocalPath: (v: string) => void;
  repoUrl: string;
  setRepoUrl: (v: string) => void;
  pickFolder: () => void;
  tools: ToolsInfo | null;
  setTools: (t: ToolsInfo) => void;
  error: string | null;
  respectGitignore: boolean;
  setRespectGitignore: (v: boolean) => void;
  includeVendor: boolean;
  setIncludeVendor: (v: boolean) => void;
  checkSecrets: boolean;
  setCheckSecrets: (v: boolean) => void;
  checkDependencies: boolean;
  setCheckDependencies: (v: boolean) => void;
  experimental: boolean;
  setExperimental: (v: boolean) => void;
  dataflow: boolean;
  setDataflow: (v: boolean) => void;
  enabledTools: Set<ToolId>;
  setEnabledTools: (v: Set<ToolId>) => void;
  canScan: boolean;
  startScan: () => void;
  import1c: () => void;
  projects1c: Project1c[];
  pick1cProject: (pr: Project1c) => void;
}

function SetupScreen(p: SetupProps) {
  const t = useT();
  return (
    <div className="setup">
      <div className="setup-scroll">
      <div className="setup-inner">
        <div className="hero">
          <div className="hero-mark">
            <Icon name="shield_lock" />
          </div>
          <h1>{t("Проверьте код на уязвимости")}</h1>
          <p>
{t("Локальный анализ без отправки кода наружу. Находит опасные конструкции, секреты в исходниках и известные CVE в зависимостях.")}
          </p>
        </div>

        {p.error && (
          <div className="error-banner">
            <Icon name="error" />
            {p.error}
          </div>
        )}

        <div className="card">
          <div className="tabs">
            <button
              className={`tab ${p.mode === "local" ? "active" : ""}`}
              onClick={() => p.setMode("local")}
            >
              <Icon name="folder" />
              {t("Локальная папка")}
            </button>
            <button
              className={`tab ${p.mode === "repo" ? "active" : ""}`}
              onClick={() => p.setMode("repo")}
            >
              <Icon name="cloud_download" />
              {t("Репозиторий")}
            </button>
          </div>

          {p.mode === "local" ? (
            <>
              <div className="field-row">
                <input
                  className="input mono"
                  placeholder="D:\Projects\my-app"
                  value={p.localPath}
                  onChange={(e) => p.setLocalPath(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && p.canScan) p.startScan();
                  }}
                  autoFocus
                />
                <button className="btn btn-ghost" onClick={p.pickFolder}>
                  <Icon name="folder_open" />
                  {t("Выбрать")}
                </button>
              </div>
              <div className="field-hint">
                <Icon name="lock" />
                {t("Файлы читаются только на этом компьютере и никуда не отправляются.")}
              </div>
            </>
          ) : (
            <>
              <div className="field-row">
                <input
                  className="input mono"
                  placeholder="https://github.com/owner/repo"
                  value={p.repoUrl}
                  onChange={(e) => p.setRepoUrl(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && p.canScan) p.startScan();
                  }}
                  autoFocus
                />
              </div>
              <div className="field-hint">
                <Icon name={p.tools?.gitAvailable ? "info" : "warning"} />
                {p.tools?.gitAvailable
                  ? t("Публичный репозиторий клонируется во временную папку. Она нужна, чтобы показывать код после проверки, и очищается при следующем сканировании.")
                  : t("Git не найден в PATH — сканирование по ссылке недоступно.")}
              </div>
            </>
          )}

          {/* Import an audit-target registry exported from 1C, then pick one. */}
          <div className="import-1c">
            <button className="btn btn-ghost btn-sm" onClick={p.import1c}>
              <Icon name="account_balance" />
              {t("Импорт проектов из 1С")}
            </button>
            {p.projects1c.length > 0 && (
              <div className="import-1c-list">
                {p.projects1c.map((pr, i) => (
                  <button key={i} className="import-1c-item" onClick={() => p.pick1cProject(pr)}>
                    <Icon name={pr.repo ? "cloud_download" : "folder"} />
                    <span className="i1c-name">{pr.name || pr.repo || pr.path}</span>
                    <span className="i1c-target">{pr.repo || pr.path}</span>
                    {pr.owner && <span className="i1c-owner">{pr.owner}</span>}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <Icon name="tune" />
            {t("Что проверять")}
          </div>
          <div className="opt-grid">
            <Check
              checked={p.checkSecrets}
              onChange={p.setCheckSecrets}
              title={t("Секреты в коде")}
              desc={t("Ключи API, токены, пароли, приватные ключи")}
            />
            <Check
              checked={p.checkDependencies}
              onChange={p.setCheckDependencies}
              title={t("CVE в зависимостях")}
              desc={t("Запрос к базе OSV.dev, результат кэшируется")}
            />
            <Check
              checked={p.respectGitignore}
              onChange={p.setRespectGitignore}
              title={t("Учитывать .gitignore")}
              desc={t("Пропускать то, что не попадает в репозиторий")}
            />
            <Check
              checked={p.includeVendor}
              onChange={p.setIncludeVendor}
              title={t("Включая зависимости")}
              desc={t("Сканировать node_modules, venv и т.п. Заметно дольше")}
            />
            <Check
              checked={p.dataflow}
              onChange={(v) => {
                p.setDataflow(v);
                localStorage.setItem("vs.dataflow", v ? "1" : "0");
              }}
              title={t("Анализ потока данных")}
              desc={t(
                "Прослеживает пользовательский ввод через переменные до опасного вызова и показывает весь путь",
              )}
            />
            <Check
              checked={p.experimental}
              onChange={(v) => {
                p.setExperimental(v);
                localStorage.setItem("vs.experimental", v ? "1" : "0");
              }}
              title={
                <>
                  {t("Экспериментальные проверки")}
                  <span className="beta-badge">BETA</span>
                </>
              }
              desc={t(
                "Эвристики: помечают возможные уязвимости, которые не поймали точные правила",
              )}
            />
          </div>
        </div>

        {p.tools ? (
          <ToolsCard
            tools={p.tools}
            setTools={p.setTools}
            enabledTools={p.enabledTools}
            setEnabledTools={p.setEnabledTools}
          />
        ) : (
          <ToolsLoading />
        )}

      </div>
      </div>

      {/* Outside the scroll area on purpose: the tools card loads a moment
          after the screen and used to push the only action below the fold. */}
      <div className="setup-actions">
        <button className="btn btn-primary btn-scan" disabled={!p.canScan} onClick={p.startScan}>
          <Icon name="play_arrow" />
          {t("Начать сканирование")}
        </button>
        {/* The slot keeps its height whether or not the hint is there: letting
            the hint appear and vanish would shift the button under the cursor. */}
        <div className="scan-hint-slot">
          {!p.canScan && (
            <span className="scan-hint">
              <Icon name="info" />
              {p.mode === "local" ? t("Укажите папку с проектом") : t("Вставьте ссылку на репозиторий")}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function Check({
  checked,
  onChange,
  title,
  desc,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  title: ReactNode;
  desc: string;
}) {
  return (
    <label className={`opt ${checked ? "checked" : ""}`}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span className="opt-box">
        <Icon name="check" />
      </span>
      <span className="opt-text">
        <strong>{title}</strong>
        <span>{desc}</span>
      </span>
    </label>
  );
}

// --------------------------------------------------------------- scanning

/** The order phases actually run in. Used to decide what is already behind us. */
const PHASE_ORDER: ScanPhase[] = [
  "preparing",
  "cloning",
  "discovering",
  "scanningCode",
  "scanningSecrets",
  "resolvingDependencies",
  "queryingOsv",
  "runningExternalTools",
  "finalizing",
];

const PHASE_STEP_LABEL: Partial<Record<ScanPhase, string>> = {
  preparing: "Подготовка",
  cloning: "Клонирование",
  discovering: "Поиск файлов",
  scanningCode: "Анализ кода",
  resolvingDependencies: "Зависимости",
  queryingOsv: "База CVE",
  runningExternalTools: "Внешние сканеры",
  finalizing: "Отчёт",
};

/** Phases whose progress the file counter actually describes. */
const COUNTED_PHASES: ScanPhase[] = ["discovering", "scanningCode", "scanningSecrets"];

function ScanningScreen({ progress, plan }: { progress: ScanProgress | null; plan: ScanPhase[] }) {
  const t = useT();
  const pct = progress && progress.total > 0 ? (progress.processed / progress.total) * 100 : 0;
  const phase = progress?.phase ?? "preparing";
  const at = PHASE_ORDER.indexOf(phase);
  const counted = COUNTED_PHASES.includes(phase) && (progress?.total ?? 0) > 0;

  // The backend only emits between units of work, so during a long external
  // scanner the elapsed time would sit frozen and the app would look hung.
  // Time is passing either way — keep counting it locally from the last event.
  const [now, setNow] = useState(() => performance.now());
  const arrivedAt = useRef(performance.now());
  useEffect(() => {
    arrivedAt.current = performance.now();
    setNow(performance.now());
  }, [progress]);
  useEffect(() => {
    const id = setInterval(() => setNow(performance.now()), 200);
    return () => clearInterval(id);
  }, []);
  const elapsed = Math.round((progress?.elapsedMs ?? 0) + (now - arrivedAt.current));

  // A screen-reader announcement built from milestones, not frames. The visible
  // numbers change dozens of times a second; reading every change through a
  // live region is noise, so this updates only when the phase changes or the
  // progress crosses a 25% mark — the points a person actually wants to hear.
  const [liveMsg, setLiveMsg] = useState("");
  const lastSaid = useRef({ phase: "", bucket: -1 });
  useEffect(() => {
    const label = t(progress?.phaseLabel ?? t("Подготовка"));
    const bucket = counted ? Math.floor(pct / 25) : -1;
    if (label !== lastSaid.current.phase || bucket !== lastSaid.current.bucket) {
      lastSaid.current = { phase: label, bucket };
      setLiveMsg(
        counted && progress
          ? t("{label}: {pct}%, проверено {done} из {total}", { label, pct: Math.round(pct), done: progress.processed, total: progress.total })
          : label
      );
    }
  }, [progress, counted, pct]);

  return (
    <div className="progress-view">
      <Announce message={liveMsg} />

      <ProgressRing percent={pct} indeterminate={!counted} label={progress?.phaseLabel ? t(progress.phaseLabel) : undefined} />
      <div style={{ textAlign: "center" }}>
        <div className="progress-phase">{t(progress?.phaseLabel ?? t("Подготовка"))}</div>
        <div className="progress-file" title={progress?.currentFile}>
          {progress?.currentFile || " "}
        </div>
      </div>

      {/* A slim progress line under the phase: a filled gradient bar when the
          phase counts files, an indeterminate sweep when it cannot (cloning,
          querying OSV). aria-hidden — the ring and live region already speak. */}
      <div
        className={`progress-line ${counted ? "" : "indeterminate"}`}
        aria-hidden="true"
      >
        <div className="progress-line-fill" style={counted ? { width: `${pct}%` } : undefined} />
      </div>

      {/* Built from the options this scan was started with, so a step that will
          never run is never shown waiting: OSV takes seconds while the code pass
          takes milliseconds, and without this the wait looks like a freeze. */}
      {/* aria-hidden: the done/active/todo state lives in colour and an icon,
          not in the text, so reading the raw list would drop exactly the part
          that matters. The live region announces the phase instead. */}
      <ol className="phase-steps" aria-hidden="true">
        {plan.map((p) => {
          const i = PHASE_ORDER.indexOf(p);
          const state = i < at ? "done" : i === at ? "active" : "todo";
          return (
            <li key={p} className={`phase-step ${state}`}>
              <span className="ps-dot">
                {state === "done" && <Icon name="check" />}
              </span>
              <span className="ps-label">{t(PHASE_STEP_LABEL[p] ?? p)}</span>
            </li>
          );
        })}
      </ol>
      {/* aria-hidden: these tick many times a second. The milestone the user
          needs is in the live region; letting a reader chase every number is
          the anti-pattern this whole design avoids. */}
      <div className="progress-stats" aria-hidden="true">
        <div className="pstat">
          <div className="pstat-val">
            {formatNumber(progress?.processed ?? 0)}
            <span style={{ color: "var(--t-3)", fontWeight: 400 }}>
              {" / "}
              {formatNumber(progress?.total ?? 0)}
            </span>
          </div>
          <div className="pstat-key">{t("Файлов")}</div>
        </div>
        <div className="pstat">
          <div className="pstat-val" style={{ color: "var(--crit)" }}>
            {formatNumber(progress?.findingsSoFar ?? 0)}
          </div>
          <div className="pstat-key">{t("Находок")}</div>
        </div>
        <div className="pstat">
          <div className="pstat-val">{Math.round(progress?.filesPerSec ?? 0)}</div>
          <div className="pstat-key">{t("Файлов/с")}</div>
        </div>
        <div className="pstat">
          <div className="pstat-val">
            {progress?.etaMs != null ? formatDuration(progress.etaMs) : "—"}
          </div>
          <div className="pstat-key">{t("Осталось")}</div>
        </div>
        <div className="pstat">
          <div className="pstat-val">{formatDuration(elapsed)}</div>
          <div className="pstat-key">{t("Прошло")}</div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- overview

/** Translates a backend engine name, handling the parameterised custom-rules one. */
function engineLabel(e: string, t: TFn): string {
  const m = /^Свои правила \((\d+)\)$/.exec(e);
  if (m) return t("Свои правила ({n})", { n: m[1] });
  return t(e);
}

/** One sentence describing how the scan ended, for the screen-reader summary. */
function scanSummary(report: ScanReport, lang: Lang): string {
  const t: TFn = (s, v) => translate(lang, s, v);
  if (report.cancelled) {
    return t("Сканирование отменено, результаты неполные. Отсутствие находок не означает, что код чист.");
  }
  const total = SEVERITY_ORDER.reduce((n, s) => n + report.counts[s], 0);
  if (total === 0) {
    return t("Сканирование завершено. Находок нет. Проверено файлов: {files}.", {
      files: report.filesScanned,
    });
  }
  // Russian inflects the severity word by count; English does not, so it just
  // takes the number and the translated label.
  const breakdown = SEVERITY_ORDER.filter((s) => report.counts[s] > 0)
    .map((s) =>
      lang === "en"
        ? `${report.counts[s]} ${translate(lang, SEVERITY_LABEL[s]).toLowerCase()}`
        : severityCounted(report.counts[s], s)
    )
    .join(", ");
  const parts = [t("Сканирование завершено. Найдено {total}: {breakdown}.", { total, breakdown })];
  if (report.delta.previousScanAt && (report.delta.newCount > 0 || report.delta.fixedCount > 0)) {
    parts.push(
      t("С прошлого скана: {new} новых, {fixed} исправлено.", {
        new: report.delta.newCount,
        fixed: report.delta.fixedCount,
      })
    );
  }
  if (report.suppressedCount > 0) {
    parts.push(t("Подавлено: {n}.", { n: report.suppressedCount }));
  }
  return parts.join(" ");
}

/** Maps a grade to the severity-token family it should be painted in. */
const GRADE_TONE: Record<Grade, string> = {
  A: "ok",
  B: "ok",
  C: "med",
  D: "high",
  F: "crit",
};

/**
 * The dashboard's headline: one animated ring that turns the whole report into a
 * 0–100 security score and an A–F grade, with the factor breakdown beside it.
 * The number that makes the report a verdict, not a list.
 */
function ScoreHero({ score }: { score: SecurityScore }) {
  const t = useT();
  const tone = GRADE_TONE[score.grade];
  const R = 52;
  const C = 2 * Math.PI * R;
  const dash = (score.score / 100) * C;

  return (
    <div className={`score-hero tone-${tone}`}>
      <div className="score-ring-wrap">
        <svg className="score-ring" viewBox="0 0 120 120" role="img" aria-label={`${score.score} / 100`}>
          <circle className="score-track" cx="60" cy="60" r={R} />
          <circle
            className="score-arc"
            cx="60"
            cy="60"
            r={R}
            style={{ strokeDasharray: `${dash} ${C}` }}
          />
        </svg>
        <div className="score-center">
          <div className="score-grade">{score.grade}</div>
          <div className="score-num">{Math.round(score.score)}</div>
        </div>
      </div>

      <div className="score-body">
        <div className="score-title">{t("Оценка защищённости")}</div>
        <div className="score-label">{t(score.label)}</div>
        {score.reachable > 0 && (
          <div className="score-reach" title={t("Учитываются подтверждённые находки; BETA и подавленные не входят. Достижимые по потоку данных весят больше.")}>
            <Icon name="my_location" />
            {t("{n} на пути данных", { n: String(score.reachable) })}
          </div>
        )}
        <div className="score-factors">
          {score.factors.map((f) => (
            <span key={f.severity} className={`score-factor ${f.severity}`} title={`−${f.penalty}`}>
              <span className={`sev-dot ${f.severity}`} />
              {t(SEVERITY_LABEL[f.severity])}
              <b>{f.count}</b>
            </span>
          ))}
          {score.factors.length === 0 && (
            <span className="score-clean">
              <Icon name="verified_user" />
              {t("Подтверждённых находок нет")}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Attack paths — the flagship made actionable.
 *
 * The score says "how bad"; this says "here are the exact routes an attacker
 * takes". The traced data-flows, ranked worst-first (severity, then whether the
 * chain crosses a file, then its length), each shown as a one-line
 * entry → sink summary you can click straight into. A grade plus its receipts.
 */
function AttackPaths({
  report,
  onOpenFinding,
}: {
  report: ScanReport;
  onOpenFinding: (f: Finding) => void;
}) {
  const t = useT();
  const paths = useMemo(() => {
    const sevRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return report.findings
      .filter((f) => f.ruleId === "VS-FLOW" && !f.suppressed)
      .map((f) => {
        const flow = f.extra?.flow ?? [];
        const crosses = flow.some((s) => s.file && s.file !== f.file);
        return { f, flow, crosses, steps: flow.length };
      })
      .sort(
        (a, b) =>
          sevRank[a.f.severity] - sevRank[b.f.severity] ||
          Number(b.crosses) - Number(a.crosses) ||
          b.steps - a.steps
      )
      .slice(0, 6);
  }, [report.findings]);

  if (paths.length === 0) return null;

  return (
    <div className="card attack-paths">
      <div className="card-title">
        <Icon name="conversion_path" />
        {t("Пути атаки")}
        <span className="count">{report.findings.filter((f) => f.ruleId === "VS-FLOW" && !f.suppressed).length}</span>
        <span className="ap-sub">{t("прослежено от ввода до опасного вызова")}</span>
      </div>
      <div className="ap-list">
        {paths.map(({ f, flow, crosses, steps }) => {
          const sink = flow[flow.length - 1];
          return (
            <button key={f.id} className="ap-row" onClick={() => onOpenFinding(f)}>
              <span className={`sev-dot ${f.severity}`} />
              <span className="ap-entry">
                <Icon name="login" />
                {t(f.extra?.entry ?? "пользовательский ввод")}
              </span>
              <Icon name="arrow_right_alt" className="ap-arrow" />
              <span className="ap-sink">{t(f.category)}</span>
              {crosses && (
                <span className="ap-xfile" title={t("Цепочка проходит через другой файл")}>
                  <Icon name="alt_route" />
                  {t("межфайловый")}
                </span>
              )}
              <span className="ap-loc">
                {(sink?.file ?? f.file).split(/[\\/]/).pop()}
                {sink ? `:${sink.line}` : ""}
              </span>
              <span className="ap-steps">{t("{n} шагов", { n: String(steps) })}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function Overview({
  report,
  onOpenFinding,
}: {
  report: ScanReport;
  onOpenFinding: (f: Finding) => void;
}) {
  const t = useT();
  const lang = useContext(LangContext);

  // Experimental (BETA) findings are *suspected*, not confirmed, and live on
  // their own tab — so they must not inflate the dashboard's headline numbers,
  // severity bars, or the risk shield. Count them separately.
  const confirmed = useMemo(
    () => report.findings.filter((f) => !f.extra?.experimental),
    [report.findings]
  );
  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
    for (const f of confirmed) c[f.severity]++;
    return c;
  }, [confirmed]);
  const betaCount = report.findings.length - confirmed.length;

  // A cancelled scan checked nothing, so it must never be styled like a clean
  // result — a green shield over "0 находок" reads as "you are safe".
  const risk = report.cancelled
    ? ""
    : counts.critical > 0
    ? "risk-critical"
    : counts.high > 0
    ? "risk-high"
    : "risk-ok";
  const maxSev = Math.max(...SEVERITY_ORDER.map((s) => counts[s]), 1);
  const maxLang = Math.max(...report.languages.map((l) => l.files), 1);

  // The spoken end of the scan, so a screen-reader user hears the outcome the
  // dashboard shows visually instead of landing on a silent screen. The reader
  // reached "Готово" on the progress screen; this is the result.
  const summary = scanSummary(report, lang);

  const score = useMemo(() => computeScore(report), [report]);

  return (
    <div className="overview">
      <Announce message={summary} />
      {score && <ScoreHero score={score} />}
      {!report.cancelled && <AttackPaths report={report} onOpenFinding={onOpenFinding} />}
      {!report.cancelled && report.delta.previousScanAt && (
        <div className="delta-bar">
          <div className={`delta-stat ${report.delta.newCount > 0 ? "bad" : ""}`}>
            <Icon name={report.delta.newCount > 0 ? "trending_up" : "check"} />
            <b>{report.delta.newCount}</b> {t("новых")}
          </div>
          <div className={`delta-stat ${report.delta.fixedCount > 0 ? "good" : ""}`}>
            <Icon name="trending_down" />
            <b>{report.delta.fixedCount}</b> {t("исправлено")}
          </div>
          <div className="delta-stat">
            <Icon name="remove" />
            <b>{report.delta.unchangedCount}</b> {t("без изменений")}
          </div>
          <div style={{ flex: 1 }} />
          <span className="meta-chip">
            <Icon name="history" />
            {t("с прошлого скана {date}", { date: new Date(report.delta.previousScanAt).toLocaleString(lang === "en" ? "en-US" : "ru-RU") })}
          </span>
        </div>
      )}

      {!report.cancelled && !report.delta.previousScanAt && (
        <div className="delta-bar">
          <Icon name="history" style={{ color: "var(--t-4)" }} />
          <span style={{ color: "var(--t-3)", fontSize: 12 }}>
{t("Первое сканирование этой цели — сравнивать пока не с чем. Следующий прогон покажет, что изменилось.")}
          </span>
        </div>
      )}

      {report.suppressedCount > 0 && (
        <div className="warn-box">
          <Icon name="visibility_off" />
{t("Подавлено находок: {n}. Они исключены из счётчиков и скрыты — включите «Подавленные» над списком, чтобы посмотреть или вернуть. Правила лежат в", { n: report.suppressedCount })} <code>.vulnscope-ignore</code>.
        </div>
      )}

      {report.cancelled && (
        <div className="error-banner">
          <Icon name="cancel" />
{t("Сканирование отменено — результаты неполные. Отсутствие находок здесь не означает, что код чист: большая часть файлов не проверялась.")}
        </div>
      )}
      {!report.cancelled &&
        report.warnings.map((w, i) => (
          <div key={i} className="warn-box">
            <Icon name="warning" />
            {w}
          </div>
        ))}

      <div className="ov-grid">
        <div className={`stat-card ${risk}`}>
          <Icon
            name={
              report.cancelled
                ? "cancel"
                : counts.critical > 0
                ? "gpp_maybe"
                : "verified_user"
            }
          />
          <div className="stat-val">
            {report.cancelled ? "—" : formatNumber(confirmed.length)}
          </div>
          <div className="stat-key">
            {report.cancelled ? t("Проверка не завершена") : t("Всего находок")}
          </div>
          {!report.cancelled && betaCount > 0 && (
            <div className="stat-beta" title={t("Экспериментальные (BETA) находки не входят в счётчики — см. отдельную вкладку")}>
              <Icon name="science" />
              {t("+{n} BETA", { n: String(betaCount) })}
            </div>
          )}
        </div>
        <div className="stat-card">
          <Icon name="description" />
          <div className="stat-val">{formatNumber(report.filesScanned)}</div>
          <div className="stat-key">{t("Файлов проверено")}</div>
        </div>
        <div className="stat-card">
          <Icon name="numbers" />
          <div className="stat-val">{formatNumber(report.linesScanned)}</div>
          <div className="stat-key">{t("Строк кода")}</div>
        </div>
        <div className="stat-card">
          <Icon name="inventory_2" />
          <div className="stat-val">{formatNumber(report.dependenciesChecked)}</div>
          <div className="stat-key">{t("Зависимостей проверено")}</div>
        </div>
        <div className="stat-card">
          <Icon name="timer" />
          <div className="stat-val">{formatDuration(report.durationMs)}</div>
          <div className="stat-key">{t("Время сканирования")}</div>
        </div>
        <div className="stat-card">
          <Icon name="database" />
          <div className="stat-val">{formatBytes(report.bytesScanned)}</div>
          <div className="stat-key">{t("Объём кода")}</div>
        </div>
      </div>

      <div className="two-col">
        <div className="card">
          <div className="card-title">
            <Icon name="bar_chart" />
            {t("По уровню опасности")}
          </div>
          {(() => {
            const total = SEVERITY_ORDER.reduce((n, s) => n + counts[s], 0);
            if (total === 0) return null;
            // A single proportional bar answers "how much of this is critical?"
            // before the eye reaches the per-level rows below.
            return (
              <div
                className="sev-split"
                role="img"
                aria-label={SEVERITY_ORDER.filter((s) => counts[s] > 0)
                  .map((s) => `${t(SEVERITY_LABEL[s])}: ${counts[s]}`)
                  .join(", ")}
              >
                {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
                  <span
                    key={s}
                    className={`sev-split-seg ${s}`}
                    style={{ flexGrow: counts[s] }}
                    title={`${t(SEVERITY_LABEL[s])}: ${counts[s]}`}
                  />
                ))}
              </div>
            );
          })()}
          {SEVERITY_ORDER.map((s) => (
            <SeverityBar
              key={s}
              label={t(SEVERITY_LABEL[s])}
              value={counts[s]}
              max={maxSev}
              kind={s}
            />
          ))}
        </div>

        <div className="card">
          <div className="card-title">
            <Icon name="code" />
            {t("Языки")}
          </div>
          {report.languages.slice(0, 6).map((l) => (
            <SeverityBar key={l.language} label={l.label} value={l.files} max={maxLang} kind="lang" />
          ))}
          {report.languages.length === 0 && (
            <p style={{ color: "var(--t-2)", fontSize: 12.5 }}>{t("Файлы не найдены")}</p>
          )}
        </div>
      </div>

      {report.delta.fixed.length > 0 && (
        <div className="card fixed-card">
          <div className="card-title">
            <Icon name="task_alt" />
            {t("Исправлено с прошлого скана")}
            <span className="count">{report.delta.fixed.length}</span>
          </div>
          <div className="fixed-list">
            {report.delta.fixed.slice(0, 12).map((f) => (
              <div key={f.fingerprint} className="fixed-row">
                <span className={`sev-dot ${f.severity}`} />
                <span className="fx-title">{t(f.title)}</span>
                <span className="fx-file">{f.file}</span>
              </div>
            ))}
          </div>
          {report.delta.fixed.length > 12 && (
            <p className="fx-more">{t("и ещё {n}", { n: report.delta.fixed.length - 12 })}</p>
          )}
        </div>
      )}

      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title">
          <Icon name="checklist" />
          {t("Использованные движки")}
        </div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {report.enginesUsed.map((e) => (
            <span key={e} className="tag" style={{ fontSize: 11, padding: "3px 8px" }}>
              {/* Engine names come from the backend as full strings. "Свои
                  правила (N)" bakes in the count, so it is matched by pattern;
                  the rest are looked up directly. */}
              {engineLabel(e, t)}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- skipped

function SkippedView({ report }: { report: ScanReport }) {
  const t = useT();
  const grouped = useMemo(() => {
    const m = new Map<string, typeof report.skipped>();
    for (const s of report.skipped) {
      const arr = m.get(s.reasonLabel) ?? [];
      arr.push(s);
      m.set(s.reasonLabel, arr);
    }
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [report]);

  return (
    <div className="overview">
      <div
        className="warn-box"
        style={{ background: "var(--s-2)", borderColor: "var(--line)", color: "var(--t-1)" }}
      >
        <Icon name="info" />
{t("Эти файлы не анализировались. Бинарники, медиа и архивы не содержат читаемого исходного кода, поэтому проверить их статическим анализом невозможно.")}
      </div>

      {grouped.length === 0 && (
        <div className="list-empty">
          <Icon name="check_circle" />
          <p>{t("Все найденные файлы были проверены")}</p>
        </div>
      )}

      {grouped.map(([reason, items]) => (
        <div key={reason} className="card">
          <div className="card-title">
            <Icon name="block" />
            {reason}
            <span style={{ marginLeft: "auto", color: "var(--t-3)", fontWeight: 400 }}>
              {items.length}
            </span>
          </div>
          {items.slice(0, 50).map((s) => (
            <div key={s.path} className="skip-row">
              <Icon name="description" />
              <span className="skip-path" title={s.path}>
                {s.path}
              </span>
              <span className="skip-reason">{formatBytes(s.size)}</span>
            </div>
          ))}
          {items.length > 50 && (
            <div style={{ padding: "8px 9px", color: "var(--t-3)", fontSize: 12 }}>
              {t("…и ещё {n}", { n: items.length - 50 })}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
