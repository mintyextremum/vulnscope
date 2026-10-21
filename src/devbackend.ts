import { mockIPC, mockWindows } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import type {
  AppSettings,
  Finding,
  KeybindAction,
  RuleInfo,
  ScanOptions,
  ScanPhase,
  ScanProgress,
  ToolsInfo,
  UpdateInfo,
} from "./types";
import { DEMO_SETTINGS, DEMO_SOURCES, demoHistory, demoReport } from "./demo";

/**
 * A stand-in for the Rust backend, for working on the interface in a plain
 * browser (`npm run dev` without Tauri).
 *
 * It answers the same commands through Tauri's own IPC mock, so the app runs
 * its real code paths: the setup screen, a scan with live progress events,
 * the results, the code viewer, edit-and-recheck, settings that save, the
 * history chart. A special-cased demo screen would only ever show that the
 * demo screen works.
 *
 * Installed from main.tsx only when `import.meta.env.DEV` is set and Tauri is
 * absent, through a dynamic import — a production build contains none of it.
 */

const PHASE_LABEL: Partial<Record<ScanPhase, string>> = {
  preparing: "Подготовка",
  discovering: "Поиск файлов",
  scanningCode: "Анализ кода",
  resolvingDependencies: "Разбор зависимостей",
  queryingOsv: "Запрос базы CVE (OSV.dev)",
  finalizing: "Формирование отчёта",
  done: "Готово",
};

const ACTIONS: [string, string, string][] = [
  ["palette", "Командная палитра", "Навигация"],
  ["rules", "Каталог правил", "Навигация"],
  ["myRules", "Свои правила", "Навигация"],
  ["settings", "Настройки", "Навигация"],
  ["newScan", "Новое сканирование", "Сканирование"],
  ["rescan", "Пересканировать", "Сканирование"],
  ["export", "Экспорт отчёта", "Сканирование"],
  ["tabOverview", "Вкладка «Обзор»", "Вкладки"],
  ["tabFindings", "Вкладка «Находки»", "Вкладки"],
  ["tabBeta", "Вкладка «Экспериментальные»", "Вкладки"],
  ["tabCode", "Вкладка «Код»", "Вкладки"],
  ["tabSkipped", "Вкладка «Пропущено»", "Вкладки"],
  ["nextFinding", "Следующая находка", "Находки"],
  ["prevFinding", "Предыдущая находка", "Находки"],
  ["openInCode", "Открыть находку в коде", "Находки"],
  ["focusSearch", "Поиск по файлам", "Находки"],
];

const TOOLS: ToolsInfo = {
  gitAvailable: true,
  tools: [
    {
      tool: "semgrep",
      label: "Semgrep",
      available: true,
      version: "1.99.0",
      installHint: "pip install semgrep",
      docsUrl: "https://semgrep.dev/docs/",
      adds: "Тысячи правил сообщества для десятков языков",
      scope: "Код",
      integrated: true,
      installOptions: [],
    },
    {
      tool: "gitleaks",
      label: "gitleaks",
      available: false,
      version: null,
      installHint: "winget install gitleaks",
      docsUrl: "https://github.com/gitleaks/gitleaks",
      adds: "Секреты в истории git",
      scope: "Секреты",
      integrated: true,
      installOptions: [],
    },
  ],
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function installDevBackend(): void {
  mockWindows("main");
  // Kept across reloads, like the real settings file: switching the language
  // or a theme and pressing F5 should not quietly undo it.
  const STORE = "vs.dev.settings";
  let settings: AppSettings = (() => {
    try {
      return { ...DEMO_SETTINGS, ...JSON.parse(localStorage.getItem(STORE) ?? "{}") };
    } catch {
      return { ...DEMO_SETTINGS };
    }
  })();
  const keep = () => {
    try {
      localStorage.setItem(STORE, JSON.stringify(settings));
    } catch {
      /* the demo simply forgets */
    }
  };
  let cancelled = false;
  const sources: Record<string, string> = { ...DEMO_SOURCES };

  /** Plays a scan's progress events, then hands back the report. */
  async function scan(options: ScanOptions) {
    cancelled = false;
    const files = Object.keys(sources);
    const total = 214;
    const started = performance.now();
    let processed = 0;
    let found = 0;
    const send = (phase: ScanPhase, currentFile = "") =>
      emit("scan-progress", {
        scanId: "demo",
        phase,
        phaseLabel: PHASE_LABEL[phase] ?? phase,
        currentFile,
        processed,
        total,
        findingsSoFar: found,
        severeSoFar: Math.round(found * 0.45),
        elapsedMs: performance.now() - started,
        etaMs: processed > 0 ? ((total - processed) * (performance.now() - started)) / processed : null,
        filesPerSec: processed / Math.max(0.001, (performance.now() - started) / 1000),
      } satisfies ScanProgress);

    await send("preparing");
    await sleep(250);
    await send("discovering");
    await sleep(350);
    for (processed = 0; processed <= total; processed += 6) {
      if (cancelled) break;
      if (processed % 18 === 0) found++;
      await send("scanningCode", files[processed % files.length]);
      await sleep(40);
    }
    processed = Math.min(processed, total);
    if (!cancelled && options.checkDependencies) {
      await send("resolvingDependencies");
      await sleep(300);
      await send("queryingOsv");
      await sleep(700);
    }
    await send("finalizing");
    await sleep(200);
    const report = demoReport(Math.round(performance.now() - started));
    if (cancelled) {
      return { ...report, cancelled: true, findings: [], files: [], counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } };
    }
    if (options.changedOnly) {
      // The demo's "uncommitted edits": the files whose findings are new.
      const changed = new Set(report.findings.filter((f) => f.isNew).map((f) => f.file));
      report.findings = report.findings.filter((f) => changed.has(f.file));
      report.files = report.files.filter((f) => changed.has(f.path));
      report.filesScanned = changed.size;
      report.changedOnly = true;
      report.delta = { previousScanAt: null, newCount: 0, fixedCount: 0, unchangedCount: 0, fixed: [], newBySeverity: {} };
      for (const f of report.findings) f.isNew = false;
      report.counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of report.findings) if (!f.suppressed) report.counts[f.severity]++;
    }
    // The options are honoured where they change what a real scan returns.
    report.findings = report.findings.filter(
      (f) =>
        (options.experimental || !f.extra?.experimental) &&
        (options.dataflow || f.ruleId !== "VS-FLOW") &&
        (options.checkSecrets || f.source !== "secrets") &&
        (options.checkDependencies || !f.package),
    );
    return report;
  }

  /** Re-check after an edit: a finding survives while its flagged line does. */
  function recheck(relative: string, content: string): Finding[] {
    const before = sources[relative] ?? "";
    sources[relative] = content;
    const lines = content.split("\n");
    return demoReport()
      .findings.filter((f) => f.file === relative && ["builtin", "custom", "secrets"].includes(f.source))
      .flatMap((f) => {
        const text = before.split("\n")[f.line - 1]?.trim();
        const at = text ? lines.findIndex((l) => l.trim() === text) : -1;
        return at < 0 ? [] : [{ ...f, line: at + 1, endLine: at + 1 }];
      });
  }

  /** The demo's built-in findings as catalogue entries. */
  function rules(): RuleInfo[] {
    const seen = new Map<string, RuleInfo>();
    for (const f of demoReport().findings) {
      if (f.source !== "builtin" || seen.has(f.ruleId) || f.ruleId.startsWith("VS-EXP") || f.ruleId === "VS-FLOW") continue;
      seen.set(f.ruleId, {
        id: f.ruleId,
        title: f.title,
        description: f.description,
        recommendation: f.recommendation,
        severity: f.severity,
        confidence: f.confidence,
        category: f.category,
        languages: [],
        cwe: f.cwe,
        owasp: f.owasp,
        references: [],
      });
    }
    return [...seen.values()];
  }

  mockIPC(
    async (cmd, raw) => {
      const args = (raw ?? {}) as Record<string, unknown>;
      switch (cmd) {
        case "get_settings":
          return settings;
        case "save_settings":
          settings = { ...(args.settings as AppSettings) };
          keep();
          return settings;
        case "reset_settings":
          settings = { ...DEMO_SETTINGS };
          keep();
          return settings;
        case "get_settings_path":
          return "C:/Users/demo/AppData/Roaming/vulnscope/settings.json";
        case "get_keybind_actions":
          return ACTIONS.map(([id, label, group]) => ({ id, label, group }) satisfies KeybindAction);
        case "check_keybind_conflicts":
          return [];
        case "get_tools":
          return TOOLS;
        case "check_update":
          return { current: "2.0.0", latest: "2.0.0", updateAvailable: false, url: "", error: null } satisfies UpdateInfo;
        case "start_scan":
          return scan(args.options as ScanOptions);
        case "cancel_scan":
          cancelled = true;
          return null;
        case "read_source": {
          const text = sources[String(args.relative)];
          if (text === undefined) throw new Error("Файл недоступен в демо-режиме");
          return text;
        }
        case "recheck_file":
          return recheck(String(args.relative), String(args.content));
        case "get_scan_history":
          return demoHistory();
        case "get_rules":
          return rules();
        case "get_languages":
          return [
            { id: "python", label: "Python" },
            { id: "javascript", label: "JavaScript" },
            { id: "go", label: "Go" },
          ];
        case "get_user_rules":
          return [];
        case "get_user_rules_path":
          return "C:/Users/demo/AppData/Roaming/vulnscope/rules.json";
        case "test_user_rule": {
          const rule = args.rule as { pattern: string; unlessContains: string[] };
          let re: RegExp;
          try {
            re = new RegExp(rule.pattern);
          } catch (e) {
            return { ok: false, error: String(e), matches: [] };
          }
          const matches = String(args.sample ?? "")
            .split("\n")
            .flatMap((text, i) => {
              const m = re.exec(text);
              if (!m) return [];
              const suppressed = rule.unlessContains.some((u) => u && text.includes(u));
              return [{ line: i + 1, text, matched: m[0], suppressed }];
            });
          return { ok: true, error: null, matches };
        }
        case "save_user_rule":
          return [];
        case "import_user_rules":
          return 0;
        case "install_tool":
          return { ok: false, command: "", output: "Установка недоступна в демо-режиме" };
        case "plugin:dialog|open":
          return "D:/Projects/shop";
        case "plugin:window|is_maximized":
          return false;
        default:
          // Saving files, opening links, window controls, suppressions: the
          // demo has nowhere to put them, and pretending is harmless.
          return null;
      }
    },
    { shouldMockEvents: true },
  );

  // @tauri-apps/api 2.11's mock reads `args.id` when removing a listener, but
  // `unlisten()` sends `eventId`, so nothing was ever removed: every unmounted
  // listener (StrictMode mounts effects twice) stayed registered, and each
  // progress event warned "Couldn't find callback id". Pass both names.
  const internals = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...a: unknown[]) => unknown } })
    .__TAURI_INTERNALS__;
  const invoke = internals.invoke;
  internals.invoke = (cmd: unknown, args: unknown, opts: unknown) =>
    invoke(
      cmd,
      cmd === "plugin:event|unlisten" ? { ...(args as object), id: (args as { eventId: unknown }).eventId } : args,
      opts,
    );
}
