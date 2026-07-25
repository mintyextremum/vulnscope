import { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { Icon } from "./components";
import { AppSettings, KeybindAction, KeybindConflict } from "./types";
import {
  ALL_TOKENS,
  defaultToken,
  isColor,
  PRESET_KIND_LABEL,
  PresetKind,
  PRESETS,
  TOKEN_GROUPS,
} from "./theme-tokens";
import { useT } from "./i18n";

/**
 * The live search query, shared with every control on the screen.
 *
 * A context rather than a prop chain: with six tabs and ~40 controls, threading
 * the query would mean touching every call site, and any control someone forgot
 * would silently stay visible in a filtered list — which reads as "no match" for
 * everything else.
 */
const SearchCtx = createContext("");

/** Whether a control survives the current query. Empty query shows everything. */
function useMatches(...text: (string | undefined)[]): boolean {
  const q = useContext(SearchCtx).trim().toLowerCase();
  if (!q) return true;
  return text.filter(Boolean).join(" ").toLowerCase().includes(q);
}

/**
 * A settings group header.
 *
 * While searching, headers step aside: results come from every tab at once, so
 * a header would either sit above someone else's matches or head an empty
 * group. Matching a group by name still works — the header itself is a match.
 */
function Section({ title }: { title: string }) {
  const q = useContext(SearchCtx).trim();
  if (q && !title.toLowerCase().includes(q.toLowerCase())) return null;
  return <div className="set-section">{title}</div>;
}

/** Wraps content that is not a plain control (theme picker, key list) so it can
 *  still be found by name. */
function Findable({ name, children }: { name: string; children: React.ReactNode }) {
  return useMatches(name) ? <>{children}</> : null;
}

/** One shortcut row, filterable by the action's own name. */
function KeyRow({ label, children }: { label: string; children: React.ReactNode }) {
  if (!useMatches(label)) return null;
  return (
    <div className="key-row">
      <span className="key-label">{label}</span>
      {children}
    </div>
  );
}

/** Export ids paired with what they are called. Mirrors `EXPORT_FORMATS` in
 *  settings.rs — the backend rejects anything not on that list. */
const EXPORT_CHOICES: [string, string][] = [
  ["json", "JSON"],
  ["sarif", "SARIF"],
  ["md", "Markdown"],
  ["csv", "CSV"],
  ["xlsx", "Excel"],
  ["html", "HTML"],
  ["pdf", "Отчёт (PDF)"],
  ["xml1c", "XML для 1С"],
];

type TabId = "scan" | "engines" | "report" | "look" | "keys" | "a11y";

/** Tab order and labels. Six categories rather than four: the screen grew past
 *  the point where "Сканирование" meant anything specific. */
const TABS: { id: TabId; label: string; icon: string }[] = [
  { id: "scan", label: "Сканирование", icon: "radar" },
  { id: "engines", label: "Движки", icon: "manufacturing" },
  { id: "report", label: "Отчёты", icon: "summarize" },
  { id: "look", label: "Вид", icon: "palette" },
  { id: "keys", label: "Клавиши", icon: "keyboard" },
  { id: "a11y", label: "Доступность", icon: "accessibility_new" },
];

/** Turns a KeyboardEvent into the same combo string the hotkey layer parses. */
function comboFrom(e: React.KeyboardEvent): string | null {
  const key = e.key.toLowerCase();
  // A modifier on its own is not a binding.
  if (["control", "shift", "alt", "meta", "os"].includes(key)) return null;

  const parts: string[] = [];
  if (e.ctrlKey || e.metaKey) parts.push("mod");
  if (e.shiftKey) parts.push("shift");
  if (e.altKey) parts.push("alt");
  parts.push(key === " " ? "space" : key);
  return parts.join("+");
}

/** Renders a combo the way a user reads it, not the way we store it. */
export function prettyCombo(combo: string): string {
  if (!combo) return "—";
  return combo
    .split("+")
    .map((p) => {
      const map: Record<string, string> = {
        mod: "Ctrl",
        shift: "Shift",
        alt: "Alt",
        arrowup: "↑",
        arrowdown: "↓",
        arrowleft: "←",
        arrowright: "→",
        enter: "Enter",
        escape: "Esc",
        space: "Space",
      };
      return map[p] ?? p.toUpperCase();
    })
    .join(" + ");
}

export function SettingsScreen({
  onClose,
  onApplied,
}: {
  onClose: () => void;
  onApplied: (s: AppSettings) => void;
}) {
  const t = useT();
  const [s, setS] = useState<AppSettings | null>(null);
  const [actions, setActions] = useState<KeybindAction[]>([]);
  const [capturing, setCapturing] = useState<string | null>(null);
  const [conflicts, setConflicts] = useState<KeybindConflict[]>([]);
  const [path, setPath] = useState("");
  const [toast, setToast] = useState<string | null>(null);
  const [tab, setTab] = useState<TabId>("scan");
  const [query, setQuery] = useState("");
  // A query searches every category, not the open one: someone looking for
  // "blame" should not have to know it lives under "Движки".
  const searching = query.trim().length > 0;
  const shows = (id: TabId) => searching || tab === id;

  useEffect(() => {
    invoke<AppSettings>("get_settings").then(setS).catch(() => {});
    invoke<KeybindAction[]>("get_keybind_actions").then(setActions).catch(() => {});
    invoke<string>("get_settings_path").then(setPath).catch(() => {});
  }, []);

  // Conflicts are checked in the backend so the rule matches what actually
  // dispatches keys, not a second implementation in the UI.
  useEffect(() => {
    if (!s) return;
    invoke<KeybindConflict[]>("check_keybind_conflicts", { keybinds: s.keybinds })
      .then(setConflicts)
      .catch(() => {});
  }, [s]);

  const flash = (m: string) => {
    setToast(m);
    setTimeout(() => setToast(null), 1800);
  };

  // The freshest settings, readable outside a render. Two rows edited in quick
  // succession both build their payload from the `s` of *their* render, so
  // without this the second save reverts the first — blurring one number field
  // by clicking into the next is enough to hit it.
  const latest = useRef<AppSettings | null>(null);
  latest.current = s;

  /** Saves a patch. The backend clamps; take back what it actually stored so
   *  the UI never shows a value the scanner will not honour. */
  const apply = async (patch: Partial<AppSettings>) => {
    const base = latest.current;
    if (!base) return;
    const next = { ...base, ...patch };
    latest.current = next;
    const stored = await invoke<AppSettings>("save_settings", { settings: next });
    latest.current = stored;
    setS(stored);
    onApplied(stored);
  };

  const reset = async () => {
    const d = await invoke<AppSettings>("reset_settings");
    setS(d);
    onApplied(d);
    flash(t("Настройки сброшены"));
  };

  const onCapture = (action: string, e: React.KeyboardEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.key === "Escape") {
      setCapturing(null);
      return;
    }
    if (e.key === "Backspace" || e.key === "Delete") {
      if (s) apply({ keybinds: { ...s.keybinds, [action]: "" } });
      setCapturing(null);
      return;
    }
    const combo = comboFrom(e);
    if (!combo || !s) return;
    apply({ keybinds: { ...s.keybinds, [action]: combo } });
    setCapturing(null);
  };

  const grouped = useMemo(() => {
    const m = new Map<string, KeybindAction[]>();
    for (const a of actions) {
      const arr = m.get(a.group) ?? [];
      arr.push(a);
      m.set(a.group, arr);
    }
    return [...m.entries()];
  }, [actions]);

  const conflictFor = (action: string) =>
    conflicts.find((c) => c.action === action || c.otherAction === action);

  if (!s) return <div className="viewer-loading">{t("Загрузка настроек…")}</div>;

  return (
    <div className="rules-screen">
      <div className="rules-bar">
        <button className="btn btn-ghost" onClick={onClose}>
          <Icon name="arrow_back" />
          {t("Назад")}
        </button>
        <div className="rules-title">
          <Icon name="tune" />
          {t("Настройки")}
        </div>
        <div className="seg set-tabs" style={{ marginLeft: 12 }}>
          {TABS.map((tb) => (
            <button
              key={tb.id}
              className={`seg-btn ${!searching && tab === tb.id ? "active" : ""}`}
              // Picking a tab while filtering means "show me this one" — the
              // query is what is hiding the rest, so it has to go.
              onClick={() => {
                setQuery("");
                setTab(tb.id);
              }}
            >
              <Icon name={tb.icon} />
              {t(tb.label)}
            </button>
          ))}
        </div>
        <div style={{ flex: 1 }} />
        <div className="set-search">
          <Icon name="search" />
          <input
            className="input"
            placeholder={t("Поиск по настройкам")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label={t("Поиск по настройкам")}
          />
          {searching && (
            <button className="icon-btn" onClick={() => setQuery("")} aria-label={t("Очистить поиск")}>
              <Icon name="close" />
            </button>
          )}
        </div>
        <button className="btn btn-ghost btn-sm" onClick={reset}>
          <Icon name="restart_alt" />
          {t("Сбросить всё")}
        </button>
      </div>

      {toast && (
        <div className="toast">
          <Icon name="check_circle" />
          {toast}
        </div>
      )}

      <SearchCtx.Provider value={query}>
      <div className="rules-body">
        {shows("scan") && (
          <div className="set-grid">
            <Section title={t("Пределы")} />
            <Num
              label={t("Максимальный размер файла")}
              unit={t("МБ")}
              hint={t("Файлы крупнее пропускаются: это почти всегда сгенерированные данные, а не код.")}
              value={s.maxFileSizeMb}
              min={1}
              max={64}
              onChange={(v) => apply({ maxFileSizeMb: v })}
            />
            <Num
              label={t("Порог длины строки")}
              unit={t("символов")}
              hint={t("Файл со строкой длиннее считается бандлом и не сканируется.")}
              value={s.minifiedLineLen}
              min={200}
              max={100000}
              onChange={(v) => apply({ minifiedLineLen: v })}
            />
            <Num
              label={t("Находок на файл")}
              unit={t("макс.")}
              hint={t("Предел, чтобы одно шумное правило не залило собой отчёт.")}
              value={s.maxFindingsPerFile}
              min={10}
              max={5000}
              onChange={(v) => apply({ maxFindingsPerFile: v })}
            />

            <Section title={t("Обход файлов")} />
            <Num
              label={t("Глубина вложенности")}
              unit={t("уровней")}
              hint={t("Насколько глубоко заходить от корня проекта. 0 — без ограничения.")}
              value={s.maxDepth}
              min={0}
              max={64}
              onChange={(v) => apply({ maxDepth: v })}
            />
            <Toggle
              label={t("Идти по символическим ссылкам")}
              hint={t("По умолчанию выключено: ссылка наружу превращает скан «этой папки» в скан чужой, а кольцо ссылок подвешивает обход.")}
              on={s.followSymlinks}
              onChange={(v) => apply({ followSymlinks: v })}
            />
            <Area
              label={t("Не сканировать пути")}
              hint={t("По шаблону, как в .gitignore, по одному в строке. Например: docs/**")}
              placeholder={"docs/**\nmigrations/**"}
              value={s.excludeGlobs}
              onChange={(v) => apply({ excludeGlobs: v })}
            />

            <Section title={t("Поведение правил")} />
            <Toggle
              label={t("Пропускать шумные правила в тестах")}
              hint={t("Math.random и подобные в тестовых файлах — не проблема.")}
              on={s.skipNoisyInTests}
              onChange={(v) => apply({ skipNoisyInTests: v })}
            />
            <Toggle
              label={t("Игнорировать комментарии")}
              hint={t("Закомментированный код не считается уязвимостью.")}
              on={s.ignoreComments}
              onChange={(v) => apply({ ignoreComments: v })}
            />

            <Section title={t("Что включено по умолчанию")} />
            <Toggle
              label={t("Секреты в коде")}
              on={s.defaultCheckSecrets}
              onChange={(v) => apply({ defaultCheckSecrets: v })}
            />
            <Toggle
              label={t("CVE в зависимостях")}
              on={s.defaultCheckDependencies}
              onChange={(v) => apply({ defaultCheckDependencies: v })}
            />
            <Toggle
              label={t("Учитывать .gitignore")}
              on={s.defaultRespectGitignore}
              onChange={(v) => apply({ defaultRespectGitignore: v })}
            />
            <Toggle
              label={t("Включая зависимости (node_modules и т.п.)")}
              on={s.defaultIncludeVendor}
              onChange={(v) => apply({ defaultIncludeVendor: v })}
            />
          </div>
        )}

        {shows("engines") && (
          <div className="set-grid">
            <Section title={t("Сеть")} />
            <Toggle
              label={t("Офлайн-режим")}
              hint={t("Совсем без сети: зависимости всё равно разбираются и считаются, но CVE не запрашиваются. Единственное, что VulnScope отправляет наружу, — имена и версии пакетов в OSV.dev.")}
              on={s.offline}
              onChange={(v) => apply({ offline: v })}
            />
            <Num
              label={t("Кэш OSV")}
              unit={t("дней")}
              hint={t("Сколько ответы OSV считаются свежими. 0 — всегда спрашивать заново.")}
              value={s.osvCacheDays}
              min={0}
              max={365}
              onChange={(v) => apply({ osvCacheDays: v })}
            />
            <Num
              label={t("Параллельных запросов к OSV")}
              unit=""
              hint={t("Больше — быстрее, но вежливее к бесплатному API держать умеренно.")}
              value={s.osvConcurrency}
              min={1}
              max={64}
              onChange={(v) => apply({ osvConcurrency: v })}
            />

            <Section title={t("Ответственные (git blame)")} />
            <Toggle
              label={t("Определять автора строки")}
              hint={t("git blame: приписывает находку тому, кто последним менял строку. Стоит одного вызова git на файл.")}
              on={s.enableBlame}
              onChange={(v) => apply({ enableBlame: v })}
            />
            <Num
              label={t("Файлов под blame")}
              unit={t("макс.")}
              hint={t("Потолок числа вызовов git, чтобы хвост скана не встал на большом проекте.")}
              value={s.blameMaxFiles}
              min={0}
              max={100000}
              onChange={(v) => apply({ blameMaxFiles: v })}
            />

            <Section title={t("Внешние инструменты")} />
            <Num
              label={t("Таймаут инструмента")}
              unit={t("сек")}
              hint={t("На каждый инструмент отдельно: semgrep на большом репозитории законно работает минутами.")}
              value={s.externalTimeoutSecs}
              min={10}
              max={3600}
              onChange={(v) => apply({ externalTimeoutSecs: v })}
            />

            <Section title={t("Редактор")} />
            <Txt
              label={t("Команда открытия находки")}
              hint={t("{file} и {line} подставляются. Пусто — кнопка скрыта. Например: code -g {file}:{line}")}
              placeholder="code -g {file}:{line}"
              value={s.editorCommand}
              onChange={(v) => apply({ editorCommand: v })}
            />
          </div>
        )}

        {shows("report") && (
          <div className="set-grid">
            <Txt
              label={t("Организация")}
              hint={t("Печатается в шапке отчёта. Это же поле можно править прямо в отчёте.")}
              placeholder={t("ООО «Ромашка»")}
              value={s.reportOrg}
              onChange={(v) => apply({ reportOrg: v })}
            />
            <Pick
              label={t("Формат экспорта по умолчанию")}
              hint={t("Что запишет Ctrl+S без открытия меню. В меню этот формат помечен.")}
              value={s.defaultExportFormat}
              options={EXPORT_CHOICES}
              onChange={(v) => apply({ defaultExportFormat: v })}
            />
            <Num
              label={t("Хранить сканов в истории")}
              unit={t("шт.")}
              hint={t("Глубина графика динамики. Лишнее отсекается при следующем скане, а не сразу.")}
              value={s.historyCap}
              min={2}
              max={500}
              onChange={(v) => apply({ historyCap: v })}
            />
          </div>
        )}

        {shows("keys") && (
          <div className="set-grid">
            <Findable name={t("Клавиши")}>
              <div className="tools-note">
                <Icon name="info" />
                {t("Нажмите на сочетание и введите новое. Backspace — очистить, Esc — отмена.")}
              </div>
            </Findable>

            {conflicts.length > 0 && (
              <div className="error-banner">
                <Icon name="error" />
                {t("Одно сочетание назначено на несколько действий — сработает только одно.")}
              </div>
            )}

            {grouped.map(([group, items]) => (
              <div key={group}>
                {/* Both come from the backend as Russian strings, so they need
                    the same t() as the rest of the catalogue content. */}
                <Section title={t(group)} />
                {items.map((a) => {
                  const combo = s.keybinds[a.id] ?? "";
                  const clash = conflictFor(a.id);
                  return (
                    <KeyRow key={a.id} label={t(a.label)}>
                      {clash && (
                        <span className="tag cve" title={t("Конфликт сочетаний")}>
                          {t("конфликт")}
                        </span>
                      )}
                      <button
                        className={`key-btn ${capturing === a.id ? "capturing" : ""} ${
                          clash ? "clash" : ""
                        }`}
                        onClick={() => setCapturing(capturing === a.id ? null : a.id)}
                        onKeyDown={(e) => capturing === a.id && onCapture(a.id, e)}
                      >
                        {capturing === a.id ? t("Нажмите клавиши…") : prettyCombo(combo)}
                      </button>
                    </KeyRow>
                  );
                })}
              </div>
            ))}
          </div>
        )}

        {shows("look") && (
          <div className="set-grid">
            <Findable name={t("Язык интерфейса")}>
            <div className="field">
              <div className="field-label">{t("Язык")}</div>
              <div className="seg" style={{ maxWidth: 320 }}>
                {(["ru", "en"] as const).map((code) => (
                  <button
                    key={code}
                    className={`seg-btn ${(s.language ?? "ru") === code ? "active" : ""}`}
                    onClick={() => apply({ language: code })}
                  >
                    {code === "ru" ? t("Русский") : "English"}
                  </button>
                ))}
              </div>
            </div>
            </Findable>

            <Findable name={t("Схема, тема, оформление")}>
            <div className="field set-wide">
              <div className="field-label">{t("Схема")}</div>
              {(["dark", "light", "contrast"] as PresetKind[]).map((kind) => (
              <div key={kind} className="preset-group">
              <div className="preset-group-title">{t(PRESET_KIND_LABEL[kind])}</div>
              <div className="preset-row">
                {PRESETS.filter((p) => p.kind === kind).map((p) => (
                  <button
                    key={p.id}
                    className={`preset ${s.themePreset === p.id ? "active" : ""}`}
                    onClick={() =>
                      // Switching preset drops the old tweaks: they were picked
                      // against different surfaces, and keeping them is how you
                      // get unreadable text on a scheme you never chose.
                      apply({ themePreset: p.id, theme: {} })
                    }
                    title={t(p.hint)}
                  >
                    <span className="preset-dots">
                      {/* The preset's own colours, never var(--x): that would
                          resolve against the active theme and show every preset
                          as a copy of the current one. */}
                      {["s-1", "s-3", "a", "crit", "ok"].map((t) => (
                        <span
                          key={t}
                          className="preset-dot"
                          style={{ background: p.theme[t] ?? defaultToken(t) }}
                        />
                      ))}
                    </span>
                    <b>{t(p.label)}</b>
                    <span>{t(p.hint)}</span>
                  </button>
                ))}
              </div>
              </div>
              ))}
            </div>
            </Findable>

            <Findable name={t("Акцентный цвет")}>
            <div className="field">
              <div className="field-label">{t("Акцентный цвет")}</div>
              <div className="swatches">
                {["#5b8def", "#8b5cf6", "#3fd68a", "#ff9147", "#ff5470", "#58c4f5"].map((c) => (
                  <button
                    key={c}
                    className={`swatch ${(s.theme?.a ?? s.accent) === c ? "active" : ""}`}
                    style={{ background: c }}
                    // `accent` is the old name for the `a` token; both are
                    // written so neither can drift out of step.
                    onClick={() => apply({ accent: c, theme: { ...s.theme, a: c } })}
                    aria-label={t("Акцент {c}", { c })}
                  />
                ))}
              </div>
            </div>
            </Findable>

            <Findable name={t("Плотность")}>
            <div className="field">
              <div className="field-label">{t("Плотность")}</div>
              <div className="seg" style={{ maxWidth: 320 }}>
                {(["comfortable", "compact"] as const).map((d) => (
                  <button
                    key={d}
                    className={`seg-btn ${s.density === d ? "active" : ""}`}
                    onClick={() => apply({ density: d })}
                  >
                    {d === "comfortable" ? t("Просторно") : t("Плотно")}
                  </button>
                ))}
              </div>
            </div>
            </Findable>

            <Section title={t("Просмотр кода")} />
            <Num
              label={t("Кегль кода")}
              unit={t("px")}
              hint={t("Размер шрифта в просмотрщике и сниппетах. Высота строки пересчитывается вместе с ним.")}
              value={s.codeFontSize}
              min={9}
              max={28}
              onChange={(v) => apply({ codeFontSize: v })}
            />
            <Num
              label={t("Ширина табуляции")}
              unit={t("симв.")}
              hint={t("Во сколько пробелов разворачивается табуляция.")}
              value={s.tabWidth}
              min={1}
              max={16}
              onChange={(v) => apply({ tabWidth: v })}
            />
            <Toggle
              label={t("Переносить длинные строки")}
              hint={t("Вместо прокрутки вбок. На файлах длиннее 4000 строк не действует: там просмотрщик рисует строки по арифметике.")}
              on={s.wrapCodeLines}
              onChange={(v) => apply({ wrapCodeLines: v })}
            />

            {/* Its own section: a boxed Num card sitting in the third column
                next to two plain fields read as an orphan. A header spans the
                grid, so the card starts a fresh row and says why it is here. */}
            <Section title={t("Производительность")} />

            <Num
              label={t("Подсветка синтаксиса до")}
              unit={t("строк")}
              hint={t("На файлах длиннее подсветка отключается: она работает в главном потоке и на бандлах ощутимо тормозит.")}
              value={s.maxHighlightLines}
              min={0}
              max={200000}
              onChange={(v) => apply({ maxHighlightLines: v })}
            />

            <ThemeEditor settings={s} apply={apply} />

            {path && (
              <p className="hint-path">
                {t("Файл настроек:")} <code>{path}</code> — тему можно править и прямо в нём,
                ключ <code>theme</code>.
              </p>
            )}
          </div>
        )}

        {shows("a11y") && <A11yTab s={s} apply={apply} path={path} />}
      </div>
      </SearchCtx.Provider>
    </div>
  );
}

/**
 * Everything that makes the app usable when the defaults do not fit — motion,
 * zoom, focus, and cues that do not rely on colour. Grouped in one place
 * because someone who needs one of these usually needs to find the rest.
 */
function A11yTab({
  s,
  apply,
  path,
}: {
  s: AppSettings;
  apply: (patch: Partial<AppSettings>) => void;
  path: string;
}) {
  const t = useT();
  const scale = s.a11yUiScale ?? 100;
  const showScale = useMatches(t("Масштаб интерфейса"), t("Увеличивает весь интерфейс"));
  return (
    <div className="set-grid">
      {showScale && (
      <div className="field">
        <div className="field-label">{t("Масштаб интерфейса")}</div>
        <p className="field-note">
{t("Увеличивает весь интерфейс, а не только шрифт, поэтому на 200% ничего не наезжает (WCAG 1.4.4).")}
        </p>
        <div className="scale-row">
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => apply({ a11yUiScale: Math.max(80, scale - 10) })}
            aria-label={t("Меньше")}
          >
            <Icon name="remove" />
          </button>
          <input
            type="range"
            min={80}
            max={250}
            step={10}
            value={scale}
            onChange={(e) => apply({ a11yUiScale: Number(e.target.value) })}
            aria-label={t("Масштаб интерфейса, проценты")}
          />
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => apply({ a11yUiScale: Math.min(250, scale + 10) })}
            aria-label={t("Больше")}
          >
            <Icon name="add" />
          </button>
          <span className="scale-val">{scale}%</span>
          {scale !== 100 && (
            <button className="btn btn-ghost btn-sm" onClick={() => apply({ a11yUiScale: 100 })}>
              {t("Сброс")}
            </button>
          )}
        </div>
      </div>
      )}

      <Toggle
        label={t("Уменьшить анимацию")}
        hint={t("Отключает переходы и фоновое движение. Системная настройка учитывается и без этого.")}
        on={s.reduceMotion}
        onChange={(v) => apply({ reduceMotion: v })}
      />
      <Toggle
        label={t("Не показывать фоновое свечение")}
        hint={t("Убирает плавно движущиеся пятна за интерфейсом.")}
        on={s.a11yNoAmbient}
        onChange={(v) => apply({ a11yNoAmbient: v })}
      />
      <Toggle
        label={t("Всегда показывать фокус")}
        hint={t("Рамка фокуса видна и после клика мышью, не только при навигации с клавиатуры.")}
        on={s.a11yAlwaysFocus}
        onChange={(v) => apply({ a11yAlwaysFocus: v })}
      />
      <Toggle
        label={t("Подписывать уровень опасности")}
        hint={t("Добавляет слово («Крит», «Выс»…) рядом со счётчиками — на случай, когда цвета трудно различить (WCAG 1.4.1).")}
        on={s.a11ySeverityText}
        onChange={(v) => apply({ a11ySeverityText: v })}
      />
      <Toggle
        label={t("Подчёркивать ссылки")}
        hint={t("Ссылки отличаются не только цветом.")}
        on={s.a11yUnderlineLinks}
        onChange={(v) => apply({ a11yUnderlineLinks: v })}
      />
      <Toggle
        label={t("Крупные области нажатия")}
        hint={t("Кнопки и переключатели не меньше 24×24 px (WCAG 2.5.8).")}
        on={s.a11yBigTargets}
        onChange={(v) => apply({ a11yBigTargets: v })}
      />

      <Findable name={t("Доступность")}>
        <p className="field-note">
{t("Смысловые цвета (уровни опасности) проверены на контраст WCAG 2.2 AA и на три типа дальтонизма во всех схемах. У каждого уровня есть свой значок, так что цвет никогда не единственный признак.")}
        </p>

        {path && (
          <p className="hint-path">
            {t("Файл настроек:")} <code>{path}</code>
          </p>
        )}
      </Findable>
    </div>
  );
}

/**
 * The token editor.
 *
 * Every colour in the app is one of these, so this is the whole theme — not a
 * curated subset. Edits apply live because the tokens are what the stylesheet
 * reads; there is no preview to keep in sync with reality.
 */
function ThemeEditor({
  settings,
  apply,
}: {
  settings: AppSettings;
  apply: (patch: Partial<AppSettings>) => void;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const theme = settings.theme ?? {};
  const preset = PRESETS.find((p) => p.id === settings.themePreset)?.theme ?? {};

  /** What a token shows right now: user override → preset → stylesheet. */
  const current = (id: string) => theme[id] ?? preset[id] ?? defaultToken(id);

  const set = (id: string, value: string) => {
    const next = { ...theme, [id]: value };
    apply({ ...settings, theme: next, ...(id === "a" ? { accent: value } : {}) });
  };

  const clear = (id: string) => {
    const next = { ...theme };
    delete next[id];
    apply({ ...settings, theme: next });
  };

  const exportTheme = async () => {
    const file = await saveDialog({
      defaultPath: `${settings.themePreset || "custom"}.vulnscope-theme.json`,
      filters: [{ name: t("Тема VulnScope"), extensions: ["json"] }],
    });
    if (!file) return;
    const doc = { preset: settings.themePreset, theme };
    await invoke("save_report", { path: file, json: JSON.stringify(doc, null, 2) }).catch((e) =>
      setErr(String(e))
    );
  };

  const importTheme = async () => {
    const file = await openDialog({ multiple: false, filters: [{ name: t("Тема"), extensions: ["json"] }] });
    if (typeof file !== "string") return;
    try {
      // Same route the rule import takes: the backend reads the file, the
      // frontend has no filesystem access of its own.
      const raw = await invoke<string>("read_source", {
        root: file.replace(/[\\/][^\\/]+$/, ""),
        relative: file.split(/[\\/]/).pop() ?? "",
      });
      const doc = JSON.parse(raw) as { preset?: string; theme?: Record<string, string> };
      const clean: Record<string, string> = {};
      // A theme file is just data from somewhere else: take only the tokens
      // this build knows and only values that are really colours.
      for (const [k, v] of Object.entries(doc.theme ?? {})) {
        if (ALL_TOKENS.some((t) => t.id === k) && typeof v === "string" && isColor(v)) clean[k] = v;
      }
      const dropped = Object.keys(doc.theme ?? {}).length - Object.keys(clean).length;
      setErr(dropped > 0 ? t("Пропущено записей, не похожих на цвет: {n}", { n: dropped }) : null);
      apply({ ...settings, themePreset: doc.preset ?? settings.themePreset, theme: clean });
    } catch (e) {
      setErr(t("Не удалось прочитать тему: {e}", { e: String(e) }));
    }
  };

  const changed = Object.keys(theme).length;

  // Without this the whole token editor sits under every search result, which
  // reads as "these are matches too".
  if (!useMatches(t("Токены темы"), t("Схема, тема, оформление"))) return null;
  return (
    <div className="field set-wide">
      <div className="field-label">
        {t("Токены темы")}
        {changed > 0 && <span className="tag" style={{ marginLeft: 8 }}>{t("изменено: {n}", { n: changed })}</span>}
      </div>
      <p className="field-note">
{t("Из этих значений собран весь интерфейс, включая подсветку кода. Правки применяются сразу и хранятся в")} <code>settings.json</code>.
      </p>

      <div className="theme-actions">
        <button className="btn btn-ghost btn-sm" onClick={() => setOpen(!open)}>
          <Icon name={open ? "expand_less" : "tune"} />
          {open ? t("Свернуть цвета") : t("Показать все цвета")}
        </button>
        <button className="btn btn-ghost btn-sm" onClick={exportTheme}>
          <Icon name="download" />
          {t("Экспорт")}
        </button>
        <button className="btn btn-ghost btn-sm" onClick={importTheme}>
          <Icon name="upload" />
          {t("Импорт")}
        </button>
        {changed > 0 && (
          <button className="btn btn-ghost btn-sm" onClick={() => apply({ ...settings, theme: {} })}>
            <Icon name="restart_alt" />
            {t("Сбросить к схеме")}
          </button>
        )}
      </div>

      {err && <div className="warn-box">{err}</div>}

      {open && (
        <div className="token-groups">
          {TOKEN_GROUPS.map((g) => (
            <div key={g.title} className="token-group">
              <div className="tg-head">
                <b>{g.title}</b>
                <span>{g.hint}</span>
              </div>
              <div className="token-rows">
                {g.tokens.map((tok) => {
                  const value = current(tok.id);
                  const overridden = theme[tok.id] !== undefined;
                  // A colour input cannot show rgba(); those stay text-only.
                  const hex = /^#[0-9a-f]{6}$/i.test(value) ? value : null;
                  return (
                    <div key={tok.id} className={`token-row ${overridden ? "changed" : ""}`}>
                      <span className="tr-preview" style={{ background: value }} />
                      {hex ? (
                        <input
                          type="color"
                          className="tr-color"
                          value={hex}
                          onChange={(e) => set(tok.id, e.target.value)}
                          aria-label={tok.label}
                        />
                      ) : (
                        <span className="tr-color tr-nocolor" title={t("Значение с прозрачностью — правится текстом")}>
                          <Icon name="opacity" />
                        </span>
                      )}
                      <span className="tr-label" title={tok.hint}>
                        {tok.label}
                        <code>--{tok.id}</code>
                      </span>
                      <input
                        className="tr-value"
                        value={value}
                        spellCheck={false}
                        onChange={(e) => {
                          const v = e.target.value;
                          if (isColor(v)) set(tok.id, v);
                        }}
                      />
                      {overridden && (
                        <button className="tr-reset" onClick={() => clear(tok.id)} title={t("Вернуть к схеме")}>
                          <Icon name="undo" />
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Num({
  label,
  unit,
  hint,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  unit: string;
  hint?: string;
  value: number;
  min: number;
  max: number;
  onChange: (v: number) => void;
}) {
  const [text, setText] = useState(String(value));
  useEffect(() => setText(String(value)), [value]);
  const shown = useMatches(label, hint, unit);

  const commit = () => {
    const n = parseInt(text, 10);
    // An unparseable or out-of-range entry snaps back rather than silently
    // writing something the scanner would clamp anyway.
    if (!Number.isFinite(n)) {
      setText(String(value));
      return;
    }
    onChange(Math.min(max, Math.max(min, n)));
  };

  if (!shown) return null;
  return (
    <div className="set-row">
      <div className="set-info">
        <div className="set-label">{label}</div>
        {hint && <div className="field-note">{hint}</div>}
      </div>
      <div className="set-control">
        <input
          className="input mono"
          style={{ width: 92, textAlign: "right" }}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => e.key === "Enter" && commit()}
          inputMode="numeric"
        />
        <span className="set-unit">{unit}</span>
      </div>
    </div>
  );
}

/** A free-text row, committed on blur/Enter like Num — not on every keystroke,
 *  so half-typed commands never reach the backend. */
function Txt({
  label,
  hint,
  placeholder,
  value,
  onChange,
}: {
  label: string;
  hint?: string;
  placeholder?: string;
  value: string;
  onChange: (v: string) => void;
}) {
  const [text, setText] = useState(value);
  useEffect(() => setText(value), [value]);
  const shown = useMatches(label, hint, placeholder);
  const commit = () => {
    if (text.trim() !== value) onChange(text.trim());
  };
  if (!shown) return null;
  return (
    // Full width: a command line next to a long hint is unreadable squeezed
    // into a single column of the settings grid.
    <div className="set-row set-wide">
      <div className="set-info">
        <div className="set-label">{label}</div>
        {hint && <div className="field-note">{hint}</div>}
      </div>
      <div className="set-control">
        <input
          className="input mono"
          style={{ width: 320 }}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => e.key === "Enter" && commit()}
          placeholder={placeholder}
          spellCheck={false}
        />
      </div>
    </div>
  );
}

/** Multi-line free text: one pattern per line. */
function Area({
  label,
  hint,
  placeholder,
  value,
  onChange,
}: {
  label: string;
  hint?: string;
  placeholder?: string;
  value: string;
  onChange: (v: string) => void;
}) {
  const [text, setText] = useState(value);
  useEffect(() => setText(value), [value]);
  const shown = useMatches(label, hint);
  if (!shown) return null;
  return (
    <div className="set-row set-wide">
      <div className="set-info">
        <div className="set-label">{label}</div>
        {hint && <div className="field-note">{hint}</div>}
      </div>
      <div className="set-control">
        <textarea
          className="input mono set-area"
          rows={4}
          value={text}
          placeholder={placeholder}
          onChange={(e) => setText(e.target.value)}
          // On blur, not per keystroke: every change is a round-trip to disk,
          // and a half-typed glob would be saved and then scanned against.
          onBlur={() => text !== value && onChange(text)}
          aria-label={label}
        />
      </div>
    </div>
  );
}

/** A short list of mutually exclusive choices. */
function Pick({
  label,
  hint,
  value,
  options,
  onChange,
}: {
  label: string;
  hint?: string;
  value: string;
  options: [string, string][];
  onChange: (v: string) => void;
}) {
  const t = useT();
  if (!useMatches(label, hint, ...options.map(([, l]) => l))) return null;
  return (
    <div className="set-row set-wide">
      <div className="set-info">
        <div className="set-label">{label}</div>
        {hint && <div className="field-note">{hint}</div>}
      </div>
      <div className="set-control pick-row">
        {options.map(([id, l]) => (
          <button
            key={id}
            className={`chip ${value === id ? "active" : ""}`}
            onClick={() => onChange(id)}
            aria-pressed={value === id}
          >
            {t(l)}
          </button>
        ))}
      </div>
    </div>
  );
}

function Toggle({
  label,
  hint,
  on,
  onChange,
}: {
  label: string;
  hint?: string;
  on: boolean;
  onChange: (v: boolean) => void;
}) {
  if (!useMatches(label, hint)) return null;
  return (
    <div className="set-row">
      <div className="set-info">
        <div className="set-label">{label}</div>
        {hint && <div className="field-note">{hint}</div>}
      </div>
      <button
        className={`switch ${on ? "on" : ""}`}
        onClick={() => onChange(!on)}
        role="switch"
        aria-checked={on}
        aria-label={label}
      >
        <span className="knob" />
      </button>
    </div>
  );
}
