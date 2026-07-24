import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { Icon } from "./components";
import { AppSettings, KeybindAction, KeybindConflict } from "./types";
import { ALL_TOKENS, defaultToken, isColor, PRESETS, TOKEN_GROUPS } from "./theme-tokens";
import { useT } from "./i18n";

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
  const [tab, setTab] = useState<"scan" | "keys" | "look" | "a11y">("scan");

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

  const apply = async (next: AppSettings) => {
    // The backend clamps; take back what it actually stored so the UI never
    // shows a value the scanner will not honour.
    const stored = await invoke<AppSettings>("save_settings", { settings: next });
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
      if (s) apply({ ...s, keybinds: { ...s.keybinds, [action]: "" } });
      setCapturing(null);
      return;
    }
    const combo = comboFrom(e);
    if (!combo || !s) return;
    apply({ ...s, keybinds: { ...s.keybinds, [action]: combo } });
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
        <div className="seg" style={{ marginLeft: 12 }}>
          <button className={`seg-btn ${tab === "scan" ? "active" : ""}`} onClick={() => setTab("scan")}>
            {t("Сканирование")}
          </button>
          <button className={`seg-btn ${tab === "keys" ? "active" : ""}`} onClick={() => setTab("keys")}>
            {t("Клавиши")}
          </button>
          <button className={`seg-btn ${tab === "look" ? "active" : ""}`} onClick={() => setTab("look")}>
            {t("Вид")}
          </button>
          <button className={`seg-btn ${tab === "a11y" ? "active" : ""}`} onClick={() => setTab("a11y")}>
            {t("Доступность")}
          </button>
        </div>
        <div style={{ flex: 1 }} />
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

      <div className="rules-body">
        {tab === "scan" && (
          <div className="set-grid">
            <Num
              label={t("Максимальный размер файла")}
              unit={t("МБ")}
              hint={t("Файлы крупнее пропускаются: это почти всегда сгенерированные данные, а не код.")}
              value={s.maxFileSizeMb}
              min={1}
              max={64}
              onChange={(v) => apply({ ...s, maxFileSizeMb: v })}
            />
            <Num
              label={t("Порог длины строки")}
              unit={t("символов")}
              hint={t("Файл со строкой длиннее считается бандлом и не сканируется.")}
              value={s.minifiedLineLen}
              min={200}
              max={100000}
              onChange={(v) => apply({ ...s, minifiedLineLen: v })}
            />
            <Num
              label={t("Находок на файл")}
              unit={t("макс.")}
              hint={t("Предел, чтобы одно шумное правило не залило собой отчёт.")}
              value={s.maxFindingsPerFile}
              min={10}
              max={5000}
              onChange={(v) => apply({ ...s, maxFindingsPerFile: v })}
            />
            <Num
              label={t("Кэш OSV")}
              unit={t("дней")}
              hint={t("Сколько ответы OSV считаются свежими. 0 — всегда спрашивать заново.")}
              value={s.osvCacheDays}
              min={0}
              max={365}
              onChange={(v) => apply({ ...s, osvCacheDays: v })}
            />
            <Num
              label={t("Параллельных запросов к OSV")}
              unit=""
              hint={t("Больше — быстрее, но вежливее к бесплатному API держать умеренно.")}
              value={s.osvConcurrency}
              min={1}
              max={64}
              onChange={(v) => apply({ ...s, osvConcurrency: v })}
            />

            <div className="set-section">{t("Поведение правил")}</div>
            <Toggle
              label={t("Пропускать шумные правила в тестах")}
              hint={t("Math.random и подобные в тестовых файлах — не проблема.")}
              on={s.skipNoisyInTests}
              onChange={(v) => apply({ ...s, skipNoisyInTests: v })}
            />
            <Toggle
              label={t("Игнорировать комментарии")}
              hint={t("Закомментированный код не считается уязвимостью.")}
              on={s.ignoreComments}
              onChange={(v) => apply({ ...s, ignoreComments: v })}
            />

            <div className="set-section">{t("Редактор")}</div>
            <Txt
              label={t("Команда открытия находки")}
              hint={t("{file} и {line} подставляются. Пусто — кнопка скрыта. Например: code -g {file}:{line}")}
              placeholder="code -g {file}:{line}"
              value={s.editorCommand}
              onChange={(v) => apply({ ...s, editorCommand: v })}
            />

            <div className="set-section">{t("Что включено по умолчанию")}</div>
            <Toggle
              label={t("Секреты в коде")}
              on={s.defaultCheckSecrets}
              onChange={(v) => apply({ ...s, defaultCheckSecrets: v })}
            />
            <Toggle
              label={t("CVE в зависимостях")}
              on={s.defaultCheckDependencies}
              onChange={(v) => apply({ ...s, defaultCheckDependencies: v })}
            />
            <Toggle
              label={t("Учитывать .gitignore")}
              on={s.defaultRespectGitignore}
              onChange={(v) => apply({ ...s, defaultRespectGitignore: v })}
            />
            <Toggle
              label={t("Включая зависимости (node_modules и т.п.)")}
              on={s.defaultIncludeVendor}
              onChange={(v) => apply({ ...s, defaultIncludeVendor: v })}
            />
          </div>
        )}

        {tab === "keys" && (
          <div className="set-grid">
            <div className="tools-note">
              <Icon name="info" />
              {t("Нажмите на сочетание и введите новое. Backspace — очистить, Esc — отмена.")}
            </div>

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
                <div className="set-section">{t(group)}</div>
                {items.map((a) => {
                  const combo = s.keybinds[a.id] ?? "";
                  const clash = conflictFor(a.id);
                  return (
                    <div key={a.id} className="key-row">
                      <span className="key-label">{t(a.label)}</span>
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
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        )}

        {tab === "look" && (
          <div className="set-grid">
            <div className="field">
              <div className="field-label">{t("Язык")}</div>
              <div className="seg" style={{ maxWidth: 320 }}>
                {(["ru", "en"] as const).map((code) => (
                  <button
                    key={code}
                    className={`seg-btn ${(s.language ?? "ru") === code ? "active" : ""}`}
                    onClick={() => apply({ ...s, language: code })}
                  >
                    {code === "ru" ? t("Русский") : "English"}
                  </button>
                ))}
              </div>
            </div>

            <div className="field set-wide">
              <div className="field-label">{t("Схема")}</div>
              <div className="preset-row">
                {PRESETS.map((p) => (
                  <button
                    key={p.id}
                    className={`preset ${s.themePreset === p.id ? "active" : ""}`}
                    onClick={() =>
                      // Switching preset drops the old tweaks: they were picked
                      // against different surfaces, and keeping them is how you
                      // get unreadable text on a scheme you never chose.
                      apply({ ...s, themePreset: p.id, theme: {} })
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
                    onClick={() => apply({ ...s, accent: c, theme: { ...s.theme, a: c } })}
                    aria-label={t("Акцент {c}", { c })}
                  />
                ))}
              </div>
            </div>

            <div className="field">
              <div className="field-label">{t("Плотность")}</div>
              <div className="seg" style={{ maxWidth: 320 }}>
                {(["comfortable", "compact"] as const).map((d) => (
                  <button
                    key={d}
                    className={`seg-btn ${s.density === d ? "active" : ""}`}
                    onClick={() => apply({ ...s, density: d })}
                  >
                    {d === "comfortable" ? t("Просторно") : t("Плотно")}
                  </button>
                ))}
              </div>
            </div>

            {/* Its own section: a boxed Num card sitting in the third column
                next to two plain fields read as an orphan. A header spans the
                grid, so the card starts a fresh row and says why it is here. */}
            <div className="set-section">{t("Производительность")}</div>

            <Num
              label={t("Подсветка синтаксиса до")}
              unit={t("строк")}
              hint={t("На файлах длиннее подсветка отключается: она работает в главном потоке и на бандлах ощутимо тормозит.")}
              value={s.maxHighlightLines}
              min={0}
              max={200000}
              onChange={(v) => apply({ ...s, maxHighlightLines: v })}
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

        {tab === "a11y" && <A11yTab s={s} apply={apply} path={path} />}
      </div>
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
  apply: (s: AppSettings) => void;
  path: string;
}) {
  const t = useT();
  const scale = s.a11yUiScale ?? 100;
  return (
    <div className="set-grid">
      <div className="field">
        <div className="field-label">{t("Масштаб интерфейса")}</div>
        <p className="field-note">
{t("Увеличивает весь интерфейс, а не только шрифт, поэтому на 200% ничего не наезжает (WCAG 1.4.4).")}
        </p>
        <div className="scale-row">
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => apply({ ...s, a11yUiScale: Math.max(80, scale - 10) })}
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
            onChange={(e) => apply({ ...s, a11yUiScale: Number(e.target.value) })}
            aria-label={t("Масштаб интерфейса, проценты")}
          />
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => apply({ ...s, a11yUiScale: Math.min(250, scale + 10) })}
            aria-label={t("Больше")}
          >
            <Icon name="add" />
          </button>
          <span className="scale-val">{scale}%</span>
          {scale !== 100 && (
            <button className="btn btn-ghost btn-sm" onClick={() => apply({ ...s, a11yUiScale: 100 })}>
              {t("Сброс")}
            </button>
          )}
        </div>
      </div>

      <Toggle
        label={t("Уменьшить анимацию")}
        hint={t("Отключает переходы и фоновое движение. Системная настройка учитывается и без этого.")}
        on={s.reduceMotion}
        onChange={(v) => apply({ ...s, reduceMotion: v })}
      />
      <Toggle
        label={t("Не показывать фоновое свечение")}
        hint={t("Убирает плавно движущиеся пятна за интерфейсом.")}
        on={s.a11yNoAmbient}
        onChange={(v) => apply({ ...s, a11yNoAmbient: v })}
      />
      <Toggle
        label={t("Всегда показывать фокус")}
        hint={t("Рамка фокуса видна и после клика мышью, не только при навигации с клавиатуры.")}
        on={s.a11yAlwaysFocus}
        onChange={(v) => apply({ ...s, a11yAlwaysFocus: v })}
      />
      <Toggle
        label={t("Подписывать уровень опасности")}
        hint={t("Добавляет слово («Крит», «Выс»…) рядом со счётчиками — на случай, когда цвета трудно различить (WCAG 1.4.1).")}
        on={s.a11ySeverityText}
        onChange={(v) => apply({ ...s, a11ySeverityText: v })}
      />
      <Toggle
        label={t("Подчёркивать ссылки")}
        hint={t("Ссылки отличаются не только цветом.")}
        on={s.a11yUnderlineLinks}
        onChange={(v) => apply({ ...s, a11yUnderlineLinks: v })}
      />
      <Toggle
        label={t("Крупные области нажатия")}
        hint={t("Кнопки и переключатели не меньше 24×24 px (WCAG 2.5.8).")}
        on={s.a11yBigTargets}
        onChange={(v) => apply({ ...s, a11yBigTargets: v })}
      />

      <p className="field-note">
{t("Смысловые цвета (уровни опасности) проверены на контраст WCAG 2.2 AA и на три типа дальтонизма во всех схемах. У каждого уровня есть свой значок, так что цвет никогда не единственный признак.")}
      </p>

      {path && (
        <p className="hint-path">
          {t("Файл настроек:")} <code>{path}</code>
        </p>
      )}
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
  apply: (s: AppSettings) => void;
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
  const commit = () => {
    if (text.trim() !== value) onChange(text.trim());
  };
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
