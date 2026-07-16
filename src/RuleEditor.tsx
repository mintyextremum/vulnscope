import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { Icon } from "./components";
import { useT } from "./i18n";
import {
  Confidence,
  LanguageOption,
  RuleTestResult,
  Severity,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  SEVERITY_SYMBOL,
  UserRule,
  ValidationIssue,
} from "./types";

const BLANK: UserRule = {
  id: "",
  title: "",
  description: "",
  recommendation: "",
  severity: "high",
  confidence: "medium",
  category: "Своё правило",
  languages: [],
  pattern: "",
  unlessContains: [],
  cwe: [],
  owasp: null,
  references: [],
  skipInTests: false,
  enabled: true,
};

/** Splits a comma-separated field into a clean list. */
function parseList(s: string): string[] {
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

export function RuleEditor({ onClose }: { onClose: () => void }) {
  const t = useT();
  const [rules, setRules] = useState<UserRule[] | null>(null);
  const [editing, setEditing] = useState<UserRule | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [issues, setIssues] = useState<ValidationIssue[]>([]);
  const [sample, setSample] = useState("");
  const [test, setTest] = useState<RuleTestResult | null>(null);
  const [languages, setLanguages] = useState<LanguageOption[]>([]);
  const [path, setPath] = useState("");
  const [toast, setToast] = useState<string | null>(null);

  const reload = useCallback(() => {
    invoke<UserRule[]>("get_user_rules")
      .then(setRules)
      .catch(() => setRules([]));
  }, []);

  useEffect(() => {
    reload();
    invoke<LanguageOption[]>("get_languages").then(setLanguages).catch(() => {});
    invoke<string>("get_user_rules_path").then(setPath).catch(() => {});
  }, [reload]);

  // Live preview: re-run the pattern as the user types, so a mistake shows up
  // immediately instead of after a save-and-scan round trip.
  useEffect(() => {
    if (!editing || !editing.pattern.trim()) {
      setTest(null);
      return;
    }
    let alive = true;
    const t = setTimeout(() => {
      invoke<RuleTestResult>("test_user_rule", { rule: editing, sample })
        .then((r) => alive && setTest(r))
        .catch(() => {});
    }, 180);
    return () => {
      alive = false;
      clearTimeout(t);
    };
  }, [editing, sample]);

  const flash = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 2200);
  };

  const startNew = () => {
    setEditing({ ...BLANK });
    setIsNew(true);
    setIssues([]);
    setSample("");
  };

  const startEdit = (r: UserRule) => {
    setEditing({ ...r });
    setIsNew(false);
    setIssues([]);
  };

  const save = async () => {
    if (!editing) return;
    const found = await invoke<ValidationIssue[]>("save_user_rule", { rule: editing });
    setIssues(found);
    if (found.length === 0) {
      setEditing(null);
      reload();
      flash(isNew ? t("Правило создано") : t("Правило сохранено"));
    }
  };

  const remove = async (id: string) => {
    await invoke("delete_user_rule", { id });
    reload();
    flash(t("Правило удалено"));
  };

  const toggle = async (r: UserRule) => {
    await invoke("set_user_rule_enabled", { id: r.id, enabled: !r.enabled });
    reload();
  };

  const exportRules = async () => {
    if (!rules?.length) return;
    const target = await saveDialog({
      defaultPath: "vulnscope-rules.json",
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (!target) return;
    await invoke("save_report", {
      path: target,
      json: JSON.stringify({ rules }, null, 2),
    });
    flash(t("Набор правил выгружен"));
  };

  const importRules = async () => {
    const picked = await openDialog({
      multiple: false,
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (typeof picked !== "string") return;
    try {
      const json = await invoke<string>("read_source", {
        root: picked.replace(/[\\/][^\\/]+$/, ""),
        relative: picked.split(/[\\/]/).pop() ?? "",
      });
      const n = await invoke<number>("import_user_rules", { json });
      reload();
      flash(t("Импортировано правил: {n}", { n }));
    } catch (e) {
      flash(String(e));
    }
  };

  const issueFor = (field: string) => issues.find((i) => i.field === field)?.message;

  const fired = useMemo(
    () => (test?.matches ?? []).filter((m) => !m.suppressed).length,
    [test]
  );

  return (
    <div className="rules-screen">
      <div className="rules-bar">
        <button className="btn btn-ghost" onClick={editing ? () => setEditing(null) : onClose}>
          <Icon name="arrow_back" />
          {t("Назад")}
        </button>
        <div className="rules-title">
          <Icon name="edit_note" />
          {editing ? (isNew ? "Новое правило" : `Правка ${editing.id}`) : t("Свои правила")}
          {!editing && <span className="tool-badge">{rules?.length ?? 0}</span>}
        </div>
        <div style={{ flex: 1 }} />
        {!editing && (
          <>
            <button className="btn btn-ghost btn-sm" onClick={importRules}>
              <Icon name="upload" />
              {t("Импорт")}
            </button>
            <button
              className="btn btn-ghost btn-sm"
              onClick={exportRules}
              disabled={!rules?.length}
            >
              <Icon name="download" />
              {t("Экспорт")}
            </button>
            <button className="btn btn-primary btn-sm" onClick={startNew}>
              <Icon name="add" />
              {t("Создать правило")}
            </button>
          </>
        )}
        {editing && (
          <button className="btn btn-primary btn-sm" onClick={save}>
            <Icon name="check" />
            {t("Сохранить")}
          </button>
        )}
      </div>

      {toast && (
        <div className="toast">
          <Icon name="check_circle" />
          {toast}
        </div>
      )}

      {!editing && (
        <div className="rules-body">
          {rules === null && <div className="viewer-loading">{t("Загрузка…")}</div>}

          {rules?.length === 0 && (
            <div className="empty-state">
              <Icon name="edit_note" />
              <h3>{t("Своих правил пока нет")}</h3>
              <p>
{t("Правило — это регулярное выражение плюс описание и рекомендация. Оно работает наравне со встроенными: так же пропускает комментарии и тестовые файлы.")}
              </p>
              <button className="btn btn-primary" onClick={startNew}>
                <Icon name="add" />
                {t("Создать первое правило")}
              </button>
              {path && (
                <p className="hint-path">
                  {t("Файл правил:")} <code>{path}</code>
                </p>
              )}
            </div>
          )}

          {rules?.map((r) => (
            <div key={r.id} className={`rule-row ${r.enabled ? "" : "off"}`}>
              <div className="rule-main">
                <label
                  className={`tool-check ${r.enabled ? "checked" : ""}`}
                  title={r.enabled ? t("Выключить") : t("Включить")}
                  onClick={(e) => {
                    e.stopPropagation();
                    toggle(r);
                  }}
                >
                  <span className="opt-box">
                    <Icon name="check" />
                  </span>
                </label>
                <Icon name={SEVERITY_SYMBOL[r.severity]} className={`sev-${r.severity}`} />
                <span className="rule-id">{r.id}</span>
                <span className="rule-title">{r.title}</span>
                <code className="rule-pattern">{r.pattern}</code>
                <div className="rule-tags">
                  {r.languages.length === 0 ? (
                    <span className="tag">{t("все языки")}</span>
                  ) : (
                    r.languages.slice(0, 3).map((l) => (
                      <span key={l} className="tag">
                        {languages.find((x) => x.id === l)?.label ?? l}
                      </span>
                    ))
                  )}
                </div>
                <button className="btn btn-ghost btn-sm" onClick={() => startEdit(r)}>
                  <Icon name="edit" />
                </button>
                <button className="btn btn-ghost btn-sm" onClick={() => remove(r.id)} title={t("Удалить")}>
                  <Icon name="delete" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {editing && (
        <div className="editor">
          <div className="editor-form">
            <Field label={t("Идентификатор")} error={issueFor("id")} hint={t("Например MY-001. Префикс VS- занят встроенными правилами.")}>
              <input
                className="input mono"
                value={editing.id}
                disabled={!isNew}
                onChange={(e) => setEditing({ ...editing, id: e.target.value })}
                placeholder="MY-001"
              />
            </Field>

            <Field label={t("Название")} error={issueFor("title")}>
              <input
                className="input"
                value={editing.title}
                onChange={(e) => setEditing({ ...editing, title: e.target.value })}
                placeholder={t("Что нашли — коротко")}
              />
            </Field>

            <Field label={t("Регулярное выражение")} error={issueFor("pattern")} hint={t("Синтаксис Rust regex: без lookahead и обратных ссылок.")}>
              <input
                className="input mono"
                value={editing.pattern}
                onChange={(e) => setEditing({ ...editing, pattern: e.target.value })}
                placeholder="dangerous_call\\s*\\("
                spellCheck={false}
              />
            </Field>

            <div className="field-grid">
              <Field label={t("Важность")}>
                <div className="seg">
                  {SEVERITY_ORDER.map((s) => (
                    <button
                      key={s}
                      className={`seg-btn ${editing.severity === s ? `active ${s}` : ""}`}
                      onClick={() => setEditing({ ...editing, severity: s as Severity })}
                    >
                      {t(SEVERITY_LABEL[s])}
                    </button>
                  ))}
                </div>
              </Field>

              <Field label={t("Достоверность")}>
                <div className="seg">
                  {(["low", "medium", "high"] as Confidence[]).map((c) => (
                    <button
                      key={c}
                      className={`seg-btn ${editing.confidence === c ? "active" : ""}`}
                      onClick={() => setEditing({ ...editing, confidence: c })}
                    >
                      {{ low: t("Требует проверки"), medium: t("Средняя"), high: t("Высокая") }[c]}
                    </button>
                  ))}
                </div>
              </Field>
            </div>

            <Field
              label={t("Языки")}
              error={issueFor("languages")}
              hint={t("Ничего не выбрано — правило работает во всех текстовых файлах.")}
            >
              <div className="lang-chips">
                {languages.map((l) => {
                  const on = editing.languages.includes(l.id);
                  return (
                    <button
                      key={l.id}
                      className={`lang-chip ${on ? "active" : ""}`}
                      onClick={() =>
                        setEditing({
                          ...editing,
                          languages: on
                            ? editing.languages.filter((x) => x !== l.id)
                            : [...editing.languages, l.id],
                        })
                      }
                    >
                      {l.label}
                    </button>
                  );
                })}
              </div>
            </Field>

            <Field label={t("В чём проблема")}>
              <textarea
                className="input area"
                value={editing.description}
                onChange={(e) => setEditing({ ...editing, description: e.target.value })}
                placeholder={t("Почему это опасно и что может сделать атакующий")}
                rows={3}
              />
            </Field>

            <Field label={t("Как исправить")}>
              <textarea
                className="input area"
                value={editing.recommendation}
                onChange={(e) => setEditing({ ...editing, recommendation: e.target.value })}
                placeholder={t("Конкретное действие, а не «будьте осторожны»")}
                rows={2}
              />
            </Field>

            <div className="field-grid">
              <Field label={t("Не срабатывать, если строка содержит")} hint={t("Через запятую")}>
                <input
                  className="input mono"
                  value={editing.unlessContains.join(", ")}
                  onChange={(e) =>
                    setEditing({ ...editing, unlessContains: parseList(e.target.value) })
                  }
                  placeholder="sanitize, // ok"
                />
              </Field>
              <Field label="CWE" hint={t("Через запятую")}>
                <input
                  className="input mono"
                  value={editing.cwe.join(", ")}
                  onChange={(e) => setEditing({ ...editing, cwe: parseList(e.target.value) })}
                  placeholder="CWE-89"
                />
              </Field>
            </div>

            <div className="field-grid">
              <Field label={t("Категория")}>
                <input
                  className="input"
                  value={editing.category}
                  onChange={(e) => setEditing({ ...editing, category: e.target.value })}
                />
              </Field>
              <Field label="OWASP Top 10">
                <input
                  className="input"
                  value={editing.owasp ?? ""}
                  onChange={(e) =>
                    setEditing({ ...editing, owasp: e.target.value || null })
                  }
                  placeholder="A03:2021 – Injection"
                />
              </Field>
            </div>

            <label className={`opt ${editing.skipInTests ? "checked" : ""}`}>
              <input
                type="checkbox"
                checked={editing.skipInTests}
                onChange={(e) => setEditing({ ...editing, skipInTests: e.target.checked })}
              />
              <span className="opt-box">
                <Icon name="check" />
              </span>
              <span className="opt-text">
                <strong>{t("Не срабатывать в тестах")}</strong>
                <span>{t("Включите, если правило шумит на тестовых файлах")}</span>
              </span>
            </label>
          </div>

          <div className="editor-preview">
            <div className="panel-head">
              <Icon name="science" />
              {t("Проверка на примере")}
            </div>
            <textarea
              className="input area mono sample"
              value={sample}
              onChange={(e) => setSample(e.target.value)}
              placeholder={t("Вставьте сюда код, чтобы увидеть,\nчто правило поймает")}
              spellCheck={false}
            />

            <div className="preview-result">
              {test === null && <div className="preview-idle">{t("Введите выражение и пример кода")}</div>}

              {test && !test.ok && (
                <div className="error-banner">
                  <Icon name="error" />
                  {test.error}
                </div>
              )}

              {test?.ok && sample.trim() !== "" && (
                <>
                  <div className={`preview-summary ${fired > 0 ? "hit" : ""}`}>
                    <Icon name={fired > 0 ? "check_circle" : "search_off"} />
                    {fired > 0
                      ? t("Сработает на строках: {lines}", { lines: fired })
                      : t("На этом примере не срабатывает")}
                  </div>
                  {test.matches.map((m, i) => (
                    <div key={i} className={`preview-line ${m.suppressed ? "suppressed" : ""}`}>
                      <span className="ln">{m.line}</span>
                      <span className="lc">{m.text}</span>
                      {m.suppressed && (
                        <span className="tag" title={t("Отсечено правилом «не срабатывать, если содержит»")}>
                          {t("отсечено")}
                        </span>
                      )}
                    </div>
                  ))}
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={`field ${error ? "has-error" : ""}`}>
      <div className="field-label">{label}</div>
      {children}
      {error ? (
        <div className="field-error">
          <Icon name="error" />
          {error}
        </div>
      ) : (
        hint && <div className="field-note">{hint}</div>
      )}
    </div>
  );
}
