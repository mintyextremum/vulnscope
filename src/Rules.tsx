import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Confidence,
  CONFIDENCE_LABEL,
  RuleInfo,
  Severity,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  SEVERITY_SYMBOL,
} from "./types";
import { Icon } from "./components";
import { useT } from "./i18n";

/**
 * The catalogue of built-in rules. Users of a scanner reasonably ask "what does
 * it actually check?" — without this the answer is only visible in the source.
 */
export function RulesScreen({ onClose }: { onClose: () => void }) {
  const t = useT();
  const [rules, setRules] = useState<RuleInfo[] | null>(null);
  const [query, setQuery] = useState("");
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [confFilter, setConfFilter] = useState<Set<Confidence>>(new Set());
  const [langFilter, setLangFilter] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    invoke<RuleInfo[]>("get_rules")
      .then(setRules)
      .catch(() => setRules([]));
  }, []);

  const languages = useMemo(() => {
    if (!rules) return [];
    const set = new Set<string>();
    rules.forEach((r) => r.languages.forEach((l) => set.add(l)));
    return [...set].sort();
  }, [rules]);

  const filtered = useMemo(() => {
    if (!rules) return [];
    const q = query.trim().toLowerCase();
    return rules.filter((r) => {
      if (sevFilter.size > 0 && !sevFilter.has(r.severity)) return false;
      if (confFilter.size > 0 && !confFilter.has(r.confidence)) return false;
      if (langFilter && !r.languages.includes(langFilter)) return false;
      if (!q) return true;
      return (
        r.id.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q) ||
        r.cwe.some((c) => c.toLowerCase().includes(q)) ||
        (r.owasp ?? "").toLowerCase().includes(q)
      );
    });
  }, [rules, query, sevFilter, confFilter, langFilter]);

  const filtersActive =
    query.trim() !== "" ||
    sevFilter.size > 0 ||
    confFilter.size > 0 ||
    langFilter !== null;

  const byCategory = useMemo(() => {
    const m = new Map<string, RuleInfo[]>();
    for (const r of filtered) {
      const arr = m.get(r.category) ?? [];
      arr.push(r);
      m.set(r.category, arr);
    }
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [filtered]);

  const toggleSev = (s: Severity) =>
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });

  const toggleConf = (c: Confidence) =>
    setConfFilter((prev) => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c);
      else next.add(c);
      return next;
    });

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    (rules ?? []).forEach((r) => {
      c[r.severity] = (c[r.severity] ?? 0) + 1;
    });
    return c;
  }, [rules]);

  const confCounts = useMemo(() => {
    const c: Record<string, number> = {};
    (rules ?? []).forEach((r) => {
      c[r.confidence] = (c[r.confidence] ?? 0) + 1;
    });
    return c;
  }, [rules]);

  const CONF_ORDER: Confidence[] = ["high", "medium", "low"];

  return (
    <div className="rules-screen">
      <div className="rules-bar">
        <button className="btn btn-ghost" onClick={onClose}>
          <Icon name="arrow_back" />
          {t("Назад")}
        </button>
        <div className="rules-title">
          <Icon name="rule" />
          {t("Каталог правил")}
          <span
            className="tool-badge"
            title={
              filtersActive
                ? t("{n} из {total}")
                    .replace("{n}", String(filtered.length))
                    .replace("{total}", String(rules?.length ?? 0))
                : undefined
            }
          >
            {filtersActive ? filtered.length : rules?.length ?? 0}
          </span>
        </div>
        <div style={{ flex: 1 }} />
        <div className="sev-pills">
          {SEVERITY_ORDER.map((s) => (
            <button
              key={s}
              className={`sev-pill ${s} ${sevFilter.has(s) ? "active" : ""} ${
                !counts[s] ? "zero" : ""
              }`}
              onClick={() => toggleSev(s)}
              title={t(SEVERITY_LABEL[s])}
            >
              <Icon name={SEVERITY_SYMBOL[s]} />
              {counts[s] ?? 0}
            </button>
          ))}
        </div>
      </div>

      <div className="rules-filters">
        <div className="search-box" style={{ border: "none", padding: 0 }}>
          <Icon name="search" style={{ left: 10 }} />
          <input
            placeholder={t("Поиск по id, названию, CWE, OWASP…")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <div className="rules-chiprow">
          <div className="conf-chips">
            {CONF_ORDER.map((c) => (
              <button
                key={c}
                className={`lang-chip conf-chip conf-${c} ${
                  confFilter.has(c) ? "active" : ""
                } ${!confCounts[c] ? "zero" : ""}`}
                onClick={() => toggleConf(c)}
                title={t(CONFIDENCE_LABEL[c])}
              >
                {t(CONFIDENCE_LABEL[c])}
                <span className="chip-count">{confCounts[c] ?? 0}</span>
              </button>
            ))}
          </div>
          <div className="lang-chips">
            <button
              className={`lang-chip ${langFilter === null ? "active" : ""}`}
              onClick={() => setLangFilter(null)}
            >
              {t("Все")}
            </button>
            {languages.map((l) => (
              <button
                key={l}
                className={`lang-chip ${langFilter === l ? "active" : ""}`}
                onClick={() => setLangFilter(langFilter === l ? null : l)}
              >
                {l}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="rules-body">
        {rules === null && (
          <div className="viewer-loading">
            <Icon name="progress_activity" className="spin" />
            <span>{t("Загрузка правил…")}</span>
          </div>
        )}

        {rules !== null && filtered.length === 0 && (
          <div className="list-empty">
            <Icon name="search_off" style={{ color: "var(--t-3)" }} />
            <p>{t("Ничего не найдено")}</p>
          </div>
        )}

        {byCategory.map(([category, items]) => (
          <div key={category} className="rule-group">
            <div className="rule-group-head">
              {t(category)}
              <span className="count">{items.length}</span>
            </div>
            {items.map((r) => {
              const open = expanded === r.id;
              return (
                <div key={r.id} className={`rule-row ${open ? "open" : ""}`}>
                  <div
                    className="rule-main"
                    onClick={() => setExpanded(open ? null : r.id)}
                  >
                    <Icon name={SEVERITY_SYMBOL[r.severity]} className={`sev-${r.severity}`} />
                    <span className="rule-id">{r.id}</span>
                    <span className="rule-title">{t(r.title)}</span>
                    <div className="rule-tags">
                      {r.languages.slice(0, 3).map((l) => (
                        <span key={l} className="tag">
                          {l}
                        </span>
                      ))}
                      {r.cwe.slice(0, 1).map((c) => (
                        <span key={c} className="tag cwe">
                          {c.split(":")[0]}
                        </span>
                      ))}
                    </div>
                    <Icon
                      name={open ? "expand_less" : "expand_more"}
                      style={{ color: "var(--t-3)" }}
                    />
                  </div>
                  {open && (
                    <div className="rule-detail">
                      <p>{t(r.description)}</p>
                      <div className="fix-box" style={{ marginTop: 10 }}>
                        <p>{t(r.recommendation)}</p>
                      </div>
                      <div className="rule-meta">
                        {r.cwe.map((c) => (
                          <span key={c} className="tag cwe">
                            {c}
                          </span>
                        ))}
                        {r.owasp && <span className="tag owasp">{r.owasp}</span>}
                        <span className="tag">
                          {r.confidence === "high"
                            ? t("Высокая точность")
                            : r.confidence === "medium"
                            ? t("Средняя точность")
                            : t("Требует проверки")}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}
