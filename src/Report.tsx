import { useContext, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ScanReport, Finding, Severity, HistoryPoint } from "./types";
import { SEVERITY_ORDER, SEVERITY_LABEL } from "./types";
import { Icon, formatNumber, formatDuration } from "./components";
import { computeScore, type Grade } from "./score";
import { useT, LangContext } from "./i18n";

/**
 * The executive report — a clean, print-ready page for accountability and
 * efficiency reporting. It answers "how are we doing, and what changed since
 * last time?" with a security grade, key metrics, the dynamics since the
 * previous scan, and remediation efficiency, then prints straight to PDF via the
 * webview (no heavy PDF library, and Cyrillic renders with system fonts).
 */

const GRADE_TONE: Record<Grade, string> = {
  A: "ok",
  B: "ok",
  C: "med",
  D: "high",
  F: "crit",
};

function pct(n: number, d: number): string {
  if (d <= 0) return "—";
  return `${Math.round((n / d) * 100)}%`;
}

export function ReportScreen({ report, onClose }: { report: ScanReport; onClose: () => void }) {
  const t = useT();
  const lang = useContext(LangContext);
  const score = computeScore(report);
  // The organisation for the report header — accountability wants a "who is this
  // for". Kept in localStorage; the field shows on screen and prints as text.
  const [org, setOrg] = useState(() => localStorage.getItem("vs.org") ?? "");

  // The scan-history series, for the trend chart. Loaded lazily: an empty or
  // single-point series simply hides the chart.
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  useEffect(() => {
    let live = true;
    invoke<HistoryPoint[]>("get_scan_history", { root: report.root })
      .then((h) => live && setHistory(h))
      .catch(() => live && setHistory([]));
    return () => {
      live = false;
    };
  }, [report.root]);

  const confirmed = report.findings.filter((f) => !f.extra?.experimental && !f.suppressed);
  const counts = SEVERITY_ORDER.reduce(
    (acc, s) => ((acc[s] = confirmed.filter((f) => f.severity === s).length), acc),
    {} as Record<Severity, number>
  );
  const reachable = confirmed.filter((f) => f.extra?.onDataPath).length;
  const secrets = confirmed.filter((f) => f.source === "secrets").length;
  const vulnDeps = confirmed.filter((f) => f.package != null).length;
  const flows = report.findings.filter((f) => f.ruleId === "VS-FLOW" && !f.suppressed);

  const d = report.delta;
  const carried = d.newCount + d.unchangedCount; // vulnerabilities present after the scan
  const remediation = pct(d.fixedCount, d.fixedCount + carried);
  const throughput =
    report.durationMs > 0 ? Math.round(report.filesScanned / (report.durationMs / 1000)) : 0;

  const dateStr = (iso: string | null) =>
    iso ? new Date(iso).toLocaleString(lang === "en" ? "en-US" : "ru-RU") : "—";

  // A one-line verdict on the direction of travel since the previous scan.
  const trend =
    !d.previousScanAt
      ? t("Первое сканирование — база для сравнения заложена.")
      : d.newCount === 0 && d.fixedCount > 0
        ? t("Защищённость выросла: новых проблем нет, часть устранена.")
        : d.newCount > d.fixedCount
          ? t("Защищённость снизилась: новых проблем больше, чем устранено.")
          : d.fixedCount > d.newCount
            ? t("Есть прогресс: устранено больше, чем появилось.")
            : t("Без заметных сдвигов с прошлого скана.");

  // Top categories, so the report says *what kind* of problems dominate.
  const byCategory = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of confirmed) m.set(f.category, (m.get(f.category) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [confirmed]);

  // Per-author accountability, from git blame: who owns how much of the
  // problem, and how much of it is new since the previous scan. Only rendered
  // when the scanned project is a (non-shallow) git work tree.
  const byAuthor = useMemo(() => {
    const m = new Map<string, { total: number; severe: number; isNew: number }>();
    for (const f of confirmed) {
      const a = f.extra?.blame?.author;
      if (!a) continue;
      const row = m.get(a) ?? { total: 0, severe: 0, isNew: 0 };
      row.total += 1;
      if (f.severity === "critical" || f.severity === "high") row.severe += 1;
      if (f.isNew) row.isNew += 1;
      m.set(a, row);
    }
    return [...m.entries()].sort((a, b) => b[1].total - a[1].total).slice(0, 12);
  }, [confirmed]);

  const tone = score ? GRADE_TONE[score.grade] : "";
  const worst = [...confirmed]
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    .slice(0, 40);

  const tile = (label: string, value: string | number, hint?: string) => (
    <div className="rep-tile">
      <div className="rep-tile-val">{value}</div>
      <div className="rep-tile-key">{label}</div>
      {hint && <div className="rep-tile-hint">{hint}</div>}
    </div>
  );

  return (
    <div className="report-screen">
      <div className="report-bar no-print">
        <button className="btn btn-ghost" onClick={onClose}>
          <Icon name="arrow_back" />
          {t("Назад")}
        </button>
        <div className="rules-title">
          <Icon name="summarize" />
          {t("Отчёт")}
        </div>
        <div style={{ flex: 1 }} />
        <button className="btn btn-primary btn-sm" onClick={() => window.print()}>
          <Icon name="print" />
          {t("Сохранить в PDF")}
        </button>
      </div>

      <div className="report-page">
        {/* Header */}
        <div className="rep-head">
          <div className="rep-head-main">
            <input
              className="rep-org"
              placeholder={t("Организация (для шапки отчёта)")}
              value={org}
              onChange={(e) => {
                setOrg(e.target.value);
                localStorage.setItem("vs.org", e.target.value);
              }}
            />
            <div className="rep-kicker">{t("Отчёт о безопасности")}</div>
            <h1 className="rep-title">{report.targetLabel}</h1>
            <div className="rep-sub">
              {t("Сканирование")}: {dateStr(report.finishedAt || report.startedAt)}
            </div>
          </div>
          {score && (
            <div className={`rep-score tone-${tone}`}>
              <div className="rep-grade">{score.grade}</div>
              <div className="rep-score-num">
                {Math.round(score.score)}
                <span>/100</span>
              </div>
              <div className="rep-score-label">{t(score.label)}</div>
            </div>
          )}
        </div>

        {/* Key metrics */}
        <h2 className="rep-h2">{t("Ключевые показатели")}</h2>
        <div className="rep-tiles">
          {tile(t("Всего находок"), formatNumber(confirmed.length))}
          {tile(t("Достижимо по данным"), formatNumber(reachable), pct(reachable, confirmed.length))}
          {tile(t("Критических"), formatNumber(counts.critical))}
          {tile(t("Высоких"), formatNumber(counts.high))}
          {tile(t("Секретов"), formatNumber(secrets))}
          {tile(t("Уязвимых зависимостей"), formatNumber(vulnDeps))}
          {tile(t("Путей атаки"), formatNumber(flows.length))}
          {tile(t("Файлов проверено"), formatNumber(report.filesScanned))}
        </div>

        {/* Dynamics since last scan */}
        <h2 className="rep-h2">{t("Динамика с прошлого скана")}</h2>
        <div className="rep-dyn">
          <div className="rep-dyn-row">
            <span className="rep-dyn-cell bad">
              <Icon name="trending_up" />
              <b>{d.newCount}</b> {t("новых")}
            </span>
            <span className="rep-dyn-cell good">
              <Icon name="trending_down" />
              <b>{d.fixedCount}</b> {t("исправлено")}
            </span>
            <span className="rep-dyn-cell">
              <Icon name="remove" />
              <b>{d.unchangedCount}</b> {t("без изменений")}
            </span>
            <span className="rep-dyn-when">
              {t("Предыдущий скан")}: {dateStr(d.previousScanAt)}
            </span>
          </div>
          <p className="rep-verdict">{trend}</p>
        </div>

        {/* Trend over recent scans */}
        {history.length >= 2 && (
          <>
            <h2 className="rep-h2">{t("Динамика за последние сканы")}</h2>
            <TrendChart history={history} lang={lang} t={t} />
          </>
        )}

        {/* Efficiency */}
        <h2 className="rep-h2">{t("Эффективность")}</h2>
        <div className="rep-tiles">
          {tile(t("Доля устранённых"), remediation, t("исправлено от всех активных"))}
          {tile(t("Доля достижимых"), pct(reachable, confirmed.length), t("реально эксплуатируемы"))}
          {tile(t("Строк проверено"), formatNumber(report.linesScanned))}
          {tile(t("Зависимостей"), formatNumber(report.dependenciesChecked))}
          {tile(t("Время"), formatDuration(report.durationMs))}
          {tile(t("Скорость"), `${formatNumber(throughput)}/${t("с")}`, t("файлов в секунду"))}
        </div>

        {/* Severity breakdown */}
        <h2 className="rep-h2">{t("По уровню опасности")}</h2>
        <div className="rep-bars">
          {SEVERITY_ORDER.map((s) => {
            const max = Math.max(...SEVERITY_ORDER.map((x) => counts[x]), 1);
            return (
              <div key={s} className="rep-bar-row">
                <span className="rep-bar-label">{t(SEVERITY_LABEL[s])}</span>
                <span className="rep-bar-track">
                  <span className={`rep-bar-fill sev-${s}`} style={{ width: `${(counts[s] / max) * 100}%` }} />
                </span>
                <span className="rep-bar-num">{counts[s]}</span>
              </div>
            );
          })}
        </div>

        {/* Categories breakdown */}
        {byCategory.length > 0 && (
          <>
            <h2 className="rep-h2">{t("По категориям")}</h2>
            <div className="rep-bars">
              {byCategory.map(([cat, n]) => {
                const max = byCategory[0][1] || 1;
                return (
                  <div key={cat} className="rep-bar-row">
                    <span className="rep-bar-label rep-cat-label" title={t(cat)}>{t(cat)}</span>
                    <span className="rep-bar-track">
                      <span className="rep-bar-fill rep-cat-fill" style={{ width: `${(n / max) * 100}%` }} />
                    </span>
                    <span className="rep-bar-num">{n}</span>
                  </div>
                );
              })}
            </div>
          </>
        )}

        {/* Per-author accountability */}
        {byAuthor.length > 0 && (
          <>
            <h2 className="rep-h2">{t("По сотрудникам")}</h2>
            <table className="rep-table">
              <thead>
                <tr>
                  <th>{t("Автор")}</th>
                  <th className="rep-num-col">{t("Находок")}</th>
                  <th className="rep-num-col">{t("Критич. + высокие")}</th>
                  <th className="rep-num-col">{t("Новых")}</th>
                </tr>
              </thead>
              <tbody>
                {byAuthor.map(([author, r]) => (
                  <tr key={author}>
                    <td>{author}</td>
                    <td className="rep-num-col">{r.total}</td>
                    <td className="rep-num-col">{r.severe > 0 ? r.severe : "—"}</td>
                    <td className="rep-num-col">{r.isNew > 0 ? r.isNew : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="rep-more">
              {t("Автор — по git blame строки находки; это последний, кто её менял.")}
            </p>
          </>
        )}

        {/* Top findings table */}
        {worst.length > 0 && (
          <>
            <h2 className="rep-h2">{t("Находки")}</h2>
            <table className="rep-table">
              <thead>
                <tr>
                  <th>{t("Важность")}</th>
                  <th>{t("Категория")}</th>
                  <th>{t("Файл")}</th>
                  <th>{t("Правило")}</th>
                  <th>{t("Достижима")}</th>
                </tr>
              </thead>
              <tbody>
                {worst.map((f: Finding) => (
                  <tr key={f.id}>
                    <td>
                      <span className={`rep-sev sev-${f.severity}`}>{t(SEVERITY_LABEL[f.severity])}</span>
                    </td>
                    <td>{t(f.category)}</td>
                    <td className="rep-file">
                      {f.file}
                      {f.line > 0 ? `:${f.line}` : ""}
                    </td>
                    <td>{f.ruleId}</td>
                    <td>{f.extra?.onDataPath ? t("Да") : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {confirmed.length > worst.length && (
              <p className="rep-more">
                {t("и ещё {n} находок в полном отчёте", { n: confirmed.length - worst.length })}
              </p>
            )}
          </>
        )}

        <div className="rep-foot">
          {t("Сгенерировано VulnScope")} · {dateStr(new Date().toISOString())}
        </div>
      </div>
    </div>
  );
}

/**
 * A compact multi-series line chart of the last several scans: total findings,
 * critical+high, and reachable-by-data-flow. It answers "is this project getting
 * safer over time?" — the one thing a single scan cannot show. Pure inline SVG so
 * it prints to PDF with the rest of the page and needs no charting library.
 */
function TrendChart({
  history,
  lang,
  t,
}: {
  history: HistoryPoint[];
  lang: string;
  t: (s: string, v?: Record<string, string | number>) => string;
}) {
  const W = 720;
  const H = 210;
  const padL = 10;
  const padR = 10;
  const padT = 14;
  const padB = 30;

  const series = useMemo(() => {
    const total = history.map((p) => p.total);
    const sevHi = history.map((p) => p.critical + p.high);
    const reach = history.map((p) => p.reachable);
    const maxY = Math.max(1, ...total, ...sevHi, ...reach);
    const n = history.length;
    const x = (i: number) => padL + (i * (W - padL - padR)) / Math.max(1, n - 1);
    const y = (v: number) => padT + (1 - v / maxY) * (H - padT - padB);
    const line = (vals: number[]) => vals.map((v, i) => `${x(i)},${y(v)}`).join(" ");
    const area =
      `${padL},${y(0)} ` + total.map((v, i) => `${x(i)},${y(v)}`).join(" ") + ` ${x(n - 1)},${y(0)}`;
    return {
      total,
      sevHi,
      reach,
      maxY,
      x,
      y,
      lineTotal: line(total),
      lineSev: line(sevHi),
      lineReach: line(reach),
      area,
      n,
    };
  }, [history]);

  const dateShort = (iso: string) =>
    new Date(iso).toLocaleDateString(lang === "en" ? "en-US" : "ru-RU", {
      day: "2-digit",
      month: "2-digit",
    });

  const last = history[history.length - 1];
  const first = history[0];
  const dot = (vals: number[], cls: string) => (
    <circle className={cls} cx={series.x(series.n - 1)} cy={series.y(vals[series.n - 1])} r="3.5" />
  );

  return (
    <div className="rep-trend">
      <svg viewBox={`0 0 ${W} ${H}`} className="rep-trend-svg" preserveAspectRatio="none" role="img">
        {/* baseline */}
        <line className="rep-trend-axis" x1={padL} y1={series.y(0)} x2={W - padR} y2={series.y(0)} />
        <polygon className="rep-trend-area" points={series.area} />
        <polyline className="rep-trend-total" points={series.lineTotal} fill="none" />
        <polyline className="rep-trend-sev" points={series.lineSev} fill="none" />
        <polyline className="rep-trend-reach" points={series.lineReach} fill="none" />
        {dot(series.total, "rep-trend-total")}
        {dot(series.sevHi, "rep-trend-sev")}
        {dot(series.reach, "rep-trend-reach")}
      </svg>
      <div className="rep-trend-x">
        <span>{dateShort(first.scannedAt)}</span>
        <span className="rep-trend-x-mid">{t("{n} сканов", { n: history.length })}</span>
        <span>{dateShort(last.scannedAt)}</span>
      </div>
      <div className="rep-trend-legend">
        <span className="rep-trend-key">
          <i className="rep-trend-sw sw-total" /> {t("Всего")} <b>{last.total}</b>
        </span>
        <span className="rep-trend-key">
          <i className="rep-trend-sw sw-sev" /> {t("Критич. + высокие")} <b>{last.critical + last.high}</b>
        </span>
        <span className="rep-trend-key">
          <i className="rep-trend-sw sw-reach" /> {t("Достижимо")} <b>{last.reachable}</b>
        </span>
      </div>
    </div>
  );
}
