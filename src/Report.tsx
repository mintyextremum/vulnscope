import { useContext } from "react";
import type { ScanReport, Finding, Severity } from "./types";
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
          <div>
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
