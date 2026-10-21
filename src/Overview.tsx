import { useContext, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Finding, HistoryPoint, ScanReport, Severity } from "./types";
import { SEVERITY_LABEL, SEVERITY_ORDER, severityCounted } from "./types";
import { Announce, Icon, LtrPath, SeverityBar, formatBytes, formatDuration, formatNumber } from "./components";
import { computeScore, findingRisk, isReachable, planStepTitle, GRADE_TONE, type SecurityScore } from "./score";
import { LangContext, translate, useT, type Lang, type TFn } from "./i18n";

/**
 * The dashboard: what a scan means, before the list of what it found.
 *
 * Read top to bottom it answers four questions in order. How bad is it — the
 * score, with its reasons one click away. What do I do first — the fix plan,
 * ranked by the points each step buys. Where can an attacker get in — the
 * traced paths, and the files carrying the most risk. Is it getting better —
 * the change since the last scan. The facts of the scan itself come last:
 * they matter for trusting the result, not for acting on it.
 */
export function Overview({
  report,
  onOpenFinding,
  onOpenReport,
  onOpenFile,
  onShowReachable,
  onShowSuppressed,
}: {
  report: ScanReport;
  onOpenFinding: (f: Finding) => void;
  onOpenReport: () => void;
  onOpenFile: (path: string) => void;
  onShowReachable: () => void;
  onShowSuppressed: () => void;
}) {
  const t = useT();
  const lang = useContext(LangContext);
  const score = useMemo(() => computeScore(report), [report]);

  // The spoken end of the scan, so a screen-reader user hears the outcome the
  // dashboard shows visually instead of landing on a silent screen.
  const summary = scanSummary(report, lang);

  return (
    <div className="overview">
      <Announce message={summary} />

      {report.cancelled && (
        <div className="error-banner">
          <Icon name="cancel" />
          {t("Сканирование отменено — результаты неполные. Отсутствие находок здесь не означает, что код чист: большая часть файлов не проверялась.")}
        </div>
      )}

      {report.changedOnly && (
        <div className="scope-note">
          <Icon name="difference" />
          <span>
            {t("Проверены только изменения с последнего коммита — файлов: {n}. Оценка относится к ним; сравнение с прошлым сканом и история не обновлялись.", {
              n: report.filesScanned,
            })}
          </span>
        </div>
      )}

      {score && (
        <div className="ov-top">
          <ScoreCard score={score} onShowReachable={onShowReachable} partial={!!report.changedOnly} />
          <FixPlan score={score} report={report} onOpenFinding={onOpenFinding} />
        </div>
      )}

      {!report.cancelled &&
        report.warnings.map((w, i) => (
          <div key={i} className="warn-box">
            <Icon name="warning" />
            {t(w)}
          </div>
        ))}

      {!report.cancelled && (
        <div className="ov-cols">
          <AttackPaths report={report} onOpenFinding={onOpenFinding} />
          <RiskyFiles report={report} onOpenFile={onOpenFile} />
        </div>
      )}

      {!report.cancelled && !report.changedOnly && <Dynamics report={report} onOpenReport={onOpenReport} />}

      {report.delta.fixed.length > 0 && <FixedSince report={report} />}

      <ScanFacts report={report} onShowSuppressed={onShowSuppressed} />
    </div>
  );
}

// ------------------------------------------------------------------- score

function Ring({ score }: { score: SecurityScore }) {
  const R = 52;
  const C = 2 * Math.PI * R;
  // A sliver of arc even at zero, so an F still reads as a ring with a value.
  const dash = Math.max(0.012, score.score / 100) * C;
  return (
    <div className="score-ring-wrap">
      <svg className="score-ring" viewBox="0 0 120 120" role="img" aria-label={`${Math.round(score.score)} / 100`}>
        <circle className="score-track" cx="60" cy="60" r={R} />
        <circle className="score-arc" cx="60" cy="60" r={R} style={{ strokeDasharray: `${dash} ${C}` }} />
      </svg>
      <div className="score-center">
        <div className="score-grade">{score.grade}</div>
        <div className="score-num">
          {Math.round(score.score)}
          <span className="score-num-max">/100</span>
        </div>
      </div>
    </div>
  );
}

/**
 * The headline verdict, and the arithmetic behind it. The score is only worth
 * trusting if it can be taken apart, so "why this score?" opens the factors,
 * the repeat discount and the limit that held it — every number the formula
 * used, none of it hidden.
 */
function ScoreCard({
  score,
  onShowReachable,
  partial,
}: {
  score: SecurityScore;
  onShowReachable: () => void;
  /** Only the changed files were scanned: the score is theirs, not the project's. */
  partial: boolean;
}) {
  const t = useT();
  const [why, setWhy] = useState(false);
  const tone = GRADE_TONE[score.grade];
  const load = score.factors.reduce((n, f) => n + f.penalty, 0) || 1;

  return (
    <section className={`card score-card tone-${tone}`} aria-label={t("Оценка защищённости")}>
      <div className="sc-head">
        <Ring score={score} />
        <div className="score-body">
          <div className="score-title">{partial ? t("Оценка изменений") : t("Оценка защищённости")}</div>
          <div className="score-label">{t(score.label)}</div>
          {score.limit && (
            <div className={`score-limit ${score.limit.kind}`}>
              <Icon name={score.limit.kind === "ceiling" ? "vertical_align_top" : "vertical_align_bottom"} />
              {t(score.limit.reason, { n: score.limit.value })}
            </div>
          )}
          {score.total === 0 && (
            <span className="score-clean">
              <Icon name="verified_user" />
              {t("Подтверждённых находок нет")}
            </span>
          )}
        </div>
      </div>

      {score.total > 0 && (
        <>
          <div
            className="sev-split"
            role="img"
            aria-label={score.factors.map((f) => `${t(SEVERITY_LABEL[f.severity])}: ${f.count}`).join(", ")}
          >
            {score.factors.map((f) => (
              <span
                key={f.severity}
                className={`sev-split-seg ${f.severity}`}
                style={{ flexGrow: f.count }}
                title={`${t(SEVERITY_LABEL[f.severity])}: ${f.count}`}
              />
            ))}
          </div>
          <div className="sc-legend">
            {score.factors.map((f) => (
              <span key={f.severity} className="sc-legend-item">
                <span className={`sev-dot ${f.severity}`} />
                {t(SEVERITY_LABEL[f.severity])}
                <b>{f.count}</b>
              </span>
            ))}
          </div>
          <div className="sc-stats">
            <span className="sc-stat">
              <b>{formatNumber(score.total)}</b>
              {t("Находки")}
            </span>
            <span className="sc-stat" title={t("Находки одного правила или одной версии пакета — одна причина")}>
              <b>{formatNumber(score.causes)}</b>
              {t("Причины")}
            </span>
            {score.reachable > 0 ? (
              <button
                className="sc-stat sc-reach"
                onClick={onShowReachable}
                title={t("Показать только находки, до которых доходит недоверенный ввод")}
              >
                <b>{formatNumber(score.reachable)}</b>
                <Icon name="my_location" />
                {t("На пути данных")}
              </button>
            ) : (
              <span className="sc-stat">
                <b>0</b>
                {t("На пути данных")}
              </span>
            )}
            <button className="sc-why-toggle" onClick={() => setWhy((v) => !v)} aria-expanded={why}>
              <Icon name={why ? "expand_less" : "help"} />
              {t("Почему такая оценка?")}
            </button>
          </div>
        </>
      )}

      {why && (
        <div className="score-why">
          <div className="sw-factors">
            {score.factors.map((f) => {
              const share = Math.round((f.penalty / load) * 100);
              return (
                <div key={f.severity} className="sw-factor">
                  <span className={`sev-dot ${f.severity}`} />
                  <span className="sw-label">{t(SEVERITY_LABEL[f.severity])}</span>
                  <span className="sw-count">{f.count}</span>
                  <span className="sw-bar">
                    <span className={`sw-fill ${f.severity}`} style={{ width: `${Math.max(2, share)}%` }} />
                  </span>
                  <span className="sw-share">{t("{n}% риска", { n: share })}</span>
                </div>
              );
            })}
          </div>
          <ul className="sw-notes">
            <li>
              {t("Повторы одной причины весят всё меньше — находок: {n}, причин: {c}.", {
                n: score.total,
                c: score.causes,
              })}
            </li>
            <li>{t("Достижимое из внешнего ввода весит в 1,8 раза больше, находка правила с низкой уверенностью — вдвое меньше.")}</li>
            <li>
              {score.limit
                ? t("{reason}. Без предела было бы {raw}.", {
                    reason: t(score.limit.reason, { n: score.limit.value }),
                    raw: Math.round(score.raw),
                  })
                : t("Пределы не сработали: оценка — это риск как он есть.")}
            </li>
            <li>{t("BETA и подавленные находки в оценку не входят.")}</li>
          </ul>
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------- fix plan

/**
 * "What do I fix first?", answered by the score itself. Each step is the root
 * cause whose fix buys the most points given the steps above it, and its
 * number is a promise the score audit checks: fix it, rescan, and that is the
 * score you get.
 */
function FixPlan({
  score,
  report,
  onOpenFinding,
}: {
  score: SecurityScore;
  report: ScanReport;
  onOpenFinding: (f: Finding) => void;
}) {
  const t = useT();
  const [all, setAll] = useState(false);
  const TOP = 4;
  const byId = useMemo(() => new Map(report.findings.map((f) => [f.id, f])), [report.findings]);

  if (score.plan.length === 0) {
    return (
      <section className="card fix-plan fp-done">
        <div className="card-title">
          <Icon name="task_alt" />
          {t("План исправлений")}
        </div>
        <p className="fp-empty">
          <Icon name="verified" />
          {t("Исправлять нечего: подтверждённых находок нет.")}
        </p>
      </section>
    );
  }

  const steps = all ? score.plan : score.plan.slice(0, TOP);
  const goal = score.plan[score.plan.length - 1];
  const shownGoal = steps[steps.length - 1];

  return (
    <section className="card fix-plan">
      <div className="card-title">
        <Icon name="trending_up" />
        {t("План исправлений")}
        <span className="ap-sub">{t("что поднимет оценку сильнее всего")}</span>
      </div>
      <ol className="fp-list">
        {steps.map((step, i) => {
          const before = i === 0 ? score.score : score.plan[i - 1].scoreAfter;
          const shown = Math.round(step.scoreAfter) - Math.round(before);
          const target = byId.get(step.findingId);
          const where =
            step.files === 1 && target
              ? target.file.split(/[\\/]/).pop()
              : t("файлов: {n}", { n: step.files });
          return (
            <li key={step.key}>
              <button
                className="fp-row"
                onClick={() => target && onOpenFinding(target)}
                title={t("Оценка после этого шага: {n}", { n: Math.round(step.scoreAfter) })}
              >
                <span className="fp-n">{i + 1}</span>
                <span className={`sev-dot ${step.severity}`} />
                <span className="fp-main">
                  <span className="fp-title">{planStepTitle(step, t)}</span>
                  <span className="fp-meta">
                    <span className="fp-where">{where}</span>
                    {step.count > 1 && <span>{t("мест: {n}", { n: step.count })}</span>}
                    {step.reachable > 0 && (
                      <span className="fp-reach" title={t("Достижимо по данным")}>
                        <Icon name="my_location" />
                        {step.reachable}
                      </span>
                    )}
                    {step.alsoCloses > 0 && (
                      <span title={t("Находки других правил на тех же строках уйдут вместе с этой правкой")}>
                        {t("+{n} на тех же строках", { n: step.alsoCloses })}
                      </span>
                    )}
                  </span>
                </span>
                <span className={`fp-gain ${shown > 0 ? "up" : ""}`}>
                  {shown > 0 ? `+${shown}` : step.gain > 0 ? "+<1" : "±0"}
                </span>
                <span className={`fp-after tone-${GRADE_TONE[step.gradeAfter]}`}>{step.gradeAfter}</span>
              </button>
            </li>
          );
        })}
      </ol>
      <div className="fp-foot">
        <span className="fp-goal">
          {t("Шагов: {n} — {from} → {to}", {
            n: all ? score.plan.length : steps.length,
            from: Math.round(score.score),
            to: Math.round((all ? goal : shownGoal).scoreAfter),
          })}
          <b className={`tone-${GRADE_TONE[(all ? goal : shownGoal).gradeAfter]}`}>{(all ? goal : shownGoal).gradeAfter}</b>
        </span>
        {score.plan.length > TOP && (
          <button className="ap-more" onClick={() => setAll((v) => !v)}>
            <Icon name={all ? "expand_less" : "expand_more"} />
            {all ? t("Свернуть план") : t("Весь план ({n})", { n: score.plan.length })}
          </button>
        )}
      </div>
    </section>
  );
}

// ------------------------------------------------------------ attack paths

/**
 * Attack paths — the routes an attacker takes. The traced data flows, worst
 * first (severity, then whether the chain crosses a file, then its length),
 * each as entry → sink you can click straight into.
 */
function AttackPaths({ report, onOpenFinding }: { report: ScanReport; onOpenFinding: (f: Finding) => void }) {
  const t = useT();
  const all = useMemo(() => {
    const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return report.findings
      .filter((f) => f.ruleId === "VS-FLOW" && !f.suppressed)
      .map((f) => {
        const flow = f.extra?.flow ?? [];
        return { f, flow, crosses: flow.some((s) => s.file && s.file !== f.file), steps: flow.length };
      })
      .sort(
        (a, b) =>
          rank[a.f.severity] - rank[b.f.severity] || Number(b.crosses) - Number(a.crosses) || b.steps - a.steps,
      );
  }, [report.findings]);

  const TOP = 5;
  const [expanded, setExpanded] = useState(false);
  const paths = expanded ? all : all.slice(0, TOP);

  return (
    <section className="card attack-paths">
      <div className="card-title">
        <Icon name="conversion_path" />
        {t("Пути атаки")}
        {all.length > 0 && <span className="count">{all.length}</span>}
        <span className="ap-sub">{t("прослежено от ввода до опасного вызова")}</span>
      </div>
      {all.length === 0 ? (
        <p className="ov-empty">
          <Icon name="shield" />
          {t("Путей от внешнего ввода до опасного вызова не найдено.")}
        </p>
      ) : (
        <div className={`ap-list ${expanded ? "expanded" : ""}`}>
          {paths.map(({ f, flow, crosses, steps }) => {
            const sink = flow[flow.length - 1];
            return (
              <button key={f.id} className="ap-row" onClick={() => onOpenFinding(f)}>
                <span className={`sev-dot ${f.severity}`} />
                <span className="ap-route">
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
                  {f.isNew && <span className="tag is-new">{t("новое")}</span>}
                </span>
                <span className="ap-where">
                  <span className="ap-loc">
                    <LtrPath>
                      {(sink?.file ?? f.file).split(/[\\/]/).pop()}
                      {sink ? `:${sink.line}` : ""}
                    </LtrPath>
                  </span>
                  <span className="ap-steps">{t("шагов: {n}", { n: steps })}</span>
                </span>
              </button>
            );
          })}
        </div>
      )}
      {all.length > TOP && (
        <button className="ap-more" onClick={() => setExpanded((v) => !v)}>
          <Icon name={expanded ? "expand_less" : "expand_more"} />
          {expanded ? t("Свернуть список") : t("Показать все пути ({n})", { n: all.length })}
        </button>
      )}
    </section>
  );
}

// ------------------------------------------------------------- risky files

/**
 * "Where to start" — the files carrying the most risk, weighed exactly as the
 * score weighs findings. The bar is the file's risk against the riskiest one;
 * the percentage is its share of the whole project's.
 */
function RiskyFiles({ report, onOpenFile }: { report: ScanReport; onOpenFile: (path: string) => void }) {
  const t = useT();
  const { rows, total } = useMemo(() => {
    const by = new Map<string, { risk: number; count: number; reachable: number; worst: Severity }>();
    let total = 0;
    for (const f of report.findings) {
      if (f.suppressed || f.extra?.experimental || !f.file) continue;
      const r = by.get(f.file) ?? { risk: 0, count: 0, reachable: 0, worst: "info" as Severity };
      const risk = findingRisk(f);
      r.risk += risk;
      total += risk;
      r.count += 1;
      if (isReachable(f)) r.reachable += 1;
      if (SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(r.worst)) r.worst = f.severity;
      by.set(f.file, r);
    }
    const rows = [...by.entries()]
      .map(([file, r]) => ({ file, ...r }))
      .sort((a, b) => b.risk - a.risk)
      .slice(0, 6);
    return { rows, total };
  }, [report.findings]);

  const max = rows[0]?.risk || 1;

  return (
    <section className="card risky-files">
      <div className="card-title">
        <Icon name="priority_high" />
        {t("С чего начать")}
        <span className="ap-sub">{t("файлы с наибольшим риском")}</span>
      </div>
      {rows.length === 0 ? (
        <p className="ov-empty">
          <Icon name="check_circle" />
          {t("Ни один файл не несёт подтверждённого риска.")}
        </p>
      ) : (
        <div className="rf-list">
          {rows.map((r) => (
            <button
              key={r.file}
              className="rf-row"
              onClick={() => onOpenFile(r.file)}
              title={t("{file}: находок {n}. Полоса — риск файла относительно самого рискованного.", {
                file: r.file,
                n: r.count,
              })}
            >
              <span className={`rf-bar sev-${r.worst}`} style={{ width: `${(r.risk / max) * 100}%` }} />
              <span className="rf-name">{r.file.split(/[\\/]/).pop()}</span>
              <span className="rf-path">
                <LtrPath>{r.file}</LtrPath>
              </span>
              {r.reachable > 0 && (
                <span className="rf-reach" title={t("Достижимо по данным")}>
                  <Icon name="my_location" />
                  {r.reachable}
                </span>
              )}
              <span className="rf-share" title={t("Доля риска всего проекта")}>
                {Math.max(1, Math.round((r.risk / (total || 1)) * 100))}%
              </span>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------- dynamics

/**
 * Better or worse than last time: the change since the previous scan, and the
 * trend over the ones before it. One card, because they answer one question.
 */
function Dynamics({ report, onOpenReport }: { report: ScanReport; onOpenReport: () => void }) {
  const t = useT();
  const lang = useContext(LangContext);
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

  const d = report.delta;
  if (!d.previousScanAt) {
    return (
      <section className="card dynamics dyn-first">
        <Icon name="history" />
        <span>
          {t("Первое сканирование этой цели — сравнивать пока не с чем. Следующий прогон покажет, что изменилось.")}
        </span>
      </section>
    );
  }

  return (
    <section className="card dynamics">
      <div className="card-title">
        <Icon name="show_chart" />
        {t("Динамика")}
        <span className="ap-sub">
          {t("с прошлого скана {date}", {
            date: new Date(d.previousScanAt).toLocaleString(lang === "en" ? "en-US" : "ru-RU"),
          })}
        </span>
      </div>
      <div className="dyn-body">
        <div className="dyn-stats">
          <div className={`delta-stat ${d.newCount > 0 ? "bad" : ""}`}>
            <Icon name={d.newCount > 0 ? "trending_up" : "check"} />
            <b>{d.newCount}</b> {t("новых")}
          </div>
          <div className={`delta-stat ${d.fixedCount > 0 ? "good" : ""}`}>
            <Icon name="trending_down" />
            <b>{d.fixedCount}</b> {t("исправлено")}
          </div>
          <div className="delta-stat">
            <Icon name="remove" />
            <b>{d.unchangedCount}</b> {t("без изменений")}
          </div>
        </div>
        {history.length >= 2 && <Sparkline history={history} onOpen={onOpenReport} />}
      </div>
    </section>
  );
}

/** Total findings over the last scans, scaled to their own range. */
function Sparkline({ history, onOpen }: { history: HistoryPoint[]; onOpen: () => void }) {
  const t = useT();
  const W = 260;
  const H = 40;
  const pad = 3;
  const totals = history.map((p) => p.total);
  // The data's own min..max, not 0..max: a mature project barely moves scan to
  // scan, and a zero-based axis would draw a flat line pinned to the top.
  const lo = Math.min(...totals);
  const hi = Math.max(...totals);
  const span = hi - lo || 1;
  const x = (i: number) => pad + (i * (W - 2 * pad)) / (history.length - 1);
  const y = (v: number) => pad + (1 - (v - lo) / span) * (H - 2 * pad);
  const line = totals.map((v, i) => `${x(i)},${y(v)}`).join(" ");
  const area = `${x(0)},${H - pad} ${line} ${x(history.length - 1)},${H - pad}`;
  const delta = totals[totals.length - 1] - totals[0];
  // Fewer findings over time is improvement — the whole point of the tool.
  const dir = delta < 0 ? "good" : delta > 0 ? "bad" : "flat";

  return (
    <button className="trend-strip" onClick={onOpen} title={t("Открыть отчёт с полным графиком динамики")}>
      <svg className="trend-strip-svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true">
        <polygon className={`trend-strip-area ${dir}`} points={area} />
        <polyline className={`trend-strip-line ${dir}`} points={line} fill="none" />
        <circle className={`trend-strip-dot ${dir}`} cx={x(history.length - 1)} cy={y(totals[totals.length - 1])} r="2.5" />
      </svg>
      <span className={`trend-strip-delta ${dir}`}>
        <Icon name={dir === "good" ? "trending_down" : dir === "bad" ? "trending_up" : "remove"} />
        {delta > 0 ? "+" : ""}
        {delta} {t("находок за {n} сканов", { n: history.length })}
      </span>
    </button>
  );
}

function FixedSince({ report }: { report: ScanReport }) {
  const t = useT();
  const fixed = report.delta.fixed;
  return (
    <section className="card fixed-card">
      <div className="card-title">
        <Icon name="task_alt" />
        {t("Исправлено с прошлого скана")}
        <span className="count">{fixed.length}</span>
      </div>
      <div className="fixed-list">
        {fixed.slice(0, 12).map((f) => (
          <div key={f.fingerprint} className="fixed-row">
            <span className={`sev-dot ${f.severity}`} />
            <span className="fx-title">{t(f.title)}</span>
            <span className="fx-file">
              <LtrPath>{f.file}</LtrPath>
            </span>
          </div>
        ))}
      </div>
      {fixed.length > 12 && <p className="fx-more">{t("и ещё {n}", { n: fixed.length - 12 })}</p>}
    </section>
  );
}

// -------------------------------------------------------------- scan facts

/** Translates a backend engine name, handling the parameterised custom-rules one. */
function engineLabel(e: string, t: TFn): string {
  const m = /^Свои правила \((\d+)\)$/.exec(e);
  if (m) return t("Свои правила ({n})", { n: m[1] });
  return t(e);
}

/**
 * What the scan covered — for trusting the result rather than acting on it,
 * so it comes last and stays compact: the volume, the languages, the engines,
 * and what was deliberately left out of view.
 */
function ScanFacts({ report, onShowSuppressed }: { report: ScanReport; onShowSuppressed: () => void }) {
  const t = useT();
  const maxLang = Math.max(...report.languages.map((l) => l.files), 1);
  const facts: [string, string, string][] = [
    ["description", formatNumber(report.filesScanned), t("Файлов проверено")],
    ["numbers", formatNumber(report.linesScanned), t("Строк кода")],
    ["database", formatBytes(report.bytesScanned), t("Объём кода")],
    ["inventory_2", formatNumber(report.dependenciesChecked), t("Зависимостей проверено")],
    ["timer", formatDuration(report.durationMs), t("Время сканирования")],
  ];
  const beta = report.findings.filter((f) => f.extra?.experimental && !f.suppressed).length;

  return (
    <section className="card scan-facts">
      <div className="card-title">
        <Icon name="fact_check" />
        {t("О сканировании")}
      </div>
      <div className="sf-facts">
        {facts.map(([icon, value, label]) => (
          <div key={label} className="sf-fact">
            <Icon name={icon} />
            <span className="sf-val">{value}</span>
            <span className="sf-key">{label}</span>
          </div>
        ))}
      </div>
      <div className="sf-cols">
        <div>
          <div className="sf-sub">{t("Языки")}</div>
          {report.languages.slice(0, 6).map((l) => (
            <SeverityBar key={l.language} label={l.label} value={l.files} max={maxLang} kind="lang" />
          ))}
          {report.languages.length === 0 && <p className="ov-empty">{t("Файлы не найдены")}</p>}
        </div>
        <div>
          <div className="sf-sub">{t("Использованные движки")}</div>
          <div className="sf-engines">
            {report.enginesUsed.map((e) => (
              <span key={e} className="tag">
                {engineLabel(e, t)}
              </span>
            ))}
          </div>
          {(report.suppressedCount > 0 || beta > 0) && (
            <div className="sf-notes">
              {report.suppressedCount > 0 && (
                <p>
                  <Icon name="visibility_off" />
                  <span>
                    {t("Подавлено: {n}. Не входят в счётчики и оценку; правила лежат в {file}.", {
                      n: report.suppressedCount,
                      file: ".vulnscope-ignore",
                    })}
                  </span>
                  <button className="link-btn" onClick={onShowSuppressed}>
                    {t("Показать")}
                  </button>
                </p>
              )}
              {beta > 0 && (
                <p>
                  <Icon name="science" />
                  <span>
                    {t("BETA: {n}. Эвристические находки для ручной проверки — на своей вкладке, в оценку не входят.", {
                      n: beta,
                    })}
                  </span>
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

// ------------------------------------------------------------- announcement

/** One sentence describing how the scan ended, for the screen-reader summary. */
export function scanSummary(report: ScanReport, lang: Lang): string {
  const t: TFn = (s, v) => translate(lang, s, v);
  if (report.cancelled) {
    return t("Сканирование отменено, результаты неполные. Отсутствие находок не означает, что код чист.");
  }
  const total = SEVERITY_ORDER.reduce((n, s) => n + report.counts[s], 0);
  if (total === 0) {
    return t("Сканирование завершено. Находок нет. Проверено файлов: {files}.", { files: report.filesScanned });
  }
  // Russian inflects the severity word by count; English does not, so it just
  // takes the number and the translated label.
  const breakdown = SEVERITY_ORDER.filter((s) => report.counts[s] > 0)
    .map((s) =>
      lang === "en" ? `${report.counts[s]} ${translate(lang, SEVERITY_LABEL[s]).toLowerCase()}` : severityCounted(report.counts[s], s),
    )
    .join(", ");
  const parts = [t("Сканирование завершено. Найдено {total}: {breakdown}.", { total, breakdown })];
  if (report.delta.previousScanAt && (report.delta.newCount > 0 || report.delta.fixedCount > 0)) {
    parts.push(
      t("С прошлого скана: {new} новых, {fixed} исправлено.", {
        new: report.delta.newCount,
        fixed: report.delta.fixedCount,
      }),
    );
  }
  if (report.suppressedCount > 0) parts.push(t("Подавлено: {n}.", { n: report.suppressedCount }));
  const score = computeScore(report);
  if (score) parts.push(t("Оценка {score} из 100, класс {grade}.", { score: Math.round(score.score), grade: score.grade }));
  return parts.join(" ");
}
