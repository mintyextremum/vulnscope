import type { ScanReport, Finding, Severity, Confidence } from "./types";

/** Severity order, worst first. Kept local (not imported from `./types`) so this
 *  module has no runtime import and the score audit can load it under Node's
 *  type-stripping without a bundler. */
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Security score — the project's headline number.
 *
 * A count of findings answers "how many?"; it does not answer "how bad?". This
 * turns the whole report into one defensible, explainable figure:
 *
 *  1. Each confirmed finding weighs by severity, by how sure the rule is, and —
 *     the part that sets it apart — by whether the taint engine proved it
 *     *reachable* from untrusted input.
 *  2. Findings are grouped by root cause: one rule, or one vulnerable package
 *     version. Repeats of a cause still cost, but less each time — forty MD5
 *     calls are one habit to break, not forty separate catastrophes.
 *  3. The result is held inside honest limits set by the worst finding. A
 *     project whose worst problem is a low-severity nit cannot be graded
 *     "critical risks" however many nits it has; a project with a critical
 *     vulnerability cannot be graded "good" however small it is next to the
 *     codebase.
 *
 * Deterministic and transparent: the same report always yields the same score,
 * every point is attributable to a factor shown in the breakdown, and the fix
 * plan says exactly which change buys how many points. No AI, no opaque model.
 */

/** Points a single finding of each severity contributes to the risk load. */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 12,
  high: 6,
  medium: 2.5,
  low: 0.8,
  info: 0.2,
};

/** How much of its weight a finding carries by the rule's own confidence. A
 *  pattern that is often right still counts; one that is often wrong counts
 *  half, so a noisy rule cannot sink the score on its own. */
const CONFIDENCE_WEIGHT: Record<Confidence, number> = {
  high: 1,
  medium: 0.75,
  low: 0.5,
};

/** A finding the engine traced from untrusted input weighs this much more:
 *  "present" is one thing, "an attacker can reach it" is another. */
const REACHABLE_MULTIPLIER = 1.8;

/**
 * The risk one finding contributes, on the same scale the score is built from.
 * Exported so anything that ranks findings — the dashboard's riskiest-files
 * panel, for one — orders them exactly the way the headline score weighs them,
 * instead of inventing a second, quietly different opinion of "worse".
 */
export function findingRisk(f: Finding): number {
  return (
    SEVERITY_WEIGHT[f.severity] *
    (CONFIDENCE_WEIGHT[f.confidence] ?? 1) *
    (isReachable(f) ? REACHABLE_MULTIPLIER : 1)
  );
}

/**
 * Whether untrusted input provably reaches the finding: a pattern finding lying
 * on a traced path, or the traced path itself. Reports from before 2.0 did not
 * mark the paths themselves, so the rule id is checked as well.
 */
export function isReachable(f: Finding): boolean {
  return !!f.extra?.onDataPath || f.ruleId === "VS-FLOW";
}

/**
 * The root cause a finding belongs to. Every advisory against one installed
 * package version is fixed by one upgrade, so they are one cause; everything
 * else is grouped by the rule that raised it.
 */
export function rootCause(f: Finding): string {
  if (f.package) return `pkg:${f.package.ecosystem}:${f.package.name}@${f.package.version}`;
  // Every traced path carries the one rule id; what it reaches is the cause.
  if (f.ruleId === "VS-FLOW") return `flow:${f.category}`;
  return `rule:${f.source}:${f.ruleId}`;
}

/**
 * The line of code a finding points at. Findings on one spot fall to one fix —
 * a traced SQL path and the pattern rule on its sink are the same `execute`
 * call — so the fix plan clears them together. Dependencies are not spots: a
 * manifest holds many packages, each its own upgrade.
 */
function spotKey(f: Finding): string | null {
  if (f.package || !f.file || f.line <= 0) return null;
  return `${f.file}|${f.line}|${f.category}`;
}

/**
 * The share of its weight the k-th finding (1-based, worst first) of one cause
 * carries. The first two count in full — a repeat is still a second place to
 * fix — and after that the shares shrink so that n findings of one cause weigh
 * like 1 + log2(n) findings: 4 like 3, 16 like 5, 1000 like 11.
 *
 * The shares never increase, which is what keeps the score monotonic: adding a
 * finding to a cause always adds to its load (see the score audit).
 */
function repeatShare(k: number): number {
  return k <= 1 ? 1 : Math.log2(k / (k - 1));
}

/** Higher spreads the curve — a larger project needs a bigger risk load to sink
 *  the score. Tuned so a handful of criticals lands mid-range, not instantly F. */
const SCALE = 24;

export type Grade = "A" | "B" | "C" | "D" | "F";

/** The severity-token family each grade is painted in. */
export const GRADE_TONE: Record<Grade, "ok" | "med" | "high" | "crit"> = {
  A: "ok",
  B: "ok",
  C: "med",
  D: "high",
  F: "crit",
};

/** One contributing bucket, so the score reads as arithmetic, not a verdict. */
export interface ScoreFactor {
  severity: Severity;
  count: number;
  /** Points of risk load this bucket added, after repeats and confidence. */
  penalty: number;
}

/** An honest limit that held the score in place, and why. */
export interface ScoreLimit {
  kind: "ceiling" | "floor";
  /** The score the limit holds it to. */
  value: number;
  /** Russian explanation with an `{n}` placeholder for `value`, translated at
   *  the call site. */
  reason: string;
}

/** One step of the fix plan: a root cause, and what fixing it is worth. */
export interface PlanStep {
  key: string;
  ruleId: string;
  /** Title of the cause's worst finding (Russian; translated at the call site). */
  title: string;
  /** Its category — what a data-flow cause is named by. */
  category: string;
  severity: Severity;
  count: number;
  files: number;
  /** How many of the cause's findings sit on a traced data-flow path. */
  reachable: number;
  /** Findings of other causes on the same lines, which this fix clears too. */
  alsoCloses: number;
  /** For a vulnerable dependency: the package and the version that fixes it. */
  package: { name: string; version: string; ecosystem: string; fixedVersion: string | null } | null;
  /** Points this step adds, given the steps above it are done. */
  gain: number;
  /** The score once this step and every step above it are done. */
  scoreAfter: number;
  gradeAfter: Grade;
  /** The cause's worst finding, to open it from the plan. */
  findingId: string;
}

/**
 * What a plan step asks the user to do, in words — the same wording on the
 * dashboard, in the printed report and in the exports. `t` translates the
 * Russian source; this module stays free of runtime imports.
 */
export function planStepTitle(step: PlanStep, t: (s: string, vars?: Record<string, string | number>) => string): string {
  if (step.package) {
    return step.package.fixedVersion
      ? t("Обновить {name} до {version}", { name: step.package.name, version: step.package.fixedVersion })
      : t("Заменить {name} {version} — исправленной версии нет", {
          name: step.package.name,
          version: step.package.version,
        });
  }
  if (step.ruleId === "VS-FLOW") return t("Разорвать путь данных: {category}", { category: t(step.category) });
  return t(step.title);
}

export interface SecurityScore {
  /** 0–100; 100 is a clean project. */
  score: number;
  grade: Grade;
  /** Russian label for the grade (translated at the call site). */
  label: string;
  /** How many confirmed findings sit on a traced data-flow path. */
  reachable: number;
  /** Total confirmed, non-suppressed findings the score is based on. */
  total: number;
  /** Distinct root causes behind `total`. */
  causes: number;
  factors: ScoreFactor[];
  /** The score the risk load alone gives, before the honest limits. */
  raw: number;
  /** The limit that changed the score, if any. */
  limit: ScoreLimit | null;
  /** The causes worth fixing first, greedily ordered by points gained. */
  plan: PlanStep[];
}

const GRADE_LABEL: Record<Grade, string> = {
  A: "Отличная защита",
  B: "Хорошая защита",
  C: "Средняя защита",
  D: "Слабая защита",
  F: "Критические риски",
};
/** F without a single critical finding is serious, not critical — the label
 *  says what the report holds, not just where the number fell. */
const F_WITHOUT_CRITICAL = "Серьёзные риски";

function gradeFor(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 55) return "C";
  if (score >= 35) return "D";
  return "F";
}

/**
 * The lowest the score may fall when nothing worse than this severity is
 * present. Many small problems make a weak project, never a critically
 * vulnerable one: only high and critical findings can reach F.
 */
const FLOOR: Partial<Record<Severity, { value: number; reason: string }>> = {
  info: { value: 90, reason: "Только информационные находки — оценка не ниже {n}" },
  low: { value: 75, reason: "Нет находок выше низкого уровня — оценка не ниже {n}" },
  medium: { value: 35, reason: "Нет находок выше среднего уровня — оценка не ниже {n}" },
};

/**
 * The highest the score may reach while a finding of this kind is present. A
 * critical vulnerability is not "good protection" because the rest of the
 * codebase is large and clean.
 */
function ceilingFor(c: Presence): { value: number; reason: string } | null {
  if (c.criticalReachable)
    return { value: 54, reason: "Критическая уязвимость достижима из внешнего ввода — оценка не выше {n}" };
  if (c.critical) return { value: 74, reason: "Есть критическая уязвимость — оценка не выше {n}" };
  if (c.highReachable)
    return { value: 74, reason: "Уязвимость высокого уровня достижима из внешнего ввода — оценка не выше {n}" };
  if (c.high) return { value: 89, reason: "Есть уязвимость высокого уровня — оценка не выше {n}" };
  return null;
}

/** What the limits need to know about a set of findings. */
interface Presence {
  /** Index into SEVERITY_ORDER of the worst finding; 5 when there are none. */
  worst: number;
  critical: boolean;
  criticalReachable: boolean;
  high: boolean;
  highReachable: boolean;
}

/** A root cause with everything the score needs, computed once. */
interface Cause {
  key: string;
  findings: Finding[];
  load: number;
  presence: Presence;
  /** Decayed load per severity, for the factor breakdown. */
  bySeverity: Map<Severity, number>;
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

/** A confirmed, non-suppressed finding — the score ignores BETA and silenced. */
function counts(f: Finding): boolean {
  return !f.suppressed && !f.extra?.experimental;
}

function buildCause(key: string, findings: Finding[]): Cause {
  const ranked = findings
    .map((f) => ({ f, risk: findingRisk(f) }))
    .sort((a, b) => b.risk - a.risk || SEVERITY_ORDER.indexOf(a.f.severity) - SEVERITY_ORDER.indexOf(b.f.severity));
  let load = 0;
  const bySeverity = new Map<Severity, number>();
  const presence: Presence = { worst: 5, critical: false, criticalReachable: false, high: false, highReachable: false };
  ranked.forEach(({ f, risk }, i) => {
    const part = risk * repeatShare(i + 1);
    load += part;
    bySeverity.set(f.severity, (bySeverity.get(f.severity) ?? 0) + part);
    presence.worst = Math.min(presence.worst, SEVERITY_ORDER.indexOf(f.severity));
    const reach = isReachable(f);
    if (f.severity === "critical") {
      presence.critical = true;
      presence.criticalReachable ||= reach;
    } else if (f.severity === "high") {
      presence.high = true;
      presence.highReachable ||= reach;
    }
  });
  return { key, findings: ranked.map((r) => r.f), load, presence, bySeverity };
}

/**
 * A set of causes reduced to what the score reads: the load, and how many
 * causes carry each kind of finding the limits look at. Counts rather than
 * flags, so a cause can be taken out of the set in O(1) — the fix plan asks
 * "what if this one were fixed?" for every cause at every step.
 */
interface Totals {
  load: number;
  /** Causes whose worst finding sits at each index of SEVERITY_ORDER. */
  worst: number[];
  critical: number;
  criticalReachable: number;
  high: number;
  highReachable: number;
}

function totalsOf(causes: Iterable<Cause>): Totals {
  const t: Totals = { load: 0, worst: [0, 0, 0, 0, 0], critical: 0, criticalReachable: 0, high: 0, highReachable: 0 };
  for (const c of causes) shift(t, c, 1);
  return t;
}

/** Adds (`sign` 1) or removes (`sign` -1) one cause. */
function shift(t: Totals, c: Cause, sign: 1 | -1): void {
  const p = c.presence;
  t.load += sign * c.load;
  if (p.worst < 5) t.worst[p.worst] += sign;
  t.critical += sign * Number(p.critical);
  t.criticalReachable += sign * Number(p.criticalReachable);
  t.high += sign * Number(p.high);
  t.highReachable += sign * Number(p.highReachable);
}

/** The score of a set of causes: raw from the load, then held in its limits. */
function evaluate(t: Totals): { score: number; raw: number; limit: ScoreLimit | null; presence: Presence } {
  const worst = t.worst.findIndex((n) => n > 0);
  const p: Presence = {
    worst: worst < 0 ? 5 : worst,
    critical: t.critical > 0,
    criticalReachable: t.criticalReachable > 0,
    high: t.high > 0,
    highReachable: t.highReachable > 0,
  };
  // Hyperbolic decay: never negative, diminishing, and 0 load → exactly 100.
  // Removing causes one by one can leave float dust instead of 0 — clamp it.
  const raw = round1(100 / (1 + Math.max(0, t.load) / SCALE));
  let score = raw;
  let limit: ScoreLimit | null = null;
  const floor = p.worst < 5 ? FLOOR[SEVERITY_ORDER[p.worst]] : undefined;
  const ceiling = ceilingFor(p);
  if (floor && score < floor.value) {
    score = floor.value;
    limit = { kind: "floor", ...floor };
  }
  if (ceiling && score > ceiling.value) {
    score = ceiling.value;
    limit = { kind: "ceiling", ...ceiling };
  }
  return { score, raw, limit, presence: p };
}

/**
 * The highest of several version strings, compared segment by segment as
 * numbers where both are numeric ("4.17.21" > "4.17.9"), as text otherwise.
 */
export function highestVersion(versions: (string | null)[]): string | null {
  const parts = (v: string) => v.replace(/^[v=]/, "").split(/[.+-]/);
  const cmp = (a: string, b: string): number => {
    const x = parts(a);
    const y = parts(b);
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const p = x[i] ?? "0";
      const q = y[i] ?? "0";
      const d = /^\d+$/.test(p) && /^\d+$/.test(q) ? Number(p) - Number(q) : p.localeCompare(q);
      if (d !== 0) return d;
    }
    return 0;
  };
  return versions.reduce<string | null>((best, v) => (v && (!best || cmp(v, best) > 0) ? v : best), null);
}

/** How many plan steps are worth showing; the rest is the long tail. */
const PLAN_STEPS = 8;

/**
 * Greedy fix plan: at each step, the cause whose fix raises the score the most
 * given the steps already taken. Greedy rather than ranked once, because the
 * limits interact — fixing the only critical lifts a ceiling, and only then do
 * the high findings below it start to pay off.
 *
 * A fix is a change to code, so it clears everything on the lines it touches:
 * fixing a cause also removes the other causes' findings on the same spots.
 * Each step's score is therefore the real score of the report once that code
 * is fixed — the score audit re-scores the report without them to prove it.
 */
function buildPlan(causes: Cause[]): PlanStep[] {
  let left = causes;
  let current = evaluate(totalsOf(left)).score;
  const plan: PlanStep[] = [];
  while (left.length > 0 && plan.length < PLAN_STEPS) {
    const owner = new Map<Finding, Cause>();
    const bySpot = new Map<string, Finding[]>();
    for (const c of left) {
      for (const f of c.findings) {
        owner.set(f, c);
        const k = spotKey(f);
        if (!k) continue;
        const list = bySpot.get(k);
        if (list) list.push(f);
        else bySpot.set(k, [f]);
      }
    }
    const totals = totalsOf(left);

    let best: { cause: Cause; score: number; touched: Map<Cause, Cause | null>; closes: number } | null = null;
    for (const c of left) {
      // What the fix clears beyond the cause itself, grouped by their causes.
      const cleared = new Set<Finding>(c.findings);
      for (const f of c.findings) {
        const k = spotKey(f);
        if (k) for (const g of bySpot.get(k) ?? []) cleared.add(g);
      }
      const touched = new Map<Cause, Cause | null>();
      for (const g of cleared) {
        const d = owner.get(g);
        if (d && d !== c && !touched.has(d)) touched.set(d, null);
      }
      const t: Totals = { ...totals, worst: totals.worst.slice() };
      shift(t, c, -1);
      for (const d of touched.keys()) {
        shift(t, d, -1);
        const rest = d.findings.filter((f) => !cleared.has(f));
        const rebuilt = rest.length > 0 ? buildCause(d.key, rest) : null;
        if (rebuilt) shift(t, rebuilt, 1);
        touched.set(d, rebuilt);
      }
      const s = evaluate(t).score;
      // Ties go to the heavier cause: equal points now, more risk removed.
      if (!best || s > best.score || (s === best.score && c.load > best.cause.load)) {
        best = { cause: c, score: s, touched, closes: cleared.size - c.findings.length };
      }
    }
    if (!best) break;

    const { cause, score, touched, closes } = best;
    left = left
      .filter((c) => c !== cause && !touched.has(c))
      .concat([...touched.values()].filter((c): c is Cause => c !== null));
    const worst = cause.findings[0];
    const pkg = worst.package;
    plan.push({
      key: cause.key,
      ruleId: worst.ruleId,
      title: worst.title,
      category: worst.category,
      severity: SEVERITY_ORDER[cause.presence.worst],
      count: cause.findings.length,
      files: new Set(cause.findings.map((f) => f.file)).size,
      reachable: cause.findings.filter(isReachable).length,
      alsoCloses: closes,
      package: pkg
        ? {
            name: pkg.name,
            version: pkg.version,
            ecosystem: pkg.ecosystem,
            // One upgrade has to clear every advisory of the cause, so the
            // version to name is the highest any of them needs.
            fixedVersion: highestVersion(cause.findings.map((f) => f.package?.fixedVersion ?? null)),
          }
        : null,
      gain: round1(score - current),
      scoreAfter: score,
      gradeAfter: gradeFor(score),
      findingId: worst.id,
    });
    current = score;
  }
  return plan;
}

/**
 * Computes the score, or `null` for a cancelled scan — which checked almost
 * nothing, so any grade would be a lie.
 */
export function computeScore(report: ScanReport): SecurityScore | null {
  if (report.cancelled) return null;
  // The dashboard, the report screen, the exports and the recent list all ask
  // for the score of the same report. Reports are replaced, never mutated, so
  // the object itself is a safe key.
  const cached = memo.get(report);
  if (cached) return cached;
  const result = scoreOf(report);
  memo.set(report, result);
  return result;
}

const memo = new WeakMap<ScanReport, SecurityScore>();

function scoreOf(report: ScanReport): SecurityScore {

  const scored = report.findings.filter(counts);
  const grouped = new Map<string, Finding[]>();
  for (const f of scored) {
    const key = rootCause(f);
    const list = grouped.get(key);
    if (list) list.push(f);
    else grouped.set(key, [f]);
  }
  const causes = [...grouped].map(([key, list]) => buildCause(key, list));

  const factors: ScoreFactor[] = [];
  for (const sev of SEVERITY_ORDER) {
    const count = scored.filter((f) => f.severity === sev).length;
    if (count === 0) continue;
    const penalty = causes.reduce((sum, c) => sum + (c.bySeverity.get(sev) ?? 0), 0);
    factors.push({ severity: sev, count, penalty: round1(penalty) });
  }

  const { score, raw, limit, presence } = evaluate(totalsOf(causes));
  const grade = gradeFor(score);
  const label = grade === "F" && !presence.critical ? F_WITHOUT_CRITICAL : GRADE_LABEL[grade];

  return {
    score,
    grade,
    label,
    reachable: scored.filter(isReachable).length,
    total: scored.length,
    causes: causes.length,
    factors,
    raw,
    limit,
    plan: buildPlan(causes),
  };
}
