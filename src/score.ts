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
    (f.extra?.onDataPath ? REACHABLE_MULTIPLIER : 1)
  );
}

/**
 * The root cause a finding belongs to. Every advisory against one installed
 * package version is fixed by one upgrade, so they are one cause; everything
 * else is grouped by the rule that raised it.
 */
export function rootCause(f: Finding): string {
  if (f.package) return `pkg:${f.package.ecosystem}:${f.package.name}@${f.package.version}`;
  return `rule:${f.source}:${f.ruleId}`;
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
  severity: Severity;
  count: number;
  files: number;
  /** How many of the cause's findings sit on a traced data-flow path. */
  reachable: number;
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
    const reach = !!f.extra?.onDataPath;
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

/** How many plan steps are worth showing; the rest is the long tail. */
const PLAN_STEPS = 8;

/**
 * Greedy fix plan: at each step, the cause whose fix raises the score the most
 * given the steps already taken. Greedy rather than ranked once, because the
 * limits interact — fixing the only critical lifts a ceiling, and only then do
 * the high findings below it start to pay off.
 */
function buildPlan(causes: Cause[]): PlanStep[] {
  const left = new Set(causes);
  const totals = totalsOf(left);
  let current = evaluate(totals).score;
  const plan: PlanStep[] = [];
  while (left.size > 0 && plan.length < PLAN_STEPS) {
    let best: Cause | null = null;
    let bestScore = -1;
    for (const c of left) {
      shift(totals, c, -1);
      const s = evaluate(totals).score;
      shift(totals, c, 1);
      // Ties go to the heavier cause: equal points now, more risk removed.
      if (s > bestScore || (s === bestScore && best && c.load > best.load)) {
        best = c;
        bestScore = s;
      }
    }
    if (!best) break;
    left.delete(best);
    shift(totals, best, -1);
    const worst = best.findings[0];
    const pkg = worst.package;
    plan.push({
      key: best.key,
      ruleId: worst.ruleId,
      title: worst.title,
      severity: SEVERITY_ORDER[best.presence.worst],
      count: best.findings.length,
      files: new Set(best.findings.map((f) => f.file)).size,
      reachable: best.findings.filter((f) => f.extra?.onDataPath).length,
      package: pkg
        ? { name: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem, fixedVersion: pkg.fixedVersion }
        : null,
      gain: round1(bestScore - current),
      scoreAfter: bestScore,
      gradeAfter: gradeFor(bestScore),
      findingId: worst.id,
    });
    current = bestScore;
  }
  return plan;
}

/**
 * Computes the score, or `null` for a cancelled scan — which checked almost
 * nothing, so any grade would be a lie.
 */
export function computeScore(report: ScanReport): SecurityScore | null {
  if (report.cancelled) return null;

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
    reachable: scored.filter((f) => f.extra?.onDataPath).length,
    total: scored.length,
    causes: causes.length,
    factors,
    raw,
    limit,
    plan: buildPlan(causes),
  };
}
