import type { ScanReport, Finding, Severity } from "./types";

/** Severity order, worst first. Kept local (not imported from `./types`) so this
 *  module has no runtime import and the score audit can load it under Node's
 *  type-stripping without a bundler. */
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Security score — the project's headline number.
 *
 * A count of findings answers "how many?"; it does not answer "how bad?". This
 * turns the whole report into one defensible, explainable figure by weighting
 * each confirmed finding by severity and — the part that sets it apart — by
 * whether the taint engine proved it *reachable* from untrusted input. A
 * reachable critical is worse than an isolated one, and the score says so.
 *
 * Deterministic and transparent: the same report always yields the same score,
 * and every point is attributable to a factor shown in the breakdown. No AI, no
 * opaque model.
 */

/** Points a single finding of each severity subtracts from a perfect score. */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 12,
  high: 6,
  medium: 2.5,
  low: 0.8,
  info: 0.2,
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
  return SEVERITY_WEIGHT[f.severity] * (f.extra?.onDataPath ? REACHABLE_MULTIPLIER : 1);
}

/** Higher spreads the curve — a larger project needs a bigger risk load to sink
 *  the score. Tuned so a handful of criticals lands mid-range, not instantly F. */
const SCALE = 24;

export type Grade = "A" | "B" | "C" | "D" | "F";

/** One contributing bucket, so the score reads as arithmetic, not a verdict. */
export interface ScoreFactor {
  severity: Severity;
  count: number;
  /** Points this bucket subtracted, reachable amplification included. */
  penalty: number;
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
  factors: ScoreFactor[];
}

const GRADE_LABEL: Record<Grade, string> = {
  A: "Отличная защита",
  B: "Хорошая защита",
  C: "Средняя защита",
  D: "Слабая защита",
  F: "Критические риски",
};

function gradeFor(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 55) return "C";
  if (score >= 35) return "D";
  return "F";
}

/** A confirmed, non-suppressed finding — the score ignores BETA and silenced. */
function counts(f: Finding): boolean {
  return !f.suppressed && !f.extra?.experimental;
}

/**
 * Computes the score, or `null` for a cancelled scan — which checked almost
 * nothing, so any grade would be a lie.
 */
export function computeScore(report: ScanReport): SecurityScore | null {
  if (report.cancelled) return null;

  const scored = report.findings.filter(counts);
  const factors: ScoreFactor[] = [];
  let load = 0;
  let reachable = 0;

  for (const sev of SEVERITY_ORDER) {
    const group = scored.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    let penalty = 0;
    for (const f of group) {
      const w = findingRisk(f);
      penalty += w;
      if (f.extra?.onDataPath) reachable++;
    }
    load += penalty;
    factors.push({ severity: sev, count: group.length, penalty: Math.round(penalty * 10) / 10 });
  }

  // Hyperbolic decay: never negative, diminishing, and 0 load → exactly 100.
  const score = Math.round((100 / (1 + load / SCALE)) * 10) / 10;
  const grade = gradeFor(score);

  return {
    score,
    grade,
    label: GRADE_LABEL[grade],
    reachable,
    total: scored.length,
    factors,
  };
}
