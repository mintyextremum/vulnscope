/**
 * Security-score audit.
 *
 * The score is the dashboard's headline — the one number a user reads as a
 * verdict. If it stops being monotonic (more findings → lower score) or stops
 * rewarding the reachability signal, it quietly lies, and nothing else in the
 * pipeline would notice. `tsc` proves the types; only this proves the maths.
 *
 * Pins the properties that make the number trustworthy:
 *   1. A clean project scores 100 / grade A.
 *   2. More (or worse) findings never raise the score.
 *   3. A finding proven reachable by the taint engine lowers the score more than
 *      the same finding sitting unreachable — the whole point of the metric.
 *   4. A cancelled scan yields no score (any grade would be a lie).
 *
 * Usage: npm run audit:score
 */
import { computeScore } from "../src/score.ts";

function report(findings, over = {}) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  return {
    id: "1", root: "", targetLabel: "x", startedAt: "", finishedAt: "", durationMs: 1,
    cancelled: false,
    delta: { previousScanAt: null, newCount: 0, fixedCount: 0, unchangedCount: 0, fixed: [], newBySeverity: {} },
    suppressedCount: 0,
    findings,
    files: [], skipped: [], counts,
    filesScanned: 1, filesSkipped: 0, linesScanned: 1, bytesScanned: 1,
    languages: [], dependenciesChecked: 0, enginesUsed: [], warnings: [],
    ...over,
  };
}

let n = 0;
function finding(severity, over = {}) {
  return {
    id: "f" + n++, fingerprint: "fp" + n, suppressed: false, suppressionReason: null,
    isNew: false, ruleId: "VS-X", title: "T", description: "D", recommendation: "R",
    severity, confidence: "high", source: "builtin", sourceLabel: "L", category: "C",
    file: "a.py", line: 1, endLine: 1, column: 1, endColumn: 1, snippet: "s", snippetStartLine: 1,
    cwe: [], owasp: null, cve: [], extra: null, package: null, ...over,
  };
}

const problems = [];
const check = (cond, msg) => { if (!cond) problems.push(msg); };

// 1) Clean project.
const clean = computeScore(report([]));
check(clean !== null && clean.score === 100 && clean.grade === "A", `clean project must be 100/A, got ${clean && clean.score + "/" + clean.grade}`);

// 2) Monotonic: adding findings never raises the score.
const one = computeScore(report([finding("high")]));
const many = computeScore(report([finding("high"), finding("high"), finding("critical")]));
check(one.score < 100, "a finding must lower the score below 100");
check(many.score < one.score, "more/worse findings must lower the score further");

// 3) Reachability weighs more.
const unreachable = computeScore(report([finding("critical")]));
const reachable = computeScore(report([finding("critical", { extra: { onDataPath: true } })]));
check(reachable.score < unreachable.score, "a reachable finding must lower the score more than an unreachable one");
check(reachable.reachable === 1 && unreachable.reachable === 0, "reachable count must reflect onDataPath");

// 4) Suppressed and BETA are excluded.
const withNoise = computeScore(report([
  finding("critical", { suppressed: true }),
  finding("critical", { extra: { experimental: true } }),
]));
check(withNoise.score === 100, "suppressed and BETA findings must not affect the score");

// 5) Grades are ordered and cover the range.
check(computeScore(report([finding("info")])).grade === "A", "a lone info finding should still be ~A");
const fGrade = computeScore(report(Array.from({ length: 10 }, () => finding("critical", { extra: { onDataPath: true } }))));
check(fGrade.grade === "F", `ten reachable criticals must be grade F, got ${fGrade.grade} (${fGrade.score})`);

// 6) Cancelled → no score.
check(computeScore(report([], { cancelled: true })) === null, "a cancelled scan must yield no score");

if (problems.length === 0) {
  console.log("Оценка защищённости: монотонна, достижимость весит больше, отменённый скан без оценки.");
  process.exit(0);
}
console.log("Проблемы в оценке защищённости:");
for (const p of problems) console.log(`  ✗ ${p}`);
process.exit(1);
