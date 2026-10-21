/**
 * Security-score audit.
 *
 * The score is the dashboard's headline — the one number a user reads as a
 * verdict. If it stops being monotonic (more findings → lower score), stops
 * rewarding the reachability signal, or starts calling a pile of nits a
 * critical risk, it quietly lies, and nothing else in the pipeline would
 * notice. `tsc` proves the types; only this proves the maths.
 *
 * Pins the properties that make the number trustworthy:
 *   1. A clean project scores 100 / grade A.
 *   2. More (or worse) findings never raise the score — checked on fixed cases
 *      and on thousands of random reports.
 *   3. A finding proven reachable by the taint engine lowers the score more than
 *      the same finding sitting unreachable — the whole point of the metric.
 *   4. Suppressed and BETA findings are excluded; a cancelled scan has no score.
 *   5. Honest limits: only high and critical findings can reach F; a critical
 *      never grades better than C, a reachable one never better than D; a pile
 *      of info findings is still A.
 *   6. Root causes: repeats of one rule cost less than as many distinct rules,
 *      advisories against one package version are one cause, and a low-
 *      confidence finding weighs less than a high-confidence one.
 *   7. Traced data flows count as reachable even in reports that did not mark
 *      them, and a flow's cause is what it reaches.
 *   8. The fix plan: each step's score is the real score of the report once
 *      that cause is fixed — its findings and everything else on the same lines
 *      gone — and fixing everything reaches 100.
 *
 * Usage: npm run audit:score
 */
import { computeScore, rootCause, isReachable } from "../src/score.ts";

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
  n++;
  return {
    id: "f" + n, fingerprint: "fp" + n, suppressed: false, suppressionReason: null,
    // A distinct rule per finding unless the case says otherwise: most checks
    // are about severity, and must not be blurred by the repeat discount.
    isNew: false, ruleId: "VS-" + n, title: "T", description: "D", recommendation: "R",
    severity, confidence: "high", source: "builtin", sourceLabel: "L", category: "C",
    // A line of its own, so no two findings share a spot unless a case says so.
    file: "a.py", line: n, endLine: n, column: 1, endColumn: 1, snippet: "s", snippetStartLine: 1,
    cwe: [], owasp: null, cve: [], references: [], extra: null, package: null, ...over,
  };
}
const many = (k, sev, over = {}) => Array.from({ length: k }, () => finding(sev, over));
const score = (fs) => computeScore(report(fs));
const reach = { extra: { onDataPath: true } };

const problems = [];
const check = (cond, msg) => { if (!cond) problems.push(msg); };

// 1) Clean project.
const clean = score([]);
check(clean !== null && clean.score === 100 && clean.grade === "A" && clean.limit === null && clean.plan.length === 0,
  `clean project must be 100/A with no limit and no plan, got ${clean && clean.score + "/" + clean.grade}`);

// 2) Monotonic: adding findings never raises the score.
const one = score([finding("high")]);
const worse = score([finding("high"), finding("high"), finding("critical")]);
check(one.score < 100, "a finding must lower the score below 100");
check(worse.score < one.score, "more/worse findings must lower the score further");

// Random reports: add one finding at a time and the score never goes up. The
// generator is a fixed LCG, so a failure reproduces exactly.
let seed = 42;
const rnd = (k) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % k; };
const SEVS = ["critical", "high", "medium", "low", "info"];
const CONFS = ["high", "medium", "low"];
let monotonicBreaks = 0;
for (let trial = 0; trial < 400 && monotonicBreaks === 0; trial++) {
  const fs = [];
  let prev = 100;
  for (let step = 0; step < 25; step++) {
    const pkg = rnd(5) === 0 ? { name: "p" + rnd(3), version: "1.0." + rnd(2), ecosystem: "npm", fixedVersion: null } : null;
    fs.push(finding(SEVS[rnd(5)], {
      ruleId: "R" + rnd(6),
      confidence: CONFS[rnd(3)],
      extra: rnd(3) === 0 ? { onDataPath: true } : null,
      package: pkg,
      // Few files, lines and categories, so findings keep landing on shared
      // spots — the case where a fix clears several causes at once.
      file: "f" + rnd(3),
      line: 1 + rnd(4),
      category: "C" + rnd(2),
    }));
    const s = score(fs).score;
    if (s > prev + 1e-9) {
      monotonicBreaks++;
      problems.push(`random report ${trial}, step ${step}: score rose ${prev} → ${s}`);
    }
    prev = s;
  }
}

// 3) Reachability weighs more.
const unreachable = score([finding("critical")]);
const reachable = score([finding("critical", reach)]);
check(reachable.score < unreachable.score, "a reachable finding must lower the score more than an unreachable one");
check(reachable.reachable === 1 && unreachable.reachable === 0, "reachable count must reflect onDataPath");

// 4) Suppressed and BETA are excluded; cancelled → no score.
const withNoise = score([
  finding("critical", { suppressed: true }),
  finding("critical", { extra: { experimental: true } }),
]);
check(withNoise.score === 100 && withNoise.total === 0, "suppressed and BETA findings must not affect the score");
check(computeScore(report([], { cancelled: true })) === null, "a cancelled scan must yield no score");

// 5) Honest limits.
const lows = score(many(100, "low"));
check(lows.grade === "B" && lows.score >= 75, `100 low findings must still be B, got ${lows.grade} (${lows.score})`);
const sameLows = score(many(100, "low", { ruleId: "VS-NIT" }));
check(sameLows.score >= lows.score, "100 repeats of one low rule must not score below 100 distinct low rules");
const md5 = score(many(40, "medium", { ruleId: "VS-MD5" }));
check(md5.grade !== "F" && md5.score >= 35, `40 repeats of one medium rule must not be F, got ${md5.grade} (${md5.score})`);
const mediums = score(many(300, "medium"));
check(mediums.grade === "D" && mediums.limit?.kind === "floor", `300 distinct mediums must floor at D, got ${mediums.grade}`);
check(mediums.label !== "Критические риски", "no critical finding, no 'critical risks' label");
const infos = score(many(60, "info"));
check(infos.grade === "A", `60 info findings must still be A, got ${infos.grade} (${infos.score})`);
const crit = score([finding("critical")]);
check(infos.score > crit.score, "info findings must never weigh like a critical one");
check(crit.score < 75, `a critical must never grade above C, got ${crit.score}`);
const softCrit = score([finding("critical", { confidence: "low" })]);
check(softCrit.score <= 74 && softCrit.limit?.kind === "ceiling", `a low-confidence critical is still capped at C, got ${softCrit.score}`);
const reachCrit = score([finding("critical", { confidence: "low", ...reach })]);
check(reachCrit.score <= 54, `a reachable critical must never grade above D, got ${reachCrit.score}`);
const high = score([finding("high", { confidence: "low" })]);
check(high.grade !== "A", `a high finding must never be A, got ${high.score}`);
const fGrade = score(many(10, "critical", reach));
check(fGrade.grade === "F" && fGrade.label === "Критические риски", `ten reachable criticals must be F / critical risks, got ${fGrade.grade} (${fGrade.score})`);
const fHigh = score(many(40, "high", reach));
check(fHigh.grade === "F" && fHigh.label === "Серьёзные риски", `F without a critical must say 'serious', got ${fHigh.label}`);

// 6) Root causes and confidence.
const repeated = score(many(20, "high", { ruleId: "VS-SAME" }));
const distinct = score(many(20, "high"));
const single = score([finding("high", { ruleId: "VS-SAME" })]);
check(repeated.score > distinct.score, "20 repeats of one rule must cost less than 20 distinct rules");
check(repeated.score < single.score, "repeats must still cost something");
check(repeated.causes === 1 && distinct.causes === 20, "causes must count distinct rules");
const pkg = { name: "lodash", version: "4.17.0", ecosystem: "npm", fixedVersion: "4.17.21" };
const advisories = score([
  finding("high", { ruleId: "GHSA-1", package: pkg, source: "osv" }),
  finding("critical", { ruleId: "GHSA-2", package: pkg, source: "osv" }),
]);
check(advisories.causes === 1 && advisories.plan.length === 1 && advisories.plan[0].count === 2,
  "advisories against one package version must be one cause and one plan step");
check(advisories.plan[0].package?.fixedVersion === "4.17.21" && advisories.plan[0].severity === "critical",
  "a dependency step must carry the fix version and its worst severity");
check(rootCause(finding("low", { ruleId: "X", source: "semgrep" })) !== rootCause(finding("low", { ruleId: "X", source: "bandit" })),
  "the same rule id from two engines is two causes");
const sure = score([finding("medium")]);
const unsure = score([finding("medium", { confidence: "low" })]);
check(unsure.score > sure.score, "a low-confidence finding must weigh less than a high-confidence one");

// 7) Traced flows.
const legacyFlow = finding("high", { ruleId: "VS-FLOW", category: "SQL-инъекция", confidence: "medium" });
check(isReachable(legacyFlow), "a traced flow is reachable even when the report did not mark it");
check(score([legacyFlow]).limit?.reason.includes("достижима"), "a reachable high must use the reachable ceiling");
const twoFlows = score([
  finding("high", { ruleId: "VS-FLOW", category: "SQL-инъекция" }),
  finding("high", { ruleId: "VS-FLOW", category: "XSS" }),
]);
check(twoFlows.causes === 2, `flows into different sinks are different causes, got ${twoFlows.causes}`);

// 8) The fix plan tells the truth: fixing a step means the real report has
//    lost that cause's findings and everything on the same lines.
const spot = (f) => (f.package || f.line <= 0 ? null : `${f.file}|${f.line}|${f.category}`);
function replay(findings, plan) {
  let left = findings.filter((f) => !f.suppressed && !f.extra?.experimental);
  for (const step of plan) {
    const fixed = left.filter((f) => rootCause(f) === step.key);
    const spots = new Set(fixed.map(spot).filter(Boolean));
    const before = left.length;
    left = left.filter((f) => rootCause(f) !== step.key && !spots.has(spot(f)));
    const after = computeScore(report(left));
    if (after.score !== step.scoreAfter) return `${step.key}: promised ${step.scoreAfter}, real ${after.score}`;
    if (before - left.length !== step.count + step.alsoCloses)
      return `${step.key}: says it clears ${step.count}+${step.alsoCloses}, really ${before - left.length}`;
  }
  return null;
}
const mixed = [
  finding("critical", { ruleId: "SQL", ...reach }),
  ...many(6, "medium", { ruleId: "MD5" }),
  ...many(3, "high", { ruleId: "XSS" }),
  ...many(12, "low", { ruleId: "NIT" }),
  finding("info", { ruleId: "TODO" }),
];
const full = score(mixed);
check(full.plan.length === 5, `every cause of a small report must be in the plan, got ${full.plan.length}`);
check(full.plan[0].ruleId === "SQL", `the reachable critical must be fixed first, got ${full.plan[0]?.ruleId}`);
const lie = replay(mixed, full.plan);
check(lie === null, `plan replay: ${lie}`);
check(full.plan.at(-1).scoreAfter === 100 && full.plan.at(-1).gradeAfter === "A", "fixing every cause must reach 100");
check(full.plan.every((s, i) => Math.abs(s.scoreAfter - (i ? full.plan[i - 1].scoreAfter : full.score) - s.gain) < 0.11),
  "each step's gain must be the difference between consecutive scores");

// A traced path and the pattern rule on its sink are one line of code: one fix.
const sink = { file: "db.py", line: 40, category: "SQL-инъекция" };
const paired = [
  finding("critical", { ruleId: "VS-FLOW", confidence: "medium", ...sink }),
  finding("critical", { ruleId: "VS-PY-SQL", ...reach, ...sink }),
  finding("critical", { ruleId: "VS-PY-SQL", file: "db.py", line: 90, category: "SQL-инъекция" }),
  ...many(2, "medium", { ruleId: "MD5" }),
];
const pairedScore = score(paired);
check(pairedScore.plan[0].alsoCloses === 1, `fixing the sink line must also close its twin, got ${pairedScore.plan[0].alsoCloses}`);
const pairLie = replay(paired, pairedScore.plan);
check(pairLie === null, `paired plan replay: ${pairLie}`);

// Random reports: every plan replays exactly.
seed = 7;
for (let trial = 0; trial < 150; trial++) {
  const fs = Array.from({ length: 4 + rnd(30) }, () =>
    finding(SEVS[rnd(5)], {
      ruleId: rnd(4) === 0 ? "VS-FLOW" : "R" + rnd(5),
      confidence: CONFS[rnd(3)],
      extra: rnd(3) === 0 ? { onDataPath: true } : null,
      file: "f" + rnd(3),
      line: 1 + rnd(5),
      category: "C" + rnd(2),
    }),
  );
  const r = score(fs);
  const bad = replay(fs, r.plan);
  if (bad) {
    problems.push(`random plan ${trial}: ${bad}`);
    break;
  }
}
const big = score(Array.from({ length: 3000 }, (_, i) => finding(SEVS[i % 5], { ruleId: "R" + (i % 700) })));
check(big.plan.length === 8, "a big report's plan is capped at eight steps");

if (problems.length === 0) {
  console.log("Оценка защищённости: монотонна, честные пределы, повторы и уверенность учтены, план исправлений сходится.");
  process.exit(0);
}
console.log("Проблемы в оценке защищённости:");
for (const p of problems) console.log(`  ✗ ${p}`);
process.exit(1);
