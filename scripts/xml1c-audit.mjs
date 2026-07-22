/**
 * 1C export shape audit.
 *
 * 1C loads this XML with `ЧтениеXML`/XDTO; malformed XML or an unescaped value
 * fails the import silently, on someone else's machine. Nothing else exercises
 * it — `tsc` proves the types, not that the document is well-formed.
 *
 * Pins what a 1C reading routine relies on:
 *   1. An XML prolog and a single balanced root element.
 *   2. Every XML metacharacter in a value is escaped — a finding title with
 *      `<`, `&`, `"` must not break the document.
 *   3. BETA (suspected) findings are excluded — audit records are confirmed only.
 *   4. The dynamics block and the per-severity tallies are present.
 *
 * Usage: npm run audit:xml1c
 */
import { toXml1C } from "../src/xml1c.ts";

const t = (s) => s; // identity: checking structure, not wording

let n = 0;
function finding(over = {}) {
  return {
    id: "f" + n++, fingerprint: "fp" + n, suppressed: false, suppressionReason: null,
    isNew: false, ruleId: "VS-X", title: "T", description: "D", recommendation: "R",
    severity: "high", confidence: "high", source: "builtin", sourceLabel: "L", category: "C",
    file: "a.py", line: 1, endLine: 1, column: 1, endColumn: 1, snippet: "s", snippetStartLine: 1,
    cwe: ["CWE-89"], owasp: null, cve: [], extra: null, package: null, ...over,
  };
}

const report = {
  id: "1", root: "", targetLabel: "proj & <co>", startedAt: "2026-07-01T00:00:00", finishedAt: "2026-07-01T01:00:00", durationMs: 1,
  cancelled: false,
  delta: { previousScanAt: "x", newCount: 2, fixedCount: 1, unchangedCount: 3, fixed: [], newBySeverity: {} },
  suppressedCount: 1,
  findings: [
    finding({ title: "XSS via <script> & \"quotes\"", severity: "critical", extra: { onDataPath: true } }),
    finding({ isNew: true }),
    finding({ suppressed: true }),
    finding({ extra: { experimental: true } }), // must be excluded
  ],
  files: [], skipped: [],
  counts: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
  filesScanned: 5, filesSkipped: 0, linesScanned: 100, bytesScanned: 1,
  languages: [], dependenciesChecked: 0, enginesUsed: [], warnings: [],
};
const score = { score: 42.5, grade: "D", label: "x", reachable: 1, total: 3, factors: [] };

const xml = toXml1C(report, t, score);
const problems = [];
const check = (cond, msg) => { if (!cond) problems.push(msg); };

// 1) Prolog + a single balanced root.
check(xml.startsWith("<?xml"), "no XML prolog");
check(/<ОтчётБезопасности[ >]/.test(xml) && xml.trimEnd().endsWith("</ОтчётБезопасности>"), "root element not balanced");

// 2) Escaping: the injected metacharacters must be entities, and no raw < or &
//    may survive inside a text value.
check(xml.includes("&lt;script&gt; &amp; &quot;quotes&quot;"), "finding title was not escaped");
check(xml.includes("proj &amp; &lt;co&gt;"), "project name was not escaped");
// Every & must open a known entity — the strongest cheap well-formedness signal.
check(!/&(?!(amp|lt|gt|quot|apos);)/.test(xml), "an unescaped '&' survived");

// 3) BETA excluded, confirmed counted.
const findingCount = (xml.match(/<Находка>/g) || []).length;
check(findingCount === 3, `expected 3 audit records (BETA excluded), got ${findingCount}`);
check(xml.includes("<ВсегоНаходок>3</ВсегоНаходок>"), "confirmed total wrong");

// 4) Dynamics + tallies + score.
check(/<Динамика>[\s\S]*<Новых>2<\/Новых>[\s\S]*<\/Динамика>/.test(xml), "dynamics block missing/incomplete");
check(xml.includes("<ПоВажности>") && xml.includes("<Уровень"), "per-severity tallies missing");
check(xml.includes("<ОценкаЗащищённости>42.5</ОценкаЗащищённости>") && xml.includes("<Класс>D</Класс>"), "score not carried");
check(xml.includes("<Достижима>Да</Достижима>"), "reachability flag missing on the reachable finding");

if (problems.length === 0) {
  console.log("Выгрузка 1С: XML корректен, значения экранированы, BETA исключены, динамика на месте.");
  process.exit(0);
}
console.log("Проблемы в выгрузке 1С:");
for (const p of problems) console.log(`  ✗ ${p}`);
process.exit(1);
