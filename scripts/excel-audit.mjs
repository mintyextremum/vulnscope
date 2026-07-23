/**
 * Excel (SpreadsheetML) export shape audit.
 *
 * Excel and LibreOffice silently refuse to open a malformed SpreadsheetML file,
 * or drop cells with an unescaped metacharacter — on someone else's machine.
 * `tsc` proves the types, not that the workbook is well-formed. This pins what a
 * spreadsheet reader relies on:
 *   1. The XML prolog, the mso-application processing instruction, and a single
 *      balanced <Workbook> root.
 *   2. The expected worksheets exist (Summary, Findings, and — with blame — the
 *      per-responsible sheet), each ≤ 31 chars.
 *   3. Every XML metacharacter in a value is escaped.
 *   4. BETA (suspected) findings are excluded; confirmed ones are rows.
 *   5. The per-responsible sheet maps the staff registry (name + role) and the
 *      per-finding responsible column is populated.
 *
 * Usage: npm run audit:excel
 */
import { toExcel } from "../src/excel.ts";

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
    finding({
      title: "XSS via <script> & \"quotes\"", severity: "critical",
      extra: { onDataPath: true, blame: { author: "m.ivanova", email: "maria@example.com", commit: "abc12345", date: "2026-06-01" } },
    }),
    finding({ isNew: true, extra: { blame: { author: "unknown.dev", email: "u@x.com", commit: "def67890", date: "2026-06-02" } } }),
    finding({ suppressed: true }),
    finding({ extra: { experimental: true } }), // must be excluded
  ],
  files: [], skipped: [],
  counts: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
  filesScanned: 5, filesSkipped: 0, linesScanned: 100, bytesScanned: 1,
  languages: [], dependenciesChecked: 0, enginesUsed: [], warnings: [],
};
const score = { score: 42.5, grade: "D", label: "x", reachable: 1, total: 3, factors: [] };
const staff = [
  { name: "Иванова Мария Петровна", role: "Разработчик", emails: ["maria@example.com"], aliases: ["m.ivanova"] },
];

const xml = toExcel(report, t, score, staff);
const problems = [];
const check = (cond, msg) => { if (!cond) problems.push(msg); };

// 1) Prolog, processing instruction, balanced root.
check(xml.startsWith("<?xml"), "no XML prolog");
check(xml.includes('<?mso-application progid="Excel.Sheet"?>'), "missing mso-application PI (Excel won't recognise it)");
check(/<Workbook[ >]/.test(xml) && xml.trimEnd().endsWith("</Workbook>"), "Workbook root not balanced");

// 2) Worksheets present, names within Excel's 31-char limit.
const names = [...xml.matchAll(/<Worksheet ss:Name="([^"]*)"/g)].map((m) => m[1]);
check(names.length === 3, `expected 3 worksheets (summary, findings, responsibles), got ${names.length}`);
check(names.every((nm) => nm.length <= 31), `a worksheet name exceeds 31 chars: ${names}`);

// 3) Escaping: injected metacharacters must be entities; no unescaped & survives.
check(xml.includes("XSS via &lt;script&gt; &amp; &quot;quotes&quot;"), "finding title was not escaped");
check(!/&(?!(amp|lt|gt|quot|apos);)/.test(xml), "an unescaped '&' survived");

// 4) BETA excluded: the findings sheet has a header row + 3 confirmed rows.
//    Count Data cells typed String in the ruleId column is fiddly; instead count
//    rows carrying the VS-X rule id (one per confirmed finding).
const ruleCells = (xml.match(/>VS-X</g) || []).length;
check(ruleCells === 3, `expected 3 confirmed finding rows (BETA excluded), got ${ruleCells}`);

// 5) Accountability: staff mapping (name + role) and per-finding responsible.
check(xml.includes("Иванова Мария Петровна"), "mapped employee name missing");
check(xml.includes("Разработчик"), "employee role missing");
check(xml.includes("unknown.dev"), "unmapped git author should still appear under its own name");

// Number cells must be typed as numbers so Excel sums/sorts them.
check(/<Data ss:Type="Number">100<\/Data>/.test(xml), "linesScanned should be a numeric cell");

if (problems.length === 0) {
  console.log("Выгрузка Excel: SpreadsheetML корректен, листы на месте, значения экранированы, BETA исключены, разбивка по ответственным есть.");
  process.exit(0);
}
console.log("Проблемы в выгрузке Excel:");
for (const p of problems) console.log(`  ✗ ${p}`);
process.exit(1);
