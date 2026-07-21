/**
 * SARIF export shape audit.
 *
 * SARIF is the one export nobody reads: it goes straight into GitHub code
 * scanning or a CI dashboard, which either accepts it silently or rejects the
 * upload with a schema error nobody sees until a release. Nothing else in the
 * pipeline exercises it — `tsc` proves the code compiles, not that the document
 * says what a consumer expects.
 *
 * The parts worth pinning are the ones carrying the flagship engine's evidence:
 *
 *  1. `codeFlows` — the traced source → … → sink path, which GitHub renders as a
 *     clickable chain. `executionOrder` must be 1-based and increasing or the
 *     steps display out of order.
 *  2. `relatedLocations` — the places a dangerous combination links. These must
 *     NOT become a codeFlow: a combination is a set of co-occurring issues, and
 *     claiming an execution order it never established would be a lie in a
 *     machine-readable document.
 *  3. The invariants a consumer relies on regardless: forward-slash URIs, a rule
 *     descriptor per rule that fired, suppressions preserved.
 *
 * The report is synthetic on purpose — a real scan would make the expected
 * numbers drift with the rule catalogue.
 *
 * Usage: npm run audit:sarif
 */
import { toSarif } from "../src/sarif.ts";

/** Identity translation: this checks the document's shape, not its wording. */
const t = (s) => s;

function finding(over) {
  return {
    id: "x",
    fingerprint: "fp",
    suppressed: false,
    suppressionReason: null,
    isNew: false,
    ruleId: "VS-X-001",
    title: "T",
    description: "D",
    recommendation: "R",
    severity: "high",
    confidence: "high",
    source: "builtin",
    sourceLabel: "L",
    category: "C",
    // Backslashes on purpose: Windows paths must come out as SARIF URIs.
    file: "backend\\app.py",
    line: 20,
    endLine: 20,
    column: 1,
    endColumn: 9,
    snippet: "s",
    snippetStartLine: 18,
    cwe: ["CWE-89"],
    owasp: null,
    cve: [],
    references: [],
    extra: null,
    package: null,
    ...over,
  };
}

const EXTRA = { exploit: null, impact: [], fixCode: null, corroborated: false };

const withFlow = finding({
  ruleId: "VS-FLOW",
  extra: {
    ...EXTRA,
    flow: [
      { category: "Источник (пользовательский ввод)", line: 17, code: "cmd = request.args.get('c')" },
      { category: "Передача через переменную", line: 18, code: "full = cmd + ' -v'" },
      { category: "Приёмник (опасный вызов)", line: 20, code: "os.system(full)" },
    ],
  },
});

const withCombo = finding({
  ruleId: "VS-EXP-COMBO-1",
  extra: {
    ...EXTRA,
    combination: true,
    experimental: true,
    combineSpots: [
      { category: "Инъекция команд", line: 20, code: "os.system(full)" },
      { category: "Путь из ввода", line: 31, code: "open(p)" },
    ],
  },
});

const plain = finding({ ruleId: "VS-PY-001" });
const hushed = finding({ ruleId: "VS-PY-002", suppressed: true, suppressionReason: "проверено" });

const report = {
  id: "1",
  root: "D:/x",
  targetLabel: "x",
  startedAt: "",
  finishedAt: "",
  durationMs: 1,
  cancelled: false,
  delta: { previousScanAt: null, newCount: 0, fixedCount: 0, unchangedCount: 0, fixed: [], newBySeverity: {} },
  suppressedCount: 1,
  findings: [withFlow, withCombo, plain, hushed],
  files: [],
  skipped: [],
  counts: { critical: 0, high: 4, medium: 0, low: 0, info: 0 },
  filesScanned: 1,
  filesSkipped: 0,
  linesScanned: 1,
  bytesScanned: 1,
  languages: [],
  dependenciesChecked: 0,
  enginesUsed: [],
  warnings: [],
};

const out = toSarif(report, t);
const [rFlow, rCombo, rPlain, rHushed] = out.runs[0].results;

const problems = [];
const check = (cond, msg) => {
  if (!cond) problems.push(msg);
};

// --- the traced path -------------------------------------------------------
const flows = rFlow.codeFlows;
check(Array.isArray(flows) && flows.length === 1, "у находки с потоком данных нет codeFlows");
const steps = flows?.[0]?.threadFlows?.[0]?.locations ?? [];
check(steps.length === 3, `ожидалось 3 шага в threadFlow, получено ${steps.length}`);
check(
  steps.every((s, i) => s.executionOrder === i + 1),
  "executionOrder должен идти 1..n по порядку, иначе шаги покажутся вперемешку"
);
check(steps.every((s) => s.nestingLevel === 0), "nestingLevel должен быть 0: анализ внутрипроцедурный");
check(steps[0]?.location.physicalLocation.region.startLine === 17, "первый шаг указывает не на ту строку");
check(steps[2]?.location.physicalLocation.region.startLine === 20, "последний шаг указывает не на ту строку");
check(
  steps[0]?.location.physicalLocation.region.snippet.text.includes("request.args"),
  "в шаге потерян фрагмент кода"
);
check(steps[0]?.location.message.text.includes("Источник"), "в шаге потеряна подпись роли");
check(
  steps[0]?.location.physicalLocation.artifactLocation.uri === "backend/app.py",
  "путь не приведён к URI с прямыми слэшами"
);

// --- the linked places -----------------------------------------------------
check(rCombo.codeFlows === undefined, "связка не должна выдавать себя за путь исполнения");
const related = rCombo.relatedLocations;
check(Array.isArray(related) && related.length === 2, "у связки нет relatedLocations");
check(related?.[0].id === 1 && related?.[1].id === 2, "id в relatedLocations должны идти 1..n");
check(related?.[0].message.text === "Инъекция команд", "в relatedLocations потеряна категория");

// --- everything else stays as it was ---------------------------------------
check(
  rPlain.codeFlows === undefined && rPlain.relatedLocations === undefined,
  "обычная находка не должна получать ни путь, ни связанные места"
);
check(rHushed.suppressions?.[0]?.justification === "проверено", "потеряна причина подавления");
check(out.version === "2.1.0", "версия SARIF должна быть 2.1.0");
check(out.runs[0].tool.driver.rules.length === 4, "на каждое сработавшее правило нужен свой descriptor");

try {
  JSON.parse(JSON.stringify(out));
} catch {
  problems.push("документ не сериализуется в JSON");
}

if (problems.length === 0) {
  console.log("SARIF: путь потока данных и связанные места на месте, документ пригоден для выгрузки.");
  process.exit(0);
}
console.log("Проблемы в SARIF-экспорте:");
for (const p of problems) console.log(`  ✗ ${p}`);
process.exit(1);
