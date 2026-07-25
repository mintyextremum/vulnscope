import type { ScanReport, Finding, Severity, Staff1c } from "./types";
import type { TFn } from "./i18n";
import type { SecurityScore } from "./score";
import { resolveResponsible, responsibleBreakdown } from "./responsible.ts";
import { formatStamp } from "./datetime.ts";

/**
 * Excel export — a real multi-sheet workbook, not CSV.
 *
 * CSV is one flat table; an efficiency report wants the score and dynamics up
 * front, the findings to sort and filter, and the per-employee accountability on
 * its own tab. This emits SpreadsheetML 2003: a single self-describing XML file
 * that Excel (and LibreOffice) opens as a formatted, multi-sheet workbook — no
 * ZIP container and no third-party library, which keeps the desktop build lean
 * and the output auditable.
 *
 * Like `xml1c.ts` and `score.ts`, this module pulls in no runtime *value* from
 * the app (labels are inlined, score/staff arrive as parameters), so the export
 * audit loads it under Node's type stripping without a bundler. Its one runtime
 * import, `./responsible`, is itself value-free and loads the same way.
 */

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
  info: "Информация",
};

/** Escapes the five XML metacharacters so any value is safe inside a cell. */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** A String or Number cell, optionally styled. SpreadsheetML String cells are
 *  literal text, never formulas, so no spreadsheet-injection escaping is needed. */
function cell(value: string | number, style?: string): string {
  const styleAttr = style ? ` ss:StyleID="${style}"` : "";
  if (typeof value === "number" && Number.isFinite(value)) {
    return `<Cell${styleAttr}><Data ss:Type="Number">${value}</Data></Cell>`;
  }
  return `<Cell${styleAttr}><Data ss:Type="String">${esc(String(value))}</Data></Cell>`;
}

/** A table row from a list of pre-rendered cells. */
function row(cells: string[]): string {
  return `    <Row>${cells.join("")}</Row>`;
}

/** A worksheet with a frozen header row and auto-sized-ish columns. */
function sheet(name: string, rows: string[], cols: number): string {
  // SpreadsheetML caps sheet names at 31 chars and forbids : \ / ? * [ ].
  const safeName = esc(name.replace(/[:\\/?*[\]]/g, " ").slice(0, 31));
  const colDefs = Array.from({ length: cols }, () => `    <Column ss:Width="130"/>`).join("\n");
  return `  <Worksheet ss:Name="${safeName}">
   <Table>
${colDefs}
${rows.join("\n")}
   </Table>
   <WorksheetOptions xmlns="urn:schemas-microsoft-com:office:excel">
    <FreezePanes/>
    <FrozenNoSplit/>
    <SplitHorizontal>1</SplitHorizontal>
    <TopRowBottomPane>1</TopRowBottomPane>
    <ActivePane>2</ActivePane>
   </WorksheetOptions>
  </Worksheet>`;
}

export function toExcel(
  report: ScanReport,
  t: TFn,
  score: SecurityScore | null,
  staff: Staff1c[] = []
): string {
  const confirmed = report.findings.filter((f) => !f.extra?.experimental);
  const th = (label: string) => cell(label, "hdr");

  // ---- Sheet 1: Summary --------------------------------------------------
  const summary: string[] = [];
  const kv = (k: string, v: string | number) => row([cell(k, "key"), cell(v)]);
  summary.push(row([th(t("Показатель")), th(t("Значение"))]));
  summary.push(kv(t("Проект"), report.targetLabel));
  summary.push(kv(t("Дата"), formatStamp(report.finishedAt || report.startedAt)));
  if (score) {
    summary.push(kv(t("Оценка защищённости"), Math.round(score.score)));
    summary.push(kv(t("Класс"), score.grade));
  }
  summary.push(kv(t("Всего находок"), confirmed.filter((f) => !f.suppressed).length));
  summary.push(kv(t("Файлов проверено"), report.filesScanned));
  summary.push(kv(t("Строк кода"), report.linesScanned));
  summary.push(row([])); // spacer
  summary.push(row([th(t("Уровень")), th(t("Количество"))]));
  for (const s of SEVERITY_ORDER) {
    summary.push(row([cell(t(SEVERITY_LABEL[s])), cell(report.counts[s])]));
  }
  summary.push(row([]));
  summary.push(row([th(t("Динамика с прошлого скана")), th("")]));
  summary.push(kv(t("Новых"), report.delta.newCount));
  summary.push(kv(t("Исправлено"), report.delta.fixedCount));
  summary.push(kv(t("Без изменений"), report.delta.unchangedCount));

  // ---- Sheet 2: Findings -------------------------------------------------
  const findings: string[] = [];
  findings.push(
    row(
      [
        t("Уровень"),
        t("Правило"),
        t("Находка"),
        t("Файл"),
        t("Строка"),
        "CWE",
        "OWASP",
        "CVE",
        t("Категория"),
        t("Достижима"),
        t("Статус"),
        t("Ответственный"),
      ].map(th)
    )
  );
  const statusOf = (f: Finding) =>
    f.suppressed ? t("Подавлена") : f.isNew ? t("Новая") : t("Присутствует");
  for (const f of confirmed) {
    const resp = resolveResponsible(f, staff);
    findings.push(
      row([
        cell(t(SEVERITY_LABEL[f.severity]), `sev-${f.severity}`),
        cell(f.ruleId),
        cell(t(f.title)),
        cell(f.file),
        cell(f.line > 0 ? f.line : ""),
        cell(f.cwe.join(" ")),
        cell(f.owasp ?? ""),
        cell(f.cve.join(" ")),
        cell(t(f.category)),
        cell(f.extra?.onDataPath ? t("Да") : t("Нет")),
        cell(statusOf(f)),
        cell(resp?.name ?? ""),
      ])
    );
  }

  // ---- Sheet 3: By responsible (only with git-blame attribution) ---------
  const rows = responsibleBreakdown(report.findings, staff);

  const worksheets = [
    sheet(t("Сводка"), summary, 2),
    sheet(t("Находки"), findings, 12),
  ];
  if (rows.length > 0) {
    const respSheet: string[] = [
      row([t("Ответственный"), t("Должность"), t("Находок"), t("Критич. + высокие"), t("Новых")].map(th)),
      ...rows.map((r) =>
        row([cell(r.name), cell(r.role ? t(r.role) : ""), cell(r.total), cell(r.severe), cell(r.isNew)])
      ),
    ];
    worksheets.push(sheet(t("По ответственным"), respSheet, 5));
  }

  return `<?xml version="1.0"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:x="urn:schemas-microsoft-com:office:excel"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
 <Styles>
  <Style ss:ID="hdr">
   <Font ss:Bold="1" ss:Color="#FFFFFF"/>
   <Interior ss:Color="#334155" ss:Pattern="Solid"/>
   <Alignment ss:Vertical="Center"/>
  </Style>
  <Style ss:ID="key"><Font ss:Bold="1"/></Style>
  <Style ss:ID="sev-critical"><Font ss:Bold="1" ss:Color="#B91C1C"/></Style>
  <Style ss:ID="sev-high"><Font ss:Color="#C2410C"/></Style>
  <Style ss:ID="sev-medium"><Font ss:Color="#A16207"/></Style>
  <Style ss:ID="sev-low"><Font ss:Color="#0369A1"/></Style>
  <Style ss:ID="sev-info"><Font ss:Color="#475569"/></Style>
 </Styles>
${worksheets.join("\n")}
</Workbook>`;
}
