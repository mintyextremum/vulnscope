import type { ScanReport, Finding, Severity, Staff1c } from "./types";
import type { TFn } from "./i18n";
import type { SecurityScore } from "./score";
import { resolveResponsible, responsibleBreakdown } from "./responsible.ts";

/** Severity labels, inlined (not imported from `./types`) so this module pulls
 *  in no runtime *value* from the app: the 1C export audit loads it under Node's
 *  type stripping without a bundler. Its only runtime import is `./responsible`,
 *  which is itself value-free (type imports only) and so loads the same way. */
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
  info: "Информация",
};

/**
 * 1C:Enterprise data-exchange export.
 *
 * 1C does not read our JSON or SARIF, but it reads XML with `ЧтениеXML` /
 * XDTO out of the box. This emits a flat, self-describing document with Russian
 * element names, so a small 1C processing (обработка) maps it straight into a
 * register or a document — a "security audit" record per finding — for
 * corporate reporting alongside everything else in 1C.
 *
 * The schema is deliberately generic and open: it owns no assumptions about a
 * particular 1C configuration. A config wires its own reading routine to these
 * element names; nothing here needs to change per deployment.
 */

/** Escapes the five XML metacharacters so any value is safe inside a tag. */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** One `<Тег>value</Тег>` line, escaped, at the given indent. */
function el(tag: string, value: string | number, indent: string): string {
  return `${indent}<${tag}>${esc(String(value))}</${tag}>`;
}

/** The status word 1C reporting cares about: new, suppressed, or present. */
function status(f: Finding, t: TFn): string {
  if (f.suppressed) return t("Подавлена");
  if (f.isNew) return t("Новая");
  return t("Присутствует");
}

export function toXml1C(
  report: ScanReport,
  t: TFn,
  score: SecurityScore | null,
  staff: Staff1c[] = []
): string {
  const out: string[] = [];
  out.push(`<?xml version="1.0" encoding="UTF-8"?>`);
  out.push(`<ОтчётБезопасности ВерсияСхемы="1.0" Источник="VulnScope">`);
  out.push(el("Проект", report.targetLabel, "  "));
  out.push(el("Дата", report.finishedAt || report.startedAt, "  "));
  out.push(el("ФайловПроверено", report.filesScanned, "  "));
  out.push(el("СтрокКода", report.linesScanned, "  "));
  if (score) {
    out.push(el("ОценкаЗащищённости", score.score, "  "));
    out.push(el("Класс", score.grade, "  "));
  }
  out.push(el("ВсегоНаходок", report.findings.filter((f) => !f.extra?.experimental).length, "  "));

  // Severity tallies, so a 1C report can chart them without re-counting.
  out.push("  <ПоВажности>");
  (Object.keys(report.counts) as Severity[]).forEach((s) => {
    out.push(`    <Уровень Название="${esc(t(SEVERITY_LABEL[s]))}">${report.counts[s]}</Уровень>`);
  });
  out.push("  </ПоВажности>");

  // Change since the previous scan — the "dynamics" a report needs.
  out.push("  <Динамика>");
  out.push(el("Новых", report.delta.newCount, "    "));
  out.push(el("Исправлено", report.delta.fixedCount, "    "));
  out.push(el("БезИзменений", report.delta.unchangedCount, "    "));
  out.push("  </Динамика>");

  // Accountability breakdown, so 1C can post per-employee KPIs without parsing
  // every finding. Built from git-blame attribution, mapped through the staff
  // registry when one was imported. Omitted entirely outside a git work tree
  // (no blame → no responsible), rather than emitting an empty section.
  const rows = responsibleBreakdown(report.findings, staff);
  if (rows.length > 0) {
    out.push("  <ПоОтветственным>");
    for (const r of rows) {
      out.push(
        `    <Ответственный ФИО="${esc(r.name)}"${r.role ? ` Должность="${esc(t(r.role))}"` : ""}>`
      );
      out.push(el("Находок", r.total, "      "));
      out.push(el("КритическихВысоких", r.severe, "      "));
      out.push(el("Новых", r.isNew, "      "));
      out.push("    </Ответственный>");
    }
    out.push("  </ПоОтветственным>");
  }

  out.push("  <Находки>");
  for (const f of report.findings) {
    if (f.extra?.experimental) continue; // BETA are suspicions, not audit records
    out.push("    <Находка>");
    out.push(el("Важность", t(SEVERITY_LABEL[f.severity]), "      "));
    out.push(el("Категория", t(f.category), "      "));
    out.push(el("Заголовок", t(f.title), "      "));
    out.push(el("Файл", f.file, "      "));
    out.push(el("Строка", f.line, "      "));
    out.push(el("Правило", f.ruleId, "      "));
    if (f.cwe.length > 0) out.push(el("CWE", f.cwe.join(", "), "      "));
    if (f.owasp) out.push(el("OWASP", f.owasp, "      "));
    out.push(el("Статус", status(f, t), "      "));
    out.push(el("Достижима", f.extra?.onDataPath ? t("Да") : t("Нет"), "      "));
    // Who last touched this line — the accountable person, when known.
    const resp = resolveResponsible(f, staff);
    if (resp) out.push(el("Ответственный", resp.name, "      "));
    out.push(el("Отпечаток", f.fingerprint, "      "));
    out.push("    </Находка>");
  }
  out.push("  </Находки>");
  out.push("</ОтчётБезопасности>");
  return out.join("\n");
}
