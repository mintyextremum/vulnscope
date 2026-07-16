import type { ScanReport, Finding } from "./types";
import { SEVERITY_LABEL } from "./types";
import type { TFn } from "./i18n";

/**
 * CSV export.
 *
 * The other formats are a document (Markdown) or a machine feed (JSON/SARIF);
 * this one is a table. It opens in any spreadsheet, so a team can sort by
 * severity, filter by file, tick off a triage column, or pivot findings by
 * rule — the things a flat report cannot do. One row per finding, one column
 * per field a reviewer actually sorts on.
 *
 * Text goes through `t`, so the header row and the human-readable columns match
 * the language on screen; ids, paths and codes stay verbatim.
 */

/**
 * Wraps a value per RFC 4180: always quote, double the inner quotes. Quoting
 * unconditionally keeps a stray comma, newline, or leading `=`/`+` (a
 * spreadsheet-formula injection vector) from ever breaking or executing in a
 * cell, and a leading apostrophe neutralises the formula triggers.
 */
function cell(value: string | number): string {
  let s = String(value);
  if (/^[=+\-@]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

export function toCsv(report: ScanReport, t: TFn): string {
  const headers = [
    t("Уровень"),
    t("правило"),
    t("Находка"),
    t("Файл"),
    t("Строка"),
    "CWE",
    "OWASP",
    "CVE",
    t("Категория"),
    t("Источник"),
    t("Подавлено"),
    t("Причина"),
  ];

  const row = (f: Finding): string =>
    [
      t(SEVERITY_LABEL[f.severity]),
      f.ruleId,
      t(f.title),
      f.file,
      f.line > 0 ? f.line : "",
      f.cwe.join(" "),
      f.owasp ?? "",
      f.cve.join(" "),
      t(f.category),
      t(f.sourceLabel),
      f.suppressed ? t("Да") : t("Нет"),
      f.suppressed ? f.suppressionReason ?? "" : "",
    ]
      .map(cell)
      .join(",");

  // Prefix the BOM so Excel reads UTF-8 (Cyrillic) instead of the local
  // codepage; CRLF line endings are what RFC 4180 and spreadsheets expect.
  return "﻿" + [headers.map(cell).join(","), ...report.findings.map(row)].join("\r\n") + "\r\n";
}
