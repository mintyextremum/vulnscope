import type { ScanReport, Severity } from "./types";
import { SEVERITY_ORDER, SEVERITY_LABEL } from "./types";
import type { TFn } from "./i18n";

/**
 * Markdown export.
 *
 * JSON and SARIF are for machines; this is for people — a report you can paste
 * straight into a pull request, an issue, or a chat message. It is grouped by
 * severity, links each finding to `file:line`, and keeps the fix inline, so the
 * reader sees what is wrong and what to do without opening the app.
 *
 * Text goes through `t`, so the document matches the language on screen.
 */

const SEV_MARK: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

/** Escapes the pipe so a value never breaks a Markdown table row. */
function cell(s: string): string {
  return s.replace(/\|/g, "\\|");
}

export function toMarkdown(report: ScanReport, t: TFn): string {
  const out: string[] = [];
  const total = SEVERITY_ORDER.reduce((n, s) => n + report.counts[s], 0);

  out.push(`# ${t("Отчёт VulnScope")} — ${report.targetLabel}`, "");
  if (report.cancelled) {
    out.push(`> ⚠️ ${t("Сканирование отменено — результаты неполные.")}`, "");
  }
  out.push(
    t("Найдено: {total} · файлов: {files} · строк: {lines}", {
      total,
      files: report.filesScanned,
      lines: report.linesScanned,
    }),
    ""
  );

  // Severity summary table — only rows that have findings.
  out.push(`## ${t("Сводка")}`, "");
  out.push(`| ${t("Уровень")} | ${t("Количество")} |`, "| --- | ---: |");
  for (const s of SEVERITY_ORDER) {
    if (report.counts[s] > 0) out.push(`| ${SEV_MARK[s]} ${t(SEVERITY_LABEL[s])} | ${report.counts[s]} |`);
  }
  out.push("");

  // Findings grouped by severity, suppressed ones last and marked.
  const active = report.findings.filter((f) => !f.suppressed);
  const suppressed = report.findings.filter((f) => f.suppressed);

  out.push(`## ${t("Находки")}`, "");
  for (const sev of SEVERITY_ORDER) {
    const group = active.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    for (const f of group) {
      out.push(`### ${SEV_MARK[sev]} ${t(SEVERITY_LABEL[sev])}: ${t(f.title)}`);
      const tags = [
        `\`${f.file}:${f.line}\``,
        `${t("правило")} \`${f.ruleId}\``,
        ...f.cwe,
        ...(f.owasp ? [f.owasp] : []),
        ...f.cve,
      ];
      out.push(tags.join(" · "), "");
      out.push(t(f.description), "");
      if (f.recommendation) out.push(`**${t("Как исправить")}:** ${t(f.recommendation)}`, "");
    }
  }

  if (suppressed.length > 0) {
    out.push(`## ${t("Подавленные")} (${suppressed.length})`, "");
    out.push(`| ${t("Находка")} | ${t("Файл")} | ${t("Причина")} |`, "| --- | --- | --- |");
    for (const f of suppressed) {
      out.push(`| ${cell(t(f.title))} | \`${f.file}:${f.line}\` | ${cell(f.suppressionReason ?? "")} |`);
    }
    out.push("");
  }

  out.push("---", `*${t("Сгенерировано VulnScope")}*`, "");
  return out.join("\n");
}
