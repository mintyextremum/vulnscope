import type { Finding, ScanReport, Severity, Staff1c } from "./types";
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

/** Language hint for a fenced block, from the file's extension. */
function fenceLang(file: string): string {
  const map: Record<string, string> = {
    rs: "rust", py: "python", js: "javascript", mjs: "javascript", cjs: "javascript",
    jsx: "jsx", ts: "typescript", tsx: "tsx", go: "go", java: "java", kt: "kotlin",
    php: "php", rb: "ruby", cs: "csharp", c: "c", h: "c", cpp: "cpp", swift: "swift",
    scala: "scala", pl: "perl", lua: "lua", ex: "elixir", exs: "elixir", sql: "sql",
    sh: "bash", bash: "bash", ps1: "powershell", yml: "yaml", yaml: "yaml",
    tf: "hcl", json: "json", vue: "vue", svelte: "svelte",
  };
  return map[file.split(".").pop()?.toLowerCase() ?? ""] ?? "";
}

/**
 * One finding as a self-contained Markdown block.
 *
 * Shared so the report and the per-finding copy cannot drift apart. The report
 * leaves the snippet out — it already links the line and would double in size —
 * while a single finding pasted into a ticket is far more useful with it.
 */
export function findingToMarkdown(f: Finding, t: TFn, includeSnippet = false): string {
  const out: string[] = [];
  out.push(`### ${SEV_MARK[f.severity]} ${t(SEVERITY_LABEL[f.severity])}: ${t(f.title)}`);
  const tags = [
    `\`${f.file}${f.line > 0 ? ":" + f.line : ""}\``,
    `${t("правило")} \`${f.ruleId}\``,
    ...f.cwe,
    ...(f.owasp ? [f.owasp] : []),
    ...f.cve,
  ];
  out.push(tags.join(" · "), "");
  out.push(t(f.description), "");
  if (f.extra?.flow && f.extra.flow.length > 0) {
    out.push(`**${t("Поток данных")}:**`);
    for (const s of f.extra.flow) {
      out.push(`- ${t(s.category)} — \`${s.file ?? f.file}:${s.line}\`: \`${s.code}\``);
    }
    out.push("");
  }
  if (f.extra?.exploit) {
    out.push(`**${t("Пример эксплуатации")}:** ${t(f.extra.exploit)}`, "");
  }
  if (f.extra && f.extra.impact.length > 0) {
    out.push(`**${t("Возможные последствия")}:**`);
    for (const c of f.extra.impact) out.push(`- ${t(c)}`);
    out.push("");
  }
  if (includeSnippet && f.snippet) {
    out.push("```" + fenceLang(f.file), f.snippet.replace(/\s+$/, ""), "```", "");
  }
  if (f.recommendation) out.push(`**${t("Как исправить")}:** ${t(f.recommendation)}`, "");
  if (f.extra?.fixCode) {
    out.push("```" + fenceLang(f.file), f.extra.fixCode, "```", "");
  }
  return out.join("\n");
}

/** Who is accountable for a finding: the git-blame author, mapped onto a 1C
 *  employee when a staff registry was imported, else the raw git author. */
function responsibleName(f: Finding, staff: Staff1c[]): string | null {
  const b = f.extra?.blame;
  if (!b) return null;
  const mail = (b.email ?? "").toLowerCase();
  const name = b.author.toLowerCase();
  const emp =
    (mail && staff.find((s) => s.emails.some((e) => e.toLowerCase() === mail))) ||
    staff.find((s) => s.name.toLowerCase() === name || s.aliases.some((a) => a.toLowerCase() === name));
  return emp ? emp.name : b.author;
}

/**
 * `note` is printed as a leading warning. The filtered export passes one: a
 * document holding a subset must say so, or it reads as the whole report.
 *
 * `staff` (from an imported 1C registry) maps git authors onto responsible
 * people for the accountability table; empty falls back to raw git names.
 */
export function toMarkdown(report: ScanReport, t: TFn, note?: string, staff: Staff1c[] = []): string {
  const out: string[] = [];
  const total = SEVERITY_ORDER.reduce((n, s) => n + report.counts[s], 0);

  out.push(`# ${t("Отчёт VulnScope")} — ${report.targetLabel}`, "");
  if (report.cancelled) {
    out.push(`> ⚠️ ${t("Сканирование отменено — результаты неполные.")}`, "");
  }
  if (note) {
    out.push(`> 🔎 ${note}`, "");
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

  // Accountability by responsible person, from git blame — only when the scan
  // ran on a git work tree (otherwise no finding carries an author).
  const confirmed = report.findings.filter((f) => !f.suppressed && !f.extra?.experimental);
  const byAuthor = new Map<string, { total: number; severe: number; isNew: number }>();
  for (const f of confirmed) {
    const who = responsibleName(f, staff);
    if (!who) continue;
    const r = byAuthor.get(who) ?? { total: 0, severe: 0, isNew: 0 };
    r.total += 1;
    if (f.severity === "critical" || f.severity === "high") r.severe += 1;
    if (f.isNew) r.isNew += 1;
    byAuthor.set(who, r);
  }
  if (byAuthor.size > 0) {
    out.push(`## ${t("По ответственным")}`, "");
    out.push(
      `| ${t("Ответственный")} | ${t("Находок")} | ${t("Критич. + высокие")} | ${t("Новых")} |`,
      "| --- | ---: | ---: | ---: |"
    );
    for (const [who, r] of [...byAuthor.entries()].sort((a, b) => b[1].total - a[1].total)) {
      out.push(`| ${cell(who)} | ${r.total} | ${r.severe || ""} | ${r.isNew || ""} |`);
    }
    out.push("");
  }

  // Findings grouped by severity, suppressed ones last and marked.
  const active = report.findings.filter((f) => !f.suppressed);
  const suppressed = report.findings.filter((f) => f.suppressed);

  out.push(`## ${t("Находки")}`, "");
  for (const sev of SEVERITY_ORDER) {
    const group = active.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    for (const f of group) out.push(findingToMarkdown(f, t));
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
