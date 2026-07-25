import type { ScanReport, Severity, Finding, Staff1c } from "./types";
import { SEVERITY_ORDER, SEVERITY_LABEL } from "./types";
import type { TFn } from "./i18n";
import { responsibleBreakdown } from "./responsible.ts";
import { formatStamp } from "./datetime.ts";

/**
 * Self-contained HTML export.
 *
 * JSON/SARIF feed a machine, Markdown pastes into a thread, CSV opens in a
 * spreadsheet — this is the one you open in a browser and read, or print to
 * PDF and attach. Everything is inline: one file, no network, no assets, so it
 * survives being emailed or dropped in a shared drive. The report data already
 * has secrets masked, so nothing here re-exposes them.
 *
 * Every interpolated value is HTML-escaped. A finding's title, description, or
 * file path can contain `<`, `>`, `&` (this is a scanner — it quotes suspect
 * code back at you), and unescaped that would break the page or inject markup.
 */

const SEV_COLOR: Record<Severity, string> = {
  critical: "#e5484d",
  high: "#f76808",
  medium: "#f5d90a",
  low: "#3e63dd",
  info: "#8b8d98",
};

/** Escapes the five characters that are unsafe in HTML text and attributes. */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * `note` is shown as a warning in the header. The filtered export passes one: a
 * document holding a subset must say so, or it reads as the whole report.
 *
 * `staff` (from an imported 1C registry) maps git authors onto responsible
 * people for the accountability table; empty falls back to raw git names.
 */
export function toHtml(report: ScanReport, t: TFn, note?: string, staff: Staff1c[] = []): string {
  const total = SEVERITY_ORDER.reduce((n, s) => n + report.counts[s], 0);
  const active = report.findings.filter((f) => !f.suppressed);
  const suppressed = report.findings.filter((f) => f.suppressed);

  const chip = (sev: Severity, n: number): string =>
    `<span class="chip" style="--c:${SEV_COLOR[sev]}"><b>${n}</b> ${esc(t(SEVERITY_LABEL[sev]))}</span>`;

  const findingCard = (f: Finding): string => {
    const tags = [
      `<code>${esc(f.file)}${f.line > 0 ? ":" + f.line : ""}</code>`,
      `${esc(t("правило"))} <code>${esc(f.ruleId)}</code>`,
      ...f.cwe.map((c) => `<span class="tag">${esc(c)}</span>`),
      ...(f.owasp ? [`<span class="tag">${esc(f.owasp)}</span>`] : []),
      ...f.cve.map((c) => `<span class="tag">${esc(c)}</span>`),
      `<span class="tag">${esc(t(f.sourceLabel))}</span>`,
    ].join(" ");
    const rec = f.recommendation
      ? `<p class="rec"><b>${esc(t("Как исправить"))}:</b> ${esc(t(f.recommendation))}</p>`
      : "";
    const sup = f.suppressed
      ? `<p class="sup">${esc(t("Подавлено"))}: ${esc(f.suppressionReason ?? "")}</p>`
      : "";
    return `<article class="card" style="--c:${SEV_COLOR[f.severity]}">
        <h3>${esc(t(f.title))}</h3>
        <p class="meta">${tags}</p>
        <p>${esc(t(f.description))}</p>
        ${rec}${sup}
      </article>`;
  };

  const sections = SEVERITY_ORDER.map((sev) => {
    const group = active.filter((f) => f.severity === sev);
    if (group.length === 0) return "";
    return `<section>
        <h2 style="--c:${SEV_COLOR[sev]}">${esc(t(SEVERITY_LABEL[sev]))} <span class="n">${group.length}</span></h2>
        ${group.map(findingCard).join("\n")}
      </section>`;
  }).join("\n");

  const suppressedSection =
    suppressed.length > 0
      ? `<section class="suppressed">
        <h2>${esc(t("Подавленные"))} <span class="n">${suppressed.length}</span></h2>
        ${suppressed.map(findingCard).join("\n")}
      </section>`
      : "";

  const cancelled = report.cancelled
    ? `<p class="warn">⚠️ ${esc(t("Сканирование отменено — результаты неполные."))}</p>`
    : "";

  const filtered = note ? `<p class="warn">🔎 ${esc(note)}</p>` : "";

  const empty =
    total === 0 && suppressed.length === 0
      ? `<p class="ok">✓ ${esc(t("Находок нет"))}</p>`
      : "";

  const chips = SEVERITY_ORDER.filter((s) => report.counts[s] > 0)
    .map((s) => chip(s, report.counts[s]))
    .join(" ");

  // Accountability by responsible person, from git blame — rendered only when
  // the scan ran on a git work tree (otherwise no finding carries an author).
  const byAuthor = responsibleBreakdown(report.findings, staff);
  const authorSection =
    byAuthor.length > 0
      ? `<section>
        <h2>${esc(t("По ответственным"))}</h2>
        <table class="resp">
          <thead><tr><th>${esc(t("Ответственный"))}</th><th>${esc(t("Находок"))}</th><th>${esc(
            t("Критич. + высокие")
          )}</th><th>${esc(t("Новых"))}</th></tr></thead>
          <tbody>${byAuthor
            .map(
              (r) =>
                `<tr><td>${esc(r.name)}</td><td>${r.total}</td><td>${r.severe || "—"}</td><td>${
                  r.isNew || "—"
                }</td></tr>`
            )
            .join("")}</tbody>
        </table>
      </section>`
      : "";

  return `<!doctype html>
<html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(t("Отчёт VulnScope"))} — ${esc(report.targetLabel)}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    color: #1a1a1e; background: #fff; padding: 40px 24px; }
  main { max-width: 820px; margin: 0 auto; }
  header { border-bottom: 2px solid #e6e6ea; padding-bottom: 20px; margin-bottom: 28px; }
  h1 { font-size: 24px; margin: 0 0 6px; }
  .target { color: #62636c; font-size: 14px; word-break: break-all; }
  .summary { margin: 16px 0 4px; color: #45464f; font-size: 14px; }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
  .chip { border-left: 4px solid var(--c); background: #f4f4f6; padding: 4px 10px 4px 8px;
    border-radius: 4px; font-size: 13px; }
  .chip b { font-size: 14px; }
  h2 { font-size: 17px; margin: 32px 0 12px; padding-left: 12px; border-left: 4px solid var(--c, #999); }
  .n { color: #8b8d98; font-weight: 400; }
  .card { border: 1px solid #e6e6ea; border-left: 4px solid var(--c); border-radius: 8px;
    padding: 14px 16px; margin: 10px 0; background: #fafafb; }
  .card h3 { font-size: 15px; margin: 0 0 8px; }
  .meta { font-size: 12.5px; color: #62636c; margin: 0 0 10px; display: flex;
    flex-wrap: wrap; gap: 6px 10px; align-items: center; }
  .card p { margin: 8px 0 0; }
  code { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; font-size: 12.5px;
    background: #ececed; padding: 1px 5px; border-radius: 4px; }
  .tag { font-size: 11.5px; background: #ececed; color: #45464f; padding: 1px 7px; border-radius: 10px; }
  .rec { background: #eef6ee; border-radius: 6px; padding: 8px 12px; font-size: 13.5px; }
  table.resp { border-collapse: collapse; font-size: 13.5px; margin-top: 4px; }
  table.resp th { text-align: left; color: #62636c; font-weight: 600; padding: 4px 14px 4px 0; border-bottom: 1px solid #e6e6ea; }
  table.resp td { padding: 4px 14px 4px 0; border-bottom: 1px solid #f0f0f2; font-variant-numeric: tabular-nums; }
  table.resp td:not(:first-child), table.resp th:not(:first-child) { text-align: right; }
  .sup { color: #62636c; font-size: 13px; font-style: italic; }
  .warn { background: #fff4e5; border: 1px solid #ffd8a8; border-radius: 6px; padding: 10px 14px; }
  .ok { color: #2b8a3e; font-size: 16px; }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e6e6ea;
    color: #8b8d98; font-size: 12.5px; }
  a { color: #3e63dd; }
  @media (prefers-color-scheme: dark) {
    body { color: #e4e4e7; background: #161618; }
    header, .card, footer, h2 { border-color: #2a2a2e; }
    table.resp th { color: #9a9aa2; border-color: #2a2a2e; }
    table.resp td { border-color: #232326; }
    .card { background: #1c1c1f; }
    .chip, code, .tag { background: #26262a; color: #c4c4c8; }
    .target, .summary, .meta, .sup, .tag, .n, footer { color: #9a9aa2; }
    .rec { background: #16241a; color: #c8e6c9; }
    .warn { background: #2a2213; border-color: #4a3a1a; color: #f0d9a8; }
  }
  @media print {
    body { padding: 0; } .card { break-inside: avoid; }
  }
</style>
<main>
  <header>
    <h1>${esc(t("Отчёт VulnScope"))}</h1>
    <div class="target">${esc(report.targetLabel)}</div>
    ${cancelled}
    ${filtered}
    <div class="summary">${esc(
      t("Найдено: {total} · файлов: {files} · строк: {lines}", {
        total,
        files: report.filesScanned,
        lines: report.linesScanned,
      })
    )}</div>
    <div class="chips">${chips}</div>
  </header>
  ${empty}
  ${authorSection}
  ${sections}
  ${suppressedSection}
  <footer>${esc(t("Сгенерировано VulnScope"))} · ${esc(formatStamp(report.finishedAt))}</footer>
</main>
</html>
`;
}
