/**
 * Timestamp formatting for exported documents.
 *
 * The backend stamps reports in RFC 3339 with nanosecond precision
 * (`2026-07-25T12:48:15.673033500+00:00`). That is right for machines and wrong
 * for a document someone opens or emails. This module holds only type imports,
 * so the audited runtime-import-free exports (`excel.ts`) can use it too.
 */

/**
 * `YYYY-MM-DD HH:MM` in local time — deliberately locale-neutral rather than
 * `toLocaleString`: an exported report travels to readers whose locale is not
 * the exporter's, and an unambiguous ISO-like stamp beats a date that means
 * something different depending on who opens it. Unparseable input is returned
 * unchanged, so a document never shows "Invalid Date".
 */
export function formatStamp(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
