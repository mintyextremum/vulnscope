import type { Finding, Staff1c } from "./types";

/**
 * Accountability from git blame, shared by every export and the report.
 *
 * This module holds only type imports, so it stays loadable under Node's
 * `--experimental-strip-types` (no bundler) — which is why the audited
 * runtime-import-free modules (`xml1c.ts`, `excel.ts`) can import it too, and
 * the mapping no longer lives in five hand-copied places.
 */

/** The person accountable for a finding: the git-blame author, mapped onto a 1C
 *  employee when a staff registry was imported (e-mail first, then name/alias),
 *  else the raw git author. Null when the finding carries no blame at all. */
export function resolveResponsible(f: Finding, staff: Staff1c[]): { name: string; role: string } | null {
  const b = f.extra?.blame;
  if (!b) return null;
  const mail = (b.email ?? "").toLowerCase();
  const name = b.author.toLowerCase();
  const emp =
    (mail && staff.find((s) => s.emails.some((e) => e.toLowerCase() === mail))) ||
    staff.find((s) => s.name.toLowerCase() === name || s.aliases.some((a) => a.toLowerCase() === name));
  return emp ? { name: emp.name, role: emp.role } : { name: b.author, role: "" };
}

export interface ResponsibleRow {
  name: string;
  role: string;
  total: number;
  /** Critical + high findings owned by this person. */
  severe: number;
  /** Findings new since the previous scan. */
  isNew: number;
}

/**
 * Per-responsible tally over the confirmed, non-suppressed findings, sorted by
 * total descending. Empty when the scan carried no blame (not a git work tree)
 * or no staff mapped — callers render the section only when it is non-empty.
 * Callers cap the list themselves (the report shows a top-N; the exports list all).
 */
export function responsibleBreakdown(findings: Finding[], staff: Staff1c[]): ResponsibleRow[] {
  const rows = new Map<string, ResponsibleRow>();
  for (const f of findings) {
    if (f.suppressed || f.extra?.experimental) continue;
    const who = resolveResponsible(f, staff);
    if (!who) continue;
    const r = rows.get(who.name) ?? { name: who.name, role: who.role, total: 0, severe: 0, isNew: 0 };
    r.total += 1;
    if (f.severity === "critical" || f.severity === "high") r.severe += 1;
    if (f.isNew) r.isNew += 1;
    rows.set(who.name, r);
  }
  return [...rows.values()].sort((a, b) => b.total - a.total);
}
