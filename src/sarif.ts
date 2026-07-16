import type { Finding, ScanReport, Severity } from "./types";
import type { TFn } from "./i18n";

/**
 * SARIF 2.1.0 export.
 *
 * SARIF is the format GitHub code scanning and most CI security dashboards
 * ingest, so exporting it lets a VulnScope run feed a pipeline instead of
 * living only in this window. The shape here is the OASIS 2.1.0 schema: one
 * run, a driver that lists every rule that fired, and one result per finding.
 *
 * Text is translated through `t`, so the SARIF matches the language the user is
 * reading — the report itself stores the source (Russian) strings.
 */

/** SARIF result levels. It has no "critical", so the two top severities map to
 *  `error` and carry the numeric severity in a property GitHub understands. */
function sarifLevel(sev: Severity): "error" | "warning" | "note" {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

/** GitHub reads `security-severity` as a CVSS-like 0–10 to bucket findings. */
function securitySeverity(sev: Severity): string {
  return { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" }[sev];
}

/** A file path as a SARIF artifact URI: forward slashes, no leading slash. */
function uri(file: string): string {
  return file.replace(/\\/g, "/").replace(/^\/+/, "");
}

export function toSarif(report: ScanReport, t: TFn): unknown {
  // One reportingDescriptor per rule that actually produced a finding, keyed by
  // ruleId so the same rule is described once even when it fires many times.
  const rules = new Map<string, unknown>();
  for (const f of report.findings) {
    if (rules.has(f.ruleId)) continue;
    const tags = [f.category, ...f.cwe, ...(f.owasp ? [f.owasp] : [])].filter(Boolean);
    rules.set(f.ruleId, {
      id: f.ruleId,
      name: f.ruleId,
      shortDescription: { text: t(f.title) },
      fullDescription: { text: t(f.description) },
      help: { text: t(f.recommendation) },
      defaultConfiguration: { level: sarifLevel(f.severity) },
      properties: {
        tags: tags.map((x) => t(x)),
        "security-severity": securitySeverity(f.severity),
      },
      ...(f.references.length ? { helpUri: f.references[0] } : {}),
    });
  }

  const results = report.findings.map((f: Finding) => {
    const line = f.line > 0 ? f.line : 1;
    const result: Record<string, unknown> = {
      ruleId: f.ruleId,
      level: sarifLevel(f.severity),
      message: { text: t(f.description) },
      // The stable fingerprint doubles as SARIF's partialFingerprints, so a
      // dashboard can track a finding across runs the same way the app does.
      partialFingerprints: { vulnscope: f.fingerprint },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: uri(f.file) },
            region: {
              startLine: line,
              ...(f.endLine > line ? { endLine: f.endLine } : {}),
              ...(f.column > 0 ? { startColumn: f.column } : {}),
            },
          },
        },
      ],
    };
    // A suppressed finding is exported as suppressed, not dropped: the dashboard
    // should see it exists and was deliberately silenced, with the reason.
    if (f.suppressed) {
      result.suppressions = [
        { kind: "external", justification: f.suppressionReason ?? "" },
      ];
    }
    return result;
  });

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "VulnScope",
            informationUri: "https://github.com/mintyextremum/vulnscope",
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
}
