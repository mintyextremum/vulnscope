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

/** One physical place in a file, with the offending line as the snippet. */
function locationFor(file: string, line: number, code: string, message: string) {
  return {
    physicalLocation: {
      artifactLocation: { uri: uri(file) },
      region: {
        startLine: line > 0 ? line : 1,
        ...(code ? { snippet: { text: code } } : {}),
      },
    },
    message: { text: message },
  };
}

/**
 * The traced data-flow path as a SARIF `codeFlows` entry.
 *
 * This is the part of the flagship engine a dashboard can actually show: GitHub
 * code scanning renders `threadFlows` as a clickable source → … → sink chain, so
 * the evidence that made the finding travels with it instead of staying in this
 * window. Each step's `category` carries its role label ("Источник…",
 * "Передача через переменную", "Приёмник…"), which becomes the step's message.
 *
 * `executionOrder` is 1-based and must increase along the path; `nestingLevel`
 * stays 0 because the analysis is intra-procedural — there are no nested calls
 * to represent.
 */
function codeFlowsFor(f: Finding, t: TFn) {
  const flow = f.extra?.flow;
  if (!flow || flow.length === 0) return undefined;
  return [
    {
      message: { text: t("Поток данных") },
      threadFlows: [
        {
          locations: flow.map((step, i) => ({
            location: locationFor(f.file, step.line, step.code, t(step.category)),
            nestingLevel: 0,
            executionOrder: i + 1,
          })),
        },
      ],
    },
  ];
}

/**
 * The other places a "dangerous combination" links, as `relatedLocations`.
 *
 * Deliberately not a codeFlow: a combination is a set of issues that co-occur
 * and amplify each other, not an ordered path through the program, and claiming
 * an execution order it never established would be a lie in a machine-readable
 * document.
 */
function relatedLocationsFor(f: Finding, t: TFn) {
  const spots = f.extra?.combineSpots;
  if (!spots || spots.length === 0) return undefined;
  return spots.map((s, i) => ({
    id: i + 1,
    ...locationFor(f.file, s.line, s.code, t(s.category)),
  }));
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
    // The traced path and the linked places, when the finding carries them.
    const codeFlows = codeFlowsFor(f, t);
    if (codeFlows) result.codeFlows = codeFlows;
    const related = relatedLocationsFor(f, t);
    if (related) result.relatedLocations = related;

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
