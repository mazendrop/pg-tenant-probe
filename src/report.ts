import type { CheckStatus, Finding, Report, Severity } from "./types.js";

const SYMBOL: Record<CheckStatus, string> = {
  pass: "✓",
  leak: "✗",
  inconclusive: "?",
  "no-access": "–",
  skipped: "·",
};
const RANK: Record<CheckStatus, number> = { leak: 4, inconclusive: 3, pass: 2, "no-access": 1, skipped: 0 };
const LEGEND = "✓ no foreign rows reachable   ✗ leak   ? inconclusive   – no privilege   · not probed (shared/unmapped)";

/** One cell per relation × principal: the worst status across read and write checks. */
export function matrix(report: Report): { relation: string; cells: CheckStatus[] }[] {
  return report.relations.map((rel) => ({
    relation: rel.id,
    cells: report.principals.map((p) => {
      const statuses = report.checks.filter((c) => c.relation === rel.id && c.principal === p.name).map((c) => c.status);
      return statuses.reduce<CheckStatus>((worst, s) => (RANK[s] > RANK[worst] ? s : worst), "skipped");
    }),
  }));
}

export interface TextOptions {
  color?: boolean;
}

export function formatText(report: Report, options: TextOptions = {}): string {
  const paint = (code: number) => (s: string) => (options.color ? `\u001b[${code}m${s}\u001b[0m` : s);
  const red = paint(31), yellow = paint(33), green = paint(32), dim = paint(2), bold = paint(1);
  const colorFor: Record<Severity, (s: string) => string> = { error: red, warn: yellow, info: dim };
  const mark: Record<Severity, string> = { error: "✗", warn: "!", info: "·" };
  const out: string[] = [];
  const { summary, database } = report;

  out.push(
    bold(`${report.tool.name} ${report.tool.version}`) +
      dim(` · PostgreSQL ${database.serverVersion} · schemas: ${database.schemas.join(", ")} · writes: ${report.writes ? "on" : "off"}`),
  );
  out.push(dim(`${summary.principals} principal(s) × ${summary.relations} relation(s) · ${summary.checks} checks · ${report.durationMs} ms`));

  for (const severity of ["error", "warn", "info"] as const) {
    const list = report.findings.filter((f) => f.severity === severity);
    if (!list.length) continue;
    out.push("", bold({ error: "ERRORS", warn: "WARNINGS", info: "INFO" }[severity]));
    const codeWidth = Math.max(...list.map((f) => f.code.length));
    const relWidth = Math.max(0, ...list.map((f) => (f.relation ?? "").length));
    for (const f of list) {
      out.push(
        `  ${colorFor[severity](mark[severity])} ${colorFor[severity](f.code.padEnd(codeWidth))}  ${(f.relation ?? "").padEnd(relWidth)}  ${f.message}`,
      );
    }
  }

  const rows = matrix(report);
  if (rows.length && report.principals.length) {
    const names = report.principals.map((p) => p.name);
    const relWidth = Math.max(8, ...rows.map((r) => r.relation.length));
    out.push("", bold("MATRIX".padEnd(relWidth + 4)) + names.map((n) => bold(n)).join("  "));
    for (const row of rows) {
      const cells = row.cells.map((s, i) => {
        const sym = SYMBOL[s];
        const painted = s === "leak" ? red(sym) : s === "pass" ? green(sym) : s === "inconclusive" ? yellow(sym) : dim(sym);
        return painted + " ".repeat(Math.max(0, names[i]!.length - 1));
      });
      out.push(`  ${row.relation.padEnd(relWidth + 2)}${cells.join("  ").trimEnd()}`);
    }
    out.push(dim(LEGEND));
  }

  const verdict = summary.ok ? green("PASS") : red("FAIL");
  out.push(
    "",
    `${bold("Result:")} ${verdict} — ${summary.errors} error(s), ${summary.warnings} warning(s) · ${summary.passed} passed · ${summary.leaks} leak(s) · ${summary.inconclusive} inconclusive`,
  );
  return out.join("\n") + "\n";
}

const escapeCell = (s: string) => s.replaceAll("|", "\\|").replaceAll("\n", " ");

/** GitHub-flavoured Markdown, e.g. for $GITHUB_STEP_SUMMARY. */
export function formatMarkdown(report: Report): string {
  const { summary } = report;
  const out: string[] = [];
  out.push(`### ${summary.ok ? "✅" : "❌"} pg-tenant-probe: ${summary.ok ? "no cross-tenant access found" : `${summary.errors} error(s)`}`);
  out.push("");
  out.push(
    `${summary.principals} principal(s) × ${summary.relations} relation(s) · ${summary.checks} checks · ${summary.passed} passed · ${summary.leaks} leak(s) · ${summary.inconclusive} inconclusive · writes ${report.writes ? "on" : "off"}`,
  );
  if (report.findings.length) {
    out.push("", "| | Code | Relation | Principal | Details |", "|---|---|---|---|---|");
    const icon: Record<Severity, string> = { error: "❌", warn: "⚠️", info: "ℹ️" };
    const order: Record<Severity, number> = { error: 0, warn: 1, info: 2 };
    const sorted = [...report.findings].sort((a: Finding, b: Finding) => order[a.severity] - order[b.severity]);
    for (const f of sorted) {
      out.push(`| ${icon[f.severity]} | \`${f.code}\` | ${f.relation ? `\`${f.relation}\`` : ""} | ${escapeCell(f.principal ?? "")} | ${escapeCell(f.message)} |`);
    }
  }
  const rows = matrix(report);
  if (rows.length && report.principals.length) {
    out.push("", `| Relation | ${report.principals.map((p) => escapeCell(p.name)).join(" | ")} |`);
    out.push(`|---|${report.principals.map(() => ":---:").join("|")}|`);
    for (const row of rows) out.push(`| \`${row.relation}\` | ${row.cells.map((s) => SYMBOL[s]).join(" | ")} |`);
    out.push("", `<sub>${LEGEND}</sub>`);
  }
  return out.join("\n") + "\n";
}

/** CLI exit code: 1 when there are error findings (or warnings with failOn "warn"). */
export function exitCode(report: Report, failOn: "error" | "warn" = "error"): number {
  if (report.summary.errors > 0) return 1;
  if (failOn === "warn" && report.summary.warnings > 0) return 1;
  return 0;
}
