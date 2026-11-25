import { describe, expect, it } from "vitest";
import { ConfigError, normalizeConfig, starterConfig } from "../src/config.js";
import { splitCounts } from "../src/probe.js";
import { exitCode, formatMarkdown, formatText, matrix } from "../src/report.js";
import { ident, matchesPattern, plainColumn } from "../src/sql.js";
import type { Report } from "../src/types.js";

describe("sql helpers", () => {
  it("quotes identifiers", () => {
    expect(ident("tenant_id")).toBe('"tenant_id"');
    expect(ident('we"ird')).toBe('"we""ird"');
    expect(() => ident("")).toThrow();
  });
  it("recognises plain columns, quoted or not", () => {
    expect(plainColumn("tenant_id", ["id", "tenant_id"])).toBe("tenant_id");
    expect(plainColumn(' "Tenant" ', ["Tenant"])).toBe("Tenant");
    expect(plainColumn("(select 1)", ["tenant_id"])).toBeNull();
    expect(plainColumn("org_id", ["tenant_id"])).toBeNull();
  });
  it("matches exclusion patterns", () => {
    expect(matchesPattern("pg_stat", "pg_*")).toBe(true);
    expect(matchesPattern("notes", "note")).toBe(false);
  });
});

describe("config", () => {
  it("fills defaults", () => {
    const c = normalizeConfig({ principals: [{ name: "a", role: "app", tenant: "t1" }] });
    expect(c).toMatchObject({ schemas: ["public"], tenantColumns: ["tenant_id"], writes: false, statementTimeoutMs: 30000 });
    expect(c.principals[0]).toMatchObject({ role: "app", tenants: ["t1"] });
  });
  it("builds PostgREST-style claims for the supabase preset", () => {
    const c = normalizeConfig({ preset: "supabase", principals: [{ name: "u", claims: { sub: "abc" } }, { name: "visitor" }] });
    expect(c.principals[0]!.role).toBe("authenticated");
    expect(c.principals[0]!.settings).toContainEqual(["request.jwt.claim.sub", "abc"]);
    expect(JSON.parse(c.principals[0]!.settings[0]![1])).toEqual({ role: "authenticated", sub: "abc" });
    expect(c.principals[1]).toMatchObject({ role: "anon", tenants: [], settings: [] });
  });
  it.each([
    [{}, /principals/],
    [{ principals: [] }, /principals/],
    [{ principals: [{ name: "a" }] }, /role is required/],
    [{ principals: [{ name: "a", role: "r", claims: {} }] }, /preset "supabase"/],
    [{ principals: [{ name: "a", role: "r", tenant: "x", tenants: ["y"] }] }, /either/],
    [{ principals: [{ name: "a", role: "r" }, { name: "a", role: "r" }] }, /duplicate/],
    [{ tables: { t: { tenat: "x" } }, principals: [{ name: "a", role: "r" }] }, /unknown option/],
  ])("rejects %j", (input, message) => {
    expect(() => normalizeConfig(input)).toThrow(ConfigError);
    expect(() => normalizeConfig(input)).toThrow(message);
  });
  it("ships starter configs that validate", () => {
    expect(() => normalizeConfig(starterConfig("supabase"))).not.toThrow();
    expect(() => normalizeConfig(starterConfig("generic"))).not.toThrow();
  });
});

it("splits per-tenant counts for a principal", () => {
  const byTenant = new Map<string | null, number>([["a", 2], ["b", 3], [null, 1]]);
  expect(splitCounts(byTenant, ["a"])).toEqual({ own: 2, foreign: 3, noTenant: 1 });
  expect(splitCounts(byTenant, [])).toEqual({ own: 0, foreign: 5, noTenant: 1 });
});

describe("report formatting", () => {
  const report: Report = {
    tool: { name: "pg-tenant-probe", version: "0.0.0" },
    startedAt: "2026-01-01T00:00:00.000Z",
    durationMs: 12,
    database: { serverVersion: "17.0", connectedAs: "postgres", schemas: ["public"], baselineBypassesRls: true },
    writes: false,
    principals: [{ name: "alice", role: "authenticated", tenants: ["a"] }],
    relations: [
      { schema: "public", name: "notes", id: "public.notes", kind: "table", owner: "postgres", rlsEnabled: true, rlsForced: false, policyCount: 1, securityInvoker: false, tenantExpr: '"tenant_id"', tenantColumn: "tenant_id", shared: false },
    ],
    checks: [{ relation: "public.notes", principal: "alice", kind: "read", status: "leak", message: "can read 2 of 2 rows that belong to other tenants" }],
    findings: [{ severity: "error", code: "CROSS_TENANT_READ", relation: "public.notes", principal: "alice", message: 'a "pipe" | here' }],
    summary: { relations: 1, principals: 1, checks: 1, passed: 0, leaks: 1, inconclusive: 0, errors: 1, warnings: 0, ok: false },
  };
  it("builds the matrix from the worst status", () => {
    expect(matrix(report)).toEqual([{ relation: "public.notes", cells: ["leak"] }]);
  });
  it("renders text without colour codes unless asked", () => {
    const text = formatText(report);
    expect(text).toContain("CROSS_TENANT_READ");
    expect(text).toContain("Result: FAIL");
    expect(text).not.toContain("\u001b[");
    expect(formatText(report, { color: true })).toContain("\u001b[31m");
  });
  it("renders markdown with escaped pipes", () => {
    const md = formatMarkdown(report);
    expect(md).toContain("| ❌ | `CROSS_TENANT_READ`");
    expect(md).toContain('a "pipe" \\| here');
  });
  it("maps findings to exit codes", () => {
    expect(exitCode(report)).toBe(1);
    expect(exitCode({ ...report, summary: { ...report.summary, errors: 0, warnings: 2 } })).toBe(0);
    expect(exitCode({ ...report, summary: { ...report.summary, errors: 0, warnings: 2 } }, "warn")).toBe(1);
  });
});
