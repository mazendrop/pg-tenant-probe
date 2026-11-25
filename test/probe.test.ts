import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { probe } from "../src/probe.js";
import type { Report } from "../src/types.js";
import { fixtureConfig, freshDb, type TestDb } from "./helpers.js";

let t: TestDb;
let report: Report;

const findings = (code: string) =>
  report.findings
    .filter((f) => f.code === code)
    .map((f) => [f.relation ?? "", f.principal ?? ""].join(" "))
    .sort();
const check = (relation: string, principal: string, kind = "read") =>
  report.checks.find((c) => c.relation === `public.${relation}` && c.principal === principal && c.kind === kind);

beforeAll(async () => {
  t = await freshDb();
  report = await probe(t.db, { ...(await fixtureConfig()), writes: true });
});
afterAll(() => t.close());

describe("pg-tenant-probe on the fixture", () => {
  it("finds every cross-tenant read, and nothing else", () => {
    expect(findings("CROSS_TENANT_READ")).toEqual(
      [
        "public.invoice_totals alice",
        "public.invoice_totals bob",
        "public.notes alice",
        "public.notes bob",
        "public.payments alice",
        "public.payments bob",
        "public.project_overview alice",
        "public.project_overview bob",
        "public.reports alice",
        "public.reports bob",
        "public.tasks alice",
        "public.tasks anon",
        "public.tasks bob",
      ].sort(),
    );
  });

  it("counts exactly how many foreign rows leak", () => {
    expect(check("notes", "alice")?.visible).toEqual({ own: 1, foreign: 2, noTenant: 0 });
    expect(check("tasks", "anon")?.visible).toEqual({ own: 0, foreign: 2, noTenant: 0 });
  });

  it("evaluates tenant expressions with owner rights, so a leaky child table is not mistaken for tenant-less rows", () => {
    // payments' tenant comes from invoices, which alice may not see for globex.
    expect(check("payments", "alice")).toMatchObject({ status: "leak", visible: { own: 1, foreign: 1, noTenant: 0 } });
    expect(check("invoice_lines", "alice")).toMatchObject({ status: "pass", visible: { own: 3, foreign: 0, noTenant: 0 } });
  });

  it("passes correct tables and the security_invoker view", () => {
    for (const rel of ["tenants", "members", "projects", "invoices", "invoice_lines", "comments", "audit_log", "project_overview_safe"]) {
      expect(check(rel, "alice")?.status, rel).toBe("pass");
      expect(check(rel, "bob")?.status, rel).toBe("pass");
    }
  });

  it("finds cross-tenant writes: permissive UPDATE USING, permissive WITH CHECK, owner bypass", () => {
    expect(findings("CROSS_TENANT_WRITE")).toEqual(
      [
        "public.comments alice",
        "public.comments alice",
        "public.comments bob",
        "public.comments bob",
        "public.invoices alice",
        "public.invoices bob",
        "public.reports alice",
        "public.reports alice",
        "public.reports alice",
        "public.reports bob",
        "public.reports bob",
        "public.reports bob",
      ].sort(),
    );
    expect(check("comments", "alice", "update")).toMatchObject({ status: "leak", affected: 1 });
    // No WITH CHECK means the USING (true) doubles as the check: rows can be moved, too.
    expect(check("comments", "alice", "reassign")).toMatchObject({ status: "leak", affected: 2 });
    expect(check("invoices", "alice", "reassign")).toMatchObject({ status: "leak", affected: 2 });
    expect(check("projects", "alice", "reassign")?.status).toBe("pass");
    expect(check("projects", "alice", "update")?.status).toBe("pass");
    expect(check("projects", "alice", "delete")?.status).toBe("pass");
    expect(check("notes", "alice", "reassign")?.status).toBe("pass");
  });

  it("reports structural problems", () => {
    expect(findings("RLS_DISABLED")).toEqual(["public.tasks "]);
    expect(findings("OWNER_BYPASS")).toEqual(["public.reports "]);
    expect(findings("RLS_NO_POLICIES")).toEqual(["public.audit_log "]);
    expect(findings("VIEW_OWNER_RIGHTS")).toEqual(["public.project_overview "]);
    expect(findings("MATVIEW_EXPOSED")).toEqual(["public.invoice_totals "]);
    expect(findings("UNMAPPED")).toEqual(["public.feature_flags "]);
    expect(findings("PRINCIPAL_SEES_NOTHING")).toEqual([]);
    expect(findings("PROBE_ERROR")).toEqual([]);
  });

  it("skips shared tables and respects missing privileges", () => {
    expect(check("countries", "alice")?.status).toBe("skipped");
    expect(check("projects", "anon")?.status).toBe("no-access");
    expect(check("tasks", "alice", "update")?.status).toBe("no-access");
  });

  it("summarises and fails", () => {
    expect(report.summary.ok).toBe(false);
    expect(report.summary.leaks).toBe(25);
    expect(report.database.baselineBypassesRls).toBe(true);
  });

  it("leaves no trace: data, ownership and temp tables are untouched", async () => {
    const { rows } = await t.db.query(
      `select (select string_agg(tenant_id, ',' order by id) from invoices) as invoices,
              (select count(*)::int from comments where body is null) as wiped_comments,
              (select count(*)::int from projects) as projects,
              (select count(*)::int from pg_class where relname like 'tenant_probe_%') as temp_tables,
              current_user as usr`,
    );
    expect(rows[0]).toMatchObject({ invoices: "acme,acme,globex", wiped_comments: 0, projects: 3, temp_tables: 0 });
    expect(rows[0].usr).not.toBe("authenticated");
  });
});

describe("misconfigured principals", () => {
  it("warns when a principal cannot see any of its own rows", async () => {
    const db = await freshDb();
    try {
      const config = await fixtureConfig();
      config.principals = [{ name: "typo", tenant: "acme", claims: { sub: "00000000-0000-0000-0000-0000000000ff" } }];
      const r = await probe(db.db, config);
      expect(r.findings.map((f) => f.code)).toContain("PRINCIPAL_SEES_NOTHING");
    } finally {
      await db.close();
    }
  });

  it("reports roles that do not exist instead of crashing", async () => {
    const db = await freshDb();
    try {
      const config = await fixtureConfig();
      config.principals = [{ name: "ghost", role: "no_such_role", tenant: "acme" }];
      const r = await probe(db.db, config);
      expect(r.findings).toContainEqual(expect.objectContaining({ code: "PROBE_ERROR", principal: "ghost" }));
      expect(r.checks).toEqual([]);
    } finally {
      await db.close();
    }
  });
});
