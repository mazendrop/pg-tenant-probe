import { blindUpdateColumn, readCatalog, type Catalog, type CatalogRelation } from "./catalog.js";
import { normalizeConfig, type NormalizedConfig, type Principal } from "./config.js";
import { errorCode, errorMessage, ident, INSUFFICIENT_PRIVILEGE, qualified } from "./sql.js";
import type { Check, CheckStatus, Counts, Finding, ProbeConfig, Queryable, Report } from "./types.js";
import { VERSION } from "./version.js";

type Outcome<T> = { ok: true; value: T } | { ok: false; error: unknown };

const rowCount = (r: { rowCount?: number | null; affectedRows?: number }) => r.rowCount ?? r.affectedRows ?? 0;

/** Run `fn` inside a savepoint and keep its effects (unless it fails). */
async function attempt<T>(db: Queryable, fn: () => Promise<T>): Promise<Outcome<T>> {
  await db.query("savepoint tenant_probe");
  try {
    const value = await fn();
    await db.query("release savepoint tenant_probe");
    return { ok: true, value };
  } catch (error) {
    await db.query("rollback to savepoint tenant_probe");
    await db.query("release savepoint tenant_probe");
    return { ok: false, error };
  }
}

/** Run `fn` inside a savepoint and always undo it: used for every write probe. */
async function undo<T>(db: Queryable, fn: () => Promise<T>): Promise<Outcome<T>> {
  await db.query("savepoint tenant_probe_write");
  let outcome: Outcome<T>;
  try {
    outcome = { ok: true, value: await fn() };
  } catch (error) {
    outcome = { ok: false, error };
  }
  await db.query("rollback to savepoint tenant_probe_write");
  await db.query("release savepoint tenant_probe_write");
  return outcome;
}

/** Split per-tenant row counts into own / foreign / no-tenant for one principal. */
export function splitCounts(byTenant: Map<string | null, number>, tenants: readonly string[]): Counts {
  const counts: Counts = { own: 0, foreign: 0, noTenant: 0 };
  for (const [tenant, n] of byTenant) {
    if (tenant === null) counts.noTenant += n;
    else if (tenants.includes(tenant)) counts.own += n;
    else counts.foreign += n;
  }
  return counts;
}

const FOREIGN = `t.tenant is not null and not (t.tenant = any($1::text[]))`;

/**
 * Probe every relation in the configured schemas as every principal and
 * report which rows of OTHER tenants each principal can reach.
 *
 * All work happens inside transactions that are rolled back, but write
 * probes do fire triggers: point it at a staging or CI database.
 */
export async function probe(db: Queryable, input: ProbeConfig): Promise<Report> {
  const config = normalizeConfig(input);
  const startedAt = new Date();
  const catalog = await readCatalog(db, config);
  const checks: Check[] = [];
  const findings: Finding[] = [];
  const probed: Principal[] = [];

  if (!catalog.baselineBypassesRls) {
    findings.push({
      severity: "warn",
      code: "BASELINE_FILTERED",
      message: `Connected as "${catalog.connectedAs}", which is itself subject to RLS: row totals may be incomplete. Connect as a superuser or a role with BYPASSRLS.`,
    });
  }

  for (const principal of config.principals) {
    const role = catalog.roles.get(principal.role)!;
    if (!role.exists) {
      findings.push({ severity: "error", code: "PROBE_ERROR", principal: principal.name, message: `Role "${principal.role}" does not exist.` });
    } else if (!role.canAssume) {
      findings.push({
        severity: "error",
        code: "PROBE_ERROR",
        principal: principal.name,
        message: `"${catalog.connectedAs}" cannot SET ROLE "${principal.role}". Grant the role to it or connect as a superuser.`,
      });
    } else {
      if (role.bypassRls) {
        findings.push({
          severity: "error",
          code: "ROLE_BYPASSES_RLS",
          principal: principal.name,
          message: `Role "${principal.role}" is a superuser or has BYPASSRLS: no policy ever applies to it.`,
        });
      }
      probed.push(principal);
    }
  }

  relationFindings(catalog, probed, findings);
  for (const principal of probed) {
    await probePrincipal(db, config, catalog, principal, checks, findings);
  }
  checkFindings(catalog, probed, checks, findings);

  const count = (s: CheckStatus) => checks.filter((c) => c.status === s).length;
  const errors = findings.filter((f) => f.severity === "error").length;
  return {
    tool: { name: "pg-tenant-probe", version: VERSION },
    startedAt: startedAt.toISOString(),
    durationMs: Date.now() - startedAt.getTime(),
    database: {
      serverVersion: catalog.serverVersion,
      connectedAs: catalog.connectedAs,
      schemas: config.schemas,
      baselineBypassesRls: catalog.baselineBypassesRls,
    },
    writes: config.writes,
    principals: config.principals.map((p) => ({ name: p.name, role: p.role, tenants: p.tenants })),
    relations: catalog.relations.map(({ oid: _oid, columns: _columns, ...info }) => info),
    checks,
    findings,
    summary: {
      relations: catalog.relations.length,
      principals: config.principals.length,
      checks: checks.length,
      passed: count("pass"),
      leaks: count("leak"),
      inconclusive: count("inconclusive"),
      errors,
      warnings: findings.filter((f) => f.severity === "warn").length,
      ok: errors === 0,
    },
  };
}

function relationFindings(catalog: Catalog, principals: Principal[], findings: Finding[]): void {
  const roles = [...new Set(principals.map((p) => p.role))];
  for (const rel of catalog.relations) {
    const priv = (role: string) => catalog.privileges.get(`${rel.oid}|${role}`);
    const readers = roles.filter((r) => priv(r)?.select);
    if (readers.length === 0) continue;
    const who = readers.map((r) => `"${r}"`).join(", ");
    const isTable = rel.kind === "table" || rel.kind === "partitioned table";

    if (isTable && !rel.rlsEnabled && !rel.shared) {
      findings.push({ severity: "error", code: "RLS_DISABLED", relation: rel.id, message: `RLS is disabled, yet ${who} can SELECT from it.` });
    }
    if (isTable && rel.rlsEnabled && rel.policyCount === 0) {
      findings.push({ severity: "info", code: "RLS_NO_POLICIES", relation: rel.id, message: `RLS is enabled with no policies: deny-all for ${who}. Intended?` });
    }
    for (const role of readers) {
      if (isTable && rel.rlsEnabled && !rel.rlsForced && priv(role)!.ownerRights) {
        findings.push({
          severity: "error",
          code: "OWNER_BYPASS",
          relation: rel.id,
          message: `Role "${role}" has the rights of the owner "${rel.owner}", so RLS does not apply to it. Change the owner or use FORCE ROW LEVEL SECURITY.`,
        });
      }
    }
    if (rel.kind === "view" && !rel.securityInvoker && !rel.shared) {
      findings.push({
        severity: "warn",
        code: "VIEW_OWNER_RIGHTS",
        relation: rel.id,
        message: `View runs with its owner's rights (security_invoker is off), so RLS on its base tables is checked against "${rel.owner}", not the caller. Consider WITH (security_invoker = true).`,
      });
    }
    if (rel.kind === "materialized view" && !rel.shared) {
      findings.push({
        severity: "warn",
        code: "MATVIEW_EXPOSED",
        relation: rel.id,
        message: `Materialized views cannot have RLS, and ${who} can SELECT from this one.`,
      });
    }
    if (!rel.shared && !rel.tenantExpr) {
      findings.push({
        severity: "warn",
        code: "UNMAPPED",
        relation: rel.id,
        message: `No tenant key found, so it was not probed. Add tables["${rel.name}"].tenant (an SQL expression) or mark it shared.`,
      });
    }
  }
}

async function probePrincipal(
  db: Queryable,
  config: NormalizedConfig,
  catalog: Catalog,
  principal: Principal,
  checks: Check[],
  findings: Finding[],
): Promise<void> {
  const role = principal.role;
  const tenantsParam = [principal.tenants];
  const add = (rel: CatalogRelation, kind: Check["kind"], status: CheckStatus, message: string, extra: Partial<Check> = {}) =>
    checks.push({ relation: rel.id, principal: principal.name, kind, status, message, ...extra });

  const targets: CatalogRelation[] = [];
  for (const rel of catalog.relations) {
    if (rel.shared) add(rel, "read", "skipped", "shared relation: visible to every tenant by design");
    else if (!rel.tenantExpr) add(rel, "read", "skipped", "unmapped: no tenant key");
    else if (!catalog.privileges.get(`${rel.oid}|${role}`)?.select) add(rel, "read", "no-access", `role "${role}" has no SELECT privilege`);
    else targets.push(rel);
  }
  if (targets.length === 0) return;

  await db.query("begin isolation level repeatable read");
  try {
    if (config.statementTimeoutMs > 0) {
      await db.query(`set local statement_timeout = ${Math.floor(config.statementTimeoutMs)}`);
    }

    // 1. Baseline, with the connecting user's rights. For tables, remember the
    //    tenant of every physical row (tableoid, ctid) in a temp table, so the
    //    tenant expression is never filtered by RLS — even when it looks up a
    //    parent row the principal must not see.
    const temp = new Map<string, string>();
    const totals = new Map<string, Map<string | null, number>>();
    for (const [i, rel] of targets.entries()) {
      const q = qualified(rel.schema, rel.name);
      const isTable = rel.kind === "table" || rel.kind === "partitioned table";
      const tmp = ident(`tenant_probe_${i}`);
      const outcome = await attempt(db, async () => {
        if (isTable) {
          await db.query(
            `create temp table ${tmp} on commit drop as
               select r.tableoid as rel, r.ctid as rid, (${rel.tenantExpr})::text as tenant from ${q} r`,
          );
          await db.query(`grant select on ${tmp} to ${ident(role)}`);
          return (await db.query(`select tenant, count(*)::int as n from ${tmp} group by tenant`)).rows;
        }
        return (await db.query(`select (${rel.tenantExpr})::text as tenant, count(*)::int as n from ${q} r group by 1`)).rows;
      });
      if (!outcome.ok) {
        add(rel, "read", "inconclusive", `baseline query failed: ${errorMessage(outcome.error)}`);
        findings.push({ severity: "warn", code: "PROBE_ERROR", relation: rel.id, principal: principal.name, message: `Tenant expression failed: ${errorMessage(outcome.error)}` });
        continue;
      }
      totals.set(rel.id, new Map(outcome.value.map((r: { tenant: string | null; n: number }) => [r.tenant, Number(r.n)])));
      if (isTable) temp.set(rel.id, tmp);
    }

    // 2. Become the principal.
    await db.query(`set local role ${ident(role)}`);
    for (const [key, value] of principal.settings) {
      await db.query("select set_config($1, $2, true)", [key, value]);
    }
    for (const statement of principal.setup) await db.query(statement);

    // 3. Probe.
    for (const rel of targets) {
      const byTenant = totals.get(rel.id);
      if (!byTenant) continue;
      const tot = splitCounts(byTenant, principal.tenants);
      const q = qualified(rel.schema, rel.name);
      const tmp = temp.get(rel.id);

      const read = await attempt(db, async () => {
        const sql = tmp
          ? `select count(*) filter (where t.tenant is null)::int as none,
                    count(*) filter (where t.tenant = any($1::text[]))::int as own,
                    count(*) filter (where ${FOREIGN})::int as foreign
               from ${q} r left join ${tmp} t on t.rel = r.tableoid and t.rid = r.ctid`
          : `select count(*) filter (where t.tenant is null)::int as none,
                    count(*) filter (where t.tenant = any($1::text[]))::int as own,
                    count(*) filter (where ${FOREIGN})::int as foreign
               from (select (${rel.tenantExpr})::text as tenant from ${q} r) t`;
        return (await db.query(sql, tenantsParam)).rows[0];
      });
      if (!read.ok) {
        const denied = errorCode(read.error) === INSUFFICIENT_PRIVILEGE;
        add(rel, "read", denied ? "no-access" : "inconclusive", denied ? "permission denied" : `query failed: ${errorMessage(read.error)}`, { totals: tot });
      } else {
        const visible: Counts = { own: Number(read.value.own), foreign: Number(read.value.foreign), noTenant: Number(read.value.none) };
        if (visible.foreign > 0) {
          add(rel, "read", "leak", `can read ${visible.foreign} of ${tot.foreign} rows that belong to other tenants`, { totals: tot, visible });
        } else if (tot.foreign === 0) {
          add(rel, "read", "inconclusive", "no rows of other tenants exist: seed data for a second tenant", { totals: tot, visible });
        } else {
          add(rel, "read", "pass", `sees ${visible.own}/${tot.own} own rows and 0/${tot.foreign} foreign rows`, { totals: tot, visible });
        }
      }

      if (config.writes && tmp) await probeWrites(db, catalog, principal, rel, q, tmp, tot, byTenant, add);
    }
  } catch (error) {
    findings.push({ severity: "error", code: "PROBE_ERROR", principal: principal.name, message: `Probe aborted: ${errorMessage(error)}` });
  } finally {
    await db.query("rollback");
  }
}

async function probeWrites(
  db: Queryable,
  catalog: Catalog,
  principal: Principal,
  rel: CatalogRelation,
  q: string,
  tmp: string,
  tot: Counts,
  byTenant: Map<string | null, number>,
  add: (rel: CatalogRelation, kind: Check["kind"], status: CheckStatus, message: string, extra?: Partial<Check>) => void,
): Promise<void> {
  const priv = catalog.privileges.get(`${rel.oid}|${principal.role}`)!;
  const tenantsParam = [principal.tenants];
  const targetForeign = `(tableoid, ctid) in (select t.rel, t.rid from ${tmp} t where ${FOREIGN})`;
  const allowed = tot.own + tot.noTenant;

  /** Combine a targeted probe (WHERE on foreign rows) and a blind one (no WHERE). */
  const judge = (kind: "update" | "delete", targeted: Outcome<number>, blind: Outcome<number> | null) => {
    if (tot.foreign === 0) return add(rel, kind, "inconclusive", "no rows of other tenants exist");
    const notes: string[] = [];
    let status: CheckStatus = "pass";
    let affected = 0;
    const consider = (label: string, o: Outcome<number> | null, leaked: (n: number) => number) => {
      if (!o) return;
      if (!o.ok) {
        if (errorCode(o.error) === INSUFFICIENT_PRIVILEGE) return notes.push(`${label}: denied`);
        if (status === "pass") status = "inconclusive";
        return notes.push(`${label}: failed (${errorMessage(o.error)})`);
      }
      const n = leaked(o.value);
      if (n > 0) {
        status = "leak";
        affected = Math.max(affected, n);
        notes.push(`${label}: reached ${n} foreign row(s)`);
      } else notes.push(`${label}: 0 foreign rows`);
    };
    consider(`targeted ${kind.toUpperCase()}`, targeted, (n) => n);
    // A blind statement may touch own and tenant-less rows legitimately; anything beyond that is foreign.
    consider(`blind ${kind.toUpperCase()}`, blind, (n) => Math.max(0, n - allowed));
    add(rel, kind, status, notes.join("; "), { totals: tot, affected });
  };

  if (priv.update) {
    const any = rel.columns.find((c) => !c.generated && !c.identityAlways);
    const blindCol = blindUpdateColumn(rel);
    const targeted = any
      ? await undo(db, async () => rowCount(await db.query(`update ${q} set ${ident(any.name)} = ${ident(any.name)} where ${targetForeign}`, tenantsParam)))
      : ({ ok: false, error: new Error("no updatable column") } as const);
    const blind = blindCol
      ? await undo(db, async () => rowCount(await db.query(`update ${q} set ${ident(blindCol.name)} = default`)))
      : null;
    judge("update", targeted, blind);
  } else add(rel, "update", "no-access", `role "${principal.role}" has no UPDATE privilege`);

  if (priv.delete) {
    const targeted = await undo(db, async () => rowCount(await db.query(`delete from ${q} where ${targetForeign}`, tenantsParam)));
    const blind = await undo(db, async () => rowCount(await db.query(`delete from ${q}`)));
    judge("delete", targeted, blind);
  } else add(rel, "delete", "no-access", `role "${principal.role}" has no DELETE privilege`);

  // Reassign: can the principal move its OWN rows into another tenant? That is
  // what a missing or permissive WITH CHECK allows. The statement is blind (no
  // WHERE, nothing read), because reading would also check the new row against
  // the SELECT policies and hide a permissive WITH CHECK.
  if (!rel.tenantColumn || !priv.update || principal.tenants.length === 0) return;
  const foreignTenant = [...byTenant.keys()].find((t) => t !== null && !principal.tenants.includes(t));
  if (!foreignTenant) return add(rel, "reassign", "inconclusive", "no other tenant id known to move rows into");
  if (tot.own === 0) return add(rel, "reassign", "inconclusive", "no own rows to try to move");
  const column = rel.columns.find((c) => c.name === rel.tenantColumn)!;
  const moved = await undo(db, async () =>
    rowCount(await db.query(`update ${q} set ${ident(column.name)} = $1::${column.type}`, [foreignTenant])),
  );
  if (!moved.ok) {
    if (errorCode(moved.error) === INSUFFICIENT_PRIVILEGE) add(rel, "reassign", "pass", "moving own rows to another tenant is rejected");
    else add(rel, "reassign", "inconclusive", `failed: ${errorMessage(moved.error)}`);
  } else if (moved.value > 0) {
    add(rel, "reassign", "leak", `could rewrite the tenant key of ${moved.value} row(s) to another tenant: the UPDATE policy does not check the new row`, {
      affected: moved.value,
    });
  } else add(rel, "reassign", "pass", "UPDATE reaches none of its rows, so nothing can be moved");
}

function checkFindings(catalog: Catalog, principals: Principal[], checks: Check[], findings: Finding[]): void {
  for (const c of checks) {
    if (c.status !== "leak") continue;
    findings.push({
      severity: "error",
      code: c.kind === "read" ? "CROSS_TENANT_READ" : "CROSS_TENANT_WRITE",
      relation: c.relation,
      principal: c.principal,
      message: c.kind === "read" ? `"${c.principal}" ${c.message}.` : `"${c.principal}" ${c.kind.toUpperCase()}: ${c.message}.`,
    });
  }
  for (const c of checks) {
    const rel = catalog.relations.find((r) => r.id === c.relation);
    if (c.kind === "read" && c.visible && c.visible.noTenant > 0 && rel && !rel.shared) {
      findings.push({
        severity: "info",
        code: "NO_TENANT_ROWS_VISIBLE",
        relation: c.relation,
        principal: c.principal,
        message: `"${c.principal}" can read ${c.visible.noTenant} row(s) whose tenant key is NULL. Fine for global rows; a leak otherwise.`,
      });
    }
  }
  for (const p of principals) {
    if (p.tenants.length === 0) continue;
    // Only passing checks: a leaky table shows "own" rows even to a principal whose setup is wrong.
    const reads = checks.filter((c) => c.principal === p.name && c.kind === "read" && c.status === "pass" && c.totals && c.visible);
    const ownTotal = reads.reduce((s, c) => s + c.totals!.own, 0);
    const ownVisible = reads.reduce((s, c) => s + c.visible!.own, 0);
    if (ownTotal > 0 && ownVisible === 0) {
      findings.push({
        severity: "warn",
        code: "PRINCIPAL_SEES_NOTHING",
        principal: p.name,
        message: `"${p.name}" cannot see any of its own ${ownTotal} rows. Its claims/settings probably do not match your policies, so its passing checks prove little.`,
      });
    }
  }
}
