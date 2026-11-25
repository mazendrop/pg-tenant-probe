/**
 * Anything that can run a parameterised SQL statement on ONE pinned session.
 * A `pg.Client` and a PGlite instance both fit. A pool does not: the probe
 * relies on `BEGIN … SET LOCAL ROLE … ROLLBACK` staying on one connection.
 */
export interface Queryable {
  query(
    text: string,
    params?: unknown[],
  ): Promise<{ rows: any[]; rowCount?: number | null; affectedRows?: number }>;
}

export interface PrincipalConfig {
  /** Label used in the report, e.g. "alice (member of acme)". */
  name: string;
  /** Tenant ids this principal legitimately belongs to. Empty = none (e.g. anon). */
  tenants?: string[];
  /** Shorthand for `tenants: [tenant]`. */
  tenant?: string;
  /** Database role to `SET LOCAL ROLE` to. Supabase preset: "authenticated" (or "anon" without claims). */
  role?: string;
  /** Supabase preset: JWT claims, exposed as `request.jwt.claims` the way PostgREST does it. */
  claims?: Record<string, unknown>;
  /** Extra session settings: `set_config(key, value, true)` for each entry. */
  settings?: Record<string, string>;
  /** Raw SQL run after `SET LOCAL ROLE`, inside the probe transaction. Trusted input. */
  setup?: string[];
}

export interface TableConfig {
  /**
   * SQL expression that yields the tenant id of a row, evaluated with the
   * connecting user's rights (so it is NOT filtered by RLS). Defaults to the
   * first column found from `tenantColumn`. Trusted input.
   */
  tenant?: string;
  /** Rows are meant to be visible to every tenant (lookup tables). */
  shared?: boolean;
  /** Leave this relation out of the probe entirely. */
  skip?: boolean;
}

export interface ProbeConfig {
  /** Schemas to scan. Default: ["public"]. */
  schemas?: string[];
  /** Candidate tenant-key column names, first match wins. Default: ["tenant_id"]. */
  tenantColumn?: string | string[];
  /** Per-relation overrides, keyed by "name" or "schema.name". */
  tables?: Record<string, TableConfig>;
  /** Relations to ignore; a trailing "*" matches a prefix, e.g. "pg_*". */
  exclude?: string[];
  /** "supabase" builds role + claims the way PostgREST does. Default: "generic". */
  preset?: "generic" | "supabase";
  principals: PrincipalConfig[];
  /** Also probe UPDATE / DELETE / tenant reassignment (always rolled back). Default: false. */
  writes?: boolean;
  /** Per-statement timeout inside the probe. Default: 30000. */
  statementTimeoutMs?: number;
}

export type RelationKind = "table" | "partitioned table" | "view" | "materialized view";

export interface RelationInfo {
  schema: string;
  name: string;
  /** "schema.name" */
  id: string;
  kind: RelationKind;
  owner: string;
  rlsEnabled: boolean;
  rlsForced: boolean;
  policyCount: number;
  /** Views only: true when the view runs with the caller's rights (PG15+). */
  securityInvoker: boolean;
  /** Tenant expression in use, or null when the relation is unmapped. */
  tenantExpr: string | null;
  /** The tenant key is a plain column of the relation (enables the reassign probe). */
  tenantColumn: string | null;
  shared: boolean;
}

export type CheckKind = "read" | "update" | "delete" | "reassign";

export type CheckStatus =
  /** Rows of other tenants existed and none were reachable. */
  | "pass"
  /** Rows of other tenants were reachable. */
  | "leak"
  /** Could not decide (no foreign rows to test against, or the statement errored). */
  | "inconclusive"
  /** The role lacks the privilege, so RLS is never reached. */
  | "no-access"
  /** Shared or unmapped relation: not tested. */
  | "skipped";

export interface Counts {
  own: number;
  foreign: number;
  /** Rows whose tenant expression is NULL (often global rows). */
  noTenant: number;
}

export interface Check {
  relation: string;
  principal: string;
  kind: CheckKind;
  status: CheckStatus;
  /** Rows that exist, seen with the connecting user's rights. */
  totals?: Counts;
  /** Rows the principal could see (read) */
  visible?: Counts;
  /** Rows a write statement touched. */
  affected?: number;
  message: string;
}

export type Severity = "error" | "warn" | "info";

export interface Finding {
  severity: Severity;
  code:
    | "CROSS_TENANT_READ"
    | "CROSS_TENANT_WRITE"
    | "RLS_DISABLED"
    | "RLS_NO_POLICIES"
    | "OWNER_BYPASS"
    | "ROLE_BYPASSES_RLS"
    | "VIEW_OWNER_RIGHTS"
    | "MATVIEW_EXPOSED"
    | "NO_TENANT_ROWS_VISIBLE"
    | "UNMAPPED"
    | "PRINCIPAL_SEES_NOTHING"
    | "BASELINE_FILTERED"
    | "PROBE_ERROR";
  relation?: string;
  principal?: string;
  message: string;
}

export interface Report {
  tool: { name: string; version: string };
  startedAt: string;
  durationMs: number;
  database: {
    serverVersion: string;
    connectedAs: string;
    schemas: string[];
    /** False if the connecting user is itself subject to RLS: totals may be incomplete. */
    baselineBypassesRls: boolean;
  };
  writes: boolean;
  principals: { name: string; role: string; tenants: string[] }[];
  relations: RelationInfo[];
  checks: Check[];
  findings: Finding[];
  summary: {
    relations: number;
    principals: number;
    checks: number;
    passed: number;
    leaks: number;
    inconclusive: number;
    errors: number;
    warnings: number;
    /** No error-level findings. */
    ok: boolean;
  };
}
