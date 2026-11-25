import type { PrincipalConfig, ProbeConfig, TableConfig } from "./types.js";

export class ConfigError extends Error {
  override name = "ConfigError";
}

/** Identity helper so `.mjs` configs get type checking via JSDoc or TS. */
export function defineConfig(config: ProbeConfig): ProbeConfig {
  return config;
}

export interface Principal {
  name: string;
  role: string;
  tenants: string[];
  /** Session settings applied with set_config(key, value, is_local => true). */
  settings: [string, string][];
  setup: string[];
}

export interface NormalizedConfig {
  schemas: string[];
  tenantColumns: string[];
  tables: Map<string, TableConfig>;
  exclude: string[];
  principals: Principal[];
  writes: boolean;
  statementTimeoutMs: number;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

function stringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string" || v.length === 0)) {
    throw new ConfigError(`${path} must be an array of non-empty strings`);
  }
  return value as string[];
}

/** Validate a user config and fill in defaults. Throws ConfigError with a precise path. */
export function normalizeConfig(input: unknown): NormalizedConfig {
  if (!isObject(input)) throw new ConfigError("config must be an object");
  const preset = input.preset ?? "generic";
  if (preset !== "generic" && preset !== "supabase") {
    throw new ConfigError(`preset must be "generic" or "supabase", got ${JSON.stringify(preset)}`);
  }

  const schemas = input.schemas === undefined ? ["public"] : stringArray(input.schemas, "schemas");
  const tenantColumns =
    input.tenantColumn === undefined
      ? ["tenant_id"]
      : typeof input.tenantColumn === "string"
        ? [input.tenantColumn]
        : stringArray(input.tenantColumn, "tenantColumn");
  const exclude = input.exclude === undefined ? [] : stringArray(input.exclude, "exclude");

  const tables = new Map<string, TableConfig>();
  if (input.tables !== undefined) {
    if (!isObject(input.tables)) throw new ConfigError("tables must be an object keyed by table name");
    for (const [key, raw] of Object.entries(input.tables)) {
      if (!isObject(raw)) throw new ConfigError(`tables.${key} must be an object`);
      const { tenant, shared, skip, ...rest } = raw;
      const unknown = Object.keys(rest);
      if (unknown.length) throw new ConfigError(`tables.${key}: unknown option(s) ${unknown.join(", ")}`);
      if (tenant !== undefined && (typeof tenant !== "string" || !tenant.trim())) {
        throw new ConfigError(`tables.${key}.tenant must be a non-empty SQL expression`);
      }
      for (const [opt, val] of [["shared", shared], ["skip", skip]] as const) {
        if (val !== undefined && typeof val !== "boolean") throw new ConfigError(`tables.${key}.${opt} must be a boolean`);
      }
      tables.set(key, raw as TableConfig);
    }
  }

  if (!Array.isArray(input.principals) || input.principals.length === 0) {
    throw new ConfigError("principals must be a non-empty array");
  }
  const seen = new Set<string>();
  const principals = input.principals.map((raw, i) => {
    const principal = normalizePrincipal(raw, `principals[${i}]`, preset);
    if (seen.has(principal.name)) throw new ConfigError(`principals[${i}]: duplicate name "${principal.name}"`);
    seen.add(principal.name);
    return principal;
  });

  const writes = input.writes ?? false;
  if (typeof writes !== "boolean") throw new ConfigError("writes must be a boolean");
  const statementTimeoutMs = input.statementTimeoutMs ?? 30_000;
  if (typeof statementTimeoutMs !== "number" || !Number.isInteger(statementTimeoutMs) || statementTimeoutMs < 0) {
    throw new ConfigError("statementTimeoutMs must be a non-negative integer");
  }

  return { schemas, tenantColumns, tables, exclude, principals, writes, statementTimeoutMs };
}

function normalizePrincipal(raw: unknown, path: string, preset: "generic" | "supabase"): Principal {
  if (!isObject(raw)) throw new ConfigError(`${path} must be an object`);
  const p = raw as Partial<PrincipalConfig> & Record<string, unknown>;
  if (typeof p.name !== "string" || !p.name.trim()) throw new ConfigError(`${path}.name is required`);

  if (p.tenant !== undefined && p.tenants !== undefined) {
    throw new ConfigError(`${path}: use either "tenant" or "tenants", not both`);
  }
  const tenants =
    p.tenant !== undefined
      ? [String(p.tenant)]
      : p.tenants === undefined
        ? []
        : stringArray(p.tenants, `${path}.tenants`);

  const settings: [string, string][] = [];
  if (p.settings !== undefined) {
    if (!isObject(p.settings)) throw new ConfigError(`${path}.settings must be an object of strings`);
    for (const [key, value] of Object.entries(p.settings)) {
      if (typeof value !== "string") throw new ConfigError(`${path}.settings.${key} must be a string`);
      settings.push([key, value]);
    }
  }
  const setup = p.setup === undefined ? [] : stringArray(p.setup, `${path}.setup`);

  let role = p.role;
  if (p.claims !== undefined && !isObject(p.claims)) throw new ConfigError(`${path}.claims must be an object`);
  if (preset === "supabase") {
    role ??= p.claims ? "authenticated" : "anon";
    if (p.claims) {
      // PostgREST exposes the whole token as request.jwt.claims; older auth.uid()
      // implementations read request.jwt.claim.<name>, so set both.
      const claims = { role, ...p.claims };
      const claimSettings: [string, string][] = [["request.jwt.claims", JSON.stringify(claims)]];
      for (const [key, value] of Object.entries(claims)) {
        if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
          claimSettings.push([`request.jwt.claim.${key}`, String(value)]);
        }
      }
      settings.unshift(...claimSettings);
    }
  } else if (p.claims !== undefined) {
    throw new ConfigError(`${path}.claims needs preset "supabase" (use settings for other setups)`);
  }
  if (typeof role !== "string" || !role) {
    throw new ConfigError(`${path}.role is required (the database role the principal runs as)`);
  }
  return { name: p.name, role, tenants, settings, setup };
}

/** Look up per-table overrides by "schema.name" first, then bare "name". */
export function tableConfig(config: NormalizedConfig, schema: string, name: string): TableConfig {
  return config.tables.get(`${schema}.${name}`) ?? config.tables.get(name) ?? {};
}

/** A ready-to-edit starter config, used by `pg-tenant-probe init`. */
export function starterConfig(preset: "generic" | "supabase"): ProbeConfig {
  if (preset === "supabase") {
    return {
      preset: "supabase",
      schemas: ["public"],
      tenantColumn: ["tenant_id", "org_id"],
      tables: {
        tenants: { tenant: "id" },
        countries: { shared: true },
      },
      principals: [
        { name: "user of tenant A", tenant: "<tenant-a-id>", claims: { sub: "<user-a-uuid>" } },
        { name: "user of tenant B", tenant: "<tenant-b-id>", claims: { sub: "<user-b-uuid>" } },
        { name: "anonymous visitor" },
      ],
    };
  }
  return {
    schemas: ["public"],
    tenantColumn: "tenant_id",
    tables: { tenants: { tenant: "id" } },
    principals: [
      { name: "tenant A", role: "app_user", tenant: "<tenant-a-id>", settings: { "app.tenant_id": "<tenant-a-id>" } },
      { name: "tenant B", role: "app_user", tenant: "<tenant-b-id>", settings: { "app.tenant_id": "<tenant-b-id>" } },
    ],
  };
}
