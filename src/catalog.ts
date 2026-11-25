import { tableConfig, type NormalizedConfig } from "./config.js";
import { matchesPattern, plainColumn, ident } from "./sql.js";
import type { Queryable, RelationInfo, RelationKind } from "./types.js";

export interface Column {
  name: string;
  type: string;
  notNull: boolean;
  hasDefault: boolean;
  generated: boolean;
  identityAlways: boolean;
  unique: boolean;
}

export interface CatalogRelation extends RelationInfo {
  oid: string;
  columns: Column[];
}

export interface RoleInfo {
  exists: boolean;
  bypassRls: boolean;
  /** The connecting user may SET ROLE to it. */
  canAssume: boolean;
}

export interface Privileges {
  select: boolean;
  update: boolean;
  delete: boolean;
  /** Role has the rights of the relation owner: RLS does not apply unless FORCEd. */
  ownerRights: boolean;
}

export interface Catalog {
  serverVersion: string;
  connectedAs: string;
  baselineBypassesRls: boolean;
  relations: CatalogRelation[];
  roles: Map<string, RoleInfo>;
  /** key: `${oid}|${role}` */
  privileges: Map<string, Privileges>;
}

const KINDS: Record<string, RelationKind> = {
  r: "table",
  p: "partitioned table",
  v: "view",
  m: "materialized view",
};

export async function readCatalog(db: Queryable, config: NormalizedConfig): Promise<Catalog> {
  const [server] = (
    await db.query(
      `select current_setting('server_version') as version, current_user as usr,
              coalesce((select rolsuper or rolbypassrls from pg_roles where rolname = current_user), false) as bypass`,
    )
  ).rows;

  const relRows = (
    await db.query(
      `select c.oid::text as oid, n.nspname as schema, c.relname as name, c.relkind::text as kind,
              c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced,
              pg_get_userbyid(c.relowner) as owner,
              (select count(*) from pg_policy p where p.polrelid = c.oid)::int as policy_count,
              coalesce((select lower(o.option_value) in ('true', 'on', '1', 'yes')
                          from pg_options_to_table(c.reloptions) o
                         where o.option_name = 'security_invoker'), false) as security_invoker
         from pg_class c
         join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = any($1::text[]) and c.relkind in ('r', 'p', 'v', 'm')
        order by n.nspname, c.relname`,
      [config.schemas],
    )
  ).rows.filter((r) => {
    const id = `${r.schema}.${r.name}`;
    if (config.exclude.some((p) => matchesPattern(r.name, p) || matchesPattern(id, p))) return false;
    return !tableConfig(config, r.schema, r.name).skip;
  });

  const oids = relRows.map((r) => r.oid);
  const colRows = oids.length
    ? (
        await db.query(
          `select a.attrelid::text as oid, a.attname as name, format_type(a.atttypid, a.atttypmod) as type,
                  a.attnotnull as not_null, a.atthasdef as has_default,
                  a.attgenerated::text <> '' as generated, a.attidentity::text = 'a' as identity_always,
                  exists (select 1 from pg_index i
                           where i.indrelid = a.attrelid and i.indisunique and a.attnum = any(i.indkey)) as is_unique
             from pg_attribute a
            where a.attrelid = any($1::oid[]) and a.attnum > 0 and not a.attisdropped
            order by a.attrelid, a.attnum`,
          [oids],
        )
      ).rows
    : [];
  const columnsByOid = new Map<string, Column[]>();
  for (const c of colRows) {
    const list = columnsByOid.get(c.oid) ?? [];
    list.push({
      name: c.name,
      type: c.type,
      notNull: c.not_null,
      hasDefault: c.has_default,
      generated: c.generated,
      identityAlways: c.identity_always,
      unique: c.is_unique,
    });
    columnsByOid.set(c.oid, list);
  }

  const relations: CatalogRelation[] = relRows.map((r) => {
    const columns = columnsByOid.get(r.oid) ?? [];
    const names = columns.map((c) => c.name);
    const override = tableConfig(config, r.schema, r.name);
    const shared = override.shared ?? false;
    let tenantExpr: string | null = null;
    if (!shared) {
      if (override.tenant) tenantExpr = override.tenant;
      else {
        const col = config.tenantColumns.find((c) => names.includes(c));
        if (col) tenantExpr = ident(col);
      }
    }
    return {
      oid: r.oid,
      schema: r.schema,
      name: r.name,
      id: `${r.schema}.${r.name}`,
      kind: KINDS[r.kind]!,
      owner: r.owner,
      rlsEnabled: r.rls_enabled,
      rlsForced: r.rls_forced,
      policyCount: r.policy_count,
      securityInvoker: r.security_invoker,
      tenantExpr,
      tenantColumn: tenantExpr ? plainColumn(tenantExpr, names) : null,
      shared,
      columns,
    };
  });

  const roleNames = [...new Set(config.principals.map((p) => p.role))];
  const roleRows = (
    await db.query(
      `select r.rolname as name, r.rolbypassrls or r.rolsuper as bypass,
              pg_has_role(current_user, r.oid, 'MEMBER') as can_assume
         from pg_roles r where r.rolname = any($1::text[])`,
      [roleNames],
    )
  ).rows;
  const roles = new Map<string, RoleInfo>();
  for (const name of roleNames) {
    const row = roleRows.find((r) => r.name === name);
    roles.set(name, {
      exists: Boolean(row),
      bypassRls: Boolean(row?.bypass),
      canAssume: Boolean(row?.can_assume),
    });
  }

  const privileges = new Map<string, Privileges>();
  const existingRoles = roleNames.filter((r) => roles.get(r)!.exists);
  if (oids.length && existingRoles.length) {
    const privRows = (
      await db.query(
        `select c.oid::text as oid, r.role,
                has_table_privilege(r.role, c.oid, 'SELECT') as sel,
                has_any_column_privilege(r.role, c.oid, 'UPDATE') as upd,
                has_table_privilege(r.role, c.oid, 'DELETE') as del,
                pg_has_role(r.role, c.relowner, 'USAGE') as owner_rights
           from pg_class c, unnest($2::text[]) as r(role)
          where c.oid = any($1::oid[])`,
        [oids, existingRoles],
      )
    ).rows;
    for (const p of privRows) {
      privileges.set(`${p.oid}|${p.role}`, {
        select: p.sel,
        update: p.upd,
        delete: p.del,
        ownerRights: p.owner_rights,
      });
    }
  }

  return {
    serverVersion: server.version,
    connectedAs: server.usr,
    baselineBypassesRls: server.bypass,
    relations,
    roles,
    privileges,
  };
}

/**
 * Column for the blind UPDATE probe: `SET col = DEFAULT` must not read any
 * column (reading would also apply SELECT policies and hide a permissive
 * UPDATE policy), so pick a non-unique column that accepts DEFAULT.
 */
export function blindUpdateColumn(rel: CatalogRelation): Column | null {
  const candidates = rel.columns.filter(
    (c) => !c.generated && !c.identityAlways && !c.unique && c.name !== rel.tenantColumn,
  );
  return candidates.find((c) => !c.notNull) ?? candidates.find((c) => c.hasDefault) ?? null;
}
