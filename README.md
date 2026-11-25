# pg-tenant-probe

[![CI](https://github.com/mazendrop/pg-tenant-probe/actions/workflows/ci.yml/badge.svg)](https://github.com/mazendrop/pg-tenant-probe/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Prove that Postgres row-level security keeps your tenants apart.**

In a multi-tenant app on Postgres (Supabase, PostgREST, or your own `SET ROLE` setup), one missing
or too-generous policy is enough for one customer to read another customer's data. Code review
catches some of it. `pg-tenant-probe` checks it the direct way: it signs in as each of your test
users, looks at **every table and view**, and counts the rows of *other* tenants that user can reach.

```text
$ npx pg-tenant-probe --config tenant-probe.config.json --writes

ERRORS
  ✗ RLS_DISABLED        public.tasks             RLS is disabled, yet "authenticated", "anon" can SELECT from it.
  ✗ CROSS_TENANT_READ   public.notes             "alice" can read 2 of 2 rows that belong to other tenants.
  ✗ CROSS_TENANT_READ   public.payments          "alice" can read 1 of 1 rows that belong to other tenants.
  ✗ CROSS_TENANT_WRITE  public.comments          "alice" UPDATE: targeted UPDATE: 0 foreign rows; blind UPDATE: reached 1 foreign row(s).
  ✗ CROSS_TENANT_WRITE  public.invoices          "alice" REASSIGN: could rewrite the tenant key of 2 row(s) to another tenant: the UPDATE policy does not check the new row.
  …
WARNINGS
  ! VIEW_OWNER_RIGHTS   public.project_overview  View runs with its owner's rights (security_invoker is off), so RLS on its base tables is checked against "postgres", not the caller.

MATRIX                          alice  bob  anon
  public.comments               ✗      ✗    –
  public.countries              ·      ·    ·
  public.invoice_lines          ✓      ✓    –
  public.invoices               ✗      ✗    –
  public.notes                  ✗      ✗    –
  public.payments               ✗      ✗    –
  public.project_overview       ✗      ✗    –
  public.project_overview_safe  ✓      ✓    –
  public.projects               ✓      ✓    –
  public.tasks                  ✗      ✗    ✗
  …
✓ no foreign rows reachable   ✗ leak   ? inconclusive   – no privilege   · not probed (shared/unmapped)

Result: FAIL — 27 error(s), 3 warning(s) · 34 passed · 25 leak(s) · 0 inconclusive
```

*(Output from the test fixture in [`test/fixture.sql`](test/fixture.sql): a small multi-tenant schema with deliberate mistakes.)*

## What it checks

| Check | Finds |
|---|---|
| **Cross-tenant read** | A principal can `SELECT` rows whose tenant is not theirs. Reports exact counts. |
| **Cross-tenant write** (`--writes`) | `UPDATE` / `DELETE` reach rows of other tenants, either aimed at them (`WHERE …`) or blind (no `WHERE`). |
| **Tenant reassignment** (`--writes`) | A principal can rewrite the tenant key of its rows, i.e. the `UPDATE` policy has no real `WITH CHECK`. |
| `RLS_DISABLED` | A table the app role can read has RLS switched off. |
| `OWNER_BYPASS`, `ROLE_BYPASSES_RLS` | The app role owns the table (owners skip RLS unless `FORCE`d) or has `BYPASSRLS`. |
| `VIEW_OWNER_RIGHTS` | A view without `security_invoker = true` checks RLS against its owner, not the caller. |
| `MATVIEW_EXPOSED` | A materialized view (which cannot have RLS) is readable by the app role. |
| `UNMAPPED`, `PRINCIPAL_SEES_NOTHING` | Coverage gaps: a relation with no tenant key, or a test user whose setup is wrong so every "pass" would be meaningless. |

Every result is also judged for **meaning**: if no other tenant has rows in a table, the read check is
`inconclusive`, not `pass`. "0 leaks" only counts where there was something to leak.

## Quick start

> Run it against a **staging or CI database** with seed data for at least two tenants, never production.
> All probing happens in transactions that are rolled back, but write probes still fire triggers.

```bash
npm install --save-dev pg-tenant-probe
npx pg-tenant-probe init --supabase > tenant-probe.config.json   # or: init (generic)
# edit the principals: one test user per tenant, plus an anonymous one
DATABASE_URL=postgres://postgres:…@localhost:54322/postgres npx pg-tenant-probe --writes
```

Connect as a user that bypasses RLS (a superuser, or a role with `BYPASSRLS`) and can `SET ROLE` to the roles you
probe. On a local Supabase stack that is the `postgres` user.

### Config

```jsonc
{
  "preset": "supabase",                 // role + request.jwt.claims, the way PostgREST sets them
  "schemas": ["public"],
  "tenantColumn": ["org_id", "tenant_id"], // first column found is the tenant key
  "tables": {
    "organizations": { "tenant": "id" },
    // child tables without a tenant column: an SQL expression, the row is alias r
    "invoice_items": { "tenant": "(select i.org_id from invoices i where i.id = r.invoice_id)" },
    "currencies": { "shared": true }    // visible to everyone by design
  },
  "principals": [
    { "name": "member of org A", "tenant": "<org-a-uuid>", "claims": { "sub": "<user-a-uuid>" } },
    { "name": "member of org B", "tenant": "<org-b-uuid>", "claims": { "sub": "<user-b-uuid>" } },
    { "name": "consultant in A and B", "tenants": ["<org-a-uuid>", "<org-b-uuid>"], "claims": { "sub": "<user-c-uuid>" } },
    { "name": "anonymous visitor" }
  ]
}
```

Not on Supabase? Use `role` plus `settings` (applied with `set_config(…, true)`) or raw `setup` SQL. See
[`examples/generic.config.mjs`](examples/generic.config.mjs).

| Option | Default | |
|---|---|---|
| `schemas` | `["public"]` | Schemas to scan. |
| `tenantColumn` | `"tenant_id"` | Column name(s) holding the tenant id. |
| `tables.<name>.tenant` | – | SQL expression for the tenant of a row (`r` is the row). |
| `tables.<name>.shared` / `.skip` | `false` | Lookup tables / tables to ignore. |
| `exclude` | `[]` | Relation names to ignore, `"audit_*"` style prefixes allowed. |
| `principals[].tenant(s)` | `[]` | The tenant(s) this user legitimately belongs to. Ids are compared as text. |
| `principals[].role` | Supabase: `authenticated` / `anon` | Database role to `SET LOCAL ROLE` to. |
| `principals[].claims` | – | Supabase preset: JWT claims. |
| `principals[].settings`, `.setup` | – | Session settings and raw SQL for other setups. |
| `writes` | `false` | Same as `--writes`. |
| `statementTimeoutMs` | `30000` | Per statement. |

### In CI

```yaml
- name: Tenant isolation
  run: npx pg-tenant-probe --writes --json tenant-report.json
  env:
    DATABASE_URL: ${{ env.STAGING_DATABASE_URL }}
```

Exit code `1` when anything at error level is found (`--fail-on warn` to be stricter), `2` for usage or
connection errors. On GitHub Actions a Markdown summary is added to the job page automatically.

### As a library

```ts
import pg from "pg";
import { probe, formatText } from "pg-tenant-probe";

const client = new pg.Client(process.env.DATABASE_URL); // one pinned connection, not a pool
await client.connect();
const report = await probe(client, config);
console.log(formatText(report));
expect(report.summary.leaks).toBe(0); // e.g. inside your own test suite
```

`probe()` takes anything with a `query(text, params)` method on a single session, so it also runs on
[PGlite](https://pglite.dev) for fast in-process tests (this repo's own tests do exactly that).

## How it works

For each principal, in one `REPEATABLE READ` transaction that is always rolled back:

1. **Baseline, with full rights.** For every table it records the tenant of each physical row
   (`tableoid`, `ctid`) in a temporary table. Tenant expressions are evaluated **here**, not as the
   principal. Otherwise a child table whose policy leaks would look harmless: its tenant lookup into the
   parent would itself be filtered by RLS and come back `NULL`. The fixture's `payments` table is exactly that case.
2. **Become the principal:** `SET LOCAL ROLE`, then claims and settings with `set_config(…, true)`.
3. **Read probe:** join what the principal can see against the baseline and count own / foreign /
   tenant-less rows.
4. **Write probes,** each in a savepoint that is rolled back:
   - *targeted* `UPDATE … WHERE (tableoid, ctid) IN (foreign rows)` and the same for `DELETE`;
   - *blind* `UPDATE … SET col = DEFAULT` and `DELETE` with no `WHERE`. A statement that reads no column
     is checked against the `UPDATE`/`DELETE` policies only, not the `SELECT` policies, so this catches
     `USING (true)` on writes even when reads are locked down. Anything beyond the principal's own rows is foreign.
   - *reassign:* `UPDATE … SET tenant_id = '<other tenant>'` with no `WHERE`, which only a missing or permissive
     `WITH CHECK` lets through.

Writes that fail with an error other than "permission denied" are reported as `inconclusive` with the
message, never silently as a pass.

## Limitations

- It tests the database layer: policies, grants, views. Server code that uses a service key bypasses RLS
  and needs its own tests.
- It needs seed data for at least two tenants; with one tenant there is nothing to leak, and the report says so.
- `INSERT … WITH CHECK` and `SECURITY DEFINER` functions are not probed yet.
- Views have no row identity, so their tenant expression should be a plain column.
- Tested on PostgreSQL 15, 16 and 17 and on PGlite. The Supabase preset mirrors how PostgREST passes claims.

## Development

```bash
npm install
npm test                      # PGlite: no database needed
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres npm test   # against a real server
```

## License

[MIT](LICENSE) © 2026 Mazen Abdallah
