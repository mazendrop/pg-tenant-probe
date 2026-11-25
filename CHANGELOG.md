# Changelog

## 0.1.0 — unreleased

First version.

- Probes every table, view and materialized view in the configured schemas as each principal.
- Read probe: counts rows of other tenants a principal can see; tenant keys are resolved with the
  connecting user's rights, so a leaky child table is not mistaken for tenant-less rows.
- Write probes (`--writes`, always rolled back): targeted and blind `UPDATE` / `DELETE`, and
  tenant reassignment (a permissive `WITH CHECK`).
- Structural checks: RLS disabled, RLS without policies, owner bypass, roles with `BYPASSRLS`,
  views without `security_invoker`, exposed materialized views, unmapped relations,
  principals that see none of their own rows.
- Supabase preset (role + `request.jwt.claims` like PostgREST) and a generic mode (`SET ROLE` + settings).
- Text, Markdown (GitHub job summary) and JSON output; exit code 1 on findings for CI.
