-- A tiny multi-tenant app shaped like a Supabase project, with deliberate
-- mistakes. Every "✗" and "!" below must show up in the probe report.

do $$
begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end
$$;

create schema auth;
create function auth.uid() returns uuid language sql stable as $$
  select nullif(coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub'
  ), '')::uuid
$$;
grant usage on schema auth to anon, authenticated;
grant usage on schema public to anon, authenticated;

create table tenants (id text primary key, name text not null);
create table members (
  user_id uuid not null,
  tenant_id text not null references tenants,
  primary key (user_id, tenant_id)
);

-- Runs as its owner, so policies can use it without recursing into members.
create function app_tenant_ids() returns setof text
  language sql stable security definer set search_path = public as $$
  select tenant_id from members where user_id = auth.uid()
$$;

alter table tenants enable row level security;
create policy tenants_read on tenants for select to authenticated using (id in (select app_tenant_ids()));
alter table members enable row level security;
create policy members_read on members for select to authenticated using (user_id = auth.uid());

-- ✓ correct for every command
create table projects (
  id serial primary key,
  tenant_id text not null references tenants,
  name text not null,
  archived_at timestamptz
);
alter table projects enable row level security;
create policy projects_all on projects for all to authenticated
  using (tenant_id in (select app_tenant_ids()))
  with check (tenant_id in (select app_tenant_ids()));

-- ✗ write: WITH CHECK (true) lets a member move invoices into another tenant
create table invoices (id serial primary key, tenant_id text not null references tenants, total numeric not null, note text);
alter table invoices enable row level security;
create policy invoices_read on invoices for select to authenticated using (tenant_id in (select app_tenant_ids()));
create policy invoices_update on invoices for update to authenticated
  using (tenant_id in (select app_tenant_ids())) with check (true);

-- ✓ child table without a tenant column, isolated through its parent
create table invoice_lines (id serial primary key, invoice_id int not null references invoices, amount numeric not null);
alter table invoice_lines enable row level security;
create policy lines_read on invoice_lines for select to authenticated
  using (exists (select 1 from invoices i where i.id = invoice_id));

-- ✗ read: child table whose policy forgot the parent check
create table payments (id serial primary key, invoice_id int not null references invoices, amount numeric not null);
alter table payments enable row level security;
create policy payments_read on payments for select to authenticated using (true);

-- ✗ read: a policy written as "true"
create table notes (id serial primary key, tenant_id text not null references tenants, body text);
alter table notes enable row level security;
create policy notes_read on notes for select to authenticated using (true);

-- ✗ RLS never enabled
create table tasks (id serial primary key, tenant_id text not null references tenants, title text);

-- · RLS on, no policy: deny-all (reported as info)
create table audit_log (id serial primary key, tenant_id text not null, action text);
alter table audit_log enable row level security;

-- ✗ write: SELECT is isolated, but UPDATE USING (true) lets a blind UPDATE reach everyone
create table comments (id serial primary key, tenant_id text not null references tenants, body text);
alter table comments enable row level security;
create policy comments_read on comments for select to authenticated using (tenant_id in (select app_tenant_ids()));
create policy comments_update on comments for update to authenticated using (true);

-- ✗ owned by the app role, so its policies never apply
create table reports (id serial primary key, tenant_id text not null references tenants, title text);
alter table reports enable row level security;
create policy reports_read on reports for select to authenticated using (tenant_id in (select app_tenant_ids()));

-- ✓ shared lookup table (the config marks it shared)
create table countries (code text primary key, name text not null);

-- ! no tenant key and not marked shared: cannot be probed
create table feature_flags (key text primary key, enabled boolean not null default false);
alter table feature_flags enable row level security;
create policy flags_read on feature_flags for select to authenticated using (true);

-- ! ✗ a view runs with its owner's rights unless security_invoker is on
create view project_overview as select id, tenant_id, name from projects;
-- ✓ the same view with the caller's rights
create view project_overview_safe with (security_invoker = true) as select id, tenant_id, name from projects;

-- ! ✗ materialized views have no RLS at all
create materialized view invoice_totals as select tenant_id, sum(total) as total from invoices group by tenant_id;

grant select on all tables in schema public to authenticated;
grant update, delete on projects, invoices, comments, notes to authenticated;
grant select on tasks, countries to anon;
alter table reports owner to authenticated;

insert into tenants values ('acme', 'Acme GmbH'), ('globex', 'Globex AG');
insert into members values
  ('00000000-0000-0000-0000-00000000000a', 'acme'),
  ('00000000-0000-0000-0000-00000000000b', 'globex');
insert into projects (tenant_id, name) values ('acme', 'Website'), ('acme', 'App'), ('globex', 'ERP');
insert into invoices (tenant_id, total) values ('acme', 100), ('acme', 250), ('globex', 900);
insert into invoice_lines (invoice_id, amount) values (1, 60), (1, 40), (2, 250), (3, 900);
insert into payments (invoice_id, amount) values (1, 100), (3, 450);
insert into notes (tenant_id, body) values ('acme', 'a'), ('globex', 'g1'), ('globex', 'g2');
insert into tasks (tenant_id, title) values ('acme', 'call client'), ('globex', 'renew lease');
insert into audit_log (tenant_id, action) values ('acme', 'login'), ('globex', 'login');
insert into comments (tenant_id, body) values ('acme', 'ok'), ('globex', 'fine');
insert into reports (tenant_id, title) values ('acme', 'Q3'), ('globex', 'Q3');
insert into countries values ('PS', 'Palestine'), ('DE', 'Germany');
insert into feature_flags values ('beta', true);
refresh materialized view invoice_totals;
