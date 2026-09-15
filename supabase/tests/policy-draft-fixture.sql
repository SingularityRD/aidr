-- Minimal prerequisite fixture ONLY for a fresh disposable PostgreSQL database.
-- Mirrors relevant columns, FKs, grants, and the existing timestamp trigger.
\set ON_ERROR_STOP on
create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls;
create schema auth;
create table auth.users(id uuid primary key);
create table public.tenants(id uuid primary key, status text not null default 'active');
create table public.teams(id uuid primary key references public.tenants(id));
create table public.tenant_members(
  tenant_id uuid references public.tenants(id), user_id uuid references auth.users(id),
  role text not null, expires_at timestamptz, primary key(tenant_id,user_id));
create table public.team_policies(
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id), content text not null,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null,
  constraint team_policies_tenant_matches_team check (tenant_id=team_id));
create function public.touch_updated_at() returns trigger language plpgsql as $$
begin new.updated_at=now(); return new; end; $$;
create trigger team_policies_touch_updated_at before update on public.team_policies
  for each row execute procedure public.touch_updated_at();
alter table public.team_policies enable row level security;
-- Permissive fixture policies ensure direct-write denial is from migration ACLs,
-- not a missing prerequisite RLS policy accidentally masking an ACL regression.
create policy fixture_authenticated on public.team_policies to authenticated using(true) with check(true);
grant usage on schema public to anon, authenticated, service_role;
grant all on public.team_policies to authenticated;
grant all on all tables in schema public to service_role;
insert into auth.users select ('20000000-0000-0000-0000-' || lpad(n::text,12,'0'))::uuid from generate_series(1,5) n;
insert into public.tenants select ('10000000-0000-0000-0000-' || lpad(n::text,12,'0'))::uuid,'active' from generate_series(1,5) n;
update public.tenants set status='suspended' where id='10000000-0000-0000-0000-000000000003';
insert into public.teams select id from public.tenants;
insert into public.tenant_members values
 ('10000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','member',null),
 ('10000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000002','viewer',null),
 ('10000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000003','member',now()-interval '1 second'),
 ('10000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000004','admin',null),
 ('10000000-0000-0000-0000-000000000002','20000000-0000-0000-0000-000000000001','owner',null),
 ('10000000-0000-0000-0000-000000000003','20000000-0000-0000-0000-000000000001','member',null),
 ('10000000-0000-0000-0000-000000000004','20000000-0000-0000-0000-000000000001','member',null),
 ('10000000-0000-0000-0000-000000000005','20000000-0000-0000-0000-000000000001','member',null);
-- Deliberately reverse UUID order versus timestamp order to detect backfill head changes.
insert into public.team_policies(id,team_id,tenant_id,content,updated_at,updated_by) values
 ('ffffffff-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000002',E'legacy: old\r\n','2025-01-01Z','20000000-0000-0000-0000-000000000001'),
 ('00000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000002',E'legacy: newest\n','2025-02-01Z','20000000-0000-0000-0000-000000000001');
create schema draft_test;
create table draft_test.legacy_before as select * from public.team_policies;
create table draft_test.results(label text not null, passed boolean not null);
create table draft_test.rollback_probe(id integer primary key);
create table draft_test.race_outcomes(kind text not null, outcome text not null);
create function draft_test.check_result(label text, passed boolean) returns void language plpgsql as $$
begin
 insert into draft_test.results values(label,coalesce(passed,false));
 raise notice '%: %',case when coalesce(passed,false) then 'PASS' else 'FAIL' end,label;
end; $$;
create function draft_test.expect_state(label text, command text, expected text, as_role text default 'service_role') returns void language plpgsql as $$
declare actual text := '00000';
begin
 begin
   execute format('set local role %I',as_role);
   execute command;
 exception when others then get stacked diagnostics actual=returned_sqlstate;
 end;
 reset role;
 perform draft_test.check_result(label || ' [expected=' || expected || ', actual=' || actual || ']',actual=expected);
end; $$;
grant usage on schema draft_test to service_role, authenticated, anon;
grant insert, select on draft_test.results, draft_test.rollback_probe, draft_test.race_outcomes to service_role;
