-- TEST ONLY. Minimal prerequisites, not a substitute for the complete Supabase
-- migration chain. The runner applies both SHIPPED invoice migrations verbatim.
-- Roles model the API privilege boundary; only service_role bypasses RLS.
create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls;
grant usage on schema public to anon, authenticated, service_role;
-- Model broad API default privileges: the authority migration must explicitly
-- remove inherited table writes, not assume a bare PostgreSQL default ACL.
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
create schema auth;
create table auth.users (id uuid primary key);
create table public.tenants (
  id uuid primary key,
  name text not null,
  status text not null default 'active'
    check (status in ('active', 'suspended', 'closing', 'closed'))
);
create table public.tenant_members (
  tenant_id uuid not null references public.tenants(id),
  user_id uuid not null references auth.users(id),
  role text not null check (role in ('owner', 'admin', 'member', 'viewer', 'support_jit')),
  expires_at timestamptz,
  primary key (tenant_id, user_id)
);
create table public.entitlements (
  user_id uuid primary key references auth.users(id),
  tenant_id uuid not null unique references public.tenants(id),
  included_agents integer not null default 1,
  extra_agents integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table public.admin_audit_logs (
  id bigint generated always as identity primary key,
  actor_user_id uuid,
  tenant_id uuid references public.tenants(id),
  action text not null,
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
alter table public.admin_audit_logs enable row level security;
create function public.touch_updated_at() returns trigger language plpgsql as $$
begin new.updated_at := now(); return new; end;
$$;
-- Only a prerequisite for CREATE TRIGGER in the unmodified intake migration.
-- No offboarding/retention transition is executed by this regression suite.
create table public.tenant_offboarding_phase_receipts (status text);

create schema test;
grant usage on schema test to anon, authenticated, service_role;
create function test.assert(ok boolean, message text) returns void language plpgsql as $$
begin
  if ok is distinct from true then raise exception 'ASSERTION FAILED: %', message; end if;
end;
$$;
create function test.expect_error(statement text, expected_state text, expected_message text default null)
returns void language plpgsql security invoker as $$
begin
  begin
    execute statement;
  exception when others then
    if sqlstate <> expected_state or
       (expected_message is not null and sqlerrm <> expected_message) then
      raise exception 'Wrong error: expected % / %, received % / %',
        expected_state, expected_message, sqlstate, sqlerrm;
    end if;
    return;
  end;
  raise exception 'Expected error %, statement succeeded: %', expected_state, statement;
end;
$$;

-- Fixed identities are local fixtures, not real customer records.
-- tenant ...001, owner ...011, admin ...012, external finance actor ...013.
insert into auth.users values
 ('00000000-0000-0000-0000-000000000011'),
 ('00000000-0000-0000-0000-000000000012'),
 ('00000000-0000-0000-0000-000000000013');
insert into public.tenants(id, name) values
 ('00000000-0000-0000-0000-000000000001', 'finance regression');
insert into public.tenant_members(tenant_id, user_id, role) values
 ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000011', 'owner'),
 ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000012', 'admin');
insert into public.entitlements(user_id, tenant_id) values
 ('00000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-000000000001');
