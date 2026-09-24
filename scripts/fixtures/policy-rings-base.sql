-- Minimal PRE-runtime-policy base for test-policy-rings-postgres.mjs only.
-- Modeled from 20260327000000_initial.sql, 20260327000200_golive_v1.sql,
-- 20260805000000_hybrid_tenancy.sql and API-key columns from
-- 20260915000000_key_rotation_overlap.sql. Policy tables, FK constraints,
-- triggers, grants and RPCs are installed by the ACTUAL policy migrations.
-- Limits: not a full Supabase bootstrap; auth.users is identity-only;
-- entitlement/pilot rows only satisfy the seed, not licensing; unrelated
-- billing/enrollment/telemetry tables, tenant RLS, resource quotas and
-- lifecycle triggers are absent. No HTTP/JWT/Edge or host claims are tested.
-- service_role has Supabase's BYPASSRLS behavior; anon/authenticated do not.
create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls;
create schema auth;
create schema app;
grant usage on schema public, auth, app to anon, authenticated, service_role;
create table auth.users (id uuid primary key);
create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  status text not null default 'active' check (status in ('active','suspended','closing','closed'))
);
create table public.tenant_members (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','admin','member','viewer','support_jit')),
  expires_at timestamptz,
  primary key (tenant_id,user_id)
);
create table public.entitlements (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  included_agents integer not null default 1
);
create table public.pilot_applications (
  user_id uuid not null references auth.users(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  status text not null default 'pending',
  primary key (user_id,tenant_id)
);
create table public.agents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  user_id uuid not null references auth.users(id) on delete cascade,
  iid text not null,
  unique (tenant_id,iid)
);
create table public.api_keys (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  user_id uuid not null references auth.users(id) on delete cascade,
  key_hash text not null unique,
  revoked boolean not null default false,
  previous_hash text,
  previous_hash_expires_at timestamptz,
  rotated_at timestamptz
);
create table public.admin_audit_logs (
  id bigint generated always as identity primary key,
  actor_user_id uuid references auth.users(id),
  tenant_id uuid references public.tenants(id),
  action text not null,
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create function public.touch_updated_at() returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;
