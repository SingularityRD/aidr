-- Singularity AIDR control plane schema (Supabase Postgres)

create extension if not exists pgcrypto;

-- ── Entitlements (1 free agent + paid extras) ──────────────────────

create table if not exists public.entitlements (
  user_id uuid primary key references auth.users (id) on delete cascade,
  included_agents integer not null default 1,
  extra_agents integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists entitlements_touch_updated_at on public.entitlements;
create trigger entitlements_touch_updated_at
before update on public.entitlements
for each row execute procedure public.touch_updated_at();

-- Ensure every user starts with default entitlements (1 free agent).
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.entitlements (user_id)
  values (new.id)
  on conflict (user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- ── API keys (stored as hashes) ────────────────────────────────────

create table if not exists public.api_keys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  label text,
  key_hash text not null unique,
  revoked boolean not null default false,
  created_at timestamptz not null default now()
);

create index if not exists api_keys_user_id_idx on public.api_keys (user_id);

-- ── Agents (installations) ─────────────────────────────────────────

create table if not exists public.agents (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  iid text not null,
  agent_runtime text,
  agent_runtime_version text,
  display_name text,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  unique (user_id, iid)
);

create index if not exists agents_user_id_idx on public.agents (user_id);
create index if not exists agents_last_seen_idx on public.agents (last_seen desc);

-- ── Events (telemetry) ─────────────────────────────────────────────

create table if not exists public.events (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  agent_id uuid not null references public.agents (id) on delete cascade,
  type text not null,
  created_at timestamptz not null default now(),
  payload jsonb not null
);

create index if not exists events_agent_id_created_at_idx on public.events (agent_id, created_at desc);
create index if not exists events_user_id_created_at_idx on public.events (user_id, created_at desc);

-- ── RLS ────────────────────────────────────────────────────────────

alter table public.entitlements enable row level security;
alter table public.api_keys enable row level security;
alter table public.agents enable row level security;
alter table public.events enable row level security;

-- entitlements: owner can read
drop policy if exists entitlements_select_own on public.entitlements;
create policy entitlements_select_own
on public.entitlements for select
using (user_id = auth.uid());

-- api_keys: owner can manage (hash only; plaintext is never stored)
drop policy if exists api_keys_select_own on public.api_keys;
create policy api_keys_select_own
on public.api_keys for select
using (user_id = auth.uid());

drop policy if exists api_keys_insert_own on public.api_keys;
create policy api_keys_insert_own
on public.api_keys for insert
with check (user_id = auth.uid());

drop policy if exists api_keys_update_own on public.api_keys;
create policy api_keys_update_own
on public.api_keys for update
using (user_id = auth.uid())
with check (user_id = auth.uid());

drop policy if exists api_keys_delete_own on public.api_keys;
create policy api_keys_delete_own
on public.api_keys for delete
using (user_id = auth.uid());

-- agents: owner can read/update naming fields; inserts are typically via ingest function (service role)
drop policy if exists agents_select_own on public.agents;
create policy agents_select_own
on public.agents for select
using (user_id = auth.uid());

drop policy if exists agents_update_own on public.agents;
create policy agents_update_own
on public.agents for update
using (user_id = auth.uid())
with check (user_id = auth.uid());

-- events: owner can read; inserts are via ingest function (service role)
drop policy if exists events_select_own on public.events;
create policy events_select_own
on public.events for select
using (user_id = auth.uid());

