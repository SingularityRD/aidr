-- Hybrid tenancy and control-plane admission hardening.
--
-- The control plane is shared, while tenant-scoped scans/evidence are kept
-- behind tenant_id ownership. Existing personal accounts are mapped to a
-- deterministic personal tenant (tenant_id = auth.users.id). Team tenants
-- retain teams.id as their tenant id and are mirrored into tenant_members.
--
-- This migration is additive and intentionally fails on inconsistent legacy
-- ownership rather than silently moving customer evidence between tenants.

create extension if not exists pgcrypto;
create schema if not exists app;

-- ---------------------------------------------------------------------------
-- Authoritative tenant and membership model
-- ---------------------------------------------------------------------------

create table if not exists public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  kind text not null default 'personal'
    check (kind in ('personal', 'team', 'enterprise')),
  status text not null default 'active'
    check (status in ('active', 'suspended', 'closing', 'closed')),
  created_by uuid references auth.users (id) on delete set null,
  region text,
  retention_days integer not null default 30 check (retention_days between 1 and 3650),
  created_at timestamptz not null default now(),
  closed_at timestamptz
);

create index if not exists tenants_status_idx on public.tenants (status);
create index if not exists tenants_created_by_idx on public.tenants (created_by);

create table if not exists public.tenant_members (
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null default 'member'
    check (role in ('owner', 'admin', 'member', 'viewer', 'support_jit')),
  joined_at timestamptz not null default now(),
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);

create index if not exists tenant_members_user_idx on public.tenant_members (user_id);
create index if not exists tenant_members_tenant_role_idx
  on public.tenant_members (tenant_id, role);

-- A team is also a tenant. Keep the existing team_id API stable while adding
-- a canonical tenant_id column for new APIs and RLS policies.
alter table public.teams add column if not exists tenant_id uuid;
insert into public.tenants (id, name, kind, created_at)
select t.id, t.name, 'team', t.created_at
from public.teams t
on conflict (id) do nothing;
update public.teams set tenant_id = id where tenant_id is null;
alter table public.teams alter column tenant_id set not null;
do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'teams_tenant_id_fkey'
      and conrelid = 'public.teams'::regclass
  ) then
    alter table public.teams
      add constraint teams_tenant_id_fkey
      foreign key (tenant_id) references public.tenants (id) on delete cascade;
  end if;
end;
$$;
create unique index if not exists teams_tenant_id_uniq on public.teams (tenant_id);

-- Backfill personal tenants and their owner membership. Existing production
-- projects must review this mapping before applying the migration.
insert into public.tenants (id, name, kind, created_by)
select u.id,
       coalesce(nullif(u.raw_user_meta_data ->> 'full_name', ''), 'Personal'),
       'personal',
       u.id
from auth.users u
on conflict (id) do nothing;

insert into public.tenant_members (tenant_id, user_id, role)
select u.id, u.id, 'owner'
from auth.users u
on conflict (tenant_id, user_id) do nothing;

insert into public.tenant_members (tenant_id, user_id, role, joined_at)
select tm.team_id, tm.user_id, tm.role, tm.joined_at
from public.team_members tm
on conflict (tenant_id, user_id) do update
set role = excluded.role,
    joined_at = least(public.tenant_members.joined_at, excluded.joined_at);

-- ---------------------------------------------------------------------------
-- Tenant columns and ownership backfill
-- ---------------------------------------------------------------------------

alter table public.entitlements add column if not exists tenant_id uuid;
alter table public.api_keys add column if not exists tenant_id uuid;
alter table public.agents add column if not exists tenant_id uuid;
alter table public.events add column if not exists tenant_id uuid;
alter table public.url_reputation add column if not exists tenant_id uuid;
alter table public.file_reputation add column if not exists tenant_id uuid;
alter table public.enrollment_tokens add column if not exists tenant_id uuid;
alter table public.billing_customers add column if not exists tenant_id uuid;
alter table public.subscriptions add column if not exists tenant_id uuid;
alter table public.pilot_applications add column if not exists tenant_id uuid;
alter table public.entitlement_snapshots add column if not exists tenant_id uuid;
alter table public.team_members add column if not exists tenant_id uuid;
alter table public.team_policies add column if not exists tenant_id uuid;
alter table public.audit_logs add column if not exists tenant_id uuid;
alter table public.admin_audit_logs add column if not exists tenant_id uuid;
alter table public.device_sessions add column if not exists tenant_id uuid;
alter table public.billing_webhook_events add column if not exists tenant_id uuid;
alter table public.rate_limits add column if not exists tenant_id uuid;
alter table public.pack_versions add column if not exists tenant_id uuid;
alter table public.revocations add column if not exists tenant_id uuid;
alter table public.waitlist_signups add column if not exists tenant_id uuid;

update public.entitlements set tenant_id = user_id where tenant_id is null;
update public.api_keys set tenant_id = user_id where tenant_id is null;
update public.agents set tenant_id = user_id where tenant_id is null;
update public.url_reputation set tenant_id = user_id where tenant_id is null;
update public.file_reputation set tenant_id = user_id where tenant_id is null;
update public.enrollment_tokens set tenant_id = user_id where tenant_id is null;
update public.billing_customers set tenant_id = user_id where tenant_id is null;
update public.subscriptions set tenant_id = user_id where tenant_id is null;
update public.pilot_applications set tenant_id = user_id where tenant_id is null;
update public.entitlement_snapshots set tenant_id = user_id where tenant_id is null;
update public.team_members set tenant_id = team_id where tenant_id is null;
update public.team_policies set tenant_id = team_id where tenant_id is null;
update public.audit_logs set tenant_id = team_id where tenant_id is null;
update public.admin_audit_logs a
set tenant_id = u.id
from auth.users u
where a.tenant_id is null
  and (a.target_user_id = u.id or a.actor_user_id = u.id);
update public.device_sessions set tenant_id = user_id where tenant_id is null and user_id is not null;
update public.events ev
set tenant_id = ag.tenant_id
from public.agents ag
where ev.tenant_id is null and ev.agent_id = ag.id;

do $$
begin
  if exists (
    select 1 from public.events ev
    join public.agents ag on ag.id = ev.agent_id
    where ev.tenant_id is distinct from ag.tenant_id
  ) then
    raise exception 'hybrid_tenancy: events contain cross-tenant agent references';
  end if;
  if exists (
    select 1 from public.entitlement_snapshots s
    join public.agents ag on ag.id = s.agent_id
    where s.tenant_id is distinct from ag.tenant_id
  ) then
    raise exception 'hybrid_tenancy: entitlement snapshots contain cross-tenant agents';
  end if;
end;
$$;

alter table public.entitlements alter column tenant_id set not null;
alter table public.api_keys alter column tenant_id set not null;
alter table public.agents alter column tenant_id set not null;
alter table public.events alter column tenant_id set not null;
alter table public.url_reputation alter column tenant_id set not null;
alter table public.file_reputation alter column tenant_id set not null;
alter table public.enrollment_tokens alter column tenant_id set not null;
alter table public.billing_customers alter column tenant_id set not null;
alter table public.subscriptions alter column tenant_id set not null;
alter table public.pilot_applications alter column tenant_id set not null;
alter table public.entitlement_snapshots alter column tenant_id set not null;
alter table public.team_members alter column tenant_id set not null;
alter table public.team_policies alter column tenant_id set not null;
alter table public.audit_logs alter column tenant_id set not null;

-- Entitlements are a tenant plan, not a user plan. Preserve the legacy
-- user_id owner/audit column, but make tenant_id the canonical key so one
-- user may belong to multiple team tenants with independent seats.
alter table public.entitlements drop constraint if exists entitlements_pkey;
alter table public.entitlements
  add constraint entitlements_tenant_pkey primary key (tenant_id);
do $$
begin
  if exists (
    select 1
    from public.tenants t
    where t.kind in ('team', 'enterprise')
      and not exists (
        select 1 from public.tenant_members tm
        where tm.tenant_id = t.id and tm.role = 'owner'
      )
  ) then
    raise exception 'hybrid_tenancy: team tenant without owner cannot receive entitlements';
  end if;
end;
$$;
insert into public.entitlements (user_id, tenant_id)
select tm.user_id, tm.tenant_id
from public.tenant_members tm
join public.tenants t on t.id = tm.tenant_id
where tm.role = 'owner'
on conflict (tenant_id) do nothing;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'team_members_tenant_matches_team') then
    alter table public.team_members
      add constraint team_members_tenant_matches_team check (tenant_id = team_id);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'team_policies_tenant_matches_team') then
    alter table public.team_policies
      add constraint team_policies_tenant_matches_team check (tenant_id = team_id);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'audit_logs_tenant_matches_team') then
    alter table public.audit_logs
      add constraint audit_logs_tenant_matches_team check (tenant_id = team_id);
  end if;
end;
$$;

create index if not exists entitlements_tenant_idx on public.entitlements (tenant_id);
create index if not exists api_keys_tenant_idx on public.api_keys (tenant_id);
create unique index if not exists agents_tenant_iid_uniq on public.agents (tenant_id, iid);
create index if not exists events_tenant_created_idx on public.events (tenant_id, created_at desc);
create index if not exists url_reputation_tenant_idx on public.url_reputation (tenant_id);
create index if not exists file_reputation_tenant_idx on public.file_reputation (tenant_id);
create index if not exists enrollment_tokens_tenant_idx on public.enrollment_tokens (tenant_id);
create index if not exists subscriptions_tenant_idx on public.subscriptions (tenant_id);
create index if not exists snapshots_tenant_idx on public.entitlement_snapshots (tenant_id);
create index if not exists audit_logs_tenant_idx on public.audit_logs (tenant_id, created_at desc);

create unique index if not exists agents_tenant_id_uniq on public.agents (tenant_id, id);

-- Remove legacy user-scoped uniqueness/FK pairs. A user can belong to more
-- than one team tenant, so the canonical uniqueness key is tenant + iid and
-- the composite tenant FK below is the ownership proof.
alter table public.events drop constraint if exists events_agent_owner_fkey;
drop index if exists public.agents_user_id_id_uniq;
alter table public.agents drop constraint if exists agents_user_id_iid_key;

do $$
begin
  if exists (
    select 1 from pg_constraint
    where conname = 'entitlement_snapshots_pkey'
      and conrelid = 'public.entitlement_snapshots'::regclass
  ) then
    alter table public.entitlement_snapshots drop constraint entitlement_snapshots_pkey;
  end if;
  if not exists (
    select 1 from pg_constraint
    where conname = 'entitlement_snapshots_tenant_iid_pkey'
      and conrelid = 'public.entitlement_snapshots'::regclass
  ) then
    alter table public.entitlement_snapshots
      add constraint entitlement_snapshots_tenant_iid_pkey primary key (tenant_id, iid);
  end if;
end;
$$;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'events_tenant_agent_fkey'
      and conrelid = 'public.events'::regclass
  ) then
    alter table public.events
      add constraint events_tenant_agent_fkey
      foreign key (tenant_id, agent_id)
      references public.agents (tenant_id, id)
      on delete cascade;
  end if;
  if not exists (
    select 1 from pg_constraint
    where conname = 'snapshots_tenant_agent_fkey'
      and conrelid = 'public.entitlement_snapshots'::regclass
  ) then
    alter table public.entitlement_snapshots
      add constraint snapshots_tenant_agent_fkey
      foreign key (tenant_id, agent_id)
      references public.agents (tenant_id, id)
      on delete cascade;
  end if;
end;
$$;

-- ---------------------------------------------------------------------------
-- Tenant context, immutable ownership, and membership helpers
-- ---------------------------------------------------------------------------

create or replace function app.current_tenant_id()
returns uuid
language plpgsql
stable
security definer
set search_path = public, pg_catalog
as $$
declare
  raw_claim text;
  claim_id uuid;
  caller_id uuid;
begin
  raw_claim := nullif(current_setting('request.jwt.claim.tenant_id', true), '');
  if raw_claim is not null then
    begin
      claim_id := raw_claim::uuid;
      if exists (select 1 from public.tenants where id = claim_id) then
        return claim_id;
      end if;
    exception when invalid_text_representation then
      null;
    end;
  end if;
  caller_id := auth.uid();
  if caller_id is not null and exists (select 1 from public.tenants where id = caller_id) then
    return caller_id;
  end if;
  return null;
end;
$$;

create or replace function app.is_tenant_member(p_tenant_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_catalog
as $$
  select exists (
    select 1 from public.tenant_members tm
    where tm.tenant_id = p_tenant_id
      and tm.user_id = auth.uid()
      and (tm.expires_at is null or tm.expires_at > now())
  );
$$;

create or replace function app.is_tenant_member_with_role(p_tenant_id uuid, p_min_role text)
returns boolean
language sql
stable
security definer
set search_path = public, pg_catalog
as $$
  select exists (
    select 1 from public.tenant_members tm
    where tm.tenant_id = p_tenant_id
      and tm.user_id = auth.uid()
      and (tm.expires_at is null or tm.expires_at > now())
      and tm.role = any (
        case p_min_role
          when 'owner' then array['owner']
          when 'admin' then array['owner', 'admin']
          when 'member' then array['owner', 'admin', 'member']
          when 'viewer' then array['owner', 'admin', 'member', 'viewer']
          else array[]::text[]
        end
      )
  );
$$;

create or replace function app.is_tenant_creator(p_tenant_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_catalog
as $$
  select exists (
    select 1 from public.tenants t
    where t.id = p_tenant_id and t.created_by = p_user_id
  ) and not exists (
    select 1 from public.tenant_members tm where tm.tenant_id = p_tenant_id
  );
$$;

create or replace function app.prevent_tenant_change()
returns trigger
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
begin
  if tg_op = 'UPDATE' and new.tenant_id is distinct from old.tenant_id then
    raise exception 'tenant_id is immutable';
  end if;
  return new;
end;
$$;
revoke all on function app.prevent_tenant_change() from public, anon, authenticated;

do $$
declare
  table_name text;
begin
  foreach table_name in array array[
    'entitlements','api_keys','agents','events','url_reputation','file_reputation',
    'enrollment_tokens','billing_customers','subscriptions','pilot_applications',
    'entitlement_snapshots','team_members','team_policies','audit_logs'
  ] loop
    execute format('drop trigger if exists %I on public.%I', table_name || '_tenant_immutable', table_name);
    execute format(
      'create trigger %I before update on public.%I for each row execute function app.prevent_tenant_change()',
      table_name || '_tenant_immutable', table_name
    );
  end loop;
end;
$$;

-- Mirror the legacy team_members API into canonical tenant_members rows.
create or replace function app.sync_team_member_to_tenant()
returns trigger
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
begin
  if tg_op = 'DELETE' then
    delete from public.tenant_members
    where tenant_id = old.team_id and user_id = old.user_id;
    return old;
  end if;
  insert into public.tenant_members (tenant_id, user_id, role, joined_at)
  values (new.team_id, new.user_id, new.role, new.joined_at)
  on conflict (tenant_id, user_id) do update
    set role = excluded.role,
        joined_at = excluded.joined_at;
  return new;
end;
$$;
revoke all on function app.sync_team_member_to_tenant() from public, anon, authenticated;
drop trigger if exists team_members_tenant_sync on public.team_members;
create trigger team_members_tenant_sync
after insert or update or delete on public.team_members
for each row execute function app.sync_team_member_to_tenant();

-- Team helper functions now use canonical tenant membership.
create or replace function public.is_team_member(team_id uuid)
returns boolean
language sql
stable security definer
set search_path = public, pg_catalog
as $$ select app.is_tenant_member(team_id); $$;

create or replace function public.is_team_member_with_role(team_id uuid, min_role text)
returns boolean
language sql
stable security definer
set search_path = public, pg_catalog
as $$ select app.is_tenant_member_with_role(team_id, min_role); $$;

-- Fix the old first-member policy: the previous expression compared a column
-- with itself and failed for every team after the first global membership.
drop policy if exists team_members_insert_admin on public.team_members;
create policy team_members_insert_admin
on public.team_members for insert
with check (
  app.is_tenant_creator(team_id, user_id)
  or app.is_tenant_member_with_role(team_id, 'admin')
);

-- Canonical tenant membership policies.
alter table public.tenants enable row level security;
alter table public.tenant_members enable row level security;
drop policy if exists tenants_select_member on public.tenants;
create policy tenants_select_member on public.tenants for select
using (app.is_tenant_member(id));
drop policy if exists tenants_insert_authenticated on public.tenants;
create policy tenants_insert_authenticated on public.tenants for insert
with check (auth.uid() = created_by and auth.role() = 'authenticated');
drop policy if exists tenants_update_admin on public.tenants;
create policy tenants_update_admin on public.tenants for update
using (app.is_tenant_member_with_role(id, 'admin'))
with check (app.is_tenant_member_with_role(id, 'admin'));
drop policy if exists tenant_members_select_member on public.tenant_members;
create policy tenant_members_select_member on public.tenant_members for select
using (app.is_tenant_member(tenant_id));
drop policy if exists tenant_members_insert_admin on public.tenant_members;
create policy tenant_members_insert_admin on public.tenant_members for insert
with check (
  app.is_tenant_creator(tenant_id, user_id)
  or app.is_tenant_member_with_role(tenant_id, 'admin')
);
drop policy if exists tenant_members_update_admin on public.tenant_members;
create policy tenant_members_update_admin on public.tenant_members for update
using (app.is_tenant_member_with_role(tenant_id, 'admin'))
with check (app.is_tenant_member_with_role(tenant_id, 'admin'));
drop policy if exists tenant_members_delete_admin on public.tenant_members;
create policy tenant_members_delete_admin on public.tenant_members for delete
using (app.is_tenant_member_with_role(tenant_id, 'admin'));

-- Tenant RLS policies for all user-owned resources. Existing user_id policies
-- remain compatible for personal tenants, while these policies protect team
-- tenants and prevent a user from choosing a foreign tenant_id on writes.
alter table public.entitlements enable row level security;
alter table public.api_keys enable row level security;
alter table public.agents enable row level security;
alter table public.events enable row level security;
alter table public.url_reputation enable row level security;
alter table public.file_reputation enable row level security;
alter table public.enrollment_tokens enable row level security;
alter table public.billing_customers enable row level security;
alter table public.subscriptions enable row level security;
alter table public.pilot_applications enable row level security;
alter table public.entitlement_snapshots enable row level security;
alter table public.team_members enable row level security;
alter table public.team_policies enable row level security;
alter table public.audit_logs enable row level security;

drop policy if exists tenant_entitlements_select on public.entitlements;
create policy tenant_entitlements_select on public.entitlements for select
using (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id));
drop policy if exists tenant_api_keys_select on public.api_keys;
create policy tenant_api_keys_select on public.api_keys for select
using (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id));
drop policy if exists tenant_api_keys_insert on public.api_keys;
create policy tenant_api_keys_insert on public.api_keys for insert
with check (tenant_id = app.current_tenant_id() and app.is_tenant_member_with_role(tenant_id, 'member'));
drop policy if exists tenant_api_keys_update on public.api_keys;
create policy tenant_api_keys_update on public.api_keys for update
using (tenant_id = app.current_tenant_id() and app.is_tenant_member_with_role(tenant_id, 'member'))
with check (tenant_id = app.current_tenant_id() and app.is_tenant_member_with_role(tenant_id, 'member'));
drop policy if exists tenant_api_keys_delete on public.api_keys;
create policy tenant_api_keys_delete on public.api_keys for delete
using (tenant_id = app.current_tenant_id() and app.is_tenant_member_with_role(tenant_id, 'member'));

drop policy if exists tenant_agents_select on public.agents;
create policy tenant_agents_select on public.agents for select
using (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id));
drop policy if exists tenant_agents_update on public.agents;
create policy tenant_agents_update on public.agents for update
using (tenant_id = app.current_tenant_id() and app.is_tenant_member_with_role(tenant_id, 'member'))
with check (tenant_id = app.current_tenant_id() and app.is_tenant_member_with_role(tenant_id, 'member'));

drop policy if exists tenant_events_select on public.events;
create policy tenant_events_select on public.events for select
using (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id));

do $$
declare
  table_name text;
begin
  foreach table_name in array array[
    'url_reputation','file_reputation','enrollment_tokens','billing_customers',
    'subscriptions','pilot_applications','entitlement_snapshots'
  ] loop
    execute format('drop policy if exists tenant_%I_select on public.%I', table_name, table_name);
    execute format(
      'create policy tenant_%I_select on public.%I for select using (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id))',
      table_name, table_name
    );
  end loop;
end;
$$;

drop policy if exists tenant_url_reputation_insert on public.url_reputation;
create policy tenant_url_reputation_insert on public.url_reputation for insert
with check (tenant_id = app.current_tenant_id() and app.is_tenant_member_with_role(tenant_id, 'member'));
drop policy if exists tenant_file_reputation_insert on public.file_reputation;
create policy tenant_file_reputation_insert on public.file_reputation for insert
with check (tenant_id = app.current_tenant_id() and app.is_tenant_member_with_role(tenant_id, 'member'));

drop policy if exists tenant_team_policies_select on public.team_policies;
create policy tenant_team_policies_select on public.team_policies for select
using (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id));
drop policy if exists tenant_team_policies_insert on public.team_policies;
create policy tenant_team_policies_insert on public.team_policies for insert
with check (tenant_id = app.current_tenant_id() and app.is_tenant_member_with_role(tenant_id, 'member'));
drop policy if exists tenant_team_policies_update on public.team_policies;
create policy tenant_team_policies_update on public.team_policies for update
using (tenant_id = app.current_tenant_id() and app.is_tenant_member_with_role(tenant_id, 'member'))
with check (tenant_id = app.current_tenant_id() and app.is_tenant_member_with_role(tenant_id, 'member'));

drop policy if exists tenant_audit_logs_select on public.audit_logs;
create policy tenant_audit_logs_select on public.audit_logs for select
using (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id));

-- Rebind derived dashboard views to tenant ownership. The original views
-- counted by user_id, which would mix a user's personal and team tenants.
create or replace view public.seat_usage
with (security_invoker = true)
as
select
  e.user_id,
  e.included_agents,
  e.extra_agents,
  (e.included_agents + e.extra_agents) as allowed_agents,
  (
    select count(*)::int
    from public.agents a
    where a.tenant_id = e.tenant_id
  ) as current_agents,
  e.tenant_id
from public.entitlements e;

create or replace view public.incident_events
with (security_invoker = true)
as
select
  ev.id,
  ev.user_id,
  ev.agent_id,
  ev.type,
  ev.created_at,
  ev.payload,
  ev.tenant_id
from public.events ev
where
  ev.type = 'incident'
  or (
    ev.type = 'runtime_verdict'
    and (ev.payload->>'verdict') in ('deny', 'ask')
  )
  or (
    ev.type = 'plugin_scan'
    and coalesce(nullif(ev.payload->>'findings_count','')::int, 0) > 0
  );
grant select on public.seat_usage, public.incident_events to authenticated;

-- ---------------------------------------------------------------------------
-- Atomic admission/idempotency operations used by Edge Functions
-- ---------------------------------------------------------------------------

create or replace function public.authorize_device_session(
  p_user_code text,
  p_user_id uuid,
  p_tenant_id uuid default null
)
returns table (id uuid, user_id uuid, tenant_id uuid, expires_at timestamptz)
language sql
security definer
set search_path = public, pg_catalog
as $$
  update public.device_sessions d
  set user_id = p_user_id,
      tenant_id = coalesce(p_tenant_id, p_user_id),
      authorized_at = now(),
      status = 'authorized'
  where d.user_code = upper(trim(p_user_code))
    and d.authorized_at is null
    and d.expires_at > now()
  returning d.id, d.user_id, d.tenant_id, d.expires_at;
$$;

create or replace function public.exchange_device_session(p_device_code_hash text)
returns table (id uuid, user_id uuid, tenant_id uuid, expires_at timestamptz, user_code text)
language sql
security definer
set search_path = public, pg_catalog
as $$
  update public.device_sessions d
  set exchanged_at = now(), status = 'exchanged'
  where d.device_code_hash = p_device_code_hash
    and d.user_id is not null
    and d.exchanged_at is null
    and d.expires_at > now()
  returning d.id, d.user_id, d.tenant_id, d.expires_at, d.user_code;
$$;

create or replace function public.register_agent_for_ingest(
  p_user_id uuid,
  p_iid text,
  p_agent_runtime text default null,
  p_agent_runtime_version text default null,
  p_tenant_id uuid default null
)
returns table (
  agent_id uuid,
  tenant_id uuid,
  created boolean,
  current_agents integer,
  allowed_agents integer,
  seat_exceeded boolean
)
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_tenant_id uuid := coalesce(p_tenant_id, p_user_id);
  v_allowed integer := 1;
  v_current integer := 0;
  v_agent_id uuid;
  v_included integer;
  v_extra integer;
begin
  if p_user_id is null or nullif(trim(p_iid), '') is null then
    raise exception 'invalid agent identity';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 0));
  select e.included_agents, e.extra_agents
    into v_included, v_extra
    from public.entitlements e
   where e.tenant_id = v_tenant_id
   for update;
  v_allowed := greatest(0, coalesce(v_included, 1) + coalesce(v_extra, 0));
  select a.id into v_agent_id
    from public.agents a
   where a.tenant_id = v_tenant_id and a.iid = trim(p_iid)
   limit 1;
  select count(*)::integer into v_current
    from public.agents a where a.tenant_id = v_tenant_id;
  if v_agent_id is null and v_current >= v_allowed then
    return query select null::uuid, v_tenant_id, false, v_current, v_allowed, true;
    return;
  end if;
  if v_agent_id is null then
    insert into public.agents (user_id, tenant_id, iid, agent_runtime, agent_runtime_version, last_seen)
    values (p_user_id, v_tenant_id, trim(p_iid), p_agent_runtime, p_agent_runtime_version, now())
    returning id into v_agent_id;
    v_current := v_current + 1;
    return query select v_agent_id, v_tenant_id, true, v_current, v_allowed, false;
    return;
  end if;
  update public.agents
     set agent_runtime = coalesce(p_agent_runtime, agent_runtime),
         agent_runtime_version = coalesce(p_agent_runtime_version, agent_runtime_version),
         last_seen = now()
   where id = v_agent_id;
  return query select v_agent_id, v_tenant_id, false, v_current, v_allowed, false;
end;
$$;

create or replace function public.record_billing_webhook_event(
  p_provider text,
  p_event_id text,
  p_payload jsonb,
  p_tenant_id uuid default null
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
begin
  insert into public.billing_webhook_events (provider, event_id, payload, tenant_id)
  values (p_provider, p_event_id, p_payload, p_tenant_id)
  on conflict (event_id) do nothing;
  return found;
end;
$$;

-- Extend the atomic enrollment exchange with the canonical tenant id. The
-- function signature is dropped/recreated because PostgreSQL does not allow
-- CREATE OR REPLACE to change a RETURNS TABLE definition.
drop function if exists public.consume_enrollment_token(text);
create function public.consume_enrollment_token(p_token_hash text)
returns table (id uuid, user_id uuid, tenant_id uuid, expires_at timestamptz)
language sql
security definer
set search_path = public, pg_catalog
as $$
  update public.enrollment_tokens
  set consumed_at = now()
  where token_hash = p_token_hash
    and consumed_at is null
    and expires_at > now()
  returning enrollment_tokens.id,
            enrollment_tokens.user_id,
            enrollment_tokens.tenant_id,
            enrollment_tokens.expires_at;
$$;
revoke all on function public.consume_enrollment_token(text) from public, anon, authenticated;
grant execute on function public.consume_enrollment_token(text) to service_role;

-- ---------------------------------------------------------------------------
-- Grants and SECURITY DEFINER execution boundaries
-- ---------------------------------------------------------------------------

grant usage on schema public, app to authenticated, service_role;
alter default privileges for role postgres in schema public
  grant all on tables to service_role;
alter default privileges for role postgres in schema public
  grant usage, select on sequences to service_role;
alter default privileges for role postgres in schema public
  revoke execute on functions from public;

grant all privileges on all tables in schema public to service_role;
grant usage, select on all sequences in schema public to service_role;
grant execute on function public.authorize_device_session(text, uuid, uuid) to service_role;
grant execute on function public.exchange_device_session(text) to service_role;
grant execute on function public.register_agent_for_ingest(uuid, text, text, text, uuid) to service_role;
grant execute on function public.record_billing_webhook_event(text, text, jsonb, uuid) to service_role;
grant execute on function public.consume_enrollment_token(text) to service_role;
revoke all on function public.authorize_device_session(text, uuid, uuid) from public, anon, authenticated;
revoke all on function public.exchange_device_session(text) from public, anon, authenticated;
revoke all on function public.register_agent_for_ingest(uuid, text, text, text, uuid) from public, anon, authenticated;
revoke all on function public.record_billing_webhook_event(text, text, jsonb, uuid) from public, anon, authenticated;
grant execute on function public.authorize_device_session(text, uuid, uuid) to service_role;
grant execute on function public.exchange_device_session(text) to service_role;
grant execute on function public.register_agent_for_ingest(uuid, text, text, text, uuid) to service_role;
grant execute on function public.record_billing_webhook_event(text, text, jsonb, uuid) to service_role;

-- Authenticated users receive only the table operations represented by the
-- RLS policies. Public/anon never receives direct customer-table DML.
grant select on public.tenants, public.tenant_members,
  public.entitlements, public.api_keys, public.agents, public.events,
  public.url_reputation, public.file_reputation, public.enrollment_tokens,
  public.billing_customers, public.subscriptions, public.pilot_applications,
  public.entitlement_snapshots, public.team_members, public.team_policies,
  public.audit_logs to authenticated;
grant insert, update, delete on public.api_keys, public.url_reputation,
  public.file_reputation, public.enrollment_tokens, public.team_members,
  public.team_policies, public.teams to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- Security-definer helpers are never public RPC endpoints.
revoke all on function public.increment_rate_limit(text, bigint, integer) from public, anon, authenticated;
grant execute on function public.increment_rate_limit(text, bigint, integer) to service_role;
revoke all on function public.user_id_by_email(text) from public, anon, authenticated;
grant execute on function public.user_id_by_email(text) to service_role;
revoke all on function public.consume_enrollment_token(text) from public, anon, authenticated;
revoke all on function app.current_tenant_id() from public, anon;
grant execute on function app.current_tenant_id() to authenticated, service_role;
revoke all on function app.is_tenant_member(uuid) from public, anon;
grant execute on function app.is_tenant_member(uuid) to authenticated, service_role;
revoke all on function app.is_tenant_member_with_role(uuid, text) from public, anon;
grant execute on function app.is_tenant_member_with_role(uuid, text) to authenticated, service_role;
revoke all on function app.is_tenant_creator(uuid, uuid) from public, anon;
grant execute on function app.is_tenant_creator(uuid, uuid) to authenticated, service_role;
revoke all on function public.is_team_member(uuid) from public, anon;
grant execute on function public.is_team_member(uuid) to authenticated, service_role;
revoke all on function public.is_team_member_with_role(uuid, text) from public, anon;
grant execute on function public.is_team_member_with_role(uuid, text) to authenticated, service_role;

-- New users receive both a personal tenant and default entitlements. Keep the
-- existing trigger name so this remains compatible with deployed projects.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
begin
  insert into public.tenants (id, name, kind, created_by)
  values (new.id, coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), 'Personal'), 'personal', new.id)
  on conflict (id) do nothing;
  insert into public.tenant_members (tenant_id, user_id, role)
  values (new.id, new.id, 'owner')
  on conflict (tenant_id, user_id) do nothing;
  insert into public.entitlements (user_id, tenant_id)
  values (new.id, new.id)
  on conflict (tenant_id) do nothing;
  return new;
end;
$$;
revoke all on function public.handle_new_user() from public, anon, authenticated;

-- The legacy team bootstrap trigger runs immediately after handle_new_user.
-- teams.tenant_id is now mandatory, so create the canonical team tenant and
-- use the same UUID for teams.id/teams.tenant_id before inserting membership.
create or replace function public.handle_new_user_team()
returns trigger
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_team_id uuid := gen_random_uuid();
begin
  insert into public.tenants (id, name, kind, created_by)
  values (
    v_team_id,
    coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), 'Personal'),
    'team',
    new.id
  );
  insert into public.teams (id, tenant_id, name)
  values (
    v_team_id,
    v_team_id,
    coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), 'Personal')
  );
  insert into public.team_members (team_id, tenant_id, user_id, role)
  values (v_team_id, v_team_id, new.id, 'owner');
  return new;
end;
$$;
revoke all on function public.handle_new_user_team() from public, anon, authenticated;
