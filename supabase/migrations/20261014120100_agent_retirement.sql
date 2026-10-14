-- Agent retirement: free seats held by decommissioned or long-offline devices (C8).
--
-- Before this migration a seat was never released: every `public.agents` row
-- counted against the tenant's admitted capacity forever, so a reinstalled
-- workstation, a new user profile or a non-persistent VDI desktop consumed a
-- new seat each time and the tenant eventually hit `agent_limit_exceeded`.
--
--   * `agents.retired_at` / `retired_reason` / `retired_by` mark a retired
--     device. Only `public.retire_agent` (owner/admin, called by the
--     agent-lifecycle Edge function after session, identity-barrier, role and
--     AAL2 checks) and `public.retire_offline_agents` (scheduled maintenance)
--     set them; a guard trigger refuses any other writer.
--   * Retiring revokes every API key bound to that agent (the device key the
--     enrollment issued), so the device stops syncing immediately. Its local
--     detection is unaffected. A Browser Guard installation is unlinked from
--     its shared ingest key so the key's install slot is free again.
--   * `agent_retirement_settings.auto_retire_offline_days` (7..365, null = off)
--     retires active agents whose `last_seen` is older than that many days.
--   * Seat counting (`register_agent_for_ingest`, the events seat trigger,
--     `seat_usage`, `get_tenant_plan`, `operator_tenant_usage`) counts active,
--     non-retired agents only.
--   * Re-enrollment of the same installation id (iid) reuses its row: an
--     active agent keeps its seat; a retired agent becomes active again only
--     when a seat is free, and is ranked as the newest agent (its `first_seen`
--     is reset) so it can never displace a device that took the seat meanwhile.
--
-- Additive: new columns/table/functions; redefined functions keep their
-- signatures and grants.

alter table public.agents
  add column if not exists retired_at timestamptz,
  add column if not exists retired_reason text,
  add column if not exists retired_by uuid references auth.users(id) on delete set null;

alter table public.agents drop constraint if exists agents_retirement_check;
alter table public.agents add constraint agents_retirement_check check (
  (retired_at is null and retired_reason is null and retired_by is null)
  or (retired_at is not null and retired_reason in ('manual', 'offline')
      and (retired_reason = 'manual' or retired_by is null))
);

create index if not exists agents_tenant_active_seat_rank_idx
  on public.agents (tenant_id, first_seen, id) where retired_at is null;
create index if not exists agents_tenant_active_last_seen_idx
  on public.agents (tenant_id, last_seen) where retired_at is null;

-- Only the lifecycle functions below may change retirement state. They set a
-- transaction-local flag; every other writer (including service_role
-- PostgREST updates) is refused, so a retired device cannot be silently
-- re-admitted around the seat check.
create or replace function app.guard_agent_retirement()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
begin
  if (new.retired_at, new.retired_reason, new.retired_by)
       is distinct from (old.retired_at, old.retired_reason, old.retired_by)
     and coalesce(current_setting('aidr.agent_lifecycle', true), '') <> 'on' then
    raise exception 'agent_retirement_protected' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.guard_agent_retirement() from public, anon, authenticated, service_role;

drop trigger if exists agents_retirement_guard on public.agents;
create trigger agents_retirement_guard
before update of retired_at, retired_reason, retired_by on public.agents
for each row execute function app.guard_agent_retirement();

create or replace function app.guard_agent_retirement_insert()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
begin
  if new.retired_at is not null or new.retired_reason is not null or new.retired_by is not null then
    raise exception 'agent_retirement_protected' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.guard_agent_retirement_insert() from public, anon, authenticated, service_role;

drop trigger if exists agents_retirement_insert_guard on public.agents;
create trigger agents_retirement_insert_guard
before insert on public.agents
for each row execute function app.guard_agent_retirement_insert();

create table if not exists public.agent_retirement_settings (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  auto_retire_offline_days integer
    check (auto_retire_offline_days is null or auto_retire_offline_days between 7 and 365),
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default clock_timestamp()
);
alter table public.agent_retirement_settings enable row level security;
revoke all on public.agent_retirement_settings from public, anon, authenticated, service_role;
grant select on public.agent_retirement_settings to authenticated, service_role;
drop policy if exists agent_retirement_settings_member_read on public.agent_retirement_settings;
create policy agent_retirement_settings_member_read on public.agent_retirement_settings
  for select to authenticated
  using (app.is_tenant_member(tenant_id) and public.tenant_identity_access_allowed(tenant_id));
drop policy if exists tenant_identity_access_restrict on public.agent_retirement_settings;
create policy tenant_identity_access_restrict on public.agent_retirement_settings
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- Seat registration: count and rank active agents only. A retired row with the
-- same iid is re-admitted only into a free seat and ranks as the newest agent.
create or replace function public.register_agent_for_ingest(
  p_user_id uuid,
  p_iid text,
  p_agent_runtime text default null,
  p_agent_runtime_version text default null,
  p_tenant_id uuid default null
)
returns table(agent_id uuid, tenant_id uuid, created boolean, current_agents integer,
  allowed_agents integer, seat_exceeded boolean)
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_tenant_id uuid := coalesce(p_tenant_id, p_user_id);
  v_allowed integer;
  v_current integer;
  v_agent_id uuid;
  v_retired_at timestamptz;
  v_retired_reason text;
  v_agent_rank bigint;
begin
  if p_user_id is null or nullif(trim(p_iid), '') is null then
    raise exception 'invalid agent identity';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 0));
  v_allowed := public.tenant_admission_capacity(v_tenant_id);
  select a.id, a.retired_at, a.retired_reason into v_agent_id, v_retired_at, v_retired_reason
    from public.agents a
    where a.tenant_id = v_tenant_id and a.iid = trim(p_iid) for update;
  select count(*)::integer into v_current from public.agents a
    where a.tenant_id = v_tenant_id and a.retired_at is null;
  if v_allowed < 1 then
    return query select null::uuid, v_tenant_id, false, v_current, v_allowed, true;
    return;
  end if;
  if (v_agent_id is null or v_retired_at is not null) and v_current >= v_allowed then
    return query select null::uuid, v_tenant_id, false, v_current, v_allowed, true;
    return;
  end if;
  if v_agent_id is null then
    insert into public.agents
      (user_id, tenant_id, iid, agent_runtime, agent_runtime_version, last_seen)
    values (p_user_id, v_tenant_id, trim(p_iid), p_agent_runtime,
      p_agent_runtime_version, clock_timestamp())
    returning id into v_agent_id;
    v_current := v_current + 1;
    return query select v_agent_id, v_tenant_id, true, v_current, v_allowed, false;
    return;
  end if;
  if v_retired_at is not null then
    -- Same installation id re-enrolled (or reporting again) after retirement:
    -- take a free seat as the newest agent.
    perform set_config('aidr.agent_lifecycle', 'on', true);
    update public.agents
       set retired_at = null, retired_reason = null, retired_by = null,
           first_seen = clock_timestamp(),
           agent_runtime = coalesce(p_agent_runtime, agent_runtime),
           agent_runtime_version = coalesce(p_agent_runtime_version, agent_runtime_version),
           last_seen = clock_timestamp()
     where id = v_agent_id;
    perform set_config('aidr.agent_lifecycle', '', true);
    insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values (p_user_id, v_tenant_id, p_user_id, 'agent.reactivated',
      jsonb_build_object('agent_id', v_agent_id, 'iid', trim(p_iid),
        'previous_retired_reason', v_retired_reason, 'previous_retired_at', v_retired_at));
    v_current := v_current + 1;
    return query select v_agent_id, v_tenant_id, false, v_current, v_allowed, false;
    return;
  end if;
  if v_current > v_allowed then
    select ranked.agent_rank into v_agent_rank from (
      select a.id, row_number() over (order by a.first_seen, a.id) agent_rank
        from public.agents a where a.tenant_id = v_tenant_id and a.retired_at is null
    ) ranked where ranked.id = v_agent_id;
    if v_agent_rank is null or v_agent_rank > v_allowed then
      return query select null::uuid, v_tenant_id, false, v_current, v_allowed, true;
      return;
    end if;
  end if;
  update public.agents
     set agent_runtime = coalesce(p_agent_runtime, agent_runtime),
         agent_runtime_version = coalesce(p_agent_runtime_version, agent_runtime_version),
         last_seen = clock_timestamp()
   where id = v_agent_id;
  return query select v_agent_id, v_tenant_id, false, v_current, v_allowed, false;
end;
$$;

-- Events: a retired agent has no seat; rank among active agents only.
create or replace function app.enforce_event_seat_admission()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_allowed integer;
  v_first_seen timestamptz;
  v_retired_at timestamptz;
  v_prior bigint;
  v_existing_agent uuid;
  v_existing_user uuid;
begin
  if new.tenant_id is null or new.agent_id is null then
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 0));
  if (select mode from app.tenant_admission_config where singleton) = 'pilot' then
    -- Pilot approval writes the application before the entitlement row.
    v_allowed := public.tenant_admission_capacity(new.tenant_id);
  end if;
  perform 1 from public.entitlements e
    where e.tenant_id = new.tenant_id for update;
  if not found then
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;
  select a.first_seen, a.retired_at into v_first_seen, v_retired_at from public.agents a
    where a.id = new.agent_id and a.tenant_id = new.tenant_id
      and a.user_id = new.user_id for key share;
  if not found or v_retired_at is not null then
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;
  if v_allowed is null then
    v_allowed := public.tenant_admission_capacity(new.tenant_id);
  end if;
  if v_allowed < 1 then
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;
  select ev.agent_id, ev.user_id into v_existing_agent, v_existing_user
    from public.events ev
   where ev.tenant_id = new.tenant_id and ev.event_id = new.event_id
   for share;
  if found then
    if v_existing_agent = new.agent_id and v_existing_user = new.user_id then
      return new;
    end if;
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;
  select count(*) into v_prior from public.agents a
   where a.tenant_id = new.tenant_id and a.retired_at is null
     and (a.first_seen, a.id) < (v_first_seen, new.agent_id);
  if v_prior >= v_allowed then
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;
  return new;
end;
$$;

-- Shared retirement step. Caller holds the tenant lock and has authorized the
-- action. Revokes the agent's bound keys and frees its Browser Guard install
-- slot; returns the number of keys revoked.
create or replace function app.retire_agent_row(
  p_tenant_id uuid, p_agent_id uuid, p_reason text, p_actor_user_id uuid
)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_revoked integer;
begin
  perform set_config('aidr.agent_lifecycle', 'on', true);
  update public.agents
     set retired_at = clock_timestamp(), retired_reason = p_reason,
         retired_by = case when p_reason = 'manual' then p_actor_user_id else null end
   where id = p_agent_id and tenant_id = p_tenant_id and retired_at is null;
  perform set_config('aidr.agent_lifecycle', '', true);
  with revoked as (
    update public.api_keys set revoked = true
     where tenant_id = p_tenant_id and agent_id = p_agent_id and revoked = false
    returning 1
  ) select count(*)::integer into v_revoked from revoked;
  delete from public.api_key_ingest_installations
   where tenant_id = p_tenant_id and agent_id = p_agent_id;
  return v_revoked;
end;
$$;
revoke all on function app.retire_agent_row(uuid, uuid, text, uuid)
  from public, anon, authenticated, service_role;

create or replace function public.retire_agent(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_agent_id uuid,
  p_note text default null
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_agent public.agents%rowtype;
  v_revoked integer;
  v_note text := nullif(trim(coalesce(p_note, '')), '');
begin
  if p_actor_user_id is null or p_tenant_id is null or p_agent_id is null
     or (v_note is not null and (length(v_note) > 200 or v_note ~ '[[:cntrl:]]')) then
    raise exception 'invalid_agent_retirement' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
  perform 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
     and m.role in ('owner', 'admin')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m;
  if not found then
    raise exception 'agent_retirement_forbidden' using errcode = '42501';
  end if;
  select * into v_agent from public.agents
   where id = p_agent_id and tenant_id = p_tenant_id for update;
  if not found then
    raise exception 'agent_not_found' using errcode = 'P0002';
  end if;
  if v_agent.retired_at is not null then
    return jsonb_build_object('status', 'already_retired', 'agent_id', p_agent_id,
      'retired_at', v_agent.retired_at, 'retired_reason', v_agent.retired_reason);
  end if;
  v_revoked := app.retire_agent_row(p_tenant_id, p_agent_id, 'manual', p_actor_user_id);
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_actor_user_id, p_tenant_id, v_agent.user_id, 'agent.retired',
    jsonb_build_object('agent_id', p_agent_id, 'iid', v_agent.iid, 'reason', 'manual',
      'note', v_note, 'revoked_keys', v_revoked, 'last_seen', v_agent.last_seen));
  return jsonb_build_object('status', 'retired', 'agent_id', p_agent_id,
    'revoked_keys', v_revoked, 'retired_reason', 'manual');
end;
$$;
revoke all on function public.retire_agent(uuid, uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.retire_agent(uuid, uuid, uuid, text) to service_role;

create or replace function public.set_agent_auto_retirement(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_days integer
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_before integer;
begin
  if p_actor_user_id is null or p_tenant_id is null
     or (p_days is not null and p_days not between 7 and 365) then
    raise exception 'invalid_agent_auto_retirement' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
  perform 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
     and m.role in ('owner', 'admin')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m;
  if not found then
    raise exception 'agent_retirement_forbidden' using errcode = '42501';
  end if;
  select auto_retire_offline_days into v_before
    from public.agent_retirement_settings where tenant_id = p_tenant_id for update;
  insert into public.agent_retirement_settings(tenant_id, auto_retire_offline_days, updated_by, updated_at)
  values (p_tenant_id, p_days, p_actor_user_id, clock_timestamp())
  on conflict (tenant_id) do update
    set auto_retire_offline_days = excluded.auto_retire_offline_days,
        updated_by = excluded.updated_by, updated_at = excluded.updated_at;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, 'agent.auto_retirement_configured',
    jsonb_build_object('before_days', v_before, 'after_days', p_days));
  return jsonb_build_object('status', 'configured', 'auto_retire_offline_days', p_days);
end;
$$;
revoke all on function public.set_agent_auto_retirement(uuid, uuid, integer) from public, anon, authenticated;
grant execute on function public.set_agent_auto_retirement(uuid, uuid, integer) to service_role;

-- Scheduled sweep: retire active agents not seen for each tenant's configured
-- number of days. A tenant whose lock is busy is skipped and reported, never
-- waited on. Dry runs only count.
create or replace function public.retire_offline_agents(p_limit integer default 1000, p_apply boolean default false)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_limit integer := least(greatest(coalesce(p_limit, 1000), 1), 10000);
  v_apply boolean := coalesce(p_apply, false);
  v_tenant record;
  v_agent record;
  v_eligible integer := 0;
  v_retired integer := 0;
  v_contended integer := 0;
  v_remaining integer := 0;
  v_revoked integer;
begin
  for v_tenant in
    select s.tenant_id, s.auto_retire_offline_days as days
      from public.agent_retirement_settings s
      join public.tenants t on t.id = s.tenant_id and t.status = 'active'
     where s.auto_retire_offline_days is not null
     order by s.tenant_id
  loop
    if v_apply and not pg_try_advisory_xact_lock(hashtextextended(v_tenant.tenant_id::text, 0)) then
      v_contended := v_contended + 1;
      continue;
    end if;
    for v_agent in
      select a.id, a.iid, a.user_id, a.last_seen from public.agents a
       where a.tenant_id = v_tenant.tenant_id and a.retired_at is null
         and a.last_seen < v_now - make_interval(days => v_tenant.days)
       order by a.last_seen, a.id
    loop
      v_eligible := v_eligible + 1;
      if not v_apply or v_retired >= v_limit then
        continue;
      end if;
      v_revoked := app.retire_agent_row(v_tenant.tenant_id, v_agent.id, 'offline', null);
      insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
      values (null, v_tenant.tenant_id, v_agent.user_id, 'agent.retired',
        jsonb_build_object('agent_id', v_agent.id, 'iid', v_agent.iid, 'reason', 'offline',
          'offline_days', v_tenant.days, 'last_seen', v_agent.last_seen,
          'revoked_keys', v_revoked));
      v_retired := v_retired + 1;
    end loop;
  end loop;
  v_remaining := v_eligible - v_retired;
  return jsonb_build_object('applied', v_apply, 'eligible', v_eligible, 'retired', v_retired,
    'remaining', v_remaining, 'contended_tenants', v_contended, 'cutoff', v_now);
end;
$$;
revoke all on function public.retire_offline_agents(integer, boolean) from public, anon, authenticated;
grant execute on function public.retire_offline_agents(integer, boolean) to service_role;

-- Browser seat counts: active agents only, plus the retired count.
create or replace view public.seat_usage
with (security_invoker = true)
as
select
  e.user_id,
  least(greatest(e.included_agents, 0), admitted.allowed_agents) as included_agents,
  admitted.allowed_agents - least(greatest(e.included_agents, 0), admitted.allowed_agents) as extra_agents,
  admitted.allowed_agents,
  (
    select count(*)::int
    from public.agents a
    where a.tenant_id = e.tenant_id and a.retired_at is null
  ) as current_agents,
  e.tenant_id,
  (
    select count(*)::int
    from public.agents a
    where a.tenant_id = e.tenant_id and a.retired_at is not null
  ) as retired_agents
from public.entitlements e
cross join lateral app.visible_tenant_admission_capacity(e.tenant_id) as admitted(allowed_agents);

-- Plan view: current_agents counts active (non-retired) agents.
create or replace function public.get_tenant_plan(p_tenant_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_mode text;
  v_label text;
  v_plan_id text;
  v_source text;
  v_plan public.plans%rowtype;
  v_admission public.tenant_admissions%rowtype;
  v_has_admission boolean;
  v_admission_status text := 'none';
  v_sub public.billing_plan_subscriptions%rowtype;
  v_has_sub boolean;
  v_allowed integer;
  v_current integer;
begin
  if auth.uid() is null
     or p_tenant_id is null
     or not app.is_tenant_member(p_tenant_id)
     or not public.tenant_identity_access_allowed(p_tenant_id) then
    raise exception 'tenant_plan_access_denied' using errcode = '42501';
  end if;

  select mode into v_mode from app.tenant_admission_config where singleton;

  select * into v_admission from public.tenant_admissions where tenant_id = p_tenant_id;
  v_has_admission := found;
  if v_has_admission then
    v_admission_status := case
      when v_admission.revoked_at is not null then 'revoked'
      when v_admission.expires_at <= v_now then 'expired'
      when v_admission.starts_at > v_now then 'pending'
      else 'active' end;
  end if;

  select * into v_sub from public.billing_plan_subscriptions
   where tenant_id = p_tenant_id
   order by (admission_state = 'granted') desc, updated_at desc
   limit 1;
  v_has_sub := found;

  if v_has_sub and v_sub.admission_state = 'granted' and v_has_admission
     and v_admission_status = 'active'
     and v_admission.grant_reference = 'stripe:' || v_sub.provider_subscription_id then
    v_plan_id := v_sub.plan_id;
    v_source := 'stripe_subscription';
  else
    select t.plan into v_label from public.teams t where t.tenant_id = p_tenant_id limit 1;
    if v_label is not null then
      v_plan_id := app.catalog_plan_id(v_label);
      v_source := 'team_record';
    else
      v_plan_id := 'free';
      v_source := 'default';
    end if;
  end if;

  select * into v_plan from public.plans where id = v_plan_id;
  if not found then
    raise exception 'tenant_plan_unavailable' using errcode = '55000';
  end if;

  v_allowed := app.visible_tenant_admission_capacity(p_tenant_id);
  select count(*)::int into v_current from public.agents a
   where a.tenant_id = p_tenant_id and a.retired_at is null;

  return jsonb_build_object(
    'tenant_id', p_tenant_id,
    'plan_id', v_plan.id,
    'display_name', v_plan.display_name,
    'plan_source', v_source,
    'included_agents_per_seat', v_plan.included_agents,
    'min_seats', v_plan.min_seats,
    'self_serve', v_plan.self_serve,
    'retention_days', v_plan.retention_days,
    'allowed_agents', v_allowed,
    'current_agents', v_current,
    'admission', jsonb_build_object(
      'mode', coalesce(v_mode, 'unconfigured'),
      'status', v_admission_status,
      'kind', case when v_has_admission then v_admission.kind else null end,
      'expires_at', case when v_has_admission then v_admission.expires_at else null end),
    'subscription', case when v_has_sub then jsonb_build_object(
      'plan_id', v_sub.plan_id,
      'billing_interval', v_sub.billing_interval,
      'seats', v_sub.seats,
      'status', v_sub.status,
      'admission_state', v_sub.admission_state,
      'current_period_end', v_sub.current_period_end) else null end);
end;
$$;

-- Operator usage: enrolled = active agents; retired agents reported separately.
create or replace function public.operator_tenant_usage(p_actor_user_id uuid, p_tenant_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_tenant public.tenants%rowtype;
  v_admission public.tenant_admissions%rowtype;
  v_mode text;
  v_capacity integer;
  v_agents integer;
  v_agents_active integer;
  v_members integer;
  v_agents_retired integer;
begin
  perform app.require_platform_operator(p_actor_user_id);
  if p_tenant_id is null then
    raise exception 'tenant_not_found' using errcode = 'P0002';
  end if;
  select * into v_tenant from public.tenants where id = p_tenant_id;
  if not found then
    raise exception 'tenant_not_found' using errcode = 'P0002';
  end if;
  select mode into v_mode from app.tenant_admission_config where singleton;
  select * into v_admission from public.tenant_admissions
   where tenant_id = p_tenant_id;
  v_capacity := public.tenant_admission_capacity(p_tenant_id);
  select count(*)::int,
      (count(*) filter (where a.retired_at is null and a.last_seen > v_now - interval '7 days'))::int,
      (count(*) filter (where a.retired_at is not null))::int
    into v_agents, v_agents_active, v_agents_retired
    from public.agents a where a.tenant_id = p_tenant_id;
  v_agents := v_agents - v_agents_retired;
  select count(*)::int into v_members from public.tenant_members m
   where m.tenant_id = p_tenant_id
     and (m.expires_at is null or m.expires_at > v_now);
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, 'operator.tenant_usage_read',
    '{}'::jsonb);
  return jsonb_build_object(
    'tenant', jsonb_build_object('id', v_tenant.id, 'kind', v_tenant.kind,
      'status', v_tenant.status, 'created_at', v_tenant.created_at),
    'admission_mode', coalesce(v_mode, 'unconfigured'),
    'admission', case when v_admission.tenant_id is null then null
      else jsonb_build_object('kind', v_admission.kind,
        'plan_id', v_admission.plan_id, 'seats', v_admission.seats,
        'starts_at', v_admission.starts_at,
        'expires_at', v_admission.expires_at,
        'revoked_at', v_admission.revoked_at,
        'active', v_admission.revoked_at is null
          and v_admission.starts_at <= v_now
          and v_admission.expires_at > v_now) end,
    'allowed_agents', v_capacity,
    'agents', jsonb_build_object('enrolled', v_agents,
      'active_7d', v_agents_active, 'retired', v_agents_retired),
    'members', v_members);
end;
$$;

-- Supabase Cloud schedule (pg_cron): one bounded auto-retirement batch per
-- hour, next to the retention jobs from 20261013000200. Compose/Helm installs
-- run the same RPC from scripts/deployment-maintenance.mjs.
create or replace function app.run_retention_job(p_job text)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_result jsonb;
  v_ok boolean;
begin
  begin
    if p_job = 'billing' then
      v_result := public.prune_expired_billing_records(1000, true);
    elsif p_job = 'telemetry' then
      v_result := public.prune_expired_telemetry_events(1000, true, now());
    elsif p_job = 'trial_subjects' then
      v_result := public.purge_expired_ga_trial_subjects(1000, true);
    elsif p_job = 'waitlist' then
      v_result := public.purge_expired_waitlist_signups(1000, true);
    elsif p_job = 'team_invitations' then
      v_result := public.prune_expired_team_invitations(1000, true);
    elsif p_job = 'approval_requests' then
      v_result := public.prune_expired_approval_requests(1000, true);
    elsif p_job = 'ai_governance' then
      v_result := public.run_ai_governance_maintenance(1000, true);
    elsif p_job = 'rate_limits' then
      v_result := public.prune_expired_rate_limits(1000, true);
    elsif p_job = 'agent_retirement' then
      v_result := public.retire_offline_agents(1000, true);
    elsif p_job = 'governance_digest' then
      v_result := app.dispatch_governance_digest_via_pg_net();
    else
      raise exception 'unknown_retention_job' using errcode = '22023';
    end if;
    v_ok := v_result is not null and coalesce(v_result->>'status', '') <> 'not_configured';
  exception when others then
    -- The batch rolled back; keep a failure receipt so a stale or failing
    -- schedule is visible in retention_job_status.
    v_ok := false;
    v_result := jsonb_build_object('error', sqlstate, 'message', left(sqlerrm, 300));
  end;
  insert into public.retention_job_runs(job, ok, result) values (left(coalesce(p_job, '?'), 64), v_ok, coalesce(v_result, '{}'::jsonb));
  delete from public.retention_job_runs where ran_at < clock_timestamp() - interval '30 days';
  return jsonb_build_object('job', p_job, 'ok', v_ok, 'result', v_result);
end;
$$;
revoke all on function app.run_retention_job(text) from public, anon, authenticated, service_role;

create or replace function app.schedule_retention_maintenance()
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
declare
  v_job record;
  v_names text[] := '{}';
begin
  if to_regprocedure('cron.schedule(text,text,text)') is null then
    return jsonb_build_object('scheduled', false, 'reason', 'pg_cron is not installed');
  end if;
  for v_job in
    select * from (values
      ('aidr-retention-telemetry', '*/10 * * * *', 'telemetry'),
      ('aidr-retention-billing', '7 * * * *', 'billing'),
      ('aidr-retention-trial-subjects', '12 * * * *', 'trial_subjects'),
      ('aidr-retention-waitlist', '17 * * * *', 'waitlist'),
      ('aidr-retention-team-invitations', '22 * * * *', 'team_invitations'),
      ('aidr-retention-approval-requests', '27 * * * *', 'approval_requests'),
      ('aidr-retention-ai-governance', '32 * * * *', 'ai_governance'),
      ('aidr-retention-rate-limits', '*/15 * * * *', 'rate_limits'),
      ('aidr-retention-agent-retirement', '52 * * * *', 'agent_retirement'),
      ('aidr-governance-digest', '47 * * * *', 'governance_digest')
    ) as jobs(name, schedule, job)
  loop
    execute 'select cron.schedule($1, $2, $3)'
      using v_job.name, v_job.schedule, format('select app.run_retention_job(%L)', v_job.job);
    v_names := v_names || v_job.name;
  end loop;
  return jsonb_build_object('scheduled', true, 'jobs', to_jsonb(v_names));
end;
$$;
revoke all on function app.schedule_retention_maintenance() from public, anon, authenticated, service_role;

do $$
begin
  if to_regprocedure('cron.schedule(text,text,text)') is not null then
    perform app.schedule_retention_maintenance();
  end if;
end;
$$;
