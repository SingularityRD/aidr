-- Explicit tenant admission is distinct from seat allocations, paid invoice
-- records and pilot applications. No deployment mode is enabled by default.
create table app.tenant_admission_config (
  singleton boolean primary key default true check (singleton),
  mode text not null default 'unconfigured'
    check (mode in ('unconfigured', 'cloud', 'onprem', 'pilot')),
  configured_at timestamptz
);
insert into app.tenant_admission_config(singleton, mode) values (true, 'unconfigured');
revoke all on app.tenant_admission_config from public, anon, authenticated, service_role;

create table public.tenant_admissions (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  owner_user_id uuid references auth.users(id) on delete set null,
  kind text not null check (kind in ('trial', 'licensed')),
  seats integer not null check (seats between 1 and 100000),
  starts_at timestamptz not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  grant_reference text,
  granted_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp(),
  check (isfinite(starts_at) and isfinite(expires_at) and expires_at > starts_at),
  check (revoked_at is null or revoked_at >= starts_at),
  check (kind <> 'trial' or (seats = 1 and expires_at = starts_at + interval '14 days')),
  check (kind <> 'licensed' or (grant_reference is not null and length(trim(grant_reference)) between 1 and 200))
);
alter table public.tenant_admissions enable row level security;
revoke all on public.tenant_admissions from public, anon, authenticated, service_role;

-- One-trial history lives in server-only Auth app metadata for the lifetime of
-- that Auth account. Team offboarding/upgrades cannot reset it; account deletion
-- removes it. The original tenant retains its fixed term after owner deletion,
-- but cannot refresh it. This does not identify the same human after deletion.
create or replace function app.protect_auth_trial_claim()
returns trigger
language plpgsql security definer
set search_path = pg_catalog, auth, pg_temp
as $$
begin
  if coalesce(old.raw_app_meta_data, '{}'::jsonb) ? 'aidr_trial'
     and (coalesce(new.raw_app_meta_data, '{}'::jsonb) -> 'aidr_trial')
         is distinct from (old.raw_app_meta_data -> 'aidr_trial') then
    raise exception 'trial_claim_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_auth_trial_claim()
  from public, anon, authenticated, service_role;
create trigger protect_auth_trial_claim
before update of raw_app_meta_data on auth.users
for each row execute function app.protect_auth_trial_claim();

-- Independently provisioned by a database administrator; neither a tenant
-- owner nor a Finance invoice approver can make itself an admission operator.
create table public.admission_operators (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  expires_at timestamptz not null default (transaction_timestamp() + interval '30 days')
    check (isfinite(expires_at)),
  revoked_at timestamptz,
  primary key (tenant_id, user_id)
);
alter table public.admission_operators enable row level security;
revoke all on public.admission_operators from public, anon, authenticated, service_role;

create or replace function public.configure_tenant_admission_mode(p_mode text)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare v_mode text;
begin
  if p_mode is null or p_mode not in ('cloud', 'onprem', 'pilot') then
    raise exception 'invalid_admission_mode' using errcode = '22023';
  end if;
  select mode into v_mode from app.tenant_admission_config
    where singleton for update;
  if v_mode = p_mode then
    return jsonb_build_object('status', 'already_configured', 'mode', v_mode);
  end if;
  if v_mode is distinct from 'unconfigured' then
    raise exception 'admission_mode_immutable' using errcode = '42501';
  end if;
  update app.tenant_admission_config
     set mode = p_mode, configured_at = clock_timestamp() where singleton;
  insert into public.admin_audit_logs(action, detail)
  values ('admission.mode_configured', jsonb_build_object('mode', p_mode));
  return jsonb_build_object('status', 'configured', 'mode', p_mode);
end;
$$;
revoke all on function public.configure_tenant_admission_mode(text)
  from public, anon, authenticated;
grant execute on function public.configure_tenant_admission_mode(text)
  to service_role;

-- Every write boundary consumes this one capacity. It holds the tenant's
-- admission and entitlement rows until the caller commits; expiry is tested
-- against wall-clock time on each call. A paid invoice alone never admits.
create or replace function public.tenant_admission_capacity(p_tenant_id uuid)
returns integer
language plpgsql volatile security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_mode text;
  v_admission public.tenant_admissions%rowtype;
  v_included integer;
  v_extra integer;
  v_seats integer;
begin
  if p_tenant_id is null then return 0; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
  select mode into v_mode from app.tenant_admission_config
    where singleton for share;
  if v_mode is null or v_mode = 'unconfigured' then return 0; end if;
  perform 1 from public.tenants t
    where t.id = p_tenant_id and t.status = 'active' for share;
  if not found then return 0; end if;

  if v_mode = 'pilot' then
    perform 1 from public.pilot_applications p
      where p.tenant_id = p_tenant_id and p.status = 'approved'
      limit 1 for share;
    if not found then return 0; end if;
    -- The pilot decision trigger updates the application before entitlements.
    select e.included_agents into v_included from public.entitlements e
      where e.tenant_id = p_tenant_id for share;
    if not found then return 0; end if;
  else
    -- Trial/license grants allocate entitlements before admission rows.
    select e.included_agents into v_included from public.entitlements e
      where e.tenant_id = p_tenant_id for share;
    if not found then return 0; end if;
    select * into v_admission from public.tenant_admissions a
      where a.tenant_id = p_tenant_id and a.revoked_at is null
        and a.starts_at <= clock_timestamp()
        and a.expires_at > clock_timestamp()
      for share;
    if not found then return 0; end if;
  end if;

  select s.extra_agents into v_extra
    from public.effective_tenant_seats(p_tenant_id) s;
  v_seats := greatest(0, coalesce(v_included, 0) + coalesce(v_extra, 0));
  if v_mode = 'pilot' then return v_seats; end if;
  return least(v_seats, v_admission.seats);
end;
$$;
revoke all on function public.tenant_admission_capacity(uuid)
  from public, anon, authenticated;
grant execute on function public.tenant_admission_capacity(uuid)
  to service_role;

create or replace function public.start_verified_trial(p_user_id uuid, p_tenant_id uuid)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, auth, pg_temp
as $$
declare
  v_mode text;
  v_started_at timestamptz;
  v_expires_at timestamptz;
  v_app_metadata jsonb;
  v_trial jsonb;
  v_existing public.tenant_admissions%rowtype;
begin
  select mode into v_mode from app.tenant_admission_config where singleton for share;
  if v_mode is distinct from 'cloud' then
    return jsonb_build_object('status', 'disabled');
  end if;
  if p_user_id is null or p_tenant_id is null then
    return jsonb_build_object('status', 'ineligible');
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 3491));
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
  select coalesce(u.raw_app_meta_data, '{}'::jsonb) into v_app_metadata
    from auth.users u where u.id = p_user_id
      and u.email_confirmed_at is not null for update;
  if not found then return jsonb_build_object('status', 'ineligible'); end if;
  perform 1 from public.tenants t
    join public.tenant_members m on m.tenant_id = t.id and m.user_id = p_user_id
   where t.id = p_tenant_id and t.status = 'active'
     and t.kind = 'team' and t.created_by = p_user_id
     and m.role = 'owner' and (m.expires_at is null or m.expires_at > clock_timestamp())
   for share of t, m;
  if not found then return jsonb_build_object('status', 'ineligible'); end if;

  v_trial := v_app_metadata -> 'aidr_trial';
  if v_trial is not null then
    select * into v_existing from public.tenant_admissions
      where tenant_id = p_tenant_id and kind = 'trial';
    if v_trial ->> 'tenant_id' = p_tenant_id::text and found then
      return jsonb_build_object('status', 'existing', 'expires_at', v_trial ->> 'expires_at',
        'allowed_agents', public.tenant_admission_capacity(p_tenant_id));
    end if;
    return jsonb_build_object('status', 'ineligible');
  end if;
  perform 1 from public.tenant_admissions where tenant_id = p_tenant_id;
  if found then return jsonb_build_object('status', 'ineligible'); end if;

  v_started_at := clock_timestamp();
  v_expires_at := v_started_at + interval '14 days';
  update auth.users set raw_app_meta_data = jsonb_set(v_app_metadata,
    '{aidr_trial}', jsonb_build_object('tenant_id', p_tenant_id,
      'started_at', v_started_at, 'expires_at', v_expires_at), true)
    where id = p_user_id;
  insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents)
  values (p_user_id, p_tenant_id, 1, 0)
  on conflict (tenant_id) do update
    set included_agents = greatest(public.entitlements.included_agents, 1);
  insert into public.tenant_admissions
    (tenant_id, owner_user_id, kind, seats, starts_at, expires_at)
  values (p_tenant_id, p_user_id, 'trial', 1, v_started_at, v_expires_at);
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_user_id, p_tenant_id, p_user_id, 'admission.trial_started',
    jsonb_build_object('started_at', v_started_at, 'expires_at', v_expires_at, 'seats', 1));
  return jsonb_build_object('status', 'started', 'expires_at', v_expires_at,
    'allowed_agents', 1);
end;
$$;
revoke all on function public.start_verified_trial(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.start_verified_trial(uuid, uuid)
  to service_role;

create or replace function public.get_tenant_admission(p_tenant_id uuid, p_user_id uuid)
returns jsonb
language plpgsql volatile security definer
set search_path = pg_catalog, public, app, auth, pg_temp
as $$
declare
  v_mode text;
  v_row public.tenant_admissions%rowtype;
  v_capacity integer;
  v_status text := 'none';
  v_kind text;
  v_trial_available boolean := false;
  v_tenant public.tenants%rowtype;
begin
  select mode into v_mode from app.tenant_admission_config where singleton;
  select * into v_tenant from public.tenants
    where id = p_tenant_id and status = 'active';
  if not found or not exists (
    select 1 from public.tenant_members m where m.tenant_id = p_tenant_id
      and m.user_id = p_user_id and (m.expires_at is null or m.expires_at > clock_timestamp())
  ) then return jsonb_build_object('mode', coalesce(v_mode, 'unconfigured'),
    'status', 'forbidden', 'access_kind', null, 'allowed_agents', 0,
    'expires_at', null, 'trial_available', false); end if;
  v_capacity := public.tenant_admission_capacity(p_tenant_id);
  if v_mode = 'pilot' then
    v_kind := case when exists (
      select 1 from public.pilot_applications p
      where p.tenant_id = p_tenant_id and p.status = 'approved'
    ) then 'pilot' else null end;
    v_status := case when v_capacity > 0 then 'active' else 'not_entitled' end;
  elsif v_mode in ('cloud', 'onprem') then
    select * into v_row from public.tenant_admissions where tenant_id = p_tenant_id;
    if found then
      v_kind := v_row.kind;
      v_status := case when v_row.revoked_at is not null then 'revoked'
        when v_row.expires_at <= clock_timestamp() then 'expired'
        when v_capacity > 0 then 'active' else 'not_entitled' end;
    end if;
  else
    v_status := 'unconfigured';
  end if;
  if v_mode = 'cloud' and v_status = 'none' and v_tenant.kind = 'team'
     and v_tenant.created_by = p_user_id and exists (
       select 1 from auth.users u where u.id = p_user_id
         and u.email_confirmed_at is not null
         and not (coalesce(u.raw_app_meta_data, '{}'::jsonb) ? 'aidr_trial')
     ) and exists (
       select 1 from public.tenant_members m where m.tenant_id = p_tenant_id
         and m.user_id = p_user_id and m.role = 'owner'
         and (m.expires_at is null or m.expires_at > clock_timestamp())
     ) then v_trial_available := true; end if;
  return jsonb_build_object('mode', coalesce(v_mode, 'unconfigured'),
    'status', v_status, 'access_kind', v_kind,
    'allowed_agents', v_capacity,
    'expires_at', case when v_mode <> 'pilot' then v_row.expires_at else null end,
    'trial_available', v_trial_available);
end;
$$;
revoke all on function public.get_tenant_admission(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.get_tenant_admission(uuid, uuid)
  to service_role;

-- Cloud paid activation is an independent, accountable operator action. A
-- pending order, a paid invoice row or tenant owner cannot call this transition.
create or replace function public.grant_licensed_tenant_admission(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_owner_user_id uuid,
  p_seats integer,
  p_expires_at timestamptz,
  p_grant_reference text
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz;
  v_mode text;
begin
  if p_actor_user_id is null or p_tenant_id is null or p_owner_user_id is null
     or p_seats is null or p_seats not between 1 and 100000
     or p_expires_at is null or not isfinite(p_expires_at)
     or p_grant_reference is null or length(trim(p_grant_reference)) not between 1 and 200
     or p_grant_reference ~ '[[:cntrl:]]' then
    raise exception 'invalid_admission_grant' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
  v_now := clock_timestamp();
  if p_expires_at <= v_now then
    raise exception 'invalid_admission_grant' using errcode = '22023';
  end if;
  select mode into v_mode from app.tenant_admission_config where singleton for share;
  if v_mode not in ('cloud', 'onprem') then
    raise exception 'admission_mode_not_licensed' using errcode = '42501';
  end if;
  perform 1 from public.admission_operators o
    where o.tenant_id = p_tenant_id and o.user_id = p_actor_user_id
      and o.revoked_at is null
      and o.expires_at > v_now for share;
  if not found or exists (
    select 1 from public.tenant_members m
     where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
  ) then raise exception 'admission_operator_forbidden' using errcode = '42501'; end if;
  perform 1 from public.tenants t
    join public.tenant_members m on m.tenant_id = t.id
   where t.id = p_tenant_id and t.status = 'active'
     and m.user_id = p_owner_user_id and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > v_now)
   for share of t, m;
  if not found then raise exception 'admission_owner_forbidden' using errcode = '42501'; end if;

  insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents)
  values (p_owner_user_id, p_tenant_id, p_seats, 0)
  on conflict (tenant_id) do update
    set included_agents = p_seats;
  insert into public.tenant_admissions
    (tenant_id, owner_user_id, kind, seats, starts_at, expires_at,
     revoked_at, grant_reference, granted_by)
  values (p_tenant_id, p_owner_user_id, 'licensed', p_seats, v_now,
    p_expires_at, null, trim(p_grant_reference), p_actor_user_id)
  on conflict (tenant_id) do update
    set owner_user_id = excluded.owner_user_id, kind = 'licensed',
        seats = excluded.seats, starts_at = excluded.starts_at,
        expires_at = excluded.expires_at, revoked_at = null,
        grant_reference = excluded.grant_reference,
        granted_by = excluded.granted_by, updated_at = clock_timestamp();
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id,
    action, detail)
  values (p_actor_user_id, p_tenant_id, p_owner_user_id,
    'admission.licensed_granted', jsonb_build_object('seats', p_seats,
      'expires_at', p_expires_at, 'reference', trim(p_grant_reference)));
  return jsonb_build_object('status', 'granted', 'tenant_id', p_tenant_id,
    'allowed_agents', public.tenant_admission_capacity(p_tenant_id),
    'expires_at', p_expires_at);
end;
$$;
revoke all on function public.grant_licensed_tenant_admission(
  uuid, uuid, uuid, integer, timestamptz, text)
  from public, anon, authenticated;
grant execute on function public.grant_licensed_tenant_admission(
  uuid, uuid, uuid, integer, timestamptz, text)
  to service_role;

create or replace function public.revoke_licensed_tenant_admission(
  p_actor_user_id uuid, p_tenant_id uuid, p_reason text
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_owner uuid;
  v_now timestamptz;
begin
  if p_actor_user_id is null or p_tenant_id is null or p_reason is null
     or length(trim(p_reason)) not between 1 and 200
     or p_reason ~ '[[:cntrl:]]' then
    raise exception 'invalid_admission_revocation' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
  v_now := clock_timestamp();
  perform 1 from public.admission_operators o
    where o.tenant_id = p_tenant_id and o.user_id = p_actor_user_id
      and o.revoked_at is null
      and o.expires_at > v_now for share;
  if not found or exists (
    select 1 from public.tenant_members m
     where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
  ) then raise exception 'admission_operator_forbidden' using errcode = '42501'; end if;
  perform 1 from public.tenant_admissions
   where tenant_id = p_tenant_id and kind = 'licensed' and revoked_at is null;
  if not found then return jsonb_build_object('status', 'not_active'); end if;
  update public.entitlements
     set revocation_epoch = revocation_epoch + 1
   where tenant_id = p_tenant_id;
  if not found then
    raise exception 'admission_entitlement_missing' using errcode = '55000';
  end if;
  update public.tenant_admissions
     set revoked_at = greatest(starts_at, v_now), updated_at = v_now
   where tenant_id = p_tenant_id and kind = 'licensed' and revoked_at is null
  returning owner_user_id into v_owner;
  if not found then
    raise exception 'admission_revocation_conflict' using errcode = '40001';
  end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id,
    action, detail)
  values (p_actor_user_id, p_tenant_id, v_owner,
    'admission.licensed_revoked', jsonb_build_object('reason', trim(p_reason)));
  return jsonb_build_object('status', 'revoked', 'tenant_id', p_tenant_id);
end;
$$;
revoke all on function public.revoke_licensed_tenant_admission(uuid, uuid, text)
  from public, anon, authenticated;
grant execute on function public.revoke_licensed_tenant_admission(uuid, uuid, text)
  to service_role;

-- An admitted cloud trial can also be stopped for abuse without allowing the
-- owner to mint a replacement: its Auth claim remains immutable.
create or replace function public.revoke_trial_tenant_admission(
  p_actor_user_id uuid, p_tenant_id uuid, p_reason text
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_owner uuid;
  v_now timestamptz;
begin
  if p_actor_user_id is null or p_tenant_id is null or p_reason is null
     or length(trim(p_reason)) not between 1 and 200
     or p_reason ~ '[[:cntrl:]]' then
    raise exception 'invalid_admission_revocation' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
  v_now := clock_timestamp();
  perform 1 from public.admission_operators o
    where o.tenant_id = p_tenant_id and o.user_id = p_actor_user_id
      and o.revoked_at is null
      and o.expires_at > v_now for share;
  if not found or exists (
    select 1 from public.tenant_members m
     where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
  ) then raise exception 'admission_operator_forbidden' using errcode = '42501'; end if;
  perform 1 from public.tenant_admissions
   where tenant_id = p_tenant_id and kind = 'trial' and revoked_at is null;
  if not found then return jsonb_build_object('status', 'not_active'); end if;
  update public.entitlements
     set revocation_epoch = revocation_epoch + 1
   where tenant_id = p_tenant_id;
  if not found then
    raise exception 'admission_entitlement_missing' using errcode = '55000';
  end if;
  update public.tenant_admissions
     set revoked_at = greatest(starts_at, v_now), updated_at = v_now
   where tenant_id = p_tenant_id and kind = 'trial' and revoked_at is null
  returning owner_user_id into v_owner;
  if not found then
    raise exception 'admission_revocation_conflict' using errcode = '40001';
  end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id,
    action, detail)
  values (p_actor_user_id, p_tenant_id, v_owner,
    'admission.trial_revoked', jsonb_build_object('reason', trim(p_reason)));
  return jsonb_build_object('status', 'revoked', 'tenant_id', p_tenant_id);
end;
$$;
revoke all on function public.revoke_trial_tenant_admission(uuid, uuid, text)
  from public, anon, authenticated;
grant execute on function public.revoke_trial_tenant_admission(uuid, uuid, text)
  to service_role;

-- Replace migration 29's pilot-only trigger without changing its table coverage.
create or replace function public.require_enrollment_admission()
returns trigger
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
begin
  if public.tenant_admission_capacity(new.tenant_id) < 1 then
    raise exception 'tenant_not_admitted' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function public.require_enrollment_admission()
  from public, anon, authenticated;

-- Rebase migration 29's deterministic seat rank on admission capacity. This
-- also blocks existing agents immediately after trial expiry or revocation.
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
language plpgsql security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_tenant_id uuid := coalesce(p_tenant_id, p_user_id);
  v_allowed integer;
  v_current integer;
  v_agent_id uuid;
  v_agent_rank bigint;
begin
  if p_user_id is null or nullif(trim(p_iid), '') is null then
    raise exception 'invalid agent identity';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 0));
  v_allowed := public.tenant_admission_capacity(v_tenant_id);
  select a.id into v_agent_id from public.agents a
    where a.tenant_id = v_tenant_id and a.iid = trim(p_iid) for update;
  select count(*)::integer into v_current from public.agents a
    where a.tenant_id = v_tenant_id;
  if v_allowed < 1 then
    return query select null::uuid, v_tenant_id, false, v_current, v_allowed, true;
    return;
  end if;
  if v_agent_id is null and v_current >= v_allowed then
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
  if v_current > v_allowed then
    select ranked.agent_rank into v_agent_rank from (
      select a.id, row_number() over (order by a.first_seen, a.id) agent_rank
        from public.agents a where a.tenant_id = v_tenant_id
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
revoke all on function public.register_agent_for_ingest(uuid, text, text, text, uuid)
  from public, anon, authenticated;
grant execute on function public.register_agent_for_ingest(uuid, text, text, text, uuid)
  to service_role;

-- A registration and its event upsert are separate transactions. Keep the
-- seat-rank check from migration 32, but test live admission even for a no-op
-- duplicate event so expired/revoked credentials cannot report success.
create or replace function app.enforce_event_seat_admission()
returns trigger
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_allowed integer;
  v_first_seen timestamptz;
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
  select a.first_seen into v_first_seen from public.agents a
    where a.id = new.agent_id and a.tenant_id = new.tenant_id
      and a.user_id = new.user_id for key share;
  if not found then
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
   where a.tenant_id = new.tenant_id
     and (a.first_seen, a.id) < (v_first_seen, new.agent_id);
  if v_prior >= v_allowed then
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.enforce_event_seat_admission()
  from public, anon, authenticated, service_role;

-- The device-poll commit must recheck the same admission boundary as manual
-- token issue, regardless of what a browser saw before a revocation/expiry.
create or replace function public.issue_device_enrollment_token(
  p_device_code_hash text,
  p_token_hash text,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_session public.device_sessions%rowtype;
  v_tenant_id uuid;
  v_user_id uuid;
  v_revoked_before timestamptz;
begin
  if p_device_code_hash is null or p_device_code_hash !~ '^[a-f0-9]{64}$'
     or p_token_hash is null or p_token_hash !~ '^[a-f0-9]{64}$'
     or p_expires_at is null
     or p_expires_at < now() + interval '1 minute'
     or p_expires_at > now() + interval '30 days' then
    raise exception 'invalid device enrollment input' using errcode = '22023';
  end if;
  select d.user_id into v_user_id from public.device_sessions d
    where d.device_code_hash = p_device_code_hash;
  if not found or v_user_id is null then
    return jsonb_build_object('status', 'already_exchanged_or_invalid');
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611));
  select d.* into v_session from public.device_sessions d
    where d.device_code_hash = p_device_code_hash for update;
  if not found or v_session.user_id is null
     or v_session.user_id is distinct from v_user_id
     or v_session.authorized_at is null or v_session.exchanged_at is not null
     or v_session.expires_at <= now() then
    return jsonb_build_object('status', 'already_exchanged_or_invalid');
  end if;
  select s.revoked_before into v_revoked_before
    from public.identity_user_session_state s
   where s.user_id = v_session.user_id;
  if v_revoked_before is not null
     and v_session.authorized_at <= v_revoked_before then
    return jsonb_build_object('status', 'already_exchanged_or_invalid');
  end if;
  v_tenant_id := coalesce(v_session.tenant_id, v_session.user_id);
  if not exists (
    select 1 from public.tenant_members m
      join public.tenants t on t.id = m.tenant_id
     where m.tenant_id = v_tenant_id and m.user_id = v_session.user_id
       and m.role in ('owner', 'admin', 'member')
       and (m.expires_at is null or m.expires_at > clock_timestamp())
       and t.status = 'active'
  ) or public.tenant_admission_capacity(v_tenant_id) < 1 then
    return jsonb_build_object('status', 'tenant_not_admitted');
  end if;
  insert into public.enrollment_tokens
    (user_id, tenant_id, label, token_hash, expires_at)
  values (v_session.user_id, v_tenant_id,
    'device:' || left(coalesce(v_session.user_code, ''), 16),
    p_token_hash, p_expires_at);
  update public.device_sessions set exchanged_at = now(), status = 'exchanged'
    where id = v_session.id;
  return jsonb_build_object('status', 'issued');
end;
$$;
revoke all on function public.issue_device_enrollment_token(text, text, timestamptz)
  from public, anon, authenticated;
grant execute on function public.issue_device_enrollment_token(text, text, timestamptz)
  to service_role;
