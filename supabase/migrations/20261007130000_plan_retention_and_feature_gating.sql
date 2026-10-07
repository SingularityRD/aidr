-- Plan-bound retention, server-side plan feature gating and the member view of
-- the administrative audit trail.
--
-- 1. Plan resolver. `app.tenant_plan_entitlements(tenant)` is the single
--    database decision of which catalog edition a tenant is entitled to. Only
--    audited sources count:
--      * a granted Stripe subscription bound to the tenant's active licensed
--        admission (`stripe:<subscription id>`), as in get_tenant_plan;
--      * otherwise the billing-managed team label (`teams.plan`, no browser
--        write path), honoured ONLY while the tenant holds an active licensed
--        admission or an approved pilot; a paid label without one is Free
--        (`admission_inactive`), so a lapsed licence stops paid features;
--      * an active verified trial evaluates the Team edition.
--    Tier names are the catalog's: free / team / business / enterprise (the
--    legacy `pro` label keeps mapping to `team` through app.catalog_plan_id).
--    `public.tenant_plan_entitlements` exposes it to the service role (Edge
--    Functions, `_shared/plan-entitlements.ts`), and
--    `public.get_tenant_plan_entitlements` to members (dashboard gating). The
--    server is authoritative; the dashboard only hides what the server refuses.
-- 2. AI Security Posture views. posture_findings is read directly by members,
--    so the plan gate is a RESTRICTIVE RLS policy (fails closed: an unreadable
--    plan hides the rows).
-- 3. Retention bound to plan. The effective telemetry (event) retention is
--    min(tenant setting, plan maximum); a tenant that never chose a value
--    (seeded row, updated_by null) gets the plan's term. A contractual plan
--    (retention_days null) keeps the tenant setting. The reaper and the
--    retention admin RPC use the same function; the retention-admin Edge
--    Function reports the same value through `effectiveRetentionDays`.
-- 4. `public.list_tenant_admin_audit_logs`: owner/admin-only, tenant-scoped,
--    keyset-paginated read of admin_audit_logs for the team audit panel.

-- ── 1. Plan resolver ─────────────────────────────────────────────────────────

create or replace function app.tenant_plan_entitlements(p_tenant_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  -- Transaction time keeps the function STABLE (usable from RLS).
  v_now timestamptz := now();
  v_mode text;
  v_admission public.tenant_admissions%rowtype;
  v_admission_active boolean := false;
  v_licensed_active boolean := false;
  v_trial_active boolean := false;
  v_pilot_approved boolean := false;
  v_tenant_active boolean := false;
  v_sub public.billing_plan_subscriptions%rowtype;
  v_has_sub boolean := false;
  v_label text;
  v_plan_id text := 'free';
  v_source text := 'default';
  v_plan public.plans%rowtype;
begin
  if p_tenant_id is null then
    raise exception 'tenant_plan_invalid' using errcode = '22023';
  end if;

  select exists (select 1 from public.tenants t where t.id = p_tenant_id and t.status = 'active')
    into v_tenant_active;
  select c.mode into v_mode from app.tenant_admission_config c where c.singleton;

  select * into v_admission from public.tenant_admissions a where a.tenant_id = p_tenant_id;
  if found then
    v_admission_active := v_admission.revoked_at is null
      and v_admission.starts_at <= v_now
      and v_admission.expires_at > v_now;
    v_licensed_active := v_admission_active and v_admission.kind = 'licensed';
    v_trial_active := v_admission_active and v_admission.kind = 'trial';
  end if;
  v_pilot_approved := v_mode = 'pilot' and exists (
    select 1 from public.pilot_applications p
     where p.tenant_id = p_tenant_id and p.status = 'approved');

  if not v_tenant_active then
    v_source := 'admission_inactive';
    v_trial_active := false;
  else
    select * into v_sub from public.billing_plan_subscriptions s
     where s.tenant_id = p_tenant_id
     order by (s.admission_state = 'granted') desc, s.updated_at desc
     limit 1;
    v_has_sub := found;
    if v_has_sub and v_sub.admission_state = 'granted' and v_licensed_active
       and v_admission.grant_reference = 'stripe:' || v_sub.provider_subscription_id then
      v_plan_id := v_sub.plan_id;
      v_source := 'stripe_subscription';
    else
      select t.plan into v_label from public.teams t where t.tenant_id = p_tenant_id limit 1;
      if v_label is not null and app.catalog_plan_id(v_label) <> 'free' then
        if v_licensed_active or v_pilot_approved then
          v_plan_id := app.catalog_plan_id(v_label);
          v_source := 'team_record';
        else
          v_source := 'admission_inactive';
        end if;
      end if;
    end if;
    -- A verified trial evaluates the self-serve paid edition.
    if v_trial_active and v_plan_id = 'free' then
      v_plan_id := 'team';
      v_source := 'trial';
    end if;
  end if;

  select * into v_plan from public.plans where id = v_plan_id;
  if not found then
    raise exception 'tenant_plan_unavailable' using errcode = '55000';
  end if;

  return jsonb_build_object(
    'tenant_id', p_tenant_id,
    'plan_id', v_plan.id,
    'plan_source', v_source,
    'trial_active', v_trial_active,
    'features', v_plan.features,
    'retention_days_max', v_plan.retention_days);
end;
$$;
revoke all on function app.tenant_plan_entitlements(uuid) from public, anon, authenticated, service_role;

-- Service-role entry point for Edge Functions (`requireFeature`).
create or replace function public.tenant_plan_entitlements(p_tenant_id uuid)
returns jsonb
language sql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
  select app.tenant_plan_entitlements(p_tenant_id);
$$;
revoke all on function public.tenant_plan_entitlements(uuid) from public, anon, authenticated;
grant execute on function public.tenant_plan_entitlements(uuid) to service_role;

-- Member projection for dashboard gating; same resolver, membership re-checked.
create or replace function public.get_tenant_plan_entitlements(p_tenant_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
begin
  if auth.uid() is null
     or p_tenant_id is null
     or not app.is_tenant_member(p_tenant_id)
     or not public.tenant_identity_access_allowed(p_tenant_id) then
    raise exception 'tenant_plan_access_denied' using errcode = '42501';
  end if;
  return app.tenant_plan_entitlements(p_tenant_id);
end;
$$;
revoke all on function public.get_tenant_plan_entitlements(uuid) from public, anon;
grant execute on function public.get_tenant_plan_entitlements(uuid) to authenticated;

-- Boolean gate for RLS. Any failure to resolve the plan is "not entitled".
create or replace function app.tenant_has_plan_feature(p_tenant_id uuid, p_feature text)
returns boolean
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
begin
  if p_tenant_id is null or p_feature is null then return false; end if;
  return coalesce((app.tenant_plan_entitlements(p_tenant_id) -> 'features') ? p_feature, false);
exception when others then
  return false;
end;
$$;
revoke all on function app.tenant_has_plan_feature(uuid, text) from public, anon;
grant execute on function app.tenant_has_plan_feature(uuid, text) to authenticated, service_role;

-- ── 2. AI Security Posture views (BUSINESS and up) ──────────────────────────

drop policy if exists posture_findings_plan_feature on public.posture_findings;
create policy posture_findings_plan_feature on public.posture_findings
  as restrictive for select to authenticated
  using (app.tenant_has_plan_feature(tenant_id, 'ai_security_posture'));

-- ── 3. Retention bound to plan ──────────────────────────────────────────────

-- Effective retention for one class. Only the telemetry (event) class carries
-- the catalog's "event retention" term; every other class keeps its policy.
-- An unresolvable plan keeps the tenant's own setting (the pre-plan behaviour)
-- rather than aborting the reaper batch for every tenant.
create or replace function app.tenant_effective_retention_days(
  p_tenant_id uuid,
  p_data_class text,
  p_configured_days integer,
  p_explicitly_configured boolean
) returns integer
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_max integer;
begin
  if p_data_class is distinct from 'telemetry' or p_configured_days is null then
    return p_configured_days;
  end if;
  begin
    v_max := (app.tenant_plan_entitlements(p_tenant_id) ->> 'retention_days_max')::integer;
  exception when others then
    return p_configured_days;
  end;
  if v_max is null then return p_configured_days; end if;
  if coalesce(p_explicitly_configured, false) then
    return least(p_configured_days, v_max);
  end if;
  return v_max;
end;
$$;
revoke all on function app.tenant_effective_retention_days(uuid, text, integer, boolean)
  from public, anon, authenticated;
grant execute on function app.tenant_effective_retention_days(uuid, text, integer, boolean)
  to service_role;

-- The reaper now deletes at the effective (plan-capped) period.
create or replace function public.prune_expired_telemetry_events(
  p_limit integer default 100,
  p_apply boolean default true,
  p_cutoff timestamptz default now()
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_tenant uuid;
  v_retention_days integer;
  v_explicit boolean;
  v_eligible integer := 0;
  v_deleted integer := 0;
  v_count integer;
  v_contended integer := 0;
  v_held_tenants integer := 0;
  v_missing_policy_tenants integer := 0;
  v_hold_race_skips integer := 0;
begin
  if p_limit is null or p_limit not between 1 and 1000 or p_apply is null or p_cutoff is null then
    raise exception 'invalid_retention_batch' using errcode = '22023';
  end if;
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  p_cutoff := least(p_cutoff, now());

  select count(*) into v_missing_policy_tenants from (
    select t.id
    from public.tenants t
    where t.status = 'active'
      and exists (select 1 from public.events e where e.tenant_id = t.id)
      and not exists (
        select 1 from public.tenant_data_retention_policies p
        where p.tenant_id = t.id and p.data_class = 'telemetry'
      )
    order by t.id
    limit (p_limit + 1)
  ) missing_policy;

  select count(*) into v_held_tenants from (
    select p.tenant_id
    from public.tenant_data_retention_policies p
    join public.tenants t on t.id = p.tenant_id and t.status = 'active'
    where p.data_class = 'telemetry'
      and exists (
        select 1 from public.events e
        where e.tenant_id = p.tenant_id
          and e.created_at <= p_cutoff - make_interval(days =>
            app.tenant_effective_retention_days(p.tenant_id, p.data_class, p.retention_days, p.updated_by is not null))
      )
      and exists (
        select 1 from public.tenant_legal_holds h
        where h.tenant_id = p.tenant_id and h.released_at is null
      )
    order by p.tenant_id
    limit (p_limit + 1)
  ) held;

  for v_tenant in
    select p.tenant_id
    from public.tenant_data_retention_policies p
    join public.tenants t on t.id = p.tenant_id and t.status = 'active'
    where p.data_class = 'telemetry'
      and exists (
        select 1 from public.events e
        where e.tenant_id = p.tenant_id
          and e.created_at <= p_cutoff - make_interval(days =>
            app.tenant_effective_retention_days(p.tenant_id, p.data_class, p.retention_days, p.updated_by is not null))
      )
      and not exists (
        select 1 from public.tenant_legal_holds h
        where h.tenant_id = p.tenant_id and h.released_at is null
      )
    order by p.tenant_id
    limit p_limit
  loop
    exit when v_eligible >= p_limit;
    if not pg_try_advisory_xact_lock(hashtextextended(v_tenant::text, 2606)) then
      v_contended := v_contended + 1;
      continue;
    end if;

    -- Re-read policy, status, and hold state after acquiring the shared tenant lock.
    select p.retention_days, p.updated_by is not null into v_retention_days, v_explicit
    from public.tenant_data_retention_policies p
    join public.tenants t on t.id = p.tenant_id and t.status = 'active'
    where p.tenant_id = v_tenant and p.data_class = 'telemetry'
    for share of p;
    if not found then continue; end if;
    v_retention_days := app.tenant_effective_retention_days(v_tenant, 'telemetry', v_retention_days, v_explicit);
    if exists (select 1 from public.tenant_legal_holds where tenant_id = v_tenant and released_at is null) then
      v_hold_race_skips := v_hold_race_skips + 1;
      continue;
    end if;

    if p_apply then
      delete from public.events e using (
        select id from public.events
        where tenant_id = v_tenant
          and created_at <= p_cutoff - make_interval(days => v_retention_days)
        order by created_at, id
        limit (p_limit - v_eligible)
        for update
      ) expired where e.id = expired.id and e.tenant_id = v_tenant;
      get diagnostics v_count = row_count;
      v_deleted := v_deleted + v_count;
    else
      select count(*) into v_count from (
        select 1 from public.events
        where tenant_id = v_tenant
          and created_at <= p_cutoff - make_interval(days => v_retention_days)
        order by created_at, id
        limit (p_limit - v_eligible)
      ) expired;
    end if;
    v_eligible := v_eligible + v_count;
  end loop;

  return jsonb_build_object(
    'applied', p_apply,
    'cutoff', p_cutoff,
    'events_eligible', v_eligible,
    'events_deleted', v_deleted,
    'active_tenants_missing_policy', least(v_missing_policy_tenants, p_limit),
    'missing_policy_tenants_truncated', v_missing_policy_tenants > p_limit,
    'held_tenants', least(v_held_tenants, p_limit),
    'held_tenants_truncated', v_held_tenants > p_limit,
    'hold_race_skips', v_hold_race_skips,
    'contended_tenants', v_contended
  );
end;
$$;
revoke all on function public.prune_expired_telemetry_events(integer, boolean, timestamptz)
  from public, anon, authenticated;
grant execute on function public.prune_expired_telemetry_events(integer, boolean, timestamptz)
  to service_role;

-- The admin path refuses a telemetry period above the plan's term instead of
-- storing a value that would never take effect.
create or replace function public.admin_set_tenant_retention(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_data_class text,
  p_retention_days integer,
  p_reason text
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog, pg_temp
as $$
declare
  v_bounds public.retention_policy_bounds;
  v_previous integer;
  v_plan_max integer;
begin
  perform app.retention_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  if p_data_class is null or p_retention_days is null
     or p_reason is null or p_reason <> btrim(p_reason) or length(p_reason) not between 1 and 500
     or p_reason ~ '[[:cntrl:]]' then
    raise exception 'retention_invalid_request' using errcode = '22023';
  end if;
  -- Same tenant lock as hold placement, routine retention and offboarding.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  select * into v_bounds from public.retention_policy_bounds where data_class = p_data_class;
  if not found or not v_bounds.tenant_configurable then
    raise exception 'retention_class_not_configurable' using errcode = '22023';
  end if;
  if p_retention_days < v_bounds.min_days or p_retention_days > v_bounds.max_days then
    raise exception 'retention_days_out_of_bounds' using errcode = '22023',
      detail = format('allowed %s..%s days', v_bounds.min_days, v_bounds.max_days);
  end if;
  if p_data_class = 'telemetry' then
    -- Fails closed: an unresolvable plan raises and nothing is changed.
    v_plan_max := (app.tenant_plan_entitlements(p_tenant_id) ->> 'retention_days_max')::integer;
    if v_plan_max is not null and p_retention_days > v_plan_max then
      raise exception 'retention_days_exceeds_plan' using errcode = '22023',
        detail = format('plan allows at most %s days', v_plan_max);
    end if;
  end if;
  -- Phase eligibility is snapshotted per offboarding run; do not change it mid-run.
  if exists (select 1 from public.tenant_offboarding_runs where tenant_id = p_tenant_id and status <> 'completed') then
    raise exception 'retention_change_refused_offboarding' using errcode = '55000';
  end if;
  select retention_days into v_previous
    from public.tenant_data_retention_policies
   where tenant_id = p_tenant_id and data_class = p_data_class
   for update;
  if not found then
    raise exception 'retention_policy_missing' using errcode = 'P0002';
  end if;
  if v_previous = p_retention_days then
    return jsonb_build_object('data_class', p_data_class, 'retention_days', v_previous,
                              'previous_retention_days', v_previous, 'changed', false);
  end if;
  update public.tenant_data_retention_policies
     set retention_days = p_retention_days, updated_by = p_actor_user_id
   where tenant_id = p_tenant_id and data_class = p_data_class;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (p_actor_user_id, p_tenant_id, 'retention.policy.changed',
      jsonb_build_object('data_class', p_data_class, 'previous_days', v_previous,
                         'new_days', p_retention_days, 'reason', p_reason));
  return jsonb_build_object('data_class', p_data_class, 'retention_days', p_retention_days,
                            'previous_retention_days', v_previous, 'changed', true);
end;
$$;

revoke all on function public.admin_set_tenant_retention(uuid, uuid, text, integer, text) from public, anon, authenticated;
grant execute on function public.admin_set_tenant_retention(uuid, uuid, text, integer, text) to service_role;

-- ── 4. Administrative audit trail for owners and admins ────────────────────

create index if not exists admin_audit_logs_tenant_created_idx
  on public.admin_audit_logs (tenant_id, created_at desc, id desc);

create or replace function public.list_tenant_admin_audit_logs(
  p_tenant_id uuid,
  p_limit integer default 50,
  p_before_created_at timestamptz default null,
  p_before_id bigint default null
) returns table(id bigint, created_at timestamptz, actor_user_id uuid, target_user_id uuid,
                action text, detail jsonb)
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
begin
  if auth.uid() is null
     or p_tenant_id is null
     or not public.tenant_identity_access_allowed(p_tenant_id)
     or not exists (
       select 1 from public.tenant_members m
        where m.tenant_id = p_tenant_id
          and m.user_id = auth.uid()
          and m.role in ('owner', 'admin')
          and (m.expires_at is null or m.expires_at > clock_timestamp())) then
    raise exception 'admin_audit_access_denied' using errcode = '42501';
  end if;
  if p_limit is null or p_limit not between 1 and 200
     or (p_before_created_at is null) <> (p_before_id is null) then
    raise exception 'admin_audit_invalid_page' using errcode = '22023';
  end if;
  return query
    select a.id, a.created_at, a.actor_user_id, a.target_user_id, a.action, a.detail
      from public.admin_audit_logs a
     where a.tenant_id = p_tenant_id
       and (p_before_created_at is null
            or (a.created_at, a.id) < (p_before_created_at, p_before_id))
     order by a.created_at desc, a.id desc
     limit p_limit;
end;
$$;
revoke all on function public.list_tenant_admin_audit_logs(uuid, integer, timestamptz, bigint)
  from public, anon;
grant execute on function public.list_tenant_admin_audit_logs(uuid, integer, timestamptz, bigint)
  to authenticated;
