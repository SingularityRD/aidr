-- Reap active-tenant telemetry using each tenant's configured retention policy.
-- Legal holds and offboarding serialize on the same tenant lock as routine retention.
create function public.prune_expired_telemetry_events(
  p_limit integer default 100,
  p_apply boolean default true,
  p_cutoff timestamptz default now()
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_tenant uuid;
  v_retention_days integer;
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
          and e.created_at <= p_cutoff - make_interval(days => p.retention_days)
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
          and e.created_at <= p_cutoff - make_interval(days => p.retention_days)
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
    select p.retention_days into v_retention_days
    from public.tenant_data_retention_policies p
    join public.tenants t on t.id = p.tenant_id and t.status = 'active'
    where p.tenant_id = v_tenant and p.data_class = 'telemetry'
    for share of p;
    if not found then continue; end if;
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
