-- Delete expired invitations after the tenant's existing identity_membership
-- retention window. Active legal holds and non-active tenants are preserved.
-- The matching maintenance worker is an external side effect owner; this RPC
-- performs bounded database deletion only and never touches accepted invites.
create index if not exists team_invitations_expired_prune_idx
  on public.team_invitations (tenant_id, expires_at, created_at, id)
  where accepted_at is null;

create function public.prune_expired_team_invitations(
  p_limit integer default 100,
  p_apply boolean default true
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
declare
  v_cutoff timestamptz := clock_timestamp();
  v_tenant uuid;
  v_retention_days integer;
  v_eligible integer := 0;
  v_deleted integer := 0;
  v_count integer;
  v_remaining integer := 0;
  v_contended integer := 0;
  v_hold_race_skips integer := 0;
  v_missing_policy integer := 0;
  v_held integer := 0;
  v_inactive integer := 0;
begin
  if p_limit is null or p_limit not between 1 and 1000 or p_apply is null then
    raise exception 'invalid_invitation_retention_batch' using errcode = '22023';
  end if;
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'invitation_retention_requires_read_committed' using errcode = '25001';
  end if;

  -- Missing policy is a visible hold, not an implicit zero-day lifetime. Count
  -- active tenants with expired unaccepted invitations whose retention age
  -- cannot be evaluated; operators must repair policy before claiming clean.
  select count(*) into v_missing_policy from (
    select t.id
    from public.tenants t
    where t.status = 'active'
      and exists (
        select 1 from public.team_invitations i
        where i.tenant_id = t.id and i.accepted_at is null and i.expires_at <= v_cutoff
      )
      and not exists (
        select 1 from public.tenant_data_retention_policies p
        where p.tenant_id = t.id and p.data_class = 'identity_membership'
      )
    order by t.id
    limit (p_limit + 1)
  ) missing_policy;

  select count(*) into v_held from (
    select p.tenant_id
    from public.tenant_data_retention_policies p
    join public.tenants t on t.id = p.tenant_id and t.status = 'active'
    where p.data_class = 'identity_membership'
      and exists (
        select 1 from public.team_invitations i
        where i.tenant_id = p.tenant_id and i.accepted_at is null
          and i.expires_at <= v_cutoff
          and i.created_at <= v_cutoff - make_interval(days => p.retention_days)
      )
      and exists (
        select 1 from public.tenant_legal_holds h
        where h.tenant_id = p.tenant_id and h.released_at is null
      )
    order by p.tenant_id
    limit (p_limit + 1)
  ) held;

  select count(*) into v_inactive from (
    select p.tenant_id
    from public.tenant_data_retention_policies p
    join public.tenants t on t.id = p.tenant_id and t.status <> 'active'
    where p.data_class = 'identity_membership'
      and exists (
        select 1 from public.team_invitations i
        where i.tenant_id = p.tenant_id and i.accepted_at is null
          and i.expires_at <= v_cutoff
          and i.created_at <= v_cutoff - make_interval(days => p.retention_days)
      )
    order by p.tenant_id
    limit (p_limit + 1)
  ) inactive;

  for v_tenant in
    select p.tenant_id
    from public.tenant_data_retention_policies p
    join public.tenants t on t.id = p.tenant_id and t.status = 'active'
    where p.data_class = 'identity_membership'
      and exists (
        select 1 from public.team_invitations i
        where i.tenant_id = p.tenant_id and i.accepted_at is null
          and i.expires_at <= v_cutoff
          and i.created_at <= v_cutoff - make_interval(days => p.retention_days)
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

    -- Re-read tenant state and policy after taking the same lock as legal-hold
    -- placement and offboarding. A concurrent hold wins before any delete.
    select p.retention_days into v_retention_days
    from public.tenant_data_retention_policies p
    join public.tenants t on t.id = p.tenant_id and t.status = 'active'
    where p.tenant_id = v_tenant and p.data_class = 'identity_membership'
    for share of p, t;
    if not found then continue; end if;
    if exists (
      select 1 from public.tenant_legal_holds h
      where h.tenant_id = v_tenant and h.released_at is null
    ) then
      v_hold_race_skips := v_hold_race_skips + 1;
      continue;
    end if;

    if p_apply then
      delete from public.team_invitations i using (
        select candidate.id
        from public.team_invitations candidate
        where candidate.tenant_id = v_tenant
          and candidate.accepted_at is null
          and candidate.expires_at <= v_cutoff
          and candidate.created_at <= v_cutoff - make_interval(days => v_retention_days)
        order by candidate.created_at, candidate.id
        limit (p_limit - v_eligible)
        for update
      ) due
      where i.id = due.id and i.tenant_id = v_tenant;
      get diagnostics v_count = row_count;
      v_deleted := v_deleted + v_count;
    else
      select count(*) into v_count from (
        select 1 from public.team_invitations candidate
        where candidate.tenant_id = v_tenant
          and candidate.accepted_at is null
          and candidate.expires_at <= v_cutoff
          and candidate.created_at <= v_cutoff - make_interval(days => v_retention_days)
        order by candidate.created_at, candidate.id
        limit (p_limit - v_eligible)
      ) due;
    end if;
    v_eligible := v_eligible + v_count;
  end loop;

  select 1 into v_remaining
  from public.team_invitations i
  join public.tenants t on t.id = i.tenant_id and t.status = 'active'
  join public.tenant_data_retention_policies p
    on p.tenant_id = i.tenant_id and p.data_class = 'identity_membership'
  where i.accepted_at is null and i.expires_at <= v_cutoff
    and i.created_at <= v_cutoff - make_interval(days => p.retention_days)
    and not exists (
      select 1 from public.tenant_legal_holds h
      where h.tenant_id = i.tenant_id and h.released_at is null
    )
  limit 1;
  v_remaining := coalesce(v_remaining, 0);

  return jsonb_build_object(
    'applied', p_apply,
    'cutoff', v_cutoff,
    'eligible', v_eligible,
    'deleted', v_deleted,
    'remaining', v_remaining,
    'contended_tenants', v_contended,
    'hold_race_skips', v_hold_race_skips,
    'active_tenants_missing_policy', least(v_missing_policy, p_limit),
    'missing_policy_tenants_truncated', v_missing_policy > p_limit,
    'held_tenants_present', least(v_held, p_limit),
    'held_tenants_truncated', v_held > p_limit,
    'inactive_tenant_rows_present', least(v_inactive, p_limit),
    'inactive_tenant_rows_truncated', v_inactive > p_limit
  );
end;
$$;

revoke all on function public.prune_expired_team_invitations(integer, boolean)
  from public, anon, authenticated;
grant execute on function public.prune_expired_team_invitations(integer, boolean)
  to service_role;
