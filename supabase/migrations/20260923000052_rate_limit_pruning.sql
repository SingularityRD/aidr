-- Rate-limit buckets are operational counters, not durable audit evidence.
-- All current writers use one-minute windows except identity reset/break-glass
-- (ten minutes). A five-minute margin after the *last update* protects both.
create index if not exists rate_limits_updated_at_idx
  on public.rate_limits (updated_at);

create function public.prune_expired_rate_limits(p_limit integer, p_apply boolean)
returns jsonb language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
declare
  v_cutoff timestamptz := clock_timestamp() - interval '15 minutes';
  v_eligible integer := 0;
  v_deleted integer := 0;
  v_remaining integer := 0;
  v_batch_eligible integer;
  v_batch_deleted integer;
  v_tenant uuid;
  v_contended integer := 0;
  v_held integer := 0;
  v_inactive integer := 0;
begin
  if p_limit is null or p_limit not between 1 and 1000 or p_apply is null then
    raise exception 'invalid_rate_limit_prune' using errcode = '22023';
  end if;

  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'rate_limit_prune_requires_read_committed' using errcode = '25001';
  end if;

  if p_apply then
    -- Global legacy counters have no tenant association. Tenant counters use
    -- the same advisory lock as hold placement and offboarding below.
    with candidate as materialized (
      select key, window_start from public.rate_limits
      where tenant_id is null and updated_at < v_cutoff
        and window_start < case
          when key like 'identity-reset:%' or key like 'identity-break-glass:%'
            then floor(extract(epoch from v_cutoff) / 600)::bigint
          else floor(extract(epoch from v_cutoff) / 60)::bigint end
      order by updated_at, key, window_start
      limit p_limit for update skip locked
    ), deleted as (
      delete from public.rate_limits r using candidate c
      where r.key = c.key and r.window_start = c.window_start
        and r.tenant_id is null and r.updated_at < v_cutoff
        and r.window_start < case
          when r.key like 'identity-reset:%' or r.key like 'identity-break-glass:%'
            then floor(extract(epoch from v_cutoff) / 600)::bigint
          else floor(extract(epoch from v_cutoff) / 60)::bigint end
      returning 1
    )
    select (select count(*) from candidate), (select count(*) from deleted)
      into v_eligible, v_deleted;

    for v_tenant in
      select distinct due.tenant_id from (
        select r.tenant_id from public.rate_limits r
        join public.tenants t on t.id = r.tenant_id and t.status = 'active'
        where r.updated_at < v_cutoff
          and r.window_start < case
            when r.key like 'identity-reset:%' or r.key like 'identity-break-glass:%'
              then floor(extract(epoch from v_cutoff) / 600)::bigint
            else floor(extract(epoch from v_cutoff) / 60)::bigint end
          and not exists (select 1 from public.tenant_legal_holds h
            where h.tenant_id = r.tenant_id and h.released_at is null)
        order by r.updated_at limit p_limit
      ) due
    loop
      exit when v_eligible >= p_limit;
      if not pg_try_advisory_xact_lock(hashtextextended(v_tenant::text, 2606)) then
        v_contended := v_contended + 1;
        continue;
      end if;
      -- The shared lock makes this recheck atomic with hold/offboarding.
      if not exists (select 1 from public.tenants t
        where t.id = v_tenant and t.status = 'active')
        or exists (select 1 from public.tenant_legal_holds h
          where h.tenant_id = v_tenant and h.released_at is null) then
        continue;
      end if;
      with candidate as materialized (
        select key, window_start from public.rate_limits
        where tenant_id = v_tenant and updated_at < v_cutoff
          and window_start < case
            when key like 'identity-reset:%' or key like 'identity-break-glass:%'
              then floor(extract(epoch from v_cutoff) / 600)::bigint
            else floor(extract(epoch from v_cutoff) / 60)::bigint end
        order by updated_at, key, window_start
        limit (p_limit - v_eligible) for update skip locked
      ), deleted as (
        delete from public.rate_limits r using candidate c
        where r.key = c.key and r.window_start = c.window_start
          and r.tenant_id = v_tenant and r.updated_at < v_cutoff
          and r.window_start < case
            when r.key like 'identity-reset:%' or r.key like 'identity-break-glass:%'
              then floor(extract(epoch from v_cutoff) / 600)::bigint
            else floor(extract(epoch from v_cutoff) / 60)::bigint end
        returning 1
      )
      select (select count(*) from candidate), (select count(*) from deleted)
        into v_batch_eligible, v_batch_deleted;
      v_eligible := v_eligible + v_batch_eligible;
      v_deleted := v_deleted + v_batch_deleted;
    end loop;
  else
    select count(*) into v_eligible from (
      select 1 from public.rate_limits r
      where r.updated_at < v_cutoff
        and r.window_start < case
          when r.key like 'identity-reset:%' or r.key like 'identity-break-glass:%'
            then floor(extract(epoch from v_cutoff) / 600)::bigint
          else floor(extract(epoch from v_cutoff) / 60)::bigint end
        and (r.tenant_id is null or (
        exists (select 1 from public.tenants t where t.id = r.tenant_id and t.status = 'active')
        and not exists (select 1 from public.tenant_legal_holds h
          where h.tenant_id = r.tenant_id and h.released_at is null)
      )) limit p_limit
    ) due;
  end if;

  select count(*) into v_remaining from (
    select 1 from public.rate_limits r
    where r.updated_at < v_cutoff
      and r.window_start < case
        when r.key like 'identity-reset:%' or r.key like 'identity-break-glass:%'
          then floor(extract(epoch from v_cutoff) / 600)::bigint
        else floor(extract(epoch from v_cutoff) / 60)::bigint end
      and (r.tenant_id is null or (
      exists (select 1 from public.tenants t where t.id = r.tenant_id and t.status = 'active')
      and not exists (select 1 from public.tenant_legal_holds h
        where h.tenant_id = r.tenant_id and h.released_at is null)
    )) limit 1
  ) due;
  select count(*) into v_held from (
    select 1 from public.rate_limits r
    where r.updated_at < v_cutoff and r.tenant_id is not null
      and exists (select 1 from public.tenant_legal_holds h
        where h.tenant_id = r.tenant_id and h.released_at is null)
    limit 1
  ) held;
  select count(*) into v_inactive from (
    select 1 from public.rate_limits r
    where r.updated_at < v_cutoff and r.tenant_id is not null
      and not exists (select 1 from public.tenants t
        where t.id = r.tenant_id and t.status = 'active')
    limit 1
  ) inactive;
  return jsonb_build_object('eligible', v_eligible, 'deleted', v_deleted,
    'remaining', v_remaining, 'applied', p_apply, 'cutoff', v_cutoff,
    'contended_tenants', v_contended, 'held_tenants_present', v_held,
    'inactive_tenant_rows_present', v_inactive);
end;
$$;
revoke all on function public.prune_expired_rate_limits(integer, boolean)
  from public, anon, authenticated;
grant execute on function public.prune_expired_rate_limits(integer, boolean)
  to service_role;
