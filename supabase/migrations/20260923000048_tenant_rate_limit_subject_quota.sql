-- A full tenant bucket must reject before allocating a new subject bucket.
-- Previously a caller could generate unlimited distinct subject rows after
-- exhausting the tenant's minute quota, despite every request returning 429.
create or replace function public.consume_tenant_rate_limit(
  p_tenant_id uuid,
  p_subject text,
  p_endpoint text,
  p_window_start bigint,
  p_subject_limit integer,
  p_tenant_limit integer,
  p_cost integer default 1
)
returns table (allowed boolean, remaining integer)
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_subject_key text;
  v_tenant_key text;
  v_subject_count integer;
  v_tenant_count integer;
begin
  if p_tenant_id is null
     or p_subject is null or length(p_subject) < 1 or octet_length(p_subject) > 512
     or p_endpoint is null or p_endpoint !~ '^[A-Za-z0-9_.:/-]{1,64}$'
     or p_window_start is null or p_window_start < 0
     or p_subject_limit is null or p_subject_limit < 1 or p_subject_limit > 1000000
     or p_tenant_limit is null or p_tenant_limit < p_subject_limit or p_tenant_limit > 1000000
     or p_cost is null or p_cost < 1 or p_cost > 1000000 then
    raise exception using errcode = '22023', message = 'invalid rate limit contract';
  end if;

  if not exists (
    select 1 from public.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception using errcode = '42501', message = 'tenant is not active';
  end if;

  v_tenant_key := 'api:v1:' || encode(
    extensions.digest(p_tenant_id::text || ':tenant:' || p_endpoint, 'sha256'), 'hex'
  );
  v_subject_key := 'api:v1:' || encode(
    extensions.digest(p_tenant_id::text || ':subject:' || p_subject || ':' || p_endpoint, 'sha256'), 'hex'
  );

  insert into public.rate_limits (key, window_start, count, tenant_id)
  values (v_tenant_key, p_window_start, 0, p_tenant_id)
  on conflict (key, window_start) do nothing;

  -- Every request takes this lock first. A full tenant rejects without
  -- creating an unbounded series of zero-count per-subject rows.
  select rl.count into strict v_tenant_count
  from public.rate_limits rl
  where rl.key = v_tenant_key
    and rl.window_start = p_window_start
    and rl.tenant_id = p_tenant_id
  for update;

  if v_tenant_count > p_tenant_limit - p_cost then
    return query select false, greatest(0, p_tenant_limit - v_tenant_count);
    return;
  end if;

  insert into public.rate_limits (key, window_start, count, tenant_id)
  values (v_subject_key, p_window_start, 0, p_tenant_id)
  on conflict (key, window_start) do nothing;

  select rl.count into strict v_subject_count
  from public.rate_limits rl
  where rl.key = v_subject_key
    and rl.window_start = p_window_start
    and rl.tenant_id = p_tenant_id
  for update;

  if v_subject_count > p_subject_limit - p_cost then
    return query select false, greatest(0, least(
      p_tenant_limit - v_tenant_count,
      p_subject_limit - v_subject_count
    ));
    return;
  end if;

  update public.rate_limits
  set count = count + p_cost
  where key = v_tenant_key
    and window_start = p_window_start
    and tenant_id = p_tenant_id;

  update public.rate_limits
  set count = count + p_cost
  where key = v_subject_key
    and window_start = p_window_start
    and tenant_id = p_tenant_id;

  return query select true, least(
    p_tenant_limit - (v_tenant_count + p_cost),
    p_subject_limit - (v_subject_count + p_cost)
  );
end;
$$;

revoke all on function public.consume_tenant_rate_limit(uuid, text, text, bigint, integer, integer, integer)
  from public, anon, authenticated;
grant execute on function public.consume_tenant_rate_limit(uuid, text, text, bigint, integer, integer, integer)
  to service_role;
