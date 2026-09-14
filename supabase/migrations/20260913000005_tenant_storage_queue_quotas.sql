-- Tenant-scoped storage bytes, a per-tenant fleet-response queue ceiling, and a
-- hardened replacement for the legacy caller-key rate limiter.
--
-- 1. `aidr-audit-exports` is the only writable bucket. `audit_export_objects`
--    now records the byte size of each object and `register_audit_export_object`
--    reserves those bytes under a tenant advisory lock *before* the Edge
--    Function uploads, so two concurrent exports cannot both pass the same byte
--    budget. Reads on `storage.objects` are tenant-folder bound; client roles
--    can never create, replace or delete an export object.
-- 2. `poll_fleet_response_command` leases one command with
--    `for update skip locked limit 1`. That is a delivery lease, not a depth
--    bound: nothing stopped a tenant from queueing unbounded work. The bounded
--    entry point enforces a reviewed ceiling inside one transaction and the
--    unbounded entry point is removed from the RPC surface.
-- 3. `increment_rate_limit` accepted any caller-chosen key. The replacement
--    refuses keys outside the reviewed scope allowlist and refuses a
--    non-positive or oversized delta, and its EXECUTE grants are re-asserted as
--    service-role only (supabase/README.md: "keep their EXECUTE grants
--    restricted after every schema change").

-- ---------------------------------------------------------------------------
-- 1. Per-tenant storage byte quota
-- ---------------------------------------------------------------------------

comment on table public.audit_export_objects is
  'Temporary private export objects. `bytes` is the reserved size of the stored '
  'object and the tenant quota ledger; the row is deleted together with the '
  'object (retention reaper / tenant offboarding), which releases the quota.';

alter table public.audit_export_objects
  add column if not exists bytes bigint not null default 0 check (bytes >= 0);

-- Existing rows predate the ledger. Recover their size from the object metadata
-- when the storage schema is present; a row that never recorded a size stays 0
-- and is released by the normal retention path within one day.
do $migration$
begin
  if to_regclass('storage.objects') is not null then
    update public.audit_export_objects o
    set bytes = greatest(0, coalesce((
      select case
        when so.metadata->>'size' ~ '^[0-9]{1,12}$' then (so.metadata->>'size')::bigint
        else 0
      end
      from storage.objects so
      where so.bucket_id = 'aidr-audit-exports' and so.name = o.path
    ), 0))
    where o.bytes = 0;
  end if;
end;
$migration$;

create function public.register_audit_export_object(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_path text,
  p_bytes bigint,
  p_limit_bytes bigint
)
returns table (allowed boolean, remaining_bytes bigint)
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_used bigint;
begin
  -- The ceiling is a caller-supplied plan figure like the rate-limit limits, but
  -- it is bounded here: a caller cannot raise its own storage budget to the
  -- point where the check is decorative.
  if p_tenant_id is null
     or p_actor_user_id is null
     or p_path is null
     or p_path !~ '^[0-9a-f-]{36}/[0-9a-f-]{36}\.(csv|json)$'
     or split_part(p_path, '/', 1) <> p_tenant_id::text
     or p_bytes is null or p_bytes < 1 or p_bytes > 8388608
     or p_limit_bytes is null or p_limit_bytes < 1 or p_limit_bytes > 1099511627776 then
    raise exception using errcode = '22023', message = 'invalid_tenant_storage_contract';
  end if;

  if not exists (
    select 1 from public.tenants t where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception using errcode = '42501', message = 'tenant is not active';
  end if;

  -- One tenant lock for the usage read and the reservation insert: concurrent
  -- exports of the same tenant can never both observe the pre-limit usage.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2615));

  select coalesce(sum(o.bytes), 0) into v_used
  from public.audit_export_objects o
  where o.tenant_id = p_tenant_id;

  -- A retry of an already-reserved path is not a second reservation.
  if exists (select 1 from public.audit_export_objects o where o.path = p_path) then
    return query select true, greatest(0, p_limit_bytes - v_used);
    return;
  end if;

  if v_used + p_bytes > p_limit_bytes then
    return query select false, greatest(0, p_limit_bytes - v_used);
    return;
  end if;

  insert into public.audit_export_objects (path, tenant_id, created_by, bytes)
  values (p_path, p_tenant_id, p_actor_user_id, p_bytes);

  insert into public.admin_audit_logs (actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, 'storage.audit_export.reserved',
    jsonb_build_object('path', p_path, 'bytes', p_bytes,
      'tenant_bytes', v_used + p_bytes, 'limit_bytes', p_limit_bytes));

  return query select true, greatest(0, p_limit_bytes - (v_used + p_bytes));
end;
$$;

revoke all on function public.register_audit_export_object(uuid, uuid, text, bigint, bigint)
  from public, anon, authenticated;
grant execute on function public.register_audit_export_object(uuid, uuid, text, bigint, bigint)
  to service_role;

-- Reads are bound to the caller's own tenant folder. Writes stay service-role
-- only: no permissive write policy exists for the bucket, and the restrictive
-- policies below keep it that way even if a future migration adds one.
alter table storage.objects enable row level security;

drop policy if exists audit_exports_read_own_tenant on storage.objects;
create policy audit_exports_read_own_tenant on storage.objects
  for select to authenticated
  using (
    bucket_id = 'aidr-audit-exports'
    and (storage.foldername(name))[1] = app.current_tenant_id()::text
    and app.is_tenant_member(app.current_tenant_id())
  );

drop policy if exists audit_exports_client_insert_denied on storage.objects;
create policy audit_exports_client_insert_denied on storage.objects
  as restrictive for insert to anon, authenticated
  with check (bucket_id <> 'aidr-audit-exports');

drop policy if exists audit_exports_client_update_denied on storage.objects;
create policy audit_exports_client_update_denied on storage.objects
  as restrictive for update to anon, authenticated
  using (bucket_id <> 'aidr-audit-exports');

drop policy if exists audit_exports_client_delete_denied on storage.objects;
create policy audit_exports_client_delete_denied on storage.objects
  as restrictive for delete to anon, authenticated
  using (bucket_id <> 'aidr-audit-exports');

-- ---------------------------------------------------------------------------
-- 2. Per-tenant fleet-response command depth
-- ---------------------------------------------------------------------------

create function public.queue_bounded_fleet_response_command(
  p_tenant_id uuid, p_actor_user_id uuid, p_agent_id uuid,
  p_command_type text, p_reason text, p_idempotency_key text,
  p_ttl_seconds integer, p_rollback_of uuid default null
)
returns public.fleet_response_commands
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  -- Reviewed ceiling for live commands per tenant. Expired commands do not
  -- count, and a rollback is exempt: an operator must always be able to release
  -- a containment action they queued, and `unique(rollback_of)` already bounds
  -- how many rollbacks can exist.
  c_max_outstanding constant integer := 200;
  v_outstanding integer;
  v_command public.fleet_response_commands;
begin
  if p_tenant_id is null or p_idempotency_key is null then
    raise exception 'invalid_fleet_command' using errcode='22023';
  end if;

  -- One tenant lock around the depth check and the insert. The bounded function
  -- then takes the inner per-idempotency-key lock, so the lock order is always
  -- tenant -> key.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2616));

  if p_rollback_of is null and not exists (
    select 1 from public.fleet_response_commands c
    where c.tenant_id = p_tenant_id and c.idempotency_key = p_idempotency_key
  ) then
    select count(*) into v_outstanding
    from public.fleet_response_commands c
    where c.tenant_id = p_tenant_id
      and c.state in ('pending', 'delivered', 'acknowledged')
      and c.expires_at > now();
    if v_outstanding >= c_max_outstanding then
      raise exception 'tenant_queue_limit_reached' using errcode='54000';
    end if;
  end if;

  select * into v_command from public.queue_fleet_response_command(
    p_tenant_id, p_actor_user_id, p_agent_id, p_command_type, p_reason,
    p_idempotency_key, p_ttl_seconds, p_rollback_of);
  return v_command;
end;
$$;

-- The unbounded entry point is no longer an RPC surface: every caller goes
-- through the depth-bounded wrapper, which invokes it as the function owner.
revoke all on function public.queue_fleet_response_command(uuid, uuid, uuid, text, text, text, integer, uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.queue_bounded_fleet_response_command(uuid, uuid, uuid, text, text, text, integer, uuid)
  from public, anon, authenticated;
grant execute on function public.queue_bounded_fleet_response_command(uuid, uuid, uuid, text, text, text, integer, uuid)
  to service_role;

-- ---------------------------------------------------------------------------
-- 3. Legacy caller-key rate limiter
-- ---------------------------------------------------------------------------

create or replace function public.increment_rate_limit(p_key text, p_window_start bigint, p_delta integer)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_scope text;
begin
  if p_key is null
     or octet_length(p_key) < 3 or octet_length(p_key) > 160
     or p_key !~ '^[A-Za-z0-9][A-Za-z0-9:_.-]{2,159}$'
     or p_window_start is null or p_window_start < 0 or p_window_start > 100000000000
     or p_delta is null or p_delta < 1 or p_delta > 1000 then
    raise exception using errcode = '22023', message = 'invalid_rate_limit_contract';
  end if;

  -- A caller may only address a scope that has been reviewed here. The previous
  -- definition stored any caller-chosen string as the counter key, so a caller
  -- could mint unbounded independent counters (or decrement its own counter with
  -- a negative delta) instead of being throttled.
  v_scope := split_part(p_key, ':', 1);
  if v_scope not in (
    'waitlist', 'device_start', 'enroll', 'identity-reset', 'identity-break-glass',
    'apikey_create', 'enrolltoken_create', 'team-invite'
  ) then
    raise exception using errcode = '22023', message = 'invalid_rate_limit_scope';
  end if;

  insert into public.rate_limits (key, window_start, count)
  values (p_key, p_window_start, p_delta)
  on conflict (key, window_start)
  do update set count = public.rate_limits.count + p_delta;
end;
$$;

-- `create or replace` keeps the previous grants, so the restricted grants are
-- re-asserted here exactly as `20260805000000_hybrid_tenancy.sql` established.
revoke all on function public.increment_rate_limit(text, bigint, integer) from public, anon, authenticated;
grant execute on function public.increment_rate_limit(text, bigint, integer) to service_role;
