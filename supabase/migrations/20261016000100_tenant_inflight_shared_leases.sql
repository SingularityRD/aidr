-- Fair-share admission state shared by every edge worker (load-soak drill
-- 2026-10-11, finding O1; docs/production-readiness/load-soak-drill-2026-10-11.md).
--
-- The first fair-share limiter (supabase/functions/_shared/tenant-concurrency.ts)
-- kept its in-flight counts and its key-to-tenant hints inside one edge worker.
-- Under overload the runtime replaces workers every few seconds, so each new
-- worker started from zero and charged every key to a shared "unresolved"
-- bucket, and ingest and policy each had their own counts. The local A/B missed
-- its pre-declared quiet-tenant bound for that reason.
--
-- This moves the state into the database, for every worker, replica and both
-- functions at once:
--
-- * acquire_tenant_inflight_lease() resolves the tenant from the presented key's
--   SHA-256 (the same active / retired-hash lookup as API-key authentication),
--   applies the fair-share rules to the leases currently held in the scope and,
--   if admitted, writes one lease with an expiry. Resolution only decides whose
--   share a request counts against; the edge function still authenticates the
--   key in full before reading any tenant data.
-- * release_tenant_inflight_lease() frees that lease. A worker that is killed
--   before it releases cannot leak the slot past the lease expiry: an expired
--   lease no longer counts and its slot row is reused.
--
-- Decisions in one scope are serialised by a row lock on the scope row taken by
-- the acquire call's own short transaction (no advisory lock, nothing held
-- across requests). Slot rows are reused in place and no indexed column changes
-- on reuse, so the churn stays in HOT updates on a table no larger than the
-- peak number of leases. The tables are UNLOGGED: leases are worthless after a
-- crash or failover, and losing them only admits up to one capacity of extra
-- requests until they would have expired anyway.
--
-- Rules, for a request charged to c with n = c's live leases, total = all live
-- leases and active = distinct charged parties (as the edge function documents):
--   unresolved key that already holds a live lease, under pressure -> 429
--   total >= capacity                                             -> 503
--   n >= per-tenant max                                           -> 429
--   total >= per-tenant max and n >= max(floor, capacity / active') -> 429
-- where active' counts c even when it holds nothing yet.

create unlogged table if not exists app.tenant_inflight_scopes (
  scope text primary key check (scope ~ '^[a-z0-9_-]{1,48}$')
);
revoke all on app.tenant_inflight_scopes from public, anon, authenticated, service_role;

create unlogged table if not exists app.tenant_inflight_slots (
  scope text not null references app.tenant_inflight_scopes(scope) on delete cascade,
  slot integer not null check (slot between 1 and 10000),
  lease_id uuid,
  -- A tenant id as text, or 'unresolved' for a key that resolves to no tenant.
  charged_to text,
  -- Only for unresolved leases: the presented SHA-256, for the one-in-flight rule.
  unresolved_key text,
  expires_at timestamptz,
  primary key (scope, slot),
  check ((lease_id is null) = (expires_at is null) and (lease_id is null) = (charged_to is null))
) with (fillfactor = 50);
revoke all on app.tenant_inflight_slots from public, anon, authenticated, service_role;

create or replace function public.acquire_tenant_inflight_lease(
  p_scope text,
  p_key_hash text,
  p_capacity integer,
  p_per_tenant_max integer,
  p_fair_share_floor integer,
  p_lease_seconds integer
)
returns jsonb
language plpgsql volatile security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_key record;
  v_charged text;
  v_total integer;
  v_held integer;
  v_active integer;
  v_busy boolean;
  v_reason text;
  v_slot integer;
  v_reclaimed boolean := false;
  v_lease uuid;
begin
  if p_scope is null or p_scope !~ '^[a-z0-9_-]{1,48}$' then
    raise exception 'invalid admission scope' using errcode = '22023';
  end if;
  if p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$' then
    raise exception 'invalid key hash' using errcode = '22023';
  end if;
  if p_capacity is null or p_capacity not between 1 and 10000
     or p_per_tenant_max is null or p_per_tenant_max not between 1 and p_capacity
     or p_fair_share_floor is null or p_fair_share_floor not between 1 and p_per_tenant_max
     or p_lease_seconds is null or p_lease_seconds not between 1 and 600 then
    raise exception 'invalid admission limits' using errcode = '22023';
  end if;

  -- Charging only, mirroring authentication: a row matched by its active hash
  -- decides (a revoked one charges nothing); only a miss consults the retired
  -- hash inside its overlap window.
  select k.tenant_id, k.revoked into v_key from public.api_keys k where k.key_hash = p_key_hash;
  if found then
    if not v_key.revoked then v_charged := v_key.tenant_id::text; end if;
  else
    select k.tenant_id into v_charged from public.api_keys k
      where k.previous_hash = p_key_hash and not k.revoked
        and k.previous_hash_expires_at > v_now
      limit 1;
  end if;
  v_charged := coalesce(v_charged, 'unresolved');

  insert into app.tenant_inflight_scopes(scope) values (p_scope) on conflict (scope) do nothing;
  perform 1 from app.tenant_inflight_scopes where scope = p_scope for update;

  select count(*)::integer,
         (count(*) filter (where s.charged_to = v_charged))::integer,
         (count(distinct s.charged_to))::integer,
         coalesce(bool_or(s.unresolved_key = p_key_hash), false)
    into v_total, v_held, v_active, v_busy
    from app.tenant_inflight_slots s
    where s.scope = p_scope and s.expires_at > v_now;

  if v_charged = 'unresolved' and v_busy and v_total >= p_per_tenant_max then
    v_reason := 'unresolved_key_busy';
  elsif v_total >= p_capacity then
    v_reason := 'capacity';
  elsif v_held >= p_per_tenant_max then
    v_reason := 'tenant_max';
  elsif v_total >= p_per_tenant_max
        and v_held >= greatest(p_fair_share_floor,
                               p_capacity / greatest(1, v_active + case when v_held = 0 then 1 else 0 end)) then
    v_reason := 'fair_share';
  end if;
  if v_reason is not null then
    return jsonb_build_object('admitted', false, 'reason', v_reason, 'charged_to', v_charged,
      'held', v_held, 'total', v_total, 'active', v_active);
  end if;

  v_lease := gen_random_uuid();
  select s.slot, s.lease_id is not null into v_slot, v_reclaimed
    from app.tenant_inflight_slots s
    where s.scope = p_scope and (s.expires_at is null or s.expires_at <= v_now)
    order by s.slot
    limit 1;
  if found then
    update app.tenant_inflight_slots
      set lease_id = v_lease, charged_to = v_charged,
          unresolved_key = case when v_charged = 'unresolved' then p_key_hash end,
          expires_at = v_now + make_interval(secs => p_lease_seconds)
      where scope = p_scope and slot = v_slot;
  else
    v_reclaimed := false;
    select coalesce(max(s.slot), 0) + 1 into v_slot from app.tenant_inflight_slots s where s.scope = p_scope;
    insert into app.tenant_inflight_slots(scope, slot, lease_id, charged_to, unresolved_key, expires_at)
      values (p_scope, v_slot, v_lease, v_charged,
              case when v_charged = 'unresolved' then p_key_hash end,
              v_now + make_interval(secs => p_lease_seconds));
  end if;
  return jsonb_build_object('admitted', true, 'slot', v_slot, 'lease_id', v_lease, 'charged_to', v_charged,
    'reclaimed', v_reclaimed, 'held', v_held + 1, 'total', v_total + 1, 'active', v_active + case when v_held = 0 then 1 else 0 end);
end;
$$;
revoke all on function public.acquire_tenant_inflight_lease(text, text, integer, integer, integer, integer)
  from public, anon, authenticated;
grant execute on function public.acquire_tenant_inflight_lease(text, text, integer, integer, integer, integer)
  to service_role;

-- Frees exactly the lease it names. A late release after the lease expired and
-- its slot was reused matches no row and changes nothing.
create or replace function public.release_tenant_inflight_lease(p_scope text, p_slot integer, p_lease_id uuid)
returns boolean
language plpgsql volatile security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
begin
  if p_scope is null or p_slot is null or p_lease_id is null then
    raise exception 'invalid lease' using errcode = '22023';
  end if;
  update app.tenant_inflight_slots
    set lease_id = null, charged_to = null, unresolved_key = null, expires_at = null
    where scope = p_scope and slot = p_slot and lease_id = p_lease_id;
  return found;
end;
$$;
revoke all on function public.release_tenant_inflight_lease(text, integer, uuid)
  from public, anon, authenticated;
grant execute on function public.release_tenant_inflight_lease(text, integer, uuid)
  to service_role;
