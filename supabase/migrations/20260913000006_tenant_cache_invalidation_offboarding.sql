-- Tenant cache-layer invalidation for offboarding.
--
-- The live-data phases in 20260912140000_tenant_offboarding_retention.sql delete
-- rows and private storage objects, but a derived read cache (edge/CDN response
-- cache, per-tenant rate-limit cache, client-side verdict cache) can keep
-- serving tenant data after the authoritative rows are gone. Without an
-- explicit cache step, "the data is gone from the API" is unprovable for that
-- layer, so this migration adds an ordered cache-invalidation phase and its own
-- receipt column.
--
-- It extends the shipped phase machinery the way
-- 20260912140002_fleet_response_offboarding.sql does: a trigger seeds the extra
-- phase for every new run, in-flight runs are backfilled, and the batch RPC is
-- extended to hand the cache action to the offboarding driver. The shipped
-- migration is not edited, the ten explicit data classes are unchanged, and
-- backups stay outside every receipt (`covers_backups = false` is untouched).
--
-- Access is revoked before any cache step can run: request_tenant_offboarding
-- revokes API keys, SCIM tokens and delegated grants and moves the tenant to
-- 'closing', so an invalidated cache cannot be repopulated by a tenant request.

-- 1. Receipt surface for the cache phase ------------------------------------
--
-- `cache_invalidation_receipt` is the phase's own receipt: the acknowledged
-- cache keys, the invalidated count and the acknowledgement time. The final
-- constraint makes that receipt mandatory for a completed cache phase, so the
-- machinery cannot close a run while the cache layer is unaddressed.
alter table public.tenant_offboarding_phase_receipts
  add column cache_invalidation_receipt jsonb;

alter table public.tenant_offboarding_phase_receipts
  drop constraint if exists tenant_offboarding_phase_receipts_operation_check;
alter table public.tenant_offboarding_phase_receipts
  add constraint tenant_offboarding_phase_receipts_operation_check
  check (operation in ('delete_records', 'delete_storage_objects', 'invalidate_cache'));

alter table public.tenant_offboarding_phase_receipts
  add constraint tenant_offboarding_cache_receipt_required
  check (
    operation <> 'invalidate_cache'
    or status <> 'completed'
    or (cache_invalidation_receipt is not null
        and jsonb_typeof(cache_invalidation_receipt) = 'object')
  );

-- The operation check is a generated-name inline constraint; verify that the
-- extension actually replaced it instead of leaving a narrower check in place.
do $migration$
begin
  if exists (
    select 1 from pg_constraint c
    where c.conrelid = 'public.tenant_offboarding_phase_receipts'::regclass
      and c.contype = 'c'
      and pg_get_constraintdef(c.oid) like '%''delete_storage_objects''%'
      and pg_get_constraintdef(c.oid) not like '%''invalidate_cache''%'
  ) then
    raise exception 'offboarding_operation_constraint_not_extended';
  end if;
end;
$migration$;

-- 2. The phase for every run -------------------------------------------------
--
-- The cache holds derived copies of tenant-scoped operational state, so it
-- follows the `operational_ephemera` retention class. Phase order 40 already
-- belongs to fleet command evidence, so this phase takes 41 and stays unique
-- per run.
create function app.seed_tenant_cache_invalidation_phase()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare v_days integer;
begin
  select p.retention_days into v_days from public.tenant_data_retention_policies p
    where p.tenant_id = new.tenant_id and p.data_class = 'operational_ephemera';
  if v_days is null then
    raise exception 'cache_retention_policy_missing' using errcode = '23514';
  end if;
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  values (new.id, 41, 'tenant_cache', 'operational_ephemera', 'invalidate_cache',
    v_days, new.requested_at + make_interval(days => v_days))
  on conflict (run_id, phase) do nothing;
  return new;
end;
$$;
revoke all on function app.seed_tenant_cache_invalidation_phase() from public, anon, authenticated;
create trigger tenant_offboarding_cache_phase
after insert on public.tenant_offboarding_runs
for each row execute function app.seed_tenant_cache_invalidation_phase();

-- An in-flight run started before this migration still needs the phase (and its
-- receipt). Completed runs are left exactly as they were.
insert into public.tenant_offboarding_phase_receipts
  (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
select r.id, 41, 'tenant_cache', 'operational_ephemera', 'invalidate_cache',
  p.retention_days, r.requested_at + make_interval(days => p.retention_days)
from public.tenant_offboarding_runs r
join public.tenant_data_retention_policies p
  on p.tenant_id = r.tenant_id and p.data_class = 'operational_ephemera'
where r.status <> 'completed'
on conflict (run_id, phase) do nothing;

-- 3. Batch dispatch ----------------------------------------------------------
--
-- The existing batch RPC already supplies the legal-hold check, retention
-- eligibility, one-phase receipts and bounded work. Extend only its dispatch so
-- the cache phase is handed out as an action instead of being mistaken for a
-- table deletion.
do $migration$
declare v_definition text; v_old text; v_new text;
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure)
    into v_definition;
  v_old := 'if v_phase.operation = ''delete_storage_objects'' then';
  v_new := 'if v_phase.operation = ''invalidate_cache'' then'
    || chr(10) || '    return jsonb_build_object(''run_id'',p_run_id,''status'',''running'',''complete'',false,'
    || chr(10) || '      ''phase'',v_phase.phase,''action'',''invalidate_cache'',''cache_scope'',v_run.tenant_id);'
    || chr(10) || '  end if;'
    || chr(10) || '  if v_phase.operation = ''delete_storage_objects'' then';
  if position(v_old in v_definition) = 0
     or position('invalidate_cache' in v_definition) > 0
  then raise exception 'unexpected_offboarding_batch_definition'; end if;
  execute replace(v_definition, v_old, v_new);
end;
$migration$;

-- 4. The cache receipt -------------------------------------------------------
--
-- The cache layer is external to PostgreSQL, so the driver reports the
-- acknowledged invalidation and this RPC records it as the phase receipt. A
-- legal hold blocks the acknowledgement exactly as it blocks row and object
-- deletion, and the receipt is required before the run can complete.
create function public.ack_tenant_offboarding_cache(
  p_run_id uuid, p_cache_keys text[], p_invalidated bigint default null
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_run public.tenant_offboarding_runs;
  v_receipt public.tenant_offboarding_phase_receipts;
  v_invalidated bigint;
begin
  if p_run_id is null or coalesce(cardinality(p_cache_keys), 0) not between 1 and 1000
    or exists(select 1 from unnest(p_cache_keys) k where k is null or length(k) not between 1 and 512)
    or (p_invalidated is not null and p_invalidated < 0)
  then raise exception 'invalid_offboarding_cache_ack' using errcode = '22023'; end if;
  select * into v_run from public.tenant_offboarding_runs where id = p_run_id;
  if not found then raise exception 'offboarding_run_not_found' using errcode = 'P0002'; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_run.tenant_id::text, 2606));
  if exists(select 1 from public.tenant_legal_holds where tenant_id = v_run.tenant_id and released_at is null) then
    update public.tenant_offboarding_runs set status = 'blocked_legal_hold', last_error = 'active legal hold' where id = p_run_id;
    return jsonb_build_object('run_id', p_run_id, 'status', 'blocked_legal_hold', 'complete', false,
      'phase', 'tenant_cache');
  end if;
  select * into v_receipt from public.tenant_offboarding_phase_receipts
    where run_id = p_run_id and phase = 'tenant_cache';
  if not found then
    raise exception 'offboarding_cache_phase_missing' using errcode = 'P0002';
  end if;
  if v_receipt.status <> 'running' or v_receipt.eligible_at > now() then
    raise exception 'offboarding_cache_phase_not_active' using errcode = '42501';
  end if;
  v_invalidated := coalesce(p_invalidated, cardinality(p_cache_keys));
  update public.tenant_offboarding_phase_receipts
    set status = 'completed', completed_at = now(),
        cache_invalidation_receipt = jsonb_build_object(
          'phase', 'tenant_cache',
          'tenant_id', v_run.tenant_id,
          'keys', to_jsonb(p_cache_keys),
          'invalidated', v_invalidated,
          'acknowledged_at', now())
    where run_id = p_run_id and phase = 'tenant_cache';
  return jsonb_build_object('run_id', p_run_id, 'status', 'running', 'complete', false,
    'phase', 'tenant_cache', 'phase_complete', true, 'invalidated', v_invalidated);
end;
$$;
revoke all on function public.ack_tenant_offboarding_cache(uuid, text[], bigint) from public, anon, authenticated;
grant execute on function public.ack_tenant_offboarding_cache(uuid, text[], bigint) to service_role;
