-- Preserve the immutable provider settlement ledger when a tenant closes.
-- Settlement rows are financial evidence: closure removes every operational
-- idempotency/projection/entitlement surface, but records the ledger as an
-- explicit external finance/legal retention exception instead of deleting it.
-- This receipt is local integrity evidence only; it is not external approval.

-- The old phase-23 and tenant-close hooks attempted DELETEs against the ledger's
-- append-only trigger. Replace both paths without weakening that trigger.
drop trigger if exists tenant_offboarding_purge_billing_settlements
  on public.tenant_offboarding_phase_receipts;
drop trigger if exists tenants_purge_billing_settlements_on_close
  on public.tenants;

-- The Edge service reaches the ledger only through authorization-checking RPCs.
-- SECURITY DEFINER RPC owners can still read/write for an active tenant, while a
-- service key can no longer expose retained rows through direct PostgREST table
-- access. There is deliberately no closure export RPC or claimed finance grant.
revoke select, insert on public.billing_settlements from service_role;

create function app.billing_settlement_retention_digest(p_tenant_id uuid)
returns text
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select encode(extensions.digest(coalesce(string_agg(
    format('%s:%s:%s:%s', s.id, s.settlement_id, s.sequence, s.receipt_hash),
    E'\n' order by s.settlement_id, s.sequence, s.id
  ), ''), 'sha256'), 'hex')
  from public.billing_settlements s
  where s.tenant_id = p_tenant_id
$$;
revoke all on function app.billing_settlement_retention_digest(uuid)
  from public, anon, authenticated, service_role;

alter table public.tenant_offboarding_phase_receipts
  add column settlement_rows_retained bigint,
  add column settlement_retention_digest text,
  add column settlement_retention_reason text,
  add column settlement_retention_owner_requirement text;

alter table public.tenant_offboarding_phase_receipts
  drop constraint tenant_offboarding_phase_receipts_operation_check;
alter table public.tenant_offboarding_phase_receipts
  add constraint tenant_offboarding_phase_receipts_operation_check
  check (operation in (
    'delete_records', 'delete_storage_objects', 'invalidate_cache',
    'retain_immutable_evidence'
  ));

alter table public.tenant_offboarding_phase_receipts
  add constraint tenant_offboarding_settlement_retention_receipt_check
  check (
    phase <> 'billing_settlements' or (
      operation = 'retain_immutable_evidence'
      and status = 'completed'
      and rows_deleted = 0
      and settlement_rows_retained is not null
      and settlement_rows_retained >= 0
      and settlement_retention_digest ~ '^[0-9a-f]{64}$'
      and settlement_retention_reason =
        'Immutable settlement ledger retained outside tenant operational access for external finance/legal retention.'
      and settlement_retention_owner_requirement =
        'External finance/legal retention owner must govern retention duration and authorized evidence access.'
    )
  ) not valid;

-- Convert receipts created for empty-ledger runs by the superseded purge hook.
-- No settlement row is rewritten or removed.
update public.tenant_offboarding_phase_receipts p
set operation = 'retain_immutable_evidence',
    rows_deleted = 0,
    settlement_rows_retained = evidence.retained,
    settlement_retention_digest = app.billing_settlement_retention_digest(r.tenant_id),
    settlement_retention_reason =
      'Immutable settlement ledger retained outside tenant operational access for external finance/legal retention.',
    settlement_retention_owner_requirement =
      'External finance/legal retention owner must govern retention duration and authorized evidence access.'
from public.tenant_offboarding_runs r
cross join lateral (
  select count(*)::bigint as retained
  from public.billing_settlements s
  where s.tenant_id = r.tenant_id
) evidence
where p.run_id = r.id and p.phase = 'billing_settlements';

alter table public.tenant_offboarding_phase_receipts
  validate constraint tenant_offboarding_settlement_retention_receipt_check;

create or replace function public.purge_billing_settlements_at_commercial_retention()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_tenant_id uuid;
  v_retained bigint;
begin
  if new.phase = 'entitlements' and new.status = 'completed'
     and old.status is distinct from 'completed' then
    select tenant_id into strict v_tenant_id
      from public.tenant_offboarding_runs where id = new.run_id;

    -- Operational state is erased. The immutable ledger itself is retained.
    delete from public.billing_settlement_requests where tenant_id = v_tenant_id;
    delete from public.billing_entitlement_projections where tenant_id = v_tenant_id;
    select count(*) into v_retained
      from public.billing_settlements where tenant_id = v_tenant_id;

    insert into public.tenant_offboarding_phase_receipts
      (run_id, phase_order, phase, data_class, operation, retention_days,
       eligible_at, status, rows_deleted, attempts, started_at, completed_at,
       settlement_rows_retained, settlement_retention_digest,
       settlement_retention_reason, settlement_retention_owner_requirement)
    values
      (new.run_id, 91, 'billing_settlements', 'commercial_records',
       'retain_immutable_evidence', new.retention_days, new.eligible_at,
       'completed', 0, 1, now(), now(), v_retained,
       app.billing_settlement_retention_digest(v_tenant_id),
       'Immutable settlement ledger retained outside tenant operational access for external finance/legal retention.',
       'External finance/legal retention owner must govern retention duration and authorized evidence access.');
  end if;
  return new;
end;
$$;
revoke all on function public.purge_billing_settlements_at_commercial_retention()
  from public, anon, authenticated, service_role;

-- Keep the legacy-named close function non-destructive even though its trigger
-- is removed, so accidentally reattaching it cannot erase settlement evidence.
create or replace function public.purge_billing_settlements_on_tenant_close()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if old.status is distinct from 'closed' and new.status = 'closed' then
    delete from public.billing_settlement_requests where tenant_id = new.id;
    delete from public.billing_entitlement_projections where tenant_id = new.id;
  end if;
  return new;
end;
$$;
revoke all on function public.purge_billing_settlements_on_tenant_close()
  from public, anon, authenticated, service_role;

create trigger tenant_offboarding_retain_billing_settlements
  after update of status on public.tenant_offboarding_phase_receipts
  for each row execute function public.purge_billing_settlements_at_commercial_retention();

-- The billing RPC originally row-locked the tenant before taking its request-key
-- lock. Offboarding takes lock 2606 before updating that row, so the settlement
-- path must take the same lock BEFORE authorization/row locks to avoid inversion.
do $migration$
declare v_definition text; v_old text; v_new text;
begin
  select pg_get_functiondef(
    'public.apply_billing_settlement(uuid,uuid,uuid,text,text,text,text,text,text,jsonb,bigint,text,bigint,bigint,timestamptz,integer,text,text)'::regprocedure
  ) into v_definition;
  v_old := 'begin' || chr(10) || '  v_quote := nullif(btrim(p_quote_reference), '''');';
  v_new := 'begin' || chr(10)
    || '  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));' || chr(10)
    || '  v_quote := nullif(btrim(p_quote_reference), '''');';
  if cardinality(string_to_array(v_definition, v_old)) <> 2
     or position('hashtextextended(p_tenant_id::text, 2606)' in v_definition) > 0 then
    raise exception 'unexpected_billing_settlement_lock_definition';
  end if;
  execute replace(v_definition, v_old, v_new);
end;
$migration$;

-- A settlement cannot be appended after offboarding has taken the tenant lock.
-- The trigger retains the same protection for direct privileged inserts.
create function app.protect_billing_settlement_insert_during_offboarding()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 2606));
  if not exists (
    select 1 from public.tenants t
    where t.id = new.tenant_id and t.status = 'active'
  ) or exists (
    select 1 from public.tenant_offboarding_runs r
    where r.tenant_id = new.tenant_id
  ) then
    raise exception 'tenant_not_active_for_billing_settlement' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_billing_settlement_insert_during_offboarding()
  from public, anon, authenticated, service_role;
create trigger billing_settlements_offboarding_insert_guard
  before insert on public.billing_settlements
  for each row execute function app.protect_billing_settlement_insert_during_offboarding();

-- The retained-evidence receipt is itself immutable and must exactly describe
-- the still-immutable tenant ledger at creation time. An active legal hold never
-- permits a caller to manufacture a completion receipt.
create function app.protect_billing_settlement_retention_receipt()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_tenant_id uuid;
  v_count bigint;
begin
  if tg_op = 'DELETE' then
    if old.phase = 'billing_settlements' then
      raise exception 'billing_settlement_retention_receipt_is_immutable' using errcode = '42501';
    end if;
    return old;
  end if;
  if tg_op = 'UPDATE' then
    if old.phase = 'billing_settlements' or new.phase = 'billing_settlements' then
      raise exception 'billing_settlement_retention_receipt_is_immutable' using errcode = '42501';
    end if;
    return new;
  end if;
  if new.phase <> 'billing_settlements' then return new; end if;

  select r.tenant_id into strict v_tenant_id
    from public.tenant_offboarding_runs r where r.id = new.run_id;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2606));
  select count(*) into v_count from public.billing_settlements
    where tenant_id = v_tenant_id;
  if exists(select 1 from public.tenant_legal_holds h
      where h.tenant_id = v_tenant_id and h.released_at is null)
     or not exists(select 1 from public.tenant_offboarding_phase_receipts p
      where p.run_id = new.run_id and p.phase = 'entitlements'
        and p.status = 'completed')
     or new.settlement_rows_retained is distinct from v_count
     or new.settlement_retention_digest is distinct from
        app.billing_settlement_retention_digest(v_tenant_id) then
    raise exception 'invalid_billing_settlement_retention_receipt' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_billing_settlement_retention_receipt()
  from public, anon, authenticated, service_role;
create trigger billing_settlement_retention_receipt_guard
  before insert or update or delete on public.tenant_offboarding_phase_receipts
  for each row execute function app.protect_billing_settlement_retention_receipt();

-- A receipt is bound through run_id, so the run's tenant/request identity must
-- never be transferable after creation. Status/error/completion fields remain
-- mutable for the dispatcher.
create function app.protect_tenant_offboarding_run_identity()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if new.id is distinct from old.id
     or new.tenant_id is distinct from old.tenant_id
     or new.requested_by is distinct from old.requested_by
     or new.requested_at is distinct from old.requested_at
     or new.backup_scope is distinct from old.backup_scope
     or new.backup_exception is distinct from old.backup_exception then
    raise exception 'tenant_offboarding_run_identity_is_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_tenant_offboarding_run_identity()
  from public, anon, authenticated, service_role;
create trigger tenant_offboarding_run_identity_guard
  before update on public.tenant_offboarding_runs
  for each row execute function app.protect_tenant_offboarding_run_identity();

-- Completion is honest only when the documented receipt matches the retained
-- ledger and all operational billing/entitlement state is gone. Retained ledger
-- rows are the sole allowed billing residue, never evidence of full erasure.
create function app.assert_billing_offboarding_closure()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_tenant_id uuid;
  v_run_id uuid;
  v_count bigint;
begin
  if new.status not in ('closed', 'completed') then return new; end if;
  if tg_table_name = 'tenants' then
    v_tenant_id := new.id;
    select id into v_run_id from public.tenant_offboarding_runs
      where tenant_id = v_tenant_id order by requested_at desc limit 1;
  else
    v_tenant_id := new.tenant_id;
    v_run_id := new.id;
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2606));
  select count(*) into v_count from public.billing_settlements
    where tenant_id = v_tenant_id;

  if v_run_id is null or exists(select 1 from public.tenant_legal_holds h
       where h.tenant_id = v_tenant_id and h.released_at is null)
     or not exists (
       select 1 from public.tenant_offboarding_phase_receipts p
       where p.run_id = v_run_id and p.phase = 'entitlements'
         and p.status = 'completed'
     )
     or not exists (
       select 1 from public.tenant_offboarding_phase_receipts p
       where p.run_id = v_run_id and p.phase = 'billing_settlements'
         and p.status = 'completed'
         and p.operation = 'retain_immutable_evidence'
         and p.rows_deleted = 0
         and p.settlement_rows_retained = v_count
         and p.settlement_retention_digest =
           app.billing_settlement_retention_digest(v_tenant_id)
     ) then
    raise exception 'billing_settlement_retention_evidence_missing' using errcode = '23514';
  end if;
  if exists(select 1 from public.billing_settlement_requests where tenant_id = v_tenant_id)
     or exists(select 1 from public.billing_entitlement_projections where tenant_id = v_tenant_id)
     or exists(select 1 from public.entitlements where tenant_id = v_tenant_id) then
    raise exception 'billing_offboarding_operational_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_billing_offboarding_closure()
  from public, anon, authenticated, service_role;
create trigger tenants_billing_offboarding_closure
  before update of status on public.tenants
  for each row execute function app.assert_billing_offboarding_closure();
create trigger offboarding_runs_billing_offboarding_closure
  before update of status on public.tenant_offboarding_runs
  for each row execute function app.assert_billing_offboarding_closure();
