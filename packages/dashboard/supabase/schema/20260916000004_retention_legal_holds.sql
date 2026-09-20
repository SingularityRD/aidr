-- Routine retention must share offboarding's legal-hold lock (seed 2606).
-- SQL cannot hold a transaction across Storage HTTP. An authorization survives
-- transaction/worker failure and prevents hold placement until acknowledged.
-- It NEVER expires or transfers to another worker: a timeout is ambiguous, not
-- evidence of deletion or of cancellation. See docs/production-readiness/retention-holds.md.
create table public.audit_export_deletion_authorizations (
  path text primary key references public.audit_export_objects(path) on delete restrict,
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  authorization_id uuid not null unique default gen_random_uuid(),
  authorized_at timestamptz not null default now()
);
create index audit_export_deletion_authorizations_tenant
  on public.audit_export_deletion_authorizations(tenant_id);
alter table public.audit_export_deletion_authorizations enable row level security;
revoke all on public.audit_export_deletion_authorizations from public, anon, authenticated, service_role;
grant select on public.audit_export_deletion_authorizations to service_role;
-- Old direct-ledger deletion is no longer a supported maintenance protocol.
revoke delete on public.audit_export_objects from service_role;

create or replace function app.protect_tenant_legal_hold() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  -- Fresh snapshots after lock acquisition are required by this protocol.
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(coalesce(new.tenant_id, old.tenant_id)::text, 2606));
  if tg_op = 'DELETE' then
    raise exception 'legal_hold_history_is_immutable' using errcode = '42501';
  end if;
  if tg_op = 'UPDATE' then
    if old.released_at is not null
      or new.id is distinct from old.id
      or new.tenant_id is distinct from old.tenant_id
      or new.hold_reference is distinct from old.hold_reference
      or new.reason is distinct from old.reason
      or new.placed_by is distinct from old.placed_by
      or new.placed_at is distinct from old.placed_at
      or new.released_at is null
      or new.released_by is null
      or new.release_reason is null
    then
      raise exception 'legal_hold_update_must_be_a_single_release' using errcode = '42501';
    end if;
  end if;
  if tg_op = 'INSERT' and exists (
    select 1 from public.audit_export_deletion_authorizations
    where tenant_id = new.tenant_id
  ) then
    raise exception 'legal_hold_refused_pending_export_deletion' using errcode = '55000',
      hint = 'Fence the authorized worker and reconcile Storage before retrying hold placement; a refused hold is NOT active.';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_tenant_legal_hold() from public, anon, authenticated;

create function public.prepare_expired_audit_exports(
  p_limit integer default 100, p_apply boolean default false,
  p_cutoff timestamptz default now()
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_tenant uuid;
  v_row record;
  v_token uuid;
  v_objects jsonb := '[]'::jsonb;
  v_contended integer := 0;
  v_held integer;
  v_pending integer;
begin
  if p_limit is null or p_limit not between 1 and 1000 or p_apply is null
    or p_cutoff is null then
    raise exception 'invalid_retention_batch' using errcode = '22023';
  end if;
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  -- A fast maintenance host must not authorize future objects or stall pruning.
  p_cutoff := least(p_cutoff, now());
  -- Sort locks by tenant; never wait behind another tenant's hold/deletion.
  for v_tenant in
    select distinct e.tenant_id from public.audit_export_objects e
    where e.expires_at <= p_cutoff
      and not exists (select 1 from public.tenant_legal_holds h
        where h.tenant_id = e.tenant_id and h.released_at is null)
      and not exists (select 1 from public.audit_export_deletion_authorizations a
        where a.tenant_id = e.tenant_id)
    order by e.tenant_id
  loop
    exit when jsonb_array_length(v_objects) >= p_limit;
    if not pg_try_advisory_xact_lock(hashtextextended(v_tenant::text, 2606)) then
      v_contended := v_contended + 1;
      continue;
    end if;
    -- Recheck with a fresh statement snapshot under the hold-placement lock.
    if exists (select 1 from public.tenant_legal_holds where tenant_id = v_tenant and released_at is null)
      or exists (select 1 from public.audit_export_deletion_authorizations where tenant_id = v_tenant) then
      continue;
    end if;
    for v_row in select path from public.audit_export_objects
      where tenant_id = v_tenant and expires_at <= p_cutoff
      order by expires_at, path limit (p_limit - jsonb_array_length(v_objects))
      for update
    loop
      v_token := null;
      if p_apply then
        insert into public.audit_export_deletion_authorizations(path, tenant_id)
          values (v_row.path, v_tenant) returning authorization_id into v_token;
      end if;
      v_objects := v_objects || jsonb_build_array(jsonb_build_object(
        'path', v_row.path, 'authorization_id', v_token));
    end loop;
  end loop;
  select count(*) into v_held from public.audit_export_objects e
    where e.expires_at <= p_cutoff and exists (select 1 from public.tenant_legal_holds h
      where h.tenant_id = e.tenant_id and h.released_at is null);
  select count(*) into v_pending from public.audit_export_deletion_authorizations;
  return jsonb_build_object('cutoff', p_cutoff, 'objects', v_objects, 'held_exports', v_held,
    'pending_authorizations', v_pending, 'contended_tenants', v_contended);
end;
$$;
revoke all on function public.prepare_expired_audit_exports(integer, boolean, timestamptz) from public, anon, authenticated;
grant execute on function public.prepare_expired_audit_exports(integer, boolean, timestamptz) to service_role;

-- Call ONLY after Storage returned each exact path as deleted. This acknowledges
-- the trusted worker's observation, not an independently verified deletion receipt.
create function public.ack_expired_audit_export(p_authorization_id uuid)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_auth public.audit_export_deletion_authorizations;
  v_rows integer;
begin
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  select * into v_auth from public.audit_export_deletion_authorizations
    where authorization_id = p_authorization_id;
  if not found then raise exception 'export_authorization_not_found' using errcode = 'P0002'; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_auth.tenant_id::text, 2606));
  if exists (select 1 from public.tenant_legal_holds where tenant_id = v_auth.tenant_id and released_at is null) then
    raise exception 'active_legal_hold' using errcode = '55000';
  end if;
  delete from public.audit_export_deletion_authorizations where authorization_id = p_authorization_id;
  if not found then raise exception 'export_authorization_not_found' using errcode = 'P0002'; end if;
  delete from public.audit_export_objects where path = v_auth.path and tenant_id = v_auth.tenant_id;
  get diagnostics v_rows = row_count;
  if v_rows <> 1 then raise exception 'export_authorization_ledger_mismatch'; end if;
  return jsonb_build_object('ledger_rows_deleted', v_rows);
end;
$$;
revoke all on function public.ack_expired_audit_export(uuid) from public, anon, authenticated;
grant execute on function public.ack_expired_audit_export(uuid) to service_role;

-- Preserve the bounded per-table budget and append-only settlement evidence.
-- Unattributed legacy webhooks cannot safely be matched to a hold: retain them
-- explicitly until attribution is repaired, without blocking other tenants.
create or replace function public.prune_expired_billing_records(
  p_limit integer default 100, p_apply boolean default true
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_tenant uuid;
  v_requests_eligible integer := 0;
  v_events_eligible integer := 0;
  v_requests_deleted integer := 0;
  v_events_deleted integer := 0;
  v_count integer;
  v_contended integer := 0;
  v_unattributed integer;
begin
  if p_limit is null or p_limit not between 1 and 1000 or p_apply is null then
    raise exception 'invalid_retention_batch' using errcode = '22023';
  end if;
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  for v_tenant in
    select tenant_id from (
      select tenant_id from public.billing_settlement_requests where expires_at <= now()
      union select tenant_id from public.billing_webhook_events where expires_at <= now()
    ) candidates where tenant_id is not null and not exists (
      select 1 from public.tenant_legal_holds h where h.tenant_id = candidates.tenant_id and h.released_at is null
    ) order by tenant_id
  loop
    exit when v_requests_eligible >= p_limit and v_events_eligible >= p_limit;
    if not pg_try_advisory_xact_lock(hashtextextended(v_tenant::text, 2606)) then
      v_contended := v_contended + 1;
      continue;
    end if;
    if exists (select 1 from public.tenant_legal_holds where tenant_id = v_tenant and released_at is null) then
      continue;
    end if;
    if p_apply then
      delete from public.billing_settlement_requests r using (
        select tenant_id, request_id from public.billing_settlement_requests
        where tenant_id = v_tenant and expires_at <= now()
        order by expires_at, request_id limit (p_limit - v_requests_eligible)
      ) expired where r.tenant_id = expired.tenant_id and r.request_id = expired.request_id;
      get diagnostics v_count = row_count;
      v_requests_deleted := v_requests_deleted + v_count;
    else
      select count(*) into v_count from (
        select 1 from public.billing_settlement_requests where tenant_id = v_tenant and expires_at <= now()
        limit (p_limit - v_requests_eligible)
      ) expired;
    end if;
    v_requests_eligible := v_requests_eligible + v_count;
    if p_apply then
      delete from public.billing_webhook_events e using (
        select event_id from public.billing_webhook_events
        where tenant_id = v_tenant and expires_at <= now()
        order by expires_at, event_id limit (p_limit - v_events_eligible)
      ) expired where e.event_id = expired.event_id and e.tenant_id = v_tenant;
      get diagnostics v_count = row_count;
      v_events_deleted := v_events_deleted + v_count;
    else
      select count(*) into v_count from (
        select 1 from public.billing_webhook_events where tenant_id = v_tenant and expires_at <= now()
        limit (p_limit - v_events_eligible)
      ) expired;
    end if;
    v_events_eligible := v_events_eligible + v_count;
  end loop;
  select count(*) into v_unattributed from public.billing_webhook_events
    where tenant_id is null and expires_at <= now();
  return jsonb_build_object('applied', p_apply,
    'settlement_requests_eligible', v_requests_eligible, 'webhook_events_eligible', v_events_eligible,
    'settlement_requests_deleted', v_requests_deleted, 'webhook_events_deleted', v_events_deleted,
    'contended_tenants', v_contended, 'unattributed_webhooks_retained', v_unattributed);
end;
$$;
revoke all on function public.prune_expired_billing_records(integer, boolean) from public, anon, authenticated;
grant execute on function public.prune_expired_billing_records(integer, boolean) to service_role;
