-- Financial evidence is not an operational offboarding purge target. A payable
-- checkout or unfinished provider operation must be reconciled before the run
-- starts; completed evidence remains behind a local count/digest receipt. This
-- receipt is NOT provider finality or a legal retention-period approval.
lock table public.tenants, public.tenant_offboarding_runs,
  public.tenant_offboarding_phase_receipts, public.billing_checkout_intents,
  public.billing_provider_payments, public.billing_provider_refunds,
  public.billing_portal_operations, public.invoice_finance_operators
  in access exclusive mode;

create function app.billing_finance_evidence_digest(p_tenant_id uuid)
returns text language sql stable security definer
set search_path = pg_catalog, public, app, extensions, pg_temp as $$
  select encode(extensions.digest(coalesce(string_agg(e.row_text, E'\n' order by e.row_text), ''), 'sha256'), 'hex')
  from (
    select 'intent:' || to_jsonb(i)::text as row_text
      from public.billing_checkout_intents i where i.tenant_id = p_tenant_id
    union all
    select 'payment:' || to_jsonb(p)::text
      from public.billing_provider_payments p where p.tenant_id = p_tenant_id
    union all
    select 'refund:' || to_jsonb(r)::text
      from public.billing_provider_refunds r where r.tenant_id = p_tenant_id
  ) e
$$;
revoke all on function app.billing_finance_evidence_digest(uuid)
  from public, anon, authenticated, service_role;

alter table public.tenant_offboarding_phase_receipts
  add column finance_rows_retained bigint,
  add column finance_retention_digest text,
  add column finance_retention_reason text,
  add column finance_retention_owner_requirement text;
alter table public.tenant_offboarding_phase_receipts
  add constraint tenant_offboarding_finance_retention_receipt_check
  check (phase <> 'billing_finance_evidence' or (
    phase_order = 92 and data_class = 'commercial_records'
    and operation = 'retain_immutable_evidence' and status = 'completed'
    and rows_deleted = 0 and finance_rows_retained >= 0
    and finance_retention_digest ~ '^[0-9a-f]{64}$'
    and finance_retention_reason =
      'Checkout, payment and refund evidence retained outside operational tenant access; provider finality is not attested.'
    and finance_retention_owner_requirement =
      'External finance/legal owner must approve retention duration, evidence access and provider reconciliation.'
  )) not valid;

-- Old completed runs cannot silently acquire a financial-retention exception.
-- Existing evidence requires a separately reviewed remediation before upgrade.
do $migration$
begin
  if exists (select 1 from public.tenant_offboarding_runs r
    where r.status = 'completed' and (
      exists(select 1 from public.billing_checkout_intents i where i.tenant_id = r.tenant_id)
      or exists(select 1 from public.billing_provider_payments p where p.tenant_id = r.tenant_id)
      or exists(select 1 from public.billing_provider_refunds f where f.tenant_id = r.tenant_id)
      or exists(select 1 from public.billing_portal_operations o where o.tenant_id = r.tenant_id)
      or exists(select 1 from public.invoice_finance_operators o where o.tenant_id = r.tenant_id)
    )) then
    raise exception 'completed_offboarding_has_unreviewed_finance_residue';
  end if;
  if exists (select 1 from public.tenant_offboarding_phase_receipts
    where phase in ('billing_portal_operations', 'invoice_finance_operators',
                    'billing_finance_evidence') or phase_order in (48, 49, 92)) then
    raise exception 'unexpected_billing_finance_offboarding_phase';
  end if;
  if exists (select 1 from public.tenant_offboarding_runs r
    where not exists(select 1 from public.tenant_data_retention_policies p
      where p.tenant_id = r.tenant_id and p.data_class = 'commercial_records')
      or not exists(select 1 from public.tenant_data_retention_policies p
      where p.tenant_id = r.tenant_id and p.data_class = 'access_credentials')) then
    raise exception 'billing_finance_offboarding_retention_policy_missing';
  end if;
end;
$migration$;

create function app.billing_finance_evidence_count(p_tenant_id uuid)
returns bigint language sql stable security definer
set search_path = pg_catalog, public, app, pg_temp as $$
  select (select count(*) from public.billing_checkout_intents where tenant_id = p_tenant_id)
       + (select count(*) from public.billing_provider_payments where tenant_id = p_tenant_id)
       + (select count(*) from public.billing_provider_refunds where tenant_id = p_tenant_id)
$$;
revoke all on function app.billing_finance_evidence_count(uuid)
  from public, anon, authenticated, service_role;

create function app.assert_billing_finance_offboarding_start()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp as $$
begin
  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 2606));
  if exists(select 1 from public.billing_checkout_intents i
      where i.tenant_id = new.tenant_id and i.status <> 'paid')
    or exists(select 1 from public.billing_portal_operations o
      where o.tenant_id = new.tenant_id and o.status <> 'completed')
    or exists(select 1 from public.subscriptions s
      where s.tenant_id = new.tenant_id and s.provider in ('stripe', 'paddle')
        and s.status not in ('canceled', 'cancelled', 'incomplete_expired')) then
    raise exception 'billing_provider_reconciliation_required' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_billing_finance_offboarding_start()
  from public, anon, authenticated, service_role;
create trigger billing_finance_offboarding_start_guard
before insert on public.tenant_offboarding_runs
for each row execute function app.assert_billing_finance_offboarding_start();

-- Request already holds the offboarding lock. Revoke finance authority in the
-- same transaction, then seed resumable operational deletion phases.
create function app.seed_billing_finance_offboarding_phases()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp as $$
begin
  update public.invoice_finance_operators
    set revoked_at = clock_timestamp()
    where tenant_id = new.tenant_id and revoked_at is null;
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  select new.id, c.phase_order, c.phase, c.data_class, 'delete_records',
    p.retention_days, new.requested_at + make_interval(days => p.retention_days)
  from (values
    (48, 'billing_portal_operations', 'commercial_records'),
    (49, 'invoice_finance_operators', 'access_credentials')
  ) c(phase_order, phase, data_class)
  join public.tenant_data_retention_policies p
    on p.tenant_id = new.tenant_id and p.data_class = c.data_class;
  if (select count(*) from public.tenant_offboarding_phase_receipts
      where run_id = new.id and phase in
        ('billing_portal_operations', 'invoice_finance_operators')) <> 2 then
    raise exception 'billing_finance_offboarding_retention_policy_missing' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.seed_billing_finance_offboarding_phases()
  from public, anon, authenticated, service_role;
create trigger tenant_offboarding_billing_finance_phases
after insert on public.tenant_offboarding_runs
for each row execute function app.seed_billing_finance_offboarding_phases();

-- Resume an existing run; a completed zero-evidence run gets honest zero-row
-- receipts, not an invented statement that paid evidence was erased.
insert into public.tenant_offboarding_phase_receipts
  (run_id, phase_order, phase, data_class, operation, retention_days,
   eligible_at, status, rows_deleted, attempts, started_at, completed_at)
select r.id, c.phase_order, c.phase, c.data_class, 'delete_records',
  p.retention_days, r.requested_at + make_interval(days => p.retention_days),
  case when r.status = 'completed' then 'completed' else 'pending' end,
  0, case when r.status = 'completed' then 1 else 0 end,
  case when r.status = 'completed' then now() else null end,
  case when r.status = 'completed' then now() else null end
from public.tenant_offboarding_runs r
cross join (values
  (48, 'billing_portal_operations', 'commercial_records'),
  (49, 'invoice_finance_operators', 'access_credentials')
) c(phase_order, phase, data_class)
join public.tenant_data_retention_policies p
  on p.tenant_id = r.tenant_id and p.data_class = c.data_class;

insert into public.tenant_offboarding_phase_receipts
  (run_id, phase_order, phase, data_class, operation, retention_days,
   eligible_at, status, rows_deleted, attempts, started_at, completed_at,
   finance_rows_retained, finance_retention_digest, finance_retention_reason,
   finance_retention_owner_requirement)
select r.id, 92, 'billing_finance_evidence', 'commercial_records',
  'retain_immutable_evidence', p.retention_days,
  r.requested_at + make_interval(days => p.retention_days),
  'completed', 0, 1, now(), now(), 0,
  app.billing_finance_evidence_digest(r.tenant_id),
  'Checkout, payment and refund evidence retained outside operational tenant access; provider finality is not attested.',
  'External finance/legal owner must approve retention duration, evidence access and provider reconciliation.'
from public.tenant_offboarding_runs r
join public.tenant_data_retention_policies p
  on p.tenant_id = r.tenant_id and p.data_class = 'commercial_records'
where r.status = 'completed';

alter table public.tenant_offboarding_phase_receipts
  validate constraint tenant_offboarding_finance_retention_receipt_check;

-- Add only the two bounded delete targets; financial evidence never enters the
-- generic delete dispatcher.
do $migration$
declare v_definition text; v_old text; v_new text;
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure)
    into v_definition;
  v_old := 'when ''rate_limits'' then ''public.rate_limits''';
  v_new := 'when ''billing_portal_operations'' then ''public.billing_portal_operations'''
    || chr(10) || '    when ''invoice_finance_operators'' then ''public.invoice_finance_operators'''
    || chr(10) || '    ' || v_old;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_billing_finance_offboarding_dispatch_definition';
  end if;
  execute replace(v_definition, v_old, v_new);
end;
$migration$;

create function app.protect_billing_finance_evidence_write()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp as $$
declare v_tenant_id uuid;
begin
  v_tenant_id := case when tg_op = 'INSERT' then new.tenant_id else old.tenant_id end;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2606));
  if tg_op = 'UPDATE' and new.tenant_id is distinct from old.tenant_id then
    raise exception 'billing_finance_evidence_tenant_immutable' using errcode = '42501';
  end if;
  if not exists(select 1 from public.tenants where id = v_tenant_id and status = 'active')
    or exists(select 1 from public.tenant_offboarding_runs where tenant_id = v_tenant_id) then
    raise exception 'billing_finance_evidence_closed' using errcode = '42501';
  end if;
  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;
revoke all on function app.protect_billing_finance_evidence_write()
  from public, anon, authenticated, service_role;
create trigger billing_checkout_intents_offboarding_guard
before insert or update or delete on public.billing_checkout_intents
for each row execute function app.protect_billing_finance_evidence_write();
create trigger billing_provider_payments_offboarding_guard
before insert or update or delete on public.billing_provider_payments
for each row execute function app.protect_billing_finance_evidence_write();
create trigger billing_provider_refunds_offboarding_guard
before insert or update or delete on public.billing_provider_refunds
for each row execute function app.protect_billing_finance_evidence_write();

create function app.protect_billing_finance_operation_write()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp as $$
declare v_tenant_id uuid;
begin
  v_tenant_id := case when tg_op = 'INSERT' then new.tenant_id else old.tenant_id end;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2606));
  if tg_op = 'UPDATE' and new.tenant_id is distinct from old.tenant_id then
    raise exception 'billing_finance_operation_tenant_immutable' using errcode = '42501';
  end if;
  if tg_table_name = 'invoice_finance_operators' and tg_op = 'UPDATE' then
    if old.revoked_at is null and new.revoked_at is not null
       and new.user_id is not distinct from old.user_id
       and new.expires_at is not distinct from old.expires_at
       and new.created_at is not distinct from old.created_at then
      return new;
    end if;
  end if;
  if not exists(select 1 from public.tenants where id = v_tenant_id and status = 'active')
    or exists(select 1 from public.tenant_offboarding_runs where tenant_id = v_tenant_id) then
    raise exception 'billing_finance_operation_closed' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_billing_finance_operation_write()
  from public, anon, authenticated, service_role;
create trigger billing_portal_operations_offboarding_guard
before insert or update on public.billing_portal_operations
for each row execute function app.protect_billing_finance_operation_write();
create trigger invoice_finance_operators_offboarding_guard
before insert or update on public.invoice_finance_operators
for each row execute function app.protect_billing_finance_operation_write();

create function app.complete_billing_finance_retention_receipt()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp as $$
declare v_tenant_id uuid;
begin
  if new.phase <> 'billing_portal_operations' or new.status <> 'completed'
     or old.status = 'completed' then return new; end if;
  select tenant_id into strict v_tenant_id from public.tenant_offboarding_runs
    where id = new.run_id;
  if exists(select 1 from public.billing_checkout_intents
      where tenant_id = v_tenant_id and status <> 'paid')
    or exists(select 1 from public.billing_portal_operations
      where tenant_id = v_tenant_id) then
    raise exception 'billing_finance_reconciliation_required' using errcode = '23514';
  end if;
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days,
     eligible_at, status, rows_deleted, attempts, started_at, completed_at,
     finance_rows_retained, finance_retention_digest, finance_retention_reason,
     finance_retention_owner_requirement)
  values (new.run_id, 92, 'billing_finance_evidence', 'commercial_records',
    'retain_immutable_evidence', new.retention_days, new.eligible_at,
    'completed', 0, 1, now(), now(),
    app.billing_finance_evidence_count(v_tenant_id),
    app.billing_finance_evidence_digest(v_tenant_id),
    'Checkout, payment and refund evidence retained outside operational tenant access; provider finality is not attested.',
    'External finance/legal owner must approve retention duration, evidence access and provider reconciliation.');
  return new;
end;
$$;
revoke all on function app.complete_billing_finance_retention_receipt()
  from public, anon, authenticated, service_role;
create trigger billing_finance_retention_on_portal_cleanup
after update of status on public.tenant_offboarding_phase_receipts
for each row execute function app.complete_billing_finance_retention_receipt();

create function app.protect_billing_finance_retention_receipt()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp as $$
declare v_tenant_id uuid;
begin
  if tg_op = 'DELETE' then
    if old.phase = 'billing_finance_evidence' then
      raise exception 'billing_finance_retention_receipt_immutable' using errcode = '42501';
    end if;
    return old;
  end if;
  if tg_op = 'UPDATE' then
    if old.phase = 'billing_finance_evidence' or new.phase = 'billing_finance_evidence' then
      raise exception 'billing_finance_retention_receipt_immutable' using errcode = '42501';
    end if;
    return new;
  end if;
  if new.phase <> 'billing_finance_evidence' then return new; end if;
  select tenant_id into strict v_tenant_id from public.tenant_offboarding_runs
    where id = new.run_id;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2606));
  if exists(select 1 from public.tenant_legal_holds
      where tenant_id = v_tenant_id and released_at is null)
    or not exists(select 1 from public.tenant_offboarding_phase_receipts
      where run_id = new.run_id and phase = 'billing_portal_operations'
        and status = 'completed')
    or new.finance_rows_retained is distinct from app.billing_finance_evidence_count(v_tenant_id)
    or new.finance_retention_digest is distinct from app.billing_finance_evidence_digest(v_tenant_id) then
    raise exception 'invalid_billing_finance_retention_receipt' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_billing_finance_retention_receipt()
  from public, anon, authenticated, service_role;
create trigger billing_finance_retention_receipt_guard
before insert or update or delete on public.tenant_offboarding_phase_receipts
for each row execute function app.protect_billing_finance_retention_receipt();

create function app.assert_billing_finance_offboarding_closure()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp as $$
declare v_tenant_id uuid; v_run_id uuid;
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
  if v_run_id is null
    or exists(select 1 from public.billing_portal_operations where tenant_id = v_tenant_id)
    or exists(select 1 from public.invoice_finance_operators where tenant_id = v_tenant_id)
    or exists(select 1 from public.billing_checkout_intents
      where tenant_id = v_tenant_id and status <> 'paid')
    or exists(select 1 from public.subscriptions
      where tenant_id = v_tenant_id and provider in ('stripe', 'paddle')
        and status not in ('canceled', 'cancelled', 'incomplete_expired'))
    or not exists(select 1 from public.tenant_offboarding_phase_receipts
      where run_id = v_run_id and phase = 'billing_portal_operations'
        and status = 'completed')
    or not exists(select 1 from public.tenant_offboarding_phase_receipts
      where run_id = v_run_id and phase = 'invoice_finance_operators'
        and status = 'completed')
    or not exists(select 1 from public.tenant_offboarding_phase_receipts
      where run_id = v_run_id and phase = 'billing_finance_evidence'
        and status = 'completed' and operation = 'retain_immutable_evidence'
        and finance_rows_retained = app.billing_finance_evidence_count(v_tenant_id)
        and finance_retention_digest = app.billing_finance_evidence_digest(v_tenant_id)) then
    raise exception 'billing_finance_offboarding_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_billing_finance_offboarding_closure()
  from public, anon, authenticated, service_role;
create trigger tenants_billing_finance_offboarding_closure
before update of status on public.tenants
for each row execute function app.assert_billing_finance_offboarding_closure();
create trigger offboarding_runs_billing_finance_offboarding_closure
before update of status on public.tenant_offboarding_runs
for each row execute function app.assert_billing_finance_offboarding_closure();
