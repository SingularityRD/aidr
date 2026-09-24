-- Revoke admission at request time; erase the two grant tables only after
-- their own retention clocks and legal holds allow the normal batch runner.
lock table public.admission_operators, public.tenants,
  public.tenant_offboarding_runs, public.tenant_offboarding_phase_receipts
  in access exclusive mode;

do $migration$
declare v_definition text; v_old text; v_new text;
begin
  select pg_get_functiondef('public.request_tenant_offboarding(uuid,uuid)'::regprocedure)
    into v_definition;
  v_old := 'update public.tenants set status = ''closing'' where id = p_tenant_id and status <> ''closed'';';
  v_new := 'update public.admission_operators set revoked_at = clock_timestamp()'
    || chr(10) || '    where tenant_id = p_tenant_id and revoked_at is null;'
    || chr(10) || '  ' || v_old;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_admission_offboarding_request_definition';
  end if;
  v_definition := replace(v_definition, v_old, v_new);

  v_old := 'update public.api_keys set revoked = true where tenant_id = p_tenant_id and not revoked;';
  v_new := 'update public.tenant_admissions'
    || chr(10) || '    set revoked_at = greatest(starts_at, clock_timestamp()), updated_at = clock_timestamp()'
    || chr(10) || '    where tenant_id = p_tenant_id and revoked_at is null;'
    || chr(10) || '  update public.entitlements set revocation_epoch = revocation_epoch + 1'
    || chr(10) || '    where tenant_id = p_tenant_id;'
    || chr(10) || '  ' || v_old;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_admission_offboarding_request_definition';
  end if;
  execute replace(v_definition, v_old, v_new);
end;
$migration$;

-- A late trial/license grant or operator reactivation must not repopulate a
-- closing tenant. The revocation updates above remain permitted.
create function app.protect_closing_tenant_admission()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp as $$
begin
  if tg_op = 'INSERT' or new.revoked_at is null then
    perform 1 from public.tenants where id = new.tenant_id
      and status = 'active' for share;
    if not found then
      raise exception 'tenant_admission_closed' using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function app.protect_closing_tenant_admission()
  from public, anon, authenticated, service_role;
create trigger tenant_admissions_closing_guard
before insert or update on public.tenant_admissions
for each row execute function app.protect_closing_tenant_admission();
create trigger admission_operators_closing_guard
before insert or update on public.admission_operators
for each row execute function app.protect_closing_tenant_admission();

create function app.seed_admission_offboarding_phases()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp as $$
begin
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  select new.id, c.phase_order, c.phase, c.data_class, 'delete_records',
    p.retention_days, new.requested_at + make_interval(days => p.retention_days)
  from (values
    (46, 'admission_operators', 'access_credentials'),
    (47, 'tenant_admissions', 'commercial_records')
  ) c(phase_order, phase, data_class)
  join public.tenant_data_retention_policies p
    on p.tenant_id = new.tenant_id and p.data_class = c.data_class;
  if (select count(*) from public.tenant_offboarding_phase_receipts
      where run_id = new.id and phase in ('admission_operators', 'tenant_admissions')) <> 2 then
    raise exception 'admission_offboarding_retention_policy_missing' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.seed_admission_offboarding_phases()
  from public, anon, authenticated, service_role;
create trigger tenant_offboarding_admission_phases
after insert on public.tenant_offboarding_runs
for each row execute function app.seed_admission_offboarding_phases();

do $migration$
begin
  if exists(select 1 from public.tenant_offboarding_runs r
    where r.status = 'completed' and (
      exists(select 1 from public.tenant_admissions a where a.tenant_id = r.tenant_id)
      or exists(select 1 from public.admission_operators o where o.tenant_id = r.tenant_id)
    )) then
    raise exception 'completed_offboarding_has_admission_residue';
  end if;
  if exists(select 1 from public.tenant_offboarding_runs r
    where not exists(select 1 from public.tenant_data_retention_policies p
      where p.tenant_id = r.tenant_id and p.data_class = 'access_credentials')
      or not exists(select 1 from public.tenant_data_retention_policies p
      where p.tenant_id = r.tenant_id and p.data_class = 'commercial_records')) then
    raise exception 'admission_offboarding_retention_policy_missing';
  end if;
  if exists(select 1 from public.tenant_offboarding_runs r
    join public.tenant_data_retention_policies p on p.tenant_id = r.tenant_id
    where r.status = 'completed'
      and p.data_class in ('access_credentials', 'commercial_records')
      and r.requested_at + make_interval(days => p.retention_days) > now()) then
    raise exception 'completed_offboarding_admission_retention_not_met';
  end if;
  if exists(select 1 from public.tenant_offboarding_phase_receipts
    where phase in ('admission_operators', 'tenant_admissions')
      or phase_order in (46, 47)) then
    raise exception 'unexpected_admission_offboarding_phase';
  end if;
end;
$migration$;

-- In-flight runs gain pending, resumable phases. An already-completed run may
-- gain completed zero-row receipts only when it truly has no grant residue.
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
  (46, 'admission_operators', 'access_credentials'),
  (47, 'tenant_admissions', 'commercial_records')
) c(phase_order, phase, data_class)
join public.tenant_data_retention_policies p
  on p.tenant_id = r.tenant_id and p.data_class = c.data_class;

update public.admission_operators o
   set revoked_at = clock_timestamp()
 where revoked_at is null and exists(select 1 from public.tenant_offboarding_runs r
   where r.tenant_id = o.tenant_id);
update public.tenant_admissions a
   set revoked_at = greatest(a.starts_at, clock_timestamp()),
       updated_at = clock_timestamp()
 where revoked_at is null and exists(select 1 from public.tenant_offboarding_runs r
   where r.tenant_id = a.tenant_id);
update public.entitlements e
   set revocation_epoch = revocation_epoch + 1
 where exists(select 1 from public.tenant_offboarding_runs r
   where r.tenant_id = e.tenant_id);

do $migration$
declare v_definition text; v_old text; v_new text;
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure)
    into v_definition;
  v_old := 'when ''rate_limits'' then ''public.rate_limits''';
  v_new := 'when ''admission_operators'' then ''public.admission_operators'''
    || chr(10) || '    when ''tenant_admissions'' then ''public.tenant_admissions'''
    || chr(10) || '    ' || v_old;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_admission_offboarding_dispatch_definition';
  end if;
  execute replace(v_definition, v_old, v_new);
end;
$migration$;

create function app.assert_admission_offboarding_receipt()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp as $$
declare v_tenant_id uuid;
begin
  if new.phase not in ('admission_operators', 'tenant_admissions')
    or new.status <> 'completed' or old.status = 'completed' then
    return new;
  end if;
  select tenant_id into strict v_tenant_id from public.tenant_offboarding_runs
    where id = new.run_id and status = 'running';
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2606));
  if old.status <> 'running' or new.eligible_at > now()
    or exists(select 1 from public.tenant_legal_holds
      where tenant_id = v_tenant_id and released_at is null)
    or (new.phase = 'admission_operators' and exists(select 1
      from public.admission_operators where tenant_id = v_tenant_id))
    or (new.phase = 'tenant_admissions' and exists(select 1
      from public.tenant_admissions where tenant_id = v_tenant_id)) then
    raise exception 'admission_offboarding_phase_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_admission_offboarding_receipt()
  from public, anon, authenticated, service_role;
create trigger admission_offboarding_phase_receipt_guard
before update of status on public.tenant_offboarding_phase_receipts
for each row execute function app.assert_admission_offboarding_receipt();

create function app.assert_admission_offboarding_closure()
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
    or exists(select 1 from public.tenant_admissions where tenant_id = v_tenant_id)
    or exists(select 1 from public.admission_operators where tenant_id = v_tenant_id)
    or not exists(select 1 from public.tenant_offboarding_phase_receipts
      where run_id = v_run_id and phase = 'tenant_admissions' and status = 'completed')
    or not exists(select 1 from public.tenant_offboarding_phase_receipts
      where run_id = v_run_id and phase = 'admission_operators' and status = 'completed') then
    raise exception 'admission_offboarding_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_admission_offboarding_closure()
  from public, anon, authenticated, service_role;
create trigger tenants_admission_offboarding_closure
before update of status on public.tenants
for each row execute function app.assert_admission_offboarding_closure();
create trigger offboarding_runs_admission_closure
before update of status on public.tenant_offboarding_runs
for each row execute function app.assert_admission_offboarding_closure();
