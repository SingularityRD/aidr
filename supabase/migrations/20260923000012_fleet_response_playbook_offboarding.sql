-- Delete playbook evidence before the fleet commands it references. Keep the
-- shipped offboarding migrations append-only and preserve every later phase.

lock table public.tenant_offboarding_runs, public.tenant_offboarding_phase_receipts
  in access exclusive mode;

do $migration$
begin
  if exists (
    select 1
    from public.tenant_offboarding_runs r
    where r.status = 'completed'
      and (
        exists (select 1 from public.fleet_response_playbook_runs p where p.tenant_id = r.tenant_id)
        or exists (select 1 from public.fleet_response_playbook_steps p where p.tenant_id = r.tenant_id)
      )
  ) then raise exception 'completed_offboarding_has_fleet_response_playbook_data'; end if;

  if exists (
    select 1 from public.tenant_offboarding_runs r
    where r.status <> 'completed'
      and not exists (
        select 1 from public.tenant_data_retention_policies p
        where p.tenant_id = r.tenant_id and p.data_class = 'security_audit'
      )
  ) then raise exception 'playbook_retention_policy_missing'; end if;

  if exists (
    select 1
    from public.tenant_offboarding_runs r
    join public.tenant_offboarding_phase_receipts p on p.run_id = r.id
    where r.status <> 'completed' and (
      (p.phase_order = 40 and p.phase <> 'fleet_response_commands') or
      (p.phase = 'fleet_response_commands' and p.phase_order <> 40) or
      (p.phase_order = 41 and p.phase <> 'tenant_cache') or
      (p.phase = 'tenant_cache' and p.phase_order <> 41) or
      (p.phase_order = 42 and p.phase <> 'dlp_policy_revisions') or
      (p.phase = 'dlp_policy_revisions' and p.phase_order <> 42) or
      (p.phase_order = 43 and p.phase <> 'tenant_dlp_policies') or
      (p.phase = 'tenant_dlp_policies' and p.phase_order <> 43) or
      p.phase_order in (44, 45)
    )
  ) then raise exception 'unexpected_inflight_offboarding_phase_order'; end if;

  if exists (
    select 1 from public.tenant_offboarding_runs r
    join public.tenant_offboarding_phase_receipts p on p.run_id = r.id
    join public.fleet_response_playbook_runs b on b.tenant_id = r.tenant_id
    where r.status <> 'completed' and p.phase = 'fleet_response_commands' and p.status = 'completed'
  ) then raise exception 'completed_fleet_phase_has_playbook_data'; end if;

  if exists (
    select 1 from public.tenant_offboarding_phase_receipts p
    where p.phase in ('fleet_response_playbook_steps', 'fleet_response_playbook_runs')
  ) then raise exception 'unexpected_existing_playbook_offboarding_phase'; end if;
end;
$migration$;

-- Free phase orders 40 and 41 for the two playbook tables. Descending updates
-- avoid collisions with the unique (run_id, phase_order) constraint.
do $migration$
declare v_receipt record;
begin
  for v_receipt in
    select p.run_id, p.phase
    from public.tenant_offboarding_phase_receipts p
    join public.tenant_offboarding_runs r on r.id = p.run_id
    where r.status <> 'completed' and p.phase_order between 40 and 43
    order by p.run_id, p.phase_order desc
    for update of p
  loop
    update public.tenant_offboarding_phase_receipts
      set phase_order = phase_order + 2
      where run_id = v_receipt.run_id and phase = v_receipt.phase;
  end loop;
end;
$migration$;

-- Keep the established extension hooks aligned with the new phase sequence.
create or replace function app.seed_fleet_response_offboarding_phase()
returns trigger language plpgsql security definer set search_path=public,pg_temp as $$
declare v_days integer;
begin
  select p.retention_days into v_days from public.tenant_data_retention_policies p
    where p.tenant_id=new.tenant_id and p.data_class='security_audit';
  if v_days is null then raise exception 'fleet_retention_policy_missing' using errcode='23514'; end if;
  insert into public.tenant_offboarding_phase_receipts
    (run_id,phase_order,phase,data_class,operation,retention_days,eligible_at)
  values(new.id,42,'fleet_response_commands','security_audit','delete_records',
    v_days,new.requested_at+make_interval(days=>v_days))
  on conflict (run_id,phase) do nothing;
  return new;
end;
$$;

create or replace function app.seed_tenant_cache_invalidation_phase()
returns trigger language plpgsql security definer set search_path=public,pg_temp as $$
declare v_days integer;
begin
  select p.retention_days into v_days from public.tenant_data_retention_policies p
    where p.tenant_id = new.tenant_id and p.data_class = 'operational_ephemera';
  if v_days is null then raise exception 'cache_retention_policy_missing' using errcode = '23514'; end if;
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  values (new.id, 43, 'tenant_cache', 'operational_ephemera', 'invalidate_cache',
    v_days, new.requested_at + make_interval(days => v_days))
  on conflict (run_id, phase) do nothing;
  return new;
end;
$$;

create or replace function app.seed_dlp_policy_offboarding_phases()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare v_days integer;
begin
  select retention_days into v_days from public.tenant_data_retention_policies
    where tenant_id = new.tenant_id and data_class = 'policy_configuration';
  if v_days is null then raise exception 'dlp_retention_policy_missing' using errcode = '23514'; end if;
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  values
    (new.id, 44, 'dlp_policy_revisions', 'policy_configuration', 'delete_records', v_days, new.requested_at + make_interval(days => v_days)),
    (new.id, 45, 'tenant_dlp_policies', 'policy_configuration', 'delete_records', v_days, new.requested_at + make_interval(days => v_days))
  on conflict (run_id, phase) do nothing;
  return new;
end;
$$;

revoke all on function app.seed_fleet_response_offboarding_phase() from public, anon, authenticated;
revoke all on function app.seed_tenant_cache_invalidation_phase() from public, anon, authenticated;
revoke all on function app.seed_dlp_policy_offboarding_phases() from public, anon, authenticated;

create function app.seed_fleet_response_playbook_offboarding_phases()
returns trigger language plpgsql security definer set search_path=public,pg_temp as $$
declare v_days integer;
begin
  select p.retention_days into v_days from public.tenant_data_retention_policies p
    where p.tenant_id=new.tenant_id and p.data_class='security_audit';
  if v_days is null then raise exception 'playbook_retention_policy_missing' using errcode='23514'; end if;
  insert into public.tenant_offboarding_phase_receipts
    (run_id,phase_order,phase,data_class,operation,retention_days,eligible_at)
  values
    (new.id,40,'fleet_response_playbook_steps','security_audit','delete_records',v_days,new.requested_at+make_interval(days=>v_days)),
    (new.id,41,'fleet_response_playbook_runs','security_audit','delete_records',v_days,new.requested_at+make_interval(days=>v_days))
  on conflict (run_id,phase) do nothing;
  return new;
end;
$$;
revoke all on function app.seed_fleet_response_playbook_offboarding_phases() from public, anon, authenticated;
create trigger tenant_offboarding_fleet_response_playbook_phases
after insert on public.tenant_offboarding_runs
for each row execute function app.seed_fleet_response_playbook_offboarding_phases();

insert into public.tenant_offboarding_phase_receipts
  (run_id,phase_order,phase,data_class,operation,retention_days,eligible_at)
select r.id,c.phase_order,c.phase,'security_audit','delete_records',p.retention_days,
  r.requested_at+make_interval(days=>p.retention_days)
from public.tenant_offboarding_runs r
join public.tenant_data_retention_policies p
  on p.tenant_id=r.tenant_id and p.data_class='security_audit'
cross join (values
  (40,'fleet_response_playbook_steps'),
  (41,'fleet_response_playbook_runs')
) c(phase_order,phase)
where r.status<>'completed';

-- Extend only the stable dispatcher anchors. It remains bounded, hold-aware,
-- and receipt-driven; playbook children are deleted before their commands.
do $migration$
declare v_definition text; v_old text; v_new text;
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure)
    into v_definition;
  v_old := 'when ''fleet_response_commands'' then ''public.fleet_response_commands''';
  v_new := 'when ''fleet_response_playbook_steps'' then ''public.fleet_response_playbook_steps'''
    || chr(10) || '    when ''fleet_response_playbook_runs'' then ''public.fleet_response_playbook_runs'''
    || chr(10) || '    ' || v_old;
  if cardinality(string_to_array(v_definition,v_old)) <> 2
     or position('fleet_response_playbook_steps' in v_definition) > 0
  then raise exception 'unexpected_playbook_offboarding_dispatch_definition'; end if;
  v_definition := replace(v_definition,v_old,v_new);

  v_old := 'if v_phase.phase in (''dlp_policy_revisions'',''tenant_dlp_policies'') then';
  v_new := 'if v_phase.phase in (''fleet_response_playbook_steps'',''fleet_response_playbook_runs'') then'
    || chr(10) || '    perform set_config(''app.aidr_playbook_offboarding_run_id'',p_run_id::text,true);'
    || chr(10) || '  end if;' || chr(10) || '  ' || v_old;
  if cardinality(string_to_array(v_definition,v_old)) <> 2
  then raise exception 'unexpected_playbook_offboarding_delete_definition'; end if;
  execute replace(v_definition,v_old,v_new);
end;
$migration$;

create function app.protect_fleet_response_playbook_offboarding()
returns trigger language plpgsql security definer set search_path=public,pg_temp as $$
declare
  v_run_text text := nullif(current_setting('app.aidr_playbook_offboarding_run_id',true),'');
  v_run_id uuid;
  v_phase text;
begin
  if v_run_text is null then
    raise exception 'fleet_response_playbook_delete_forbidden' using errcode='42501';
  end if;
  begin
    v_run_id := v_run_text::uuid;
  exception when invalid_text_representation then
    raise exception 'fleet_response_playbook_delete_forbidden' using errcode='42501';
  end;
  if tg_table_name='fleet_response_playbook_steps' then v_phase := 'fleet_response_playbook_steps';
  elsif tg_table_name='fleet_response_playbook_runs' then v_phase := 'fleet_response_playbook_runs';
  else raise exception 'unsupported_playbook_offboarding_table' using errcode='55000'; end if;

  perform pg_advisory_xact_lock(hashtextextended(old.tenant_id::text,2606));
  if exists(select 1 from public.tenant_legal_holds h
    where h.tenant_id=old.tenant_id and h.released_at is null) then
    raise exception 'active_legal_hold' using errcode='55000';
  end if;
  if not exists(
    select 1 from public.tenant_offboarding_runs r
    join public.tenant_offboarding_phase_receipts p on p.run_id=r.id
    where r.id=v_run_id and r.tenant_id=old.tenant_id and r.status='running'
      and p.phase=v_phase and p.status='running' and p.eligible_at<=now()
      and p.data_class='security_audit' and p.operation='delete_records'
  ) then raise exception 'fleet_response_playbook_offboarding_phase_required' using errcode='42501'; end if;
  return old;
end;
$$;
revoke all on function app.protect_fleet_response_playbook_offboarding() from public, anon, authenticated, service_role;
create trigger fleet_response_playbook_steps_offboarding_guard
before delete on public.fleet_response_playbook_steps
for each row execute function app.protect_fleet_response_playbook_offboarding();
create trigger fleet_response_playbook_runs_offboarding_guard
before delete on public.fleet_response_playbook_runs
for each row execute function app.protect_fleet_response_playbook_offboarding();

create function app.assert_fleet_response_playbook_offboarding_receipt()
returns trigger language plpgsql security definer set search_path=public,pg_temp as $$
declare v_tenant_id uuid;
begin
  if new.status='completed' and old.status is distinct from 'completed'
     and new.phase in ('fleet_response_playbook_steps','fleet_response_playbook_runs') then
    select r.tenant_id into strict v_tenant_id
      from public.tenant_offboarding_runs r where r.id=new.run_id;
    if (new.phase='fleet_response_playbook_steps' and exists(
          select 1 from public.fleet_response_playbook_steps where tenant_id=v_tenant_id))
       or (new.phase='fleet_response_playbook_runs' and exists(
          select 1 from public.fleet_response_playbook_runs where tenant_id=v_tenant_id)) then
      raise exception 'fleet_response_playbook_offboarding_residue' using errcode='23514';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function app.assert_fleet_response_playbook_offboarding_receipt() from public, anon, authenticated;
create trigger fleet_response_playbook_offboarding_receipt_guard
before update of status on public.tenant_offboarding_phase_receipts
for each row execute function app.assert_fleet_response_playbook_offboarding_receipt();

create function app.assert_no_fleet_response_playbook_offboarding_residue()
returns trigger language plpgsql security definer set search_path=public,pg_temp as $$
declare v_tenant_id uuid;
begin
  if tg_table_name='tenants' then
    v_tenant_id := new.id;
    if new.status <> 'closed' then return new; end if;
  else
    v_tenant_id := new.tenant_id;
    if new.status <> 'completed' then return new; end if;
  end if;
  if exists(select 1 from public.fleet_response_playbook_runs where tenant_id=v_tenant_id)
     or exists(select 1 from public.fleet_response_playbook_steps where tenant_id=v_tenant_id) then
    raise exception 'fleet_response_playbook_offboarding_residue' using errcode='23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_no_fleet_response_playbook_offboarding_residue() from public, anon, authenticated;
create trigger tenants_fleet_response_playbook_offboarding_residue
before update of status on public.tenants
for each row execute function app.assert_no_fleet_response_playbook_offboarding_residue();
create trigger offboarding_runs_fleet_response_playbook_residue
before update of status on public.tenant_offboarding_runs
for each row execute function app.assert_no_fleet_response_playbook_offboarding_residue();
