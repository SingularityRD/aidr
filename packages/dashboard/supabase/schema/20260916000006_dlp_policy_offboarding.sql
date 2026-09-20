-- Extend the existing hold-aware, bounded offboarding dispatcher. DLP documents
-- are policy_configuration (not a new data class); backups remain excluded.
create function app.seed_dlp_policy_offboarding_phases()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare v_days integer;
begin
  select retention_days into v_days from public.tenant_data_retention_policies
    where tenant_id = new.tenant_id and data_class = 'policy_configuration';
  if v_days is null then raise exception 'dlp_retention_policy_missing' using errcode = '23514'; end if;
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  values
    (new.id, 42, 'dlp_policy_revisions', 'policy_configuration', 'delete_records', v_days, new.requested_at + make_interval(days => v_days)),
    (new.id, 43, 'tenant_dlp_policies', 'policy_configuration', 'delete_records', v_days, new.requested_at + make_interval(days => v_days))
  on conflict (run_id, phase) do nothing;
  return new;
end;
$$;
revoke all on function app.seed_dlp_policy_offboarding_phases() from public, anon, authenticated;
create trigger tenant_offboarding_dlp_policy_phases
  after insert on public.tenant_offboarding_runs
  for each row execute function app.seed_dlp_policy_offboarding_phases();

-- Do not silently leave an old run outside the new deletion contract.
do $migration$
begin
  if exists (
    select 1 from public.tenant_offboarding_runs r where r.status = 'completed' and (
      exists(select 1 from public.tenant_dlp_policies p where p.tenant_id = r.tenant_id) or
      exists(select 1 from public.dlp_policy_revisions p where p.tenant_id = r.tenant_id))
  ) then raise exception 'completed_offboarding_has_dlp_policies'; end if;
  if exists (
    select 1 from public.tenant_offboarding_runs r where r.status <> 'completed' and not exists (
      select 1 from public.tenant_data_retention_policies p where p.tenant_id = r.tenant_id and p.data_class = 'policy_configuration')
  ) then raise exception 'dlp_retention_policy_missing'; end if;
end;
$migration$;
insert into public.tenant_offboarding_phase_receipts
  (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
select r.id, c.phase_order, c.phase, 'policy_configuration', 'delete_records',
  p.retention_days, r.requested_at + make_interval(days => p.retention_days)
from public.tenant_offboarding_runs r
join public.tenant_data_retention_policies p on p.tenant_id = r.tenant_id and p.data_class = 'policy_configuration'
cross join (values (42, 'dlp_policy_revisions'), (43, 'tenant_dlp_policies')) c(phase_order, phase)
where r.status <> 'completed'
on conflict (run_id, phase) do nothing;

-- Like fleet/cache extensions, patch only stable, unique anchors, preserving
-- prior extensions. Fail the migration rather than guessing on source drift.
do $migration$
declare v_definition text; v_old text; v_new text;
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure) into v_definition;
  v_old := 'when ''tenant_runtime_policies'' then ''public.tenant_runtime_policies''';
  v_new := 'when ''dlp_policy_revisions'' then ''public.dlp_policy_revisions'''
    || chr(10) || '    when ''tenant_dlp_policies'' then ''public.tenant_dlp_policies'''
    || chr(10) || '    ' || v_old;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 or position('dlp_policy_revisions' in v_definition) > 0
    then raise exception 'unexpected_dlp_offboarding_dispatch_definition'; end if;
  v_definition := replace(v_definition, v_old, v_new);
  v_old := 'if v_phase.phase=''audit_logs'' then perform set_config(''app.aidr_offboarding_run_id'',p_run_id::text,true); end if;';
  v_new := 'if v_phase.phase in (''dlp_policy_revisions'',''tenant_dlp_policies'') then'
    || chr(10) || '    perform set_config(''app.aidr_dlp_offboarding_run_id'',p_run_id::text,true);'
    || chr(10) || '  end if;' || chr(10) || '  ' || v_old;
  if cardinality(string_to_array(v_definition, v_old)) <> 2
    then raise exception 'unexpected_dlp_offboarding_delete_definition'; end if;
  execute replace(v_definition, v_old, v_new);
end;
$migration$;

-- Normal history stays immutable, including for a service client. Only a live,
-- eligible, tenant-bound phase may delete. The legal-hold lock is the SAME one
-- used by hold placement/release and the dispatcher, preventing a hold race.
create function app.protect_dlp_policy_deletion()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare v_run text := current_setting('app.aidr_dlp_offboarding_run_id', true);
begin
  if tg_op = 'DELETE' and v_run ~ '^[0-9a-f-]{36}$' then
    perform pg_advisory_xact_lock(hashtextextended(old.tenant_id::text, 2606));
    if exists (
      select 1 from public.tenant_offboarding_runs r
      join public.tenant_offboarding_phase_receipts p on p.run_id = r.id
      where r.id = v_run::uuid and r.tenant_id = old.tenant_id and r.status = 'running'
        and p.phase = tg_table_name and p.status = 'running' and p.eligible_at <= now()
        and p.data_class = 'policy_configuration' and p.operation = 'delete_records'
        and not exists(select 1 from public.tenant_legal_holds h where h.tenant_id = r.tenant_id and h.released_at is null)
    ) and (tg_table_name = 'dlp_policy_revisions' or not exists (
      select 1 from public.dlp_policy_revisions p where p.tenant_id = old.tenant_id
    )) then return old; end if;
  end if;
  raise exception 'dlp_policy_history_is_immutable_except_offboarding' using errcode = '42501';
end;
$$;
revoke all on function app.protect_dlp_policy_deletion() from public, anon, authenticated;
create trigger dlp_policy_revisions_immutable before update or delete on public.dlp_policy_revisions
  for each row execute function app.protect_dlp_policy_deletion();
create trigger tenant_dlp_policies_delete_guard before delete on public.tenant_dlp_policies
  for each row execute function app.protect_dlp_policy_deletion();

-- Receipts alone never prove deletion. Neither a final run nor a tenant close
-- can succeed with remaining current/history documents (including forged acks).
create function app.assert_no_dlp_offboarding_residue()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare v_tenant uuid;
begin
  if tg_table_name = 'tenants' then v_tenant := new.id; else v_tenant := new.tenant_id; end if;
  if new.status in ('closed', 'completed') and (
    exists(select 1 from public.tenant_dlp_policies p where p.tenant_id = v_tenant) or
    exists(select 1 from public.dlp_policy_revisions p where p.tenant_id = v_tenant)
  ) then raise exception 'dlp_policy_offboarding_residue' using errcode = '23514'; end if;
  return new;
end;
$$;
revoke all on function app.assert_no_dlp_offboarding_residue() from public, anon, authenticated;
create trigger tenants_dlp_offboarding_residue before update of status on public.tenants
  for each row execute function app.assert_no_dlp_offboarding_residue();
create trigger offboarding_runs_dlp_residue before update of status on public.tenant_offboarding_runs
  for each row execute function app.assert_no_dlp_offboarding_residue();
