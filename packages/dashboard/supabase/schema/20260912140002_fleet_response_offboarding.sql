-- Fleet command evidence follows the security-audit retention class. This
-- extension runs after the tenant offboarding migration, without changing its
-- historical bytes or shortening endpoint-identity retention.

create function app.seed_fleet_response_offboarding_phase()
returns trigger language plpgsql security definer set search_path=public,pg_temp as $$
declare v_days integer;
begin
  select p.retention_days into v_days from public.tenant_data_retention_policies p
    where p.tenant_id=new.tenant_id and p.data_class='security_audit';
  if v_days is null then raise exception 'fleet_retention_policy_missing' using errcode='23514'; end if;
  insert into public.tenant_offboarding_phase_receipts
    (run_id,phase_order,phase,data_class,operation,retention_days,eligible_at)
  values(new.id,40,'fleet_response_commands','security_audit','delete_records',
    v_days,new.requested_at+make_interval(days=>v_days))
  on conflict (run_id,phase) do nothing;
  return new;
end;
$$;
revoke all on function app.seed_fleet_response_offboarding_phase()
  from public, anon, authenticated;
create trigger tenant_offboarding_fleet_response_phase
after insert on public.tenant_offboarding_runs
for each row execute function app.seed_fleet_response_offboarding_phase();

-- An in-flight offboarding run started before this migration still gets a
-- required receipt. Completed runs cannot contain these newly introduced
-- command rows; fail the migration if that assumption is false.
do $migration$
begin
  if exists(
    select 1 from public.tenant_offboarding_runs r
    join public.fleet_response_commands c on c.tenant_id=r.tenant_id
    where r.status='completed'
  ) then raise exception 'completed_offboarding_has_fleet_commands'; end if;
end;
$migration$;
insert into public.tenant_offboarding_phase_receipts
  (run_id,phase_order,phase,data_class,operation,retention_days,eligible_at)
select r.id,40,'fleet_response_commands','security_audit','delete_records',
  p.retention_days,r.requested_at+make_interval(days=>p.retention_days)
from public.tenant_offboarding_runs r
join public.tenant_data_retention_policies p
  on p.tenant_id=r.tenant_id and p.data_class='security_audit'
where r.status<>'completed'
on conflict (run_id,phase) do nothing;

-- The existing batch RPC supplies legal-hold checks, one-phase receipts, and
-- bounded deletion. Extend only its allowlisted table mapping.
do $migration$
declare v_definition text; v_old text; v_new text;
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure)
    into v_definition;
  v_old := 'when ''revocations'' then ''public.revocations''';
  v_new := 'when ''fleet_response_commands'' then ''public.fleet_response_commands'''
    || chr(10) || '    ' || v_old;
  if position(v_old in v_definition)=0
     or position('fleet_response_commands' in v_definition)>0
  then raise exception 'unexpected_offboarding_batch_definition'; end if;
  execute replace(v_definition,v_old,v_new);
end;
$migration$;
