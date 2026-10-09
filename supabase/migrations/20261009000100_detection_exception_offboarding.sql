-- Tenant offboarding erases detection exceptions.
--
-- 20261007000200_detection_exceptions added two tenant-scoped tables that no
-- offboarding phase deleted: agent-scoped exceptions cascaded with `agents`
-- (phase 12), but user- and repository-scoped exceptions and the per-tenant
-- change-time row stayed behind after a completed offboarding (found by
-- scripts/tenant-offboarding-integration.sql on a live database).
--
-- Order matters: deleting an exception touches detection_exception_tenant_state
-- (trigger app.touch_detection_exception_state), so the state row is deleted in
-- the phase after the exceptions. Same seeding/backfill/dispatch pattern as
-- 20261005221000_oidc_scim_offboarding and 20261007000050.

create function app.seed_detection_exception_offboarding_phases()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  select new.id, c.phase_order, c.phase, 'policy_configuration', 'delete_records', p.retention_days,
    new.requested_at + make_interval(days => p.retention_days)
  from (values (58, 'detection_exceptions'), (59, 'detection_exception_tenant_state')) c(phase_order, phase)
  join public.tenant_data_retention_policies p
    on p.tenant_id = new.tenant_id and p.data_class = 'policy_configuration';
  if not found then
    raise exception 'detection_exception_retention_policy_missing' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.seed_detection_exception_offboarding_phases() from public, anon, authenticated, service_role;
create trigger tenant_offboarding_detection_exception_phases after insert on public.tenant_offboarding_runs
for each row execute function app.seed_detection_exception_offboarding_phases();

-- Runs that already exist get the phases too; completed runs record them as
-- completed (their tenants could not have exceptions created after closure).
insert into public.tenant_offboarding_phase_receipts
  (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at, status, attempts, completed_at)
select r.id, c.phase_order, c.phase, 'policy_configuration', 'delete_records', p.retention_days,
  r.requested_at + make_interval(days => p.retention_days),
  case when r.status = 'completed' then 'completed' else 'pending' end,
  case when r.status = 'completed' then 1 else 0 end,
  case when r.status = 'completed' then now() else null end
from public.tenant_offboarding_runs r
cross join (values (58, 'detection_exceptions'), (59, 'detection_exception_tenant_state')) c(phase_order, phase)
join public.tenant_data_retention_policies p on p.tenant_id = r.tenant_id and p.data_class = 'policy_configuration'
on conflict do nothing;

do $migration$
declare
  v_definition text;
  v_old text := 'when ''rate_limits'' then ''public.rate_limits''';
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure) into v_definition;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_detection_exception_offboarding_definition';
  end if;
  execute replace(v_definition, v_old,
    'when ''detection_exceptions'' then ''public.detection_exceptions''
    when ''detection_exception_tenant_state'' then ''public.detection_exception_tenant_state''
    ' || v_old);
end;
$migration$;
