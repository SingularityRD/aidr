-- Tenant offboarding erases the four tenant-scoped tables it missed.
--
-- These tables were added after the offboarding inventory and no phase,
-- cascade or trigger removed them, so a completed offboarding left the
-- customer's rows behind (found by scripts/tenant-offboarding-integration.sql,
-- run from scripts/billing-offboarding-postgres.test.mjs):
--
--   phase 62  false_positive_reports     telemetry             (20261014003300)
--   phase 63  agent_retirement_settings  policy_configuration  (20261014120100)
--   phase 64  fleet_enrollment_keys      access_credentials    (20261014000210)
--   phase 65  license_imports            commercial_records    (20261014120200)
--
-- Data classes follow the closest existing table: false-positive reports are
-- connector feedback on runtime verdicts (events/incident_triage: telemetry);
-- the auto-retire threshold is tenant configuration (detection_exceptions:
-- policy_configuration); a fleet key is an enrollment secret (api_keys,
-- enrollment_tokens: access_credentials); a signed licence import is a
-- commercial record (entitlements, subscriptions: commercial_records). Each
-- phase therefore waits for the tenant's retention window for that class.
--
-- The phases use the generic batched delete in run_tenant_offboarding_batch,
-- so they keep its legal-hold block, per-tenant advisory lock, bounded batch
-- size and receipt counting. Phase order follows api_keys (6): deleting a
-- fleet key cascades to the tenant-owned device keys it minted
-- (api_keys_fleet_key_fkey), which the api_keys phase has already removed.
--
-- Same seeding/backfill/dispatch pattern as 20261009000100 and
-- 20261014000100, plus a closure guard like assert_no_siem_offboarding_residue.

create or replace function app.seed_offboarding_purge_gap_phases()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  select new.id, c.phase_order, c.phase, c.data_class, 'delete_records', p.retention_days,
    new.requested_at + make_interval(days => p.retention_days)
  from (values
    (62, 'false_positive_reports', 'telemetry'),
    (63, 'agent_retirement_settings', 'policy_configuration'),
    (64, 'fleet_enrollment_keys', 'access_credentials'),
    (65, 'license_imports', 'commercial_records')
  ) c(phase_order, phase, data_class)
  join public.tenant_data_retention_policies p
    on p.tenant_id = new.tenant_id and p.data_class = c.data_class;
  if (select count(*) from public.tenant_offboarding_phase_receipts r
       where r.run_id = new.id and r.phase in
         ('false_positive_reports', 'agent_retirement_settings', 'fleet_enrollment_keys', 'license_imports')) <> 4 then
    raise exception 'offboarding_purge_gap_retention_policy_missing' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.seed_offboarding_purge_gap_phases() from public, anon, authenticated, service_role;
drop trigger if exists tenant_offboarding_purge_gap_phases on public.tenant_offboarding_runs;
create trigger tenant_offboarding_purge_gap_phases after insert on public.tenant_offboarding_runs
for each row execute function app.seed_offboarding_purge_gap_phases();

-- A run may not complete while any of these rows remain.
create or replace function app.assert_no_offboarding_purge_gap_residue()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  if new.status <> 'completed' then return new; end if;
  if exists (select 1 from public.false_positive_reports where tenant_id = new.tenant_id)
     or exists (select 1 from public.agent_retirement_settings where tenant_id = new.tenant_id)
     or exists (select 1 from public.fleet_enrollment_keys where tenant_id = new.tenant_id)
     or exists (select 1 from public.license_imports where tenant_id = new.tenant_id) then
    raise exception 'offboarding_purge_gap_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_no_offboarding_purge_gap_residue() from public, anon, authenticated, service_role;
drop trigger if exists offboarding_runs_purge_gap_residue on public.tenant_offboarding_runs;
create trigger offboarding_runs_purge_gap_residue
  before update of status on public.tenant_offboarding_runs
  for each row execute function app.assert_no_offboarding_purge_gap_residue();

-- Existing runs get the phases too. Unlike earlier backfills, a completed run
-- is not simply marked done: it may have left exactly these rows behind. A
-- completed run whose tenant has no such rows records the phase as completed
-- (zero rows); one that still holds rows gets a pending phase and is reopened
-- so the offboarding worker purges them through the normal batched,
-- legal-hold-respecting path and completes the run again.
insert into public.tenant_offboarding_phase_receipts
  (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at, status, attempts, completed_at)
select r.id, c.phase_order, c.phase, c.data_class, 'delete_records', p.retention_days,
  r.requested_at + make_interval(days => p.retention_days),
  case when r.status = 'completed' and not c.residue then 'completed' else 'pending' end,
  case when r.status = 'completed' and not c.residue then 1 else 0 end,
  case when r.status = 'completed' and not c.residue then now() else null end
from public.tenant_offboarding_runs r
cross join lateral (values
  (62, 'false_positive_reports', 'telemetry',
    exists (select 1 from public.false_positive_reports x where x.tenant_id = r.tenant_id)),
  (63, 'agent_retirement_settings', 'policy_configuration',
    exists (select 1 from public.agent_retirement_settings x where x.tenant_id = r.tenant_id)),
  (64, 'fleet_enrollment_keys', 'access_credentials',
    exists (select 1 from public.fleet_enrollment_keys x where x.tenant_id = r.tenant_id)),
  (65, 'license_imports', 'commercial_records',
    exists (select 1 from public.license_imports x where x.tenant_id = r.tenant_id))
) c(phase_order, phase, data_class, residue)
join public.tenant_data_retention_policies p on p.tenant_id = r.tenant_id and p.data_class = c.data_class
on conflict do nothing;

update public.tenant_offboarding_runs r
   set status = 'running', completed_at = null,
       last_error = 'reopened: tenant-scoped rows outside the original offboarding phases (20261017000200)'
 where r.status = 'completed'
   and exists (select 1 from public.tenant_offboarding_phase_receipts p
                where p.run_id = r.id and p.status = 'pending'
                  and p.phase in ('false_positive_reports', 'agent_retirement_settings',
                                  'fleet_enrollment_keys', 'license_imports'));

do $migration$
declare
  v_definition text;
  v_old text := 'when ''rate_limits'' then ''public.rate_limits''';
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure) into v_definition;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_offboarding_purge_gap_definition';
  end if;
  execute replace(v_definition, v_old,
    'when ''false_positive_reports'' then ''public.false_positive_reports''
    when ''agent_retirement_settings'' then ''public.agent_retirement_settings''
    when ''fleet_enrollment_keys'' then ''public.fleet_enrollment_keys''
    when ''license_imports'' then ''public.license_imports''
    ' || v_old);
end;
$migration$;
