-- Per-tenant retention periods, bounded and audited.
--
-- `public.tenant_data_retention_policies` already stores one row per tenant and
-- data class and drives the active telemetry reaper and offboarding phase
-- eligibility. Defaults are NOT changed by this migration: every existing row
-- keeps its value and new tenants are still seeded by
-- `app.seed_tenant_retention_policies`. This migration adds
--   * `public.retention_policy_bounds`: the platform-owned min/max (days) and
--     whether a class may be tuned by a tenant owner at all,
--   * `public.admin_set_tenant_retention`: an owner-checked, bounds-checked RPC that
--     serializes on the shared tenant lock and records old/new values plus the
--     reason in `admin_audit_logs` in the same transaction.
-- Shortening a period lets the next reaper run delete data that is already older
-- than the new period. A legal hold still blocks that deletion for the held tenant.

create table if not exists public.retention_policy_bounds (
  data_class text primary key check (data_class in (
    'temporary_exports', 'access_credentials', 'telemetry',
    'endpoint_identity', 'security_intelligence', 'policy_configuration',
    'identity_membership', 'commercial_records', 'security_audit',
    'operational_ephemera'
  )),
  min_days integer not null check (min_days between 0 and 3650),
  max_days integer not null check (max_days between 0 and 3650),
  tenant_configurable boolean not null,
  check (min_days <= max_days)
);

insert into public.retention_policy_bounds(data_class, min_days, max_days, tenant_configurable) values
  ('telemetry',             7, 3650, true),
  ('endpoint_identity',    30, 3650, true),
  ('security_intelligence', 7, 3650, true),
  ('policy_configuration', 30, 3650, true),
  ('identity_membership',  30, 3650, true),
  -- Financial and security-audit evidence keep a regulatory floor.
  ('commercial_records', 2555, 3650, true),
  ('security_audit',      365, 3650, true),
  -- Credential and transient classes are platform-controlled.
  ('temporary_exports',     0,    0, false),
  ('access_credentials',    0,    0, false),
  ('operational_ephemera',  0,    7, false)
on conflict (data_class) do nothing;

alter table public.retention_policy_bounds enable row level security;
revoke all on public.retention_policy_bounds from public, anon, authenticated, service_role;
grant select on public.retention_policy_bounds to service_role;

create or replace function public.admin_set_tenant_retention(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_data_class text,
  p_retention_days integer,
  p_reason text
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog, pg_temp
as $$
declare
  v_bounds public.retention_policy_bounds;
  v_previous integer;
begin
  perform app.retention_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  if p_data_class is null or p_retention_days is null
     or p_reason is null or p_reason <> btrim(p_reason) or length(p_reason) not between 1 and 500
     or p_reason ~ '[[:cntrl:]]' then
    raise exception 'retention_invalid_request' using errcode = '22023';
  end if;
  -- Same tenant lock as hold placement, routine retention and offboarding.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  select * into v_bounds from public.retention_policy_bounds where data_class = p_data_class;
  if not found or not v_bounds.tenant_configurable then
    raise exception 'retention_class_not_configurable' using errcode = '22023';
  end if;
  if p_retention_days < v_bounds.min_days or p_retention_days > v_bounds.max_days then
    raise exception 'retention_days_out_of_bounds' using errcode = '22023',
      detail = format('allowed %s..%s days', v_bounds.min_days, v_bounds.max_days);
  end if;
  -- Phase eligibility is snapshotted per offboarding run; do not change it mid-run.
  if exists (select 1 from public.tenant_offboarding_runs where tenant_id = p_tenant_id and status <> 'completed') then
    raise exception 'retention_change_refused_offboarding' using errcode = '55000';
  end if;
  select retention_days into v_previous
    from public.tenant_data_retention_policies
   where tenant_id = p_tenant_id and data_class = p_data_class
   for update;
  if not found then
    raise exception 'retention_policy_missing' using errcode = 'P0002';
  end if;
  if v_previous = p_retention_days then
    return jsonb_build_object('data_class', p_data_class, 'retention_days', v_previous,
                              'previous_retention_days', v_previous, 'changed', false);
  end if;
  update public.tenant_data_retention_policies
     set retention_days = p_retention_days, updated_by = p_actor_user_id
   where tenant_id = p_tenant_id and data_class = p_data_class;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (p_actor_user_id, p_tenant_id, 'retention.policy.changed',
      jsonb_build_object('data_class', p_data_class, 'previous_days', v_previous,
                         'new_days', p_retention_days, 'reason', p_reason));
  return jsonb_build_object('data_class', p_data_class, 'retention_days', p_retention_days,
                            'previous_retention_days', v_previous, 'changed', true);
end;
$$;

revoke all on function public.admin_set_tenant_retention(uuid, uuid, text, integer, text) from public, anon, authenticated;
grant execute on function public.admin_set_tenant_retention(uuid, uuid, text, integer, text) to service_role;
