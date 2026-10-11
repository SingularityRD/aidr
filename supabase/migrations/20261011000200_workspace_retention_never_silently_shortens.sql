-- Workspace retention: a workspace change never silently shortens a class.
--
-- 20261010000110 routed every workspace retention change through
-- public.admin_set_tenant_retention, but it set every tenant-configurable class
-- to the workspace value (or greatest(value, class floor)). That overwrote
-- longer values an owner had set per class through the dedicated retention
-- path: with security_audit / commercial_records / identity_membership at 3650,
-- raising the workspace value 30 -> 31 (no confirmation needed, it is an
-- increase) reset them to 365 / 2555 / 31. The Edge function's confirmation
-- only compared the request with tenants.retention_days, which says nothing
-- about the per-class values.
--
-- Forward-only fix (the applied migrations are not edited):
--   * telemetry is the class the workspace value governs. It follows the
--     workspace value, but a value below the CURRENT telemetry policy (or below
--     the current workspace value) is a reduction and is refused with
--     retention_reduction_unconfirmed (55000) unless
--     p_confirm_retention_reduction is true. The comparison runs inside the
--     RPC, under the shared tenant lock, against the stored class policy;
--   * every other tenant-configurable class is only ever raised: its target is
--     greatest(derived workspace target, current class value). Shortening one
--     of them stays an explicit per-class decision through
--     public.admin_set_tenant_retention;
--   * everything else (owner-only, bounds, plan maximum, offboarding refusal,
--     lock order, per-class and workspace audit, all-or-nothing) is unchanged.
-- The previous 4-argument signature is dropped so PostgREST resolves one
-- function; the new flag defaults to false, so existing 4-argument callers keep
-- the (now safer) behaviour.

drop function if exists public.update_tenant_workspace_settings(uuid, uuid, text, integer);

create or replace function public.update_tenant_workspace_settings(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_name text,
  p_retention_days integer,
  p_confirm_retention_reduction boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_tenant public.tenants;
  v_name text;
  v_days integer;
  v_changed text[] := array[]::text[];
  v_event_id uuid := gen_random_uuid();
  v_detail jsonb;
  v_telemetry public.retention_policy_bounds;
  v_telemetry_current integer;
  v_class record;
  v_target integer;
begin
  if p_tenant_id is null or p_actor_user_id is null
     or (p_name is null and p_retention_days is null) then
    raise exception 'invalid_workspace_settings' using errcode = '22023';
  end if;
  if p_name is not null and (
       length(btrim(p_name)) not between 1 and 200
       or p_name ~ '[[:cntrl:]]') then
    raise exception 'invalid_workspace_name' using errcode = '22023';
  end if;
  -- Shape check only (tenants.retention_days constraint); the class bounds
  -- below decide what is actually allowed.
  if p_retention_days is not null and p_retention_days not between 1 and 3650 then
    raise exception 'invalid_retention_days' using errcode = '22023';
  end if;

  if p_retention_days is not null then
    -- Same tenant lock as admin_set_tenant_retention, holds and offboarding,
    -- taken first so the lock order matches theirs.
    perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  end if;

  perform 1
    from public.tenant_members m
    join public.teams team on team.id = m.tenant_id
   where m.tenant_id = p_tenant_id
     and m.user_id = p_actor_user_id
     and m.role in ('owner', 'admin')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
   for share of m, team;
  if not found then
    raise exception 'workspace_settings_forbidden' using errcode = '42501';
  end if;
  select * into v_tenant from public.tenants where id = p_tenant_id for update;
  if not found or v_tenant.status <> 'active' then
    raise exception 'workspace_settings_forbidden' using errcode = '42501';
  end if;

  v_name := coalesce(btrim(p_name), v_tenant.name);
  v_days := coalesce(p_retention_days, v_tenant.retention_days);
  if v_name is distinct from v_tenant.name then
    v_changed := array_append(v_changed, 'name');
  end if;
  if v_days is distinct from v_tenant.retention_days then
    v_changed := array_append(v_changed, 'retention_days');
  end if;

  if 'retention_days' = any(v_changed) then
    -- Owner-only (re-checked under lock; an admin, or an owner demoted while
    -- waiting, gets retention_admin_owner_required / 42501).
    perform app.retention_assert_tenant_owner(p_tenant_id, p_actor_user_id);
    select * into v_telemetry from public.retention_policy_bounds where data_class = 'telemetry';
    if not found or v_days < v_telemetry.min_days or v_days > v_telemetry.max_days then
      raise exception 'retention_days_out_of_bounds' using errcode = '22023',
        detail = format('allowed %s..%s days', v_telemetry.min_days, v_telemetry.max_days);
    end if;
    -- A reduction is judged against what is stored now (under the tenant
    -- lock), not against what the caller last read.
    select retention_days into v_telemetry_current
      from public.tenant_data_retention_policies
     where tenant_id = p_tenant_id and data_class = 'telemetry';
    if (v_days < v_tenant.retention_days or v_days < v_telemetry_current)
       and not coalesce(p_confirm_retention_reduction, false) then
      raise exception 'retention_reduction_unconfirmed' using errcode = '55000';
    end if;
    -- Every tenant-configurable class goes through the bounded, plan-checked,
    -- offboarding-aware, audited setter. Telemetry follows the workspace
    -- value; every other class is only ever raised by it.
    for v_class in
      select p.data_class, p.retention_days as current_days, b.min_days, b.max_days
        from public.tenant_data_retention_policies p
        join public.retention_policy_bounds b on b.data_class = p.data_class
       where p.tenant_id = p_tenant_id
         and b.tenant_configurable
         and p.data_class in ('telemetry', 'endpoint_identity', 'security_intelligence',
           'policy_configuration', 'identity_membership', 'commercial_records', 'security_audit')
       order by p.data_class
    loop
      v_target := case v_class.data_class
        when 'telemetry' then v_days
        when 'commercial_records' then greatest(v_days, 2555, v_class.current_days)
        when 'security_audit' then greatest(v_days, 365, v_class.current_days)
        else greatest(v_days, v_class.current_days) end;
      v_target := least(greatest(v_target, v_class.min_days), v_class.max_days);
      perform public.admin_set_tenant_retention(
        p_tenant_id, p_actor_user_id, v_class.data_class, v_target,
        'Workspace retention setting changed');
    end loop;
    -- Platform-owned ephemera stays at or below its platform ceiling.
    update public.tenant_data_retention_policies p
       set retention_days = least(v_days, b.max_days), updated_by = p_actor_user_id
      from public.retention_policy_bounds b
     where b.data_class = p.data_class
       and p.tenant_id = p_tenant_id
       and p.data_class = 'operational_ephemera'
       and p.retention_days is distinct from least(v_days, b.max_days);
  end if;

  if cardinality(v_changed) > 0 then
    update public.tenants set name = v_name, retention_days = v_days where id = p_tenant_id;
    if 'name' = any(v_changed) then
      update public.teams set name = v_name where tenant_id = p_tenant_id;
    end if;

    -- The workspace name is customer content; the audit records that it
    -- changed, not its text.
    v_detail := jsonb_build_object(
      'event_id', v_event_id,
      'changed', to_jsonb(v_changed),
      'name_changed', 'name' = any(v_changed),
      'retention_days_before', v_tenant.retention_days,
      'retention_days_after', v_days,
      'retention_reduction_confirmed', coalesce(p_confirm_retention_reduction, false)
    );
    insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (p_actor_user_id, p_tenant_id, 'tenant.settings_updated', v_detail);
    insert into public.audit_logs(team_id, tenant_id, user_id, action, verdict)
    values (p_tenant_id, p_tenant_id, p_actor_user_id, 'tenant.settings_updated', v_detail);
  end if;

  return jsonb_build_object(
    'id', p_tenant_id,
    'name', v_name,
    'retention_days', v_days,
    'status', v_tenant.status,
    'changed', to_jsonb(v_changed)
  );
end;
$$;

revoke all on function public.update_tenant_workspace_settings(uuid, uuid, text, integer, boolean)
  from public, anon, authenticated;
grant execute on function public.update_tenant_workspace_settings(uuid, uuid, text, integer, boolean)
  to service_role;
