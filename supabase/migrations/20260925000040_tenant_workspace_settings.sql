-- Workspace settings: rename, telemetry retention and owner-requested closure.
--
-- The `tenant-settings` Edge Function authenticates the caller, applies the
-- identity barrier and AAL2, and then calls these service-role-only RPCs. Each
-- RPC re-checks the caller's live membership and tenant status under a row lock
-- so a concurrent role removal, suspension or closure cannot commit between the
-- function's check and the mutation, and writes its privileged and
-- customer-visible audit rows in the same transaction.
--
-- Closure reuses `public.request_tenant_offboarding`, which already revokes
-- credentials and admissions, moves the tenant to `closing` and schedules the
-- retention-bound offboarding phases. It is not reimplemented here.

create or replace function public.update_tenant_workspace_settings(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_name text,
  p_retention_days integer
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
  -- Same bounds as the tenants.retention_days constraint.
  if p_retention_days is not null and p_retention_days not between 1 and 3650 then
    raise exception 'invalid_retention_days' using errcode = '22023';
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

  if cardinality(v_changed) > 0 then
    update public.tenants set name = v_name, retention_days = v_days where id = p_tenant_id;
    if 'name' = any(v_changed) then
      update public.teams set name = v_name where tenant_id = p_tenant_id;
    end if;
    if 'retention_days' = any(v_changed) then
      -- Keep the per-class policy that retention and offboarding actually read
      -- in step with the workspace setting, using the seed derivation from
      -- 20260912140000: telemetry-like classes follow the setting; commercial
      -- and security-audit evidence keep their floors; ephemera stays capped.
      update public.tenant_data_retention_policies p
         set retention_days = case p.data_class
               when 'commercial_records' then greatest(v_days, 2555)
               when 'security_audit' then greatest(v_days, 365)
               when 'operational_ephemera' then least(v_days, 7)
               else v_days end,
             updated_by = p_actor_user_id
       where p.tenant_id = p_tenant_id
         and p.data_class in ('telemetry', 'endpoint_identity', 'security_intelligence',
           'policy_configuration', 'identity_membership', 'commercial_records',
           'security_audit', 'operational_ephemera');
    end if;

    -- The workspace name is customer content; the audit records that it
    -- changed, not its text.
    v_detail := jsonb_build_object(
      'event_id', v_event_id,
      'changed', to_jsonb(v_changed),
      'name_changed', 'name' = any(v_changed),
      'retention_days_before', v_tenant.retention_days,
      'retention_days_after', v_days
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

revoke all on function public.update_tenant_workspace_settings(uuid, uuid, text, integer)
  from public, anon, authenticated;
grant execute on function public.update_tenant_workspace_settings(uuid, uuid, text, integer)
  to service_role;

create or replace function public.request_workspace_closure(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_confirm_name text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_tenant public.tenants;
  v_event_id uuid := gen_random_uuid();
  v_detail jsonb;
  v_result jsonb;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_confirm_name is null then
    raise exception 'invalid_workspace_closure' using errcode = '22023';
  end if;

  -- Closure is an owner decision. Lock the owner's membership so a concurrent
  -- demotion cannot commit between this check and the offboarding request.
  perform 1
    from public.tenant_members m
    join public.teams team on team.id = m.tenant_id
   where m.tenant_id = p_tenant_id
     and m.user_id = p_actor_user_id
     and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > clock_timestamp())
   for share of m, team;
  if not found then
    raise exception 'workspace_closure_forbidden' using errcode = '42501';
  end if;
  select * into v_tenant from public.tenants where id = p_tenant_id for update;
  if not found then
    raise exception 'workspace_closure_forbidden' using errcode = '42501';
  end if;
  if v_tenant.status <> 'active' then
    raise exception 'workspace_not_active' using errcode = '55000';
  end if;
  -- Typed confirmation: the exact current workspace name, surrounding
  -- whitespace ignored. Checked again here so a rename racing the request
  -- cannot close a workspace the owner did not name.
  if btrim(p_confirm_name) is distinct from v_tenant.name then
    raise exception 'workspace_name_mismatch' using errcode = '22023';
  end if;

  v_detail := jsonb_build_object('event_id', v_event_id, 'source', 'tenant-settings');
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, 'tenant.closure_requested', v_detail);
  insert into public.audit_logs(team_id, tenant_id, user_id, action, verdict)
  values (p_tenant_id, p_tenant_id, p_actor_user_id, 'tenant.closure_requested', v_detail);

  v_result := public.request_tenant_offboarding(p_tenant_id, p_actor_user_id);
  return v_result;
end;
$$;

revoke all on function public.request_workspace_closure(uuid, uuid, text)
  from public, anon, authenticated;
grant execute on function public.request_workspace_closure(uuid, uuid, text)
  to service_role;
