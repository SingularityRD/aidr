-- Run against an isolated fully migrated database. Every fixture is rolled back.
-- public.update_tenant_workspace_settings (20261010000110): an admin may rename
-- but never change retention; an owner's retention change goes through the
-- bounded setter (class floors, plan maximum, offboarding refusal) atomically.
begin;
do $checks$
declare
  v_owner uuid := gen_random_uuid();
  v_admin uuid := gen_random_uuid();
  v_backup_owner uuid := gen_random_uuid();
  v_current integer;
  v_tenant uuid := gen_random_uuid();
  v_result jsonb;
  v_before jsonb;
  v_after jsonb;
  v_plan_max integer;
  v_target integer;
  v_floor_violations integer;
begin
  insert into auth.users(id, email)
  values (v_owner, 'ws-owner-' || v_owner || '@test.invalid'),
         (v_admin, 'ws-admin-' || v_admin || '@test.invalid'),
         (v_backup_owner, 'ws-backup-' || v_backup_owner || '@test.invalid');
  insert into public.tenants(id, name, kind, created_by)
  values (v_tenant, 'Workspace retention test', 'team', v_owner);
  insert into public.teams(id, tenant_id, name, plan)
  values (v_tenant, v_tenant, 'Workspace retention test', 'free');
  insert into public.tenant_members(tenant_id, user_id, role)
  values (v_tenant, v_owner, 'owner'), (v_tenant, v_admin, 'admin'),
         (v_tenant, v_backup_owner, 'owner');
  select retention_days into v_current from public.tenants where id = v_tenant;

  select jsonb_object_agg(data_class, retention_days) into v_before
    from public.tenant_data_retention_policies where tenant_id = v_tenant;

  -- 1. Admin cannot change retention, to any value, alone or with a rename.
  foreach v_target in array array[1, 7, 30, 3650] loop
    continue when v_target = v_current;
    begin
      perform public.update_tenant_workspace_settings(v_tenant, v_admin, null, v_target);
      raise exception 'FAIL: admin changed retention to % days', v_target;
    exception when insufficient_privilege then null;
    end;
  end loop;
  begin
    perform public.update_tenant_workspace_settings(v_tenant, v_admin, 'Renamed by admin', v_current + 1);
    raise exception 'FAIL: admin changed retention together with a rename';
  exception when insufficient_privilege then null;
  end;
  select jsonb_object_agg(data_class, retention_days) into v_after
    from public.tenant_data_retention_policies where tenant_id = v_tenant;
  if v_after is distinct from v_before then
    raise exception 'FAIL: refused admin request changed class policies: % -> %', v_before, v_after;
  end if;
  if (select name from public.tenants where id = v_tenant) <> 'Workspace retention test' then
    raise exception 'FAIL: refused admin request committed its rename';
  end if;

  -- 2. Admin rename still works (with or without restating the current value).
  v_result := public.update_tenant_workspace_settings(v_tenant, v_admin, 'Renamed by admin', null);
  if v_result -> 'changed' <> '["name"]'::jsonb then
    raise exception 'FAIL: admin rename result %', v_result;
  end if;
  v_result := public.update_tenant_workspace_settings(v_tenant, v_admin, 'Renamed again', v_current);
  if v_result -> 'changed' <> '["name"]'::jsonb
     or (select name from public.teams where tenant_id = v_tenant) <> 'Renamed again' then
    raise exception 'FAIL: admin rename with unchanged retention %', v_result;
  end if;

  -- 3. Owner cannot go below the telemetry floor (7).
  foreach v_target in array array[1, 6] loop
    begin
      perform public.update_tenant_workspace_settings(v_tenant, v_owner, null, v_target);
      raise exception 'FAIL: owner set workspace retention to % days', v_target;
    exception when invalid_parameter_value then
      if sqlerrm <> 'retention_days_out_of_bounds' then raise; end if;
    end;
  end loop;

  -- 4. Owner at the telemetry floor: telemetry follows, every class keeps its floor.
  v_plan_max := (app.tenant_plan_entitlements(v_tenant) ->> 'retention_days_max')::integer;
  v_result := public.update_tenant_workspace_settings(v_tenant, v_owner, null, 7);
  if (v_result ->> 'retention_days')::integer <> 7 then
    raise exception 'FAIL: owner floor change result %', v_result;
  end if;
  select count(*) into v_floor_violations
    from public.tenant_data_retention_policies p
    join public.retention_policy_bounds b using (data_class)
   where p.tenant_id = v_tenant
     and (p.retention_days < b.min_days or p.retention_days > b.max_days);
  if v_floor_violations <> 0 then
    raise exception 'FAIL: % class policies outside retention_policy_bounds', v_floor_violations;
  end if;
  if (select retention_days from public.tenant_data_retention_policies
       where tenant_id = v_tenant and data_class = 'telemetry') <> 7
     or (select retention_days from public.tenant_data_retention_policies
          where tenant_id = v_tenant and data_class = 'identity_membership') < 30
     or (select retention_days from public.tenant_data_retention_policies
          where tenant_id = v_tenant and data_class = 'policy_configuration') < 30
     or (select retention_days from public.tenant_data_retention_policies
          where tenant_id = v_tenant and data_class = 'endpoint_identity') < 30
     or (select retention_days from public.tenant_data_retention_policies
          where tenant_id = v_tenant and data_class = 'security_intelligence') < 7 then
    raise exception 'FAIL: per-class floors not applied';
  end if;
  if not exists (select 1 from public.admin_audit_logs
                  where tenant_id = v_tenant and action = 'retention.policy.changed'
                    and detail ->> 'data_class' = 'telemetry' and actor_user_id = v_owner)
     or not exists (select 1 from public.admin_audit_logs
                     where tenant_id = v_tenant and action = 'tenant.settings_updated'
                       and actor_user_id = v_owner) then
    raise exception 'FAIL: bounded change was not audited per class and per workspace';
  end if;

  -- 5. Owner cannot exceed the plan's telemetry maximum; nothing is committed.
  if v_plan_max is not null and v_plan_max < 3650 then
    select jsonb_object_agg(data_class, retention_days) into v_before
      from public.tenant_data_retention_policies where tenant_id = v_tenant;
    begin
      perform public.update_tenant_workspace_settings(v_tenant, v_owner, 'Should not stick', v_plan_max + 1);
      raise exception 'FAIL: owner exceeded plan maximum %', v_plan_max;
    exception when invalid_parameter_value then
      if sqlerrm <> 'retention_days_exceeds_plan' then raise; end if;
    end;
    select jsonb_object_agg(data_class, retention_days) into v_after
      from public.tenant_data_retention_policies where tenant_id = v_tenant;
    if v_after is distinct from v_before
       or (select retention_days from public.tenants where id = v_tenant) <> 7
       or (select name from public.tenants where id = v_tenant) <> 'Renamed again' then
      raise exception 'FAIL: refused plan-exceeding change was partially committed';
    end if;
  end if;

  -- 6. A demoted owner is refused like an admin.
  update public.tenant_members set role = 'admin' where tenant_id = v_tenant and user_id = v_owner;
  begin
    perform public.update_tenant_workspace_settings(v_tenant, v_owner, null, 7 + 1);
    raise exception 'FAIL: demoted owner changed retention';
  exception when insufficient_privilege then null;
  end;
  raise notice 'workspace-settings-retention: ok (plan max %)', v_plan_max;
end;
$checks$;
rollback;
