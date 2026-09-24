-- SCIM group and mapping changes may reconcile the same users concurrently.
-- Always acquire per-user row locks in a stable order to avoid cross-group
-- deadlocks when two reconciliations touch overlapping member sets.
create or replace function public.scim_replace_group_members(
  p_tenant_id uuid, p_group_id uuid, p_user_ids uuid[], p_expected_version bigint default null
) returns void language plpgsql security definer set search_path = public, pg_catalog as $$
declare v_current bigint; v_user uuid; v_affected uuid[];
begin
  select version into v_current from public.scim_groups
   where tenant_id = p_tenant_id and id = p_group_id for update;
  if not found then raise exception 'scim_group_not_found' using errcode = 'P0002'; end if;
  if p_expected_version is not null and p_expected_version <> v_current then
    raise exception 'scim_version_mismatch' using errcode = '40001';
  end if;
  if exists(select 1 from unnest(coalesce(p_user_ids, array[]::uuid[])) requested(id)
    where not exists(select 1 from public.scim_users su where su.tenant_id = p_tenant_id and su.id = requested.id)) then
    raise exception 'scim_cross_tenant_or_unknown_user' using errcode = '22023';
  end if;
  select array_agg(id order by id) into v_affected from (
    select user_id id from public.scim_group_memberships where tenant_id = p_tenant_id and group_id = p_group_id
    union select unnest(coalesce(p_user_ids, array[]::uuid[]))
  ) affected;
  delete from public.scim_group_memberships where tenant_id = p_tenant_id and group_id = p_group_id;
  insert into public.scim_group_memberships(tenant_id, group_id, user_id)
    select p_tenant_id, p_group_id, id from unnest(coalesce(p_user_ids, array[]::uuid[])) ids(id)
    on conflict do nothing;
  update public.scim_groups set version = version + 1, updated_at = now()
   where tenant_id = p_tenant_id and id = p_group_id;
  foreach v_user in array coalesce(v_affected, array[]::uuid[]) loop
    perform public.scim_reconcile_membership(p_tenant_id, v_user);
  end loop;
end;
$$;

create or replace function public.scim_delete_group(
  p_tenant_id uuid, p_group_id uuid, p_expected_version bigint default null
) returns boolean language plpgsql security definer set search_path = public, pg_catalog as $$
declare v_current bigint; v_user uuid; v_affected uuid[]; v_external_id text;
begin
  select version, external_id into v_current, v_external_id from public.scim_groups
   where tenant_id = p_tenant_id and id = p_group_id for update;
  if not found then return false; end if;
  if p_expected_version is not null and p_expected_version <> v_current then
    raise exception 'scim_version_mismatch' using errcode = '40001';
  end if;
  select array_agg(user_id order by user_id) into v_affected from public.scim_group_memberships
   where tenant_id = p_tenant_id and group_id = p_group_id;
  delete from public.scim_groups where tenant_id = p_tenant_id and id = p_group_id;
  foreach v_user in array coalesce(v_affected, array[]::uuid[]) loop
    perform public.scim_reconcile_membership(p_tenant_id, v_user);
  end loop;
  insert into public.admin_audit_logs(tenant_id, action, detail)
    values(p_tenant_id, 'scim.group.deleted', jsonb_build_object('scim_group_id', p_group_id, 'external_id', v_external_id));
  return true;
end;
$$;

-- Role-mapping changes use the same ordering as group member replacement.
create or replace function app.scim_mapping_reconcile_members()
returns trigger language plpgsql security definer set search_path = public, pg_catalog as $$
declare
  v_tenant_id uuid;
  v_external_id text;
  v_user uuid;
  v_actor_text text;
  v_actor_id uuid;
begin
  if tg_op = 'DELETE' then
    v_tenant_id := old.tenant_id;
    v_external_id := old.external_group_id;
  else
    v_tenant_id := new.tenant_id;
    v_external_id := new.external_group_id;
  end if;
  v_actor_text := nullif(current_setting('aidr.scim_actor_user_id', true), '');
  if v_actor_text ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
    v_actor_id := v_actor_text::uuid;
  elsif tg_op = 'INSERT' then
    v_actor_id := new.created_by;
  end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values(v_actor_id, v_tenant_id,
      case when tg_op = 'INSERT' then 'scim.mapping.created' else 'scim.mapping.deleted' end,
      jsonb_build_object('external_group_id', v_external_id,
        'role', case when tg_op = 'INSERT' then new.role else old.role end));
  for v_user in
    select distinct sgm.user_id
      from public.scim_groups sg
      join public.scim_group_memberships sgm on sgm.tenant_id = sg.tenant_id and sgm.group_id = sg.id
     where sg.tenant_id = v_tenant_id and sg.external_id = v_external_id
     order by sgm.user_id
  loop
    perform public.scim_reconcile_membership(v_tenant_id, v_user);
  end loop;
  return null;
end;
$$;

revoke all on function public.scim_replace_group_members(uuid, uuid, uuid[], bigint) from public, anon, authenticated;
revoke all on function public.scim_delete_group(uuid, uuid, bigint) from public, anon, authenticated;
revoke all on function app.scim_mapping_reconcile_members() from public, anon, authenticated;
grant execute on function public.scim_replace_group_members(uuid, uuid, uuid[], bigint) to service_role;
grant execute on function public.scim_delete_group(uuid, uuid, bigint) to service_role;
