-- A TABLE-returning function exposes group_id as a PL/pgSQL variable. Qualify
-- the replay query's table column so existing SCIM groups can be replayed.
create or replace function public.scim_create_group(
  p_tenant_id uuid, p_external_id text, p_display_name text, p_user_ids uuid[]
) returns table (group_id uuid, created boolean)
language plpgsql security definer set search_path = public, pg_catalog as $$
declare v_group public.scim_groups; v_existing_users uuid[];
begin
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || trim(p_external_id), 4912));
  select * into v_group from public.scim_groups where tenant_id = p_tenant_id and external_id = trim(p_external_id);
  if found then
    select coalesce(array_agg(gm.user_id order by gm.user_id), array[]::uuid[]) into v_existing_users
      from public.scim_group_memberships gm where gm.tenant_id = p_tenant_id and gm.group_id = v_group.id;
    if v_group.display_name <> trim(p_display_name)
       or v_existing_users <> (select coalesce(array_agg(id order by id), array[]::uuid[]) from unnest(coalesce(p_user_ids, array[]::uuid[])) ids(id)) then
      raise exception 'scim_replay_conflict' using errcode = '23505';
    end if;
    return query select v_group.id, false;
    return;
  end if;
  if exists(select 1 from unnest(coalesce(p_user_ids, array[]::uuid[])) requested(id)
    where not exists(select 1 from public.scim_users su where su.tenant_id = p_tenant_id and su.id = requested.id)) then
    raise exception 'scim_cross_tenant_or_unknown_user' using errcode = '22023';
  end if;
  insert into public.scim_groups(tenant_id, external_id, display_name)
    values(p_tenant_id, trim(p_external_id), trim(p_display_name)) returning * into v_group;
  if coalesce(array_length(p_user_ids, 1), 0) > 0 then
    perform public.scim_replace_group_members(p_tenant_id, v_group.id, p_user_ids, 1);
  end if;
  insert into public.admin_audit_logs(tenant_id, action, detail)
    values(p_tenant_id, 'scim.group.created', jsonb_build_object('scim_group_id', v_group.id, 'external_id', trim(p_external_id)));
  return query select v_group.id, true;
end;
$$;
