-- SCIM may manage only memberships it created. team_members mirrors into the
-- canonical tenant_members table, but a manual tenant_members row need not
-- have a matching legacy team_members row.
create or replace function public.scim_reconcile_membership(p_tenant_id uuid, p_scim_user_id uuid)
returns void language plpgsql security definer set search_path = public, pg_catalog as $$
declare
  v_auth_user_id uuid;
  v_active boolean;
  v_role text;
  v_managed boolean;
begin
  select su.auth_user_id, su.active into v_auth_user_id, v_active
    from public.scim_users su
   where su.tenant_id = p_tenant_id and su.id = p_scim_user_id
   for update;
  if not found or v_auth_user_id is null then return; end if;

  select case min(case sgrm.role when 'admin' then 1 when 'member' then 2 else 3 end)
           when 1 then 'admin' when 2 then 'member' when 3 then 'viewer' end
    into v_role
    from public.scim_group_memberships sgm
    join public.scim_groups sg on sg.tenant_id = sgm.tenant_id and sg.id = sgm.group_id
    join public.scim_group_role_mappings sgrm
      on sgrm.tenant_id = sg.tenant_id and sgrm.external_group_id = sg.external_id
   where sgm.tenant_id = p_tenant_id and sgm.user_id = p_scim_user_id;
  if not v_active then v_role := null; end if;

  select exists(select 1 from public.scim_managed_memberships smm
    where smm.tenant_id = p_tenant_id and smm.scim_user_id = p_scim_user_id) into v_managed;

  if v_role is null then
    if v_managed then
      delete from public.team_members where team_id = p_tenant_id and user_id = v_auth_user_id;
      delete from public.scim_managed_memberships where tenant_id = p_tenant_id and scim_user_id = p_scim_user_id;
    end if;
    return;
  end if;

  if not v_managed then
    -- Claim the canonical key first. A read/then-upsert can race a manual
    -- membership insert and silently replace its role through team sync.
    insert into public.tenant_members(tenant_id, user_id, role)
      values(p_tenant_id, v_auth_user_id, v_role) on conflict do nothing;
    if not found then
      raise exception 'scim_cannot_take_over_manual_membership' using errcode = '42501';
    end if;
    insert into public.team_members(team_id, tenant_id, user_id, role)
      values(p_tenant_id, p_tenant_id, v_auth_user_id, v_role);
  else
    update public.team_members set role = v_role
     where team_id = p_tenant_id and user_id = v_auth_user_id;
    if not found then
      raise exception 'scim_managed_membership_missing' using errcode = '42501';
    end if;
  end if;
  insert into public.scim_managed_memberships(tenant_id, scim_user_id, auth_user_id, role)
    values(p_tenant_id, p_scim_user_id, v_auth_user_id, v_role)
  on conflict(tenant_id, scim_user_id) do update
    set role = excluded.role, auth_user_id = excluded.auth_user_id, updated_at = now();
end;
$$;
revoke all on function public.scim_reconcile_membership(uuid, uuid) from public, anon, authenticated;
grant execute on function public.scim_reconcile_membership(uuid, uuid) to service_role;
