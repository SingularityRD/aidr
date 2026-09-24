-- Tenant-owner-only bootstrap for the inbound SCIM directory integration.
-- Raw provisioning tokens remain in the response exactly once; only SHA-256
-- hashes are persisted, and token/mapping changes are audited transactionally.

create or replace function app.scim_assert_tenant_owner(p_tenant_id uuid, p_actor_user_id uuid)
returns void
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
begin
  if not exists (
    select 1
      from public.tenants t
      join public.tenant_members tm on tm.tenant_id = t.id
     where t.id = p_tenant_id
       and t.status = 'active'
       and tm.user_id = p_actor_user_id
       and tm.role = 'owner'
       and (tm.expires_at is null or tm.expires_at > now())
  ) then
    raise exception 'scim_admin_owner_required' using errcode = '42501';
  end if;
end;
$$;

create or replace function public.scim_admin_create_token(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_token_hash text,
  p_label text,
  p_expires_at timestamptz,
  p_rotated_from_id uuid default null
) returns uuid
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare v_token_id uuid;
begin
  perform app.scim_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  if p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_label is null or p_label <> trim(p_label)
     or length(p_label) not between 1 and 120
     or p_label ~ '[[:cntrl:]]'
     or (p_expires_at is not null and p_expires_at <= now()) then
    raise exception 'scim_admin_invalid_token' using errcode = '22023';
  end if;
  if p_rotated_from_id is not null and not exists (
    select 1 from public.scim_tokens st
     where st.tenant_id = p_tenant_id and st.id = p_rotated_from_id
       and st.revoked_at is null and (st.expires_at is null or st.expires_at > now())
  ) then
    raise exception 'scim_admin_rotation_parent_unavailable' using errcode = 'P0002';
  end if;

  insert into public.scim_tokens(tenant_id, token_hash, label, expires_at, rotated_from)
    values (p_tenant_id, p_token_hash, p_label, p_expires_at, p_rotated_from_id)
    returning id into v_token_id;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (p_actor_user_id, p_tenant_id,
      case when p_rotated_from_id is null then 'scim.token.created' else 'scim.token.rotated' end,
      jsonb_build_object('token_id', v_token_id, 'rotated_from', p_rotated_from_id, 'expires_at', p_expires_at));
  return v_token_id;
end;
$$;

create or replace function public.scim_admin_revoke_token(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_token_id uuid
) returns boolean
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare v_changed uuid;
begin
  perform app.scim_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  update public.scim_tokens set revoked_at = now()
   where tenant_id = p_tenant_id and id = p_token_id and revoked_at is null
   returning id into v_changed;
  if v_changed is null then return false; end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (p_actor_user_id, p_tenant_id, 'scim.token.revoked', jsonb_build_object('token_id', v_changed));
  return true;
end;
$$;

-- Mapping updates replace the immutable row inside one transaction. The
-- existing reconciliation trigger removes a managed grant before applying a
-- changed role, and rolls the whole transaction back if a manual membership
-- would be taken over.
create or replace function public.scim_admin_set_group_role_mapping(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_external_group_id text,
  p_role text
) returns boolean
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare v_current_role text;
begin
  perform app.scim_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  if p_external_group_id is null or p_external_group_id <> trim(p_external_group_id)
     or length(p_external_group_id) not between 1 and 255
     or p_external_group_id ~ '[[:cntrl:]]'
     or p_role is null
     or p_role not in ('admin', 'member', 'viewer') then
    raise exception 'scim_admin_invalid_mapping' using errcode = '22023';
  end if;
  perform set_config('aidr.scim_actor_user_id', p_actor_user_id::text, true);
  select role into v_current_role from public.scim_group_role_mappings
   where tenant_id = p_tenant_id and external_group_id = p_external_group_id;
  if found and v_current_role = p_role then return false; end if;
  delete from public.scim_group_role_mappings
   where tenant_id = p_tenant_id and external_group_id = p_external_group_id;
  insert into public.scim_group_role_mappings(tenant_id, external_group_id, role, created_by)
    values (p_tenant_id, p_external_group_id, p_role, p_actor_user_id);
  return true;
end;
$$;

create or replace function public.scim_admin_remove_group_role_mapping(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_external_group_id text
) returns boolean
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare v_deleted text;
begin
  perform app.scim_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  if p_external_group_id is null or p_external_group_id <> trim(p_external_group_id)
     or length(p_external_group_id) not between 1 and 255
     or p_external_group_id ~ '[[:cntrl:]]' then
    raise exception 'scim_admin_invalid_mapping' using errcode = '22023';
  end if;
  perform set_config('aidr.scim_actor_user_id', p_actor_user_id::text, true);
  delete from public.scim_group_role_mappings
   where tenant_id = p_tenant_id and external_group_id = p_external_group_id
   returning external_group_id into v_deleted;
  return v_deleted is not null;
end;
$$;

-- Preserve the actual owner actor on mapping deletion (the old row's creator
-- may be a different operator).
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
  loop
    perform public.scim_reconcile_membership(v_tenant_id, v_user);
  end loop;
  return null;
end;
$$;
revoke all on function app.scim_assert_tenant_owner(uuid, uuid) from public, anon, authenticated;
revoke all on function app.scim_mapping_reconcile_members() from public, anon, authenticated;
revoke all on function public.scim_admin_create_token(uuid, uuid, text, text, timestamptz, uuid) from public, anon, authenticated;
revoke all on function public.scim_admin_revoke_token(uuid, uuid, uuid) from public, anon, authenticated;
revoke all on function public.scim_admin_set_group_role_mapping(uuid, uuid, text, text) from public, anon, authenticated;
revoke all on function public.scim_admin_remove_group_role_mapping(uuid, uuid, text) from public, anon, authenticated;
grant execute on function app.scim_assert_tenant_owner(uuid, uuid) to service_role;
grant execute on function public.scim_admin_create_token(uuid, uuid, text, text, timestamptz, uuid) to service_role;
grant execute on function public.scim_admin_revoke_token(uuid, uuid, uuid) to service_role;
grant execute on function public.scim_admin_set_group_role_mapping(uuid, uuid, text, text) to service_role;
grant execute on function public.scim_admin_remove_group_role_mapping(uuid, uuid, text) to service_role;
