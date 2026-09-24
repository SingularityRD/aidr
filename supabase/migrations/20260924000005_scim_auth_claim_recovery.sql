-- Recover a SCIM-created Auth account if the Auth write committed but its
-- following SCIM bind RPC failed. Email alone must never claim another tenant's
-- account: recovery is pinned to server-owned tenant and SCIM resource markers.
create or replace function public.scim_recover_unbound_auth_user(
  p_tenant_id uuid, p_scim_user_id uuid, p_email text
) returns uuid
language plpgsql security definer set search_path = pg_catalog, public, auth as $$
declare v_user_ids uuid[];
begin
  if p_tenant_id is null or p_scim_user_id is null or p_email is null or nullif(trim(p_email), '') is null then
    return null;
  end if;
  select array_agg(candidate.id order by candidate.id) into v_user_ids
    from (
      select u.id
        from auth.users u
        join public.scim_users su on su.tenant_id = p_tenant_id and su.id = p_scim_user_id
       where su.auth_user_id is null
         and su.normalized_user_name = lower(trim(p_email))
         and lower(u.email) = lower(trim(p_email))
         and u.raw_app_meta_data ->> 'aidr_scim_provisioned' = 'true'
         and u.raw_app_meta_data ->> 'aidr_scim_tenant_id' = p_tenant_id::text
         and u.raw_app_meta_data ->> 'aidr_scim_user_id' = p_scim_user_id::text
         and not exists (select 1 from public.scim_users bound where bound.auth_user_id = u.id)
         and not exists (select 1 from public.tenant_members tm where tm.user_id = u.id)
       limit 2
    ) candidate;
  if coalesce(cardinality(v_user_ids), 0) <> 1 then return null; end if;
  return v_user_ids[1];
end;
$$;

revoke all on function public.scim_recover_unbound_auth_user(uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.scim_recover_unbound_auth_user(uuid, uuid, text) to service_role;
