-- Tenant/auth isolation hardening for enrollment and SCIM provisioning.
create or replace function public.resolve_enrollment_token(p_token_hash text)
returns jsonb
language plpgsql security definer set search_path = public, pg_catalog as $$
declare v_token public.enrollment_tokens%rowtype;
begin
  if p_token_hash is null or p_token_hash !~ '^[a-f0-9]{64}$' then return null; end if;
  select * into v_token from public.enrollment_tokens where token_hash = p_token_hash;
  if not found or v_token.consumed_at is not null or v_token.expires_at <= now() then return null; end if;
  if not exists (select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = v_token.tenant_id and m.user_id = v_token.user_id
      and (m.expires_at is null or m.expires_at > now()) and t.status = 'active') then return null; end if;
  return jsonb_build_object('tenant_id', v_token.tenant_id, 'user_id', v_token.user_id);
end;
$$;
revoke all on function public.resolve_enrollment_token(text) from public, anon, authenticated;
grant execute on function public.resolve_enrollment_token(text) to service_role;

create or replace function public.scim_user_id_by_email(p_tenant_id uuid, p_email text)
returns uuid language sql security definer set search_path = public, auth, pg_catalog as $$
  select u.id from auth.users u
  join public.tenant_members m on m.user_id = u.id and m.tenant_id = p_tenant_id
  join public.tenants t on t.id = m.tenant_id and t.status = 'active'
  where lower(u.email) = lower(p_email)
    and (m.expires_at is null or m.expires_at > now())
  limit 1;
$$;
revoke all on function public.scim_user_id_by_email(uuid, text) from public, anon, authenticated;
grant execute on function public.scim_user_id_by_email(uuid, text) to service_role;

-- Defense in depth: SCIM must never bind an auth identity outside the token tenant.
create or replace function public.scim_bind_user(p_tenant_id uuid, p_scim_user_id uuid, p_auth_user_id uuid)
returns void language plpgsql security definer set search_path = public, pg_catalog as $$
begin
  -- A just-created auth user has no membership yet; allow that case, but
  -- reject identities already belonging to a different tenant.
  if exists (select 1 from public.tenant_members m where m.user_id = p_auth_user_id
    and m.tenant_id <> p_tenant_id) then
    raise exception 'scim_user_tenant_mismatch' using errcode = '42501';
  end if;
  if exists (select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_auth_user_id
      and (m.expires_at is null or m.expires_at > now()) and t.status = 'active') is false
     and exists (select 1 from public.tenant_members m where m.user_id = p_auth_user_id) then
    raise exception 'scim_user_tenant_mismatch' using errcode = '42501';
  end if;
  update public.scim_users set auth_user_id = p_auth_user_id, updated_at = now()
   where tenant_id = p_tenant_id and id = p_scim_user_id
     and (auth_user_id is null or auth_user_id = p_auth_user_id);
  if not found then raise exception 'scim_user_bind_conflict' using errcode = '23505'; end if;
  perform public.scim_reconcile_membership(p_tenant_id, p_scim_user_id);
  insert into public.admin_audit_logs(tenant_id, target_user_id, action, detail)
    values(p_tenant_id, p_auth_user_id, 'scim.user.bound', jsonb_build_object('scim_user_id', p_scim_user_id));
end;
$$;
revoke all on function public.scim_bind_user(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.scim_bind_user(uuid, uuid, uuid) to service_role;
