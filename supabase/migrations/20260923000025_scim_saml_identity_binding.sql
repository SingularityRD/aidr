-- SAML users have a separate Auth UUID from SCIM preprovisioned/email users.
-- Grant no enterprise access until a verified provider-qualified subject binds.
create unique index tenant_identity_policies_saml_provider_unique
  on public.tenant_identity_policies(required_saml_provider_id)
  where required_saml_provider_id is not null;

-- Supabase Auth marks the provider before auth.users is inserted. Do not give
-- new SAML accounts a consumer workspace while SCIM authorization is pending.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public, pg_catalog as $$
begin
  if new.raw_app_meta_data ->> 'aidr_scim_provisioned' = 'true'
     or new.raw_app_meta_data ->> 'provider' like 'sso:%' then return new; end if;
  insert into public.tenants (id, name, kind, created_by)
  values (new.id, coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), 'Personal'), 'personal', new.id)
  on conflict (id) do nothing;
  insert into public.tenant_members (tenant_id, user_id, role)
  values (new.id, new.id, 'owner') on conflict (tenant_id, user_id) do nothing;
  insert into public.entitlements (user_id, tenant_id)
  values (new.id, new.id) on conflict (tenant_id) do nothing;
  return new;
end;
$$;

create or replace function public.handle_new_user_team()
returns trigger language plpgsql security definer set search_path = public, pg_catalog as $$
declare v_team_id uuid := gen_random_uuid();
begin
  if new.raw_app_meta_data ->> 'aidr_scim_provisioned' = 'true'
     or new.raw_app_meta_data ->> 'provider' like 'sso:%' then return new; end if;
  insert into public.tenants (id, name, kind, created_by)
  values (v_team_id, coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), 'Personal'), 'team', new.id);
  insert into public.teams (id, tenant_id, name)
  values (v_team_id, v_team_id, coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), 'Personal'));
  insert into public.team_members (team_id, tenant_id, user_id, role)
  values (v_team_id, v_team_id, new.id, 'owner');
  return new;
end;
$$;
revoke all on function public.handle_new_user() from public, anon, authenticated;
revoke all on function public.handle_new_user_team() from public, anon, authenticated;

-- A provider cannot be activated over a prior email-bound SCIM account.
create or replace function app.scim_saml_policy_guard()
returns trigger language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp as $$
begin
  if new.required_saml_provider_id is null then return new; end if;
  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 2607));
  if exists (
    select 1 from public.scim_users su
    where su.tenant_id = new.tenant_id and su.auth_user_id is not null
      and not exists (
        select 1 from auth.identities i
        where i.user_id = su.auth_user_id
          and i.provider = 'sso:' || new.required_saml_provider_id::text
          and i.provider_id = su.external_id
          and i.identity_data ->> 'sub' = i.provider_id
          and position('@' in i.provider_id) = 0
      )
  ) then raise exception 'scim_saml_existing_identity_conflict' using errcode = '23505'; end if;
  return new;
end;
$$;
revoke all on function app.scim_saml_policy_guard() from public, anon, authenticated;
create trigger scim_saml_policy_guard
before insert or update of required_saml_provider_id on public.tenant_identity_policies
for each row execute function app.scim_saml_policy_guard();

-- Close the race between the SCIM Edge policy read and provider activation.
create or replace function public.scim_bind_user(p_tenant_id uuid, p_scim_user_id uuid, p_auth_user_id uuid)
returns void language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp as $$
declare v_provider_id uuid;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2607));
  select required_saml_provider_id into v_provider_id from public.tenant_identity_policies
    where tenant_id = p_tenant_id;
  if v_provider_id is not null and not exists (
    select 1 from public.scim_users su join auth.identities i
      on i.user_id = p_auth_user_id
     and i.provider = 'sso:' || v_provider_id::text
     and i.provider_id = su.external_id
     and i.identity_data ->> 'sub' = i.provider_id
    where su.tenant_id = p_tenant_id and su.id = p_scim_user_id
      and su.active and position('@' in i.provider_id) = 0
  ) then raise exception 'scim_saml_identity_mismatch' using errcode = '42501'; end if;
  if v_provider_id is not null and exists (
    select 1 from public.tenant_members m
    where m.tenant_id = p_tenant_id and m.user_id = p_auth_user_id
      and not exists (
        select 1 from public.scim_managed_memberships smm
        where smm.tenant_id = p_tenant_id and smm.scim_user_id = p_scim_user_id
          and smm.auth_user_id = p_auth_user_id
      )
  ) then raise exception 'scim_cannot_take_over_manual_membership' using errcode = '42501'; end if;
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

create or replace function public.scim_bind_saml_identity(p_auth_user_id uuid, p_provider_id uuid)
returns uuid language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp as $$
declare
  v_tenant_id uuid;
  v_subject text;
  v_identity_count integer;
  v_scim_user_id uuid;
  v_bound_user_id uuid;
begin
  if p_auth_user_id is null or p_provider_id is null then return null; end if;
  select p.tenant_id into v_tenant_id
    from public.tenant_identity_policies p join public.tenants t on t.id = p.tenant_id
   where p.required_saml_provider_id = p_provider_id and t.status = 'active';
  if v_tenant_id is null then return null; end if;
  select min(i.provider_id), count(*) into v_subject, v_identity_count
    from auth.identities i
   where i.user_id = p_auth_user_id and i.provider = 'sso:' || p_provider_id::text
     and i.identity_data ->> 'sub' = i.provider_id;
  if v_identity_count <> 1 or v_subject is null or v_subject = ''
     or position('@' in v_subject) > 0 then return null; end if;
  select su.id, su.auth_user_id into v_scim_user_id, v_bound_user_id
    from public.scim_users su
   where su.tenant_id = v_tenant_id and su.external_id = v_subject and su.active
   for update;
  if v_scim_user_id is null then return null; end if;
  if v_bound_user_id is not null and v_bound_user_id <> p_auth_user_id then
    raise exception 'scim_saml_identity_conflict' using errcode = '23505';
  end if;
  if v_bound_user_id is null then
    perform public.scim_bind_user(v_tenant_id, v_scim_user_id, p_auth_user_id);
  end if;
  return v_tenant_id;
end;
$$;
revoke all on function public.scim_bind_saml_identity(uuid, uuid) from public, anon, authenticated;
grant execute on function public.scim_bind_saml_identity(uuid, uuid) to service_role;
