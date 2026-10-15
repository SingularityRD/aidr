-- Just-in-time (JIT) OIDC provisioning for tenants without SCIM.
--
-- On-prem customers often run Active Directory behind Keycloak or ADFS and have
-- no SCIM client. Until now an OIDC login could only reach tenant data when SCIM
-- had pre-created the user (docs/production-readiness/oidc-sso-admin.md). This
-- migration adds an opt-in, per-tenant JIT path:
--
--   * public.oidc_jit_policies: one row per tenant OIDC provider. Off by default.
--     It pins the issuer it was configured for (a provider whose issuer changed
--     stops provisioning until an owner re-saves the policy), the email domains
--     allowed to provision (each must also be a DNS-verified domain of the same
--     tenant at login time) and an optional default role (member or viewer,
--     never admin or owner).
--   * public.oidc_jit_group_role_mappings: exact, case-sensitive group claim
--     values (Keycloak group path, ADFS group name/SID, Entra object id) mapped
--     to admin/member/viewer. The most privileged matching group wins; owner is
--     never granted.
--   * public.oidc_jit_memberships: which memberships JIT created, so later
--     logins can raise, lower or remove the role from the IdP's current groups
--     without ever touching a manual, invited or SCIM-managed membership. A row
--     whose membership an administrator removed in AIDR is kept as "removed":
--     the user is not silently re-added at the next login; an owner re-admits
--     them explicitly.
--   * public.oidc_jit_provision: the only writer at login. Service role only,
--     called by the oidc-sso Edge function after the ID token was verified. It
--     re-checks every precondition in one transaction under the tenant locks and
--     writes its own admin audit row for every membership change.
--   * public.oidc_save_jit_policy / public.oidc_jit_readmit: owner-only,
--     audited administration (the Edge function adds AAL2 and plan gating).
--
-- Precedence and safety:
--   * SCIM stays authoritative: a subject that SCIM provisioned (active or not)
--     is never JIT-provisioned. An active, unbound SCIM user with the same
--     external id is bound through the existing public.scim_bind_user path.
--   * JIT is refused while the tenant runs directory-authoritative membership
--     (20261007000050): that mode admits only SCIM memberships by design.
--   * All new tables are service-role read only (RLS on, no policies, no
--     browser grants); writes happen only inside the definer functions below.
--   * Tenant lifecycle: the tables carry app.protect_oidc_tenant_write, and they
--     cascade from oidc_providers, so the existing offboarding phase that
--     deletes providers removes them too.

-- Composite key so every JIT row provably belongs to its provider's tenant.
alter table public.oidc_providers
  add constraint oidc_providers_id_tenant_unique unique (id, tenant_id);

create table public.oidc_jit_policies (
  provider_id uuid primary key,
  tenant_id uuid not null unique references public.tenants(id) on delete cascade,
  enabled boolean not null default false,
  issuer text not null check (issuer ~ '^https://[^\s?#@]+$' and length(issuer) <= 512),
  allowed_domains text[] not null default array[]::text[]
    check (cardinality(allowed_domains) <= 50),
  default_role text check (default_role is null or default_role in ('member', 'viewer')),
  updated_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (provider_id, tenant_id) references public.oidc_providers(id, tenant_id) on delete cascade,
  check (not enabled or cardinality(allowed_domains) >= 1)
);
create trigger oidc_jit_policies_touch_updated_at
before update on public.oidc_jit_policies
for each row execute procedure public.touch_updated_at();

create table public.oidc_jit_group_role_mappings (
  provider_id uuid not null,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  group_value text not null
    check (length(group_value) between 1 and 256 and group_value !~ '[[:cntrl:]]'),
  role text not null check (role in ('admin', 'member', 'viewer')),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (provider_id, group_value),
  foreign key (provider_id, tenant_id) references public.oidc_providers(id, tenant_id) on delete cascade
);

create table public.oidc_jit_memberships (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  provider_id uuid not null,
  subject text not null check (length(subject) between 1 and 255),
  role text check (role is null or role in ('admin', 'member', 'viewer')),
  provisioned_at timestamptz not null default now(),
  last_synced_at timestamptz not null default now(),
  removed_at timestamptz,
  primary key (tenant_id, auth_user_id),
  unique (provider_id, subject),
  foreign key (provider_id, tenant_id) references public.oidc_providers(id, tenant_id) on delete cascade,
  -- Active rows carry the role JIT granted; removed rows carry none.
  check ((removed_at is null) = (role is not null))
);

alter table public.oidc_jit_policies enable row level security;
alter table public.oidc_jit_group_role_mappings enable row level security;
alter table public.oidc_jit_memberships enable row level security;
revoke all on public.oidc_jit_policies, public.oidc_jit_group_role_mappings, public.oidc_jit_memberships
  from public, anon, authenticated, service_role;
-- The Edge function reads configuration with the service role; every write goes
-- through the audited definer functions below.
grant select on public.oidc_jit_policies, public.oidc_jit_group_role_mappings, public.oidc_jit_memberships
  to service_role;
-- Tenant identity barrier (as on every RLS tenant table): no current access path
-- uses it, but it keeps the tables closed if a later grant exposes them.
create policy tenant_identity_access_restrict on public.oidc_jit_policies as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id)) with check (public.tenant_identity_access_allowed(tenant_id));
create policy tenant_identity_access_restrict on public.oidc_jit_group_role_mappings as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id)) with check (public.tenant_identity_access_allowed(tenant_id));
create policy tenant_identity_access_restrict on public.oidc_jit_memberships as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id)) with check (public.tenant_identity_access_allowed(tenant_id));

do $$
declare v_table text;
begin
  foreach v_table in array array['oidc_jit_policies', 'oidc_jit_group_role_mappings', 'oidc_jit_memberships'] loop
    execute format('create trigger oidc_tenant_write_guard before insert or update on public.%I '
      || 'for each row execute function app.protect_oidc_tenant_write()', v_table);
  end loop;
end;
$$;

-- An administrator removing a JIT member in AIDR must stick: mark the JIT row
-- removed instead of letting the next login re-create the membership. Skipped
-- while the tenant is closing (offboarding deletes members first and the write
-- guard would refuse the update; the provider cascade removes the rows).
create function app.oidc_jit_mark_member_removed()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  if exists (select 1 from public.tenants t where t.id = old.tenant_id and t.status = 'active')
     and not exists (select 1 from public.tenant_offboarding_runs r where r.tenant_id = old.tenant_id) then
    update public.oidc_jit_memberships
       set role = null, removed_at = now(), last_synced_at = now()
     where tenant_id = old.tenant_id and auth_user_id = old.user_id and removed_at is null;
  end if;
  return old;
end;
$$;
revoke all on function app.oidc_jit_mark_member_removed() from public, anon, authenticated, service_role;
create trigger tenant_members_oidc_jit_removed after delete on public.tenant_members
for each row execute function app.oidc_jit_mark_member_removed();

-- Login-time provisioning. Returns {"status": ..., "role": ...}. Statuses:
--   provisioned | updated | unchanged          JIT membership is in place
--   manual_membership | scim_managed | scim_bound   another source owns access
--   disabled | tenant_inactive | domain_not_allowed | directory_authoritative |
--   scim_inactive | scim_conflict | removed_by_admin | other_tenant |
--   groups_unevaluable | no_role | revoked      no JIT access (login is denied)
-- Raises only for malformed calls or an identity that does not match.
create function public.oidc_jit_provision(
  p_provider_id uuid,
  p_auth_user_id uuid,
  p_subject text,
  p_email_domain text,
  p_groups text[],
  p_groups_evaluable boolean,
  p_request_id text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_tenant uuid;
  v_issuer text;
  v_policy public.oidc_jit_policies;
  v_domain text := lower(btrim(coalesce(p_email_domain, '')));
  v_scim_id uuid;
  v_scim_bound uuid;
  v_scim_active boolean;
  v_jit public.oidc_jit_memberships;
  v_has_jit boolean;
  v_current text;
  v_role text;
  v_matched text[];
  v_source text;
  v_detail jsonb;
begin
  if p_provider_id is null or p_auth_user_id is null or p_groups_evaluable is null
     or p_subject is null or length(p_subject) not between 1 and 255
     or v_domain = '' or (p_groups is not null and cardinality(p_groups) > 1000)
     or (p_request_id is not null and length(p_request_id) > 128) then
    raise exception 'invalid_oidc_jit_request' using errcode = '22023';
  end if;

  select tenant_id into v_tenant from public.oidc_providers where id = p_provider_id;
  if v_tenant is null then return jsonb_build_object('status', 'disabled'); end if;
  -- Lifecycle lock first (the order the OIDC write guard and offboarding use),
  -- then the tenant binding lock shared with SCIM binding.
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  perform 1 from public.tenants where id = v_tenant and status = 'active' for share;
  if not found or exists (select 1 from public.tenant_offboarding_runs r where r.tenant_id = v_tenant) then
    return jsonb_build_object('status', 'tenant_inactive');
  end if;
  select issuer into v_issuer from public.oidc_providers
   where id = p_provider_id and tenant_id = v_tenant and enabled for share;
  if v_issuer is null then return jsonb_build_object('status', 'disabled'); end if;
  select * into v_policy from public.oidc_jit_policies where provider_id = p_provider_id for share;
  if not found or not v_policy.enabled or v_policy.issuer <> v_issuer then
    return jsonb_build_object('status', 'disabled');
  end if;

  -- The Auth user must be exactly this provider-qualified subject.
  if not exists (
    select 1 from public.oidc_identities i
     where i.provider_id = p_provider_id and i.subject = p_subject
       and i.auth_user_id = p_auth_user_id and i.tenant_id = v_tenant
  ) then
    raise exception 'oidc_jit_identity_mismatch' using errcode = '42501';
  end if;

  if not (v_domain = any (v_policy.allowed_domains)) or not exists (
    select 1 from public.oidc_tenant_domains d
     where d.tenant_id = v_tenant and d.domain = v_domain and d.verified_at is not null
  ) then
    return jsonb_build_object('status', 'domain_not_allowed');
  end if;

  if exists (select 1 from public.tenant_directory_authority a where a.tenant_id = v_tenant and a.enabled) then
    return jsonb_build_object('status', 'directory_authoritative');
  end if;

  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2607));

  select * into v_jit from public.oidc_jit_memberships
   where tenant_id = v_tenant and auth_user_id = p_auth_user_id for update;
  v_has_jit := found;

  -- SCIM precedence: a subject SCIM knows is never JIT-managed.
  select su.id, su.auth_user_id, su.active into v_scim_id, v_scim_bound, v_scim_active
    from public.scim_users su
   where su.tenant_id = v_tenant and su.external_id = p_subject
   for update;
  if v_scim_id is not null then
    if not v_scim_active then return jsonb_build_object('status', 'scim_inactive'); end if;
    if v_scim_bound = p_auth_user_id then return jsonb_build_object('status', 'scim_managed'); end if;
    if v_scim_bound is not null or position('@' in p_subject) > 0 then
      return jsonb_build_object('status', 'scim_conflict');
    end if;
    if v_has_jit then
      -- SCIM now provisions this person: hand the membership over. Drop the JIT
      -- row first so the removal marker does not fire, then let SCIM recreate
      -- the membership from its own groups.
      delete from public.oidc_jit_memberships where tenant_id = v_tenant and auth_user_id = p_auth_user_id;
      delete from public.team_members where team_id = v_tenant and user_id = p_auth_user_id and role <> 'owner';
      insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
      values (p_auth_user_id, v_tenant, p_auth_user_id, 'identity.oidc.jit_handed_to_scim',
              jsonb_build_object('provider_id', p_provider_id, 'scim_user_id', v_scim_id, 'request_id', p_request_id));
    end if;
    perform public.scim_bind_user(v_tenant, v_scim_id, p_auth_user_id);
    return jsonb_build_object('status', 'scim_bound');
  end if;

  if v_has_jit and v_jit.removed_at is not null then
    return jsonb_build_object('status', 'removed_by_admin');
  end if;

  select m.role into v_current from public.tenant_members m
   where m.tenant_id = v_tenant and m.user_id = p_auth_user_id for update;
  if not v_has_jit and v_current is not null then
    return jsonb_build_object('status', 'manual_membership', 'role', v_current);
  end if;
  if v_has_jit and v_current is null then
    -- Membership vanished without the removal marker (should not happen): treat
    -- it as an administrator removal rather than silently re-adding it.
    update public.oidc_jit_memberships set role = null, removed_at = now(), last_synced_at = now()
     where tenant_id = v_tenant and auth_user_id = p_auth_user_id;
    return jsonb_build_object('status', 'removed_by_admin');
  end if;
  if v_has_jit and v_current = 'owner' then
    -- An owner promoted this member on purpose; JIT never manages owners.
    delete from public.oidc_jit_memberships where tenant_id = v_tenant and auth_user_id = p_auth_user_id;
    insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values (p_auth_user_id, v_tenant, p_auth_user_id, 'identity.oidc.jit_membership_released',
            jsonb_build_object('provider_id', p_provider_id, 'role', v_current, 'request_id', p_request_id));
    return jsonb_build_object('status', 'manual_membership', 'role', v_current);
  end if;
  if exists (select 1 from public.tenant_members m where m.user_id = p_auth_user_id and m.tenant_id <> v_tenant) then
    return jsonb_build_object('status', 'other_tenant');
  end if;
  if not p_groups_evaluable then
    -- Fail closed without changing anything: the IdP did not say which groups apply.
    return jsonb_build_object('status', 'groups_unevaluable');
  end if;

  select case min(case g.role when 'admin' then 1 when 'member' then 2 else 3 end)
           when 1 then 'admin' when 2 then 'member' when 3 then 'viewer' end,
         array_agg(g.group_value order by g.group_value)
    into v_role, v_matched
    from public.oidc_jit_group_role_mappings g
   where g.provider_id = p_provider_id and g.group_value = any (coalesce(p_groups, array[]::text[]));
  v_source := case when v_role is not null then 'group' else 'default' end;
  v_role := coalesce(v_role, v_policy.default_role);
  v_detail := jsonb_build_object(
    'provider_id', p_provider_id, 'role', v_role, 'source', v_source,
    'matched_groups', coalesce(to_jsonb(v_matched[1:20]), '[]'::jsonb),
    'email_domain', v_domain, 'request_id', p_request_id);

  if v_role is null then
    if v_has_jit then
      delete from public.oidc_jit_memberships where tenant_id = v_tenant and auth_user_id = p_auth_user_id;
      delete from public.team_members where team_id = v_tenant and user_id = p_auth_user_id;
      insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
      values (p_auth_user_id, v_tenant, p_auth_user_id, 'identity.oidc.jit_membership_revoked',
              v_detail || jsonb_build_object('previous_role', v_current));
      return jsonb_build_object('status', 'revoked');
    end if;
    return jsonb_build_object('status', 'no_role');
  end if;

  if not v_has_jit then
    -- Claim the canonical membership key first (same pattern as the SCIM
    -- reconciler) so a concurrent manual insert is never overwritten.
    insert into public.tenant_members(tenant_id, user_id, role)
    values (v_tenant, p_auth_user_id, v_role) on conflict do nothing;
    if not found then raise exception 'oidc_jit_membership_conflict' using errcode = '40001'; end if;
    insert into public.team_members(team_id, tenant_id, user_id, role)
    values (v_tenant, v_tenant, p_auth_user_id, v_role);
    insert into public.oidc_jit_memberships(tenant_id, auth_user_id, provider_id, subject, role)
    values (v_tenant, p_auth_user_id, p_provider_id, p_subject, v_role);
    insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values (p_auth_user_id, v_tenant, p_auth_user_id, 'identity.oidc.jit_provisioned', v_detail);
    return jsonb_build_object('status', 'provisioned', 'role', v_role);
  end if;

  if v_current is distinct from v_role then
    update public.team_members set role = v_role where team_id = v_tenant and user_id = p_auth_user_id;
    if not found then raise exception 'oidc_jit_membership_missing' using errcode = '42501'; end if;
    update public.oidc_jit_memberships set role = v_role, last_synced_at = now()
     where tenant_id = v_tenant and auth_user_id = p_auth_user_id;
    insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values (p_auth_user_id, v_tenant, p_auth_user_id, 'identity.oidc.jit_role_changed',
            v_detail || jsonb_build_object('previous_role', v_current));
    return jsonb_build_object('status', 'updated', 'role', v_role);
  end if;
  update public.oidc_jit_memberships set last_synced_at = now()
   where tenant_id = v_tenant and auth_user_id = p_auth_user_id;
  return jsonb_build_object('status', 'unchanged', 'role', v_role);
end;
$$;
revoke all on function public.oidc_jit_provision(uuid, uuid, text, text, text[], boolean, text)
  from public, anon, authenticated;
grant execute on function public.oidc_jit_provision(uuid, uuid, text, text, text[], boolean, text) to service_role;

-- Owner administration: policy and mappings are replaced together with the
-- audit row, after re-checking the actor is a live owner of an active tenant.
create function public.oidc_save_jit_policy(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_provider_id uuid,
  p_enabled boolean,
  p_allowed_domains text[],
  p_default_role text,
  p_mappings jsonb,
  p_request_id text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_issuer text;
  v_domains text[];
  v_previous public.oidc_jit_policies;
  v_mapping jsonb;
  v_count integer := 0;
begin
  if p_actor_user_id is null or p_tenant_id is null or p_provider_id is null or p_enabled is null
     or p_mappings is null or jsonb_typeof(p_mappings) <> 'array' or jsonb_array_length(p_mappings) > 100
     or (p_default_role is not null and p_default_role not in ('member', 'viewer'))
     or (p_allowed_domains is not null and cardinality(p_allowed_domains) > 50)
     or (p_request_id is not null and length(p_request_id) > 128) then
    raise exception 'invalid_oidc_jit_policy' using errcode = '22023';
  end if;
  select coalesce(array_agg(distinct lower(btrim(d)) order by lower(btrim(d))), array[]::text[])
    into v_domains from unnest(coalesce(p_allowed_domains, array[]::text[])) d;
  if exists (select 1 from unnest(v_domains) d
             where d !~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') then
    raise exception 'invalid_oidc_jit_policy' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  perform 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > clock_timestamp()) and t.status = 'active'
   for share of m, t;
  if not found then raise exception 'oidc_jit_forbidden' using errcode = '42501'; end if;
  select issuer into v_issuer from public.oidc_providers
   where id = p_provider_id and tenant_id = p_tenant_id for share;
  if v_issuer is null then raise exception 'oidc_jit_provider_missing' using errcode = '42501'; end if;

  if p_enabled then
    if cardinality(v_domains) = 0 then
      raise exception 'oidc_jit_domain_required' using errcode = '22023';
    end if;
    if exists (
      select 1 from unnest(v_domains) d
       where not exists (select 1 from public.oidc_tenant_domains td
                          where td.tenant_id = p_tenant_id and td.domain = d and td.verified_at is not null)
    ) then
      raise exception 'oidc_jit_domain_not_verified' using errcode = '22023';
    end if;
    if exists (select 1 from public.tenant_directory_authority a where a.tenant_id = p_tenant_id and a.enabled) then
      raise exception 'oidc_jit_directory_authoritative' using errcode = '42501';
    end if;
  end if;

  select * into v_previous from public.oidc_jit_policies where provider_id = p_provider_id for update;
  insert into public.oidc_jit_policies as p
    (provider_id, tenant_id, enabled, issuer, allowed_domains, default_role, updated_by)
  values (p_provider_id, p_tenant_id, p_enabled, v_issuer, v_domains, p_default_role, p_actor_user_id)
  on conflict (provider_id) do update set
    enabled = excluded.enabled, issuer = excluded.issuer, allowed_domains = excluded.allowed_domains,
    default_role = excluded.default_role, updated_by = excluded.updated_by
  where p.tenant_id = excluded.tenant_id;
  if not found then raise exception 'oidc_jit_forbidden' using errcode = '42501'; end if;

  delete from public.oidc_jit_group_role_mappings where provider_id = p_provider_id;
  for v_mapping in select value from jsonb_array_elements(p_mappings) loop
    if jsonb_typeof(v_mapping) <> 'object' or jsonb_typeof(v_mapping -> 'group') <> 'string'
       or (v_mapping ->> 'role') is null or (v_mapping ->> 'role') not in ('admin', 'member', 'viewer') then
      raise exception 'invalid_oidc_jit_policy' using errcode = '22023';
    end if;
    insert into public.oidc_jit_group_role_mappings(provider_id, tenant_id, group_value, role, created_by)
    values (p_provider_id, p_tenant_id, v_mapping ->> 'group', v_mapping ->> 'role', p_actor_user_id);
    v_count := v_count + 1;
  end loop;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_actor_user_id, p_tenant_id, null, 'identity.oidc.jit_policy_updated', jsonb_build_object(
    'provider_id', p_provider_id, 'enabled', p_enabled, 'previous_enabled', coalesce(v_previous.enabled, false),
    'issuer', v_issuer, 'allowed_domains', to_jsonb(v_domains), 'default_role', p_default_role,
    'mapping_count', v_count,
    'mappings', (select coalesce(jsonb_agg(jsonb_build_object('group', g.group_value, 'role', g.role)
                   order by g.group_value), '[]'::jsonb)
                  from public.oidc_jit_group_role_mappings g where g.provider_id = p_provider_id),
    'request_id', p_request_id));
  return jsonb_build_object('enabled', p_enabled, 'mapping_count', v_count);
end;
$$;
revoke all on function public.oidc_save_jit_policy(uuid, uuid, uuid, boolean, text[], text, jsonb, text)
  from public, anon, authenticated;
grant execute on function public.oidc_save_jit_policy(uuid, uuid, uuid, boolean, text[], text, jsonb, text)
  to service_role;

-- Re-admit a JIT user an administrator removed: the next login provisions them
-- again from their current groups.
create function public.oidc_jit_readmit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_user_id uuid,
  p_request_id text
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if p_actor_user_id is null or p_tenant_id is null or p_user_id is null
     or (p_request_id is not null and length(p_request_id) > 128) then
    raise exception 'invalid_oidc_jit_request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  perform 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > clock_timestamp()) and t.status = 'active'
   for share of m, t;
  if not found then raise exception 'oidc_jit_forbidden' using errcode = '42501'; end if;
  delete from public.oidc_jit_memberships
   where tenant_id = p_tenant_id and auth_user_id = p_user_id and removed_at is not null;
  if not found then raise exception 'oidc_jit_member_not_removed' using errcode = '22023'; end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_actor_user_id, p_tenant_id, p_user_id, 'identity.oidc.jit_readmitted',
          jsonb_build_object('request_id', p_request_id));
end;
$$;
revoke all on function public.oidc_jit_readmit(uuid, uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.oidc_jit_readmit(uuid, uuid, uuid, text) to service_role;

-- Extra authorization-request scopes from a fixed allow-list. ADFS puts custom
-- claims such as group membership into the ID token only when the client asks
-- for `allatclaims`; Okta's org server needs `groups`; Keycloak can expose
-- realm roles through a `roles` client scope. Nothing else can be requested,
-- and the default (no extra scope) is unchanged.
alter table public.oidc_providers
  add column extra_scopes text[] not null default array[]::text[]
    check (extra_scopes <@ array['allatclaims', 'groups', 'roles']::text[] and cardinality(extra_scopes) <= 3);

-- The enforcement lock covers the new column like every other sign-in setting.
create or replace function app.guard_oidc_provider_configuration()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if row(new.issuer, new.client_id, new.client_secret_ref, new.token_auth_method,
         new.allowed_algs, new.subject_claim, new.groups_claim, new.groups_mode,
         new.session_max_seconds, new.clock_skew_seconds, new.enabled, new.extra_scopes)
     is not distinct from
     row(old.issuer, old.client_id, old.client_secret_ref, old.token_auth_method,
         old.allowed_algs, old.subject_claim, old.groups_claim, old.groups_mode,
         old.session_max_seconds, old.clock_skew_seconds, old.enabled, old.extra_scopes) then
    return new; -- Login timestamps and refreshed discovery do not change identity configuration.
  end if;
  perform pg_advisory_xact_lock(hashtextextended(old.tenant_id::text, 2607));
  if exists (select 1 from public.tenant_identity_policies
             where tenant_id = old.tenant_id and required_oidc_provider_id = old.id) then
    raise exception 'oidc_provider_locked_by_enforcement' using errcode = '55000';
  end if;
  if row(new.issuer, new.client_id, new.subject_claim)
     is distinct from row(old.issuer, old.client_id, old.subject_claim)
     and exists (select 1 from public.oidc_identities where provider_id = old.id) then
    raise exception 'oidc_provider_identity_namespace_locked' using errcode = '55000';
  end if;
  return new;
end;
$$;
revoke all on function app.guard_oidc_provider_configuration() from public, anon, authenticated;

-- 20261010000120 public.oidc_save_provider, unchanged except that it writes
-- extra_scopes (an omitted value means none).
create or replace function public.oidc_save_provider(
  p_actor_user_id uuid,
  p_provider jsonb,
  p_audit_action text,
  p_audit_detail jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_row public.oidc_providers;
  v_existing_tenant uuid;
begin
  if p_actor_user_id is null or p_provider is null or jsonb_typeof(p_provider) <> 'object'
     or p_audit_action is null
     or p_audit_action not in ('identity.oidc.provider_updated', 'identity.oidc.discovery_refreshed')
     or (p_audit_detail is not null and jsonb_typeof(p_audit_detail) <> 'object') then
    raise exception 'invalid_oidc_provider_request' using errcode = '22023';
  end if;
  v_row := jsonb_populate_record(null::public.oidc_providers, p_provider);
  if v_row.id is null or v_row.tenant_id is null then
    raise exception 'invalid_oidc_provider_request' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(v_row.tenant_id::text, 2606));
  perform 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = v_row.tenant_id
     and m.user_id = p_actor_user_id
     and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m, t;
  if not found then
    raise exception 'oidc_provider_forbidden' using errcode = '42501';
  end if;
  select tenant_id into v_existing_tenant from public.oidc_providers where id = v_row.id;
  if found and v_existing_tenant <> v_row.tenant_id then
    raise exception 'oidc_provider_forbidden' using errcode = '42501';
  end if;

  insert into public.oidc_providers as p (
    id, tenant_id, kind, display_name, issuer, client_id, client_secret_ref,
    token_auth_method, allowed_algs, subject_claim, groups_claim, groups_mode,
    session_max_seconds, clock_skew_seconds, discovery, discovery_fetched_at,
    enabled, created_by, extra_scopes
  ) values (
    v_row.id, v_row.tenant_id, v_row.kind, v_row.display_name, v_row.issuer,
    v_row.client_id, v_row.client_secret_ref, v_row.token_auth_method,
    v_row.allowed_algs, v_row.subject_claim, v_row.groups_claim, v_row.groups_mode,
    v_row.session_max_seconds, v_row.clock_skew_seconds, v_row.discovery,
    case when v_row.discovery is not null then now() end,
    coalesce(v_row.enabled, false), p_actor_user_id,
    coalesce(v_row.extra_scopes, array[]::text[])
  )
  on conflict (id) do update set
    kind = excluded.kind,
    display_name = excluded.display_name,
    issuer = excluded.issuer,
    client_id = excluded.client_id,
    client_secret_ref = excluded.client_secret_ref,
    token_auth_method = excluded.token_auth_method,
    allowed_algs = excluded.allowed_algs,
    subject_claim = excluded.subject_claim,
    groups_claim = excluded.groups_claim,
    groups_mode = excluded.groups_mode,
    session_max_seconds = excluded.session_max_seconds,
    clock_skew_seconds = excluded.clock_skew_seconds,
    discovery = excluded.discovery,
    discovery_fetched_at = excluded.discovery_fetched_at,
    enabled = excluded.enabled,
    extra_scopes = excluded.extra_scopes
  where p.tenant_id = excluded.tenant_id;
  if not found then
    raise exception 'oidc_provider_forbidden' using errcode = '42501';
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_actor_user_id, v_row.tenant_id, null, p_audit_action,
          coalesce(p_audit_detail, '{}'::jsonb) || jsonb_build_object('provider_id', v_row.id));

  return jsonb_build_object('provider_id', v_row.id, 'tenant_id', v_row.tenant_id,
                            'enabled', coalesce(v_row.enabled, false));
end;
$$;

revoke all on function public.oidc_save_provider(uuid, jsonb, text, jsonb)
  from public, anon, authenticated;
grant execute on function public.oidc_save_provider(uuid, jsonb, text, jsonb) to service_role;
