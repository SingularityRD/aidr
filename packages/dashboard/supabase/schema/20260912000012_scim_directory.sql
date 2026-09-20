-- Tenant-scoped SCIM v2 provisioning boundary.
-- Raw bearer tokens are never stored. Operators rotate credentials by adding a
-- second hash, moving the IdP to it, and revoking the prior row after overlap.

-- SCIM accounts are created by the service role and receive enterprise access
-- only through the exact group mapping below. Suppress the normal consumer
-- personal-workspace bootstrap for those server-marked accounts.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public, pg_catalog as $$
begin
  if new.raw_app_meta_data ->> 'aidr_scim_provisioned' = 'true' then return new; end if;
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
revoke all on function public.handle_new_user() from public, anon, authenticated;

create or replace function public.handle_new_user_team()
returns trigger language plpgsql security definer set search_path = public, pg_catalog as $$
declare v_team_id uuid := gen_random_uuid();
begin
  if new.raw_app_meta_data ->> 'aidr_scim_provisioned' = 'true' then return new; end if;
  insert into public.tenants (id, name, kind, created_by)
  values (v_team_id, coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), 'Personal'), 'team', new.id);
  insert into public.teams (id, tenant_id, name)
  values (v_team_id, v_team_id, coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), 'Personal'));
  insert into public.team_members (team_id, tenant_id, user_id, role)
  values (v_team_id, v_team_id, new.id, 'owner');
  return new;
end;
$$;
revoke all on function public.handle_new_user_team() from public, anon, authenticated;

create table public.scim_tokens (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  label text not null check (length(trim(label)) between 1 and 120),
  rotated_from uuid,
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  check (expires_at is null or expires_at > created_at),
  unique (tenant_id, id),
  foreign key (tenant_id, rotated_from) references public.scim_tokens(tenant_id, id) on delete restrict
);
create index scim_tokens_tenant_active_idx on public.scim_tokens(tenant_id, expires_at) where revoked_at is null;

create table public.scim_users (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  external_id text,
  user_name text not null check (length(user_name) between 3 and 254),
  normalized_user_name text not null check (normalized_user_name = lower(trim(user_name))),
  auth_user_id uuid references auth.users(id) on delete restrict,
  display_name text,
  active boolean not null default true,
  version bigint not null default 1 check (version > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, id),
  unique (tenant_id, normalized_user_name)
);
create unique index scim_users_tenant_external_id_uniq on public.scim_users(tenant_id, external_id) where external_id is not null;
create unique index scim_users_tenant_auth_user_uniq on public.scim_users(tenant_id, auth_user_id) where auth_user_id is not null;

create table public.scim_groups (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  external_id text not null,
  display_name text not null,
  version bigint not null default 1 check (version > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, id),
  unique (tenant_id, external_id)
);

-- This is the only directory-to-authority bridge. Display names and user
-- metadata never participate in authorization. Owner/support roles are
-- deliberately unavailable to SCIM.
create table public.scim_group_role_mappings (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  external_group_id text not null,
  role text not null check (role in ('admin', 'member', 'viewer')),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (tenant_id, external_group_id)
);

create table public.scim_group_memberships (
  tenant_id uuid not null,
  group_id uuid not null,
  user_id uuid not null,
  created_at timestamptz not null default now(),
  primary key (tenant_id, group_id, user_id),
  foreign key (tenant_id, group_id) references public.scim_groups(tenant_id, id) on delete cascade,
  foreign key (tenant_id, user_id) references public.scim_users(tenant_id, id) on delete cascade
);
create index scim_group_memberships_user_idx on public.scim_group_memberships(tenant_id, user_id);

-- Marks only memberships SCIM is allowed to update/delete. A pre-existing
-- manual membership is protected from directory takeover.
create table public.scim_managed_memberships (
  tenant_id uuid not null,
  scim_user_id uuid not null,
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('admin', 'member', 'viewer')),
  updated_at timestamptz not null default now(),
  primary key (tenant_id, scim_user_id),
  unique (tenant_id, auth_user_id),
  foreign key (tenant_id, scim_user_id) references public.scim_users(tenant_id, id) on delete cascade
);

create or replace function app.scim_mapping_immutable()
returns trigger language plpgsql security definer set search_path = public, pg_catalog as $$
begin
  if new.tenant_id is distinct from old.tenant_id
     or new.external_group_id is distinct from old.external_group_id
     or new.role is distinct from old.role then
    raise exception 'scim_group_role_mapping_is_immutable' using errcode = '22023';
  end if;
  return new;
end;
$$;
revoke all on function app.scim_mapping_immutable() from public, anon, authenticated;
create trigger scim_group_role_mapping_immutable before update on public.scim_group_role_mappings
for each row execute function app.scim_mapping_immutable();

create or replace function public.scim_resolve_token(p_token_hash text)
returns table (tenant_id uuid, token_id uuid)
language plpgsql security definer set search_path = public, pg_catalog as $$
begin
  if p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then return; end if;
  return query
    update public.scim_tokens st set last_used_at = now()
      from public.tenants t
     where st.token_hash = p_token_hash
       and st.revoked_at is null
       and (st.expires_at is null or st.expires_at > now())
       and t.id = st.tenant_id and t.status = 'active'
    returning st.tenant_id, st.id;
end;
$$;

-- Recompute one user's role from exact immutable external group IDs. Similar
-- names have no effect. A missing mapping removes a membership only when SCIM
-- previously created it.
create or replace function public.scim_reconcile_membership(p_tenant_id uuid, p_scim_user_id uuid)
returns void language plpgsql security definer set search_path = public, pg_catalog as $$
declare
  v_auth_user_id uuid;
  v_active boolean;
  v_role text;
  v_managed boolean;
  v_existing_role text;
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
  select tm.role into v_existing_role from public.team_members tm
   where tm.team_id = p_tenant_id and tm.user_id = v_auth_user_id for update;

  if v_role is null then
    if v_managed then
      delete from public.team_members where team_id = p_tenant_id and user_id = v_auth_user_id;
      delete from public.scim_managed_memberships where tenant_id = p_tenant_id and scim_user_id = p_scim_user_id;
    end if;
    return;
  end if;

  if v_existing_role is not null and not v_managed then
    raise exception 'scim_cannot_take_over_manual_membership' using errcode = '42501';
  end if;
  insert into public.team_members(team_id, tenant_id, user_id, role)
    values(p_tenant_id, p_tenant_id, v_auth_user_id, v_role)
  on conflict(team_id, user_id) do update set role = excluded.role;
  insert into public.scim_managed_memberships(tenant_id, scim_user_id, auth_user_id, role)
    values(p_tenant_id, p_scim_user_id, v_auth_user_id, v_role)
  on conflict(tenant_id, scim_user_id) do update
    set role = excluded.role, auth_user_id = excluded.auth_user_id, updated_at = now();
end;
$$;

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
  select array_agg(distinct id) into v_affected from (
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
  select array_agg(user_id) into v_affected from public.scim_group_memberships
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

create or replace function public.scim_claim_user(
  p_tenant_id uuid, p_external_id text, p_user_name text, p_display_name text, p_active boolean
) returns table (user_id uuid, created boolean)
language plpgsql security definer set search_path = public, pg_catalog as $$
declare v_id uuid; v_existing public.scim_users;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || lower(trim(coalesce(p_external_id, p_user_name))), 4812));
  select * into v_existing from public.scim_users su where su.tenant_id = p_tenant_id
    and ((p_external_id is not null and su.external_id = p_external_id) or su.normalized_user_name = lower(trim(p_user_name))) limit 1;
  if found then
    if v_existing.normalized_user_name <> lower(trim(p_user_name))
       or v_existing.external_id is distinct from nullif(trim(p_external_id), '')
       or v_existing.active is distinct from p_active
       or v_existing.display_name is distinct from nullif(trim(p_display_name), '') then
      raise exception 'scim_replay_conflict' using errcode = '23505';
    end if;
    return query select v_existing.id, false;
    return;
  end if;
  insert into public.scim_users(tenant_id, external_id, user_name, normalized_user_name, display_name, active)
    values(p_tenant_id, nullif(trim(p_external_id), ''), lower(trim(p_user_name)), lower(trim(p_user_name)), nullif(trim(p_display_name), ''), p_active)
    returning id into v_id;
  insert into public.admin_audit_logs(tenant_id, action, detail)
    values(p_tenant_id, 'scim.user.claimed', jsonb_build_object('scim_user_id', v_id, 'external_id', nullif(trim(p_external_id), '')));
  return query select v_id, true;
end;
$$;

create or replace function public.scim_bind_user(p_tenant_id uuid, p_scim_user_id uuid, p_auth_user_id uuid)
returns void language plpgsql security definer set search_path = public, pg_catalog as $$
begin
  update public.scim_users set auth_user_id = p_auth_user_id, updated_at = now()
   where tenant_id = p_tenant_id and id = p_scim_user_id
     and (auth_user_id is null or auth_user_id = p_auth_user_id);
  if not found then raise exception 'scim_user_bind_conflict' using errcode = '23505'; end if;
  perform public.scim_reconcile_membership(p_tenant_id, p_scim_user_id);
  insert into public.admin_audit_logs(tenant_id, target_user_id, action, detail)
    values(p_tenant_id, p_auth_user_id, 'scim.user.bound', jsonb_build_object('scim_user_id', p_scim_user_id));
end;
$$;

create or replace function public.scim_update_user(
  p_tenant_id uuid, p_scim_user_id uuid, p_display_name text, p_active boolean, p_expected_version bigint default null
) returns boolean language plpgsql security definer set search_path = public, pg_catalog as $$
declare v_current bigint; v_auth_user_id uuid; v_new_version bigint;
begin
  select version, auth_user_id into v_current, v_auth_user_id from public.scim_users where tenant_id = p_tenant_id and id = p_scim_user_id for update;
  if not found then return false; end if;
  if p_expected_version is not null and p_expected_version <> v_current then
    raise exception 'scim_version_mismatch' using errcode = '40001';
  end if;
  update public.scim_users set display_name = nullif(trim(p_display_name), ''), active = p_active,
    version = version + 1, updated_at = now()
   where tenant_id = p_tenant_id and id = p_scim_user_id returning version into v_new_version;
  perform public.scim_reconcile_membership(p_tenant_id, p_scim_user_id);
  insert into public.admin_audit_logs(tenant_id, target_user_id, action, detail)
    values(p_tenant_id, v_auth_user_id, 'scim.user.updated', jsonb_build_object('scim_user_id', p_scim_user_id, 'active', p_active, 'version', v_new_version));
  return true;
end;
$$;

create or replace function public.scim_create_group(
  p_tenant_id uuid, p_external_id text, p_display_name text, p_user_ids uuid[]
) returns table (group_id uuid, created boolean)
language plpgsql security definer set search_path = public, pg_catalog as $$
declare v_group public.scim_groups; v_existing_users uuid[];
begin
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || trim(p_external_id), 4912));
  select * into v_group from public.scim_groups where tenant_id = p_tenant_id and external_id = trim(p_external_id);
  if found then
    select coalesce(array_agg(user_id order by user_id), array[]::uuid[]) into v_existing_users
      from public.scim_group_memberships where tenant_id = p_tenant_id and group_id = v_group.id;
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

create or replace function public.scim_update_group(
  p_tenant_id uuid, p_group_id uuid, p_display_name text, p_user_ids uuid[], p_expected_version bigint default null
) returns boolean language plpgsql security definer set search_path = public, pg_catalog as $$
begin
  if nullif(trim(p_display_name), '') is null then raise exception 'scim_invalid_display_name' using errcode = '22023'; end if;
  if not exists(select 1 from public.scim_groups where tenant_id = p_tenant_id and id = p_group_id) then return false; end if;
  perform public.scim_replace_group_members(p_tenant_id, p_group_id, p_user_ids, p_expected_version);
  update public.scim_groups set display_name = trim(p_display_name) where tenant_id = p_tenant_id and id = p_group_id;
  insert into public.admin_audit_logs(tenant_id, action, detail)
    values(p_tenant_id, 'scim.group.updated', jsonb_build_object('scim_group_id', p_group_id));
  return true;
end;
$$;

-- Provisioning or removing an allowlist mapping takes effect immediately for
-- already-synchronized groups. This is also the revocation path when an
-- operator removes a mapping.
create or replace function app.scim_mapping_reconcile_members()
returns trigger language plpgsql security definer set search_path = public, pg_catalog as $$
declare v_tenant_id uuid;
        v_external_id text;
        v_user uuid;
begin
  if tg_op = 'DELETE' then
    v_tenant_id := old.tenant_id;
    v_external_id := old.external_group_id;
  else
    v_tenant_id := new.tenant_id;
    v_external_id := new.external_group_id;
  end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values(case when tg_op = 'INSERT' then new.created_by else null end, v_tenant_id,
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
revoke all on function app.scim_mapping_reconcile_members() from public, anon, authenticated;
create trigger scim_group_role_mapping_reconcile after insert or delete on public.scim_group_role_mappings
for each row execute function app.scim_mapping_reconcile_members();

-- These resources are service-only. There are intentionally no authenticated
-- policies: neither a browser user nor mutable IdP metadata is an authority.
alter table public.scim_tokens enable row level security;
alter table public.scim_users enable row level security;
alter table public.scim_groups enable row level security;
alter table public.scim_group_role_mappings enable row level security;
alter table public.scim_group_memberships enable row level security;
alter table public.scim_managed_memberships enable row level security;

revoke all on public.scim_tokens, public.scim_users, public.scim_groups,
  public.scim_group_role_mappings, public.scim_group_memberships,
  public.scim_managed_memberships from public, anon, authenticated;
grant all on public.scim_tokens, public.scim_users, public.scim_groups,
  public.scim_group_role_mappings, public.scim_group_memberships,
  public.scim_managed_memberships to service_role;

revoke all on function public.scim_resolve_token(text) from public, anon, authenticated;
revoke all on function public.scim_reconcile_membership(uuid, uuid) from public, anon, authenticated;
revoke all on function public.scim_replace_group_members(uuid, uuid, uuid[], bigint) from public, anon, authenticated;
revoke all on function public.scim_delete_group(uuid, uuid, bigint) from public, anon, authenticated;
revoke all on function public.scim_claim_user(uuid, text, text, text, boolean) from public, anon, authenticated;
revoke all on function public.scim_bind_user(uuid, uuid, uuid) from public, anon, authenticated;
revoke all on function public.scim_update_user(uuid, uuid, text, boolean, bigint) from public, anon, authenticated;
revoke all on function public.scim_create_group(uuid, text, text, uuid[]) from public, anon, authenticated;
revoke all on function public.scim_update_group(uuid, uuid, text, uuid[], bigint) from public, anon, authenticated;
grant execute on function public.scim_resolve_token(text) to service_role;
grant execute on function public.scim_reconcile_membership(uuid, uuid) to service_role;
grant execute on function public.scim_replace_group_members(uuid, uuid, uuid[], bigint) to service_role;
grant execute on function public.scim_delete_group(uuid, uuid, bigint) to service_role;
grant execute on function public.scim_claim_user(uuid, text, text, text, boolean) to service_role;
grant execute on function public.scim_bind_user(uuid, uuid, uuid) to service_role;
grant execute on function public.scim_update_user(uuid, uuid, text, boolean, bigint) to service_role;
grant execute on function public.scim_create_group(uuid, text, text, uuid[]) to service_role;
grant execute on function public.scim_update_group(uuid, uuid, text, uuid[], bigint) to service_role;
