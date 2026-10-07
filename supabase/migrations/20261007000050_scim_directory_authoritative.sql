-- TEN-04: tenant-level "directory-authoritative" membership mode.
--
-- Off by default; existing tenants keep their current behaviour. When an
-- owner enables it for one SCIM directory:
--  * every scim_tokens row records the directory it provisions for. Only that
--    directory's credentials resolve, and no other directory's credential can
--    be issued while the mode is on;
--  * a tenant membership grants access only when it is backed by an active
--    SCIM-managed membership stamped with the configured directory and the
--    same role, or the member is a designated break-glass owner;
--  * the invariant is enforced on write by deferred constraint triggers on
--    tenant_members and every SCIM row that backs it. Readers that consult
--    tenant_members directly (definer RPCs and service-role Edge Functions)
--    therefore observe it too. app.is_tenant_member* re-check it on read.
--
-- Break-glass: SCIM can never grant owner, so every owner is a manual
-- membership. Enabling requires the caller to name every active owner (one or
-- two) as a break-glass account; they keep access through any directory
-- outage or mass deprovisioning, the designation is audited, and the last one
-- cannot be removed, demoted or deleted while the mode is on. Owners are never
-- removed by enabling: owner changes stay on the existing audited owner path.

-- 1. Credential provenance ---------------------------------------------------
alter table public.scim_tokens add column directory_id text;
alter table public.scim_tokens add constraint scim_tokens_directory_id_format
  check (directory_id is null or directory_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$');
create index scim_tokens_tenant_directory_idx on public.scim_tokens(tenant_id, directory_id)
  where revoked_at is null;

-- Pre-existing rows stay NULL (provenance unknown). Every new credential must
-- name its directory, and a recorded directory is immutable.
create function app.scim_token_directory_guard()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  if tg_op = 'INSERT' and new.directory_id is null then
    raise exception 'scim_token_directory_required' using errcode = '23514';
  end if;
  if tg_op = 'UPDATE' and new.directory_id is distinct from old.directory_id then
    raise exception 'scim_token_directory_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.scim_token_directory_guard() from public, anon, authenticated, service_role;
create trigger scim_tokens_directory_guard before insert or update of directory_id on public.scim_tokens
for each row execute function app.scim_token_directory_guard();

-- 2. Tenant setting and break-glass owners ----------------------------------
create table public.tenant_directory_authority (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  enabled boolean not null default false,
  directory_id text check (directory_id is null or directory_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  changed_by uuid references auth.users(id) on delete set null,
  changed_at timestamptz not null default now(),
  check (not enabled or directory_id is not null)
);
create table public.tenant_directory_break_glass_owners (
  tenant_id uuid not null references public.tenant_directory_authority(tenant_id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  designated_by uuid references auth.users(id) on delete set null,
  designated_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);
alter table public.tenant_directory_authority enable row level security;
alter table public.tenant_directory_break_glass_owners enable row level security;
-- Writes only through the audited definer RPCs below.
revoke all on public.tenant_directory_authority, public.tenant_directory_break_glass_owners
  from public, anon, authenticated, service_role;
grant select on public.tenant_directory_authority, public.tenant_directory_break_glass_owners to service_role;

-- 3. Managed-membership provenance ------------------------------------------
-- A SCIM write is stamped with the tenant's authoritative directory, or NULL
-- while the mode is off (any credential could have produced it). Only the
-- configured directory's credentials resolve while the mode is on, so a stamp
-- always names the directory that provisioned the row.
alter table public.scim_managed_memberships add column directory_id text;
alter table public.scim_managed_memberships add constraint scim_managed_memberships_directory_id_format
  check (directory_id is null or directory_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$');

create function app.scim_managed_membership_stamp_directory()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
declare v_directory text;
begin
  select a.directory_id into v_directory from public.tenant_directory_authority a
   where a.tenant_id = new.tenant_id and a.enabled;
  new.directory_id := v_directory;
  return new;
end;
$$;
revoke all on function app.scim_managed_membership_stamp_directory() from public, anon, authenticated, service_role;
create trigger scim_managed_memberships_stamp_directory before insert or update on public.scim_managed_memberships
for each row execute function app.scim_managed_membership_stamp_directory();

-- 4. Membership resolution ---------------------------------------------------
create function app.directory_authority_member_qualifies(p_tenant_id uuid, p_user_id uuid, p_role text)
returns boolean language sql stable security definer
set search_path = pg_catalog, public, pg_temp as $$
  select exists (
      select 1 from public.tenant_directory_break_glass_owners b
       where b.tenant_id = p_tenant_id and b.user_id = p_user_id and p_role = 'owner'
    ) or exists (
      select 1
        from public.tenant_directory_authority a
        join public.scim_managed_memberships smm on smm.tenant_id = a.tenant_id
        join public.scim_users su on su.tenant_id = smm.tenant_id and su.id = smm.scim_user_id
       where a.tenant_id = p_tenant_id and a.enabled
         and smm.auth_user_id = p_user_id and smm.role = p_role
         and smm.directory_id = a.directory_id
         and su.active and su.auth_user_id = p_user_id
    );
$$;
revoke all on function app.directory_authority_member_qualifies(uuid, uuid, text) from public, anon, authenticated, service_role;

create function app.directory_membership_grants(p_tenant_id uuid, p_user_id uuid, p_role text)
returns boolean language sql stable security definer
set search_path = pg_catalog, public, pg_temp as $$
  select not exists (
      select 1 from public.tenant_directory_authority a where a.tenant_id = p_tenant_id and a.enabled
    ) or app.directory_authority_member_qualifies(p_tenant_id, p_user_id, p_role);
$$;
revoke all on function app.directory_membership_grants(uuid, uuid, text) from public, anon, authenticated, service_role;

-- RLS helpers: same semantics as 20260912000019, plus the directory check.
create or replace function app.is_tenant_member(p_tenant_id uuid)
returns boolean language sql stable security definer
set search_path = public, pg_catalog, pg_temp as $$
  select exists (
    select 1
    from public.tenant_members tm
    join public.tenants t on t.id = tm.tenant_id
    where tm.tenant_id = p_tenant_id
      and tm.user_id = auth.uid()
      and (tm.expires_at is null or tm.expires_at > now())
      and t.status = 'active'
      and app.directory_membership_grants(tm.tenant_id, tm.user_id, tm.role)
  );
$$;

create or replace function app.is_tenant_member_with_role(p_tenant_id uuid, p_min_role text)
returns boolean language sql stable security definer
set search_path = public, pg_catalog, pg_temp as $$
  select exists (
    select 1
    from public.tenant_members tm
    join public.tenants t on t.id = tm.tenant_id
    where tm.tenant_id = p_tenant_id
      and tm.user_id = auth.uid()
      and (tm.expires_at is null or tm.expires_at > now())
      and t.status = 'active'
      and tm.role = any (
        case p_min_role
          when 'owner' then array['owner']
          when 'admin' then array['owner', 'admin']
          when 'member' then array['owner', 'admin', 'member']
          when 'viewer' then array['owner', 'admin', 'member', 'viewer']
          else array[]::text[]
        end
      )
      and app.directory_membership_grants(tm.tenant_id, tm.user_id, tm.role)
  );
$$;

-- 5. Write-time invariant ----------------------------------------------------
-- Offboarding deletes members, SCIM rows and break-glass rows in phase order;
-- the invariant no longer applies once a run exists or the tenant is closing.
create function app.directory_authority_enforced(p_tenant_id uuid)
returns boolean language sql stable security definer
set search_path = pg_catalog, public, pg_temp as $$
  select exists (
    select 1 from public.tenant_directory_authority a
    join public.tenants t on t.id = a.tenant_id
    where a.tenant_id = p_tenant_id and a.enabled
      and t.status in ('active', 'suspended')
      and not exists (select 1 from public.tenant_offboarding_runs r where r.tenant_id = a.tenant_id)
  );
$$;
revoke all on function app.directory_authority_enforced(uuid) from public, anon, authenticated, service_role;

create function app.directory_authority_assert(p_tenant_id uuid, p_user_id uuid)
returns void language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
declare v_role text;
begin
  if p_tenant_id is null or not app.directory_authority_enforced(p_tenant_id) then return; end if;
  if p_user_id is not null then
    select tm.role into v_role from public.tenant_members tm
     where tm.tenant_id = p_tenant_id and tm.user_id = p_user_id
       and (tm.expires_at is null or tm.expires_at > clock_timestamp());
    if found and not app.directory_authority_member_qualifies(p_tenant_id, p_user_id, v_role) then
      raise exception 'directory_authority_membership_required' using errcode = '42501';
    end if;
  end if;
  if not exists (
    select 1 from public.tenant_directory_break_glass_owners b
    join public.tenant_members tm on tm.tenant_id = b.tenant_id and tm.user_id = b.user_id
    where b.tenant_id = p_tenant_id and tm.role = 'owner'
      and (tm.expires_at is null or tm.expires_at > clock_timestamp())
  ) then
    raise exception 'directory_authority_break_glass_owner_required' using errcode = '42501';
  end if;
end;
$$;
revoke all on function app.directory_authority_assert(uuid, uuid) from public, anon, authenticated, service_role;

create function app.directory_authority_assert_tenant(p_tenant_id uuid)
returns void language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  if p_tenant_id is null or not app.directory_authority_enforced(p_tenant_id) then return; end if;
  if exists (
    select 1 from public.tenant_members tm
    where tm.tenant_id = p_tenant_id
      and (tm.expires_at is null or tm.expires_at > clock_timestamp())
      and not app.directory_authority_member_qualifies(tm.tenant_id, tm.user_id, tm.role)
  ) then
    raise exception 'directory_authority_membership_required' using errcode = '42501';
  end if;
  perform app.directory_authority_assert(p_tenant_id, null);
end;
$$;
revoke all on function app.directory_authority_assert_tenant(uuid) from public, anon, authenticated, service_role;

-- Deferred to commit so one SCIM reconciliation (tenant_members, team_members
-- and scim_managed_memberships in the same transaction) is judged as a whole.
-- The check re-reads current state, so later statements in the transaction
-- are covered too.
create function app.directory_authority_guard()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  if tg_table_name = 'tenant_members' then
    if tg_op <> 'DELETE' then perform app.directory_authority_assert(new.tenant_id, new.user_id); end if;
    if tg_op <> 'INSERT' then perform app.directory_authority_assert(old.tenant_id, old.user_id); end if;
  elsif tg_table_name = 'scim_managed_memberships' then
    if tg_op <> 'DELETE' then perform app.directory_authority_assert(new.tenant_id, new.auth_user_id); end if;
    if tg_op <> 'INSERT' then perform app.directory_authority_assert(old.tenant_id, old.auth_user_id); end if;
  elsif tg_table_name = 'scim_users' then
    perform app.directory_authority_assert(new.tenant_id, new.auth_user_id);
    perform app.directory_authority_assert(old.tenant_id, old.auth_user_id);
  elsif tg_table_name = 'tenant_directory_break_glass_owners' then
    perform app.directory_authority_assert(old.tenant_id, old.user_id);
  elsif tg_table_name = 'tenant_directory_authority' then
    perform app.directory_authority_assert_tenant(new.tenant_id);
  else
    raise exception 'directory authority guard attached to unsupported table' using errcode = '55000';
  end if;
  return null;
end;
$$;
revoke all on function app.directory_authority_guard() from public, anon, authenticated, service_role;

create constraint trigger tenant_members_directory_authority
after insert or update or delete on public.tenant_members
deferrable initially deferred for each row execute function app.directory_authority_guard();
create constraint trigger scim_managed_memberships_directory_authority
after update or delete on public.scim_managed_memberships
deferrable initially deferred for each row execute function app.directory_authority_guard();
create constraint trigger scim_users_directory_authority
after update of active, auth_user_id on public.scim_users
deferrable initially deferred for each row execute function app.directory_authority_guard();
create constraint trigger break_glass_owners_directory_authority
after delete on public.tenant_directory_break_glass_owners
deferrable initially deferred for each row execute function app.directory_authority_guard();
create constraint trigger tenant_directory_authority_invariant
after insert or update on public.tenant_directory_authority
deferrable initially deferred for each row execute function app.directory_authority_guard();

-- 6. Credential resolution and issuance -------------------------------------
create or replace function public.scim_resolve_token(p_token_hash text)
returns table (tenant_id uuid, token_id uuid)
language plpgsql security definer set search_path = public, pg_catalog, pg_temp as $$
begin
  if p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then return; end if;
  return query
    update public.scim_tokens st set last_used_at = now()
      from public.tenants t
     where st.token_hash = p_token_hash
       and st.revoked_at is null
       and (st.expires_at is null or st.expires_at > now())
       and t.id = st.tenant_id and t.status = 'active'
       and not exists (
         select 1 from public.tenant_directory_authority a
          where a.tenant_id = st.tenant_id and a.enabled
            and a.directory_id is distinct from st.directory_id
       )
    returning st.tenant_id, st.id;
end;
$$;
revoke all on function public.scim_resolve_token(text) from public, anon, authenticated;
grant execute on function public.scim_resolve_token(text) to service_role;

-- Same contract as 20260923000018 plus the directory binding. A rotation
-- inherits its parent's directory; a legacy (NULL) parent must be bound
-- explicitly by the rotation.
drop function public.scim_admin_create_token(uuid, uuid, text, text, timestamptz, uuid);
create function public.scim_admin_create_token(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_token_hash text,
  p_label text,
  p_expires_at timestamptz,
  p_rotated_from_id uuid,
  p_directory_id text
) returns uuid
language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
declare
  v_token_id uuid;
  v_now timestamptz := clock_timestamp();
  v_expires_at timestamptz := coalesce(p_expires_at, v_now + interval '90 days');
  v_parent_directory text;
  v_directory text;
  v_authoritative text;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2641));
  perform app.scim_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  if p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_label is null or p_label <> trim(p_label)
     or length(p_label) not between 1 and 120
     or p_label ~ '[[:cntrl:]]'
     or v_expires_at <= v_now
     or v_expires_at > v_now + interval '365 days'
     or (p_directory_id is not null and p_directory_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') then
    raise exception 'scim_admin_invalid_token' using errcode = '22023';
  end if;
  if p_rotated_from_id is not null then
    select st.directory_id into v_parent_directory from public.scim_tokens st
     where st.tenant_id = p_tenant_id and st.id = p_rotated_from_id
       and st.revoked_at is null and (st.expires_at is null or st.expires_at > v_now);
    if not found then
      raise exception 'scim_admin_rotation_parent_unavailable' using errcode = 'P0002';
    end if;
    if v_parent_directory is not null and p_directory_id is not null
       and p_directory_id <> v_parent_directory then
      raise exception 'scim_admin_directory_mismatch' using errcode = '22023';
    end if;
  end if;
  v_directory := coalesce(p_directory_id, v_parent_directory);
  if v_directory is null then
    raise exception 'scim_admin_directory_required' using errcode = '22023';
  end if;
  select a.directory_id into v_authoritative from public.tenant_directory_authority a
   where a.tenant_id = p_tenant_id and a.enabled;
  if found and v_authoritative <> v_directory then
    raise exception 'scim_admin_directory_not_authoritative' using errcode = '42501';
  end if;

  insert into public.scim_tokens(tenant_id, token_hash, label, expires_at, rotated_from, directory_id)
    values (p_tenant_id, p_token_hash, p_label, v_expires_at, p_rotated_from_id, v_directory)
    returning id into v_token_id;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (p_actor_user_id, p_tenant_id,
      case when p_rotated_from_id is null then 'scim.token.created' else 'scim.token.rotated' end,
      jsonb_build_object('token_id', v_token_id, 'rotated_from', p_rotated_from_id,
        'expires_at', v_expires_at, 'directory_id', v_directory));
  return v_token_id;
end;
$$;
revoke all on function public.scim_admin_create_token(uuid, uuid, text, text, timestamptz, uuid, text) from public, anon, authenticated;
grant execute on function public.scim_admin_create_token(uuid, uuid, text, text, timestamptz, uuid, text) to service_role;

-- 7. Audited administration --------------------------------------------------
create function public.scim_admin_enable_directory_authority(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_directory_id text,
  p_break_glass_user_ids uuid[],
  p_adopt_existing boolean,
  p_remove_unmanaged boolean
) returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, auth, pg_temp as $$
declare
  v_tenant public.tenants;
  v_break_glass uuid[];
  v_owners uuid[];
  v_unmanaged uuid[];
  v_user uuid;
  v_adopted bigint := 0;
  v_legacy bigint;
  v_audit bigint;
begin
  if p_tenant_id is null or p_actor_user_id is null
     or p_directory_id is null or p_directory_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
     or p_break_glass_user_ids is null or p_adopt_existing is null or p_remove_unmanaged is null then
    raise exception 'directory_authority_invalid_request' using errcode = '22023';
  end if;
  select coalesce(array_agg(distinct u order by u), array[]::uuid[]) into v_break_glass
    from unnest(p_break_glass_user_ids) u where u is not null;
  if cardinality(v_break_glass) not between 1 and 2
     or cardinality(v_break_glass) <> cardinality(p_break_glass_user_ids) then
    raise exception 'directory_authority_break_glass_invalid' using errcode = '22023';
  end if;

  -- 2606 serializes with offboarding/legal holds; 2641 with credential issuance.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2641));
  perform app.scim_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  select * into v_tenant from public.tenants where id = p_tenant_id for share;
  if not found or v_tenant.kind = 'personal' or v_tenant.status <> 'active'
     or exists (select 1 from public.tenant_offboarding_runs r where r.tenant_id = p_tenant_id) then
    raise exception 'directory_authority_tenant_unsupported' using errcode = '42501';
  end if;
  if exists (select 1 from public.tenant_directory_authority a where a.tenant_id = p_tenant_id and a.enabled) then
    raise exception 'directory_authority_already_enabled' using errcode = '55000';
  end if;

  -- Exactly the configured directory may hold live credentials.
  if not exists (
    select 1 from public.scim_tokens st
     where st.tenant_id = p_tenant_id and st.directory_id = p_directory_id
       and st.revoked_at is null and (st.expires_at is null or st.expires_at > clock_timestamp())
  ) then
    raise exception 'directory_authority_directory_token_required' using errcode = '55000';
  end if;
  if exists (
    select 1 from public.scim_tokens st
     where st.tenant_id = p_tenant_id and st.directory_id is distinct from p_directory_id
       and st.revoked_at is null and (st.expires_at is null or st.expires_at > clock_timestamp())
  ) then
    raise exception 'directory_authority_foreign_token_active' using errcode = '55000';
  end if;
  -- Adoption asserts that existing SCIM-managed rows came from this directory.
  -- Refuse it when any credential of another known directory ever existed.
  if p_adopt_existing and exists (
    select 1 from public.scim_tokens st
     where st.tenant_id = p_tenant_id and st.directory_id is not null and st.directory_id <> p_directory_id
  ) then
    raise exception 'directory_authority_adoption_ambiguous' using errcode = '55000';
  end if;
  select count(*) into v_legacy from public.scim_tokens st
   where st.tenant_id = p_tenant_id and st.directory_id is null;

  -- Break-glass accounts are exactly the active owners. Enabling never
  -- removes an owner; owner changes use the audited owner path first.
  select coalesce(array_agg(tm.user_id order by tm.user_id), array[]::uuid[]) into v_owners
    from public.tenant_members tm
   where tm.tenant_id = p_tenant_id and tm.role = 'owner'
     and (tm.expires_at is null or tm.expires_at > clock_timestamp());
  if cardinality(v_owners) = 0 then
    raise exception 'directory_authority_would_remove_all_administrators' using errcode = '55000';
  end if;
  if v_owners <> v_break_glass then
    raise exception 'directory_authority_break_glass_mismatch' using errcode = '55000',
      detail = cardinality(v_owners)::text;
  end if;
  if exists (
    select 1 from unnest(v_break_glass) b(user_id)
     where exists (select 1 from public.scim_managed_memberships s
                    where s.tenant_id = p_tenant_id and s.auth_user_id = b.user_id)
        or not exists (select 1 from auth.users u where u.id = b.user_id
                        and (to_jsonb(u)->>'deleted_at') is null
                        and coalesce((to_jsonb(u)->>'banned_until')::timestamptz, to_timestamp(0)) <= clock_timestamp())
  ) then
    raise exception 'directory_authority_break_glass_invalid' using errcode = '42501';
  end if;

  insert into public.tenant_directory_authority(tenant_id, enabled, directory_id, changed_by, changed_at)
    values (p_tenant_id, true, p_directory_id, p_actor_user_id, clock_timestamp())
  on conflict (tenant_id) do update
    set enabled = true, directory_id = excluded.directory_id,
        changed_by = excluded.changed_by, changed_at = excluded.changed_at;
  delete from public.tenant_directory_break_glass_owners where tenant_id = p_tenant_id;
  insert into public.tenant_directory_break_glass_owners(tenant_id, user_id, designated_by)
    select p_tenant_id, u, p_actor_user_id from unnest(v_break_glass) u;
  if p_adopt_existing then
    -- The stamp trigger records the now-authoritative directory.
    update public.scim_managed_memberships set updated_at = updated_at where tenant_id = p_tenant_id;
    get diagnostics v_adopted = row_count;
  end if;

  select coalesce(array_agg(tm.user_id order by tm.user_id), array[]::uuid[]) into v_unmanaged
    from public.tenant_members tm
   where tm.tenant_id = p_tenant_id
     and (tm.expires_at is null or tm.expires_at > clock_timestamp())
     and not app.directory_authority_member_qualifies(tm.tenant_id, tm.user_id, tm.role);
  if cardinality(v_unmanaged) > 0 and not p_remove_unmanaged then
    raise exception 'directory_authority_unmanaged_members' using errcode = '55000',
      detail = cardinality(v_unmanaged)::text;
  end if;
  if not exists (
    select 1 from public.tenant_members tm
     where tm.tenant_id = p_tenant_id and tm.role in ('owner', 'admin')
       and (tm.expires_at is null or tm.expires_at > clock_timestamp())
       and not (tm.user_id = any(v_unmanaged))
  ) then
    raise exception 'directory_authority_would_remove_all_administrators' using errcode = '55000';
  end if;
  -- Each removal goes through the normal member-removal triggers (audit,
  -- API-key, enrollment and delegation revocation). Their stale SCIM rows go
  -- too, so the directory can provision them again from a clean state.
  foreach v_user in array v_unmanaged loop
    delete from public.scim_managed_memberships where tenant_id = p_tenant_id and auth_user_id = v_user;
    delete from public.team_members where team_id = p_tenant_id and user_id = v_user;
    delete from public.tenant_members where tenant_id = p_tenant_id and user_id = v_user;
  end loop;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (p_actor_user_id, p_tenant_id, 'scim.directory_authority.enabled', jsonb_build_object(
      'directory_id', p_directory_id, 'break_glass_user_ids', to_jsonb(v_break_glass),
      'adopt_existing', p_adopt_existing, 'adopted_memberships', v_adopted,
      'removed_user_ids', to_jsonb(v_unmanaged), 'removed_count', cardinality(v_unmanaged),
      'legacy_token_count', v_legacy))
    returning id into v_audit;
  return jsonb_build_object('enabled', true, 'directory_id', p_directory_id,
    'break_glass_user_ids', to_jsonb(v_break_glass), 'adopted_memberships', v_adopted,
    'removed_count', cardinality(v_unmanaged), 'audit_log_id', v_audit::text);
end;
$$;
revoke all on function public.scim_admin_enable_directory_authority(uuid, uuid, text, uuid[], boolean, boolean)
  from public, anon, authenticated;
grant execute on function public.scim_admin_enable_directory_authority(uuid, uuid, text, uuid[], boolean, boolean)
  to service_role;

-- Disabling only relaxes the membership rule; it grants nothing by itself.
create function public.scim_admin_disable_directory_authority(p_tenant_id uuid, p_actor_user_id uuid)
returns boolean
language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
declare
  v_directory text;
  v_break_glass uuid[];
begin
  if p_tenant_id is null or p_actor_user_id is null then
    raise exception 'directory_authority_invalid_request' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2641));
  perform app.scim_assert_tenant_owner(p_tenant_id, p_actor_user_id);
  update public.tenant_directory_authority
     set enabled = false, changed_by = p_actor_user_id, changed_at = clock_timestamp()
   where tenant_id = p_tenant_id and enabled
   returning directory_id into v_directory;
  if not found then return false; end if;
  with removed as (
    delete from public.tenant_directory_break_glass_owners where tenant_id = p_tenant_id returning user_id
  ) select coalesce(array_agg(user_id order by user_id), array[]::uuid[]) into v_break_glass from removed;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (p_actor_user_id, p_tenant_id, 'scim.directory_authority.disabled', jsonb_build_object(
      'directory_id', v_directory, 'break_glass_user_ids', to_jsonb(v_break_glass)));
  return true;
end;
$$;
revoke all on function public.scim_admin_disable_directory_authority(uuid, uuid) from public, anon, authenticated;
grant execute on function public.scim_admin_disable_directory_authority(uuid, uuid) to service_role;

-- 8. Offboarding --------------------------------------------------------------
-- The setting row (and, by cascade, its break-glass designations) is identity
-- membership data and is erased with it.
create function app.seed_directory_authority_offboarding_phase()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  select new.id, 57, 'tenant_directory_authority', 'identity_membership', 'delete_records', p.retention_days,
    new.requested_at + make_interval(days => p.retention_days)
  from public.tenant_data_retention_policies p
  where p.tenant_id = new.tenant_id and p.data_class = 'identity_membership';
  if not found then
    raise exception 'directory_authority_retention_policy_missing' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.seed_directory_authority_offboarding_phase() from public, anon, authenticated, service_role;
create trigger tenant_offboarding_directory_authority_phase after insert on public.tenant_offboarding_runs
for each row execute function app.seed_directory_authority_offboarding_phase();

insert into public.tenant_offboarding_phase_receipts
  (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at, status, attempts, completed_at)
select r.id, 57, 'tenant_directory_authority', 'identity_membership', 'delete_records', p.retention_days,
  r.requested_at + make_interval(days => p.retention_days),
  case when r.status = 'completed' then 'completed' else 'pending' end,
  case when r.status = 'completed' then 1 else 0 end,
  case when r.status = 'completed' then now() else null end
from public.tenant_offboarding_runs r
join public.tenant_data_retention_policies p on p.tenant_id = r.tenant_id and p.data_class = 'identity_membership';

do $migration$
declare
  v_definition text;
  v_old text := 'when ''rate_limits'' then ''public.rate_limits''';
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure) into v_definition;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_directory_authority_offboarding_definition';
  end if;
  execute replace(v_definition, v_old,
    'when ''tenant_directory_authority'' then ''public.tenant_directory_authority'' ' || v_old);
end;
$migration$;
