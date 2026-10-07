-- Security review hardening (2026-10-07). Forward-only; applied migrations are
-- not edited. Static contract: scripts/security-review-hardening.test.mjs.
--
-- a. Functions no longer get PUBLIC EXECUTE by default. PostgreSQL grants
--    EXECUTE on every new function to PUBLIC through the *global* default
--    privileges. 20260922000002 revoked it per schema (`... in schema public`),
--    but a per-schema ALTER DEFAULT PRIVILEGES cannot remove a privilege granted
--    by the global default, so every function created afterwards without an
--    explicit REVOKE was still executable by PUBLIC (and therefore by anon via
--    PostgREST). The global revoke below closes that for future functions; the
--    static test asserts every function created after 20260922000002 carries an
--    explicit revoke from PUBLIC.
-- b. public.tenant_identity_access_allowed(uuid) is callable over PostgREST RPC
--    by any authenticated user. For a tenant the caller does not belong to, its
--    MFA/SAML/OIDC clauses answered whether that tenant enforces MFA or which
--    SSO mode it requires. A caller with no membership row for the tenant now
--    gets only the caller-level session-revocation clause (no tenant metadata).
--    Every permissive policy that this restrictive barrier guards already
--    requires tenant membership, so strangers gain no access; members and
--    expired members are evaluated exactly as before.
-- c. The audit export bucket is forced private even if it already existed
--    (the original insert used `on conflict do nothing`).
-- d. create_team_tenant: per-user creation quota (default 10 per rolling 24h,
--    configurable in app.team_creation_quota), checked under the existing
--    per-user advisory lock. Request-ID replays do not count. Fails closed.
-- e. Tenant membership helpers resolve pg_catalog before public. They were
--    pinned to `public, pg_catalog[, pg_temp]`, so an object in public could
--    shadow a catalog function such as now() inside these SECURITY DEFINER
--    helpers. Bodies are recreated unchanged with `pg_catalog, public, pg_temp`.
-- f. Audit export objects are readable only by an active owner/admin of the
--    tenant named by the object's first path segment (the edge function writes
--    `<tenant_id>/<uuid>.<format>`), behind the tenant identity barrier. The
--    previous policy keyed on app.current_tenant_id() (the JWT/personal tenant)
--    and allowed any member, including viewers.

-- ---------------------------------------------------------------------------
-- a. Global default: no PUBLIC EXECUTE on functions created by postgres.
-- ---------------------------------------------------------------------------
alter default privileges for role postgres revoke execute on functions from public;

-- ---------------------------------------------------------------------------
-- b. No tenant identity-policy metadata for non-members.
-- ---------------------------------------------------------------------------
create or replace function public.tenant_identity_access_allowed(p_tenant_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select
    auth.uid() is not null
    and not exists (
      select 1 from public.identity_user_session_state s
      where s.user_id = auth.uid()
        and (
          s.global_revoke_pending_session_id is not null
          or (
            s.revoked_before is not null
            and (
              coalesce(auth.jwt()->>'iat', '') !~ '^[0-9]+(\.[0-9]+)?$'
              or to_timestamp((auth.jwt()->>'iat')::double precision) <= s.revoked_before
            )
          )
        )
    )
    and (
      -- A caller with no membership row learns nothing about this tenant's
      -- identity policy. Permissive tenant policies still require membership.
      not exists (
        select 1 from public.tenant_members m
        where m.tenant_id = p_tenant_id and m.user_id = auth.uid()
      )
      or (
        not exists (
          select 1 from public.tenant_identity_policies p
          where p.tenant_id = p_tenant_id
            and p.require_mfa
            and coalesce(auth.jwt()->>'aal', 'aal1') <> 'aal2'
        )
        and not exists (
          select 1 from public.tenant_identity_policies p
          where p.tenant_id = p_tenant_id
            and p.required_saml_provider_id is not null
            and not exists (
              select 1
              from jsonb_array_elements(
                case when jsonb_typeof(auth.jwt()->'amr') = 'array'
                  then auth.jwt()->'amr' else '[]'::jsonb end
              ) as amr(entry)
              where amr.entry->>'method' = 'sso/saml'
                and amr.entry->>'provider' = p.required_saml_provider_id::text
            )
        )
        and not exists (
          select 1 from public.tenant_identity_policies p
          where p.tenant_id = p_tenant_id
            and p.required_oidc_provider_id is not null
            and not exists (
              select 1 from public.oidc_sso_sessions o
              where coalesce(auth.jwt()->>'session_id', '') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                and o.session_id = (auth.jwt()->>'session_id')::uuid
                and o.user_id = auth.uid()
                and o.provider_id = p.required_oidc_provider_id
                and o.tenant_id = p_tenant_id
                and o.revoked_at is null
                and o.expires_at > now()
            )
        )
      )
    );
$$;
revoke all on function public.tenant_identity_access_allowed(uuid) from public, anon;
grant execute on function public.tenant_identity_access_allowed(uuid) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- c. The audit export bucket is private, whatever state it was created in.
-- ---------------------------------------------------------------------------
insert into storage.buckets (id, name, public)
values ('aidr-audit-exports', 'aidr-audit-exports', false)
on conflict (id) do update set public = false;

-- ---------------------------------------------------------------------------
-- d. Per-user team creation quota.
-- ---------------------------------------------------------------------------
create table if not exists app.team_creation_quota (
  singleton boolean primary key default true check (singleton),
  max_per_day integer not null default 10 check (max_per_day between 1 and 1000),
  updated_at timestamptz not null default now()
);
insert into app.team_creation_quota (singleton) values (true) on conflict (singleton) do nothing;
alter table app.team_creation_quota enable row level security;
-- Operator-only configuration: no policy and no API-role grant.
revoke all on app.team_creation_quota from public, anon, authenticated, service_role;

create index if not exists team_creation_requests_actor_created_idx
  on public.team_creation_requests (actor_user_id, created_at);

create or replace function public.create_team_tenant(
  p_name text,
  p_request_id uuid,
  p_plan text default 'free'
)
returns public.teams
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_user_id uuid := auth.uid();
  v_team_id uuid;
  v_existing_name text;
  v_team public.teams;
  v_quota integer;
  v_recent integer;
begin
  if v_user_id is null or auth.role() is distinct from 'authenticated' then
    raise exception 'authentication required' using errcode = '28000';
  end if;
  if nullif(trim(p_name), '') is null or length(trim(p_name)) > 200 then
    raise exception 'team name is required and must not exceed 200 characters'
      using errcode = '22023';
  end if;
  if p_request_id is null then
    raise exception 'team creation request ID is required' using errcode = '22023';
  end if;
  if p_plan is distinct from 'free' then
    raise exception 'team plan is managed by billing' using errcode = '42501';
  end if;

  -- This lock also serializes creation with identity revocation. It does not
  -- make the user unique: only a replay of the same request ID is deduplicated.
  perform pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611));

  select r.team_id, r.requested_name
    into v_team_id, v_existing_name
    from public.team_creation_requests r
   where r.actor_user_id = v_user_id and r.request_id = p_request_id;
  if found then
    if v_existing_name <> trim(p_name) then
      raise exception 'team creation request ID was reused with a different name'
        using errcode = '22023';
    end if;
    if not public.tenant_identity_access_allowed(v_team_id) then
      raise exception 'identity barrier rejected' using errcode = '42501';
    end if;
    select * into v_team from public.teams where id = v_team_id;
    if not found then
      raise exception 'team creation request has no live workspace' using errcode = '55000';
    end if;
    return v_team;
  end if;

  -- New workspaces are bounded per user per rolling day. The count runs under
  -- the per-user advisory lock above, so concurrent requests cannot both pass.
  -- A missing configuration row falls back to the default bound; an invalid
  -- value cannot be stored (check constraint), so the quota never disappears.
  select q.max_per_day into v_quota from app.team_creation_quota q where q.singleton;
  v_quota := coalesce(v_quota, 10);
  select count(*) into v_recent
    from public.team_creation_requests r
   where r.actor_user_id = v_user_id
     and r.created_at > clock_timestamp() - interval '1 day';
  if v_recent >= v_quota then
    raise exception 'team creation quota exceeded' using errcode = '54000';
  end if;

  v_team_id := gen_random_uuid();
  if not public.tenant_identity_access_allowed(v_team_id) then
    raise exception 'identity barrier rejected' using errcode = '42501';
  end if;

  insert into public.tenants (id, name, kind, created_by)
  values (v_team_id, trim(p_name), 'team', v_user_id);
  insert into public.teams (id, tenant_id, name, plan)
  values (v_team_id, v_team_id, trim(p_name), 'free');
  insert into public.team_members (team_id, tenant_id, user_id, role)
  values (v_team_id, v_team_id, v_user_id, 'owner');
  insert into public.team_creation_requests (actor_user_id, request_id, requested_name, team_id)
  values (v_user_id, p_request_id, trim(p_name), v_team_id);

  select * into strict v_team from public.teams where id = v_team_id;
  return v_team;
end;
$$;
revoke all on function public.create_team_tenant(text, uuid, text) from public, anon;
grant execute on function public.create_team_tenant(text, uuid, text) to authenticated;

-- ---------------------------------------------------------------------------
-- e. pg_catalog first in the tenant membership helpers (bodies unchanged).
-- ---------------------------------------------------------------------------
create or replace function app.current_tenant_id()
returns uuid
language plpgsql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  raw_claim text;
  claim_id uuid;
  caller_id uuid;
begin
  raw_claim := nullif(current_setting('request.jwt.claim.tenant_id', true), '');
  if raw_claim is not null then
    begin
      claim_id := raw_claim::uuid;
      if exists (select 1 from public.tenants where id = claim_id) then
        return claim_id;
      end if;
    exception when invalid_text_representation then
      null;
    end;
  end if;
  caller_id := auth.uid();
  if caller_id is not null and exists (select 1 from public.tenants where id = caller_id) then
    return caller_id;
  end if;
  return null;
end;
$$;

create or replace function app.is_tenant_member(p_tenant_id uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
  select exists (
    select 1
    from public.tenant_members tm
    join public.tenants t on t.id = tm.tenant_id
    where tm.tenant_id = p_tenant_id
      and tm.user_id = auth.uid()
      and (tm.expires_at is null or tm.expires_at > now())
      and t.status = 'active'
  );
$$;

create or replace function app.is_tenant_member_with_role(p_tenant_id uuid, p_min_role text)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
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
  );
$$;

create or replace function app.is_tenant_creator(p_tenant_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
  select exists (
    select 1 from public.tenants t
    where t.id = p_tenant_id and t.created_by = p_user_id and t.status = 'active'
  ) and not exists (
    select 1 from public.tenant_members tm where tm.tenant_id = p_tenant_id
  );
$$;

create or replace function public.is_team_member(team_id uuid)
returns boolean
language sql
stable security definer
set search_path = pg_catalog, public, pg_temp
as $$ select app.is_tenant_member(team_id); $$;

create or replace function public.is_team_member_with_role(team_id uuid, min_role text)
returns boolean
language sql
stable security definer
set search_path = pg_catalog, public, pg_temp
as $$ select app.is_tenant_member_with_role(team_id, min_role); $$;

-- create or replace keeps existing grants; restate them so the ACL is explicit.
revoke all on function app.current_tenant_id() from public, anon;
grant execute on function app.current_tenant_id() to authenticated, service_role;
revoke all on function app.is_tenant_member(uuid) from public, anon;
grant execute on function app.is_tenant_member(uuid) to authenticated, service_role;
revoke all on function app.is_tenant_member_with_role(uuid, text) from public, anon;
grant execute on function app.is_tenant_member_with_role(uuid, text) to authenticated, service_role;
revoke all on function app.is_tenant_creator(uuid, uuid) from public, anon;
grant execute on function app.is_tenant_creator(uuid, uuid) to authenticated, service_role;
revoke all on function public.is_team_member(uuid) from public, anon;
grant execute on function public.is_team_member(uuid) to authenticated, service_role;
revoke all on function public.is_team_member_with_role(uuid, text) from public, anon;
grant execute on function public.is_team_member_with_role(uuid, text) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- f. Audit export objects: owner/admin of the object's own tenant only.
-- ---------------------------------------------------------------------------
drop policy if exists audit_exports_read_own_tenant on storage.objects;
create policy audit_exports_read_own_tenant on storage.objects
  for select to authenticated
  using (
    -- CASE fixes evaluation order: the uuid cast runs only for a well-formed
    -- tenant folder in this bucket, so other objects can never raise 22P02.
    case
      when bucket_id = 'aidr-audit-exports'
        and (storage.foldername(name))[1] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      then
        app.is_tenant_member_with_role(((storage.foldername(name))[1])::uuid, 'admin')
        and public.tenant_identity_access_allowed(((storage.foldername(name))[1])::uuid)
      else false
    end
  );
