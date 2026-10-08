-- Restore the directory-authoritative membership gate in the RLS helpers.
-- Forward-only; applied migrations are not edited. Static contract:
-- scripts/security-review-hardening.test.mjs (tests "e" and "g").
--
-- 20261007000050_scim_directory_authoritative added
--   and app.directory_membership_grants(tm.tenant_id, tm.user_id, tm.role)
-- to app.is_tenant_member and app.is_tenant_member_with_role, so a membership
-- that a directory-authoritative tenant no longer grants stops satisfying every
-- RLS policy built on these helpers.
--
-- 20261007120000_security_review_hardening ran later and re-created both
-- helpers from the bodies that predate that clause, only to move pg_catalog
-- first in the search path. Once the whole chain is applied, the gate was gone:
-- a user removed from a directory-authoritative tenant's directory kept RLS
-- access through their stale tenant_members row.
--
-- The bodies below are the 20261007000050 bodies, byte for byte apart from the
-- search_path, which keeps the hardening migration's pg_catalog-first order.
-- create or replace keeps the existing ACL; it is restated so it is explicit.

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
      and app.directory_membership_grants(tm.tenant_id, tm.user_id, tm.role)
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
      and app.directory_membership_grants(tm.tenant_id, tm.user_id, tm.role)
  );
$$;

revoke all on function app.is_tenant_member(uuid) from public, anon;
grant execute on function app.is_tenant_member(uuid) to authenticated, service_role;
revoke all on function app.is_tenant_member_with_role(uuid, text) from public, anon;
grant execute on function app.is_tenant_member_with_role(uuid, text) to authenticated, service_role;
