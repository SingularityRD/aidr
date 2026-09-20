-- Close legacy user-owned RLS OR paths after hybrid tenancy. PostgreSQL ORs
-- permissive policies, so user_id = auth.uid() alone did not prove that a
-- caller still belonged to the row's active tenant. In particular it allowed
-- a caller to insert reputation data into another tenant with their own
-- user_id. Service-role operations continue to bypass RLS.

create or replace function app.is_tenant_member(p_tenant_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_catalog
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
set search_path = public, pg_catalog
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

-- The first owner/member insert for a newly created team is a deliberate
-- bootstrap exception to the membership requirement, but a suspended or
-- closing tenant must not be bootstrapped through that exception.
create or replace function app.is_tenant_creator(p_tenant_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_catalog
as $$
  select exists (
    select 1 from public.tenants t
    where t.id = p_tenant_id and t.created_by = p_user_id and t.status = 'active'
  ) and not exists (
    select 1 from public.tenant_members tm where tm.tenant_id = p_tenant_id
  );
$$;

-- These older policies were written before tenant_id existed. Keeping one of
-- them lets it OR past the tenant-bound policies, even on a suspended tenant
-- or after membership removal. Every affected table already has a tenant
-- SELECT policy. The few supported direct write operations are restored below
-- with tenant, role, and legacy owner checks together.
drop policy if exists entitlements_select_own on public.entitlements;
drop policy if exists api_keys_select_own on public.api_keys;
drop policy if exists api_keys_insert_own on public.api_keys;
drop policy if exists api_keys_update_own on public.api_keys;
drop policy if exists api_keys_delete_own on public.api_keys;
-- Credential writes were moved to audited Edge endpoints in 00001. Remove
-- the now unreachable permissive write policies as a second fail-closed layer
-- if a broad table GRANT is ever introduced later.
drop policy if exists tenant_api_keys_insert on public.api_keys;
drop policy if exists tenant_api_keys_update on public.api_keys;
drop policy if exists tenant_api_keys_delete on public.api_keys;
drop policy if exists agents_select_own on public.agents;
drop policy if exists agents_update_own on public.agents;
drop policy if exists events_select_own on public.events;
drop policy if exists url_rep_select_own on public.url_reputation;
drop policy if exists url_rep_insert_own on public.url_reputation;
drop policy if exists url_rep_update_own on public.url_reputation;
drop policy if exists url_rep_delete_own on public.url_reputation;
drop policy if exists file_rep_select_own on public.file_reputation;
drop policy if exists file_rep_insert_own on public.file_reputation;
drop policy if exists file_rep_update_own on public.file_reputation;
drop policy if exists file_rep_delete_own on public.file_reputation;
drop policy if exists enrollment_tokens_select_own on public.enrollment_tokens;
drop policy if exists enrollment_tokens_insert_own on public.enrollment_tokens;
drop policy if exists enrollment_tokens_delete_own on public.enrollment_tokens;
drop policy if exists billing_customers_select_own on public.billing_customers;
drop policy if exists subscriptions_select_own on public.subscriptions;
drop policy if exists pilot_applications_select_own on public.pilot_applications;
drop policy if exists entitlement_snapshots_select_own on public.entitlement_snapshots;

-- Restrictive policies are ANDed with every permissive policy, including any
-- policies introduced later. A team claim must match the row and the member
-- must still be active. Personal tenants continue to work via the existing
-- current_tenant_id() personal fallback.
do $$
declare v_table text;
begin
  foreach v_table in array array[
    'entitlements', 'api_keys', 'agents', 'events', 'url_reputation',
    'file_reputation', 'enrollment_tokens', 'billing_customers',
    'subscriptions', 'pilot_applications', 'entitlement_snapshots'
  ] loop
    execute format('drop policy if exists tenant_active_member_restrict on public.%I', v_table);
    execute format(
      'create policy tenant_active_member_restrict on public.%I as restrictive for all to authenticated '
      || 'using (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id)) '
      || 'with check (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id))',
      v_table
    );
  end loop;
end;
$$;

-- Reputation writes remain available to current members for their own
-- legacy user_id. Service-role feed management is unaffected by these RLS
-- rules. Updates cannot transfer a record to another user or tenant.
drop policy if exists tenant_url_reputation_insert on public.url_reputation;
create policy tenant_url_reputation_insert on public.url_reputation for insert
with check (
  tenant_id = app.current_tenant_id()
  and app.is_tenant_member_with_role(tenant_id, 'member')
  and user_id = auth.uid()
);
drop policy if exists tenant_file_reputation_insert on public.file_reputation;
create policy tenant_file_reputation_insert on public.file_reputation for insert
with check (
  tenant_id = app.current_tenant_id()
  and app.is_tenant_member_with_role(tenant_id, 'member')
  and user_id = auth.uid()
);

drop policy if exists tenant_url_reputation_update on public.url_reputation;
create policy tenant_url_reputation_update on public.url_reputation for update
using (
  tenant_id = app.current_tenant_id()
  and app.is_tenant_member_with_role(tenant_id, 'member')
  and user_id = auth.uid()
)
with check (
  tenant_id = app.current_tenant_id()
  and app.is_tenant_member_with_role(tenant_id, 'member')
  and user_id = auth.uid()
);
drop policy if exists tenant_file_reputation_update on public.file_reputation;
create policy tenant_file_reputation_update on public.file_reputation for update
using (
  tenant_id = app.current_tenant_id()
  and app.is_tenant_member_with_role(tenant_id, 'member')
  and user_id = auth.uid()
)
with check (
  tenant_id = app.current_tenant_id()
  and app.is_tenant_member_with_role(tenant_id, 'member')
  and user_id = auth.uid()
);

drop policy if exists tenant_url_reputation_delete on public.url_reputation;
create policy tenant_url_reputation_delete on public.url_reputation for delete
using (
  tenant_id = app.current_tenant_id()
  and app.is_tenant_member_with_role(tenant_id, 'member')
  and user_id = auth.uid()
);
drop policy if exists tenant_file_reputation_delete on public.file_reputation;
create policy tenant_file_reputation_delete on public.file_reputation for delete
using (
  tenant_id = app.current_tenant_id()
  and app.is_tenant_member_with_role(tenant_id, 'member')
  and user_id = auth.uid()
);

-- Enrollment-token DML likewise remains exclusively service-role/Edge. The
-- legacy own-row policies were removed above and are intentionally not
-- replaced for authenticated clients.
