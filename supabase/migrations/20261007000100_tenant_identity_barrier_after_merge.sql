-- Re-apply the tenant identity barrier after the Browser Guard / go-preparation
-- merge.
--
-- Two development lines added RLS tenant tables independently. The barrier
-- sweep in 20260925000060 ran before these tables existed, so they carry no
-- `tenant_identity_access_restrict` policy:
--   oidc_providers, oidc_tenant_domains, oidc_auth_requests, oidc_identities,
--   oidc_login_tickets, oidc_sso_sessions             (20261005000001)
--   tenant_saml_outage_recoveries                     (20261006002000)
--   tenant_discovery_provider_resources               (20261006003000)
-- None of them has an authenticated grant or permissive policy today (they are
-- reached through service-role functions), so the barrier changes no current
-- access path; it keeps them fail-closed if a later grant or invoker view
-- exposes them. scripts/tenant-identity-barrier.test.mjs and
-- scripts/check-supabase-migrations.mjs replay every migration and fail CI when
-- an RLS tenant table ends up without this barrier.

do $$
declare v_table record;
begin
  for v_table in
    select distinct c.table_name
    from information_schema.columns c
    join pg_class pc on pc.relname = c.table_name
    join pg_namespace pn on pn.oid = pc.relnamespace and pn.nspname = c.table_schema
    where c.table_schema = 'public' and c.column_name = 'tenant_id'
      and pc.relkind in ('r', 'p') and pc.relrowsecurity
  loop
    execute format('drop policy if exists tenant_identity_access_restrict on public.%I', v_table.table_name);
    execute format(
      'create policy tenant_identity_access_restrict on public.%I as restrictive for all to authenticated using (public.tenant_identity_access_allowed(tenant_id)) with check (public.tenant_identity_access_allowed(tenant_id))',
      v_table.table_name
    );
  end loop;
end;
$$;
