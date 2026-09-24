-- Restore the tenant identity barrier on every exposed tenant table.
--
-- `public.tenant_identity_access_allowed(tenant_id)` is the restrictive RLS
-- predicate that enforces the tenant identity policy (MFA/AAL2, a required SAML
-- provider, global session revocation) on top of the permissive membership
-- policies. It was applied by an information_schema sweep in 20260912000013 and
-- again in 20260923000021, so any RLS tenant table created after the last sweep
-- has to add it itself. `public.posture_findings` (20260925000050) did not: a
-- member whose session no longer satisfies the tenant's identity policy could
-- still read the tenant's posture findings.
--
-- Tables created since 20260923000021 without the barrier:
--   posture_findings                      readable by authenticated members
--   tenant_admissions, admission_operators,
--   tenant_pack_deletion_authorizations,
--   tenant_pack_deletion_receipts,
--   billing_plan_subscriptions            no authenticated grant today; the
--                                         barrier keeps them fail-closed if a
--                                         later grant or invoker view exposes
--                                         them.
--
-- scripts/tenant-identity-barrier.test.mjs replays every migration statically
-- and fails CI when an RLS tenant table ends up without this barrier.

drop policy if exists tenant_identity_access_restrict on public.posture_findings;
create policy tenant_identity_access_restrict on public.posture_findings
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- Include every other tenant table added after 20260923000021.
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
