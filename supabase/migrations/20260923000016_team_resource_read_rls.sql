-- Browser JWTs do not contain a selected tenant claim. Authorize these
-- browser-readable resources by active row-tenant membership; the dashboard
-- must still filter to its selected tenant. Keep the current-tenant write
-- check and the separate identity/MFA restrictive policy unchanged.
do $$
declare v_table text;
begin
  foreach v_table in array array[
    'entitlements', 'subscriptions', 'entitlement_snapshots',
    'url_reputation', 'file_reputation'
  ] loop
    execute format('drop policy if exists tenant_%I_select on public.%I', v_table, v_table);
    execute format(
      'create policy tenant_%I_select on public.%I for select to authenticated using (app.is_tenant_member(tenant_id))',
      v_table, v_table
    );
    execute format('drop policy if exists tenant_active_member_restrict on public.%I', v_table);
    execute format(
      'create policy tenant_active_member_restrict on public.%I as restrictive for all to authenticated '
      || 'using (app.is_tenant_member(tenant_id)) '
      || 'with check (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id))',
      v_table
    );
  end loop;
end;
$$;

-- API keys, enrollment tokens, billing customer identifiers, and pilot
-- applications deliberately remain absent from the browser table allowlist.
-- Their Edge endpoints perform tenant authorization and auditing.
