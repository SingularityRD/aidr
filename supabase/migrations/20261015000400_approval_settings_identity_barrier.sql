-- SEC-2: get_approval_settings is a browser-callable SECURITY DEFINER read
-- (granted to authenticated) that checked membership only. Every other
-- member read added by the 2026-10 migrations (tenant_license_status,
-- tenant_usage_report, the incident/connector/FP-report RLS policies) also
-- requires the tenant identity barrier (tenant MFA/SSO policy, global session
-- revocation), so a member whose session fails the barrier could still read
-- this tenant's approval rule. Re-define it with the same gate and drop the
-- unused service_role grant (no edge function calls it; under service_role
-- auth.uid() is null and the membership check could never pass anyway).

create or replace function public.get_approval_settings(p_tenant_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
begin
  if auth.role() is distinct from 'authenticated'
     or auth.uid() is null
     or p_tenant_id is null
     or not app.is_tenant_member(p_tenant_id)
     or not public.tenant_identity_access_allowed(p_tenant_id) then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  return jsonb_build_object(
    'require_distinct_approver', (select s.approval_require_distinct_approver
      from public.tenant_ai_governance_settings s where s.tenant_id = p_tenant_id),
    'effective', app.approval_distinct_approver_required(p_tenant_id));
end;
$$;
revoke all on function public.get_approval_settings(uuid) from public, anon, authenticated, service_role;
grant execute on function public.get_approval_settings(uuid) to authenticated;
