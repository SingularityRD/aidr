-- Ordinary Supabase Auth access tokens carry no selected tenant claim. Browser
-- reads are authorized by active row-tenant membership; callers still filter
-- the selected team explicitly. The existing identity policy also requires a
-- live session and any tenant MFA policy. Keep the current-tenant requirement
-- on direct writes, which are not part of this dashboard read path.

drop policy if exists tenant_agents_select on public.agents;
create policy tenant_agents_select on public.agents for select to authenticated
  using (app.is_tenant_member(tenant_id));
drop policy if exists tenant_events_select on public.events;
create policy tenant_events_select on public.events for select to authenticated
  using (app.is_tenant_member(tenant_id));

-- This restrictive policy previously denied team reads even when the SELECT
-- policy accepted an active member, because current_tenant_id() fell back to
-- that member's personal tenant. WITH CHECK continues to guard writes.
drop policy if exists tenant_active_member_restrict on public.agents;
create policy tenant_active_member_restrict on public.agents
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id));
drop policy if exists tenant_active_member_restrict on public.events;
create policy tenant_active_member_restrict on public.events
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (tenant_id = app.current_tenant_id() and app.is_tenant_member(tenant_id));

-- These older team policies already provided the correct member-read path.
-- Replace their duplicate permissive OR paths with one tenant rule each.
drop policy if exists team_policies_select_member on public.team_policies;
drop policy if exists tenant_team_policies_select on public.team_policies;
create policy tenant_team_policies_select on public.team_policies for select to authenticated
  using (app.is_tenant_member(tenant_id));
drop policy if exists audit_logs_select_member on public.audit_logs;
drop policy if exists tenant_audit_logs_select on public.audit_logs;
create policy tenant_audit_logs_select on public.audit_logs for select to authenticated
  using (app.is_tenant_member(tenant_id));
