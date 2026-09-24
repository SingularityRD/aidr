-- Close legacy browser privileges that bypass row-level security and bind team
-- creation, tenant ownership and export reads to their authoritative controls.

revoke create on schema public, app from public, anon, authenticated;

alter default privileges for role postgres in schema public
  revoke all on tables from public, anon, authenticated;
alter default privileges for role postgres in schema public
  revoke all on sequences from public, anon, authenticated;
alter default privileges for role postgres in schema public
  revoke execute on functions from public, anon, authenticated;
alter default privileges for role postgres in schema app
  revoke execute on functions from public, anon, authenticated;

-- Supabase projects can inherit broad API-role defaults. Reset the current
-- public schema to a small browser allowlist; service_role grants are unchanged.
revoke all privileges on all tables in schema public from public, anon, authenticated;
revoke all privileges on all sequences in schema public from public, anon, authenticated;
revoke execute on all functions in schema public, app from public, anon, authenticated;

grant select on
  public.tenants,
  public.tenant_members,
  public.teams,
  public.team_members,
  public.team_policies,
  public.audit_logs,
  public.entitlements,
  public.agents,
  public.events,
  public.entitlement_snapshots,
  public.subscriptions,
  public.url_reputation,
  public.file_reputation,
  public.seat_usage,
  public.incident_events
to authenticated;

grant insert, update, delete on public.url_reputation, public.file_reputation to authenticated;
grant usage on sequence public.url_reputation_id_seq, public.file_reputation_id_seq to authenticated;
grant update (role) on public.team_members to authenticated;
grant delete on public.team_members to authenticated;
grant execute on function app.current_tenant_id() to authenticated;
grant execute on function app.is_tenant_member(uuid) to authenticated;
grant execute on function app.is_tenant_member_with_role(uuid, text) to authenticated;
grant execute on function app.is_tenant_creator(uuid, uuid) to authenticated;
grant execute on function public.is_team_member(uuid) to authenticated;
grant execute on function public.is_team_member_with_role(uuid, text) to authenticated;
grant execute on function public.tenant_identity_access_allowed(uuid) to authenticated;

-- Team rows are created atomically through the RPC. Direct table mutation could
-- otherwise self-select a paid plan, rebind tenant_id or bypass offboarding.
drop policy if exists teams_insert_authenticated on public.teams;
drop policy if exists teams_update_admin on public.teams;
drop policy if exists teams_delete_admin on public.teams;

create or replace function public.create_team_tenant(
  p_name text,
  p_plan text default 'free'
)
returns public.teams
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_user_id uuid := auth.uid();
  v_team_id uuid := gen_random_uuid();
  v_team public.teams;
begin
  if v_user_id is null or auth.role() is distinct from 'authenticated' then
    raise exception 'authentication required' using errcode = '28000';
  end if;
  if nullif(trim(p_name), '') is null or length(trim(p_name)) > 200 then
    raise exception 'team name is required and must not exceed 200 characters'
      using errcode = '22023';
  end if;
  if p_plan is distinct from 'free' then
    raise exception 'team plan is managed by billing' using errcode = '42501';
  end if;

  insert into public.tenants (id, name, kind, created_by)
  values (v_team_id, trim(p_name), 'team', v_user_id);
  insert into public.teams (id, tenant_id, name, plan)
  values (v_team_id, v_team_id, trim(p_name), 'free');
  insert into public.team_members (team_id, tenant_id, user_id, role)
  values (v_team_id, v_team_id, v_user_id, 'owner');

  select * into strict v_team from public.teams where id = v_team_id;
  return v_team;
end;
$$;
revoke all on function public.create_team_tenant(text, text) from public, anon;
grant execute on function public.create_team_tenant(text, text) to authenticated;

-- Repair the three checks whose original catalog lookup was not scoped to the
-- intended relation, and make the teams.id = tenant_id invariant explicit.
alter table public.team_members
  drop constraint if exists team_members_tenant_matches_team;
alter table public.team_members
  add constraint team_members_tenant_matches_team check (tenant_id = team_id) not valid;
alter table public.team_members validate constraint team_members_tenant_matches_team;

alter table public.team_policies
  drop constraint if exists team_policies_tenant_matches_team;
alter table public.team_policies
  add constraint team_policies_tenant_matches_team check (tenant_id = team_id) not valid;
alter table public.team_policies validate constraint team_policies_tenant_matches_team;

alter table public.audit_logs
  drop constraint if exists audit_logs_tenant_matches_team;
alter table public.audit_logs
  add constraint audit_logs_tenant_matches_team check (tenant_id = team_id) not valid;
alter table public.audit_logs validate constraint audit_logs_tenant_matches_team;

alter table public.teams
  drop constraint if exists teams_tenant_matches_id;
alter table public.teams
  add constraint teams_tenant_matches_id check (tenant_id = id) not valid;
alter table public.teams validate constraint teams_tenant_matches_id;

drop trigger if exists teams_tenant_immutable on public.teams;
create trigger teams_tenant_immutable
before update on public.teams
for each row execute function app.prevent_tenant_change();

-- Audit evidence is service-written. Browser members retain tenant-scoped read
-- access but cannot choose action, actor, verdict or timestamp values.
drop policy if exists audit_logs_insert_service on public.audit_logs;

-- Storage RLS must honor the same immediate session-revocation and tenant MFA
-- barrier as browser reads from public tenant tables.
drop policy if exists audit_exports_read_own_tenant on storage.objects;
create policy audit_exports_read_own_tenant on storage.objects
  for select to authenticated
  using (
    bucket_id = 'aidr-audit-exports'
    and (storage.foldername(name))[1] = app.current_tenant_id()::text
    and app.is_tenant_member(app.current_tenant_id())
    and public.tenant_identity_access_allowed(app.current_tenant_id())
  );
