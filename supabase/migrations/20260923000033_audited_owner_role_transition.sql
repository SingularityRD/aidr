-- Browser owner-role mutations require an AAL2 session and produce one
-- append-only audit event in the same transaction. The first owner bootstrap
-- remains possible without MFA; the existing final-owner guard still applies.
-- Offboarding may complete either audit purge before membership cleanup because
-- phases are selected by retention eligibility. Do not recreate a purged log.
create or replace function app.is_trusted_team_member_offboarding_delete(p_tenant_id uuid)
returns boolean
language sql
volatile
security definer
set search_path = pg_catalog, public, pg_temp
as $$
  select (
    auth.role() = 'service_role'
    or (auth.role() is distinct from 'authenticated'
      and session_user in ('postgres', 'service_role', 'supabase_admin', 'supabase_auth_admin'))
  ) and exists (
    select 1
    from public.tenant_offboarding_runs r
    join public.tenants t on t.id = r.tenant_id and t.status = 'closing'
    join public.tenant_offboarding_phase_receipts member_phase
      on member_phase.run_id = r.id and member_phase.phase = 'team_members'
      and member_phase.status = 'running'
    where r.tenant_id = p_tenant_id and r.status = 'running'
      and exists (
        select 1 from public.tenant_offboarding_phase_receipts audit_phase
        where audit_phase.run_id = r.id
          and audit_phase.phase in ('audit_logs', 'admin_audit_logs')
          and audit_phase.status = 'completed'
      )
      and not exists (
        select 1 from public.tenant_legal_holds h
        where h.tenant_id = r.tenant_id and h.released_at is null
      )
  );
$$;
revoke all on function app.is_trusted_team_member_offboarding_delete(uuid)
  from public, anon, authenticated, service_role;

create or replace function app.audit_team_owner_role_transition()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_actor uuid := auth.uid();
  v_tenant_id uuid;
  v_target_user_id uuid;
  v_old_role text;
  v_new_role text;
  v_bootstrap boolean := false;
  v_event_id uuid := gen_random_uuid();
  v_detail jsonb;
begin
  if tg_table_schema <> 'public' or tg_table_name <> 'team_members' then
    raise exception 'owner audit attached to unsupported table' using errcode = '55000';
  end if;

  if tg_op <> 'INSERT' then v_old_role := old.role; end if;
  if tg_op <> 'DELETE' then v_new_role := new.role; end if;
  if v_old_role is distinct from 'owner' and v_new_role is distinct from 'owner' then
    if tg_op = 'DELETE' then return old; end if;
    return new;
  end if;
  if tg_op = 'UPDATE' and (old.team_id is distinct from new.team_id
      or old.tenant_id is distinct from new.tenant_id
      or old.user_id is distinct from new.user_id) then
    raise exception 'owner identity and tenant keys are immutable'
      using errcode = '42501';
  end if;
  if tg_op = 'UPDATE' and old.role = new.role then return new; end if;

  if tg_op = 'DELETE' then
    v_tenant_id := old.tenant_id;
    v_target_user_id := old.user_id;
  else
    v_tenant_id := new.tenant_id;
    v_target_user_id := new.user_id;
  end if;

  if tg_op = 'DELETE' and app.is_trusted_team_member_offboarding_delete(v_tenant_id) then
    return old;
  end if;

  if auth.role() = 'authenticated' then
    v_bootstrap := coalesce(tg_op = 'INSERT' and v_actor = v_target_user_id
      and exists (
        select 1 from public.tenants t
        where t.id = v_tenant_id and t.created_by = v_actor and t.status = 'active'
      ) and not exists (
        select 1 from public.tenant_members m
        where m.tenant_id = v_tenant_id and m.role = 'owner'
          and (m.expires_at is null or m.expires_at > clock_timestamp())
      ) and not exists (
        select 1 from public.team_members m
        where m.tenant_id = v_tenant_id and m.role = 'owner'
      ), false);
    if not v_bootstrap then
      if v_actor is null or auth.jwt()->>'aal' is distinct from 'aal2'
         or not public.tenant_identity_access_allowed(v_tenant_id)
         or not exists (
           select 1 from public.tenant_members m
           join public.tenants t on t.id = m.tenant_id
           where m.tenant_id = v_tenant_id and m.user_id = v_actor
             and m.role = 'owner' and t.status = 'active'
             and (m.expires_at is null or m.expires_at > clock_timestamp())
           for share of m, t
         ) then
        raise exception 'owner role change requires an active AAL2 owner session'
          using errcode = '42501';
      end if;
    end if;
  elsif auth.role() = 'service_role'
     or session_user in ('postgres', 'service_role', 'supabase_admin', 'supabase_auth_admin') then
    null; -- Trusted bootstrap, controlled migrations, and offboarding.
  else
    raise exception 'owner role change requires an authorized session'
      using errcode = '42501';
  end if;

  v_detail := jsonb_build_object(
    'event_id', v_event_id, 'target_user_id', v_target_user_id,
    'old_role', v_old_role, 'new_role', v_new_role,
    'bootstrap', v_bootstrap,
    'source', case when auth.role() = 'authenticated' then 'authenticated' else 'trusted' end
  );
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (v_actor, v_tenant_id, v_target_user_id, 'team.owner.role_changed', v_detail);
  insert into public.audit_logs(team_id, tenant_id, user_id, action, verdict)
  values (v_tenant_id, v_tenant_id, v_actor, 'team.owner.role_changed', v_detail);
  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;

revoke all on function app.audit_team_owner_role_transition()
  from public, anon, authenticated, service_role;

drop trigger if exists team_members_owner_transition_audit on public.team_members;
create trigger team_members_owner_transition_audit
before insert or update or delete on public.team_members
for each row execute function app.audit_team_owner_role_transition();
