-- Removing a team member revokes access. Keep the deletion and its receipt in
-- one transaction; owner deletion is already audited by migration 33.
create or replace function app.audit_team_member_removal()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_actor uuid := auth.uid();
  v_event_id uuid := gen_random_uuid();
  v_detail jsonb;
begin
  if tg_table_schema <> 'public' or tg_table_name <> 'team_members'
     or tg_op <> 'DELETE' then
    raise exception 'member removal audit attached to unsupported operation'
      using errcode = '55000';
  end if;
  if old.role = 'owner' then return old; end if;
  if app.is_trusted_team_member_offboarding_delete(old.tenant_id) then return old; end if;

  if auth.role() = 'authenticated' then
    if v_actor is null or not public.tenant_identity_access_allowed(old.tenant_id)
       or not exists (
         select 1 from public.tenant_members m
         join public.tenants t on t.id = m.tenant_id
         where m.tenant_id = old.tenant_id and m.user_id = v_actor
           and m.role in ('owner', 'admin') and t.status = 'active'
           and (m.expires_at is null or m.expires_at > clock_timestamp())
         for share of m, t
       ) then
      raise exception 'member removal requires an active tenant administrator'
        using errcode = '42501';
    end if;
  elsif auth.role() = 'service_role'
     or session_user in ('postgres', 'service_role', 'supabase_admin', 'supabase_auth_admin') then
    null; -- Trusted offboarding and cascades are audited too.
  else
    raise exception 'member removal requires an authorized session'
      using errcode = '42501';
  end if;

  v_detail := jsonb_build_object(
    'event_id', v_event_id, 'target_user_id', old.user_id,
    'old_role', old.role,
    'source', case when auth.role() = 'authenticated' then 'authenticated' else 'trusted' end
  );
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (v_actor, old.tenant_id, old.user_id, 'team.member.removed', v_detail);
  insert into public.audit_logs(team_id, tenant_id, user_id, action, verdict)
  values (old.team_id, old.tenant_id, v_actor, 'team.member.removed', v_detail);
  return old;
end;
$$;

revoke all on function app.audit_team_member_removal()
  from public, anon, authenticated, service_role;

drop trigger if exists team_members_member_removal_audit on public.team_members;
create trigger team_members_member_removal_audit
before delete on public.team_members
for each row execute function app.audit_team_member_removal();
