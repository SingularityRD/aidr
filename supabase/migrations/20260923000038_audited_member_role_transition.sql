-- Ordinary team role edits are privilege changes. Record them in both internal
-- and customer-visible append-only logs in the membership transaction.
-- Owner transitions retain the stronger AAL2 guard and their own paired event in 33.
create or replace function app.audit_team_member_role_transition()
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
     or tg_op <> 'UPDATE' then
    raise exception 'member audit attached to unsupported operation'
      using errcode = '55000';
  end if;
  if old.role = new.role or old.role = 'owner' or new.role = 'owner' then
    return new;
  end if;
  if old.team_id is distinct from new.team_id
     or old.tenant_id is distinct from new.tenant_id
     or old.user_id is distinct from new.user_id then
    raise exception 'membership identity and tenant keys are immutable'
      using errcode = '42501';
  end if;

  if auth.role() = 'authenticated' then
    if v_actor is null or not public.tenant_identity_access_allowed(new.tenant_id)
       or not exists (
         select 1 from public.tenant_members m
         join public.tenants t on t.id = m.tenant_id
         where m.tenant_id = new.tenant_id and m.user_id = v_actor
           and m.role in ('owner', 'admin') and t.status = 'active'
           and (m.expires_at is null or m.expires_at > clock_timestamp())
         for share of m, t
       ) then
      raise exception 'role change requires an active tenant administrator'
        using errcode = '42501';
    end if;
  elsif auth.role() = 'service_role'
     or session_user in ('postgres', 'service_role', 'supabase_admin', 'supabase_auth_admin') then
    null; -- Trusted control plane and migrations are audited too.
  else
    raise exception 'role change requires an authorized session'
      using errcode = '42501';
  end if;

  v_detail := jsonb_build_object(
    'event_id', v_event_id, 'target_user_id', new.user_id,
    'old_role', old.role, 'new_role', new.role,
    'source', case when auth.role() = 'authenticated' then 'authenticated' else 'trusted' end
  );
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (v_actor, new.tenant_id, new.user_id, 'team.member.role_changed', v_detail);
  insert into public.audit_logs(team_id, tenant_id, user_id, action, verdict)
  values (new.team_id, new.tenant_id, v_actor, 'team.member.role_changed', v_detail);
  return new;
end;
$$;

revoke all on function app.audit_team_member_role_transition()
  from public, anon, authenticated, service_role;

drop trigger if exists team_members_member_role_audit on public.team_members;
create trigger team_members_member_role_audit
before update of role on public.team_members
for each row execute function app.audit_team_member_role_transition();
