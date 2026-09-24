-- Deploy these additive RPCs before the matching Edge handlers. A pilot row
-- and its audit record must either both commit or both roll back.
create or replace function public.submit_pilot_application(
  p_user_id uuid,
  p_tenant_id uuid,
  p_notes text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_status text;
begin
  if p_user_id is null or p_tenant_id is null or length(p_notes) > 4000 then
    raise exception 'invalid_pilot_application' using errcode = '22023';
  end if;

  -- This row lock also serializes tenant selection in the admin RPC with
  -- concurrent inserts that reference the same auth user.
  perform 1 from auth.users where id = p_user_id for update;
  if not found then
    raise exception 'user_not_found' using errcode = '22023';
  end if;

  perform 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.user_id = p_user_id
     and m.tenant_id = p_tenant_id
     and m.role in ('owner', 'admin', 'member', 'viewer', 'support_jit')
     and (m.expires_at is null or m.expires_at > now())
     and t.status = 'active'
   for share of m, t;
  if not found then
    raise exception 'tenant_access_denied' using errcode = '42501';
  end if;

  insert into public.pilot_applications as application(user_id, tenant_id, status, notes)
  values (p_user_id, p_tenant_id, 'pending', p_notes)
  on conflict (user_id, tenant_id) do update
    set notes = excluded.notes
    where application.status in ('pending', 'approved', 'denied')
  returning status into v_status;
  if v_status is null then
    raise exception 'invalid_pilot_application_state' using errcode = '22023';
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
  values (p_user_id, p_tenant_id, 'pilot.apply', p_user_id,
          jsonb_build_object('has_use_case', p_notes is not null and p_notes <> ''));
  return jsonb_build_object('status', v_status);
end;
$$;

revoke all on function public.submit_pilot_application(uuid, uuid, text)
  from public, anon, authenticated;
grant execute on function public.submit_pilot_application(uuid, uuid, text)
  to service_role;

create or replace function public.decide_pilot_application(
  p_actor_user_id uuid,
  p_target_user_id uuid,
  p_tenant_id uuid,
  p_action text,
  p_cohort text,
  p_notes text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_tenant_id uuid;
  v_status text;
begin
  if p_actor_user_id is null or p_target_user_id is null
     or p_action not in ('approve', 'deny') or p_action is null then
    raise exception 'invalid_pilot_decision' using errcode = '22023';
  end if;

  perform 1 from auth.users where id = p_target_user_id for update;
  if not found then
    raise exception 'user_not_found' using errcode = '22023';
  end if;
  perform 1 from public.pilot_admins where user_id = p_actor_user_id for share;
  if not found then
    raise exception 'pilot_admin_forbidden' using errcode = '42501';
  end if;

  if p_tenant_id is null then
    select a.tenant_id into v_tenant_id
      from public.pilot_applications a
     where a.user_id = p_target_user_id
     order by a.tenant_id
     limit 1;
    if v_tenant_id is not null and exists (
      select 1 from public.pilot_applications a
       where a.user_id = p_target_user_id and a.tenant_id <> v_tenant_id
    ) then
      raise exception 'tenant_required' using errcode = '22023';
    end if;
    v_tenant_id := coalesce(v_tenant_id, p_target_user_id);
  else
    v_tenant_id := p_tenant_id;
  end if;

  perform 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.user_id = p_target_user_id
     and m.tenant_id = v_tenant_id
     and m.role in ('owner', 'admin', 'member')
     and (m.expires_at is null or m.expires_at > now())
     and t.status = 'active'
   for share of m, t;
  if not found then
    raise exception 'tenant_access_denied' using errcode = '42501';
  end if;

  v_status := case p_action when 'approve' then 'approved' else 'denied' end;
  insert into public.pilot_applications(user_id, tenant_id, status, cohort, notes)
  values (p_target_user_id, v_tenant_id, v_status, p_cohort, p_notes)
  on conflict (user_id, tenant_id) do update
    set status = excluded.status, cohort = excluded.cohort, notes = excluded.notes;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
  values (p_actor_user_id, v_tenant_id, 'pilot.' || p_action, p_target_user_id,
          jsonb_build_object('cohort', p_cohort, 'notes', p_notes));
  return jsonb_build_object('tenant_id', v_tenant_id, 'status', v_status);
end;
$$;

revoke all on function public.decide_pilot_application(uuid, uuid, uuid, text, text, text)
  from public, anon, authenticated;
grant execute on function public.decide_pilot_application(uuid, uuid, uuid, text, text, text)
  to service_role;
