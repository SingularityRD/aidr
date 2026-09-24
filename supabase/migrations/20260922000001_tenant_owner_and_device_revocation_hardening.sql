-- Owner-role changes are owner-only, while the tenant creator may establish
-- the first owner and trusted control-plane roles retain their offboarding path.
create or replace function public.guard_team_owner()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  v_actor_id uuid := auth.uid();
  v_old_tenant_id uuid;
  v_new_tenant_id uuid;
  v_old_user_id uuid;
  v_new_user_id uuid;
  v_old_role text;
  v_new_role text;
  v_old_expires_at timestamptz;
  v_new_expires_at timestamptz;
  v_now timestamptz;
  v_bootstrap boolean := false;
begin
  -- A definer function runs as its owner. JWT role and session_user identify
  -- the real trusted caller without granting that bypass to authenticated users.
  if auth.role() = 'service_role'
     or session_user in ('postgres', 'service_role', 'supabase_admin', 'supabase_auth_admin') then
    if tg_op = 'DELETE' then return old; end if;
    return new;
  end if;

  if tg_table_schema <> 'public' or tg_table_name not in ('team_members', 'tenant_members') then
    raise exception 'owner guard attached to unsupported table' using errcode = '55000';
  end if;

  if tg_table_name = 'team_members' then
    if tg_op <> 'INSERT' then
      v_old_tenant_id := old.team_id;
      v_old_user_id := old.user_id;
      v_old_role := old.role;
    end if;
    if tg_op <> 'DELETE' then
      v_new_tenant_id := new.team_id;
      v_new_user_id := new.user_id;
      v_new_role := new.role;
    end if;
  else
    if tg_op <> 'INSERT' then
      v_old_tenant_id := old.tenant_id;
      v_old_user_id := old.user_id;
      v_old_role := old.role;
      v_old_expires_at := old.expires_at;
    end if;
    if tg_op <> 'DELETE' then
      v_new_tenant_id := new.tenant_id;
      v_new_user_id := new.user_id;
      v_new_role := new.role;
      v_new_expires_at := new.expires_at;
    end if;
  end if;

  -- Serialize owner mutations per tenant. Deterministic ordering also covers a
  -- future cross-tenant owner move without introducing a lock-order deadlock.
  if v_old_role = 'owner' or v_new_role = 'owner' then
    if v_old_tenant_id is not null and v_new_tenant_id is not null
       and v_old_tenant_id is distinct from v_new_tenant_id then
      if v_old_tenant_id < v_new_tenant_id then
        perform pg_advisory_xact_lock(hashtextextended(v_old_tenant_id::text, 2612));
        perform pg_advisory_xact_lock(hashtextextended(v_new_tenant_id::text, 2612));
      else
        perform pg_advisory_xact_lock(hashtextextended(v_new_tenant_id::text, 2612));
        perform pg_advisory_xact_lock(hashtextextended(v_old_tenant_id::text, 2612));
      end if;
    else
      perform pg_advisory_xact_lock(
        hashtextextended(coalesce(v_old_tenant_id, v_new_tenant_id)::text, 2612)
      );
    end if;
  end if;

  v_now := clock_timestamp();

  -- Any mutation of an owner row requires an active owner in the old tenant.
  if v_old_role = 'owner' and not exists (
    select 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = v_old_tenant_id
      and m.user_id = v_actor_id
      and m.role = 'owner'
      and (m.expires_at is null or m.expires_at > v_now)
      and t.status = 'active'
  ) then
    raise exception 'owner role change requires an owner' using errcode = '42501';
  end if;

  -- Creating a new owner requires an owner in the destination tenant. The only
  -- exception is the tenant creator establishing the first active owner.
  if v_new_role = 'owner'
     and (tg_op = 'INSERT'
       or v_old_role is distinct from 'owner'
       or v_old_tenant_id is distinct from v_new_tenant_id
       or v_old_user_id is distinct from v_new_user_id) then
    v_bootstrap := v_actor_id = v_new_user_id
      and exists (
        select 1 from public.tenants t
        where t.id = v_new_tenant_id
          and t.created_by = v_new_user_id
          and t.status = 'active'
      )
      and not exists (
        select 1 from public.tenant_members m
        where m.tenant_id = v_new_tenant_id
          and m.role = 'owner'
          and (m.expires_at is null or m.expires_at > v_now)
      );

    if not v_bootstrap and not exists (
      select 1
      from public.tenant_members m
      join public.tenants t on t.id = m.tenant_id
      where m.tenant_id = v_new_tenant_id
        and m.user_id = v_actor_id
        and m.role = 'owner'
        and (m.expires_at is null or m.expires_at > v_now)
        and t.status = 'active'
    ) then
      raise exception 'owner role change requires an owner' using errcode = '42501';
    end if;
  end if;

  -- An authenticated owner may transfer or remove ownership only while another
  -- active owner remains. Trusted service/offboarding callers returned above.
  if v_old_role = 'owner'
     and (v_old_expires_at is null or v_old_expires_at > v_now)
     and (tg_op = 'DELETE'
       or v_new_role is distinct from 'owner'
       or v_old_tenant_id is distinct from v_new_tenant_id
       or v_old_user_id is distinct from v_new_user_id
       or (v_new_expires_at is not null and v_new_expires_at <= v_now))
     and not exists (
       select 1 from public.tenant_members m
       where m.tenant_id = v_old_tenant_id
         and m.user_id <> v_old_user_id
         and m.role = 'owner'
         and (m.expires_at is null or m.expires_at > v_now)
     ) then
    raise exception 'tenant must retain at least one owner' using errcode = '23514';
  end if;

  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;

revoke all on function public.guard_team_owner() from public, anon, authenticated;

drop trigger if exists team_members_owner_guard on public.team_members;
create trigger team_members_owner_guard
before insert or update or delete on public.team_members
for each row execute function public.guard_team_owner();

drop trigger if exists tenant_members_owner_guard on public.tenant_members;
create trigger tenant_members_owner_guard
before insert or update or delete on public.tenant_members
for each row execute function public.guard_team_owner();

-- Global identity revocation also invalidates outstanding device grants and
-- their derived, unconsumed enrollment tokens in the same transaction.
create or replace function public.mark_identity_session_revoked(
  p_user_id uuid,
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_reason text
)
returns timestamptz
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare v_barrier timestamptz;
begin
  if p_user_id is null or p_actor_user_id is null or p_user_id <> p_actor_user_id
    or p_reason not in ('user_global_signout', 'password_recovery')
  then raise exception 'session_revoke_forbidden' using errcode = '42501'; end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611));
  v_barrier := clock_timestamp();

  insert into public.identity_user_session_state(user_id, revoked_before, reason)
    values(p_user_id, v_barrier, p_reason)
    on conflict(user_id) do update
      set revoked_before = excluded.revoked_before, reason = excluded.reason;

  update public.device_sessions
    set expires_at = least(expires_at, v_barrier)
    where user_id = p_user_id
      and exchanged_at is null
      and expires_at > v_barrier;

  update public.enrollment_tokens
    set expires_at = least(expires_at, v_barrier)
    where user_id = p_user_id
      and label like 'device:%'
      and consumed_at is null
      and expires_at > v_barrier;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values(p_actor_user_id, p_tenant_id, p_user_id, 'identity.sessions.revoked',
      jsonb_build_object('reason', p_reason, 'revoked_before', v_barrier));
  return v_barrier;
end;
$$;

revoke all on function public.mark_identity_session_revoked(uuid, uuid, uuid, text)
  from public, anon, authenticated;
grant execute on function public.mark_identity_session_revoked(uuid, uuid, uuid, text)
  to service_role;

-- Serialize issue/revoke for one identity and refuse a device authorization
-- that predates the user's committed global revocation barrier.
create or replace function public.issue_device_enrollment_token(
  p_device_code_hash text,
  p_token_hash text,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_session public.device_sessions%rowtype;
  v_tenant_id uuid;
  v_user_id uuid;
  v_revoked_before timestamptz;
begin
  if p_device_code_hash is null or p_device_code_hash !~ '^[a-f0-9]{64}$'
     or p_token_hash is null or p_token_hash !~ '^[a-f0-9]{64}$'
     or p_expires_at is null
     or p_expires_at < now() + interval '1 minute'
     or p_expires_at > now() + interval '30 days' then
    raise exception 'invalid device enrollment input' using errcode = '22023';
  end if;

  select d.user_id into v_user_id
    from public.device_sessions d
    where d.device_code_hash = p_device_code_hash;
  if not found or v_user_id is null then
    return jsonb_build_object('status', 'already_exchanged_or_invalid');
  end if;

  perform pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611));

  select d.* into v_session
    from public.device_sessions d
    where d.device_code_hash = p_device_code_hash
    for update;
  if not found or v_session.user_id is null or v_session.user_id is distinct from v_user_id
     or v_session.authorized_at is null or v_session.exchanged_at is not null
     or v_session.expires_at <= now() then
    return jsonb_build_object('status', 'already_exchanged_or_invalid');
  end if;

  select s.revoked_before into v_revoked_before
    from public.identity_user_session_state s
    where s.user_id = v_session.user_id;
  if v_revoked_before is not null and v_session.authorized_at <= v_revoked_before then
    return jsonb_build_object('status', 'already_exchanged_or_invalid');
  end if;

  v_tenant_id := coalesce(v_session.tenant_id, v_session.user_id);
  if not exists (
    select 1 from public.pilot_applications p
     where p.tenant_id = v_tenant_id and p.status = 'approved'
  ) or not exists (
    select 1 from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = v_tenant_id and m.user_id = v_session.user_id
     and m.role in ('owner', 'admin', 'member')
     and (m.expires_at is null or m.expires_at > now()) and t.status = 'active'
  ) then
    return jsonb_build_object('status', 'pilot_not_approved');
  end if;

  insert into public.enrollment_tokens (user_id, tenant_id, label, token_hash, expires_at)
  values (v_session.user_id, v_tenant_id,
          'device:' || left(coalesce(v_session.user_code, ''), 16), p_token_hash, p_expires_at);
  update public.device_sessions set exchanged_at = now(), status = 'exchanged'
   where id = v_session.id;

  return jsonb_build_object('status', 'issued');
end;
$$;

revoke all on function public.issue_device_enrollment_token(text, text, timestamptz)
  from public, anon, authenticated;
grant execute on function public.issue_device_enrollment_token(text, text, timestamptz)
  to service_role;
