-- Acquire the revocable admission and membership rows before the device-session
-- row. Membership removal expires device sessions in an AFTER trigger; taking
-- the session lock first inverted that order and could deadlock with polling.
create or replace function public.issue_device_enrollment_token(
  p_device_code_hash text,
  p_token_hash text,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, pg_temp
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

  -- This read is only a lock-key lookup. The row and its identity are checked
  -- again under lock after all revocation boundaries have been acquired.
  select d.user_id, coalesce(d.tenant_id, d.user_id)
    into v_user_id, v_tenant_id
    from public.device_sessions d
   where d.device_code_hash = p_device_code_hash;
  if not found or v_user_id is null then
    return jsonb_build_object('status', 'already_exchanged_or_invalid');
  end if;

  -- Global sign-out/recovery and device verification use this same per-user
  -- lock. Keep it first so those barriers serialize before admission locks.
  perform pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611));
  select s.revoked_before into v_revoked_before
    from public.identity_user_session_state s
   where s.user_id = v_user_id;

  -- tenant_admission_capacity locks the tenant/admission/entitlement rows.
  -- Explicitly lock the active membership as well. These are the same rows
  -- locked by the token-insert triggers, but acquiring them before the device
  -- row lets a concurrent membership-removal trigger finish its session sweep.
  if public.tenant_admission_capacity(v_tenant_id) < 1 then
    return jsonb_build_object('status', 'tenant_not_admitted');
  end if;
  perform 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = v_tenant_id and m.user_id = v_user_id
     and m.role in ('owner', 'admin', 'member')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m, t;
  if not found then
    return jsonb_build_object('status', 'tenant_not_admitted');
  end if;

  select d.* into v_session
    from public.device_sessions d
   where d.device_code_hash = p_device_code_hash
   for update;
  if not found or v_session.user_id is null
     or v_session.user_id is distinct from v_user_id
     or coalesce(v_session.tenant_id, v_session.user_id) is distinct from v_tenant_id
     or v_session.authorized_at is null or v_session.exchanged_at is not null
     or v_session.expires_at <= clock_timestamp() then
    return jsonb_build_object('status', 'already_exchanged_or_invalid');
  end if;
  if v_revoked_before is not null
     and v_session.authorized_at <= v_revoked_before then
    return jsonb_build_object('status', 'already_exchanged_or_invalid');
  end if;

  insert into public.enrollment_tokens
    (user_id, tenant_id, label, token_hash, expires_at)
  values (v_session.user_id, v_tenant_id,
    'device:' || left(coalesce(v_session.user_code, ''), 16),
    p_token_hash, p_expires_at);
  update public.device_sessions set exchanged_at = clock_timestamp(), status = 'exchanged'
   where id = v_session.id;
  return jsonb_build_object('status', 'issued');
end;
$$;

revoke all on function public.issue_device_enrollment_token(text, text, timestamptz)
  from public, anon, authenticated;
grant execute on function public.issue_device_enrollment_token(text, text, timestamptz)
  to service_role;
