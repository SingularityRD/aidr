-- The one-time token, seat allocation and hash-only API-key insert are one
-- transaction. A failed insert or seat check must not burn the token.
create function public.exchange_enrollment_token(
  p_token_hash text,
  p_iid text,
  p_agent_runtime text,
  p_agent_runtime_version text,
  p_key_hash text
)
returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_token public.enrollment_tokens%rowtype;
  v_ent public.entitlements%rowtype;
  v_agent record;
begin
  if p_token_hash is null or p_token_hash !~ '^[a-f0-9]{64}$'
     or p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$'
     or p_iid is null or length(btrim(p_iid)) not between 1 and 128
     or p_iid ~ '[[:cntrl:]]'
     or (p_agent_runtime is not null and (length(p_agent_runtime) > 128 or p_agent_runtime ~ '[[:cntrl:]]'))
     or (p_agent_runtime_version is not null and (length(p_agent_runtime_version) > 128 or p_agent_runtime_version ~ '[[:cntrl:]]')) then
    raise exception 'invalid enrollment exchange input' using errcode = '22023';
  end if;

  -- FOR UPDATE serializes exchanges of the same token. A waiting caller
  -- rechecks consumed_at after the first transaction commits.
  select t.* into v_token
    from public.enrollment_tokens t
   where t.token_hash = p_token_hash
   for update;
  if not found or v_token.consumed_at is not null or v_token.expires_at <= now() then
    return jsonb_build_object('status', 'invalid_token');
  end if;

  -- The actor may have lost tenant membership or the tenant may have been
  -- suspended since the token was created. Keep the token unused in that case.
  if not exists (
    select 1 from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = v_token.tenant_id
     and m.user_id = v_token.user_id
     and (m.expires_at is null or m.expires_at > now())
     and t.status = 'active'
  ) then
    return jsonb_build_object('status', 'tenant_not_authorized');
  end if;

  select e.* into v_ent from public.entitlements e
   where e.tenant_id = v_token.tenant_id;
  if not found then
    return jsonb_build_object('status', 'missing_entitlements');
  end if;

  -- register_agent_for_ingest holds the tenant advisory lock and entitlement
  -- row lock until this entire RPC commits. Its insert/update is rolled back
  -- if the API-key insert below fails.
  select * into v_agent from public.register_agent_for_ingest(
    p_user_id => v_token.user_id,
    p_iid => btrim(p_iid),
    p_agent_runtime => p_agent_runtime,
    p_agent_runtime_version => p_agent_runtime_version,
    p_tenant_id => v_token.tenant_id
  );
  if not found then
    raise exception 'agent registration returned no result';
  end if;
  if v_agent.seat_exceeded then
    return jsonb_build_object(
      'status', 'seat_exceeded',
      'allowed_agents', v_agent.allowed_agents,
      'current_agents', v_agent.current_agents
    );
  end if;
  if v_agent.agent_id is null then
    raise exception 'agent registration returned no agent';
  end if;

  -- Refresh under the row lock held by register_agent_for_ingest so the
  -- returned signed-snapshot inputs match the committed seat allocation.
  select e.* into v_ent from public.entitlements e
   where e.tenant_id = v_token.tenant_id;
  if not found then
    raise exception 'entitlements disappeared during enrollment';
  end if;

  insert into public.api_keys (user_id, tenant_id, label, agent_id, key_hash)
  values (v_token.user_id, v_token.tenant_id, 'enroll:' || btrim(p_iid), v_agent.agent_id, p_key_hash);

  update public.enrollment_tokens set consumed_at = now() where id = v_token.id;

  return jsonb_build_object(
    'status', 'enrolled',
    'user_id', v_token.user_id,
    'tenant_id', v_token.tenant_id,
    'agent_id', v_agent.agent_id,
    'included_agents', v_ent.included_agents,
    'extra_agents', v_ent.extra_agents,
    'allowed_agents', v_agent.allowed_agents,
    'premium_intel', v_ent.premium_intel,
    'premium_correlation', v_ent.premium_correlation,
    'premium_pkg_plugin', v_ent.premium_pkg_plugin,
    'revocation_epoch', v_ent.revocation_epoch
  );
end;
$$;
revoke all on function public.exchange_enrollment_token(text, text, text, text, text) from public, anon, authenticated;
grant execute on function public.exchange_enrollment_token(text, text, text, text, text) to service_role;

-- Device-code claim and enrollment-token persistence must also share one
-- transaction. Failure to insert the token leaves the device code pollable.
create function public.issue_device_enrollment_token(
  p_device_code_hash text,
  p_token_hash text,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_session public.device_sessions%rowtype;
  v_tenant_id uuid;
begin
  if p_device_code_hash is null or p_device_code_hash !~ '^[a-f0-9]{64}$'
     or p_token_hash is null or p_token_hash !~ '^[a-f0-9]{64}$'
     or p_expires_at is null
     or p_expires_at < now() + interval '1 minute'
     or p_expires_at > now() + interval '30 days' then
    raise exception 'invalid device enrollment input' using errcode = '22023';
  end if;

  select d.* into v_session from public.device_sessions d
   where d.device_code_hash = p_device_code_hash for update;
  if not found or v_session.user_id is null or v_session.authorized_at is null
     or v_session.exchanged_at is not null or v_session.expires_at <= now() then
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
revoke all on function public.issue_device_enrollment_token(text, text, timestamptz) from public, anon, authenticated;
grant execute on function public.issue_device_enrollment_token(text, text, timestamptz) to service_role;
