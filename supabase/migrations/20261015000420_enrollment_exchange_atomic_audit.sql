-- SEC-4: the one-time enrollment-token exchange minted a device API key and
-- consumed the token without an audit row; the enroll route wrote
-- 'enroll.consume_token' afterwards as a best-effort insert whose failure was
-- ignored, so a key could be issued with no audit trail. The fleet-key path
-- (exchange_fleet_enrollment_key) already audits in its own transaction.
--
-- Also: the token creator's membership was re-checked without a role filter,
-- so a creator later demoted to viewer could still spend an outstanding token
-- to take a seat (enrollment-tokens only lets owner/admin/member create them).
--
-- Body otherwise unchanged from 20260915000000_key_rotation_overlap.sql.

create or replace function public.exchange_enrollment_token(
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

  select t.* into v_token
    from public.enrollment_tokens t
   where t.token_hash = p_token_hash
      or (t.previous_hash = p_token_hash
          and t.previous_hash_expires_at is not null
          and t.previous_hash_expires_at > now())
   order by (t.token_hash = p_token_hash) desc
   for update;
  if not found or v_token.consumed_at is not null or v_token.expires_at <= now() then
    return jsonb_build_object('status', 'invalid_token');
  end if;

  -- The creator must still hold a role that may enroll devices.
  if not exists (
    select 1 from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = v_token.tenant_id
     and m.user_id = v_token.user_id
     and m.role in ('owner', 'admin', 'member')
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

  select e.* into v_ent from public.entitlements e
   where e.tenant_id = v_token.tenant_id;
  if not found then
    raise exception 'entitlements disappeared during enrollment';
  end if;

  insert into public.api_keys (user_id, tenant_id, label, agent_id, key_hash)
  values (v_token.user_id, v_token.tenant_id, 'enroll:' || btrim(p_iid), v_agent.agent_id, p_key_hash);

  update public.enrollment_tokens set consumed_at = now() where id = v_token.id;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
  values (v_token.user_id, v_token.tenant_id, 'enroll.consume_token', v_token.user_id,
    jsonb_build_object('enrollment_token_id', v_token.id, 'iid', btrim(p_iid),
      'agent_id', v_agent.agent_id, 'new_agent', v_agent.created,
      'agent_runtime', p_agent_runtime));

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
