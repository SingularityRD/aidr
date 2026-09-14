-- Bounded overlap rotation for hash-only bearer secrets.
--
-- Renewing an API key or an enrollment token replaces the stored hash and
-- records the retired hash in `previous_hash` / `previous_hash_expires_at` for a
-- bounded window, so a caller that is already mid-request with the old secret is
-- not cut off. The window mirrors the SCIM token overlap
-- (20260912000012_scim_directory.sql): it is time bounded, hard capped, and it
-- can never outlive the retired secret's own expiry, so a rotation never extends
-- a credential's life.
--
-- The device-code rules are untouched. `device-poll` resolves its derived
-- enrollment token by `token_hash` only, so once a device-issued token is
-- rotated the device code can no longer recover it (it now matches only
-- `previous_hash`), while the retired hash stays exchangeable strictly inside
-- its recorded window. Device-code precedence in `_shared/auth.ts` and the
-- atomic exchange in 20260912000017_enrollment_exchange_atomic.sql are
-- preserved.

alter table public.api_keys
  add column if not exists previous_hash text,
  add column if not exists previous_hash_expires_at timestamptz,
  add column if not exists rotated_at timestamptz;

alter table public.enrollment_tokens
  add column if not exists previous_hash text,
  add column if not exists previous_hash_expires_at timestamptz,
  add column if not exists rotated_at timestamptz;

-- The retired hash and its deadline are recorded together or not at all, the
-- deadline is strictly after the rotation, and the window is capped at seven
-- days so a miscomputed overlap cannot park a live credential in the past
-- secret. `rotated_at` alone is allowed: rotating an already expired secret
-- leaves nothing to overlap.
alter table public.api_keys drop constraint if exists api_keys_rotation_window_check;
alter table public.api_keys add constraint api_keys_rotation_window_check check (
  (previous_hash is null and previous_hash_expires_at is null)
  or (previous_hash ~ '^[a-f0-9]{64}$'
      and previous_hash_expires_at is not null
      and rotated_at is not null
      and previous_hash_expires_at > rotated_at
      and previous_hash_expires_at <= rotated_at + interval '7 days')
);

alter table public.enrollment_tokens drop constraint if exists enrollment_tokens_rotation_window_check;
alter table public.enrollment_tokens add constraint enrollment_tokens_rotation_window_check check (
  (previous_hash is null and previous_hash_expires_at is null)
  or (previous_hash ~ '^[a-f0-9]{64}$'
      and previous_hash_expires_at is not null
      and rotated_at is not null
      and previous_hash_expires_at > rotated_at
      and previous_hash_expires_at <= rotated_at + interval '7 days')
);

create index if not exists api_keys_previous_hash_idx
  on public.api_keys (previous_hash) where previous_hash is not null;
create index if not exists enrollment_tokens_previous_hash_idx
  on public.enrollment_tokens (previous_hash) where previous_hash is not null;

-- Only the exchange path learns about the retired hash. An exact `token_hash`
-- match always wins over a retired one, and a retired hash is accepted only
-- while its own recorded deadline is in the future. Consumption, expiry, tenant
-- admission, seat allocation and the hash-only key insert stay in this one
-- transaction exactly as before.
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

  -- FOR UPDATE serializes exchanges of the same token. A waiting caller
  -- rechecks consumed_at after the first transaction commits. The active hash
  -- is ordered first so a retired hash can never shadow the current secret.
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
