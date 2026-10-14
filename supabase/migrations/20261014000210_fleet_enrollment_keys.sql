-- Fleet enrollment keys (C3): one multi-use, team-scoped secret that an
-- administrator puts into the machine policy (MSI property, Intune, GPO,
-- Ansible) so hundreds of machines can enroll without a per-machine browser
-- approval or a per-machine single-use enrollment code.
--
-- Contract:
--   * The plaintext is `aidr_fleet_<43 base64url chars>`, shown once by the
--     `fleet-keys` Edge Function. Only its SHA-256 hash (and a 4-character
--     display hint) is stored.
--   * A key is bound to one tenant and to the owner/admin who created it. The
--     exchange re-checks that this person is still an active owner/admin of an
--     active tenant (directory authority included); demoting or removing them
--     stops the key, exactly like a single-use code.
--   * `seat_cap` bounds how many NEW machines (agents) the key may register.
--     Re-enrolling a machine the tenant already knows does not consume it. The
--     tenant's own seat admission (register_agent_for_ingest and the
--     require_enrollment_admission triggers) is still enforced on every use.
--   * Every key expires (at most 365 days) and can be revoked; a revoked or
--     expired key never resolves. Revoking a key stops new enrollments only:
--     machines it already enrolled keep their own per-machine API keys, which
--     are revoked separately.
--   * Issue, revoke and every enrollment write an admin_audit_logs row in the
--     same transaction; if the audit insert fails, nothing commits.
--   * Writes happen only through the service-role RPCs below. Browsers may read
--     the non-secret columns, and only as an owner/admin of the tenant.

-- ── Table ──────────────────────────────────────────────────────────────────

create table if not exists public.fleet_enrollment_keys (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  created_by uuid not null references auth.users (id) on delete cascade,
  label text,
  key_hash text not null unique,
  key_hint text not null,
  seat_cap integer not null,
  enrolled_count integer not null default 0,
  use_count bigint not null default 0,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz,
  revoked_by uuid,
  constraint fleet_enrollment_keys_hash_format check (key_hash ~ '^[a-f0-9]{64}$'),
  constraint fleet_enrollment_keys_hint_format check (key_hint ~ '^[A-Za-z0-9_-]{4}$'),
  constraint fleet_enrollment_keys_label_check
    check (label is null or (char_length(label) between 1 and 100 and label !~ '[[:cntrl:]]')),
  constraint fleet_enrollment_keys_seat_cap_range check (seat_cap between 1 and 100000),
  constraint fleet_enrollment_keys_enrolled_bounds check (enrolled_count between 0 and seat_cap),
  constraint fleet_enrollment_keys_use_count_nonnegative check (use_count >= 0),
  constraint fleet_enrollment_keys_window
    check (expires_at > created_at and expires_at <= created_at + interval '366 days'),
  constraint fleet_enrollment_keys_revoke_shape check ((revoked_at is null) = (revoked_by is null))
);

comment on table public.fleet_enrollment_keys is
  'Multi-use, seat-capped, expiring, revocable fleet enrollment keys (aidr_fleet_*). Hash-only; written only by service-role RPCs with an admin_audit_logs row; readable by tenant owners/admins.';

create index if not exists fleet_enrollment_keys_tenant_created_idx
  on public.fleet_enrollment_keys (tenant_id, created_at desc);

-- A new key is a new credential: the tenant must be admitted, like api_keys
-- and enrollment_tokens (20260923000028 / 20260923000034).
drop trigger if exists fleet_enrollment_keys_admission on public.fleet_enrollment_keys;
create trigger fleet_enrollment_keys_admission
before insert or update of key_hash on public.fleet_enrollment_keys
for each row execute function public.require_enrollment_admission();

-- ── Row-level security ─────────────────────────────────────────────────────

alter table public.fleet_enrollment_keys enable row level security;
revoke all on public.fleet_enrollment_keys from public, anon, authenticated, service_role;
-- key_hash is never readable from a browser session.
grant select (id, tenant_id, created_by, label, key_hint, seat_cap, enrolled_count, use_count,
  expires_at, created_at, last_used_at, revoked_at, revoked_by)
  on public.fleet_enrollment_keys to authenticated;
grant select on public.fleet_enrollment_keys to service_role;

drop policy if exists fleet_enrollment_keys_admin_select on public.fleet_enrollment_keys;
create policy fleet_enrollment_keys_admin_select on public.fleet_enrollment_keys
  for select to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'));

drop policy if exists fleet_enrollment_keys_admin_restrict on public.fleet_enrollment_keys;
create policy fleet_enrollment_keys_admin_restrict on public.fleet_enrollment_keys
  as restrictive for all to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.fleet_enrollment_keys;
create policy tenant_identity_access_restrict on public.fleet_enrollment_keys
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Authorization helper ───────────────────────────────────────────────────

-- True while p_user_id is an active owner/admin of the active tenant and the
-- tenant's directory authority (if enabled) still grants that membership.
create or replace function app.fleet_key_admin(p_tenant_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
  select exists (
    select 1
      from public.tenant_members m
      join public.tenants t on t.id = m.tenant_id
     where m.tenant_id = p_tenant_id
       and m.user_id = p_user_id
       and m.role in ('owner', 'admin')
       and (m.expires_at is null or m.expires_at > clock_timestamp())
       and t.status = 'active'
       and app.directory_membership_grants(m.tenant_id, m.user_id, m.role)
  );
$$;
revoke all on function app.fleet_key_admin(uuid, uuid) from public, anon, authenticated, service_role;

-- ── Issue ──────────────────────────────────────────────────────────────────

create or replace function public.issue_fleet_enrollment_key_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_label text,
  p_seat_cap integer,
  p_ttl_days integer,
  p_key_hash text,
  p_key_hint text
) returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_id uuid;
  v_expires_at timestamptz;
  v_active integer;
begin
  if p_actor_user_id is null or p_tenant_id is null
     or p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$'
     or p_key_hint is null or p_key_hint !~ '^[A-Za-z0-9_-]{4}$'
     or p_seat_cap is null or p_seat_cap not between 1 and 100000
     or p_ttl_days is null or p_ttl_days not between 1 and 365
     or (p_label is not null and (char_length(p_label) not between 1 and 100 or p_label ~ '[[:cntrl:]]')) then
    raise exception 'invalid_fleet_enrollment_key_issue' using errcode = '22023';
  end if;
  if not app.fleet_key_admin(p_tenant_id, p_actor_user_id) then
    return jsonb_build_object('status', 'forbidden');
  end if;

  -- A retried call whose first response was lost answers with the same row
  -- (one key, one audit entry) instead of minting a second key.
  select k.id, k.expires_at into v_id, v_expires_at from public.fleet_enrollment_keys k
   where k.key_hash = p_key_hash and k.tenant_id = p_tenant_id
     and k.created_by = p_actor_user_id and k.revoked_at is null;
  if v_id is not null then
    return jsonb_build_object('status', 'issued', 'id', v_id, 'expires_at', v_expires_at);
  end if;

  -- Serialize issuance per tenant so the active-key bound cannot be raced.
  perform pg_advisory_xact_lock(hashtextextended('fleet_enrollment_keys:' || p_tenant_id::text, 0));
  select count(*)::integer into v_active from public.fleet_enrollment_keys k
   where k.tenant_id = p_tenant_id and k.revoked_at is null and k.expires_at > clock_timestamp();
  if v_active >= 50 then
    return jsonb_build_object('status', 'too_many_active_keys', 'active_keys', v_active);
  end if;

  v_expires_at := clock_timestamp() + make_interval(days => p_ttl_days);
  insert into public.fleet_enrollment_keys
    (tenant_id, created_by, label, key_hash, key_hint, seat_cap, expires_at, created_at)
  values (p_tenant_id, p_actor_user_id, p_label, p_key_hash, p_key_hint, p_seat_cap,
    v_expires_at, clock_timestamp())
  on conflict (key_hash) do nothing
  returning id into v_id;
  if v_id is null then
    return jsonb_build_object('status', 'hash_conflict');
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
  values (p_actor_user_id, p_tenant_id, 'fleet_key.create', p_actor_user_id,
    jsonb_build_object('id', v_id, 'label', p_label, 'seat_cap', p_seat_cap,
      'ttl_days', p_ttl_days, 'expires_at', v_expires_at, 'key_hint', p_key_hint));
  return jsonb_build_object('status', 'issued', 'id', v_id, 'expires_at', v_expires_at);
end;
$$;

-- ── Revoke ─────────────────────────────────────────────────────────────────

create or replace function public.revoke_fleet_enrollment_key_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_id uuid
) returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_key public.fleet_enrollment_keys%rowtype;
  v_now timestamptz := clock_timestamp();
begin
  if p_actor_user_id is null or p_tenant_id is null or p_id is null then
    raise exception 'invalid_fleet_enrollment_key_revocation' using errcode = '22023';
  end if;
  if not app.fleet_key_admin(p_tenant_id, p_actor_user_id) then
    return jsonb_build_object('status', 'forbidden');
  end if;
  select k.* into v_key from public.fleet_enrollment_keys k
   where k.id = p_id and k.tenant_id = p_tenant_id
   for update;
  if not found then return jsonb_build_object('status', 'not_found'); end if;
  -- Idempotent: a retried revoke answers with the original revocation.
  if v_key.revoked_at is not null then
    return jsonb_build_object('status', 'revoked', 'id', p_id, 'revoked_at', v_key.revoked_at);
  end if;

  update public.fleet_enrollment_keys
     set revoked_at = v_now, revoked_by = p_actor_user_id
   where id = p_id;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
  values (p_actor_user_id, p_tenant_id, 'fleet_key.revoke', v_key.created_by,
    jsonb_build_object('id', p_id, 'label', v_key.label, 'enrolled_count', v_key.enrolled_count,
      'use_count', v_key.use_count));
  return jsonb_build_object('status', 'revoked', 'id', p_id, 'revoked_at', v_now);
end;
$$;

-- ── Resolve (pre-exchange rate-limit bucket) ───────────────────────────────

-- Same acceptance rule as the exchange, without locking or writing. The Edge
-- Function picks its per-key rate-limit bucket from the result, so a guessed
-- bearer value can never choose a bucket.
create or replace function public.resolve_fleet_enrollment_key(p_key_hash text)
returns jsonb
language plpgsql stable security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare v_key public.fleet_enrollment_keys%rowtype;
begin
  if p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$' then return null; end if;
  select k.* into v_key from public.fleet_enrollment_keys k where k.key_hash = p_key_hash;
  if not found or v_key.revoked_at is not null or v_key.expires_at <= clock_timestamp() then
    return null;
  end if;
  if not app.fleet_key_admin(v_key.tenant_id, v_key.created_by) then return null; end if;
  return jsonb_build_object('key_id', v_key.id, 'tenant_id', v_key.tenant_id,
    'user_id', v_key.created_by);
end;
$$;

-- ── Exchange ───────────────────────────────────────────────────────────────

-- Mirrors exchange_enrollment_token (20260915000000): validation, tenant
-- admission, seat allocation and the hash-only API-key insert commit together.
-- The fleet key is not consumed; its row lock serializes concurrent uses so the
-- seat cap cannot be overrun.
create or replace function public.exchange_fleet_enrollment_key(
  p_fleet_key_hash text,
  p_iid text,
  p_agent_runtime text,
  p_agent_runtime_version text,
  p_key_hash text
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_key public.fleet_enrollment_keys%rowtype;
  v_ent public.entitlements%rowtype;
  v_agent record;
  v_iid text;
begin
  if p_fleet_key_hash is null or p_fleet_key_hash !~ '^[a-f0-9]{64}$'
     or p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$'
     or p_iid is null or length(btrim(p_iid)) not between 1 and 128
     or p_iid ~ '[[:cntrl:]]'
     or (p_agent_runtime is not null and (length(p_agent_runtime) > 128 or p_agent_runtime ~ '[[:cntrl:]]'))
     or (p_agent_runtime_version is not null and (length(p_agent_runtime_version) > 128 or p_agent_runtime_version ~ '[[:cntrl:]]')) then
    raise exception 'invalid fleet enrollment exchange input' using errcode = '22023';
  end if;
  v_iid := btrim(p_iid);

  select k.* into v_key from public.fleet_enrollment_keys k
   where k.key_hash = p_fleet_key_hash
   for update;
  if not found or v_key.revoked_at is not null or v_key.expires_at <= clock_timestamp() then
    return jsonb_build_object('status', 'invalid_token');
  end if;
  if not app.fleet_key_admin(v_key.tenant_id, v_key.created_by) then
    return jsonb_build_object('status', 'tenant_not_authorized');
  end if;

  select e.* into v_ent from public.entitlements e where e.tenant_id = v_key.tenant_id;
  if not found then
    return jsonb_build_object('status', 'missing_entitlements');
  end if;

  -- A machine the tenant already knows re-enrolls without using the cap.
  if v_key.enrolled_count >= v_key.seat_cap and not exists (
    select 1 from public.agents a where a.tenant_id = v_key.tenant_id and a.iid = v_iid
  ) then
    return jsonb_build_object('status', 'fleet_key_exhausted',
      'seat_cap', v_key.seat_cap, 'enrolled_count', v_key.enrolled_count);
  end if;

  select * into v_agent from public.register_agent_for_ingest(
    p_user_id => v_key.created_by,
    p_iid => v_iid,
    p_agent_runtime => p_agent_runtime,
    p_agent_runtime_version => p_agent_runtime_version,
    p_tenant_id => v_key.tenant_id
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
  if v_agent.created and v_key.enrolled_count >= v_key.seat_cap then
    -- The pre-check saw an existing agent that disappeared before the tenant
    -- lock; never exceed the cap.
    raise exception 'fleet_key_exhausted' using errcode = '40001';
  end if;

  select e.* into v_ent from public.entitlements e where e.tenant_id = v_key.tenant_id;
  if not found then
    raise exception 'entitlements disappeared during enrollment';
  end if;

  insert into public.api_keys (user_id, tenant_id, label, agent_id, key_hash)
  values (v_key.created_by, v_key.tenant_id, left('fleet:' || v_iid, 100), v_agent.agent_id, p_key_hash);

  update public.fleet_enrollment_keys
     set use_count = use_count + 1,
         enrolled_count = enrolled_count + case when v_agent.created then 1 else 0 end,
         last_used_at = clock_timestamp()
   where id = v_key.id;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
  values (v_key.created_by, v_key.tenant_id, 'fleet_key.enroll', v_key.created_by,
    jsonb_build_object('fleet_key_id', v_key.id, 'iid', v_iid, 'agent_id', v_agent.agent_id,
      'new_agent', v_agent.created, 'agent_runtime', p_agent_runtime));

  return jsonb_build_object(
    'status', 'enrolled',
    'user_id', v_key.created_by,
    'tenant_id', v_key.tenant_id,
    'agent_id', v_agent.agent_id,
    'fleet_key_id', v_key.id,
    'new_agent', v_agent.created,
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

revoke all on function public.issue_fleet_enrollment_key_with_audit(uuid, uuid, text, integer, integer, text, text)
  from public, anon, authenticated;
revoke all on function public.revoke_fleet_enrollment_key_with_audit(uuid, uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.resolve_fleet_enrollment_key(text)
  from public, anon, authenticated;
revoke all on function public.exchange_fleet_enrollment_key(text, text, text, text, text)
  from public, anon, authenticated;
grant execute on function public.issue_fleet_enrollment_key_with_audit(uuid, uuid, text, integer, integer, text, text)
  to service_role;
grant execute on function public.revoke_fleet_enrollment_key_with_audit(uuid, uuid, uuid)
  to service_role;
grant execute on function public.resolve_fleet_enrollment_key(text) to service_role;
grant execute on function public.exchange_fleet_enrollment_key(text, text, text, text, text)
  to service_role;

-- ── Rate-limit scope for key issuance ──────────────────────────────────────

-- Same in-place extension as 20261009000200_rate_limit_api_key_scopes. The
-- exchange itself charges the already admitted `enroll` scope.
do $migration$
declare
  v_definition text;
  v_old text := '''api-key'', ''version-check''';
begin
  select pg_get_functiondef('public.increment_rate_limit(text,bigint,integer)'::regprocedure) into v_definition;
  if position('''fleetkey_create''' in v_definition) > 0 then return; end if;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_rate_limit_scope_definition';
  end if;
  execute replace(v_definition, v_old, v_old || ', ''fleetkey_create''');
end
$migration$;
