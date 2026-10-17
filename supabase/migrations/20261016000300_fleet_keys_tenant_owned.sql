-- Fleet-enrolled device credentials belong to the tenant, not to a person.
--
-- Defect: exchange_fleet_enrollment_key (20261014000210) minted every device's
-- API key with user_id = the administrator who created the fleet key. Removing
-- or downgrading that person (app.revoke_member_api_keys, 20260923000047) or
-- SCIM-deprovisioning them (app.scim_deprovision_device_access,
-- 20261014000120) revokes every API key carrying their user_id, and API-key
-- authentication also required that person's membership to be active. One IT
-- administrator leaving took the whole fleet off policy, ingest and approvals
-- and forced every machine to re-enroll.
--
-- Contract from here on:
--   * A device key minted through a fleet enrollment key is TENANT-OWNED:
--     api_keys.user_id is NULL and api_keys.fleet_key_id names the fleet key
--     (same tenant, enforced by a composite foreign key). The key is bound to
--     its agent, as before.
--   * A tenant-owned key authenticates while it is not revoked, its tenant is
--     active (and admitted) and its fleet key is NOT revoked. It does not
--     depend on any person's membership, so membership removal, role changes
--     and SCIM deprovisioning (which match api_keys.user_id) never touch it.
--     Fleet-key expiry ends new enrollments only; enrolled devices keep
--     working until the key is revoked.
--   * Revoking the fleet key revokes every device key it minted, in the same
--     transaction (and authentication re-checks the fleet key, fail closed).
--     Revoking the device key, retiring the agent, suspending or offboarding
--     the tenant stop it exactly as before.
--   * New enrollments still require the fleet key's issuer to be an active
--     owner/admin (app.fleet_key_admin, unchanged): a departed administrator's
--     key cannot keep admitting new machines. Another administrator issues a
--     replacement key for the machine policy.
--   * Personal keys (user_id set, fleet_key_id NULL) keep today's behaviour.
--   * Deleting the issuer's auth account no longer deletes the fleet key row
--     (created_by becomes NULL). Agents still record the enrolling person in
--     agents.user_id (seat and event attribution), and that column keeps its
--     ON DELETE CASCADE: remove a leaver's membership, do not delete their
--     auth account, while their fleet devices are in service
--     (docs/operations/offboarding.md).
--   * Machine-side RPCs that previously joined the key owner's membership now
--     accept a tenant-owned key through app.fleet_device_key_active: policy
--     receipts, fleet-response delivery, approval requests, admission reads and
--     installer-download audit.
--
-- Backfill: existing fleet-minted keys (agent-bound, labelled `fleet:<iid>`,
-- with a matching fleet_key.enroll audit row from the same fleet key and
-- creator) are converted in place. A key that was already revoked stays
-- revoked; a revoked secret is never revived.

-- ── Schema ────────────────────────────────────────────────────────────────

alter table public.fleet_enrollment_keys alter column created_by drop not null;
alter table public.fleet_enrollment_keys drop constraint if exists fleet_enrollment_keys_created_by_fkey;
alter table public.fleet_enrollment_keys add constraint fleet_enrollment_keys_created_by_fkey
  foreign key (created_by) references auth.users (id) on delete set null;
alter table public.fleet_enrollment_keys
  add constraint fleet_enrollment_keys_id_tenant_unique unique (id, tenant_id);

alter table public.api_keys alter column user_id drop not null;
alter table public.api_keys add column if not exists fleet_key_id uuid;
alter table public.api_keys add constraint api_keys_fleet_key_fkey
  foreign key (fleet_key_id, tenant_id) references public.fleet_enrollment_keys (id, tenant_id)
  on delete cascade;
create index if not exists api_keys_fleet_key_idx on public.api_keys (fleet_key_id)
  where fleet_key_id is not null;
-- Exactly one owner: a person, or the tenant through one fleet key. A
-- tenant-owned key is always a full, agent-bound device key.
alter table public.api_keys add constraint api_keys_owner_shape check (
  (fleet_key_id is null and user_id is not null)
  or (fleet_key_id is not null and user_id is null and agent_id is not null and scope = 'tenant')
) not valid;

comment on column public.api_keys.fleet_key_id is
  'Set for a tenant-owned device key minted by exchange_fleet_enrollment_key (user_id is then NULL). Revoked with its fleet key, never with a person''s membership.';

-- ── Tenant-owned key authority ────────────────────────────────────────────

-- True while the tenant is active and the fleet key is not revoked. Takes a
-- share lock on the fleet key so a concurrent fleet-key revocation (which locks
-- the key FOR UPDATE before revoking its device keys) is serialized with the
-- caller's use of the key.
create or replace function app.fleet_device_key_active(p_tenant_id uuid, p_fleet_key_id uuid)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if p_tenant_id is null or p_fleet_key_id is null then return false; end if;
  perform 1 from public.tenants t where t.id = p_tenant_id and t.status = 'active' for share;
  if not found then return false; end if;
  perform 1 from public.fleet_enrollment_keys f
   where f.id = p_fleet_key_id and f.tenant_id = p_tenant_id and f.revoked_at is null
   for share;
  return found;
end;
$$;
revoke all on function app.fleet_device_key_active(uuid, uuid)
  from public, anon, authenticated, service_role;

-- Issue/rotation: a person's key still needs its owner's active membership; a
-- tenant-owned key needs an unrevoked fleet key of the same tenant. The same
-- trigger guards public.enrollment_tokens, which has no fleet_key_id column, so
-- the field is read through to_jsonb (a direct NEW.fleet_key_id reference fails
-- on that table).
create or replace function app.require_credential_member()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
declare
  v_fleet_key_id uuid := (to_jsonb(new) ->> 'fleet_key_id')::uuid;
begin
  if v_fleet_key_id is not null then
    if new.user_id is not null or not app.fleet_device_key_active(new.tenant_id, v_fleet_key_id) then
      raise exception 'api_key_fleet_key_inactive' using errcode = '42501';
    end if;
    return new;
  end if;
  perform 1 from public.tenant_members m
    where m.tenant_id = new.tenant_id and m.user_id = new.user_id
      and m.role in ('owner', 'admin', 'member')
      and (m.expires_at is null or m.expires_at > clock_timestamp())
    for share;
  if not found then
    raise exception 'api_key_member_inactive' using errcode = '42501';
  end if;
  return new;
end;
$$;

-- A tenant-owned key binds to an agent of its tenant; a personal key still
-- binds only to its owner's agent.
create or replace function app.protect_api_key_agent_binding() returns trigger
language plpgsql set search_path = public, pg_temp as $$
begin
  if current_user in ('authenticated','anon') and (new.agent_id is not null or (tg_op='UPDATE' and old.agent_id is not null)) then
    raise exception 'agent_key_binding_is_server_managed' using errcode='42501';
  end if;
  if new.agent_id is not null and not exists(
    select 1 from public.agents
     where id = new.agent_id and tenant_id = new.tenant_id
       and (new.fleet_key_id is not null or user_id = new.user_id)
  ) then
    raise exception 'agent_key_owner_mismatch' using errcode='23514';
  end if;
  return new;
end;
$$;

-- ── Backfill ──────────────────────────────────────────────────────────────

with matched as (
  select distinct on (k.id) k.id as api_key_id, f.id as fleet_key_id
    from public.api_keys k
    join public.admin_audit_logs a
      on a.tenant_id = k.tenant_id and a.action = 'fleet_key.enroll'
     and a.detail ->> 'agent_id' = k.agent_id::text
     and left('fleet:' || (a.detail ->> 'iid'), 100) = k.label
    join public.fleet_enrollment_keys f
      on f.id::text = a.detail ->> 'fleet_key_id' and f.tenant_id = k.tenant_id
     and f.created_by = k.user_id
   where k.fleet_key_id is null and k.agent_id is not null and k.scope = 'tenant'
     and k.label like 'fleet:%'
   order by k.id, abs(extract(epoch from (a.created_at - k.created_at))), a.created_at desc
)
update public.api_keys k
   set fleet_key_id = m.fleet_key_id, user_id = null
  from matched m
 where k.id = m.api_key_id;

alter table public.api_keys validate constraint api_keys_owner_shape;

-- Ownership is decided once, at mint time.
create or replace function app.api_key_fleet_owner_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public, pg_temp as $$
begin
  if new.fleet_key_id is distinct from old.fleet_key_id then
    raise exception 'api_key_owner_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.api_key_fleet_owner_immutable() from public, anon, authenticated, service_role;
drop trigger if exists api_keys_fleet_owner_immutable on public.api_keys;
create trigger api_keys_fleet_owner_immutable
before update of fleet_key_id on public.api_keys
for each row execute function app.api_key_fleet_owner_immutable();

-- ── Fleet key revoke: its devices stop ────────────────────────────────────

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
  v_devices integer := 0;
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
  -- The tenant-owned device keys this fleet key minted stop with it. The
  -- retired overlap hash is cleared so a renewed key cannot be replayed.
  update public.api_keys
     set revoked = true, previous_hash = null, previous_hash_expires_at = null
   where fleet_key_id = p_id and tenant_id = p_tenant_id and not revoked;
  get diagnostics v_devices = row_count;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
  values (p_actor_user_id, p_tenant_id, 'fleet_key.revoke', v_key.created_by,
    jsonb_build_object('id', p_id, 'label', v_key.label, 'enrolled_count', v_key.enrolled_count,
      'use_count', v_key.use_count, 'device_keys_revoked', v_devices));
  return jsonb_build_object('status', 'revoked', 'id', p_id, 'revoked_at', v_now,
    'device_keys_revoked', v_devices);
end;
$$;

-- ── Exchange: mint a tenant-owned device key ──────────────────────────────

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
  -- New enrollments still need an active owner/admin issuer.
  if v_key.created_by is null or not app.fleet_key_admin(v_key.tenant_id, v_key.created_by) then
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
    raise exception 'fleet_key_exhausted' using errcode = '40001';
  end if;

  select e.* into v_ent from public.entitlements e where e.tenant_id = v_key.tenant_id;
  if not found then
    raise exception 'entitlements disappeared during enrollment';
  end if;

  -- Tenant-owned: no person's membership decides this credential's life.
  insert into public.api_keys (user_id, tenant_id, label, agent_id, key_hash, fleet_key_id)
  values (null, v_key.tenant_id, left('fleet:' || v_iid, 100), v_agent.agent_id, p_key_hash, v_key.id);

  update public.fleet_enrollment_keys
     set use_count = use_count + 1,
         enrolled_count = enrolled_count + case when v_agent.created then 1 else 0 end,
         last_used_at = clock_timestamp()
   where id = v_key.id;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
  values (v_key.created_by, v_key.tenant_id, 'fleet_key.enroll', v_key.created_by,
    jsonb_build_object('fleet_key_id', v_key.id, 'iid', v_iid, 'agent_id', v_agent.agent_id,
      'new_agent', v_agent.created, 'agent_runtime', p_agent_runtime, 'key_owner', 'tenant'));

  -- user_id names the issuing administrator for the enrollment response's
  -- admission read; the minted key itself is owned by the tenant.
  return jsonb_build_object(
    'status', 'enrolled',
    'user_id', v_key.created_by,
    'key_owner', 'tenant',
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

-- ── Admission and installer audit for tenant-owned keys ───────────────────

-- get_tenant_admission(tenant, user) reads a person's membership. A
-- tenant-owned device key has none; its admission is the tenant's, with no
-- trial offer (a machine never starts a trial).
create or replace function public.get_fleet_device_admission(p_api_key_id uuid)
returns jsonb
language plpgsql volatile security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_key public.api_keys%rowtype;
  v_mode text;
  v_row public.tenant_admissions%rowtype;
  v_capacity integer;
  v_status text := 'none';
  v_kind text;
begin
  select mode into v_mode from app.tenant_admission_config where singleton;
  select k.* into v_key from public.api_keys k where k.id = p_api_key_id;
  if not found or v_key.revoked or v_key.fleet_key_id is null
     or not app.fleet_device_key_active(v_key.tenant_id, v_key.fleet_key_id) then
    return jsonb_build_object('mode', coalesce(v_mode, 'unconfigured'),
      'status', 'forbidden', 'access_kind', null, 'allowed_agents', 0,
      'expires_at', null, 'trial_available', false);
  end if;
  v_capacity := public.tenant_admission_capacity(v_key.tenant_id);
  if v_mode = 'pilot' then
    v_kind := case when exists (
      select 1 from public.pilot_applications p
      where p.tenant_id = v_key.tenant_id and p.status = 'approved'
    ) then 'pilot' else null end;
    v_status := case when v_capacity > 0 then 'active' else 'not_entitled' end;
  elsif v_mode in ('cloud', 'onprem') then
    select * into v_row from public.tenant_admissions where tenant_id = v_key.tenant_id;
    if found then
      v_kind := v_row.kind;
      v_status := case when v_row.revoked_at is not null then 'revoked'
        when v_row.expires_at <= clock_timestamp() then 'expired'
        when v_capacity > 0 then 'active' else 'not_entitled' end;
    end if;
  else
    v_status := 'unconfigured';
  end if;
  return jsonb_build_object('mode', coalesce(v_mode, 'unconfigured'),
    'status', v_status, 'access_kind', v_kind,
    'allowed_agents', v_capacity,
    'expires_at', case when v_mode <> 'pilot' then v_row.expires_at else null end,
    'trial_available', false);
end;
$$;
revoke all on function public.get_fleet_device_admission(uuid) from public, anon, authenticated;
grant execute on function public.get_fleet_device_admission(uuid) to service_role;

create or replace function public.record_fleet_device_installer_download(
  p_api_key_id uuid,
  p_tenant_id uuid,
  p_version text,
  p_platform text,
  p_file_name text,
  p_sha256 text,
  p_format text default null
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_key public.api_keys%rowtype;
begin
  if p_api_key_id is null or p_tenant_id is null
     or p_version is null or p_version !~ '^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}(-[0-9A-Za-z.-]{1,64})?$'
     or p_platform is null
     or p_platform not in ('windows-x64', 'windows-arm64', 'linux-x64', 'linux-arm64')
     or p_file_name is null or p_file_name !~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$'
     or p_sha256 is null or p_sha256 !~ '^[0-9a-f]{64}$'
     or (p_format is not null and p_format !~ '^[a-z0-9.]{1,16}$') then
    raise exception 'invalid_installer_download' using errcode = '22023';
  end if;
  select k.* into v_key from public.api_keys k
   where k.id = p_api_key_id and k.tenant_id = p_tenant_id for share;
  if not found or v_key.revoked or v_key.fleet_key_id is null
     or not app.fleet_device_key_active(p_tenant_id, v_key.fleet_key_id) then
    return jsonb_build_object('status', 'forbidden');
  end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
    values (null, p_tenant_id, 'installer.download', null,
      jsonb_strip_nulls(jsonb_build_object('version', p_version, 'platform', p_platform,
        'format', p_format, 'file', p_file_name, 'sha256', p_sha256,
        'api_key_id', p_api_key_id, 'fleet_key_id', v_key.fleet_key_id, 'key_owner', 'tenant')));
  return jsonb_build_object('status', 'recorded');
end;
$$;
revoke all on function public.record_fleet_device_installer_download(uuid, uuid, text, text, text, text, text)
  from public, anon, authenticated;
grant execute on function public.record_fleet_device_installer_download(uuid, uuid, text, text, text, text, text)
  to service_role;

-- ── Approval requests from tenant-owned keys ──────────────────────────────

-- A tenant-owned device files a request as its key (requested_key_id), not
-- as a person. Either a requester or the key must be recorded.
alter table public.approval_requests alter column requested_by drop not null;
alter table public.approval_requests add constraint approval_requests_requester_present
  check (requested_by is not null or requested_key_id is not null);

create or replace function public.create_approval_request(
  p_tenant_id uuid,
  p_requester_user_id uuid,
  p_api_key_id uuid,
  p_bound_agent_id uuid,
  p_iid text,
  p_agent_runtime text,
  p_action_id text,
  p_artifact_digest text,
  p_tool text,
  p_threat_ids text[],
  p_summary text,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_agent uuid;
  v_row public.approval_requests;
  v_pending integer;
  v_key public.api_keys%rowtype;
begin
  if p_tenant_id is null or (p_requester_user_id is null and p_api_key_id is null)
     or p_iid is null or p_action_id is null
     or p_artifact_digest is null or p_tool is null or p_threat_ids is null or p_summary is null
     or p_expires_at is null then
    raise exception 'invalid_approval_request' using errcode = '22023';
  end if;
  -- What the approver reads must be what it looks like.
  if not app.approval_text_displayable(p_summary)
     or not app.approval_text_displayable(p_tool)
     or not app.approval_text_displayable(p_iid) then
    raise exception 'invalid_approval_request_text' using errcode = '22023';
  end if;
  -- The handler bounds expires_at by its own clock; allow one minute of skew.
  if p_expires_at <= v_now or p_expires_at > v_now + interval '31 minutes' then
    raise exception 'invalid_approval_expiry' using errcode = '22023';
  end if;

  perform 1 from public.tenants where id = p_tenant_id and status = 'active' for share;
  if not found then
    raise exception 'approval_tenant_inactive' using errcode = '42501';
  end if;
  if p_requester_user_id is null then
    -- Tenant-owned device key: the key, its agent binding and its fleet key
    -- are the requester's authority.
    select k.* into v_key from public.api_keys k
     where k.id = p_api_key_id and k.tenant_id = p_tenant_id
     for share;
    if not found or v_key.revoked or v_key.fleet_key_id is null or v_key.user_id is not null
       or v_key.agent_id is distinct from p_bound_agent_id
       or not app.fleet_device_key_active(p_tenant_id, v_key.fleet_key_id) then
      raise exception 'approval_requester_forbidden' using errcode = '42501';
    end if;
  else
    perform 1 from public.tenant_members m
     where m.tenant_id = p_tenant_id and m.user_id = p_requester_user_id
       and m.role in ('owner', 'admin', 'member')
       and (m.expires_at is null or m.expires_at > v_now)
     for share of m;
    if not found then
      raise exception 'approval_requester_forbidden' using errcode = '42501';
    end if;
  end if;

  select a.id into v_agent from public.agents a where a.tenant_id = p_tenant_id and a.iid = p_iid;
  -- An agent-bound key files requests only for its own installation.
  if p_bound_agent_id is not null and v_agent is distinct from p_bound_agent_id then
    raise exception 'approval_agent_mismatch' using errcode = '42501';
  end if;

  select * into v_row from public.approval_requests
   where tenant_id = p_tenant_id and iid = p_iid and action_id = p_action_id;
  if not found then
    select count(*) into v_pending from public.approval_requests
     where tenant_id = p_tenant_id and status = 'pending' and expires_at > v_now;
    if v_pending >= 500 then
      raise exception 'approval_request_quota' using errcode = '54000';
    end if;
    insert into public.approval_requests (
      tenant_id, iid, agent_id, agent_runtime, action_id, artifact_digest, tool, threat_ids,
      summary, requested_by, requested_key_id, expires_at, created_at
    ) values (
      p_tenant_id, p_iid, v_agent, p_agent_runtime, p_action_id, p_artifact_digest, p_tool,
      p_threat_ids, p_summary, p_requester_user_id, p_api_key_id, p_expires_at, v_now
    )
    on conflict (tenant_id, iid, action_id) do nothing
    returning * into v_row;
    if found then
      perform app.approval_audit(p_tenant_id, p_requester_user_id, 'approval.requested',
        jsonb_build_object(
          'request_id', v_row.id,
          'iid', v_row.iid,
          'agent_id', v_row.agent_id,
          'action_id', v_row.action_id,
          'artifact_digest', v_row.artifact_digest,
          'tool', v_row.tool,
          'threat_ids', to_jsonb(v_row.threat_ids),
          'expires_at', v_row.expires_at,
          'api_key_id', p_api_key_id
        ));
      return jsonb_build_object('request_id', v_row.id, 'status', 'pending', 'created', true);
    end if;
    -- A concurrent request for the same action won the insert.
    select * into v_row from public.approval_requests
     where tenant_id = p_tenant_id and iid = p_iid and action_id = p_action_id;
  end if;

  -- Idempotent replay: the same action must name the same subject, down to the
  -- text the approver reads. A differing replay is a conflict, never a merge.
  if v_row.artifact_digest <> p_artifact_digest or v_row.tool <> p_tool
     or v_row.summary is distinct from p_summary
     or v_row.threat_ids is distinct from p_threat_ids
     or v_row.agent_runtime is distinct from p_agent_runtime then
    raise exception 'approval_request_conflict' using errcode = '23505';
  end if;
  return jsonb_build_object(
    'request_id', v_row.id,
    'status', case when v_row.status = 'pending' and v_row.expires_at <= v_now then 'expired' else v_row.status end,
    'created', false
  );
end;
$$;

-- The poll is bound by tenant and agent; a tenant-owned key has no person to name.
create or replace function public.read_approval_request_for_agent(
  p_request_id uuid,
  p_tenant_id uuid,
  p_bound_agent_id uuid,
  p_requester_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_row public.approval_requests;
begin
  if p_request_id is null or p_tenant_id is null
     or (p_requester_user_id is null and p_bound_agent_id is null) then
    raise exception 'invalid_approval_poll' using errcode = '22023';
  end if;
  select * into v_row from public.approval_requests
   where id = p_request_id and tenant_id = p_tenant_id
   for update;
  if not found then return null; end if;
  if p_bound_agent_id is not null and v_row.agent_id is distinct from p_bound_agent_id then
    return null;
  end if;

  if v_row.status = 'pending' and v_row.expires_at <= v_now then
    update public.approval_requests set status = 'expired' where id = v_row.id
    returning * into v_row;
    perform app.approval_audit(p_tenant_id, null, 'approval.expired',
      jsonb_build_object('request_id', v_row.id, 'action_id', v_row.action_id, 'iid', v_row.iid));
  elsif v_row.status in ('approved', 'denied') and v_row.token_delivered_at is null then
    update public.approval_requests set token_delivered_at = v_now where id = v_row.id
    returning * into v_row;
    perform app.approval_audit(p_tenant_id, p_requester_user_id, 'approval.token_delivered',
      jsonb_build_object(
        'request_id', v_row.id,
        'action_id', v_row.action_id,
        'iid', v_row.iid,
        'decision', v_row.status,
        'key_id', v_row.key_id,
        'token_expires_at', v_row.token_expires_at
      ));
  end if;

  if v_row.status in ('approved', 'denied') then
    return jsonb_build_object(
      'request_id', v_row.id,
      'status', v_row.status,
      'token', v_row.token,
      'key_id', v_row.key_id,
      'token_expires_at', v_row.token_expires_at
    );
  end if;
  return jsonb_build_object('request_id', v_row.id, 'status', v_row.status);
end;
$$;

-- ── Policy receipts ───────────────────────────────────────────────────────

create or replace function public.record_policy_receipt(p_key_hash text, p_version bigint, p_policy_sha256 text)
returns boolean language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_key public.api_keys;
  v_recorded boolean;
  v_batch public.policy_rollout_batches%rowtype;
  v_rollout public.policy_rollouts%rowtype;
begin
  select * into v_key from public.api_keys
   where not revoked and (key_hash = p_key_hash
      or (previous_hash = p_key_hash and previous_hash_expires_at > now()))
   order by (key_hash = p_key_hash) desc limit 1 for share;
  if not found or v_key.agent_id is null then return false; end if;
  if v_key.fleet_key_id is not null then
    if not app.fleet_device_key_active(v_key.tenant_id, v_key.fleet_key_id) then return false; end if;
  elsif not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
     where m.user_id = v_key.user_id and m.tenant_id = v_key.tenant_id
       and (m.expires_at is null or m.expires_at > now()) and t.status = 'active'
  ) then return false; end if;
  if p_policy_sha256 is null or p_policy_sha256 !~ '^[a-f0-9]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_key.tenant_id::text, 911));
  if not exists (select 1 from public.runtime_policy_revisions
    where tenant_id = v_key.tenant_id and version = p_version
      and encode(sha256(convert_to(app.policy_rollout_canonical_json(policy), 'UTF8')), 'hex') = p_policy_sha256
  ) then return false; end if;
  if p_version is distinct from coalesce((select version from public.agent_policy_assignments
       where tenant_id = v_key.tenant_id and agent_id = v_key.agent_id),
      (select version from public.tenant_runtime_policies where tenant_id = v_key.tenant_id), 0) then return false; end if;

  insert into public.agent_policy_receipts(tenant_id, agent_id, version, policy_sha256)
  values (v_key.tenant_id, v_key.agent_id, p_version, p_policy_sha256)
  on conflict (agent_id) do update
    set version = excluded.version, policy_sha256 = excluded.policy_sha256, received_at = now();
  v_recorded := found;
  if not v_recorded then return false; end if;

  select r.* into v_rollout
    from public.policy_rollouts r
    join public.policy_rollout_batches b
      on b.tenant_id = r.tenant_id and b.rollout_id = r.id and b.status in ('active', 'completed')
    join public.policy_rollout_targets target
      on target.tenant_id = b.tenant_id and target.batch_id = b.id and target.rollout_id = b.rollout_id
   where r.tenant_id = v_key.tenant_id and r.version = p_version
     and r.status in ('running', 'paused', 'completed') and target.agent_id = v_key.agent_id
     and exists (
       select 1 from public.agent_policy_assignments assignment
        where assignment.tenant_id = r.tenant_id and assignment.agent_id = v_key.agent_id
          and assignment.version = p_version
     )
   order by r.created_at desc limit 1
   for update of r;
  if found then
    select b.* into v_batch
      from public.policy_rollout_batches b
      join public.policy_rollout_targets target
        on target.tenant_id = b.tenant_id and target.batch_id = b.id and target.rollout_id = b.rollout_id
     where b.tenant_id = v_rollout.tenant_id and b.rollout_id = v_rollout.id
       and b.status in ('active', 'completed') and target.agent_id = v_key.agent_id
     for update;
    if found then
      update public.policy_rollout_targets
         set acknowledged_at = coalesce(acknowledged_at, now()), last_receipt_at = now()
       where tenant_id = v_key.tenant_id and batch_id = v_batch.id and agent_id = v_key.agent_id;
      if v_rollout.status = 'running' then
        select * into v_batch from public.policy_rollout_batches
         where tenant_id = v_rollout.tenant_id and rollout_id = v_rollout.id and status = 'active';
        if found then perform app.advance_policy_rollout(v_batch.tenant_id, v_batch.rollout_id, v_batch.id); end if;
      end if;
    end if;
  end if;
  return true;
end;
$$;

-- ── Fleet-response delivery ───────────────────────────────────────────────

-- poll_fleet_response_command and record_fleet_response_command authorize
-- through app.lock_fleet_response_agent (20261006001000 rewrote them in
-- place), so teaching that one function about tenant-owned keys covers the
-- whole delivery path.
create or replace function app.lock_fleet_response_agent(
  p_key_hash text, p_tenant_id uuid, p_agent_id uuid,
  p_installation_id text default null
)
returns text language plpgsql security definer
set search_path = pg_catalog, public, auth, pg_temp as $$
declare
  v_key_id uuid;
  v_user_id uuid;
  v_fleet_key_id uuid;
  v_key public.api_keys;
  v_member public.tenant_members;
  v_agent public.agents;
  v_tenant public.tenants;
begin
  if p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$'
     or p_tenant_id is null or p_agent_id is null
     or (p_installation_id is not null and
       (length(p_installation_id) not between 1 and 128
        or length(btrim(p_installation_id)) = 0 or p_installation_id ~ '[[:cntrl:]]')) then
    raise exception 'fleet_agent_forbidden' using errcode = '42501';
  end if;
  select k.id,k.user_id,k.fleet_key_id into v_key_id,v_user_id,v_fleet_key_id from public.api_keys k
    where k.tenant_id = p_tenant_id and k.agent_id = p_agent_id
      and (k.key_hash = p_key_hash or k.previous_hash = p_key_hash)
    order by (k.key_hash = p_key_hash) desc,k.id limit 1;
  if not found then raise exception 'fleet_agent_forbidden' using errcode = '42501'; end if;

  -- Parent before child: Auth deletion, tenant closing, membership revocation
  -- and fleet-key revocation cannot invert a key-first authentication lock.
  if v_fleet_key_id is null then
    perform 1 from auth.users where id = v_user_id for share;
    if not found then raise exception 'fleet_agent_forbidden' using errcode = '42501'; end if;
  end if;
  select * into v_tenant from public.tenants where id = p_tenant_id for share;
  if not found then raise exception 'fleet_agent_forbidden' using errcode = '42501'; end if;
  if v_fleet_key_id is null then
    select * into v_member from public.tenant_members
      where tenant_id = p_tenant_id and user_id = v_user_id for share;
    if not found then raise exception 'fleet_agent_forbidden' using errcode = '42501'; end if;
  elsif not app.fleet_device_key_active(p_tenant_id, v_fleet_key_id) then
    raise exception 'fleet_agent_forbidden' using errcode = '42501';
  end if;
  select * into v_agent from public.agents
    where id = p_agent_id and tenant_id = p_tenant_id for share;
  if not found then raise exception 'fleet_agent_forbidden' using errcode = '42501'; end if;
  select * into v_key from public.api_keys where id = v_key_id for share;
  if not found or v_key.revoked or v_key.user_id is distinct from v_user_id
     or v_key.fleet_key_id is distinct from v_fleet_key_id
     or v_key.tenant_id is distinct from p_tenant_id or v_key.agent_id is distinct from p_agent_id
     or (v_key.key_hash = p_key_hash or
       (v_key.previous_hash = p_key_hash and v_key.previous_hash_expires_at > clock_timestamp())) is not true
     or v_tenant.status <> 'active'
     or (v_fleet_key_id is null and (
       v_member.role not in ('owner','admin','member')
       or (v_member.expires_at is not null and v_member.expires_at <= clock_timestamp())
       or v_agent.user_id is distinct from v_user_id))
     or length(v_agent.iid) not between 1 and 128 or v_agent.iid ~ '[[:cntrl:]]'
     or (p_installation_id is not null and v_agent.iid is distinct from p_installation_id) then
    raise exception 'fleet_agent_forbidden' using errcode = '42501';
  end if;
  return v_agent.iid;
end;
$$;
