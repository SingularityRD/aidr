-- Managed-mode dashboard approvals (docs/contracts/dashboard-approvals.md).
--
-- A connector in managed mode that issues an `ask` verdict files an approval
-- request with its tenant API key. An owner/admin at AAL2 approves or denies it
-- in the dashboard; the `approval-requests` Edge Function signs a short-lived
-- Ed25519 approval token with the tenant's approval signing key and the
-- connector collects it by polling. Nothing here is callable by the agent: the
-- request is filed by the connector process, decided by a human in the
-- dashboard, and verified by the connector against public keys delivered in the
-- signed entitlement.
--
-- Two tables:
--   approval_requests             one row per (tenant, installation, action)
--   tenant_approval_signing_keys  per-tenant Ed25519 keys; the private key is
--                                 stored only as AES-256-GCM ciphertext under a
--                                 per-tenant key-encryption key derived (HKDF)
--                                 from the AIDR_APPROVAL_SIGNING_WRAP_KEY_B64
--                                 Edge secret, which never reaches the database.
--
-- Access:
--   * Members read their tenant's requests through RLS, without the token and
--     nonce columns (column grants). Nobody writes through the client roles.
--   * The key table is service-role only; its private-key ciphertext is never
--     granted to a client role and no client policy exists.
--   * Every mutation is a service-role-only SECURITY DEFINER RPC that re-checks
--     membership, role and tenant state under row locks and writes the audit
--     rows in the same transaction.

-- ── Helpers ────────────────────────────────────────────────────────────────

create or replace function app.approval_threat_ids_valid(p_ids text[])
returns boolean
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select p_ids is not null
    and cardinality(p_ids) <= 16
    and coalesce(
      (select bool_and(t is not null and t ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') from unnest(p_ids) t),
      true
    )
$$;
revoke all on function app.approval_threat_ids_valid(text[]) from public, anon, authenticated;

create or replace function app.approval_b64url_decode(p_value text)
returns bytea
language sql
immutable
strict
set search_path = pg_catalog, pg_temp
as $$
  select decode(
    translate(p_value, '-_', '+/') || repeat('=', (4 - length(p_value) % 4) % 4),
    'base64'
  )
$$;
revoke all on function app.approval_b64url_decode(text) from public, anon, authenticated;

-- Writes the privileged audit row always, and the customer-visible team audit
-- row when the tenant is a team (audit_logs.team_id references teams).
create or replace function app.approval_audit(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_action text,
  p_detail jsonb
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, p_action, p_detail);
  if exists (select 1 from public.teams where id = p_tenant_id) then
    insert into public.audit_logs(team_id, tenant_id, user_id, action, verdict)
    values (p_tenant_id, p_tenant_id, p_actor_user_id, p_action, p_detail);
  end if;
end;
$$;
revoke all on function app.approval_audit(uuid, uuid, text, jsonb) from public, anon, authenticated;

-- ── Signing keys ───────────────────────────────────────────────────────────

create table if not exists public.tenant_approval_signing_keys (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  key_id text not null check (key_id ~ '^apk_[a-f0-9]{32}$'),
  -- DER SubjectPublicKeyInfo of an Ed25519 key, standard base64 (44 bytes).
  public_key_spki_b64 text not null
    check (public_key_spki_b64 ~ '^MCowBQYDK2VwAyEA[A-Za-z0-9+/]{43}=$'),
  -- PKCS#8 private key sealed with AES-256-GCM (ciphertext || tag), base64.
  private_key_ciphertext_b64 text not null
    check (char_length(private_key_ciphertext_b64) between 16 and 512
      and private_key_ciphertext_b64 ~ '^[A-Za-z0-9+/]+={0,2}$'),
  private_key_nonce_b64 text not null check (private_key_nonce_b64 ~ '^[A-Za-z0-9+/]{16}$'),
  wrap_alg text not null default 'aes-256-gcm+hkdf-sha256'
    check (wrap_alg = 'aes-256-gcm+hkdf-sha256'),
  wrap_key_version integer not null default 1 check (wrap_key_version between 1 and 1000),
  created_by uuid,
  created_at timestamptz not null default now(),
  retired_at timestamptz,
  revoked_at timestamptz,
  constraint tenant_approval_signing_keys_key_unique unique (tenant_id, key_id),
  constraint tenant_approval_signing_keys_retired_after_created
    check (retired_at is null or retired_at >= created_at),
  constraint tenant_approval_signing_keys_revoked_after_created
    check (revoked_at is null or revoked_at >= created_at)
);

-- At most one signing key per tenant is active at a time.
create unique index if not exists tenant_approval_signing_keys_one_active
  on public.tenant_approval_signing_keys (tenant_id)
  where retired_at is null and revoked_at is null;

comment on table public.tenant_approval_signing_keys is
  'Per-tenant Ed25519 approval-token signing keys. Private keys are AES-256-GCM ciphertext under an HKDF-derived per-tenant key from an Edge secret; service-role only.';

create or replace function app.protect_approval_signing_key()
returns trigger
language plpgsql
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if new.id is distinct from old.id
     or new.tenant_id is distinct from old.tenant_id
     or new.key_id is distinct from old.key_id
     or new.public_key_spki_b64 is distinct from old.public_key_spki_b64
     or new.private_key_ciphertext_b64 is distinct from old.private_key_ciphertext_b64
     or new.private_key_nonce_b64 is distinct from old.private_key_nonce_b64
     or new.wrap_alg is distinct from old.wrap_alg
     or new.wrap_key_version is distinct from old.wrap_key_version
     or new.created_by is distinct from old.created_by
     or new.created_at is distinct from old.created_at
     or (old.retired_at is not null and new.retired_at is distinct from old.retired_at)
     or (old.revoked_at is not null and new.revoked_at is distinct from old.revoked_at) then
    raise exception 'approval_signing_key_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_approval_signing_key() from public, anon, authenticated;

drop trigger if exists tenant_approval_signing_keys_immutable on public.tenant_approval_signing_keys;
create trigger tenant_approval_signing_keys_immutable
  before update on public.tenant_approval_signing_keys
  for each row execute function app.protect_approval_signing_key();

alter table public.tenant_approval_signing_keys enable row level security;
revoke all on public.tenant_approval_signing_keys from public, anon, authenticated, service_role;
-- The Edge Function reads the active key to sign; every write is an RPC.
grant select on public.tenant_approval_signing_keys to service_role;

drop policy if exists tenant_approval_signing_keys_no_client_access on public.tenant_approval_signing_keys;
create policy tenant_approval_signing_keys_no_client_access on public.tenant_approval_signing_keys
  as restrictive for all to authenticated, anon
  using (false)
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.tenant_approval_signing_keys;
create policy tenant_identity_access_restrict on public.tenant_approval_signing_keys
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Approval requests ──────────────────────────────────────────────────────

create table if not exists public.approval_requests (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  iid text not null check (char_length(iid) between 1 and 128 and iid !~ '[[:cntrl:]]'),
  agent_id uuid,
  agent_runtime text check (agent_runtime is null or agent_runtime ~ '^[a-z0-9][a-z0-9_.-]{0,31}$'),
  action_id text not null check (action_id ~ '^[A-Za-z0-9._:-]{8,128}$'),
  artifact_digest text not null check (artifact_digest ~ '^sha256:[a-f0-9]{64}$'),
  tool text not null check (char_length(tool) between 1 and 64 and tool !~ '[[:cntrl:]]'),
  threat_ids text[] not null default '{}'::text[] check (app.approval_threat_ids_valid(threat_ids)),
  summary text not null check (char_length(summary) <= 512 and summary !~ '[[:cntrl:]]'),
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'denied', 'expired')),
  requested_by uuid not null,
  requested_key_id uuid,
  decided_by uuid,
  decided_at timestamptz,
  reason text check (reason is null or (char_length(reason) between 1 and 500 and reason !~ '[[:cntrl:]]')),
  token text check (token is null or (char_length(token) <= 4096 and token ~ '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')),
  key_id text check (key_id is null or key_id ~ '^apk_[a-f0-9]{32}$'),
  token_nonce text check (token_nonce is null or token_nonce ~ '^[A-Za-z0-9_-]{22}$'),
  token_expires_at timestamptz,
  token_delivered_at timestamptz,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  constraint approval_requests_action_unique unique (tenant_id, iid, action_id),
  constraint approval_requests_agent_fkey foreign key (agent_id, tenant_id)
    references public.agents (id, tenant_id) on delete set null (agent_id),
  constraint approval_requests_expiry_window
    check (expires_at > created_at and expires_at <= created_at + interval '31 minutes'),
  constraint approval_requests_decision_shape check (
    case
      when status in ('approved', 'denied') then
        decided_by is not null and decided_at is not null and reason is not null
        and token is not null and key_id is not null and token_nonce is not null
        and token_expires_at is not null
        and token_expires_at > decided_at
        -- The token lifetime is bounded by its signed issued_at (<= 15 minutes);
        -- one extra minute absorbs clock skew between the Edge Function and
        -- the database.
        and token_expires_at <= decided_at + interval '16 minutes'
      else
        decided_by is null and decided_at is null and reason is null
        and token is null and key_id is null and token_nonce is null
        and token_expires_at is null and token_delivered_at is null
    end
  )
);

create index if not exists approval_requests_tenant_pending_idx
  on public.approval_requests (tenant_id, expires_at)
  where status = 'pending';
create index if not exists approval_requests_tenant_created_idx
  on public.approval_requests (tenant_id, created_at desc);
create index if not exists approval_requests_agent_idx
  on public.approval_requests (agent_id, tenant_id)
  where agent_id is not null;

comment on table public.approval_requests is
  'Managed-mode ask approvals filed by connectors and decided by owner/admin at AAL2. Token and nonce columns are never granted to client roles.';

-- A request's subject is immutable; status moves pending -> approved | denied |
-- expired once, and a decided row only records its first token delivery.
create or replace function app.protect_approval_request()
returns trigger
language plpgsql
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if new.id is distinct from old.id
     or new.tenant_id is distinct from old.tenant_id
     or new.iid is distinct from old.iid
     or (new.agent_id is distinct from old.agent_id and new.agent_id is not null)
     or new.agent_runtime is distinct from old.agent_runtime
     or new.action_id is distinct from old.action_id
     or new.artifact_digest is distinct from old.artifact_digest
     or new.tool is distinct from old.tool
     or new.threat_ids is distinct from old.threat_ids
     or new.summary is distinct from old.summary
     or new.requested_by is distinct from old.requested_by
     or new.requested_key_id is distinct from old.requested_key_id
     or new.expires_at is distinct from old.expires_at
     or new.created_at is distinct from old.created_at then
    raise exception 'approval_request_immutable' using errcode = '42501';
  end if;
  if old.status <> 'pending' then
    if new.status is distinct from old.status
       or new.decided_by is distinct from old.decided_by
       or new.decided_at is distinct from old.decided_at
       or new.reason is distinct from old.reason
       or new.token is distinct from old.token
       or new.key_id is distinct from old.key_id
       or new.token_nonce is distinct from old.token_nonce
       or new.token_expires_at is distinct from old.token_expires_at
       or (old.token_delivered_at is not null
           and new.token_delivered_at is distinct from old.token_delivered_at) then
      raise exception 'approval_request_already_final' using errcode = '55000';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function app.protect_approval_request() from public, anon, authenticated;

drop trigger if exists approval_requests_immutable on public.approval_requests;
create trigger approval_requests_immutable
  before update on public.approval_requests
  for each row execute function app.protect_approval_request();

alter table public.approval_requests enable row level security;
revoke all on public.approval_requests from public, anon, authenticated, service_role;
-- Members read everything except the bearer-like token material.
grant select (
  id, tenant_id, iid, agent_id, agent_runtime, action_id, artifact_digest, tool, threat_ids,
  summary, status, decided_by, decided_at, reason, key_id, token_expires_at,
  token_delivered_at, expires_at, created_at
) on public.approval_requests to authenticated;
grant select on public.approval_requests to service_role;

drop policy if exists approval_requests_select_member on public.approval_requests;
create policy approval_requests_select_member on public.approval_requests
  for select to authenticated
  using (app.is_tenant_member(tenant_id));

drop policy if exists approval_requests_member_restrict on public.approval_requests;
create policy approval_requests_member_restrict on public.approval_requests
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.approval_requests;
create policy tenant_identity_access_restrict on public.approval_requests
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── RPC: create (connector, tenant API key) ────────────────────────────────

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
begin
  if p_tenant_id is null or p_requester_user_id is null or p_iid is null or p_action_id is null
     or p_artifact_digest is null or p_tool is null or p_threat_ids is null or p_summary is null
     or p_expires_at is null then
    raise exception 'invalid_approval_request' using errcode = '22023';
  end if;
  -- The handler bounds expires_at by its own clock; allow one minute of skew.
  if p_expires_at <= v_now or p_expires_at > v_now + interval '31 minutes' then
    raise exception 'invalid_approval_expiry' using errcode = '22023';
  end if;

  perform 1 from public.tenants where id = p_tenant_id and status = 'active' for share;
  if not found then
    raise exception 'approval_tenant_inactive' using errcode = '42501';
  end if;
  perform 1 from public.tenant_members m
   where m.tenant_id = p_tenant_id and m.user_id = p_requester_user_id
     and m.role in ('owner', 'admin', 'member')
     and (m.expires_at is null or m.expires_at > v_now)
   for share of m;
  if not found then
    raise exception 'approval_requester_forbidden' using errcode = '42501';
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

  -- Idempotent replay: the same action must name the same artifact and tool.
  if v_row.artifact_digest <> p_artifact_digest or v_row.tool <> p_tool then
    raise exception 'approval_request_conflict' using errcode = '23505';
  end if;
  return jsonb_build_object(
    'request_id', v_row.id,
    'status', case when v_row.status = 'pending' and v_row.expires_at <= v_now then 'expired' else v_row.status end,
    'created', false
  );
end;
$$;
revoke all on function public.create_approval_request(uuid, uuid, uuid, uuid, text, text, text, text, text, text[], text, timestamptz)
  from public, anon, authenticated;
grant execute on function public.create_approval_request(uuid, uuid, uuid, uuid, text, text, text, text, text, text[], text, timestamptz)
  to service_role;

-- ── RPC: poll (connector, tenant API key) ──────────────────────────────────
-- Returns NULL for a request the caller may not see (other tenant, other
-- agent), so existence is never disclosed. Marks an expired pending request
-- and records the first token delivery, both audited.

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
  if p_request_id is null or p_tenant_id is null or p_requester_user_id is null then
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
revoke all on function public.read_approval_request_for_agent(uuid, uuid, uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.read_approval_request_for_agent(uuid, uuid, uuid, uuid)
  to service_role;

-- ── RPC: decide (dashboard owner/admin at AAL2) ────────────────────────────
-- The Edge Function signs the token first (it holds the unwrapped key only in
-- memory); this RPC re-checks the actor's role, the request state and the
-- active key under locks, and refuses a token whose payload does not bind
-- exactly this request, decision, approver and nonce.

create or replace function public.decide_approval_request(
  p_request_id uuid,
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_decision text,
  p_reason text,
  p_key_id text,
  p_token text,
  p_token_nonce text,
  p_token_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_row public.approval_requests;
  v_payload jsonb;
  v_issued timestamptz;
  v_expires timestamptz;
  v_status text;
begin
  if p_request_id is null or p_tenant_id is null or p_actor_user_id is null
     or p_decision is null or p_decision not in ('approve', 'deny')
     or p_reason is null or char_length(btrim(p_reason)) not between 1 and 500
     or p_reason ~ '[[:cntrl:]]'
     or p_key_id is null or p_token is null or p_token_nonce is null or p_token_expires_at is null then
    raise exception 'invalid_approval_decision' using errcode = '22023';
  end if;

  perform 1 from public.tenant_members m
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
     and m.role in ('owner', 'admin')
     and (m.expires_at is null or m.expires_at > v_now)
   for share of m;
  if not found then
    raise exception 'approval_decision_forbidden' using errcode = '42501';
  end if;
  perform 1 from public.tenants where id = p_tenant_id and status = 'active' for share;
  if not found then
    raise exception 'approval_tenant_inactive' using errcode = '42501';
  end if;

  select * into v_row from public.approval_requests
   where id = p_request_id and tenant_id = p_tenant_id
   for update;
  if not found then
    raise exception 'approval_request_not_found' using errcode = 'P0002';
  end if;
  if v_row.status <> 'pending' then
    return jsonb_build_object('outcome', 'already_final', 'request_id', v_row.id, 'status', v_row.status);
  end if;
  if v_row.expires_at <= v_now then
    update public.approval_requests set status = 'expired' where id = v_row.id;
    perform app.approval_audit(p_tenant_id, p_actor_user_id, 'approval.expired',
      jsonb_build_object('request_id', v_row.id, 'action_id', v_row.action_id, 'iid', v_row.iid));
    return jsonb_build_object('outcome', 'expired', 'request_id', v_row.id, 'status', 'expired');
  end if;

  perform 1 from public.tenant_approval_signing_keys k
   where k.tenant_id = p_tenant_id and k.key_id = p_key_id
     and k.retired_at is null and k.revoked_at is null
   for share of k;
  if not found then
    raise exception 'approval_signing_key_inactive' using errcode = '55000';
  end if;

  -- The signed payload must bind exactly this request.
  begin
    v_payload := convert_from(app.approval_b64url_decode(split_part(p_token, '.', 1)), 'UTF8')::jsonb;
    v_issued := (v_payload->>'issued_at')::timestamptz;
    v_expires := (v_payload->>'expires_at')::timestamptz;
  exception when others then
    raise exception 'approval_token_mismatch' using errcode = '22023';
  end;
  if v_payload is distinct from jsonb_build_object(
       'v', 1,
       'tenant_id', p_tenant_id::text,
       'iid', v_row.iid,
       'action_id', v_row.action_id,
       'artifact_digest', v_row.artifact_digest,
       'tool', v_row.tool,
       'decision', p_decision,
       'approver_id', p_actor_user_id::text,
       'issued_at', v_payload->>'issued_at',
       'expires_at', v_payload->>'expires_at',
       'nonce', p_token_nonce
     )
     or v_issued is null or v_expires is null
     or v_expires is distinct from p_token_expires_at
     or v_issued < v_now - interval '2 minutes' or v_issued > v_now + interval '1 minute'
     or v_expires <= v_now or v_expires > v_issued + interval '15 minutes'
     or v_expires > v_now + interval '16 minutes' then
    raise exception 'approval_token_mismatch' using errcode = '22023';
  end if;

  v_status := case p_decision when 'approve' then 'approved' else 'denied' end;
  update public.approval_requests
     set status = v_status,
         decided_by = p_actor_user_id,
         decided_at = v_now,
         reason = btrim(p_reason),
         token = p_token,
         key_id = p_key_id,
         token_nonce = p_token_nonce,
         token_expires_at = p_token_expires_at
   where id = v_row.id;

  perform app.approval_audit(p_tenant_id, p_actor_user_id, 'approval.' || v_status,
    jsonb_build_object(
      'request_id', v_row.id,
      'iid', v_row.iid,
      'agent_id', v_row.agent_id,
      'action_id', v_row.action_id,
      'artifact_digest', v_row.artifact_digest,
      'tool', v_row.tool,
      'threat_ids', to_jsonb(v_row.threat_ids),
      'reason', btrim(p_reason),
      'key_id', p_key_id,
      'token_expires_at', p_token_expires_at
    ));
  return jsonb_build_object(
    'outcome', 'decided',
    'request_id', v_row.id,
    'status', v_status,
    'decided_at', v_now,
    'token_expires_at', p_token_expires_at
  );
end;
$$;
revoke all on function public.decide_approval_request(uuid, uuid, uuid, text, text, text, text, text, timestamptz)
  from public, anon, authenticated;
grant execute on function public.decide_approval_request(uuid, uuid, uuid, text, text, text, text, text, timestamptz)
  to service_role;

-- ── RPC: install / rotate the tenant signing key ───────────────────────────
-- The Edge Function generates the key pair and seals the private key before
-- calling this. Without p_rotate, a concurrent creator converges on whichever
-- key is already active. Rotation retires the active key (still published for
-- the lifetime of any token it signed) and is an owner/admin action.

create or replace function public.install_tenant_approval_signing_key(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_key_id text,
  p_public_key_spki_b64 text,
  p_private_key_ciphertext_b64 text,
  p_private_key_nonce_b64 text,
  p_wrap_key_version integer,
  p_rotate boolean
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_active public.tenant_approval_signing_keys;
begin
  if p_tenant_id is null or p_key_id is null or p_public_key_spki_b64 is null
     or p_private_key_ciphertext_b64 is null or p_private_key_nonce_b64 is null
     or p_wrap_key_version is null or p_rotate is null
     or (p_rotate and p_actor_user_id is null) then
    raise exception 'invalid_approval_signing_key' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':approval-signing-key', 0));
  perform 1 from public.tenants where id = p_tenant_id and status = 'active' for share;
  if not found then
    raise exception 'approval_tenant_inactive' using errcode = '42501';
  end if;
  if p_rotate then
    perform 1 from public.tenant_members m
     where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
       and m.role in ('owner', 'admin')
       and (m.expires_at is null or m.expires_at > clock_timestamp())
     for share of m;
    if not found then
      raise exception 'approval_key_rotation_forbidden' using errcode = '42501';
    end if;
  end if;

  select * into v_active from public.tenant_approval_signing_keys
   where tenant_id = p_tenant_id and retired_at is null and revoked_at is null
   for update;
  if found and not p_rotate then
    return jsonb_build_object('key_id', v_active.key_id, 'created', false);
  end if;
  if found then
    update public.tenant_approval_signing_keys set retired_at = clock_timestamp()
     where id = v_active.id;
  end if;

  insert into public.tenant_approval_signing_keys (
    tenant_id, key_id, public_key_spki_b64, private_key_ciphertext_b64,
    private_key_nonce_b64, wrap_key_version, created_by
  ) values (
    p_tenant_id, p_key_id, p_public_key_spki_b64, p_private_key_ciphertext_b64,
    p_private_key_nonce_b64, p_wrap_key_version, p_actor_user_id
  );
  perform app.approval_audit(p_tenant_id, p_actor_user_id,
    case when p_rotate then 'approval.signing_key_rotated' else 'approval.signing_key_created' end,
    jsonb_build_object(
      'key_id', p_key_id,
      'retired_key_id', case when v_active.id is null then null else v_active.key_id end,
      'wrap_key_version', p_wrap_key_version
    ));
  return jsonb_build_object(
    'key_id', p_key_id,
    'created', true,
    'retired_key_id', case when v_active.id is null then null else v_active.key_id end
  );
end;
$$;
revoke all on function public.install_tenant_approval_signing_key(uuid, uuid, text, text, text, text, integer, boolean)
  from public, anon, authenticated;
grant execute on function public.install_tenant_approval_signing_key(uuid, uuid, text, text, text, text, integer, boolean)
  to service_role;
