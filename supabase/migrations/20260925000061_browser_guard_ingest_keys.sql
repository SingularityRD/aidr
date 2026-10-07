-- Ingest-only API keys for Browser Guard telemetry.
--
-- Browser Guard reads its telemetry credential from browser management policy,
-- which any user of a managed profile can read (chrome://policy). A full tenant
-- API key there lets anyone on that machine call every API-key endpoint
-- (policy, packs, reputation, revocations, fleet commands) and forge telemetry
-- from arbitrary installation ids, each of which consumes a paid agent seat.
--
-- An `ingest:browser_guard` key can do exactly one thing: POST counts-only
-- `privacy_scan` events to /v1/ingest as agent_runtime `browser_guard`.
--   * `api_keys.scope` records the key type. Every other endpoint accepts only
--     `tenant` keys (supabase/functions/_shared/api-key-auth.ts).
--   * `api_keys.install_limit` caps how many distinct installations one key may
--     register, so a leaked key cannot burn the tenant's seats beyond it.
--   * `register_browser_guard_agent_for_ingest` enforces the runtime, the cap
--     and the key binding under the same tenant lock as seat registration, and
--     never takes over an agent another runtime registered.
--   * Only owners and admins can issue one; issuance is audited with the scope
--     and the limit in the same transaction.

alter table public.api_keys
  add column if not exists scope text not null default 'tenant',
  add column if not exists install_limit integer;

alter table public.api_keys drop constraint if exists api_keys_scope_check;
alter table public.api_keys add constraint api_keys_scope_check check (
  (scope = 'tenant' and install_limit is null)
  or (scope = 'ingest:browser_guard' and agent_id is null
      and install_limit is not null and install_limit between 1 and 100000)
);

-- A key's type is fixed at issuance. Rotation keeps the row (and so the type);
-- nothing may widen an ingest key into a tenant key or lift its cap.
create or replace function app.api_key_scope_immutable()
returns trigger
language plpgsql
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if new.scope is distinct from old.scope
     or new.install_limit is distinct from old.install_limit then
    raise exception 'api_key_scope_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.api_key_scope_immutable() from public, anon, authenticated;

drop trigger if exists api_keys_scope_immutable on public.api_keys;
create trigger api_keys_scope_immutable
  before update of scope, install_limit on public.api_keys
  for each row execute function app.api_key_scope_immutable();

-- Installations registered through an ingest-scoped key. Removing the key or
-- the agent (offboarding deletes both by tenant) removes the binding.
create table if not exists public.api_key_ingest_installations (
  api_key_id uuid not null references public.api_keys (id) on delete cascade,
  tenant_id uuid not null,
  agent_id uuid not null,
  first_seen timestamptz not null default clock_timestamp(),
  primary key (api_key_id, agent_id),
  foreign key (tenant_id, agent_id) references public.agents (tenant_id, id) on delete cascade
);
create index if not exists api_key_ingest_installations_tenant_idx
  on public.api_key_ingest_installations (tenant_id);
create index if not exists api_key_ingest_installations_agent_idx
  on public.api_key_ingest_installations (tenant_id, agent_id);

alter table public.api_key_ingest_installations enable row level security;
revoke all on public.api_key_ingest_installations from public, anon, authenticated, service_role;
grant select on public.api_key_ingest_installations to service_role;

drop policy if exists tenant_identity_access_restrict on public.api_key_ingest_installations;
create policy tenant_identity_access_restrict on public.api_key_ingest_installations
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Issuance ───────────────────────────────────────────────────────────────
create or replace function public.issue_scoped_api_key_with_audit(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_label text,
  p_key_hash text,
  p_scope text,
  p_install_limit integer
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
declare v_id uuid;
begin
  if p_actor_user_id is null or p_tenant_id is null
     or p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$'
     or p_scope is distinct from 'ingest:browser_guard'
     or p_install_limit is null or p_install_limit not between 1 and 100000 then
    raise exception 'invalid_api_key_issue' using errcode = '22023';
  end if;
  -- An ingest key is an organisation deployment credential: owners and admins.
  perform 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
     and m.role in ('owner', 'admin')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m;
  if not found then return jsonb_build_object('status', 'forbidden'); end if;

  -- A retried call whose response was lost resolves to the same key.
  select k.id into v_id from public.api_keys k
   where k.key_hash = p_key_hash and k.user_id = p_actor_user_id and k.tenant_id = p_tenant_id
     and k.scope = p_scope and k.install_limit = p_install_limit and k.revoked = false;
  if v_id is not null then return jsonb_build_object('status', 'issued', 'id', v_id); end if;

  insert into public.api_keys(user_id, tenant_id, label, key_hash, scope, install_limit)
    values (p_actor_user_id, p_tenant_id, p_label, p_key_hash, p_scope, p_install_limit)
    on conflict (key_hash) do nothing returning id into v_id;
  if v_id is null then
    select k.id into v_id from public.api_keys k
     where k.key_hash = p_key_hash and k.user_id = p_actor_user_id and k.tenant_id = p_tenant_id
       and k.scope = p_scope and k.install_limit = p_install_limit and k.revoked = false;
    if v_id is not null then return jsonb_build_object('status', 'issued', 'id', v_id); end if;
    return jsonb_build_object('status', 'hash_conflict');
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
    values (p_actor_user_id, p_tenant_id, 'api_key.create', p_actor_user_id,
      jsonb_build_object('label', p_label, 'id', v_id, 'scope', p_scope,
        'install_limit', p_install_limit));
  return jsonb_build_object('status', 'issued', 'id', v_id);
end;
$$;
revoke all on function public.issue_scoped_api_key_with_audit(uuid, uuid, text, text, text, integer)
  from public, anon, authenticated;
grant execute on function public.issue_scoped_api_key_with_audit(uuid, uuid, text, text, text, integer)
  to service_role;

-- ── Registration ───────────────────────────────────────────────────────────
-- Same result shape as register_agent_for_ingest plus `install_limit_exceeded`.
create or replace function public.register_browser_guard_agent_for_ingest(
  p_api_key_id uuid,
  p_iid text,
  p_agent_runtime_version text default null
)
returns table (
  agent_id uuid,
  tenant_id uuid,
  created boolean,
  current_agents integer,
  allowed_agents integer,
  seat_exceeded boolean,
  install_limit_exceeded boolean
)
language plpgsql security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_key public.api_keys%rowtype;
  v_iid text := trim(p_iid);
  v_agent_id uuid;
  v_agent_runtime text;
  v_linked boolean := false;
  v_installs integer;
  v_reg record;
begin
  if p_api_key_id is null or nullif(v_iid, '') is null then
    raise exception 'invalid agent identity' using errcode = '22023';
  end if;
  select k.* into v_key from public.api_keys k where k.id = p_api_key_id for share;
  if not found or v_key.revoked or v_key.scope <> 'ingest:browser_guard'
     or v_key.tenant_id is null or v_key.install_limit is null then
    raise exception 'api_key_scope_denied' using errcode = '42501';
  end if;

  -- The seat registration below takes the same tenant lock; taking it first
  -- makes the install count and the seat count one serialized decision.
  perform pg_advisory_xact_lock(hashtextextended(v_key.tenant_id::text, 0));

  select a.id, a.agent_runtime into v_agent_id, v_agent_runtime
    from public.agents a
   where a.tenant_id = v_key.tenant_id and a.iid = v_iid
   for update;
  if v_agent_id is not null then
    -- Never let a browser credential take over a CLI/IDE agent's identity.
    if v_agent_runtime is distinct from 'browser_guard' then
      raise exception 'agent_runtime_mismatch' using errcode = '42501';
    end if;
    v_linked := exists (
      select 1 from public.api_key_ingest_installations i
       where i.api_key_id = v_key.id and i.agent_id = v_agent_id
    );
  end if;

  if not v_linked then
    select count(*)::integer into v_installs
      from public.api_key_ingest_installations i where i.api_key_id = v_key.id;
    if v_installs >= v_key.install_limit then
      return query select null::uuid, v_key.tenant_id, false, v_installs, v_key.install_limit,
        false, true;
      return;
    end if;
  end if;

  select * into v_reg from public.register_agent_for_ingest(
    v_key.user_id, v_iid, 'browser_guard', p_agent_runtime_version, v_key.tenant_id);

  if v_reg.agent_id is not null and not v_linked then
    insert into public.api_key_ingest_installations(api_key_id, tenant_id, agent_id)
      values (v_key.id, v_key.tenant_id, v_reg.agent_id)
      on conflict do nothing;
  end if;

  return query select v_reg.agent_id, v_reg.tenant_id, v_reg.created, v_reg.current_agents,
    v_reg.allowed_agents, v_reg.seat_exceeded, false;
end;
$$;
revoke all on function public.register_browser_guard_agent_for_ingest(uuid, text, text)
  from public, anon, authenticated;
grant execute on function public.register_browser_guard_agent_for_ingest(uuid, text, text)
  to service_role;
