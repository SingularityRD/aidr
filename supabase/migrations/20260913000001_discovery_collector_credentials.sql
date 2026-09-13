-- A collector credential is a 256-bit random bearer secret. Only its SHA-256
-- digest reaches durable storage; a single active credential exists per
-- tenant/collector, so rotation invalidates the previous bearer atomically.
create table public.tenant_discovery_credentials (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  collector_id text not null check (collector_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  credential_id uuid not null default gen_random_uuid(),
  token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  issued_by uuid not null references auth.users(id) on delete cascade,
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  primary key (tenant_id, collector_id),
  unique (credential_id),
  check (expires_at > issued_at and expires_at <= issued_at + interval '90 days'),
  check (revoked_at is null or revoked_at >= issued_at)
);
create index tenant_discovery_credentials_issuer_idx
  on public.tenant_discovery_credentials(issued_by, tenant_id);
alter table public.tenant_discovery_credentials enable row level security;
revoke all on public.tenant_discovery_credentials from public, anon, authenticated;
grant select, insert, update, delete on public.tenant_discovery_credentials to service_role;

-- The same per-collector advisory lock is acquired first by issuance,
-- revocation, cursor reads and ingestion. In-flight work either completes
-- before rotation or sees the rotated/revoked key; it cannot straddle it.
create function public.issue_tenant_discovery_credential(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_collector_id text,
  p_token_hash text,
  p_expires_in_days integer
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_now timestamptz;
  v_credential_id uuid := gen_random_uuid();
  v_expires_at timestamptz;
  v_last_sequence bigint;
  v_tenant_status text;
begin
  if p_tenant_id is null or p_actor_user_id is null
    or p_collector_id is null or p_collector_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$'
    or p_expires_in_days is null or p_expires_in_days not between 1 and 90
  then raise exception 'invalid_discovery_credential' using errcode = '22023'; end if;

  select t.status into v_tenant_status from public.tenants t
    where t.id = p_tenant_id for share;
  if v_tenant_status is distinct from 'active'
  then raise exception 'discovery_credential_forbidden' using errcode = '42501'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || p_collector_id, 2611));
  v_now := clock_timestamp();
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
      and m.role in ('owner', 'admin')
      and (m.expires_at is null or m.expires_at > v_now) and t.status = 'active'
    for share of m
  ) then raise exception 'discovery_credential_forbidden' using errcode = '42501'; end if;

  v_expires_at := v_now + make_interval(days => p_expires_in_days);
  select c.sequence into v_last_sequence from public.tenant_discovery_collectors c
    where c.tenant_id = p_tenant_id and c.collector_id = p_collector_id;
  if coalesce(v_last_sequence, 0) >= 9007199254740991
  then raise exception 'discovery_sequence_exhausted' using errcode = 'PT409'; end if;

  insert into public.tenant_discovery_credentials
    (tenant_id, collector_id, credential_id, token_hash, issued_by, issued_at, expires_at, revoked_at)
  values (p_tenant_id, p_collector_id, v_credential_id, p_token_hash, p_actor_user_id, v_now, v_expires_at, null)
  on conflict (tenant_id, collector_id) do update set
    credential_id = excluded.credential_id, token_hash = excluded.token_hash,
    issued_by = excluded.issued_by, issued_at = excluded.issued_at,
    expires_at = excluded.expires_at, revoked_at = null;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_actor_user_id, p_tenant_id, p_actor_user_id, 'discovery.credential.issued',
    jsonb_build_object('collector_id', p_collector_id, 'credential_id', v_credential_id,
      'expires_at', v_expires_at, 'rotation', true));
  return jsonb_build_object('collector_id', p_collector_id, 'credential_id', v_credential_id,
    'expires_at', v_expires_at, 'next_sequence', coalesce(v_last_sequence, 0) + 1);
end;
$$;
revoke all on function public.issue_tenant_discovery_credential(uuid, uuid, text, text, integer)
  from public, anon, authenticated;
grant execute on function public.issue_tenant_discovery_credential(uuid, uuid, text, text, integer)
  to service_role;

create function public.revoke_tenant_discovery_credential(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_collector_id text
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_now timestamptz;
  v_credential_id uuid;
  v_tenant_status text;
begin
  if p_tenant_id is null or p_actor_user_id is null
    or p_collector_id is null or p_collector_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  then raise exception 'invalid_discovery_credential' using errcode = '22023'; end if;
  select t.status into v_tenant_status from public.tenants t
    where t.id = p_tenant_id for share;
  if v_tenant_status is distinct from 'active'
  then raise exception 'discovery_credential_forbidden' using errcode = '42501'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || p_collector_id, 2611));
  v_now := clock_timestamp();
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
      and m.role in ('owner', 'admin')
      and (m.expires_at is null or m.expires_at > v_now) and t.status = 'active'
    for share of m
  ) then raise exception 'discovery_credential_forbidden' using errcode = '42501'; end if;

  update public.tenant_discovery_credentials
    set revoked_at = coalesce(revoked_at, v_now)
    where tenant_id = p_tenant_id and collector_id = p_collector_id
    returning credential_id into v_credential_id;
  if v_credential_id is not null then
    insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values (p_actor_user_id, p_tenant_id, p_actor_user_id, 'discovery.credential.revoked',
      jsonb_build_object('collector_id', p_collector_id, 'credential_id', v_credential_id));
  end if;
  return jsonb_build_object('collector_id', p_collector_id,
    'credential_id', v_credential_id, 'revoked', v_credential_id is not null);
end;
$$;
revoke all on function public.revoke_tenant_discovery_credential(uuid, uuid, text)
  from public, anon, authenticated;
grant execute on function public.revoke_tenant_discovery_credential(uuid, uuid, text)
  to service_role;

-- This machine-only RPC returns a sequence cursor, never targets or inventory.
-- It also authenticates before Edge rate limiting; ingest rechecks within its
-- own transaction so a rotation between the two calls still fails closed.
create function public.read_tenant_discovery_collector_cursor(
  p_tenant_id uuid,
  p_collector_id text,
  p_token_hash text
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_now timestamptz;
  v_credential_id uuid;
  v_last_sequence bigint;
  v_tenant_status text;
begin
  if p_tenant_id is null or p_collector_id is null
    or p_collector_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$'
  then raise exception 'invalid_discovery_credential' using errcode = '22023'; end if;
  select t.status into v_tenant_status from public.tenants t
    where t.id = p_tenant_id for share;
  if v_tenant_status is distinct from 'active'
  then raise exception 'invalid_discovery_credential' using errcode = '42501'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || p_collector_id, 2611));
  v_now := clock_timestamp();
  select c.credential_id into v_credential_id
    from public.tenant_discovery_credentials c
    join public.tenants t on t.id = c.tenant_id
    join public.tenant_members m on m.tenant_id = c.tenant_id and m.user_id = c.issued_by
    where c.tenant_id = p_tenant_id and c.collector_id = p_collector_id
      and c.token_hash = p_token_hash and c.revoked_at is null and c.expires_at > v_now
      and t.status = 'active' and m.role in ('owner', 'admin')
      and (m.expires_at is null or m.expires_at > v_now)
    for share of m;
  if v_credential_id is null
  then raise exception 'invalid_discovery_credential' using errcode = '42501'; end if;
  select c.sequence into v_last_sequence from public.tenant_discovery_collectors c
    where c.tenant_id = p_tenant_id and c.collector_id = p_collector_id;
  if coalesce(v_last_sequence, 0) >= 9007199254740991
  then raise exception 'discovery_sequence_exhausted' using errcode = 'PT409'; end if;
  return jsonb_build_object('collector_id', p_collector_id, 'credential_id', v_credential_id,
    'last_sequence', coalesce(v_last_sequence, 0),
    'next_sequence', coalesce(v_last_sequence, 0) + 1);
end;
$$;
revoke all on function public.read_tenant_discovery_collector_cursor(uuid, text, text)
  from public, anon, authenticated;
grant execute on function public.read_tenant_discovery_collector_cursor(uuid, text, text)
  to service_role;

create function public.ingest_tenant_discovery_cycle_machine(
  p_tenant_id uuid,
  p_collector_id text,
  p_token_hash text,
  p_cycle_id uuid,
  p_sequence bigint,
  p_stale_after_ms bigint,
  p_complete boolean,
  p_expected_targets integer,
  p_items jsonb
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_now timestamptz;
  v_credential_id uuid;
  v_issued_by uuid;
  v_result jsonb;
  v_tenant_status text;
begin
  if p_tenant_id is null or p_collector_id is null
    or p_collector_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$'
  then raise exception 'invalid_discovery_credential' using errcode = '22023'; end if;
  select t.status into v_tenant_status from public.tenants t
    where t.id = p_tenant_id for share;
  if v_tenant_status is distinct from 'active'
  then raise exception 'invalid_discovery_credential' using errcode = '42501'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || p_collector_id, 2611));
  v_now := clock_timestamp();
  select c.credential_id, c.issued_by into v_credential_id, v_issued_by
    from public.tenant_discovery_credentials c
    join public.tenants t on t.id = c.tenant_id
    join public.tenant_members m on m.tenant_id = c.tenant_id and m.user_id = c.issued_by
    where c.tenant_id = p_tenant_id and c.collector_id = p_collector_id
      and c.token_hash = p_token_hash and c.revoked_at is null and c.expires_at > v_now
      and t.status = 'active' and m.role in ('owner', 'admin')
      and (m.expires_at is null or m.expires_at > v_now)
    for share of m;
  if v_credential_id is null
  then raise exception 'invalid_discovery_credential' using errcode = '42501'; end if;
  -- Reuse the existing atomic validation, target bounds and monotonic replay
  -- check. The issuing admin remains the durable authorization sponsor.
  v_result := public.ingest_tenant_discovery_cycle(p_tenant_id, v_issued_by,
    p_collector_id, p_cycle_id, p_sequence, p_stale_after_ms, p_complete,
    p_expected_targets, p_items);
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (v_issued_by, p_tenant_id, v_issued_by, 'discovery.machine_cycle.ingested',
    jsonb_build_object('collector_id', p_collector_id, 'credential_id', v_credential_id,
      'cycle_id', p_cycle_id, 'sequence', p_sequence));
  return v_result;
end;
$$;
revoke all on function public.ingest_tenant_discovery_cycle_machine(
  uuid, text, text, uuid, bigint, bigint, boolean, integer, jsonb
) from public, anon, authenticated;
grant execute on function public.ingest_tenant_discovery_cycle_machine(
  uuid, text, text, uuid, bigint, bigint, boolean, integer, jsonb
) to service_role;

-- A deactivated tenant cannot retain a usable collector key. The retained
-- metadata is removed with endpoint identity in the offboarding receipt.
create function app.revoke_discovery_credentials_on_tenant_deactivate() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if old.status = 'active' and new.status <> 'active' then
    update public.tenant_discovery_credentials set revoked_at = coalesce(revoked_at, clock_timestamp())
      where tenant_id = new.id;
  end if;
  return new;
end;
$$;
revoke all on function app.revoke_discovery_credentials_on_tenant_deactivate()
  from public, anon, authenticated;
create trigger tenants_revoke_discovery_credentials
after update of status on public.tenants
for each row execute function app.revoke_discovery_credentials_on_tenant_deactivate();

create function app.purge_discovery_credentials_at_endpoint_identity_phase() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_tenant uuid;
  v_status text;
  v_credentials bigint;
begin
  if new.phase <> 'agents' or new.data_class <> 'endpoint_identity'
    or new.status <> 'completed' or old.status = 'completed'
  then return new; end if;
  select r.tenant_id, r.status into v_tenant, v_status
    from public.tenant_offboarding_runs r where r.id = new.run_id;
  if v_tenant is null or v_status <> 'running' or new.eligible_at > now() then
    raise exception 'discovery_credential_offboarding_phase_invalid' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  if exists (select 1 from public.tenant_legal_holds h
    where h.tenant_id = v_tenant and h.released_at is null)
  then raise exception 'discovery_credential_offboarding_legal_hold' using errcode = '42501'; end if;
  delete from public.tenant_discovery_credentials where tenant_id = v_tenant;
  get diagnostics v_credentials = row_count;
  update public.tenant_offboarding_phase_receipts
    set rows_deleted = rows_deleted + v_credentials
    where run_id = new.run_id and phase = new.phase and status = 'completed';
  return new;
end;
$$;
revoke all on function app.purge_discovery_credentials_at_endpoint_identity_phase()
  from public, anon, authenticated;
create trigger tenant_offboarding_purge_discovery_credentials
after update of status on public.tenant_offboarding_phase_receipts
for each row execute function app.purge_discovery_credentials_at_endpoint_identity_phase();
