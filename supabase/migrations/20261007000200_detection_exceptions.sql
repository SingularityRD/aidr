-- Time-limited detection exceptions (catalog item 80; docs/configuration.md,
-- "Detection exceptions").
--
-- An exception lifts ONE detection rule (optionally narrowed to one exact
-- artifact digest) for ONE subject — a tenant member, an agent or a repository —
-- until expires_at, at most 30 days after creation. Expiry is applied at read
-- time: the per-principal feed never returns an expired or revoked row, so an
-- exception lifts on its end date with no sweep.
--
-- Write path: the `detection-exceptions` Edge Function (Supabase session,
-- identity barrier, owner/admin, AAL2, rate limit) calls the service-role RPCs
-- below, which re-check the role and every field under a tenant lock and write
-- the audit row in the same transaction. There is no browser or API-key write
-- path, so no agent can create one.
--
-- Read path for connectors: `detection_exceptions_for_principal`, called by the
-- `policy` Edge Function, which binds the list's digest into the Ed25519-signed
-- runtime-policy envelope. `changed_at` is a per-tenant high-water mark that
-- only moves forward (any insert, update or delete), so a revocation always
-- advances the signed sequence and an older signed response is a rollback.
--
-- Self-defense and canary rules (CLT-SELF-*, CLT-CANARY-*) can never be
-- excepted: refused by a check constraint, the RPC, the Edge Function and the
-- connector.

-- ── Tables ─────────────────────────────────────────────────────────────────

create table if not exists public.detection_exceptions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  rule_id text not null,
  artifact_sha256 text,
  subject_kind text not null check (subject_kind in ('user', 'agent', 'repo')),
  subject_user_id uuid,
  subject_agent_id uuid,
  subject_repo text,
  reason text not null check (app.ai_governance_text_valid(reason, 500, false)),
  created_by uuid not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_by uuid,
  revoked_at timestamptz,
  revoke_reason text check (revoke_reason is null or app.ai_governance_text_valid(revoke_reason, 500, false)),
  constraint detection_exceptions_rule_id_format
    check (rule_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$'),
  constraint detection_exceptions_protected_rule
    check (upper(rule_id) not like 'CLT-SELF-%' and upper(rule_id) not like 'CLT-CANARY-%'),
  constraint detection_exceptions_artifact_digest
    check (artifact_sha256 is null or artifact_sha256 ~ '^[a-f0-9]{64}$'),
  constraint detection_exceptions_subject_shape check (
    case subject_kind
      when 'user' then subject_user_id is not null and subject_agent_id is null and subject_repo is null
      when 'agent' then subject_agent_id is not null and subject_user_id is null and subject_repo is null
      else subject_repo is not null and subject_user_id is null and subject_agent_id is null
        and app.ai_governance_text_valid(subject_repo, 512, false)
    end
  ),
  constraint detection_exceptions_window
    check (expires_at > created_at and expires_at <= created_at + interval '30 days'),
  constraint detection_exceptions_revoke_shape
    check ((revoked_at is null) = (revoked_by is null) and (revoked_at is null) = (revoke_reason is null)),
  constraint detection_exceptions_agent_fkey foreign key (subject_agent_id, tenant_id)
    references public.agents (id, tenant_id) on delete cascade
);

comment on table public.detection_exceptions is
  'Operator-created, time-limited detection exceptions: one rule, one subject, at most 30 days. Written only by service-role RPCs; delivered to connectors only inside the signed runtime policy.';

create index if not exists detection_exceptions_active_idx
  on public.detection_exceptions (tenant_id, expires_at)
  where revoked_at is null;
create index if not exists detection_exceptions_tenant_created_idx
  on public.detection_exceptions (tenant_id, created_at desc);

alter table public.detection_exceptions enable row level security;
revoke all on public.detection_exceptions from public, anon, authenticated, service_role;
-- The Edge Function lists through the service role; no browser grant at all.
grant select on public.detection_exceptions to service_role;

drop policy if exists detection_exceptions_member_restrict on public.detection_exceptions;
create policy detection_exceptions_member_restrict on public.detection_exceptions
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.detection_exceptions;
create policy tenant_identity_access_restrict on public.detection_exceptions
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- Per-tenant change high-water mark for the signed sequence.
create table if not exists public.detection_exception_tenant_state (
  tenant_id uuid primary key references public.tenants (id) on delete restrict,
  changed_at timestamptz not null
);

comment on table public.detection_exception_tenant_state is
  'Latest change to a tenant''s detection exceptions; only moves forward and feeds the signed runtime-policy sequence.';

alter table public.detection_exception_tenant_state enable row level security;
revoke all on public.detection_exception_tenant_state from public, anon, authenticated, service_role;

drop policy if exists detection_exception_tenant_state_member_restrict on public.detection_exception_tenant_state;
create policy detection_exception_tenant_state_member_restrict on public.detection_exception_tenant_state
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.detection_exception_tenant_state;
create policy tenant_identity_access_restrict on public.detection_exception_tenant_state
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

create or replace function app.touch_detection_exception_state()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_tenant uuid := coalesce(new.tenant_id, old.tenant_id);
begin
  insert into public.detection_exception_tenant_state as s (tenant_id, changed_at)
  values (v_tenant, clock_timestamp())
  on conflict (tenant_id) do update
    set changed_at = greatest(s.changed_at, excluded.changed_at);
  return null;
end;
$$;
revoke all on function app.touch_detection_exception_state() from public, anon, authenticated;

drop trigger if exists detection_exceptions_touch_state on public.detection_exceptions;
create trigger detection_exceptions_touch_state
  after insert or update or delete on public.detection_exceptions
  for each row execute function app.touch_detection_exception_state();

-- ── Wire shape ─────────────────────────────────────────────────────────────

-- The snake_case record connectors verify (DetectionExceptionWireSchema in
-- packages/core/src/detection-exceptions.ts).
create or replace function app.detection_exception_json(p_row public.detection_exceptions)
returns jsonb
language sql
stable
set search_path = pg_catalog, public, pg_temp
as $$
  select jsonb_build_object(
    'id', p_row.id,
    'rule_id', p_row.rule_id,
    'artifact_sha256', p_row.artifact_sha256,
    'subject_kind', p_row.subject_kind,
    'subject_value', case p_row.subject_kind
      when 'user' then p_row.subject_user_id::text
      when 'agent' then p_row.subject_agent_id::text
      else p_row.subject_repo end,
    'created_at', p_row.created_at,
    'expires_at', p_row.expires_at,
    'created_by', p_row.created_by::text,
    'reason', p_row.reason
  )
$$;
revoke all on function app.detection_exception_json(public.detection_exceptions) from public, anon, authenticated;

-- ── RPC: create (owner/admin) ──────────────────────────────────────────────

create or replace function public.create_detection_exception(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_fields jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_role text;
  v_key text;
  v_rule text;
  v_digest text;
  v_kind text;
  v_value text;
  v_user uuid;
  v_agent uuid;
  v_repo text;
  v_expires timestamptz;
  v_reason text;
  v_row public.detection_exceptions;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_fields is null or jsonb_typeof(p_fields) <> 'object' then
    raise exception 'invalid_detection_exception' using errcode = '22023';
  end if;
  for v_key in select jsonb_object_keys(p_fields) loop
    if v_key not in ('rule_id', 'artifact_sha256', 'subject_kind', 'subject_value', 'expires_at', 'reason') then
      raise exception 'invalid_detection_exception:%', v_key using errcode = '22023';
    end if;
    if jsonb_typeof(p_fields->v_key) not in ('string', 'null') then
      raise exception 'invalid_detection_exception:%', v_key using errcode = '22023';
    end if;
  end loop;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'detection_exception_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':detection-exceptions', 0));

  v_rule := btrim(p_fields->>'rule_id');
  if v_rule is null or v_rule !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$' then
    raise exception 'invalid_detection_exception:rule_id' using errcode = '22023';
  end if;
  if upper(v_rule) like 'CLT-SELF-%' or upper(v_rule) like 'CLT-CANARY-%' then
    raise exception 'detection_exception_protected_rule' using errcode = '22023';
  end if;

  v_digest := p_fields->>'artifact_sha256';
  if v_digest is not null and v_digest !~ '^[a-f0-9]{64}$' then
    raise exception 'invalid_detection_exception:artifact_sha256' using errcode = '22023';
  end if;

  v_kind := p_fields->>'subject_kind';
  v_value := btrim(p_fields->>'subject_value');
  if v_kind is null or v_kind not in ('user', 'agent', 'repo') or v_value is null then
    raise exception 'invalid_detection_exception:subject' using errcode = '22023';
  end if;
  if v_kind in ('user', 'agent')
     and v_value !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
    raise exception 'invalid_detection_exception:subject' using errcode = '22023';
  end if;
  if v_kind = 'user' then
    v_user := v_value::uuid;
    if not exists (
      select 1 from public.tenant_members m
       where m.tenant_id = p_tenant_id and m.user_id = v_user
         and (m.expires_at is null or m.expires_at > v_now)) then
      raise exception 'detection_exception_subject_unknown' using errcode = '22023';
    end if;
  elsif v_kind = 'agent' then
    v_agent := v_value::uuid;
    if not exists (select 1 from public.agents a where a.tenant_id = p_tenant_id and a.id = v_agent) then
      raise exception 'detection_exception_subject_unknown' using errcode = '22023';
    end if;
  else
    if not app.ai_governance_text_valid(v_value, 512, false) then
      raise exception 'invalid_detection_exception:subject' using errcode = '22023';
    end if;
    v_repo := v_value;
  end if;

  begin
    v_expires := (p_fields->>'expires_at')::timestamptz;
  exception when others then
    raise exception 'invalid_detection_exception:expires_at' using errcode = '22023';
  end;
  if v_expires is null or v_expires <= v_now + interval '5 minutes' or v_expires > v_now + interval '30 days' then
    raise exception 'invalid_detection_exception:expires_at' using errcode = '22023';
  end if;

  v_reason := btrim(p_fields->>'reason');
  if not app.ai_governance_text_valid(v_reason, 500, false) then
    raise exception 'invalid_detection_exception:reason' using errcode = '22023';
  end if;

  if (select count(*) from public.detection_exceptions
       where tenant_id = p_tenant_id and revoked_at is null and expires_at > v_now) >= 500 then
    raise exception 'detection_exception_quota' using errcode = '54000';
  end if;

  insert into public.detection_exceptions (
    tenant_id, rule_id, artifact_sha256, subject_kind, subject_user_id, subject_agent_id, subject_repo,
    reason, created_by, created_at, expires_at
  ) values (
    p_tenant_id, v_rule, v_digest, v_kind, v_user, v_agent, v_repo,
    v_reason, p_actor_user_id, v_now, v_expires
  )
  returning * into v_row;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'detection_exception.created',
    jsonb_build_object('exception_id', v_row.id, 'rule_id', v_row.rule_id, 'subject_kind', v_row.subject_kind,
      'artifact_scoped', v_row.artifact_sha256 is not null, 'expires_at', v_row.expires_at));
  return jsonb_build_object('exception_id', v_row.id, 'expires_at', v_row.expires_at);
end;
$$;
revoke all on function public.create_detection_exception(uuid, uuid, jsonb) from public, anon, authenticated;
grant execute on function public.create_detection_exception(uuid, uuid, jsonb) to service_role;

-- ── RPC: revoke (owner/admin) ──────────────────────────────────────────────

create or replace function public.revoke_detection_exception(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_exception_id uuid,
  p_reason text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_role text;
  v_row public.detection_exceptions;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_exception_id is null then
    raise exception 'invalid_detection_exception' using errcode = '22023';
  end if;
  if not app.ai_governance_text_valid(p_reason, 500, false) then
    raise exception 'invalid_detection_exception:reason' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'detection_exception_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':detection-exceptions', 0));
  select * into v_row from public.detection_exceptions
   where id = p_exception_id and tenant_id = p_tenant_id
   for update;
  if not found then
    raise exception 'detection_exception_not_found' using errcode = 'P0002';
  end if;
  if v_row.revoked_at is not null or v_row.expires_at <= v_now then
    raise exception 'detection_exception_not_active' using errcode = '55000';
  end if;
  update public.detection_exceptions
     set revoked_by = p_actor_user_id, revoked_at = v_now, revoke_reason = btrim(p_reason)
   where id = v_row.id;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'detection_exception.revoked',
    jsonb_build_object('exception_id', v_row.id, 'rule_id', v_row.rule_id, 'subject_kind', v_row.subject_kind));
  return jsonb_build_object('exception_id', v_row.id, 'revoked', true);
end;
$$;
revoke all on function public.revoke_detection_exception(uuid, uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.revoke_detection_exception(uuid, uuid, uuid, text) to service_role;

-- ── RPC: per-principal feed for the signed runtime policy ──────────────────

-- Active exceptions (not revoked, created, not yet expired) that apply to the
-- caller of the policy endpoint: repository exceptions always, member
-- exceptions only for the API key's user, agent exceptions only for the key's
-- bound agent. Ordered by id and bounded, so the digest is deterministic.
create or replace function public.detection_exceptions_for_principal(
  p_tenant_id uuid,
  p_user_id uuid,
  p_agent_id uuid
)
returns jsonb
language sql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
  select jsonb_build_object(
    'exceptions', coalesce((
      select jsonb_agg(app.detection_exception_json(e.d) order by (e.d).id)
        from (
          select d from public.detection_exceptions d
           where d.tenant_id = p_tenant_id
             and d.revoked_at is null
             and d.created_at <= clock_timestamp()
             and d.expires_at > clock_timestamp()
             and (d.subject_kind = 'repo'
               or (d.subject_kind = 'user' and p_user_id is not null and d.subject_user_id = p_user_id)
               or (d.subject_kind = 'agent' and p_agent_id is not null and d.subject_agent_id = p_agent_id))
           order by d.id
           limit 500
        ) e
    ), '[]'::jsonb),
    'changed_at', (select s.changed_at from public.detection_exception_tenant_state s where s.tenant_id = p_tenant_id)
  )
$$;
revoke all on function public.detection_exceptions_for_principal(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.detection_exceptions_for_principal(uuid, uuid, uuid) to service_role;
