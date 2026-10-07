-- Four-eyes policy change control (docs/ai-governance.md).
--
-- When a tenant enables `policy_four_eyes` (tenant_ai_governance_settings),
-- publishing runtime policy (publish, compiled YAML publish, restore/rollback,
-- targeted stage, ordered rollout) or a DLP policy no longer takes effect on
-- the author's click. policy-management files a policy_change_requests row
-- instead; a second owner/admin reviews the diff and approves it, and only
-- then does decide_policy_change_request run the existing publication RPC
-- (publish_runtime_policy, publish_runtime_policy_document,
-- stage_runtime_policy, create_policy_rollout or publish_dlp_policy) with the
-- author as publisher. Versioned history, staged rollout and rollback are the
-- existing mechanisms; nothing here duplicates them.
--
-- The rule is enforced in the database, not only in the Edge Function: while
-- four-eyes is enabled, a BEFORE INSERT trigger on runtime_policy_revisions
-- and dlp_policy_revisions refuses any new revision that is not being applied
-- by an approval of a pending change request for the same tenant. Every
-- publication path writes a revision, so no path can bypass the approval.
--
-- Disabling four-eyes is itself a change request that a second owner/admin
-- must approve; enabling it is immediate and needs at least two active
-- owners/admins so the tenant cannot lock itself out.

-- ── Change requests ────────────────────────────────────────────────────────

create table if not exists public.policy_change_requests (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  change_kind text not null check (change_kind in (
    'runtime_publish', 'runtime_publish_document', 'runtime_restore', 'runtime_stage',
    'runtime_rollout', 'dlp_publish', 'disable_four_eyes'
  )),
  -- The version the author saw (runtime or DLP); applying re-checks it.
  base_version bigint not null check (base_version >= 0),
  expected_revision_version bigint check (expected_revision_version is null or expected_revision_version >= base_version),
  target_version bigint check (target_version is null or target_version >= 1),
  -- Proposed content. Never granted to client roles: a DLP payload carries
  -- sensitive matchers. The Edge Function serves it to owners/admins at AAL2.
  payload jsonb not null check (jsonb_typeof(payload) = 'object' and octet_length(payload::text) <= 131072),
  payload_sha256 text not null check (payload_sha256 ~ '^[a-f0-9]{64}$'),
  -- Counts only (for example number of rules), safe to show every member.
  summary jsonb not null default '{}'::jsonb check (jsonb_typeof(summary) = 'object'),
  status text not null default 'pending' check (status in (
    'pending', 'approved', 'rejected', 'cancelled', 'superseded', 'failed', 'expired'
  )),
  requested_by uuid not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  decided_by uuid,
  decided_at timestamptz,
  decision_reason text check (decision_reason is null or app.ai_governance_text_valid(decision_reason, 500, true)),
  closed_at timestamptz,
  applied_version bigint check (applied_version is null or applied_version >= 1),
  outcome_code text check (outcome_code is null or outcome_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  constraint policy_change_requests_expiry
    check (expires_at > created_at and expires_at <= created_at + interval '8 days'),
  -- Nobody approves their own change.
  constraint policy_change_requests_four_eyes check (decided_by is null or decided_by <> requested_by),
  constraint policy_change_requests_decision_shape check (
    case status
      when 'pending' then decided_by is null and decided_at is null and decision_reason is null
        and closed_at is null and applied_version is null and outcome_code is null
      when 'approved' then decided_by is not null and decided_at is not null and decision_reason is not null
        and closed_at is not null
      when 'rejected' then decided_by is not null and decided_at is not null and decision_reason is not null
        and closed_at is not null and applied_version is null
      when 'superseded' then decided_by is not null and decided_at is not null and closed_at is not null
        and applied_version is null and outcome_code is not null
      when 'failed' then decided_by is not null and decided_at is not null and closed_at is not null
        and applied_version is null and outcome_code is not null
      else decided_by is null and decided_at is null and closed_at is not null and applied_version is null
    end
  )
);

create index if not exists policy_change_requests_tenant_pending_idx
  on public.policy_change_requests (tenant_id, expires_at)
  where status = 'pending';
create index if not exists policy_change_requests_tenant_created_idx
  on public.policy_change_requests (tenant_id, created_at desc);
create unique index if not exists policy_change_requests_one_disable
  on public.policy_change_requests (tenant_id)
  where status = 'pending' and change_kind = 'disable_four_eyes';

comment on table public.policy_change_requests is
  'Four-eyes policy change requests: proposed runtime/DLP publications awaiting a second owner/admin. Payload is service-role only.';

-- A request's subject is immutable; only its decision fields move, once.
create or replace function app.protect_policy_change_request()
returns trigger
language plpgsql
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if new.id is distinct from old.id
     or new.tenant_id is distinct from old.tenant_id
     or new.change_kind is distinct from old.change_kind
     or new.base_version is distinct from old.base_version
     or new.expected_revision_version is distinct from old.expected_revision_version
     or new.target_version is distinct from old.target_version
     or new.payload is distinct from old.payload
     or new.payload_sha256 is distinct from old.payload_sha256
     or new.summary is distinct from old.summary
     or new.requested_by is distinct from old.requested_by
     or new.created_at is distinct from old.created_at
     or new.expires_at is distinct from old.expires_at then
    raise exception 'policy_change_request_immutable' using errcode = '42501';
  end if;
  if old.status <> 'pending' and row(new.status, new.decided_by, new.decided_at, new.decision_reason,
       new.closed_at, new.applied_version, new.outcome_code)
     is distinct from row(old.status, old.decided_by, old.decided_at, old.decision_reason,
       old.closed_at, old.applied_version, old.outcome_code) then
    raise exception 'policy_change_request_already_final' using errcode = '55000';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_policy_change_request() from public, anon, authenticated;

drop trigger if exists policy_change_requests_immutable on public.policy_change_requests;
create trigger policy_change_requests_immutable
  before update on public.policy_change_requests
  for each row execute function app.protect_policy_change_request();

alter table public.policy_change_requests enable row level security;
revoke all on public.policy_change_requests from public, anon, authenticated, service_role;
grant select (
  id, tenant_id, change_kind, base_version, expected_revision_version, target_version, payload_sha256,
  summary, status, requested_by, created_at, expires_at, decided_by, decided_at, decision_reason,
  closed_at, applied_version, outcome_code
) on public.policy_change_requests to authenticated;
grant select on public.policy_change_requests to service_role;

drop policy if exists policy_change_requests_select_member on public.policy_change_requests;
create policy policy_change_requests_select_member on public.policy_change_requests
  for select to authenticated
  using (app.is_tenant_member(tenant_id));

drop policy if exists policy_change_requests_member_restrict on public.policy_change_requests;
create policy policy_change_requests_member_restrict on public.policy_change_requests
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.policy_change_requests;
create policy tenant_identity_access_restrict on public.policy_change_requests
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Database-level guard ───────────────────────────────────────────────────

create or replace function app.policy_four_eyes_enabled(p_tenant_id uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
  select coalesce((select s.policy_four_eyes from public.tenant_ai_governance_settings s
                    where s.tenant_id = p_tenant_id), false)
$$;
revoke all on function app.policy_four_eyes_enabled(uuid) from public, anon, authenticated;

create or replace function app.enforce_policy_four_eyes()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_request text := nullif(current_setting('app.aidr_policy_change_request', true), '');
begin
  if not app.policy_four_eyes_enabled(new.tenant_id) then
    return new;
  end if;
  if v_request is null
     or v_request !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     or not exists (
       select 1 from public.policy_change_requests r
        where r.id = v_request::uuid and r.tenant_id = new.tenant_id and r.status = 'pending'
          and case when tg_table_name = 'dlp_policy_revisions'
                then r.change_kind = 'dlp_publish'
                else r.change_kind like 'runtime\_%' end) then
    raise exception 'policy_four_eyes_required' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.enforce_policy_four_eyes() from public, anon, authenticated;

drop trigger if exists runtime_policy_revisions_four_eyes on public.runtime_policy_revisions;
create trigger runtime_policy_revisions_four_eyes
  before insert on public.runtime_policy_revisions
  for each row execute function app.enforce_policy_four_eyes();

drop trigger if exists dlp_policy_revisions_four_eyes on public.dlp_policy_revisions;
create trigger dlp_policy_revisions_four_eyes
  before insert on public.dlp_policy_revisions
  for each row execute function app.enforce_policy_four_eyes();

-- ── RPC: file a change request (owner/admin author) ────────────────────────

create or replace function public.submit_policy_change_request(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_change_kind text,
  p_base_version bigint,
  p_expected_revision_version bigint,
  p_target_version bigint,
  p_payload jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_role text;
  v_keys text[];
  v_expected text[];
  v_summary jsonb;
  v_row public.policy_change_requests;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_change_kind is null
     or p_change_kind = 'disable_four_eyes'
     or p_base_version is null or p_base_version < 0
     or p_payload is null or jsonb_typeof(p_payload) <> 'object'
     or octet_length(p_payload::text) > 131072 then
    raise exception 'invalid_policy_change_request' using errcode = '22023';
  end if;
  v_expected := case p_change_kind
    when 'runtime_publish' then array['policy']
    when 'runtime_restore' then array['policy']
    when 'runtime_publish_document' then array['expected_document', 'policy']
    when 'runtime_stage' then array['agent_ids', 'policy']
    when 'runtime_rollout' then array['policy', 'rings']
    when 'dlp_publish' then array['policy']
  end;
  if v_expected is null then
    raise exception 'invalid_policy_change_request' using errcode = '22023';
  end if;
  select coalesce(array_agg(k order by k), '{}'::text[]) into v_keys from jsonb_object_keys(p_payload) k;
  if v_keys is distinct from v_expected
     or jsonb_typeof(p_payload->'policy') <> 'object'
     or (p_change_kind like 'runtime\_%' and octet_length((p_payload->'policy')::text) > 65536)
     or (p_change_kind = 'runtime_restore') <> (p_target_version is not null)
     or (p_change_kind in ('runtime_stage', 'runtime_rollout')) <> (p_expected_revision_version is not null)
     or (p_change_kind = 'runtime_stage' and (jsonb_typeof(p_payload->'agent_ids') <> 'array'
         or jsonb_array_length(p_payload->'agent_ids') not between 1 and 200))
     or (p_change_kind = 'runtime_rollout' and (jsonb_typeof(p_payload->'rings') <> 'array'
         or jsonb_array_length(p_payload->'rings') not between 1 and 100))
     or (p_change_kind = 'runtime_publish_document' and (jsonb_typeof(p_payload->'expected_document') <> 'object'
         or (p_payload->'expected_document'->>'id') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
         or (p_payload->'expected_document'->>'version') !~ '^[1-9][0-9]{0,15}$'
         or (p_payload->'expected_document'->>'source_sha256') !~ '^[0-9a-f]{64}$'))
     or (p_change_kind = 'dlp_publish' and ((p_payload->'policy'->>'tenantId') is distinct from p_tenant_id::text
         or (p_payload->'policy'->>'version') is distinct from (p_base_version + 1)::text)) then
    raise exception 'invalid_policy_change_request' using errcode = '22023';
  end if;

  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'policy_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':policy-change', 0));
  if (select count(*) from public.policy_change_requests
       where tenant_id = p_tenant_id and status = 'pending' and expires_at > v_now) >= 50 then
    raise exception 'policy_change_request_quota' using errcode = '54000';
  end if;

  v_summary := case
    when p_change_kind = 'dlp_publish' then jsonb_build_object(
      'labels', coalesce(jsonb_array_length(case when jsonb_typeof(p_payload->'policy'->'labels') = 'array' then p_payload->'policy'->'labels' end), 0),
      'rules', coalesce(jsonb_array_length(case when jsonb_typeof(p_payload->'policy'->'rules') = 'array' then p_payload->'policy'->'rules' end), 0),
      'exceptions', coalesce(jsonb_array_length(case when jsonb_typeof(p_payload->'policy'->'exceptions') = 'array' then p_payload->'policy'->'exceptions' end), 0))
    else jsonb_build_object('policy_keys', (select count(*) from jsonb_object_keys(p_payload->'policy')))
      || case when p_change_kind = 'runtime_stage'
           then jsonb_build_object('agent_count', jsonb_array_length(p_payload->'agent_ids')) else '{}'::jsonb end
      || case when p_change_kind = 'runtime_rollout'
           then jsonb_build_object('ring_count', jsonb_array_length(p_payload->'rings')) else '{}'::jsonb end
      || case when p_change_kind = 'runtime_restore'
           then jsonb_build_object('target_version', p_target_version) else '{}'::jsonb end
  end;

  insert into public.policy_change_requests (
    tenant_id, change_kind, base_version, expected_revision_version, target_version, payload,
    payload_sha256, summary, requested_by, created_at, expires_at
  ) values (
    p_tenant_id, p_change_kind, p_base_version, p_expected_revision_version, p_target_version, p_payload,
    encode(sha256(convert_to(app.policy_rollout_canonical_json(p_payload), 'UTF8')), 'hex'),
    v_summary, p_actor_user_id, v_now, v_now + interval '7 days'
  )
  returning * into v_row;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'policy_change.requested',
    jsonb_build_object('request_id', v_row.id, 'change_kind', v_row.change_kind,
      'base_version', v_row.base_version, 'target_version', v_row.target_version,
      'payload_sha256', v_row.payload_sha256, 'summary', v_row.summary));
  return jsonb_build_object('request_id', v_row.id, 'status', v_row.status, 'change_kind', v_row.change_kind,
    'payload_sha256', v_row.payload_sha256, 'expires_at', v_row.expires_at);
end;
$$;
revoke all on function public.submit_policy_change_request(uuid, uuid, text, bigint, bigint, bigint, jsonb)
  from public, anon, authenticated;
grant execute on function public.submit_policy_change_request(uuid, uuid, text, bigint, bigint, bigint, jsonb)
  to service_role;

-- ── RPC: decide a change request (a second owner/admin) ────────────────────
-- Approval runs the existing publication RPC with the author as publisher,
-- so both people must still be owners/admins. A version conflict (someone
-- published in between) marks the request superseded; nothing is applied.

create or replace function public.decide_policy_change_request(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_request_id uuid,
  p_decision text,
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
  v_row public.policy_change_requests;
  v_runtime public.tenant_runtime_policies;
  v_dlp public.tenant_dlp_policies;
  v_result jsonb;
  v_applied bigint;
  v_outcome text;
  v_state text;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_request_id is null
     or p_decision is null or p_decision not in ('approve', 'reject')
     or not app.ai_governance_text_valid(p_reason, 500, true) then
    raise exception 'invalid_policy_change_decision' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'policy_forbidden' using errcode = '42501';
  end if;
  select * into v_row from public.policy_change_requests
   where id = p_request_id and tenant_id = p_tenant_id
   for update;
  if not found then
    raise exception 'policy_change_request_not_found' using errcode = 'P0002';
  end if;
  if v_row.status <> 'pending' then
    return jsonb_build_object('outcome', 'already_final', 'request_id', v_row.id, 'status', v_row.status);
  end if;
  if v_row.expires_at <= v_now then
    update public.policy_change_requests set status = 'expired', closed_at = v_now where id = v_row.id;
    perform app.ai_governance_audit(p_tenant_id, null, 'policy_change.expired',
      jsonb_build_object('request_id', v_row.id, 'change_kind', v_row.change_kind));
    return jsonb_build_object('outcome', 'expired', 'request_id', v_row.id, 'status', 'expired');
  end if;
  if v_row.requested_by = p_actor_user_id then
    raise exception 'four_eyes_self_approval' using errcode = '42501';
  end if;

  if p_decision = 'reject' then
    update public.policy_change_requests
       set status = 'rejected', decided_by = p_actor_user_id, decided_at = v_now,
           decision_reason = btrim(p_reason), closed_at = v_now
     where id = v_row.id;
    perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'policy_change.rejected',
      jsonb_build_object('request_id', v_row.id, 'change_kind', v_row.change_kind,
        'requested_by', v_row.requested_by, 'payload_sha256', v_row.payload_sha256, 'reason', btrim(p_reason)));
    return jsonb_build_object('outcome', 'decided', 'request_id', v_row.id, 'status', 'rejected');
  end if;

  perform set_config('app.aidr_policy_change_request', v_row.id::text, true);
  begin
    case v_row.change_kind
      when 'runtime_publish', 'runtime_restore' then
        v_runtime := public.publish_runtime_policy(p_tenant_id, v_row.requested_by, v_row.base_version,
          v_row.payload->'policy');
        v_applied := v_runtime.version;
      when 'runtime_publish_document' then
        v_runtime := public.publish_runtime_policy_document(p_tenant_id, v_row.requested_by, v_row.base_version,
          v_row.payload->'policy', (v_row.payload->'expected_document'->>'id')::uuid,
          (v_row.payload->'expected_document'->>'version')::bigint,
          v_row.payload->'expected_document'->>'source_sha256');
        v_applied := v_runtime.version;
      when 'runtime_stage' then
        v_result := public.stage_runtime_policy(p_tenant_id, v_row.requested_by, v_row.base_version,
          v_row.expected_revision_version, v_row.payload->'policy',
          array(select (jsonb_array_elements_text(v_row.payload->'agent_ids'))::uuid));
        v_applied := (v_result->>'version')::bigint;
      when 'runtime_rollout' then
        v_result := public.create_policy_rollout(p_tenant_id, v_row.requested_by, v_row.base_version,
          v_row.expected_revision_version, v_row.payload->'policy', v_row.payload->'rings');
        v_applied := (v_result->>'version')::bigint;
      when 'dlp_publish' then
        v_dlp := public.publish_dlp_policy(p_tenant_id, v_row.requested_by, v_row.base_version,
          v_row.payload->'policy');
        v_applied := v_dlp.version;
      when 'disable_four_eyes' then
        update public.tenant_ai_governance_settings
           set policy_four_eyes = false, updated_by = p_actor_user_id, updated_at = v_now
         where tenant_id = p_tenant_id;
        v_applied := null;
    end case;
  exception
    when sqlstate 'PT409' or sqlstate '40001' then
      v_outcome := 'superseded';
      get stacked diagnostics v_state = message_text;
    when sqlstate '42501' or sqlstate '22023' or sqlstate '23514' or sqlstate '22P02' then
      v_outcome := 'failed';
      get stacked diagnostics v_state = message_text;
  end;
  perform set_config('app.aidr_policy_change_request', '', true);

  if v_outcome is not null then
    v_state := lower(coalesce(substring(v_state from '^([a-z][a-z0-9_]{0,63})'), v_outcome));
    update public.policy_change_requests
       set status = v_outcome, decided_by = p_actor_user_id, decided_at = v_now,
           decision_reason = btrim(p_reason), closed_at = v_now, outcome_code = v_state
     where id = v_row.id;
    perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'policy_change.' || v_outcome,
      jsonb_build_object('request_id', v_row.id, 'change_kind', v_row.change_kind,
        'requested_by', v_row.requested_by, 'outcome_code', v_state));
    return jsonb_build_object('outcome', v_outcome, 'request_id', v_row.id, 'status', v_outcome,
      'outcome_code', v_state);
  end if;

  update public.policy_change_requests
     set status = 'approved', decided_by = p_actor_user_id, decided_at = v_now,
         decision_reason = btrim(p_reason), closed_at = v_now, applied_version = v_applied
   where id = v_row.id;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'policy_change.approved',
    jsonb_build_object('request_id', v_row.id, 'change_kind', v_row.change_kind,
      'requested_by', v_row.requested_by, 'applied_version', v_applied,
      'payload_sha256', v_row.payload_sha256, 'reason', btrim(p_reason)));
  return jsonb_build_object('outcome', 'decided', 'request_id', v_row.id, 'status', 'approved',
    'change_kind', v_row.change_kind, 'applied_version', v_applied);
end;
$$;
revoke all on function public.decide_policy_change_request(uuid, uuid, uuid, text, text) from public, anon, authenticated;
grant execute on function public.decide_policy_change_request(uuid, uuid, uuid, text, text) to service_role;

-- ── RPC: settings (owner/admin) ────────────────────────────────────────────

create or replace function public.update_ai_governance_settings(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_policy_four_eyes boolean,
  p_default_review_days integer
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_role text;
  v_old public.tenant_ai_governance_settings;
  v_new public.tenant_ai_governance_settings;
  v_pending public.policy_change_requests;
  v_payload jsonb := '{}'::jsonb;
begin
  if p_tenant_id is null or p_actor_user_id is null
     or (p_policy_four_eyes is null and p_default_review_days is null)
     or (p_default_review_days is not null and p_default_review_days not between 30 and 730) then
    raise exception 'invalid_ai_governance_settings' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':policy-change', 0));
  insert into public.tenant_ai_governance_settings (tenant_id, updated_by, updated_at)
  values (p_tenant_id, p_actor_user_id, v_now)
  on conflict (tenant_id) do nothing;
  select * into v_old from public.tenant_ai_governance_settings where tenant_id = p_tenant_id for update;

  if p_policy_four_eyes is true and not v_old.policy_four_eyes then
    if (select count(*) from public.tenant_members m
         where m.tenant_id = p_tenant_id and m.role in ('owner', 'admin')
           and (m.expires_at is null or m.expires_at > v_now)) < 2 then
      raise exception 'four_eyes_requires_two_approvers' using errcode = '55000';
    end if;
  end if;

  update public.tenant_ai_governance_settings
     set policy_four_eyes = case when p_policy_four_eyes is true then true else policy_four_eyes end,
         default_review_days = coalesce(p_default_review_days, default_review_days),
         updated_by = p_actor_user_id, updated_at = v_now
   where tenant_id = p_tenant_id
  returning * into v_new;

  -- Turning four-eyes off needs a second person like any other policy change.
  if p_policy_four_eyes is false and v_old.policy_four_eyes then
    select * into v_pending from public.policy_change_requests
     where tenant_id = p_tenant_id and change_kind = 'disable_four_eyes' and status = 'pending'
       and expires_at > v_now;
    if not found then
      insert into public.policy_change_requests (
        tenant_id, change_kind, base_version, payload, payload_sha256, summary, requested_by, created_at, expires_at
      ) values (
        p_tenant_id, 'disable_four_eyes', 0, v_payload,
        encode(sha256(convert_to(app.policy_rollout_canonical_json(v_payload), 'UTF8')), 'hex'),
        '{}'::jsonb, p_actor_user_id, v_now, v_now + interval '7 days'
      )
      on conflict (tenant_id) where status = 'pending' and change_kind = 'disable_four_eyes' do nothing
      returning * into v_pending;
      if v_pending.id is null then
        raise exception 'policy_change_request_pending' using errcode = '23505';
      end if;
      perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'policy_change.requested',
        jsonb_build_object('request_id', v_pending.id, 'change_kind', 'disable_four_eyes'));
    end if;
  end if;

  if v_new.policy_four_eyes is distinct from v_old.policy_four_eyes
     or v_new.default_review_days is distinct from v_old.default_review_days then
    perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_governance.settings_updated',
      jsonb_build_object('policy_four_eyes_from', v_old.policy_four_eyes, 'policy_four_eyes_to', v_new.policy_four_eyes,
        'default_review_days_from', v_old.default_review_days, 'default_review_days_to', v_new.default_review_days));
  end if;
  return jsonb_build_object('policy_four_eyes', v_new.policy_four_eyes,
    'default_review_days', v_new.default_review_days,
    'pending_disable_request_id', v_pending.id);
end;
$$;
revoke all on function public.update_ai_governance_settings(uuid, uuid, boolean, integer) from public, anon, authenticated;
grant execute on function public.update_ai_governance_settings(uuid, uuid, boolean, integer) to service_role;

-- ── RPC: cancel a pending request (its requester, or an owner/admin) ───────

create or replace function public.cancel_ai_governance_request(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_kind text,
  p_request_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_role text;
  v_requested_by uuid;
  v_status text;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_request_id is null
     or p_kind is null or p_kind not in ('intake', 'exception', 'policy_change') then
    raise exception 'invalid_ai_governance_cancel' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  if p_kind = 'intake' then
    select requested_by, status into v_requested_by, v_status from public.ai_intake_requests
     where id = p_request_id and tenant_id = p_tenant_id for update;
  elsif p_kind = 'exception' then
    select requested_by, status into v_requested_by, v_status from public.ai_governance_exceptions
     where id = p_request_id and tenant_id = p_tenant_id for update;
  else
    select requested_by, status into v_requested_by, v_status from public.policy_change_requests
     where id = p_request_id and tenant_id = p_tenant_id for update;
  end if;
  if v_status is null then
    raise exception 'ai_governance_request_not_found' using errcode = 'P0002';
  end if;
  if v_requested_by <> p_actor_user_id and v_role not in ('owner', 'admin') then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  if v_status <> 'pending' then
    return jsonb_build_object('outcome', 'already_final', 'request_id', p_request_id, 'status', v_status);
  end if;
  if p_kind = 'intake' then
    update public.ai_intake_requests set status = 'cancelled', closed_at = v_now where id = p_request_id;
  elsif p_kind = 'exception' then
    update public.ai_governance_exceptions set status = 'cancelled', closed_at = v_now where id = p_request_id;
  else
    update public.policy_change_requests set status = 'cancelled', closed_at = v_now where id = p_request_id;
  end if;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_governance.request_cancelled',
    jsonb_build_object('kind', p_kind, 'request_id', p_request_id,
      'by_requester', v_requested_by = p_actor_user_id));
  return jsonb_build_object('outcome', 'cancelled', 'request_id', p_request_id, 'status', 'cancelled');
end;
$$;
revoke all on function public.cancel_ai_governance_request(uuid, uuid, text, uuid) from public, anon, authenticated;
grant execute on function public.cancel_ai_governance_request(uuid, uuid, text, uuid) to service_role;
