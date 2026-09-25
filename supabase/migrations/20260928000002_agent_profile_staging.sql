-- Agent permission profiles: dashboard staging for operator publication.
--
-- Why staging and not server-side signing
--   Connectors accept managed profiles only from the tenant detector bundle
--   (~/.singularity-aidr/detectors/<runtime>.json), a local file verified by
--   packages/core/src/detector-provisioning.ts against
--   `licensing.public_keys_pem` and bound to the verified entitlement's tenant.
--   There is no network path through which the control plane delivers that
--   bundle, and the per-tenant dashboard-approval keys (20260926000001) are
--   trusted only for approval tokens, never for detector bundles. Signing
--   bundles on the server would require putting a key the connectors trust for
--   detector policy on the server (widening what the entitlement signing key
--   authorises) and would still not deliver anything. So the dashboard
--   validates and STAGES a profile document (versioned, audited, optionally
--   four-eyes approved), and the operator publishes it with one command that
--   pulls exactly that staged revision and signs it with the operator-held key:
--     node scripts/provision-agent-profiles.mjs --endpoint <…/policy-management>
--       --token-file <aal2 token> --tenant <id> --revision <n> --runtime <runtime>
--       --expires-at <UTC ≤ 24h> --private-key <ed25519.pem> --output-dir <dir>
--   Signature verification in the connectors is unchanged.
--
-- Storage
--   tenant_agent_profiles        the current staged document per tenant
--   agent_profile_revisions      every staged revision (immutable history)
--   Both are service-role only (like tenant_dlp_policies): profiles describe
--   the tenant's allowed commands, paths and hosts. policy-management serves
--   them to owners/admins at AAL2. The document column is named `policy` so
--   four-eyes review (ai-governance) reads it like the runtime and DLP tables.
--
-- Four-eyes
--   With policy_four_eyes on, staging files an `agent_profiles_stage` change
--   request, and the BEFORE INSERT guard on agent_profile_revisions refuses any
--   revision not applied by the approval of such a request.

create table if not exists public.tenant_agent_profiles (
  tenant_id uuid primary key references public.tenants (id),
  version bigint not null check (version between 1 and 9007199254740991),
  policy jsonb not null check (jsonb_typeof(policy) = 'object' and octet_length(policy::text) <= 131072),
  policy_sha256 text not null check (policy_sha256 ~ '^[0-9a-f]{64}$'),
  profile_count integer not null check (profile_count between 1 and 50),
  updated_by uuid not null references auth.users (id),
  updated_at timestamptz not null default now(),
  check ((policy->>'version') = '1')
);

create table if not exists public.agent_profile_revisions (
  tenant_id uuid not null references public.tenants (id),
  version bigint not null check (version between 1 and 9007199254740991),
  policy jsonb not null check (jsonb_typeof(policy) = 'object' and octet_length(policy::text) <= 131072),
  policy_sha256 text not null check (policy_sha256 ~ '^[0-9a-f]{64}$'),
  profile_count integer not null check (profile_count between 1 and 50),
  restored_from bigint check (restored_from is null or (restored_from >= 1 and restored_from < version)),
  updated_by uuid not null references auth.users (id),
  created_at timestamptz not null default now(),
  primary key (tenant_id, version),
  check ((policy->>'version') = '1')
);

comment on table public.tenant_agent_profiles is
  'Current dashboard-staged agent permission profile document per tenant. Not signed or delivered: an operator publishes it with scripts/provision-agent-profiles.mjs.';
comment on table public.agent_profile_revisions is
  'Immutable history of staged agent permission profile documents. Service role only.';

alter table public.tenant_agent_profiles enable row level security;
alter table public.agent_profile_revisions enable row level security;
revoke all on public.tenant_agent_profiles, public.agent_profile_revisions from public, anon, authenticated, service_role;
grant select on public.tenant_agent_profiles, public.agent_profile_revisions to service_role;

drop policy if exists tenant_agent_profiles_no_client_access on public.tenant_agent_profiles;
create policy tenant_agent_profiles_no_client_access on public.tenant_agent_profiles
  as restrictive for all to authenticated
  using (false)
  with check (false);
drop policy if exists tenant_identity_access_restrict on public.tenant_agent_profiles;
create policy tenant_identity_access_restrict on public.tenant_agent_profiles
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

drop policy if exists agent_profile_revisions_no_client_access on public.agent_profile_revisions;
create policy agent_profile_revisions_no_client_access on public.agent_profile_revisions
  as restrictive for all to authenticated
  using (false)
  with check (false);
drop policy if exists tenant_identity_access_restrict on public.agent_profile_revisions;
create policy tenant_identity_access_restrict on public.agent_profile_revisions
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── RPC: stage a validated document (engine schema validated by the caller) ─

create or replace function public.stage_agent_profiles(
  p_tenant_id uuid,
  p_user_id uuid,
  p_expected_version bigint,
  p_policy jsonb,
  p_restored_from bigint
)
returns public.tenant_agent_profiles
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_current bigint;
  v_count integer;
  v_sha text;
  v_result public.tenant_agent_profiles;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 91606));
  -- Re-check the publisher inside the writing transaction and keep the rows
  -- locked so a concurrent demotion or suspension cannot slip past.
  perform 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_user_id
      and m.role in ('owner', 'admin') and (m.expires_at is null or m.expires_at > now())
      and t.status = 'active'
    for share of m, t;
  if not found then raise exception 'policy_forbidden' using errcode = '42501'; end if;
  if p_expected_version is null or p_expected_version < 0 or p_expected_version >= 9007199254740991
     or p_policy is null or jsonb_typeof(p_policy) <> 'object'
     or octet_length(p_policy::text) > 131072
     or (p_policy->>'version') is distinct from '1'
     or jsonb_typeof(p_policy->'profiles') is distinct from 'array'
     or jsonb_array_length(p_policy->'profiles') not between 1 and 50
     or exists (select 1 from jsonb_object_keys(p_policy) k
                 where k not in ('version', 'description', 'default_profile', 'profiles'))
     or (p_restored_from is not null and (p_restored_from < 1 or p_restored_from > p_expected_version)) then
    raise exception 'invalid_agent_profiles' using errcode = '22023';
  end if;
  select version into v_current from public.tenant_agent_profiles where tenant_id = p_tenant_id;
  if coalesce(v_current, 0) <> p_expected_version then
    raise exception 'policy_version_conflict' using errcode = 'PT409';
  end if;
  if p_restored_from is not null and not exists (
    select 1 from public.agent_profile_revisions r
     where r.tenant_id = p_tenant_id and r.version = p_restored_from
       and r.policy = p_policy
  ) then
    raise exception 'invalid_agent_profiles' using errcode = '22023';
  end if;
  v_count := jsonb_array_length(p_policy->'profiles');
  v_sha := encode(sha256(convert_to(app.policy_rollout_canonical_json(p_policy), 'UTF8')), 'hex');

  insert into public.agent_profile_revisions (tenant_id, version, policy, policy_sha256, profile_count,
    restored_from, updated_by)
  values (p_tenant_id, p_expected_version + 1, p_policy, v_sha, v_count, p_restored_from, p_user_id);
  insert into public.tenant_agent_profiles (tenant_id, version, policy, policy_sha256, profile_count, updated_by)
  values (p_tenant_id, p_expected_version + 1, p_policy, v_sha, v_count, p_user_id)
  on conflict (tenant_id) do update set version = excluded.version, policy = excluded.policy,
    policy_sha256 = excluded.policy_sha256, profile_count = excluded.profile_count,
    updated_by = excluded.updated_by, updated_at = now()
  returning * into v_result;
  -- Metadata only: commands, paths and hosts are not copied into audit logs.
  insert into public.admin_audit_logs (actor_user_id, tenant_id, action, detail)
  values (p_user_id, p_tenant_id, 'agent_profiles.staged', jsonb_build_object(
    'version', v_result.version, 'previous_version', p_expected_version,
    'restored_from', p_restored_from, 'profiles', v_count, 'policy_sha256', v_sha,
    'delivery_status', 'staged_not_signed'));
  return v_result;
end;
$$;
revoke all on function public.stage_agent_profiles(uuid, uuid, bigint, jsonb, bigint) from public, anon, authenticated;
grant execute on function public.stage_agent_profiles(uuid, uuid, bigint, jsonb, bigint) to service_role;

-- ── Four-eyes: new change kind ─────────────────────────────────────────────

alter table public.policy_change_requests drop constraint if exists policy_change_requests_change_kind_check;
alter table public.policy_change_requests add constraint policy_change_requests_change_kind_check
  check (change_kind in (
    'runtime_publish', 'runtime_publish_document', 'runtime_restore', 'runtime_stage',
    'runtime_rollout', 'dlp_publish', 'disable_four_eyes', 'agent_profiles_stage'
  ));

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
          and case tg_table_name
                when 'dlp_policy_revisions' then r.change_kind = 'dlp_publish'
                when 'agent_profile_revisions' then r.change_kind = 'agent_profiles_stage'
                else r.change_kind like 'runtime\_%' end) then
    raise exception 'policy_four_eyes_required' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.enforce_policy_four_eyes() from public, anon, authenticated;

drop trigger if exists agent_profile_revisions_four_eyes on public.agent_profile_revisions;
create trigger agent_profile_revisions_four_eyes
  before insert on public.agent_profile_revisions
  for each row execute function app.enforce_policy_four_eyes();

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
    when 'agent_profiles_stage' then
      case when p_payload ? 'restored_from' then array['policy', 'restored_from'] else array['policy'] end
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
         or (p_payload->'policy'->>'version') is distinct from (p_base_version + 1)::text))
     or (p_change_kind = 'agent_profiles_stage' and ((p_payload->'policy'->>'version') is distinct from '1'
         or jsonb_typeof(p_payload->'policy'->'profiles') is distinct from 'array'
         or (p_payload ? 'restored_from' and ((p_payload->>'restored_from') !~ '^[1-9][0-9]{0,15}$'
             or (p_payload->>'restored_from')::bigint > p_base_version)))) then
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
    when p_change_kind = 'agent_profiles_stage' then jsonb_build_object(
      'profiles', jsonb_array_length(p_payload->'policy'->'profiles'))
      || case when p_payload ? 'restored_from'
           then jsonb_build_object('restored_from', (p_payload->>'restored_from')::bigint) else '{}'::jsonb end
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
  v_profiles public.tenant_agent_profiles;
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
      when 'agent_profiles_stage' then
        v_profiles := public.stage_agent_profiles(p_tenant_id, v_row.requested_by, v_row.base_version,
          v_row.payload->'policy', (v_row.payload->>'restored_from')::bigint);
        v_applied := v_profiles.version;
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

-- ── History immutability ───────────────────────────────────────────────────
-- Revisions never change. Deletion is reserved to tenant offboarding (below),
-- which sets a transaction-local marker naming the tenant.
create or replace function app.protect_agent_profile_revisions()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if tg_op = 'DELETE'
     and current_setting('app.aidr_agent_profile_offboarding', true) = old.tenant_id::text then
    return old;
  end if;
  raise exception 'agent_profile_revision_immutable' using errcode = '42501';
end;
$$;
revoke all on function app.protect_agent_profile_revisions() from public, anon, authenticated;

drop trigger if exists agent_profile_revisions_immutable on public.agent_profile_revisions;
create trigger agent_profile_revisions_immutable
  before update or delete on public.agent_profile_revisions
  for each row execute function app.protect_agent_profile_revisions();

-- ── Offboarding ────────────────────────────────────────────────────────────
-- Staged profiles are policy_configuration, like the DLP documents: they are
-- deleted when the offboarding run's `tenant_dlp_policies` phase completes
-- (same retention, same tenant lock and legal-hold check), and the rows are
-- counted in that phase receipt.
create or replace function app.purge_agent_profiles_at_offboarding_phase()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_tenant uuid;
  v_status text;
  v_rows bigint;
  v_more bigint;
begin
  if new.phase <> 'tenant_dlp_policies' or new.status <> 'completed' or old.status = 'completed' then
    return new;
  end if;
  select r.tenant_id, r.status into v_tenant, v_status
    from public.tenant_offboarding_runs r where r.id = new.run_id;
  if v_tenant is null or v_status <> 'running' or new.eligible_at > now() then
    raise exception 'agent_profile_offboarding_phase_invalid' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  if exists (
    select 1 from public.tenant_legal_holds h
     where h.tenant_id = v_tenant and h.released_at is null
  ) then
    raise exception 'agent_profile_offboarding_legal_hold' using errcode = '42501';
  end if;
  perform set_config('app.aidr_agent_profile_offboarding', v_tenant::text, true);
  delete from public.agent_profile_revisions where tenant_id = v_tenant;
  get diagnostics v_rows = row_count;
  delete from public.tenant_agent_profiles where tenant_id = v_tenant;
  get diagnostics v_more = row_count;
  perform set_config('app.aidr_agent_profile_offboarding', '', true);
  v_rows := v_rows + v_more;
  if v_rows > 0 then
    update public.tenant_offboarding_phase_receipts
       set rows_deleted = rows_deleted + v_rows
     where run_id = new.run_id and phase = new.phase and status = 'completed';
  end if;
  return new;
end;
$$;
revoke all on function app.purge_agent_profiles_at_offboarding_phase() from public, anon, authenticated, service_role;

drop trigger if exists tenant_offboarding_purge_agent_profiles on public.tenant_offboarding_phase_receipts;
create trigger tenant_offboarding_purge_agent_profiles
  after update of status on public.tenant_offboarding_phase_receipts
  for each row execute function app.purge_agent_profiles_at_offboarding_phase();

-- A tenant that is already offboarding cannot stage profiles (stage_agent_profiles
-- requires an active tenant), so no completed run can hold a staged document.
