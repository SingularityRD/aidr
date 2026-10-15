-- Separation of duties for out-of-band approvals (CP-9).
--
-- decide_approval_request only checked that the actor was an active
-- owner/admin, so an admin could approve the `ask` block raised by their own
-- API key / agent. A tenant option now requires a different approver:
--
--   * tenant_ai_governance_settings.approval_require_distinct_approver:
--       true  -> the requester may never approve their own request;
--       false -> self-approval allowed (recorded as approval.self_approved);
--       null  -> plan default: required on Business and Enterprise, allowed on
--                Free and Team (a one-admin workspace must still be able to
--                unblock its own agent). An unresolvable plan counts as
--                "required" (fail closed).
--   * public.update_approval_settings (service role, called by ai-governance
--     after session, identity barrier, owner/admin and AAL2 checks) changes it;
--     relaxing it while four-eyes policy change control is on is refused, like
--     the other governance relaxations, and every change is audited.
--   * decide_approval_request refuses requester == approver approvals with the
--     outcome `self_approval_forbidden` and an `approval.self_approval_refused`
--     audit row; a permitted self-approval is audited as
--     `approval.self_approved` with `self_approval: true` in the detail.
--
-- Additive: one nullable column, two new functions, decide_approval_request
-- redefined with the same signature and grants.

alter table public.tenant_ai_governance_settings
  add column if not exists approval_require_distinct_approver boolean;

comment on column public.tenant_ai_governance_settings.approval_require_distinct_approver is
  'Approvals: the requester may not approve their own request (true), may (false), or plan default (null: Business/Enterprise require it). Changed only through update_approval_settings.';

create or replace function app.approval_distinct_approver_required(p_tenant_id uuid)
returns boolean
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_setting boolean;
  v_plan text;
begin
  select s.approval_require_distinct_approver into v_setting
    from public.tenant_ai_governance_settings s where s.tenant_id = p_tenant_id;
  if v_setting is not null then return v_setting; end if;
  begin
    v_plan := app.tenant_plan_entitlements(p_tenant_id)->>'plan_id';
  exception when others then
    return true;
  end;
  return v_plan is null or v_plan in ('business', 'enterprise');
end;
$$;
revoke all on function app.approval_distinct_approver_required(uuid) from public, anon, authenticated;

create or replace function public.update_approval_settings(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_require_distinct_approver boolean
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
  v_before boolean;
  v_after boolean;
begin
  if p_tenant_id is null or p_actor_user_id is null then
    raise exception 'invalid_approval_settings' using errcode = '22023';
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

  if v_old.approval_require_distinct_approver is not distinct from p_require_distinct_approver then
    return jsonb_build_object('require_distinct_approver', v_old.approval_require_distinct_approver,
      'effective', app.approval_distinct_approver_required(p_tenant_id), 'changed', false);
  end if;

  v_before := app.approval_distinct_approver_required(p_tenant_id);
  update public.tenant_ai_governance_settings
     set approval_require_distinct_approver = p_require_distinct_approver,
         updated_by = p_actor_user_id, updated_at = v_now
   where tenant_id = p_tenant_id;
  v_after := app.approval_distinct_approver_required(p_tenant_id);

  -- Relaxing separation of duties under four-eyes change control needs a second person.
  if v_before and not v_after and v_old.policy_four_eyes then
    raise exception 'approval_separation_four_eyes_required' using errcode = '42501';
  end if;

  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'approval.settings_updated',
    jsonb_build_object('require_distinct_approver_from', v_old.approval_require_distinct_approver,
      'require_distinct_approver_to', p_require_distinct_approver,
      'effective_from', v_before, 'effective_to', v_after));
  return jsonb_build_object('require_distinct_approver', p_require_distinct_approver,
    'effective', v_after, 'changed', true);
end;
$$;
revoke all on function public.update_approval_settings(uuid, uuid, boolean) from public, anon, authenticated;
grant execute on function public.update_approval_settings(uuid, uuid, boolean) to service_role;

-- Member projection for the dashboard: the effective rule for this tenant.
create or replace function public.get_approval_settings(p_tenant_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
begin
  if p_tenant_id is null or not app.is_tenant_member(p_tenant_id) then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  return jsonb_build_object(
    'require_distinct_approver', (select s.approval_require_distinct_approver
      from public.tenant_ai_governance_settings s where s.tenant_id = p_tenant_id),
    'effective', app.approval_distinct_approver_required(p_tenant_id));
end;
$$;
revoke all on function public.get_approval_settings(uuid) from public, anon;
grant execute on function public.get_approval_settings(uuid) to authenticated, service_role;

-- ── decide_approval_request with separation of duties ──────────────────────
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
  v_self boolean;
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

  -- Separation of duties (CP-9): the person whose key/agent raised the request
  -- may not approve it while the tenant requires a different approver. The
  -- refusal is audited and returned (not raised) so the audit row persists;
  -- nothing is signed or stored for the request. Denying your own request only
  -- tightens enforcement and stays allowed.
  v_self := v_row.requested_by = p_actor_user_id;
  if v_self and p_decision = 'approve' and app.approval_distinct_approver_required(p_tenant_id) then
    perform app.approval_audit(p_tenant_id, p_actor_user_id, 'approval.self_approval_refused',
      jsonb_build_object('request_id', v_row.id, 'iid', v_row.iid, 'agent_id', v_row.agent_id,
        'action_id', v_row.action_id, 'tool', v_row.tool));
    return jsonb_build_object('outcome', 'self_approval_forbidden', 'request_id', v_row.id, 'status', v_row.status);
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

  -- A permitted self-approval is recorded under its own action so reviewers
  -- can find every decision that was not made by a second person.
  perform app.approval_audit(p_tenant_id, p_actor_user_id,
    case when v_self and v_status = 'approved' then 'approval.self_approved' else 'approval.' || v_status end,
    jsonb_build_object(
      'self_approval', v_self,
      'requested_by', v_row.requested_by,
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
