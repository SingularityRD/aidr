-- Dashboard approvals: bind the whole request subject on idempotent replay and
-- refuse invisible/reordering characters in what the approver reads.
--
-- create_approval_request (20260926000001) is idempotent on
-- (tenant, iid, action_id) and, on a replay, compared only the artifact digest
-- and the tool. The action id and the digest are deterministic, and a policed
-- agent that can read its connector's tenant API key could file the request
-- FIRST with a harmless-looking summary and no threat ids; the connector's own
-- filing then returned the existing row (`created: false`) and the approver saw
-- the agent's text next to the real digest. A replay must now name exactly the
-- same subject (summary, threat ids and runtime as well); anything else is the
-- existing `approval_request_conflict`, which keeps the call blocked.
--
-- The summary, tool and installation id are also refused when they carry
-- Unicode format or separator characters (bidi overrides and isolates,
-- zero-width characters, BOM, tag characters, U+2028/2029): the dashboard shows
-- them to a human deciding whether to release a blocked action, and such
-- characters can reorder or hide what is displayed. The connector already
-- renders them as visible escapes, so a genuine request never contains them.
-- The Edge Function applies the same rule before the RPC.

create or replace function app.approval_text_displayable(p_value text)
returns boolean
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select p_value is not null
    and p_value !~ '[[:cntrl:]]'
    and p_value !~ '[­؀-؅؜۝܏࢐࢑࣢᠎​-‏ -‮⁠-⁤⁦-⁯﻿￹-￻\U000110bd\U000110cd\U00013430-\U0001343f\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0001\U000e0020-\U000e007f]'
$$;
revoke all on function app.approval_text_displayable(text) from public, anon, authenticated;

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
revoke all on function public.create_approval_request(uuid, uuid, uuid, uuid, text, text, text, text, text, text[], text, timestamptz)
  from public, anon, authenticated;
grant execute on function public.create_approval_request(uuid, uuid, uuid, uuid, text, text, text, text, text, text[], text, timestamptz)
  to service_role;
