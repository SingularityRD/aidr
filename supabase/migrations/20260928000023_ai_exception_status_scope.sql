-- AI governance: an exception waives only the enforcement level it was approved for.
--
-- ai_governance_policy_overlay (20260927000040) dropped an asset from the
-- connector overlay for every approved, unexpired exception in scope, whatever
-- the asset's status had become since. An exception approved while an MCP
-- server was `restricted` (require approval) therefore kept waiving it after
-- an administrator escalated the server to `banned`, for example during
-- incident response: the waived members or agents got neither the deny nor the
-- approval requirement, while the tenant-wide enforcement preview showed the
-- server as banned. Nobody decided that a ban should be waived.
--
-- Each approved exception now records the asset status it was decided against
-- (`waived_status`), and the overlay honours it only while the asset's current
-- status is no stricter (banned > restricted). Escalation therefore suspends
-- the waiver at once, without a sweep; lowering the status back restores it
-- (still bounded by the exception's own window). Waiving a ban needs a new
-- exception decided against the ban.
--
-- Existing approved exceptions are backfilled with their asset's current
-- enforced status, so the migration does not change what is enforced today.

alter table public.ai_governance_exceptions
  add column if not exists waived_status text;

update public.ai_governance_exceptions e
   set waived_status = case when a.status in ('banned', 'restricted') then a.status else 'restricted' end
  from public.ai_assets a
 where a.id = e.asset_id and a.tenant_id = e.tenant_id
   and e.waived_status is null
   and e.status in ('approved', 'revoked', 'expired');

alter table public.ai_governance_exceptions
  drop constraint if exists ai_governance_exceptions_waived_status;
alter table public.ai_governance_exceptions
  add constraint ai_governance_exceptions_waived_status check (
    (waived_status is null or waived_status in ('restricted', 'banned'))
    and (status <> 'approved' or waived_status is not null)
  );

comment on column public.ai_governance_exceptions.waived_status is
  'Asset status the exception was approved against; the overlay waives nothing stricter (20260928000023).';

-- ── RPC: decide an exception (records the waived level) ────────────────────

create or replace function public.decide_ai_governance_exception(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_exception_id uuid,
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
  v_row public.ai_governance_exceptions;
  v_asset public.ai_assets;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_exception_id is null
     or p_decision is null or p_decision not in ('approve', 'reject')
     or not app.ai_governance_text_valid(p_reason, 500, true) then
    raise exception 'invalid_ai_governance_exception_decision' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':ai-governance', 0));
  select * into v_row from public.ai_governance_exceptions
   where id = p_exception_id and tenant_id = p_tenant_id
   for update;
  if not found then
    raise exception 'ai_governance_exception_not_found' using errcode = 'P0002';
  end if;
  if v_row.status <> 'pending' then
    return jsonb_build_object('outcome', 'already_final', 'exception_id', v_row.id, 'status', v_row.status);
  end if;
  if v_row.expires_at <= v_now then
    update public.ai_governance_exceptions set status = 'expired', closed_at = v_now where id = v_row.id;
    perform app.ai_governance_audit(p_tenant_id, null, 'ai_exception.expired',
      jsonb_build_object('exception_id', v_row.id, 'asset_id', v_row.asset_id, 'was', 'pending'));
    return jsonb_build_object('outcome', 'expired', 'exception_id', v_row.id, 'status', 'expired');
  end if;
  if v_row.requested_by = p_actor_user_id then
    raise exception 'four_eyes_self_approval' using errcode = '42501';
  end if;
  select * into v_asset from public.ai_assets where id = v_row.asset_id and tenant_id = p_tenant_id for share;

  if p_decision = 'reject' then
    update public.ai_governance_exceptions
       set status = 'rejected', decided_by = p_actor_user_id, decided_at = v_now,
           decision_reason = btrim(p_reason), closed_at = v_now
     where id = v_row.id;
  else
    if v_asset.status not in ('banned', 'restricted') then
      raise exception 'ai_governance_exception_not_restricted' using errcode = '55000';
    end if;
    if v_asset.risk_tier = 'prohibited' then
      raise exception 'ai_asset_prohibited' using errcode = '55000';
    end if;
    update public.ai_governance_exceptions
       set status = 'approved', decided_by = p_actor_user_id, decided_at = v_now,
           decision_reason = btrim(p_reason), starts_at = v_now, waived_status = v_asset.status
     where id = v_row.id;
  end if;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id,
    case when p_decision = 'approve' then 'ai_exception.approved' else 'ai_exception.rejected' end,
    jsonb_build_object('exception_id', v_row.id, 'asset_id', v_row.asset_id,
      'asset_type', v_asset.asset_type, 'identifier', v_asset.identifier,
      'scope_kind', v_row.scope_kind, 'expires_at', v_row.expires_at,
      'waived_status', case when p_decision = 'approve' then v_asset.status end,
      'requested_by', v_row.requested_by, 'reason', btrim(p_reason)));
  return jsonb_build_object('outcome', 'decided', 'exception_id', v_row.id,
    'status', case when p_decision = 'approve' then 'approved' else 'rejected' end,
    'expires_at', v_row.expires_at,
    'waived_status', case when p_decision = 'approve' then v_asset.status end);
end;
$$;
revoke all on function public.decide_ai_governance_exception(uuid, uuid, uuid, text, text) from public, anon, authenticated;
grant execute on function public.decide_ai_governance_exception(uuid, uuid, uuid, text, text) to service_role;

-- ── Enforcement feed (waives only up to the approved level) ────────────────

create or replace function public.ai_governance_policy_overlay(
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
  with enforced as (
    select a.id, a.asset_type, a.identifier, a.status
      from public.ai_assets a
     where a.tenant_id = p_tenant_id
       and a.status in ('banned', 'restricted')
       and app.ai_asset_enforceable(a.asset_type, a.identifier)
  ),
  waived as (
    select distinct e.asset_id
      from public.ai_governance_exceptions e
      join enforced x on x.id = e.asset_id
     where e.tenant_id = p_tenant_id
       and e.status = 'approved'
       and e.starts_at <= clock_timestamp()
       and e.expires_at > clock_timestamp()
       -- An exception never waives a stricter status than it was approved for.
       and e.waived_status is not null
       and app.ai_status_rank(x.status) <= app.ai_status_rank(e.waived_status)
       and (e.scope_kind = 'tenant'
         or (e.scope_kind = 'members' and p_user_id is not null and p_user_id = any (e.scope_user_ids))
         or (e.scope_kind = 'agents' and p_agent_id is not null and p_agent_id = any (e.scope_agent_ids)))
  ),
  effective as (
    select * from enforced where id not in (select asset_id from waived)
  )
  select jsonb_build_object(
    'mcp_deny_servers', coalesce((
      select jsonb_agg(identifier order by identifier collate "C") from effective
       where asset_type = 'mcp_server' and status = 'banned'), '[]'::jsonb),
    'mcp_require_approval_servers', coalesce((
      select jsonb_agg(identifier order by identifier collate "C") from effective
       where asset_type = 'mcp_server' and status = 'restricted'), '[]'::jsonb),
    'browser_guard_blocked_sites', coalesce((
      select jsonb_agg(identifier order by identifier collate "C") from effective
       where asset_type = 'ai_site' and status = 'banned'), '[]'::jsonb)
  )
  where p_tenant_id is not null
$$;
revoke all on function public.ai_governance_policy_overlay(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.ai_governance_policy_overlay(uuid, uuid, uuid) to service_role;
