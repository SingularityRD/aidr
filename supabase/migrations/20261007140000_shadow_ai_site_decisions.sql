-- Shadow AI allow/block decisions for Browser Guard (docs/ai-governance.md).
--
-- Owners and administrators allow or block a detected AI service from the
-- dashboard. The decision is an AI governance register entry (public.ai_assets,
-- asset_type 'ai_site', identifier = Browser Guard Shadow AI catalog id): no new
-- table. `banned` blocks the service and `approved` sanctions it. Writes stay on
-- the existing upsert_ai_asset RPC (owner/admin re-checked under row locks,
-- AAL2 and identity barrier in the ai-governance Edge Function, audit rows in
-- the same transaction, optimistic versioning).
--
-- This migration:
--   * adds app.ai_shadow_ai_service: the catalog id shape shared with
--     packages/browser-guard (AI_SERVICE_ID_PATTERN) and the browser-guard-policy
--     Edge Function;
--   * makes such ai_site assets enforceable, so relaxing a Shadow AI ban is under
--     four-eyes change control and designated reviewers cannot lift it, exactly
--     like an MCP ban;
--   * extends ai_governance_policy_overlay with `browser_guard_shadow_ai`
--     ({ blocked, sanctioned }). Bans are resolved against approved, unexpired
--     exceptions by the same `waived` logic as MCP bans. The browser-guard-policy
--     Edge Function signs this list (Ed25519 runtime-policy envelope) and Browser
--     Guard applies it under its enterprise policy, most restrictive wins.
--     `browser_guard_blocked_sites` keeps listing only built-in Browser Guard site
--     ids, because the managed `blockedSites` key refuses anything else.
--
-- Additive and idempotent: CREATE OR REPLACE only; grants unchanged.

create or replace function app.ai_shadow_ai_service(p_identifier text)
returns boolean
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select p_identifier is not null and p_identifier ~ '^[a-z0-9][a-z0-9-]{0,31}$'
$$;
revoke all on function app.ai_shadow_ai_service(text) from public, anon, authenticated;

-- An asset whose status has an enforcement effect somewhere.
create or replace function app.ai_asset_enforceable(p_type text, p_identifier text)
returns boolean
language sql
immutable
set search_path = pg_catalog, app, pg_temp
as $$
  select p_type = 'mcp_server'
      or (p_type = 'ai_site'
          and (app.ai_browser_guard_site(p_identifier) or app.ai_shadow_ai_service(p_identifier)))
$$;
revoke all on function app.ai_asset_enforceable(text, text) from public, anon, authenticated;

-- ── Enforcement feed ───────────────────────────────────────────────────────

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
  ),
  sanctioned as (
    select a.identifier
      from public.ai_assets a
     where a.tenant_id = p_tenant_id
       and a.asset_type = 'ai_site'
       and a.status = 'approved'
       and app.ai_shadow_ai_service(a.identifier)
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
       where asset_type = 'ai_site' and status = 'banned'
         and app.ai_browser_guard_site(identifier)), '[]'::jsonb),
    'browser_guard_shadow_ai', jsonb_build_object(
      'blocked', coalesce((
        select jsonb_agg(identifier order by identifier collate "C") from effective
         where asset_type = 'ai_site' and status = 'banned'
           and app.ai_shadow_ai_service(identifier)), '[]'::jsonb),
      'sanctioned', coalesce((
        select jsonb_agg(identifier order by identifier collate "C") from sanctioned), '[]'::jsonb))
  )
  where p_tenant_id is not null
$$;
revoke all on function public.ai_governance_policy_overlay(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.ai_governance_policy_overlay(uuid, uuid, uuid) to service_role;
