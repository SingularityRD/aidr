-- AI governance: asset register, intake requests and exceptions
-- (docs/ai-governance.md).
--
-- "Who may use which AI, why, and who approved it." One tenant-scoped register
-- of AI systems in use (coding agents/connectors, MCP servers, AI chat sites,
-- models/AI services), populated from data the control plane already holds
-- (enrolled agents, MCP inventory posture findings, Browser Guard site counts,
-- discovery targets) plus manual entries and approved intake requests.
--
-- Tables
--   tenant_ai_governance_settings  per-tenant options (four-eyes policy change
--                                  control, default review interval)
--   ai_governance_reviewers        members designated to decide intake requests
--   ai_assets                      the register
--   ai_asset_evidence              links to posture findings, incidents and
--                                  dashboard approval requests (identifiers only)
--   ai_intake_requests             "may we use X?" requests and their decisions
--   ai_governance_exceptions       time-boxed waivers of a ban or restriction
--
-- Enforcement (only where a mechanism exists):
--   * MCP servers: a banned asset becomes an `mcp_deny_servers` entry and a
--     restricted asset an `mcp_require_approval_servers` entry in the governance
--     overlay that the `policy` Edge Function delivers with the runtime policy
--     (ai_governance_policy_overlay). Connectors add it on top of the published
--     policy; the register can only tighten the published policy, never relax
--     it. An approved, unexpired exception removes the governance entry for its
--     scope (tenant, named members, or named agents); it never removes an entry
--     an administrator wrote into the published policy itself.
--   * AI chat sites with a Browser Guard site id: banned sites are listed for
--     the Browser Guard managed policy (`blockedSites`), which administrators
--     deploy through their browser management. The control plane does not push
--     browser policy.
--   * Coding agents and models/AI services: register and workflow only.
--
-- Access
--   * Members read their tenant's rows through RLS (no client writes).
--   * Every mutation is a service-role-only SECURITY DEFINER RPC that re-checks
--     membership, role and tenant state under row locks and writes the audit
--     rows in the same transaction. The Edge Function additionally enforces the
--     identity barrier, AAL2 and rate limits.
--   * Four-eyes is structural: a request is never decided by its requester
--     (check constraints), for intake, exceptions and policy changes alike.

-- ── Helpers ────────────────────────────────────────────────────────────────

create or replace function app.ai_governance_text_valid(p_value text, p_max integer, p_multiline boolean)
returns boolean
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select p_value is not null
    and char_length(btrim(p_value)) between 1 and p_max
    and case when p_multiline
      then translate(p_value, E'\n\t', '') !~ '[[:cntrl:]]'
      else p_value !~ '[[:cntrl:]]' end
$$;
revoke all on function app.ai_governance_text_valid(text, integer, boolean) from public, anon, authenticated;

create or replace function app.ai_data_categories_valid(p_categories text[])
returns boolean
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select p_categories is not null
    and cardinality(p_categories) <= 5
    and coalesce((
      select bool_and(c in ('personal_data', 'special_category', 'source_code', 'secrets', 'customer_data'))
        and count(distinct c) = count(*)
      from unnest(p_categories) c
    ), true)
$$;
revoke all on function app.ai_data_categories_valid(text[]) from public, anon, authenticated;

-- Browser Guard site ids (packages/browser-guard/src/types.ts SiteId, minus
-- "other"). Only these can be listed in the managed `blockedSites` policy.
create or replace function app.ai_browser_guard_site(p_identifier text)
returns boolean
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select p_identifier in ('chatgpt', 'gemini', 'claude', 'copilot', 'perplexity', 'deepseek', 'mistral', 'grok')
$$;
revoke all on function app.ai_browser_guard_site(text) from public, anon, authenticated;

-- An asset whose status has an enforcement effect somewhere.
create or replace function app.ai_asset_enforceable(p_type text, p_identifier text)
returns boolean
language sql
immutable
set search_path = pg_catalog, app, pg_temp
as $$
  select p_type = 'mcp_server' or (p_type = 'ai_site' and app.ai_browser_guard_site(p_identifier))
$$;
revoke all on function app.ai_asset_enforceable(text, text) from public, anon, authenticated;

-- banned > restricted > everything else. A lower rank relaxes enforcement.
create or replace function app.ai_status_rank(p_status text)
returns integer
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select case p_status when 'banned' then 2 when 'restricted' then 1 else 0 end
$$;
revoke all on function app.ai_status_rank(text) from public, anon, authenticated;

-- Privileged audit row always; the customer-visible team audit row when the
-- tenant is a team (audit_logs.team_id references teams).
create or replace function app.ai_governance_audit(
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
revoke all on function app.ai_governance_audit(uuid, uuid, text, jsonb) from public, anon, authenticated;

-- The actor's live role in an active tenant, with share locks held until the
-- end of the calling transaction; NULL when the actor may not act at all.
create or replace function app.ai_governance_actor_role(p_tenant_id uuid, p_user_id uuid)
returns text
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_role text;
begin
  if p_tenant_id is null or p_user_id is null then
    return null;
  end if;
  perform 1 from public.tenants t where t.id = p_tenant_id and t.status = 'active' for share of t;
  if not found then
    return null;
  end if;
  select m.role into v_role from public.tenant_members m
   where m.tenant_id = p_tenant_id and m.user_id = p_user_id
     and m.role in ('owner', 'admin', 'member', 'viewer')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
   for share of m;
  return v_role;
end;
$$;
revoke all on function app.ai_governance_actor_role(uuid, uuid) from public, anon, authenticated;

-- ── Settings ───────────────────────────────────────────────────────────────

create table if not exists public.tenant_ai_governance_settings (
  tenant_id uuid primary key references public.tenants (id) on delete restrict,
  policy_four_eyes boolean not null default false,
  default_review_days integer not null default 180 check (default_review_days between 30 and 730),
  updated_by uuid,
  updated_at timestamptz not null default now()
);

comment on table public.tenant_ai_governance_settings is
  'Per-tenant AI governance options: four-eyes policy change control and the default asset review interval.';

alter table public.tenant_ai_governance_settings enable row level security;
revoke all on public.tenant_ai_governance_settings from public, anon, authenticated, service_role;
grant select on public.tenant_ai_governance_settings to authenticated, service_role;

drop policy if exists tenant_ai_governance_settings_select_member on public.tenant_ai_governance_settings;
create policy tenant_ai_governance_settings_select_member on public.tenant_ai_governance_settings
  for select to authenticated
  using (app.is_tenant_member(tenant_id));

drop policy if exists tenant_ai_governance_settings_member_restrict on public.tenant_ai_governance_settings;
create policy tenant_ai_governance_settings_member_restrict on public.tenant_ai_governance_settings
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.tenant_ai_governance_settings;
create policy tenant_identity_access_restrict on public.tenant_ai_governance_settings
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Designated reviewers ───────────────────────────────────────────────────

create table if not exists public.ai_governance_reviewers (
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  user_id uuid not null,
  designated_by uuid not null,
  designated_at timestamptz not null default now(),
  primary key (tenant_id, user_id),
  -- Removing the member removes the designation.
  constraint ai_governance_reviewers_member_fkey foreign key (tenant_id, user_id)
    references public.tenant_members (tenant_id, user_id) on delete cascade
);

comment on table public.ai_governance_reviewers is
  'Members designated by an owner/admin to decide AI intake requests and record asset reviews. Not a tenant role.';

alter table public.ai_governance_reviewers enable row level security;
revoke all on public.ai_governance_reviewers from public, anon, authenticated, service_role;
grant select on public.ai_governance_reviewers to authenticated, service_role;

drop policy if exists ai_governance_reviewers_select_member on public.ai_governance_reviewers;
create policy ai_governance_reviewers_select_member on public.ai_governance_reviewers
  for select to authenticated
  using (app.is_tenant_member(tenant_id));

drop policy if exists ai_governance_reviewers_member_restrict on public.ai_governance_reviewers;
create policy ai_governance_reviewers_member_restrict on public.ai_governance_reviewers
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.ai_governance_reviewers;
create policy tenant_identity_access_restrict on public.ai_governance_reviewers
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Asset register ─────────────────────────────────────────────────────────

create table if not exists public.ai_assets (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  asset_type text not null
    check (asset_type in ('coding_agent', 'mcp_server', 'ai_site', 'model_service')),
  -- Stable key: connector runtime, MCP server id (as used in mcp__<server>__…),
  -- Browser Guard site id or hostname, model/service host or id.
  identifier text not null check (identifier ~ '^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$'),
  name text not null check (app.ai_governance_text_valid(name, 120, false)),
  vendor text check (vendor is null or app.ai_governance_text_valid(vendor, 120, false)),
  owner_user_id uuid,
  business_purpose text check (business_purpose is null or app.ai_governance_text_valid(business_purpose, 1000, true)),
  data_categories text[] not null default '{}'::text[] check (app.ai_data_categories_valid(data_categories)),
  risk_tier text not null default 'unassessed'
    check (risk_tier in ('unassessed', 'minimal', 'limited', 'high', 'prohibited')),
  risk_score smallint check (risk_score is null or risk_score between 0 and 100),
  status text not null default 'proposed'
    check (status in ('proposed', 'approved', 'restricted', 'banned', 'retired')),
  review_due_at date,
  last_reviewed_at timestamptz,
  last_reviewed_by uuid,
  source text not null default 'manual'
    check (source in ('manual', 'intake', 'fleet', 'posture', 'browser_telemetry', 'discovery')),
  first_observed_at timestamptz,
  last_observed_at timestamptz,
  version integer not null default 1 check (version >= 1),
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_by uuid,
  updated_at timestamptz not null default now(),
  constraint ai_assets_identity_unique unique (tenant_id, asset_type, identifier),
  constraint ai_assets_id_tenant_unique unique (id, tenant_id),
  -- The connector policy vocabulary (runtime-policy MCP_ID).
  constraint ai_assets_mcp_identifier
    check (asset_type <> 'mcp_server' or identifier ~ '^[A-Za-z0-9][A-Za-z0-9._:/_-]{0,255}$'),
  -- EU AI Act-style "prohibited" practice: the asset may not be in use.
  constraint ai_assets_prohibited_status
    check (risk_tier <> 'prohibited' or status in ('banned', 'retired')),
  constraint ai_assets_review_shape check ((last_reviewed_at is null) = (last_reviewed_by is null)),
  constraint ai_assets_observed_order
    check (first_observed_at is null or last_observed_at is null or last_observed_at >= first_observed_at)
);

create index if not exists ai_assets_tenant_status_idx on public.ai_assets (tenant_id, status);
create index if not exists ai_assets_tenant_review_idx on public.ai_assets (tenant_id, review_due_at)
  where status <> 'retired';
create index if not exists ai_assets_enforced_idx on public.ai_assets (tenant_id, asset_type)
  where status in ('banned', 'restricted');

comment on table public.ai_assets is
  'AI governance register: AI systems in use per tenant with owner, purpose, data categories, risk tier, status and review date. Written only by service-role RPCs.';

-- Identity is fixed at creation: renaming a banned MCP server id would lift
-- its ban without a decision. Retire and register a new asset instead.
create or replace function app.protect_ai_asset()
returns trigger
language plpgsql
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if new.id is distinct from old.id
     or new.tenant_id is distinct from old.tenant_id
     or new.asset_type is distinct from old.asset_type
     or new.identifier is distinct from old.identifier
     or new.created_by is distinct from old.created_by
     or new.created_at is distinct from old.created_at then
    raise exception 'ai_asset_identity_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_ai_asset() from public, anon, authenticated;

drop trigger if exists ai_assets_identity_immutable on public.ai_assets;
create trigger ai_assets_identity_immutable
  before update on public.ai_assets
  for each row execute function app.protect_ai_asset();

alter table public.ai_assets enable row level security;
revoke all on public.ai_assets from public, anon, authenticated, service_role;
grant select on public.ai_assets to authenticated, service_role;

drop policy if exists ai_assets_select_member on public.ai_assets;
create policy ai_assets_select_member on public.ai_assets
  for select to authenticated
  using (app.is_tenant_member(tenant_id));

drop policy if exists ai_assets_member_restrict on public.ai_assets;
create policy ai_assets_member_restrict on public.ai_assets
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.ai_assets;
create policy tenant_identity_access_restrict on public.ai_assets
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Linked evidence ────────────────────────────────────────────────────────
-- Identifiers of existing tenant rows plus a label derived server-side from
-- enums of that row. No free text, no raw artifact.

create table if not exists public.ai_asset_evidence (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  asset_id uuid not null,
  evidence_kind text not null check (evidence_kind in ('posture_finding', 'incident', 'approval_request')),
  evidence_ref text not null check (evidence_ref ~ '^([0-9]{1,19}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'),
  label text not null check (app.ai_governance_text_valid(label, 200, false)),
  observed_at timestamptz,
  linked_by uuid not null,
  linked_at timestamptz not null default now(),
  constraint ai_asset_evidence_unique unique (tenant_id, asset_id, evidence_kind, evidence_ref),
  constraint ai_asset_evidence_asset_fkey foreign key (asset_id, tenant_id)
    references public.ai_assets (id, tenant_id) on delete cascade
);

create index if not exists ai_asset_evidence_asset_idx on public.ai_asset_evidence (tenant_id, asset_id);

alter table public.ai_asset_evidence enable row level security;
revoke all on public.ai_asset_evidence from public, anon, authenticated, service_role;
grant select on public.ai_asset_evidence to authenticated, service_role;

drop policy if exists ai_asset_evidence_select_member on public.ai_asset_evidence;
create policy ai_asset_evidence_select_member on public.ai_asset_evidence
  for select to authenticated
  using (app.is_tenant_member(tenant_id));

drop policy if exists ai_asset_evidence_member_restrict on public.ai_asset_evidence;
create policy ai_asset_evidence_member_restrict on public.ai_asset_evidence
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.ai_asset_evidence;
create policy tenant_identity_access_restrict on public.ai_asset_evidence
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Intake requests ────────────────────────────────────────────────────────

create table if not exists public.ai_intake_requests (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  -- Set when the request is about an asset already in the register.
  asset_id uuid,
  asset_type text not null
    check (asset_type in ('coding_agent', 'mcp_server', 'ai_site', 'model_service')),
  identifier text not null check (identifier ~ '^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$'),
  name text not null check (app.ai_governance_text_valid(name, 120, false)),
  vendor text check (vendor is null or app.ai_governance_text_valid(vendor, 120, false)),
  business_purpose text not null check (app.ai_governance_text_valid(business_purpose, 1000, true)),
  data_categories text[] not null default '{}'::text[] check (app.ai_data_categories_valid(data_categories)),
  requested_status text not null default 'approved' check (requested_status in ('approved', 'restricted')),
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'cancelled', 'expired')),
  requested_by uuid not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  decided_by uuid,
  decided_at timestamptz,
  decision_reason text check (decision_reason is null or app.ai_governance_text_valid(decision_reason, 500, true)),
  closed_at timestamptz,
  resulting_asset_id uuid,
  constraint ai_intake_requests_asset_fkey foreign key (asset_id, tenant_id)
    references public.ai_assets (id, tenant_id) on delete set null (asset_id),
  constraint ai_intake_requests_mcp_identifier
    check (asset_type <> 'mcp_server' or identifier ~ '^[A-Za-z0-9][A-Za-z0-9._:/_-]{0,255}$'),
  constraint ai_intake_requests_expiry
    check (expires_at > created_at and expires_at <= created_at + interval '91 days'),
  -- Nobody decides their own request.
  constraint ai_intake_requests_four_eyes check (decided_by is null or decided_by <> requested_by),
  constraint ai_intake_requests_decision_shape check (
    case
      when status in ('approved', 'rejected') then
        decided_by is not null and decided_at is not null and decision_reason is not null
        and closed_at is not null
      when status = 'pending' then
        decided_by is null and decided_at is null and decision_reason is null and closed_at is null
      else
        decided_by is null and decided_at is null and decision_reason is null and closed_at is not null
    end
  ),
  constraint ai_intake_requests_result check ((status = 'approved') = (resulting_asset_id is not null))
);

create unique index if not exists ai_intake_requests_one_pending
  on public.ai_intake_requests (tenant_id, asset_type, identifier)
  where status = 'pending';
create index if not exists ai_intake_requests_tenant_created_idx
  on public.ai_intake_requests (tenant_id, created_at desc);

alter table public.ai_intake_requests enable row level security;
revoke all on public.ai_intake_requests from public, anon, authenticated, service_role;
grant select on public.ai_intake_requests to authenticated, service_role;

drop policy if exists ai_intake_requests_select_member on public.ai_intake_requests;
create policy ai_intake_requests_select_member on public.ai_intake_requests
  for select to authenticated
  using (app.is_tenant_member(tenant_id));

drop policy if exists ai_intake_requests_member_restrict on public.ai_intake_requests;
create policy ai_intake_requests_member_restrict on public.ai_intake_requests
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.ai_intake_requests;
create policy tenant_identity_access_restrict on public.ai_intake_requests
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Exceptions (waivers) ───────────────────────────────────────────────────

create table if not exists public.ai_governance_exceptions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  asset_id uuid not null,
  scope_kind text not null check (scope_kind in ('tenant', 'members', 'agents')),
  scope_user_ids uuid[] not null default '{}'::uuid[],
  scope_agent_ids uuid[] not null default '{}'::uuid[],
  justification text not null check (app.ai_governance_text_valid(justification, 1000, true)),
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'cancelled', 'revoked', 'expired')),
  requested_by uuid not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  starts_at timestamptz,
  decided_by uuid,
  decided_at timestamptz,
  decision_reason text check (decision_reason is null or app.ai_governance_text_valid(decision_reason, 500, true)),
  revoked_by uuid,
  revoked_at timestamptz,
  revoke_reason text check (revoke_reason is null or app.ai_governance_text_valid(revoke_reason, 500, true)),
  closed_at timestamptz,
  constraint ai_governance_exceptions_asset_fkey foreign key (asset_id, tenant_id)
    references public.ai_assets (id, tenant_id) on delete cascade,
  constraint ai_governance_exceptions_scope_shape check (
    case scope_kind
      when 'tenant' then cardinality(scope_user_ids) = 0 and cardinality(scope_agent_ids) = 0
      when 'members' then cardinality(scope_user_ids) between 1 and 100 and cardinality(scope_agent_ids) = 0
      else cardinality(scope_agent_ids) between 1 and 200 and cardinality(scope_user_ids) = 0
    end
  ),
  constraint ai_governance_exceptions_window
    check (expires_at > created_at and expires_at <= created_at + interval '366 days'
      and (starts_at is null or (starts_at >= created_at and starts_at < expires_at))),
  constraint ai_governance_exceptions_four_eyes check (decided_by is null or decided_by <> requested_by),
  constraint ai_governance_exceptions_decision_shape check (
    case status
      when 'pending' then decided_by is null and decided_at is null and decision_reason is null
        and starts_at is null and revoked_at is null and closed_at is null
      when 'approved' then decided_by is not null and decided_at is not null and decision_reason is not null
        and starts_at is not null and revoked_at is null and closed_at is null
      when 'rejected' then decided_by is not null and decided_at is not null and decision_reason is not null
        and starts_at is null and revoked_at is null and closed_at is not null
      when 'revoked' then decided_by is not null and starts_at is not null
        and revoked_by is not null and revoked_at is not null and revoke_reason is not null and closed_at is not null
      else revoked_at is null and closed_at is not null
    end
  ),
  constraint ai_governance_exceptions_revoke_shape
    check ((revoked_at is null) = (revoked_by is null) and (revoked_at is null) = (revoke_reason is null))
);

create index if not exists ai_governance_exceptions_active_idx
  on public.ai_governance_exceptions (tenant_id, asset_id, expires_at)
  where status = 'approved';
create index if not exists ai_governance_exceptions_tenant_created_idx
  on public.ai_governance_exceptions (tenant_id, created_at desc);

alter table public.ai_governance_exceptions enable row level security;
revoke all on public.ai_governance_exceptions from public, anon, authenticated, service_role;
grant select on public.ai_governance_exceptions to authenticated, service_role;

drop policy if exists ai_governance_exceptions_select_member on public.ai_governance_exceptions;
create policy ai_governance_exceptions_select_member on public.ai_governance_exceptions
  for select to authenticated
  using (app.is_tenant_member(tenant_id));

drop policy if exists ai_governance_exceptions_member_restrict on public.ai_governance_exceptions;
create policy ai_governance_exceptions_member_restrict on public.ai_governance_exceptions
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.ai_governance_exceptions;
create policy tenant_identity_access_restrict on public.ai_governance_exceptions
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Field parsing for the RPCs ─────────────────────────────────────────────
-- JSON field readers that refuse the wrong JSON type instead of casting it.

create or replace function app.ai_json_text(p_fields jsonb, p_key text)
returns text
language plpgsql
immutable
set search_path = pg_catalog, pg_temp
as $$
begin
  if not (p_fields ? p_key) or jsonb_typeof(p_fields->p_key) = 'null' then
    return null;
  end if;
  if jsonb_typeof(p_fields->p_key) <> 'string' then
    raise exception 'invalid_ai_governance_field:%', p_key using errcode = '22023';
  end if;
  return p_fields->>p_key;
end;
$$;
revoke all on function app.ai_json_text(jsonb, text) from public, anon, authenticated;

create or replace function app.ai_json_categories(p_fields jsonb, p_key text)
returns text[]
language plpgsql
immutable
set search_path = pg_catalog, app, pg_temp
as $$
declare
  v_value text[];
begin
  if not (p_fields ? p_key) or jsonb_typeof(p_fields->p_key) = 'null' then
    return '{}'::text[];
  end if;
  if jsonb_typeof(p_fields->p_key) <> 'array'
     or exists (select 1 from jsonb_array_elements(p_fields->p_key) e where jsonb_typeof(e) <> 'string') then
    raise exception 'invalid_ai_governance_field:%', p_key using errcode = '22023';
  end if;
  select coalesce(array_agg(e order by e), '{}'::text[]) into v_value
    from jsonb_array_elements_text(p_fields->p_key) e;
  if not app.ai_data_categories_valid(v_value) then
    raise exception 'invalid_ai_governance_field:%', p_key using errcode = '22023';
  end if;
  return v_value;
end;
$$;
revoke all on function app.ai_json_categories(jsonb, text) from public, anon, authenticated;

create or replace function app.ai_json_uuid_array(p_fields jsonb, p_key text, p_max integer)
returns uuid[]
language plpgsql
immutable
set search_path = pg_catalog, pg_temp
as $$
declare
  v_value uuid[];
begin
  if not (p_fields ? p_key) or jsonb_typeof(p_fields->p_key) = 'null' then
    return '{}'::uuid[];
  end if;
  if jsonb_typeof(p_fields->p_key) <> 'array'
     or jsonb_array_length(p_fields->p_key) > p_max
     or exists (
       select 1 from jsonb_array_elements(p_fields->p_key) e
        where jsonb_typeof(e) <> 'string'
           or (e #>> '{}') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') then
    raise exception 'invalid_ai_governance_field:%', p_key using errcode = '22023';
  end if;
  select coalesce(array_agg(distinct (e #>> '{}')::uuid), '{}'::uuid[]) into v_value
    from jsonb_array_elements(p_fields->p_key) e;
  return v_value;
end;
$$;
revoke all on function app.ai_json_uuid_array(jsonb, text, integer) from public, anon, authenticated;

-- ── RPC: create or update a register entry (owner/admin) ───────────────────

create or replace function public.upsert_ai_asset(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_asset_id uuid,
  p_expected_version integer,
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
  v_old public.ai_assets;
  v_row public.ai_assets;
  v_four_eyes boolean := false;
  v_review_days integer := 180;
  v_type text;
  v_identifier text;
  v_name text;
  v_vendor text;
  v_owner uuid;
  v_purpose text;
  v_categories text[];
  v_tier text;
  v_score smallint;
  v_status text;
  v_review date;
  v_text text;
  v_changed text[] := '{}'::text[];
begin
  if p_tenant_id is null or p_actor_user_id is null or p_fields is null
     or jsonb_typeof(p_fields) <> 'object'
     or (p_asset_id is null) <> (p_expected_version is null) then
    raise exception 'invalid_ai_asset' using errcode = '22023';
  end if;
  for v_key in select jsonb_object_keys(p_fields) loop
    if v_key not in ('asset_type', 'identifier', 'name', 'vendor', 'owner_user_id', 'business_purpose',
                     'data_categories', 'risk_tier', 'risk_score', 'status', 'review_due_at') then
      raise exception 'invalid_ai_governance_field:%', v_key using errcode = '22023';
    end if;
  end loop;

  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':ai-governance', 0));
  select s.policy_four_eyes, s.default_review_days into v_four_eyes, v_review_days
    from public.tenant_ai_governance_settings s where s.tenant_id = p_tenant_id;
  v_four_eyes := coalesce(v_four_eyes, false);
  v_review_days := coalesce(v_review_days, 180);

  if p_asset_id is not null then
    select * into v_old from public.ai_assets
     where id = p_asset_id and tenant_id = p_tenant_id
     for update;
    if not found then
      raise exception 'ai_asset_not_found' using errcode = 'P0002';
    end if;
    if v_old.version <> p_expected_version then
      raise exception 'ai_asset_version_conflict' using errcode = 'PT409';
    end if;
  end if;

  v_type := coalesce(app.ai_json_text(p_fields, 'asset_type'), v_old.asset_type);
  v_identifier := coalesce(app.ai_json_text(p_fields, 'identifier'), v_old.identifier);
  if p_asset_id is not null and (v_type <> v_old.asset_type or v_identifier <> v_old.identifier) then
    raise exception 'ai_asset_identity_immutable' using errcode = '22023';
  end if;
  v_name := case when p_fields ? 'name' then app.ai_json_text(p_fields, 'name') else v_old.name end;
  v_vendor := case when p_fields ? 'vendor' then app.ai_json_text(p_fields, 'vendor') else v_old.vendor end;
  v_purpose := case when p_fields ? 'business_purpose' then app.ai_json_text(p_fields, 'business_purpose')
    else v_old.business_purpose end;
  v_categories := case when p_fields ? 'data_categories' then app.ai_json_categories(p_fields, 'data_categories')
    else coalesce(v_old.data_categories, '{}'::text[]) end;
  v_tier := coalesce(app.ai_json_text(p_fields, 'risk_tier'), v_old.risk_tier, 'unassessed');
  v_status := coalesce(app.ai_json_text(p_fields, 'status'), v_old.status, 'proposed');

  if p_fields ? 'owner_user_id' then
    v_text := app.ai_json_text(p_fields, 'owner_user_id');
    if v_text is not null and v_text !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
      raise exception 'invalid_ai_governance_field:owner_user_id' using errcode = '22023';
    end if;
    v_owner := v_text::uuid;
    if v_owner is not null and not exists (
      select 1 from public.tenant_members m
       where m.tenant_id = p_tenant_id and m.user_id = v_owner
         and m.role in ('owner', 'admin', 'member', 'viewer')
         and (m.expires_at is null or m.expires_at > v_now)
    ) then
      raise exception 'ai_asset_owner_not_member' using errcode = '22023';
    end if;
  else
    v_owner := v_old.owner_user_id;
  end if;

  if p_fields ? 'risk_score' then
    if jsonb_typeof(p_fields->'risk_score') = 'null' then
      v_score := null;
    elsif jsonb_typeof(p_fields->'risk_score') <> 'number'
       or (p_fields->>'risk_score') !~ '^[0-9]{1,3}$'
       or (p_fields->>'risk_score')::integer > 100 then
      raise exception 'invalid_ai_governance_field:risk_score' using errcode = '22023';
    else
      v_score := (p_fields->>'risk_score')::smallint;
    end if;
  else
    v_score := v_old.risk_score;
  end if;

  if p_fields ? 'review_due_at' then
    v_text := app.ai_json_text(p_fields, 'review_due_at');
    if v_text is not null and (v_text !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
       or v_text::date < (v_now at time zone 'utc')::date
       or v_text::date > (v_now at time zone 'utc')::date + 730) then
      raise exception 'invalid_ai_governance_field:review_due_at' using errcode = '22023';
    end if;
    v_review := v_text::date;
  elsif p_asset_id is null then
    v_review := (v_now at time zone 'utc')::date + v_review_days;
  else
    v_review := v_old.review_due_at;
  end if;

  if v_type is null or v_identifier is null or v_name is null then
    raise exception 'invalid_ai_asset' using errcode = '22023';
  end if;

  if p_asset_id is null then
    insert into public.ai_assets (
      tenant_id, asset_type, identifier, name, vendor, owner_user_id, business_purpose,
      data_categories, risk_tier, risk_score, status, review_due_at, source,
      created_by, created_at, updated_by, updated_at
    ) values (
      p_tenant_id, v_type, v_identifier, v_name, v_vendor, v_owner, v_purpose,
      v_categories, v_tier, v_score, v_status, v_review, 'manual',
      p_actor_user_id, v_now, p_actor_user_id, v_now
    )
    on conflict (tenant_id, asset_type, identifier) do nothing
    returning * into v_row;
    if not found then
      raise exception 'ai_asset_exists' using errcode = '23505';
    end if;
    perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_asset.created',
      jsonb_build_object('asset_id', v_row.id, 'asset_type', v_row.asset_type,
        'identifier', v_row.identifier, 'status', v_row.status, 'risk_tier', v_row.risk_tier));
  else
    -- Relaxing an enforced status (for example banned -> approved) under
    -- four-eyes change control needs a second person: an intake request.
    if v_four_eyes and app.ai_asset_enforceable(v_old.asset_type, v_old.identifier)
       and app.ai_status_rank(v_status) < app.ai_status_rank(v_old.status) then
      raise exception 'governance_four_eyes_required' using errcode = '42501';
    end if;
    if v_name is distinct from v_old.name then v_changed := array_append(v_changed, 'name'); end if;
    if v_vendor is distinct from v_old.vendor then v_changed := array_append(v_changed, 'vendor'); end if;
    if v_owner is distinct from v_old.owner_user_id then v_changed := array_append(v_changed, 'owner_user_id'); end if;
    if v_purpose is distinct from v_old.business_purpose then v_changed := array_append(v_changed, 'business_purpose'); end if;
    if v_categories is distinct from v_old.data_categories then v_changed := array_append(v_changed, 'data_categories'); end if;
    if v_tier is distinct from v_old.risk_tier then v_changed := array_append(v_changed, 'risk_tier'); end if;
    if v_score is distinct from v_old.risk_score then v_changed := array_append(v_changed, 'risk_score'); end if;
    if v_status is distinct from v_old.status then v_changed := array_append(v_changed, 'status'); end if;
    if v_review is distinct from v_old.review_due_at then v_changed := array_append(v_changed, 'review_due_at'); end if;
    if cardinality(v_changed) = 0 then
      return jsonb_build_object('asset_id', v_old.id, 'version', v_old.version, 'status', v_old.status,
        'created', false, 'changed', '[]'::jsonb);
    end if;
    update public.ai_assets
       set name = v_name, vendor = v_vendor, owner_user_id = v_owner, business_purpose = v_purpose,
           data_categories = v_categories, risk_tier = v_tier, risk_score = v_score, status = v_status,
           review_due_at = v_review, version = version + 1, updated_by = p_actor_user_id, updated_at = v_now
     where id = v_old.id
    returning * into v_row;
    perform app.ai_governance_audit(p_tenant_id, p_actor_user_id,
      case when v_row.status is distinct from v_old.status then 'ai_asset.status_changed' else 'ai_asset.updated' end,
      jsonb_build_object('asset_id', v_row.id, 'asset_type', v_row.asset_type, 'identifier', v_row.identifier,
        'changed', to_jsonb(v_changed), 'status_from', v_old.status, 'status_to', v_row.status,
        'risk_tier', v_row.risk_tier, 'version', v_row.version));
  end if;

  if (select count(*) from public.ai_assets a
       where a.tenant_id = p_tenant_id and a.asset_type = 'mcp_server'
         and a.status in ('banned', 'restricted')) > 500 then
    raise exception 'ai_governance_enforcement_quota' using errcode = '54000';
  end if;
  if (select count(*) from public.ai_assets a where a.tenant_id = p_tenant_id) > 5000 then
    raise exception 'ai_governance_register_quota' using errcode = '54000';
  end if;

  return jsonb_build_object('asset_id', v_row.id, 'version', v_row.version, 'status', v_row.status,
    'created', p_asset_id is null, 'changed', to_jsonb(v_changed));
end;
$$;
revoke all on function public.upsert_ai_asset(uuid, uuid, uuid, integer, jsonb) from public, anon, authenticated;
grant execute on function public.upsert_ai_asset(uuid, uuid, uuid, integer, jsonb) to service_role;

-- ── RPC: import candidates from observed data (owner/admin) ────────────────
-- Adds `proposed` entries for AI systems the control plane has observed and
-- refreshes the observation window of existing entries. It never changes an
-- existing entry's status, owner, purpose or risk assessment.

create or replace function public.import_ai_asset_candidates(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_limit integer
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_role text;
  v_review_days integer;
  v_candidate record;
  v_created integer := 0;
  v_refreshed integer := 0;
  v_skipped integer := 0;
  v_by_source jsonb := '{}'::jsonb;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_limit is null or p_limit not between 1 and 500 then
    raise exception 'invalid_ai_asset_import' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':ai-governance', 0));
  select coalesce(max(s.default_review_days), 180) into v_review_days
    from public.tenant_ai_governance_settings s where s.tenant_id = p_tenant_id;

  for v_candidate in
    with fleet as (
      -- Enrolled connectors (coding agents). Browser Guard installs are the
      -- guard itself, not an AI system in use.
      select 'coding_agent'::text as asset_type,
             lower(a.agent_runtime) as identifier,
             'fleet'::text as source,
             min(coalesce(a.first_seen, a.last_seen)) as first_seen,
             max(coalesce(a.last_seen, a.first_seen)) as last_seen
        from public.agents a
       where a.tenant_id = p_tenant_id
         and a.agent_runtime is not null
         and lower(a.agent_runtime) ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
         and lower(a.agent_runtime) not in ('browser_guard', 'browser-guard')
       group by lower(a.agent_runtime)
    ),
    mcp as (
      select 'mcp_server'::text, f.mcp_server_name, 'posture'::text,
             min(f.observed_at), max(f.observed_at)
        from public.posture_findings f
       where f.tenant_id = p_tenant_id and f.source = 'mcp_inventory'
         and f.mcp_server_name is not null
         and f.mcp_server_name ~ '^[A-Za-z0-9][A-Za-z0-9._:/_-]{0,255}$'
       group by f.mcp_server_name
    ),
    sites as (
      select 'ai_site'::text, e.payload->>'site', 'browser_telemetry'::text,
             min(e.created_at), max(e.created_at)
        from public.events e
       where e.tenant_id = p_tenant_id and e.type = 'privacy_scan'
         and app.ai_browser_guard_site(e.payload->>'site')
       group by e.payload->>'site'
    ),
    services as (
      select 'model_service'::text,
             lower(substring(d.target from '^https?://([^/]+)/$')),
             'discovery'::text,
             min(d.first_reported_at), max(d.last_reported_at)
        from public.tenant_discovery_items d
       where d.tenant_id = p_tenant_id
       group by lower(substring(d.target from '^https?://([^/]+)/$'))
    )
    select c.* from (
      select * from fleet union all select * from mcp union all select * from sites union all select * from services
    ) c(asset_type, identifier, source, first_seen, last_seen)
     where c.identifier ~ '^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$'
     order by c.asset_type, c.identifier
  loop
    update public.ai_assets a
       set first_observed_at = least(coalesce(a.first_observed_at, v_candidate.first_seen), v_candidate.first_seen),
           last_observed_at = greatest(coalesce(a.last_observed_at, v_candidate.last_seen), v_candidate.last_seen)
     where a.tenant_id = p_tenant_id and a.asset_type = v_candidate.asset_type
       and a.identifier = v_candidate.identifier
       and (a.first_observed_at is distinct from least(coalesce(a.first_observed_at, v_candidate.first_seen), v_candidate.first_seen)
         or a.last_observed_at is distinct from greatest(coalesce(a.last_observed_at, v_candidate.last_seen), v_candidate.last_seen));
    if found then
      v_refreshed := v_refreshed + 1;
      continue;
    end if;
    if exists (select 1 from public.ai_assets a
                where a.tenant_id = p_tenant_id and a.asset_type = v_candidate.asset_type
                  and a.identifier = v_candidate.identifier) then
      continue;
    end if;
    if v_created >= p_limit then
      v_skipped := v_skipped + 1;
      continue;
    end if;
    insert into public.ai_assets (
      tenant_id, asset_type, identifier, name, status, source, review_due_at,
      first_observed_at, last_observed_at, created_by, created_at, updated_by, updated_at
    ) values (
      p_tenant_id, v_candidate.asset_type, v_candidate.identifier,
      case
        when v_candidate.asset_type = 'ai_site' then case v_candidate.identifier
          when 'chatgpt' then 'ChatGPT' when 'gemini' then 'Gemini' when 'claude' then 'Claude'
          when 'copilot' then 'Microsoft Copilot' when 'perplexity' then 'Perplexity'
          when 'deepseek' then 'DeepSeek' when 'mistral' then 'Mistral Le Chat' when 'grok' then 'Grok'
          else v_candidate.identifier end
        when v_candidate.asset_type = 'coding_agent' then case v_candidate.identifier
          when 'claude-code' then 'Claude Code' when 'codex' then 'Codex CLI' when 'cursor' then 'Cursor'
          when 'vscode' then 'VS Code' when 'openclaw' then 'OpenClaw' when 'opencode' then 'OpenCode'
          else v_candidate.identifier end
        else left(v_candidate.identifier, 120)
      end,
      'proposed', v_candidate.source, (v_now at time zone 'utc')::date + v_review_days,
      v_candidate.first_seen, v_candidate.last_seen, p_actor_user_id, v_now, p_actor_user_id, v_now
    );
    v_created := v_created + 1;
    v_by_source := jsonb_set(v_by_source, array[v_candidate.source],
      to_jsonb(coalesce((v_by_source->>v_candidate.source)::integer, 0) + 1));
  end loop;

  if (select count(*) from public.ai_assets a where a.tenant_id = p_tenant_id) > 5000 then
    raise exception 'ai_governance_register_quota' using errcode = '54000';
  end if;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_asset.imported',
    jsonb_build_object('created', v_created, 'refreshed', v_refreshed, 'skipped', v_skipped,
      'created_by_source', v_by_source));
  return jsonb_build_object('created', v_created, 'refreshed', v_refreshed, 'skipped', v_skipped,
    'created_by_source', v_by_source);
end;
$$;
revoke all on function public.import_ai_asset_candidates(uuid, uuid, integer) from public, anon, authenticated;
grant execute on function public.import_ai_asset_candidates(uuid, uuid, integer) to service_role;

-- ── RPC: link or unlink evidence (owner/admin) ─────────────────────────────

create or replace function public.link_ai_asset_evidence(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_asset_id uuid,
  p_kind text,
  p_ref text,
  p_link boolean
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_role text;
  v_label text;
  v_observed timestamptz;
  v_id uuid;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_asset_id is null or p_link is null
     or p_kind is null or p_kind not in ('posture_finding', 'incident', 'approval_request')
     or p_ref is null
     or (p_kind in ('posture_finding', 'incident') and p_ref !~ '^[1-9][0-9]{0,18}$')
     or (p_kind = 'approval_request' and p_ref !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') then
    raise exception 'invalid_ai_asset_evidence' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  perform 1 from public.ai_assets where id = p_asset_id and tenant_id = p_tenant_id for update;
  if not found then
    raise exception 'ai_asset_not_found' using errcode = 'P0002';
  end if;

  if not p_link then
    delete from public.ai_asset_evidence
     where tenant_id = p_tenant_id and asset_id = p_asset_id and evidence_kind = p_kind and evidence_ref = p_ref
    returning id into v_id;
    if v_id is null then
      raise exception 'ai_asset_evidence_not_found' using errcode = 'P0002';
    end if;
    perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_asset.evidence_unlinked',
      jsonb_build_object('asset_id', p_asset_id, 'kind', p_kind, 'ref', p_ref));
    return jsonb_build_object('asset_id', p_asset_id, 'linked', false);
  end if;

  -- The referenced row must belong to this tenant; the label uses its enums.
  if p_kind = 'posture_finding' then
    select f.source || ' · ' || f.severity || coalesce(' · ' || coalesce(f.vuln_id, f.mcp_server_name, f.rule_id, f.component), ''),
           f.observed_at
      into v_label, v_observed
      from public.posture_findings f where f.id = p_ref::bigint and f.tenant_id = p_tenant_id;
  elsif p_kind = 'incident' then
    select 'incident · ' || to_char(e.created_at at time zone 'utc', 'YYYY-MM-DD'), e.created_at
      into v_label, v_observed
      from public.events e where e.id = p_ref::bigint and e.tenant_id = p_tenant_id and e.type = 'incident';
  else
    select 'approval · ' || r.tool || ' · ' || r.status, r.created_at
      into v_label, v_observed
      from public.approval_requests r where r.id = p_ref::uuid and r.tenant_id = p_tenant_id;
  end if;
  if v_label is null then
    raise exception 'ai_asset_evidence_source_not_found' using errcode = 'P0002';
  end if;
  if (select count(*) from public.ai_asset_evidence where tenant_id = p_tenant_id and asset_id = p_asset_id) >= 50 then
    raise exception 'ai_asset_evidence_quota' using errcode = '54000';
  end if;
  insert into public.ai_asset_evidence (tenant_id, asset_id, evidence_kind, evidence_ref, label, observed_at, linked_by)
  values (p_tenant_id, p_asset_id, p_kind, p_ref, left(v_label, 200), v_observed, p_actor_user_id)
  on conflict (tenant_id, asset_id, evidence_kind, evidence_ref) do nothing
  returning id into v_id;
  if v_id is not null then
    perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_asset.evidence_linked',
      jsonb_build_object('asset_id', p_asset_id, 'kind', p_kind, 'ref', p_ref));
  end if;
  return jsonb_build_object('asset_id', p_asset_id, 'linked', true, 'created', v_id is not null);
end;
$$;
revoke all on function public.link_ai_asset_evidence(uuid, uuid, uuid, text, text, boolean) from public, anon, authenticated;
grant execute on function public.link_ai_asset_evidence(uuid, uuid, uuid, text, text, boolean) to service_role;

-- ── RPC: record a periodic review (owner/admin or designated reviewer) ─────

create or replace function public.review_ai_asset(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_asset_id uuid,
  p_next_review_due date
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_today date := (clock_timestamp() at time zone 'utc')::date;
  v_role text;
  v_days integer;
  v_row public.ai_assets;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_asset_id is null
     or (p_next_review_due is not null and (p_next_review_due <= v_today or p_next_review_due > v_today + 730)) then
    raise exception 'invalid_ai_asset_review' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or not (v_role in ('owner', 'admin') or (v_role = 'member' and exists (
       select 1 from public.ai_governance_reviewers r
        where r.tenant_id = p_tenant_id and r.user_id = p_actor_user_id))) then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  select coalesce(max(s.default_review_days), 180) into v_days
    from public.tenant_ai_governance_settings s where s.tenant_id = p_tenant_id;
  update public.ai_assets
     set last_reviewed_at = v_now, last_reviewed_by = p_actor_user_id,
         review_due_at = coalesce(p_next_review_due, v_today + v_days),
         version = version + 1, updated_by = p_actor_user_id, updated_at = v_now
   where id = p_asset_id and tenant_id = p_tenant_id and status <> 'retired'
  returning * into v_row;
  if not found then
    raise exception 'ai_asset_not_found' using errcode = 'P0002';
  end if;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_asset.reviewed',
    jsonb_build_object('asset_id', v_row.id, 'status', v_row.status, 'risk_tier', v_row.risk_tier,
      'next_review_due', v_row.review_due_at));
  return jsonb_build_object('asset_id', v_row.id, 'version', v_row.version,
    'review_due_at', v_row.review_due_at, 'last_reviewed_at', v_row.last_reviewed_at);
end;
$$;
revoke all on function public.review_ai_asset(uuid, uuid, uuid, date) from public, anon, authenticated;
grant execute on function public.review_ai_asset(uuid, uuid, uuid, date) to service_role;

-- ── RPC: designate reviewers (owner/admin) ─────────────────────────────────

create or replace function public.set_ai_governance_reviewer(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_user_id uuid,
  p_designated boolean
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_role text;
  v_changed boolean;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_user_id is null or p_designated is null then
    raise exception 'invalid_ai_governance_reviewer' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  if p_designated then
    perform 1 from public.tenant_members m
     where m.tenant_id = p_tenant_id and m.user_id = p_user_id and m.role = 'member'
       and (m.expires_at is null or m.expires_at > clock_timestamp())
     for share of m;
    if not found then
      -- Owners and admins already decide; viewers are read-only.
      raise exception 'ai_governance_reviewer_not_member' using errcode = '22023';
    end if;
    if (select count(*) from public.ai_governance_reviewers where tenant_id = p_tenant_id) >= 50 then
      raise exception 'ai_governance_reviewer_quota' using errcode = '54000';
    end if;
    insert into public.ai_governance_reviewers (tenant_id, user_id, designated_by)
    values (p_tenant_id, p_user_id, p_actor_user_id)
    on conflict (tenant_id, user_id) do nothing;
    v_changed := found;
  else
    delete from public.ai_governance_reviewers where tenant_id = p_tenant_id and user_id = p_user_id;
    v_changed := found;
  end if;
  if v_changed then
    perform app.ai_governance_audit(p_tenant_id, p_actor_user_id,
      case when p_designated then 'ai_governance.reviewer_designated' else 'ai_governance.reviewer_removed' end,
      jsonb_build_object('user_id', p_user_id));
  end if;
  return jsonb_build_object('user_id', p_user_id, 'designated', p_designated, 'changed', v_changed);
end;
$$;
revoke all on function public.set_ai_governance_reviewer(uuid, uuid, uuid, boolean) from public, anon, authenticated;
grant execute on function public.set_ai_governance_reviewer(uuid, uuid, uuid, boolean) to service_role;

-- ── RPC: file an intake request (owner/admin/member) ───────────────────────

create or replace function public.submit_ai_intake_request(
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
  v_asset public.ai_assets;
  v_asset_id uuid;
  v_text text;
  v_row public.ai_intake_requests;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_fields is null or jsonb_typeof(p_fields) <> 'object' then
    raise exception 'invalid_ai_intake_request' using errcode = '22023';
  end if;
  for v_key in select jsonb_object_keys(p_fields) loop
    if v_key not in ('asset_id', 'asset_type', 'identifier', 'name', 'vendor', 'business_purpose',
                     'data_categories', 'requested_status') then
      raise exception 'invalid_ai_governance_field:%', v_key using errcode = '22023';
    end if;
  end loop;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin', 'member') then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':ai-governance', 0));

  v_text := app.ai_json_text(p_fields, 'asset_id');
  if v_text is not null then
    if v_text !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
      raise exception 'invalid_ai_governance_field:asset_id' using errcode = '22023';
    end if;
    select * into v_asset from public.ai_assets where id = v_text::uuid and tenant_id = p_tenant_id;
    if not found then
      raise exception 'ai_asset_not_found' using errcode = 'P0002';
    end if;
    v_asset_id := v_asset.id;
  else
    -- A request for something already registered attaches to that entry.
    select * into v_asset from public.ai_assets
     where tenant_id = p_tenant_id
       and asset_type = app.ai_json_text(p_fields, 'asset_type')
       and identifier = app.ai_json_text(p_fields, 'identifier');
    v_asset_id := v_asset.id;
  end if;
  if v_asset_id is not null and v_asset.status = 'approved'
     and coalesce(app.ai_json_text(p_fields, 'requested_status'), 'approved') = 'approved' then
    raise exception 'ai_asset_already_approved' using errcode = '55000';
  end if;

  if (select count(*) from public.ai_intake_requests
       where tenant_id = p_tenant_id and status = 'pending') >= 200 then
    raise exception 'ai_intake_request_quota' using errcode = '54000';
  end if;

  insert into public.ai_intake_requests (
    tenant_id, asset_id, asset_type, identifier, name, vendor, business_purpose, data_categories,
    requested_status, requested_by, created_at, expires_at
  ) values (
    p_tenant_id, v_asset_id,
    coalesce(v_asset.asset_type, app.ai_json_text(p_fields, 'asset_type')),
    coalesce(v_asset.identifier, app.ai_json_text(p_fields, 'identifier')),
    coalesce(app.ai_json_text(p_fields, 'name'), v_asset.name),
    coalesce(app.ai_json_text(p_fields, 'vendor'), v_asset.vendor),
    app.ai_json_text(p_fields, 'business_purpose'),
    app.ai_json_categories(p_fields, 'data_categories'),
    coalesce(app.ai_json_text(p_fields, 'requested_status'), 'approved'),
    p_actor_user_id, v_now, v_now + interval '90 days'
  )
  on conflict (tenant_id, asset_type, identifier) where status = 'pending' do nothing
  returning * into v_row;
  if not found then
    raise exception 'ai_intake_request_pending' using errcode = '23505';
  end if;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_intake.requested',
    jsonb_build_object('request_id', v_row.id, 'asset_id', v_row.asset_id, 'asset_type', v_row.asset_type,
      'identifier', v_row.identifier, 'requested_status', v_row.requested_status,
      'data_categories', to_jsonb(v_row.data_categories)));
  return jsonb_build_object('request_id', v_row.id, 'status', v_row.status, 'asset_id', v_row.asset_id,
    'expires_at', v_row.expires_at);
end;
$$;
revoke all on function public.submit_ai_intake_request(uuid, uuid, jsonb) from public, anon, authenticated;
grant execute on function public.submit_ai_intake_request(uuid, uuid, jsonb) to service_role;

-- ── RPC: decide an intake request ──────────────────────────────────────────
-- Owner/admin, or a designated reviewer; never the requester. A reviewer may
-- not approve an outcome that relaxes an enforced ban or restriction.

create or replace function public.decide_ai_intake_request(
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
  v_reviewer boolean;
  v_request public.ai_intake_requests;
  v_asset public.ai_assets;
  v_asset_id uuid;
  v_days integer;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_request_id is null
     or p_decision is null or p_decision not in ('approve', 'reject')
     or not app.ai_governance_text_valid(p_reason, 500, true) then
    raise exception 'invalid_ai_intake_decision' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  v_reviewer := v_role = 'member' and exists (
    select 1 from public.ai_governance_reviewers r
     where r.tenant_id = p_tenant_id and r.user_id = p_actor_user_id);
  if v_role is null or not (v_role in ('owner', 'admin') or v_reviewer) then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':ai-governance', 0));
  select * into v_request from public.ai_intake_requests
   where id = p_request_id and tenant_id = p_tenant_id
   for update;
  if not found then
    raise exception 'ai_intake_request_not_found' using errcode = 'P0002';
  end if;
  if v_request.status <> 'pending' then
    return jsonb_build_object('outcome', 'already_final', 'request_id', v_request.id, 'status', v_request.status);
  end if;
  if v_request.expires_at <= v_now then
    update public.ai_intake_requests set status = 'expired', closed_at = v_now where id = v_request.id;
    perform app.ai_governance_audit(p_tenant_id, null, 'ai_intake.expired',
      jsonb_build_object('request_id', v_request.id));
    return jsonb_build_object('outcome', 'expired', 'request_id', v_request.id, 'status', 'expired');
  end if;
  if v_request.requested_by = p_actor_user_id then
    raise exception 'four_eyes_self_approval' using errcode = '42501';
  end if;

  if p_decision = 'reject' then
    update public.ai_intake_requests
       set status = 'rejected', decided_by = p_actor_user_id, decided_at = v_now,
           decision_reason = btrim(p_reason), closed_at = v_now
     where id = v_request.id;
    perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_intake.rejected',
      jsonb_build_object('request_id', v_request.id, 'asset_type', v_request.asset_type,
        'identifier', v_request.identifier, 'requested_by', v_request.requested_by, 'reason', btrim(p_reason)));
    return jsonb_build_object('outcome', 'decided', 'request_id', v_request.id, 'status', 'rejected');
  end if;

  select * into v_asset from public.ai_assets
   where tenant_id = p_tenant_id and asset_type = v_request.asset_type and identifier = v_request.identifier
   for update;
  if found then
    if v_asset.risk_tier = 'prohibited' then
      raise exception 'ai_asset_prohibited' using errcode = '55000';
    end if;
    if v_reviewer and app.ai_asset_enforceable(v_asset.asset_type, v_asset.identifier)
       and app.ai_status_rank(v_request.requested_status) < app.ai_status_rank(v_asset.status) then
      raise exception 'governance_reviewer_scope' using errcode = '42501';
    end if;
    update public.ai_assets
       set status = v_request.requested_status,
           business_purpose = coalesce(business_purpose, v_request.business_purpose),
           data_categories = case when cardinality(data_categories) = 0 then v_request.data_categories else data_categories end,
           owner_user_id = coalesce(owner_user_id, v_request.requested_by),
           version = version + 1, updated_by = p_actor_user_id, updated_at = v_now
     where id = v_asset.id;
    v_asset_id := v_asset.id;
    perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_asset.status_changed',
      jsonb_build_object('asset_id', v_asset.id, 'asset_type', v_asset.asset_type, 'identifier', v_asset.identifier,
        'status_from', v_asset.status, 'status_to', v_request.requested_status, 'intake_request_id', v_request.id));
  else
    if (select count(*) from public.ai_assets a where a.tenant_id = p_tenant_id) >= 5000 then
      raise exception 'ai_governance_register_quota' using errcode = '54000';
    end if;
    select coalesce(max(s.default_review_days), 180) into v_days
      from public.tenant_ai_governance_settings s where s.tenant_id = p_tenant_id;
    insert into public.ai_assets (
      tenant_id, asset_type, identifier, name, vendor, owner_user_id, business_purpose, data_categories,
      status, source, review_due_at, created_by, created_at, updated_by, updated_at
    ) values (
      p_tenant_id, v_request.asset_type, v_request.identifier, v_request.name, v_request.vendor,
      v_request.requested_by, v_request.business_purpose, v_request.data_categories,
      v_request.requested_status, 'intake', (v_now at time zone 'utc')::date + v_days,
      p_actor_user_id, v_now, p_actor_user_id, v_now
    )
    returning id into v_asset_id;
    perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_asset.created',
      jsonb_build_object('asset_id', v_asset_id, 'asset_type', v_request.asset_type,
        'identifier', v_request.identifier, 'status', v_request.requested_status,
        'intake_request_id', v_request.id));
  end if;

  update public.ai_intake_requests
     set status = 'approved', decided_by = p_actor_user_id, decided_at = v_now,
         decision_reason = btrim(p_reason), closed_at = v_now, resulting_asset_id = v_asset_id,
         asset_id = v_asset_id
   where id = v_request.id;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_intake.approved',
    jsonb_build_object('request_id', v_request.id, 'asset_id', v_asset_id, 'asset_type', v_request.asset_type,
      'identifier', v_request.identifier, 'status', v_request.requested_status,
      'requested_by', v_request.requested_by, 'reason', btrim(p_reason),
      'decided_as', case when v_reviewer then 'reviewer' else v_role end));
  if (select count(*) from public.ai_assets a
       where a.tenant_id = p_tenant_id and a.asset_type = 'mcp_server'
         and a.status in ('banned', 'restricted')) > 500 then
    raise exception 'ai_governance_enforcement_quota' using errcode = '54000';
  end if;
  return jsonb_build_object('outcome', 'decided', 'request_id', v_request.id, 'status', 'approved',
    'asset_id', v_asset_id);
end;
$$;
revoke all on function public.decide_ai_intake_request(uuid, uuid, uuid, text, text) from public, anon, authenticated;
grant execute on function public.decide_ai_intake_request(uuid, uuid, uuid, text, text) to service_role;

-- ── RPC: request an exception (owner/admin/member) ─────────────────────────

create or replace function public.request_ai_governance_exception(
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
  v_text text;
  v_asset public.ai_assets;
  v_scope text;
  v_users uuid[];
  v_agents uuid[];
  v_expires timestamptz;
  v_row public.ai_governance_exceptions;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_fields is null or jsonb_typeof(p_fields) <> 'object' then
    raise exception 'invalid_ai_governance_exception' using errcode = '22023';
  end if;
  for v_key in select jsonb_object_keys(p_fields) loop
    if v_key not in ('asset_id', 'scope_kind', 'scope_user_ids', 'scope_agent_ids', 'justification', 'expires_at') then
      raise exception 'invalid_ai_governance_field:%', v_key using errcode = '22023';
    end if;
  end loop;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin', 'member') then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':ai-governance', 0));

  v_text := app.ai_json_text(p_fields, 'asset_id');
  if v_text is null or v_text !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
    raise exception 'invalid_ai_governance_field:asset_id' using errcode = '22023';
  end if;
  select * into v_asset from public.ai_assets where id = v_text::uuid and tenant_id = p_tenant_id;
  if not found then
    raise exception 'ai_asset_not_found' using errcode = 'P0002';
  end if;
  if v_asset.status not in ('banned', 'restricted') then
    raise exception 'ai_governance_exception_not_restricted' using errcode = '55000';
  end if;
  if v_asset.risk_tier = 'prohibited' then
    raise exception 'ai_asset_prohibited' using errcode = '55000';
  end if;

  v_scope := coalesce(app.ai_json_text(p_fields, 'scope_kind'), 'tenant');
  if v_scope not in ('tenant', 'members', 'agents') then
    raise exception 'invalid_ai_governance_field:scope_kind' using errcode = '22023';
  end if;
  v_users := app.ai_json_uuid_array(p_fields, 'scope_user_ids', 100);
  v_agents := app.ai_json_uuid_array(p_fields, 'scope_agent_ids', 200);
  if v_scope = 'members' and exists (
    select 1 from unnest(v_users) u
     where not exists (
       select 1 from public.tenant_members m
        where m.tenant_id = p_tenant_id and m.user_id = u
          and (m.expires_at is null or m.expires_at > v_now))) then
    raise exception 'ai_governance_exception_scope_member' using errcode = '22023';
  end if;
  if v_scope = 'agents' and exists (
    select 1 from unnest(v_agents) g
     where not exists (select 1 from public.agents a where a.tenant_id = p_tenant_id and a.id = g)) then
    raise exception 'ai_governance_exception_scope_agent' using errcode = '22023';
  end if;

  v_text := app.ai_json_text(p_fields, 'expires_at');
  begin
    v_expires := v_text::timestamptz;
  exception when others then
    raise exception 'invalid_ai_governance_field:expires_at' using errcode = '22023';
  end;
  if v_expires is null or v_expires <= v_now + interval '1 hour' or v_expires > v_now + interval '365 days' then
    raise exception 'invalid_ai_governance_field:expires_at' using errcode = '22023';
  end if;

  if (select count(*) from public.ai_governance_exceptions
       where tenant_id = p_tenant_id and status in ('pending', 'approved')) >= 500 then
    raise exception 'ai_governance_exception_quota' using errcode = '54000';
  end if;

  insert into public.ai_governance_exceptions (
    tenant_id, asset_id, scope_kind, scope_user_ids, scope_agent_ids, justification,
    requested_by, created_at, expires_at
  ) values (
    p_tenant_id, v_asset.id, v_scope,
    case when v_scope = 'members' then v_users else '{}'::uuid[] end,
    case when v_scope = 'agents' then v_agents else '{}'::uuid[] end,
    app.ai_json_text(p_fields, 'justification'),
    p_actor_user_id, v_now, v_expires
  )
  returning * into v_row;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_exception.requested',
    jsonb_build_object('exception_id', v_row.id, 'asset_id', v_asset.id, 'asset_type', v_asset.asset_type,
      'identifier', v_asset.identifier, 'scope_kind', v_row.scope_kind,
      'scope_size', greatest(cardinality(v_row.scope_user_ids), cardinality(v_row.scope_agent_ids)),
      'expires_at', v_row.expires_at));
  return jsonb_build_object('exception_id', v_row.id, 'status', v_row.status, 'expires_at', v_row.expires_at);
end;
$$;
revoke all on function public.request_ai_governance_exception(uuid, uuid, jsonb) from public, anon, authenticated;
grant execute on function public.request_ai_governance_exception(uuid, uuid, jsonb) to service_role;

-- ── RPC: decide an exception (owner/admin, never the requester) ────────────

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
           decision_reason = btrim(p_reason), starts_at = v_now
     where id = v_row.id;
  end if;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id,
    case when p_decision = 'approve' then 'ai_exception.approved' else 'ai_exception.rejected' end,
    jsonb_build_object('exception_id', v_row.id, 'asset_id', v_row.asset_id,
      'asset_type', v_asset.asset_type, 'identifier', v_asset.identifier,
      'scope_kind', v_row.scope_kind, 'expires_at', v_row.expires_at,
      'requested_by', v_row.requested_by, 'reason', btrim(p_reason)));
  return jsonb_build_object('outcome', 'decided', 'exception_id', v_row.id,
    'status', case when p_decision = 'approve' then 'approved' else 'rejected' end,
    'expires_at', v_row.expires_at);
end;
$$;
revoke all on function public.decide_ai_governance_exception(uuid, uuid, uuid, text, text) from public, anon, authenticated;
grant execute on function public.decide_ai_governance_exception(uuid, uuid, uuid, text, text) to service_role;

-- ── RPC: revoke an active exception (owner/admin) ──────────────────────────

create or replace function public.revoke_ai_governance_exception(
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
  v_row public.ai_governance_exceptions;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_exception_id is null
     or not app.ai_governance_text_valid(p_reason, 500, true) then
    raise exception 'invalid_ai_governance_exception_revoke' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  select * into v_row from public.ai_governance_exceptions
   where id = p_exception_id and tenant_id = p_tenant_id
   for update;
  if not found then
    raise exception 'ai_governance_exception_not_found' using errcode = 'P0002';
  end if;
  if v_row.status <> 'approved' or v_row.expires_at <= v_now then
    return jsonb_build_object('outcome', 'not_active', 'exception_id', v_row.id,
      'status', case when v_row.status = 'approved' then 'expired' else v_row.status end);
  end if;
  update public.ai_governance_exceptions
     set status = 'revoked', revoked_by = p_actor_user_id, revoked_at = v_now,
         revoke_reason = btrim(p_reason), closed_at = v_now
   where id = v_row.id;
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'ai_exception.revoked',
    jsonb_build_object('exception_id', v_row.id, 'asset_id', v_row.asset_id, 'reason', btrim(p_reason)));
  return jsonb_build_object('outcome', 'revoked', 'exception_id', v_row.id, 'status', 'revoked');
end;
$$;
revoke all on function public.revoke_ai_governance_exception(uuid, uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.revoke_ai_governance_exception(uuid, uuid, uuid, text) to service_role;

-- ── Enforcement feed ───────────────────────────────────────────────────────
-- What connectors must add on top of the published runtime policy for one
-- caller. Exceptions apply only while approved and unexpired, evaluated at
-- read time, so an expired exception stops applying without a sweep. With
-- neither a user nor an agent, only tenant-wide exceptions apply (the view an
-- administrator exports for browser management).

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
     where e.tenant_id = p_tenant_id
       and e.status = 'approved'
       and e.starts_at <= clock_timestamp()
       and e.expires_at > clock_timestamp()
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
