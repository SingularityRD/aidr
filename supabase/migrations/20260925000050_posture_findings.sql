-- AI security posture findings (dashboard /posture).
--
-- Source events arrive through /v1/ingest, whose projection
-- (supabase/functions/ingest/events.ts + posture.ts) already reduces them to
-- identifiers, enums, bounded numbers and sha256 digests:
--   infra_scan_finding     aidr scan --target … --upload  (AIG CVE / exposure)
--   mcp_inventory_finding  aidr discover --upload        (MCP server inventory)
--   plugin_scan_finding    aidr scan --skill … --upload  (skill/plugin T01–T09)
--
-- Each stored event is projected into one typed row here by an AFTER INSERT
-- trigger, so the dashboard can aggregate by severity/CVSS/category under RLS
-- without parsing JSON in the browser.
--
-- Retention and offboarding: every row references its source event with
-- ON DELETE CASCADE. Telemetry retention (prune_expired_telemetry_events) and
-- the offboarding `events` phase delete the events, which removes the posture
-- rows in the same statement and under the same legal-hold checks. A residue
-- guard below additionally refuses to close a tenant, or complete an
-- offboarding run, while any posture row for it remains.

create table if not exists public.posture_findings (
  id bigint generated always as identity primary key,
  tenant_id uuid not null,
  event_row_id bigint not null references public.events (id) on delete cascade,
  agent_id uuid not null,
  source text not null
    check (source in ('infra_scan', 'mcp_inventory', 'skill_scan')),
  finding_kind text not null
    check (finding_kind in ('cve', 'advisory', 'exposed_component', 'mcp_server', 'skill_rule')),
  severity text not null
    check (severity in ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
  cvss numeric(3, 1) check (cvss is null or cvss between 0 and 10),
  vuln_id text check (
    vuln_id is null
    or vuln_id ~ '^(CVE-[0-9]{4}-[0-9]{4,7}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$'
  ),
  component text check (component is null or component ~ '^[A-Za-z0-9][A-Za-z0-9 ._+/-]{0,79}$'),
  component_version text check (
    component_version is null or component_version ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$'
  ),
  applicability text check (applicability is null or applicability in ('confirmed', 'unconfirmed')),
  target_digest text check (target_digest is null or target_digest ~ '^sha256:[a-f0-9]{64}$'),
  mcp_server_name text check (
    mcp_server_name is null or mcp_server_name ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  ),
  mcp_transport text check (mcp_transport is null or mcp_transport in ('remote', 'stdio')),
  risk_categories text[] not null default '{}'::text[]
    check (cardinality(risk_categories) <= 16),
  attestation_status text check (
    attestation_status is null or attestation_status in
      ('approved', 'unapproved', 'quarantined', 'unsigned', 'unverifiable', 'rejected')
  ),
  subject_digest text check (subject_digest is null or subject_digest ~ '^sha256:[a-f0-9]{64}$'),
  plugin_key text check (plugin_key is null or plugin_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  rule_id text check (rule_id is null or rule_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  skill_risk_type text check (skill_risk_type is null or skill_risk_type ~ '^T0[1-9]$'),
  scan_id text check (scan_id is null or scan_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  observed_at timestamptz not null,
  created_at timestamptz not null default now(),
  constraint posture_findings_event_unique unique (event_row_id)
);

create index if not exists posture_findings_tenant_observed_idx
  on public.posture_findings (tenant_id, observed_at desc);
create index if not exists posture_findings_tenant_source_severity_idx
  on public.posture_findings (tenant_id, source, severity);

comment on table public.posture_findings is
  'Typed projection of ingested AI security posture events (infra CVEs, MCP inventory, skill/plugin findings). Rows cascade with their source event for retention and offboarding.';

-- ── Projection ─────────────────────────────────────────────────────────────
-- Every field is re-validated against the same bounded shape as the ingest
-- projection; anything else becomes NULL rather than failing the telemetry
-- insert, so a malformed optional field never loses the source event.
create or replace function app.insert_posture_finding(p_event public.events)
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  p jsonb := coalesce(p_event.payload, '{}'::jsonb);
  v_source text;
  v_kind text;
  v_severity text;
  v_cvss numeric;
  v_categories text[];
  v_observed timestamptz;
  v_subject text;
begin
  v_source := case p_event.type
    when 'infra_scan_finding' then 'infra_scan'
    when 'mcp_inventory_finding' then 'mcp_inventory'
    when 'plugin_scan_finding' then 'skill_scan'
  end;
  if v_source is null then return; end if;

  v_kind := case
    when v_source = 'infra_scan' and p->>'finding_kind' in ('cve', 'advisory', 'exposed_component')
      then p->>'finding_kind'
    when v_source = 'infra_scan' then 'advisory'
    when v_source = 'mcp_inventory' then 'mcp_server'
    else 'skill_rule'
  end;

  v_severity := case
    when p->>'finding_severity' in ('critical', 'high', 'medium', 'low', 'info', 'unknown')
      then p->>'finding_severity'
    when p->>'severity' in ('critical', 'high', 'info') then p->>'severity'
    when p->>'severity' = 'warning' then 'medium'
    else 'unknown'
  end;

  if jsonb_typeof(p->'cvss') = 'number' then
    v_cvss := (p->>'cvss')::numeric;
    v_cvss := case when v_cvss between 0 and 10 then round(v_cvss, 1) end;
  end if;

  select coalesce(array_agg(distinct c.value order by c.value), '{}'::text[]) into v_categories
  from (
    select e.value
    from jsonb_array_elements(
      case when jsonb_typeof(p->'risk_categories') = 'array' then p->'risk_categories' else '[]'::jsonb end
    ) with ordinality as a(item, ord)
    cross join lateral (select a.item #>> '{}' as value) e
    where jsonb_typeof(a.item) = 'string'
      and e.value ~ '^((aig-)?mcp-[a-z0-9-]{1,48}|remote_mcp_url|shell_wrapper_command|broad_filesystem_access_arg)$'
    order by a.ord
    limit 16
  ) c;

  begin
    v_observed := (p->>'timestamp')::timestamptz;
  exception when others then
    v_observed := null;
  end;
  -- A client clock can be wrong; never record an observation after receipt.
  v_observed := least(coalesce(v_observed, p_event.created_at), p_event.created_at);

  v_subject := case
    when v_source = 'mcp_inventory' then p->>'server_digest'
    when v_source = 'skill_scan' then p->>'source_file_digest'
  end;

  insert into public.posture_findings (
    tenant_id, event_row_id, agent_id, source, finding_kind, severity, cvss, vuln_id,
    component, component_version, applicability, target_digest, mcp_server_name,
    mcp_transport, risk_categories, attestation_status, subject_digest, plugin_key,
    rule_id, skill_risk_type, scan_id, observed_at
  ) values (
    p_event.tenant_id,
    p_event.id,
    p_event.agent_id,
    v_source,
    v_kind,
    v_severity,
    v_cvss,
    case when p->>'vuln_id' ~ '^(CVE-[0-9]{4}-[0-9]{4,7}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$'
      then p->>'vuln_id' end,
    case when p->>'component' ~ '^[A-Za-z0-9][A-Za-z0-9 ._+/-]{0,79}$' then p->>'component' end,
    case when p->>'component_version' ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$'
      then p->>'component_version' end,
    case when p->>'applicability' in ('confirmed', 'unconfirmed') then p->>'applicability' end,
    case when p->>'target_digest' ~ '^sha256:[a-f0-9]{64}$' then p->>'target_digest' end,
    case when p->>'mcp_server_name' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      then p->>'mcp_server_name' end,
    case when p->>'mcp_transport' in ('remote', 'stdio') then p->>'mcp_transport' end,
    v_categories,
    case when p->>'attestation_status' in
      ('approved', 'unapproved', 'quarantined', 'unsigned', 'unverifiable', 'rejected')
      then p->>'attestation_status' end,
    case when v_subject ~ '^sha256:[a-f0-9]{64}$' then v_subject end,
    case when p->>'plugin_key' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' then p->>'plugin_key' end,
    case when p->>'matched_threat_id' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      then p->>'matched_threat_id' end,
    case when p->>'skill_risk_type' ~ '^T0[1-9]$' then p->>'skill_risk_type' end,
    case when p->>'scan_id' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' then p->>'scan_id' end,
    v_observed
  )
  on conflict (event_row_id) do nothing;
end;
$$;
revoke all on function app.insert_posture_finding(public.events) from public, anon, authenticated;

create or replace function app.project_posture_finding()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  perform app.insert_posture_finding(new);
  return new;
end;
$$;
revoke all on function app.project_posture_finding() from public, anon, authenticated;

drop trigger if exists events_project_posture_finding on public.events;
create trigger events_project_posture_finding
  after insert on public.events
  for each row
  when (new.type in ('infra_scan_finding', 'mcp_inventory_finding', 'plugin_scan_finding'))
  execute function app.project_posture_finding();

-- Backfill events stored before this migration (idempotent).
select app.insert_posture_finding(e)
from public.events e
where e.type in ('infra_scan_finding', 'mcp_inventory_finding', 'plugin_scan_finding')
  and not exists (select 1 from public.posture_findings f where f.event_row_id = e.id);

-- ── Access ─────────────────────────────────────────────────────────────────
-- Members read their tenant's rows; nobody but the projection writes them.
alter table public.posture_findings enable row level security;
revoke all on public.posture_findings from public, anon, authenticated;
grant select on public.posture_findings to authenticated;
grant select, insert, update, delete on public.posture_findings to service_role;

drop policy if exists posture_findings_select_member on public.posture_findings;
create policy posture_findings_select_member on public.posture_findings
  for select to authenticated
  using (app.is_tenant_member(tenant_id));

drop policy if exists posture_findings_member_restrict on public.posture_findings;
create policy posture_findings_member_restrict on public.posture_findings
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

-- ── Offboarding residue guard ──────────────────────────────────────────────
-- Cascade from `events` is the deletion path. This guard makes a missed path
-- fail loudly instead of leaving posture data behind a "closed" tenant.
create or replace function app.assert_no_posture_offboarding_residue()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare v_tenant uuid;
begin
  if tg_table_name = 'tenants' then
    if new.status <> 'closed' then return new; end if;
    v_tenant := new.id;
  else
    if new.status <> 'completed' then return new; end if;
    v_tenant := new.tenant_id;
  end if;
  if exists (select 1 from public.posture_findings where tenant_id = v_tenant) then
    raise exception 'posture_findings_offboarding_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_no_posture_offboarding_residue() from public, anon, authenticated;

drop trigger if exists tenants_posture_offboarding_residue on public.tenants;
create trigger tenants_posture_offboarding_residue
  before update of status on public.tenants
  for each row execute function app.assert_no_posture_offboarding_residue();

drop trigger if exists offboarding_runs_posture_residue on public.tenant_offboarding_runs;
create trigger offboarding_runs_posture_residue
  before update of status on public.tenant_offboarding_runs
  for each row execute function app.assert_no_posture_offboarding_residue();
