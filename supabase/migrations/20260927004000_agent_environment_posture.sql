-- Agent environment and autonomy posture (dashboard /posture).
--
-- `aidr discover --agents --upload` reports one agent_posture_finding event per
-- static check that fired on an installation: the agent host, a fixed check id,
-- the severity and a bounded count. Config paths, key values, environment
-- variable names and credentials never leave the machine; the ingest projection
-- (supabase/functions/ingest/posture.ts) already enforces this, and this
-- migration re-validates every field again before storing it.
--
-- Extends the existing posture_findings projection instead of adding a parallel
-- table, so retention (cascade from public.events), RLS and the offboarding
-- residue guard from 20260925000050_posture_findings.sql apply unchanged.
-- Idempotent: every step can be re-applied.

alter table public.posture_findings
  add column if not exists agent_host text,
  add column if not exists check_id text,
  add column if not exists finding_count integer;

alter table public.posture_findings drop constraint if exists posture_findings_source_check;
alter table public.posture_findings add constraint posture_findings_source_check
  check (source in ('infra_scan', 'mcp_inventory', 'skill_scan', 'agent_environment'));

alter table public.posture_findings drop constraint if exists posture_findings_finding_kind_check;
alter table public.posture_findings add constraint posture_findings_finding_kind_check
  check (finding_kind in
    ('cve', 'advisory', 'exposed_component', 'mcp_server', 'skill_rule', 'agent_config'));

alter table public.posture_findings drop constraint if exists posture_findings_agent_host_check;
alter table public.posture_findings add constraint posture_findings_agent_host_check
  check (agent_host is null or agent_host in (
    'claude-code', 'cursor', 'vscode', 'codex', 'opencode', 'openclaw', 'gemini-cli', 'aider',
    'environment'
  ));

alter table public.posture_findings drop constraint if exists posture_findings_check_id_check;
alter table public.posture_findings add constraint posture_findings_check_id_check
  check (check_id is null or check_id in (
    'permission_bypass_mode', 'broad_shell_allow_rule', 'hooks_disabled', 'aidr_hook_missing',
    'no_aidr_connector', 'approval_policy_never', 'sandbox_full_access',
    'permission_allow_all', 'running_as_root', 'docker_socket_writable',
    'cloud_credentials_in_env', 'no_devcontainer', 'mcp_plaintext_secret'
  ));

alter table public.posture_findings drop constraint if exists posture_findings_finding_count_check;
alter table public.posture_findings add constraint posture_findings_finding_count_check
  check (finding_count is null or finding_count between 0 and 10000);

create index if not exists posture_findings_tenant_agent_idx
  on public.posture_findings (tenant_id, agent_host, check_id)
  where source = 'agent_environment';

comment on column public.posture_findings.agent_host is
  'agent_environment rows: the agent host the check ran against (or "environment" for host-wide checks).';
comment on column public.posture_findings.check_id is
  'agent_environment rows: fixed static check id (see docs/agent-environment-posture.md).';
comment on column public.posture_findings.finding_count is
  'agent_environment rows: number of items the finding covers (rules, variables, servers); never names or values.';

-- ── Projection (replaces the 20260925000050 definition; same contract plus agent rows) ──
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
  v_count integer;
begin
  v_source := case p_event.type
    when 'infra_scan_finding' then 'infra_scan'
    when 'mcp_inventory_finding' then 'mcp_inventory'
    when 'plugin_scan_finding' then 'skill_scan'
    when 'agent_posture_finding' then 'agent_environment'
  end;
  if v_source is null then return; end if;

  v_kind := case
    when v_source = 'infra_scan' and p->>'finding_kind' in ('cve', 'advisory', 'exposed_component')
      then p->>'finding_kind'
    when v_source = 'infra_scan' then 'advisory'
    when v_source = 'mcp_inventory' then 'mcp_server'
    when v_source = 'agent_environment' then 'agent_config'
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

  if jsonb_typeof(p->'finding_count') = 'number' then
    begin
      v_count := (p->>'finding_count')::integer;
    exception when others then
      v_count := null;
    end;
    v_count := case when v_count between 0 and 10000 then v_count end;
  end if;

  v_subject := case
    when v_source = 'mcp_inventory' then p->>'server_digest'
    when v_source = 'skill_scan' then p->>'source_file_digest'
  end;

  insert into public.posture_findings (
    tenant_id, event_row_id, agent_id, source, finding_kind, severity, cvss, vuln_id,
    component, component_version, applicability, target_digest, mcp_server_name,
    mcp_transport, risk_categories, attestation_status, subject_digest, plugin_key,
    rule_id, skill_risk_type, scan_id, agent_host, check_id, finding_count, observed_at
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
    case when v_source = 'agent_environment' and p->>'agent_host' in (
      'claude-code', 'cursor', 'vscode', 'codex', 'opencode', 'openclaw', 'gemini-cli',
      'aider', 'environment'
    )
      then p->>'agent_host' end,
    case when v_source = 'agent_environment' and p->>'check_id' in (
      'permission_bypass_mode', 'broad_shell_allow_rule', 'hooks_disabled',
      'aidr_hook_missing', 'no_aidr_connector', 'approval_policy_never', 'sandbox_full_access',
      'permission_allow_all', 'running_as_root', 'docker_socket_writable',
      'cloud_credentials_in_env', 'no_devcontainer', 'mcp_plaintext_secret'
    )
      then p->>'check_id' end,
    case when v_source = 'agent_environment' then v_count end,
    v_observed
  )
  on conflict (event_row_id) do nothing;
end;
$$;
revoke all on function app.insert_posture_finding(public.events) from public, anon, authenticated;

drop trigger if exists events_project_posture_finding on public.events;
create trigger events_project_posture_finding
  after insert on public.events
  for each row
  when (new.type in
    ('infra_scan_finding', 'mcp_inventory_finding', 'plugin_scan_finding', 'agent_posture_finding'))
  execute function app.project_posture_finding();

-- Backfill agent posture events stored before this migration (idempotent).
select app.insert_posture_finding(e)
from public.events e
where e.type = 'agent_posture_finding'
  and not exists (select 1 from public.posture_findings f where f.event_row_id = e.id);
