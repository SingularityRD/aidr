-- Developer-facing loop: approver notifications on by default, unprotected AI
-- tools in posture, and the false-positive report queue.
--
-- 1. Approval notifications (D8). A new notification channel now selects
--    `approval.requested` unless the administrator turns it off, so a managed
--    ask reaches an approver instead of waiting silently. Existing channels
--    keep what their administrators chose; nothing is switched on for them.
--
-- 2. Unprotected AI tools (D6). Connectors upload an `agent_posture_finding`
--    with check `no_aidr_connector` for AI coding tools AIDR does not protect.
--    The accepted host list grows by Windsurf, JetBrains AI / Junie, Cline, Roo
--    Code, GitHub Copilot CLI, Amazon Q Developer, Kiro and Zed. The projection
--    is the 20260927004000 definition with only that list extended.
--
-- 3. False-positive reports (D9). `aidr report-fp <actionId>` files a report
--    through the `false-positive-reports` function with the tenant API key.
--    One row per (tenant, feedback_id): the id is the deterministic
--    false-positive-feedback record id, so a resubmission is a no-op. Members
--    read their tenant's rows; nobody writes through the client roles.

-- ── 1. Approval notifications default ─────────────────────────────────────
alter table public.notification_channels
  alter column on_approval_requested set default true;

-- ── 2. Unprotected AI tool hosts ──────────────────────────────────────────
alter table public.posture_findings drop constraint if exists posture_findings_agent_host_check;
alter table public.posture_findings add constraint posture_findings_agent_host_check
  check (agent_host is null or agent_host in (
    'claude-code', 'cursor', 'vscode', 'codex', 'opencode', 'openclaw', 'gemini-cli', 'aider',
    'environment', 'windsurf', 'jetbrains-ai', 'cline', 'roo-code', 'copilot-cli', 'amazon-q',
    'kiro', 'zed'
  ));

-- Projection: the 20260927004000 definition with the agent host list extended.
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
      'aider', 'environment', 'windsurf', 'jetbrains-ai', 'cline', 'roo-code', 'copilot-cli',
      'amazon-q', 'kiro', 'zed'
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

-- ── 3. False-positive reports ─────────────────────────────────────────────
create table if not exists public.false_positive_reports (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  feedback_id text not null check (feedback_id ~ '^fpfb_[0-9a-f]{64}$'),
  record_hash text not null check (record_hash ~ '^[0-9a-f]{64}$'),
  iid text not null check (length(iid) between 1 and 128 and iid !~ '[[:cntrl:]]'),
  api_key_id uuid,
  agent_runtime text check (agent_runtime is null or agent_runtime ~ '^[a-z0-9][a-z0-9_.-]{0,31}$'),
  action_id text not null check (action_id ~ '^[a-f0-9]{8,128}$'),
  rule_id text check (rule_id is null or rule_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  decision text not null check (decision in ('deny', 'ask')),
  severity text check (severity is null or severity in ('info', 'warning', 'critical', 'high', 'medium', 'low')),
  category text check (category is null or category ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
  tool text check (tool is null or (length(tool) between 1 and 64 and tool !~ '[[:cntrl:]]')),
  reason_code text not null check (reason_code in (
    'benign_automation', 'benign_maintenance', 'expected_egress', 'expected_file_write',
    'legitimate_mcp_tool', 'developer_test', 'environment_specific', 'insufficient_context',
    'policy_too_strict', 'other'
  )),
  rationale text not null default '' check (length(rationale) <= 1000 and rationale !~ '[[:cntrl:]]'),
  occurred_at timestamptz,
  status text not null default 'open' check (status in ('open', 'accepted', 'rejected')),
  created_at timestamptz not null default clock_timestamp(),
  constraint false_positive_reports_tenant_feedback_unique unique (tenant_id, feedback_id)
);

create index if not exists false_positive_reports_tenant_created_idx
  on public.false_positive_reports (tenant_id, created_at desc);
create index if not exists false_positive_reports_tenant_rule_idx
  on public.false_positive_reports (tenant_id, rule_id) where rule_id is not null;

comment on table public.false_positive_reports is
  'Developer false-positive reports filed with `aidr report-fp` (tenant API key). Ids, rule, decision and a bounded, redacted note; never the command, file content or a secret.';

alter table public.false_positive_reports enable row level security;
revoke all on public.false_positive_reports from public, anon, authenticated, service_role;
grant select on public.false_positive_reports to authenticated;
grant select, insert on public.false_positive_reports to service_role;

drop policy if exists false_positive_reports_select_member on public.false_positive_reports;
create policy false_positive_reports_select_member on public.false_positive_reports
  for select to authenticated
  using (app.is_tenant_member(tenant_id));

drop policy if exists false_positive_reports_member_restrict on public.false_positive_reports;
create policy false_positive_reports_member_restrict on public.false_positive_reports
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.false_positive_reports;
create policy tenant_identity_access_restrict on public.false_positive_reports
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));
