-- Governance scorecard, governance settings and human-oversight analytics
-- (docs/ai-governance-frameworks.md, governance/frameworks/*.yaml).
--
-- Tables
--   tenant_governance_settings      one row per tenant: scheduled governance
--                                   summary (cadence, recipients, schedule
--                                   cursor, lease) and the human-oversight
--                                   review thresholds. Owners/admins read it;
--                                   writes go through set_governance_settings.
--   governance_digest_deliveries    delivery receipts of scheduled and test
--                                   summaries: counts and status only, never a
--                                   recipient address or message content.
--
-- Functions
--   app.governance_scorecard_data   counts-only aggregation shared by the
--                                   dashboard RPC and the scheduled summary.
--   public.governance_scorecard     dashboard RPC: owner/admin of an active
--                                   tenant, tenant identity barrier, fixed
--                                   7/30/90 day windows.
--   public.set_governance_settings  owner/admin update with an append-only
--                                   admin audit receipt.
--
-- Nothing here returns prompt text, event payloads, policy bodies, page
-- addresses or matched values. The only personal data is the approver list of
-- the human-oversight panel (user id and e-mail of workspace members who
-- decided approvals), returned to owners/admins of the same workspace only.

-- ── Tables ─────────────────────────────────────────────────────────────────

create table if not exists public.tenant_governance_settings (
  tenant_id uuid primary key references public.tenants (id) on delete cascade,
  digest_enabled boolean not null default false,
  digest_cadence text not null default 'weekly'
    check (digest_cadence in ('weekly', 'monthly')),
  digest_recipients text not null default 'owners_admins'
    check (digest_recipients in ('owners', 'owners_admins')),
  digest_next_at timestamptz,
  digest_last_at timestamptz,
  digest_last_status text check (digest_last_status is null or digest_last_status in
    ('sent', 'partial', 'failed', 'no_transport', 'no_recipients')),
  digest_attempts smallint not null default 0 check (digest_attempts between 0 and 10),
  digest_claim_id uuid,
  digest_claim_expires_at timestamptz,
  -- Human-oversight review prompt: an approver with at least `min_decisions`
  -- decisions in the window, of which at least `fast_share` were approvals
  -- made within `fast_seconds` of the request, is shown as "review".
  oversight_fast_seconds integer not null default 30
    check (oversight_fast_seconds between 1 and 3600),
  oversight_min_decisions integer not null default 10
    check (oversight_min_decisions between 1 and 10000),
  oversight_fast_share numeric(4, 3) not null default 0.900
    check (oversight_fast_share between 0.500 and 1.000),
  updated_by uuid,
  updated_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  constraint tenant_governance_settings_schedule
    check (not digest_enabled or digest_next_at is not null),
  constraint tenant_governance_settings_claim
    check ((digest_claim_id is null) = (digest_claim_expires_at is null))
);

comment on table public.tenant_governance_settings is
  'Governance summary schedule and human-oversight review thresholds. Owners/admins read; writes via set_governance_settings and the service-role digest RPCs.';

create table if not exists public.governance_digest_deliveries (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  trigger text not null check (trigger in ('schedule', 'test')),
  cadence text not null check (cadence in ('weekly', 'monthly')),
  period_from timestamptz not null,
  period_to timestamptz not null,
  status text not null check (status in ('sent', 'partial', 'failed', 'no_transport', 'no_recipients')),
  recipients integer not null check (recipients between 0 and 1000),
  delivered integer not null check (delivered between 0 and 1000),
  requested_by uuid,
  created_at timestamptz not null default now(),
  constraint governance_digest_deliveries_period check (period_to > period_from),
  constraint governance_digest_deliveries_counts check (delivered <= recipients),
  constraint governance_digest_deliveries_status_shape check (
    (status = 'sent' and delivered = recipients and recipients > 0)
    or (status = 'partial' and delivered > 0 and delivered < recipients)
    or (status = 'failed' and delivered = 0 and recipients > 0)
    or (status = 'no_transport' and delivered = 0)
    or (status = 'no_recipients' and recipients = 0 and delivered = 0)
  )
);

create index if not exists governance_digest_deliveries_tenant_created_idx
  on public.governance_digest_deliveries (tenant_id, created_at desc);

comment on table public.governance_digest_deliveries is
  'Receipts of governance summaries: trigger, period, status and recipient/delivered counts. No addresses or content.';

-- ── Access ─────────────────────────────────────────────────────────────────

alter table public.tenant_governance_settings enable row level security;
alter table public.governance_digest_deliveries enable row level security;

revoke all on public.tenant_governance_settings from public, anon, authenticated;
revoke all on public.governance_digest_deliveries from public, anon, authenticated;
-- The lease columns are internal to the dispatcher.
grant select (
  tenant_id, digest_enabled, digest_cadence, digest_recipients, digest_next_at,
  digest_last_at, digest_last_status, oversight_fast_seconds, oversight_min_decisions,
  oversight_fast_share, updated_at
) on public.tenant_governance_settings to authenticated;
grant select on public.governance_digest_deliveries to authenticated;
grant select, insert, update, delete on public.tenant_governance_settings to service_role;
grant select, insert, delete on public.governance_digest_deliveries to service_role;

drop policy if exists tenant_governance_settings_select_admin on public.tenant_governance_settings;
create policy tenant_governance_settings_select_admin on public.tenant_governance_settings
  for select to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'));

drop policy if exists tenant_governance_settings_no_client_write on public.tenant_governance_settings;
create policy tenant_governance_settings_no_client_write on public.tenant_governance_settings
  as restrictive for all to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.tenant_governance_settings;
create policy tenant_identity_access_restrict on public.tenant_governance_settings
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

drop policy if exists governance_digest_deliveries_select_admin on public.governance_digest_deliveries;
create policy governance_digest_deliveries_select_admin on public.governance_digest_deliveries
  for select to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'));

drop policy if exists governance_digest_deliveries_no_client_write on public.governance_digest_deliveries;
create policy governance_digest_deliveries_no_client_write on public.governance_digest_deliveries
  as restrictive for all to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.governance_digest_deliveries;
create policy tenant_identity_access_restrict on public.governance_digest_deliveries
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Schedule helper ────────────────────────────────────────────────────────

-- Next delivery time strictly after p_after: Monday 06:00 UTC (weekly) or the
-- first day of the month 06:00 UTC (monthly).
create or replace function app.governance_digest_next_at(p_cadence text, p_after timestamptz)
returns timestamptz
language plpgsql
stable
set search_path = pg_catalog, pg_temp
as $$
declare
  v_local timestamp := p_after at time zone 'utc';
  v_candidate timestamp;
begin
  if p_cadence = 'weekly' then
    v_candidate := date_trunc('week', v_local) + interval '6 hours';
    while v_candidate <= v_local loop
      v_candidate := v_candidate + interval '7 days';
    end loop;
  elsif p_cadence = 'monthly' then
    v_candidate := date_trunc('month', v_local) + interval '6 hours';
    while v_candidate <= v_local loop
      v_candidate := date_trunc('month', v_candidate + interval '1 month') + interval '6 hours';
    end loop;
  else
    raise exception 'invalid_governance_cadence' using errcode = '22023';
  end if;
  return v_candidate at time zone 'utc';
end;
$$;
revoke all on function app.governance_digest_next_at(text, timestamptz) from public, anon, authenticated;
grant execute on function app.governance_digest_next_at(text, timestamptz) to service_role;

-- ── Aggregation ────────────────────────────────────────────────────────────

create or replace function app.governance_scorecard_data(
  p_tenant_id uuid,
  p_from timestamptz,
  p_to timestamptz,
  p_identities boolean
)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_fast integer := 30;
  v_min integer := 10;
  v_share numeric := 0.900;
  v_digest_enabled boolean := false;
  v_first date;
  v_last date;
  v_usage jsonb;
  v_sites jsonb;
  v_mcp jsonb;
  v_trends jsonb;
  v_decisions jsonb;
  v_approvals jsonb;
  v_oversight jsonb;
  v_incidents jsonb;
  v_browser jsonb;
  v_policies jsonb;
  v_identity jsonb;
  v_posture jsonb;
  v_aup jsonb;
  v_agents_active bigint;
  v_browser_active bigint;
  v_requested bigint;
  v_releases bigint;
begin
  if p_tenant_id is null or p_from is null or p_to is null or p_to <= p_from
     or p_to - p_from > interval '93 days' then
    raise exception 'invalid_governance_period' using errcode = '22023';
  end if;

  select s.oversight_fast_seconds, s.oversight_min_decisions, s.oversight_fast_share, s.digest_enabled
    into v_fast, v_min, v_share, v_digest_enabled
  from public.tenant_governance_settings s where s.tenant_id = p_tenant_id;
  v_fast := coalesce(v_fast, 30);
  v_min := coalesce(v_min, 10);
  v_share := coalesce(v_share, 0.900);
  v_digest_enabled := coalesce(v_digest_enabled, false);
  v_first := (p_from at time zone 'utc')::date;
  v_last := ((p_to - interval '1 microsecond') at time zone 'utc')::date;

  -- ── AI usage: agents, browser installs ─────────────────────────────────
  select
    count(*) filter (where a.agent_runtime is distinct from 'browser_guard' and a.last_seen >= p_from),
    count(*) filter (where a.agent_runtime = 'browser_guard' and a.last_seen >= p_from),
    jsonb_build_object(
      'agents', jsonb_build_object(
        'enrolled', count(*) filter (where a.agent_runtime is distinct from 'browser_guard'),
        'active', count(*) filter (where a.agent_runtime is distinct from 'browser_guard' and a.last_seen >= p_from)
      ),
      'browser_installs', jsonb_build_object(
        'enrolled', count(*) filter (where a.agent_runtime = 'browser_guard'),
        'active', count(*) filter (where a.agent_runtime = 'browser_guard' and a.last_seen >= p_from)
      ),
      'by_runtime', coalesce((
        select jsonb_agg(jsonb_build_object('runtime', runtime, 'enrolled', enrolled, 'active', active)
          order by enrolled desc, runtime)
        from (
          select
            case when r.agent_runtime ~ '^[a-z0-9][a-z0-9_.-]{0,63}$' then r.agent_runtime else 'unknown' end as runtime,
            count(*) as enrolled,
            count(*) filter (where r.last_seen >= p_from) as active
          from public.agents r
          where r.tenant_id = p_tenant_id
          group by 1
          order by 2 desc, 1
          limit 32
        ) grouped
      ), '[]'::jsonb)
    )
    into v_agents_active, v_browser_active, v_usage
  from public.agents a
  where a.tenant_id = p_tenant_id;

  -- ── Browser Guard: sites and masking counts (counts only) ──────────────
  with scans as materialized (
    select
      e.created_at,
      case when e.payload->>'action' in ('masked', 'warned', 'blocked', 'allowed')
        then e.payload->>'action' else 'unknown' end as action,
      case when e.payload->>'site' ~ '^[a-z0-9_-]{1,32}$' then e.payload->>'site' else 'other' end as site,
      case when jsonb_typeof(e.payload->'findings_count') = 'number'
        and (e.payload->>'findings_count') ~ '^[0-9]{1,7}$'
        then (e.payload->>'findings_count')::bigint else 0 end as items
    from public.events e
    where e.tenant_id = p_tenant_id
      and e.type = 'privacy_scan'
      and e.created_at >= p_from and e.created_at < p_to
  )
  select
    jsonb_build_object(
      'distinct', (select count(distinct site) from scans),
      'by_site', coalesce((
        select jsonb_agg(jsonb_build_object('site', site, 'scans', scans, 'blocked', blocked) order by scans desc, site)
        from (
          select site, count(*) as scans, count(*) filter (where action = 'blocked') as blocked
          from scans group by site order by 2 desc, 1 limit 16
        ) grouped
      ), '[]'::jsonb)
    ),
    jsonb_build_object(
      'scans', (select count(*) from scans),
      'masked', (select count(*) from scans where action = 'masked'),
      'warned', (select count(*) from scans where action = 'warned'),
      'blocked', (select count(*) from scans where action = 'blocked'),
      'allowed', (select count(*) from scans where action = 'allowed'),
      'items_masked', (select coalesce(sum(items), 0) from scans where action = 'masked')
    )
    into v_sites, v_browser;

  -- ── MCP servers reported by inventory scans in the period ──────────────
  with servers as (
    select coalesce(f.subject_digest, f.mcp_server_name) as server,
      bool_or(f.attestation_status = 'approved') as approved
    from public.posture_findings f
    where f.tenant_id = p_tenant_id and f.source = 'mcp_inventory'
      and f.observed_at >= p_from and f.observed_at < p_to
      and coalesce(f.subject_digest, f.mcp_server_name) is not null
    group by 1
  )
  select jsonb_build_object(
    'distinct', count(*),
    'not_approved', count(*) filter (where not approved)
  ) into v_mcp
  from servers;

  -- ── Decisions and daily trend ──────────────────────────────────────────
  with verdicts as materialized (
    select
      (e.created_at at time zone 'utc')::date as day,
      coalesce(
        case when e.payload->>'decision' in ('allow', 'ask', 'deny') then e.payload->>'decision' end,
        case when e.payload->>'verdict' in ('allow', 'ask', 'deny') then e.payload->>'verdict' end,
        'unknown'
      ) as decision,
      (e.payload->>'user_override') = 'true' as override,
      case when e.payload->>'source' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'
        then lower(e.payload->>'source') else 'unspecified' end as source
    from public.events e
    where e.tenant_id = p_tenant_id
      and e.type = 'runtime_verdict'
      and e.created_at >= p_from and e.created_at < p_to
  ),
  privacy_days as (
    select (e.created_at at time zone 'utc')::date as day,
      count(*) filter (where e.payload->>'action' = 'masked') as masked,
      count(*) filter (where e.payload->>'action' = 'blocked') as blocked
    from public.events e
    where e.tenant_id = p_tenant_id and e.type = 'privacy_scan'
      and e.created_at >= p_from and e.created_at < p_to
    group by 1
  ),
  days as (
    select d::date as day
    from generate_series(v_first::timestamp, v_last::timestamp, interval '1 day') d
  )
  select
    jsonb_build_object(
      'allow', (select count(*) from verdicts where decision = 'allow'),
      'ask', (select count(*) from verdicts where decision = 'ask'),
      'deny', (select count(*) from verdicts where decision = 'deny'),
      'released_by_operator', (select count(*) from verdicts where override and source = 'operator_approval'),
      'released_by_dashboard', (select count(*) from verdicts where override and source = 'dashboard_approval'),
      'released_other', (select count(*) from verdicts where override and source not in ('operator_approval', 'dashboard_approval'))
    ),
    (select count(*) from verdicts where override),
    coalesce((
      select jsonb_agg(jsonb_build_object(
        'day', to_char(days.day, 'YYYY-MM-DD'),
        'allow', coalesce(v.allow_count, 0),
        'ask', coalesce(v.ask_count, 0),
        'deny', coalesce(v.deny_count, 0),
        'masked', coalesce(p.masked, 0),
        'blocked', coalesce(p.blocked, 0)
      ) order by days.day)
      from days
      left join (
        select day,
          count(*) filter (where decision = 'allow') as allow_count,
          count(*) filter (where decision = 'ask') as ask_count,
          count(*) filter (where decision = 'deny') as deny_count
        from verdicts group by day
      ) v on v.day = days.day
      left join privacy_days p on p.day = days.day
    ), '[]'::jsonb)
    into v_decisions, v_releases, v_trends;

  -- ── Approvals (dashboard approval requests) ────────────────────────────
  select
    count(*) filter (where r.created_at >= p_from and r.created_at < p_to),
    jsonb_build_object(
      'requested', count(*) filter (where r.created_at >= p_from and r.created_at < p_to),
      'approved', count(*) filter (where r.status = 'approved' and r.decided_at >= p_from and r.decided_at < p_to),
      'denied', count(*) filter (where r.status = 'denied' and r.decided_at >= p_from and r.decided_at < p_to),
      'expired_without_decision', count(*) filter (
        where r.expires_at >= p_from and r.expires_at < least(p_to, now())
          and (r.status = 'expired' or r.status = 'pending')
      ),
      'pending', count(*) filter (where r.status = 'pending' and r.expires_at > now()),
      'median_decision_seconds', (
        select round((percentile_cont(0.5) within group (
          order by extract(epoch from (d.decided_at - d.created_at))))::numeric, 1)
        from public.approval_requests d
        where d.tenant_id = p_tenant_id and d.status in ('approved', 'denied')
          and d.decided_at >= p_from and d.decided_at < p_to
      ),
      'p90_decision_seconds', (
        select round((percentile_cont(0.9) within group (
          order by extract(epoch from (d.decided_at - d.created_at))))::numeric, 1)
        from public.approval_requests d
        where d.tenant_id = p_tenant_id and d.status in ('approved', 'denied')
          and d.decided_at >= p_from and d.decided_at < p_to
      )
    )
    into v_requested, v_approvals
  from public.approval_requests r
  where r.tenant_id = p_tenant_id
    and (r.created_at >= p_from or r.decided_at >= p_from or r.expires_at >= p_from or r.status = 'pending');

  -- ── Human oversight: per-approver pattern (review prompt, not a verdict) ─
  with decided as (
    select r.decided_by, r.status,
      extract(epoch from (r.decided_at - r.created_at)) as seconds
    from public.approval_requests r
    where r.tenant_id = p_tenant_id
      and r.status in ('approved', 'denied')
      and r.decided_at >= p_from and r.decided_at < p_to
      and r.decided_by is not null
  ),
  per_approver as (
    select decided_by,
      count(*) as decisions,
      count(*) filter (where status = 'approved') as approved,
      count(*) filter (where status = 'denied') as denied,
      count(*) filter (where status = 'approved' and seconds <= v_fast) as fast_approvals,
      round((percentile_cont(0.5) within group (order by seconds))::numeric, 1) as median_seconds
    from decided
    group by decided_by
  ),
  flagged as (
    select p.*, (p.decisions >= v_min and p.fast_approvals >= v_share * p.decisions) as review
    from per_approver p
  )
  select jsonb_build_object(
    'thresholds', jsonb_build_object(
      'fast_seconds', v_fast, 'min_decisions', v_min, 'fast_share', v_share
    ),
    'approvers', (select count(*) from flagged),
    'review_prompts', (select count(*) from flagged where review),
    'by_approver', case when p_identities then coalesce((
      select jsonb_agg(jsonb_build_object(
        'user_id', f.decided_by,
        'email', (select left(u.email::text, 254) from auth.users u where u.id = f.decided_by),
        'decisions', f.decisions,
        'approved', f.approved,
        'denied', f.denied,
        'fast_approvals', f.fast_approvals,
        'median_seconds', f.median_seconds,
        'review', f.review
      ) order by f.review desc, f.decisions desc, f.decided_by)
      from (select * from flagged order by review desc, decisions desc, decided_by limit 50) f
    ), '[]'::jsonb) else '[]'::jsonb end
  ) into v_oversight;

  -- ── Incidents reported in the period, by latest status ─────────────────
  with latest as (
    select distinct on (incident_key) severity, status
    from (
      select
        coalesce(
          case when e.payload->>'incident_id' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' then e.payload->>'incident_id' end,
          'event:' || e.id::text
        ) as incident_key,
        case when e.payload->>'severity' in ('info', 'warning', 'high', 'critical')
          then e.payload->>'severity' else 'unknown' end as severity,
        case when e.payload->>'status' in ('open', 'acknowledged', 'contained', 'resolved', 'suppressed')
          then e.payload->>'status' else 'unknown' end as status,
        e.created_at,
        e.id
      from public.events e
      where e.tenant_id = p_tenant_id and e.type = 'incident'
        and e.created_at >= p_from and e.created_at < p_to
    ) reported
    order by incident_key, created_at desc, id desc
  )
  select jsonb_build_object(
    'reported', count(*),
    'open', count(*) filter (where status in ('open', 'acknowledged', 'contained')),
    'status_unknown', count(*) filter (where status = 'unknown'),
    'open_by_severity', jsonb_build_object(
      'critical', count(*) filter (where status in ('open', 'acknowledged', 'contained') and severity = 'critical'),
      'high', count(*) filter (where status in ('open', 'acknowledged', 'contained') and severity = 'high'),
      'warning', count(*) filter (where status in ('open', 'acknowledged', 'contained') and severity = 'warning'),
      'info', count(*) filter (where status in ('open', 'acknowledged', 'contained') and severity = 'info'),
      'unknown', count(*) filter (where status in ('open', 'acknowledged', 'contained') and severity = 'unknown')
    )
  ) into v_incidents
  from latest;

  -- ── Policy freshness (versions and ages; never bodies) ─────────────────
  select jsonb_build_object(
    'runtime', (
      select jsonb_build_object('version', p.version, 'updated_at', p.updated_at,
        'age_days', floor(extract(epoch from (now() - p.updated_at)) / 86400)::integer)
      from public.tenant_runtime_policies p where p.tenant_id = p_tenant_id
    ),
    'dlp', (
      select jsonb_build_object('version', d.version, 'updated_at', d.updated_at,
        'age_days', floor(extract(epoch from (now() - d.updated_at)) / 86400)::integer)
      from public.tenant_dlp_policies d where d.tenant_id = p_tenant_id
    ),
    'team', (
      select jsonb_build_object('updated_at', tp.updated_at,
        'age_days', floor(extract(epoch from (now() - tp.updated_at)) / 86400)::integer)
      from public.team_policies tp where tp.tenant_id = p_tenant_id
      order by tp.updated_at desc limit 1
    ),
    'runtime_revisions_in_period', (
      select count(*) from public.runtime_policy_revisions r
      where r.tenant_id = p_tenant_id and r.created_at >= p_from and r.created_at < p_to
    ),
    'dlp_revisions_in_period', (
      select count(*) from public.dlp_policy_revisions r
      where r.tenant_id = p_tenant_id and r.created_at >= p_from and r.created_at < p_to
    )
  ) into v_policies;

  -- ── Identity and retention posture ─────────────────────────────────────
  select jsonb_build_object(
    'require_mfa', coalesce((select ip.require_mfa from public.tenant_identity_policies ip where ip.tenant_id = p_tenant_id), false),
    'sso_required', coalesce((select ip.required_saml_provider_id is not null from public.tenant_identity_policies ip where ip.tenant_id = p_tenant_id), false),
    'scim_active_tokens', (
      select count(*) from public.scim_tokens st
      where st.tenant_id = p_tenant_id and st.revoked_at is null
        and (st.expires_at is null or st.expires_at > now())
    ),
    'owners_admins', (
      select count(*) from public.tenant_members m
      where m.tenant_id = p_tenant_id and m.role in ('owner', 'admin')
        and (m.expires_at is null or m.expires_at > now())
    ),
    'owners_admins_without_mfa', (
      select count(*) from public.tenant_members m
      where m.tenant_id = p_tenant_id and m.role in ('owner', 'admin')
        and (m.expires_at is null or m.expires_at > now())
        and not exists (
          select 1 from auth.mfa_factors f
          where f.user_id = m.user_id and f.status::text = 'verified'
        )
    ),
    'retention_policies', (
      select count(*) from public.tenant_data_retention_policies rp where rp.tenant_id = p_tenant_id
    ),
    'telemetry_retention_days', (
      select rp.retention_days from public.tenant_data_retention_policies rp
      where rp.tenant_id = p_tenant_id and rp.data_class = 'telemetry'
    ),
    'legal_hold_active', exists (
      select 1 from public.tenant_legal_holds h where h.tenant_id = p_tenant_id and h.released_at is null
    )
  ) into v_identity;

  -- ── AI security posture findings in the period ─────────────────────────
  select jsonb_build_object(
    'findings', count(*),
    'critical', count(*) filter (where f.severity = 'critical'),
    'high', count(*) filter (where f.severity = 'high'),
    'cve_confirmed', count(*) filter (where f.finding_kind = 'cve' and f.applicability = 'confirmed')
  ) into v_posture
  from public.posture_findings f
  where f.tenant_id = p_tenant_id and f.observed_at >= p_from and f.observed_at < p_to;

  -- ── Acceptable-use acknowledgements (counts per notice version) ────────
  -- Coverage is cumulative over retained telemetry: an install acknowledges a
  -- version once, however long ago.
  with acks as (
    select e.payload->>'notice_id' as notice_id,
      case when e.payload->>'notice_version' ~ '^[1-9][0-9]{0,5}$'
        then (e.payload->>'notice_version')::integer end as notice_version,
      e.agent_id, e.created_at
    from public.events e
    where e.tenant_id = p_tenant_id and e.type = 'aup_acknowledgement'
      and e.payload->>'notice_id' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'
      and e.payload->>'notice_version' ~ '^[1-9][0-9]{0,5}$'
  )
  select jsonb_build_object(
    'versions', coalesce((
      select jsonb_agg(jsonb_build_object(
        'notice_id', notice_id, 'notice_version', notice_version,
        'installs', installs, 'last_acknowledged_at', last_at
      ) order by last_at desc, notice_id, notice_version desc)
      from (
        select notice_id, notice_version, count(distinct agent_id) as installs, max(created_at) as last_at
        from acks group by notice_id, notice_version
        order by max(created_at) desc, notice_id, notice_version desc
        limit 20
      ) grouped
    ), '[]'::jsonb)
  ) into v_aup;

  return jsonb_build_object(
    'generated_at', now(),
    'period', jsonb_build_object('from', p_from, 'to', p_to,
      'days', (v_last - v_first) + 1),
    'usage', v_usage || jsonb_build_object('ai_sites', v_sites, 'mcp_servers', v_mcp),
    'decisions', v_decisions,
    'trend', v_trends,
    'approvals', v_approvals,
    'oversight', v_oversight,
    'incidents', v_incidents,
    'browser_guard', v_browser,
    'policies', v_policies,
    'identity', v_identity,
    'posture', v_posture,
    'acceptable_use', v_aup,
    'signals', jsonb_build_object(
      'agents_reporting', v_agents_active > 0,
      'browser_guard_reporting', v_browser_active > 0,
      'dlp_policy_configured', exists (select 1 from public.tenant_dlp_policies d where d.tenant_id = p_tenant_id),
      'runtime_policy_configured', exists (select 1 from public.tenant_runtime_policies p where p.tenant_id = p_tenant_id),
      'human_approval_in_use', v_requested > 0 or v_releases > 0,
      'acceptable_use_acknowledged', jsonb_array_length(v_aup->'versions') > 0,
      'mcp_inventory_reported', exists (
        select 1 from public.posture_findings f where f.tenant_id = p_tenant_id and f.source = 'mcp_inventory'
      ),
      'posture_reported', (v_posture->>'findings')::bigint > 0,
      'mfa_required', (v_identity->>'require_mfa')::boolean,
      'retention_configured', (v_identity->>'retention_policies')::bigint > 0,
      'compliance_report_generated', exists (
        select 1 from public.admin_audit_logs l
        where l.tenant_id = p_tenant_id and l.action = 'compliance_report.generated'
      ),
      'governance_digest_enabled', v_digest_enabled
    )
  );
end;
$$;
revoke all on function app.governance_scorecard_data(uuid, timestamptz, timestamptz, boolean)
  from public, anon, authenticated;

-- ── Dashboard RPC ──────────────────────────────────────────────────────────

create or replace function public.governance_scorecard(p_tenant_id uuid, p_days integer)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_from timestamptz;
  v_result jsonb;
begin
  if p_tenant_id is null or p_days is null or p_days not in (7, 30, 90) then
    raise exception 'invalid_governance_window' using errcode = '22023';
  end if;
  -- Owner/admin of an active tenant whose session passes the tenant identity
  -- barrier (MFA/SSO policy, global session revocation).
  if auth.uid() is null or not app.is_tenant_member_with_role(p_tenant_id, 'admin') then
    raise exception 'governance_forbidden' using errcode = '42501';
  end if;
  if not public.tenant_identity_access_allowed(p_tenant_id) then
    raise exception 'governance_identity_barrier' using errcode = '42501';
  end if;

  -- Whole UTC days, so totals and the daily trend cover the same rows.
  v_from := (((now() at time zone 'utc')::date - (p_days - 1))::timestamp) at time zone 'utc';
  v_result := app.governance_scorecard_data(p_tenant_id, v_from, now(), true);
  return v_result || jsonb_build_object(
    'window_days', p_days,
    'settings', coalesce((
      select jsonb_build_object(
        'digest_enabled', s.digest_enabled,
        'digest_cadence', s.digest_cadence,
        'digest_recipients', s.digest_recipients,
        'digest_next_at', s.digest_next_at,
        'digest_last_at', s.digest_last_at,
        'digest_last_status', s.digest_last_status,
        'oversight_fast_seconds', s.oversight_fast_seconds,
        'oversight_min_decisions', s.oversight_min_decisions,
        'oversight_fast_share', s.oversight_fast_share,
        'updated_at', s.updated_at
      )
      from public.tenant_governance_settings s where s.tenant_id = p_tenant_id
    ), jsonb_build_object(
      'digest_enabled', false, 'digest_cadence', 'weekly', 'digest_recipients', 'owners_admins',
      'digest_next_at', null, 'digest_last_at', null, 'digest_last_status', null,
      'oversight_fast_seconds', 30, 'oversight_min_decisions', 10, 'oversight_fast_share', 0.900,
      'updated_at', null
    )),
    'recent_deliveries', coalesce((
      select jsonb_agg(jsonb_build_object(
        'created_at', d.created_at, 'trigger', d.trigger, 'cadence', d.cadence,
        'period_from', d.period_from, 'period_to', d.period_to, 'status', d.status,
        'recipients', d.recipients, 'delivered', d.delivered
      ) order by d.created_at desc)
      from (
        select * from public.governance_digest_deliveries x
        where x.tenant_id = p_tenant_id order by x.created_at desc limit 5
      ) d
    ), '[]'::jsonb)
  );
end;
$$;
revoke all on function public.governance_scorecard(uuid, integer) from public, anon;
grant execute on function public.governance_scorecard(uuid, integer) to authenticated, service_role;

-- ── Settings RPC ───────────────────────────────────────────────────────────

create or replace function public.set_governance_settings(
  p_tenant_id uuid,
  p_digest_enabled boolean,
  p_digest_cadence text,
  p_digest_recipients text,
  p_oversight_fast_seconds integer,
  p_oversight_min_decisions integer,
  p_oversight_fast_share numeric
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_actor uuid := auth.uid();
  v_existing public.tenant_governance_settings;
  v_next timestamptz;
  v_row public.tenant_governance_settings;
begin
  if p_tenant_id is null or p_digest_enabled is null
     or p_digest_cadence is null or p_digest_cadence not in ('weekly', 'monthly')
     or p_digest_recipients is null or p_digest_recipients not in ('owners', 'owners_admins')
     or p_oversight_fast_seconds is null or p_oversight_fast_seconds not between 1 and 3600
     or p_oversight_min_decisions is null or p_oversight_min_decisions not between 1 and 10000
     or p_oversight_fast_share is null or p_oversight_fast_share not between 0.5 and 1
     or p_oversight_fast_share <> round(p_oversight_fast_share, 3) then
    raise exception 'invalid_governance_settings' using errcode = '22023';
  end if;
  if v_actor is null then
    raise exception 'governance_forbidden' using errcode = '42501';
  end if;
  -- Re-check owner/admin of an active tenant under share locks so a concurrent
  -- demotion or closure cannot slip past.
  perform 1
  from public.tenant_members m
  join public.tenants t on t.id = m.tenant_id
  where m.tenant_id = p_tenant_id and m.user_id = v_actor
    and m.role in ('owner', 'admin')
    and (m.expires_at is null or m.expires_at > now())
    and t.status = 'active'
  for share of m, t;
  if not found then
    raise exception 'governance_forbidden' using errcode = '42501';
  end if;
  if not public.tenant_identity_access_allowed(p_tenant_id) then
    raise exception 'governance_identity_barrier' using errcode = '42501';
  end if;

  select * into v_existing
  from public.tenant_governance_settings s where s.tenant_id = p_tenant_id
  for update;

  -- Keep the current schedule unless the summary was just enabled or its
  -- cadence changed; a disabled summary has no schedule.
  if not p_digest_enabled then
    v_next := null;
  elsif v_existing.tenant_id is null or not v_existing.digest_enabled
        or v_existing.digest_cadence <> p_digest_cadence or v_existing.digest_next_at is null then
    v_next := app.governance_digest_next_at(p_digest_cadence, now());
  else
    v_next := v_existing.digest_next_at;
  end if;

  insert into public.tenant_governance_settings as s (
    tenant_id, digest_enabled, digest_cadence, digest_recipients, digest_next_at,
    digest_attempts, oversight_fast_seconds, oversight_min_decisions, oversight_fast_share,
    updated_by, updated_at
  ) values (
    p_tenant_id, p_digest_enabled, p_digest_cadence, p_digest_recipients, v_next,
    0, p_oversight_fast_seconds, p_oversight_min_decisions, p_oversight_fast_share,
    v_actor, now()
  )
  on conflict (tenant_id) do update set
    digest_enabled = excluded.digest_enabled,
    digest_cadence = excluded.digest_cadence,
    digest_recipients = excluded.digest_recipients,
    digest_next_at = excluded.digest_next_at,
    digest_attempts = case when excluded.digest_next_at is distinct from s.digest_next_at
      then 0 else s.digest_attempts end,
    digest_claim_id = case when excluded.digest_enabled then s.digest_claim_id end,
    digest_claim_expires_at = case when excluded.digest_enabled then s.digest_claim_expires_at end,
    oversight_fast_seconds = excluded.oversight_fast_seconds,
    oversight_min_decisions = excluded.oversight_min_decisions,
    oversight_fast_share = excluded.oversight_fast_share,
    updated_by = excluded.updated_by,
    updated_at = excluded.updated_at
  returning * into v_row;

  insert into public.admin_audit_logs (actor_user_id, tenant_id, action, detail)
  values (v_actor, p_tenant_id, 'governance_settings.updated', jsonb_build_object(
    'digest_enabled', v_row.digest_enabled,
    'digest_cadence', v_row.digest_cadence,
    'digest_recipients', v_row.digest_recipients,
    'digest_next_at', v_row.digest_next_at,
    'oversight_fast_seconds', v_row.oversight_fast_seconds,
    'oversight_min_decisions', v_row.oversight_min_decisions,
    'oversight_fast_share', v_row.oversight_fast_share
  ));

  return jsonb_build_object(
    'digest_enabled', v_row.digest_enabled,
    'digest_cadence', v_row.digest_cadence,
    'digest_recipients', v_row.digest_recipients,
    'digest_next_at', v_row.digest_next_at,
    'digest_last_at', v_row.digest_last_at,
    'digest_last_status', v_row.digest_last_status,
    'oversight_fast_seconds', v_row.oversight_fast_seconds,
    'oversight_min_decisions', v_row.oversight_min_decisions,
    'oversight_fast_share', v_row.oversight_fast_share,
    'updated_at', v_row.updated_at
  );
end;
$$;
revoke all on function public.set_governance_settings(uuid, boolean, text, text, integer, integer, numeric)
  from public, anon;
grant execute on function public.set_governance_settings(uuid, boolean, text, text, integer, integer, numeric)
  to authenticated;
