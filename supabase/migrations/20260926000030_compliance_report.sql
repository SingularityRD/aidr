-- Compliance evidence report (supabase/functions/compliance-report, docs/compliance-report.md).
--
-- The report gives a security/DPO team one tenant-scoped, period-bounded
-- evidence bundle designed to support KVKK and GDPR accountability work. It
-- is not a certification and does not state that a tenant is compliant.
--
-- Two service-role-only functions back the Edge Function:
--   * public.compliance_report_evidence  aggregates the evidence. It returns
--     counts, enums, bounded identifiers, timestamps and sha256 digests only:
--     no prompt text, event payloads, DLP keywords/regexes, policy bodies,
--     legal-hold reasons or member data beyond the owner/admin access list.
--   * public.record_compliance_report    appends the issuance receipt (report
--     id, period, sha256 and signing key id) to the append-only admin audit log.
--
-- Both repeat the owner/admin + active-tenant authorization under row share
-- locks; the Edge Function additionally requires AAL2, the tenant identity
-- barrier and a tenant rate limit. No table is created, so retention and
-- offboarding coverage are unchanged (the receipt is security_audit evidence
-- in public.admin_audit_logs).

create or replace function public.compliance_report_evidence(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_from timestamptz,
  p_to timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_role text;
  v_tenant jsonb;
  v_coverage jsonb;
  v_browser jsonb;
  v_agent jsonb;
  v_policies jsonb;
  v_access jsonb;
  v_incidents jsonb;
  v_posture jsonb;
  v_retention jsonb;
  v_telemetry_days integer;
  v_oldest timestamptz;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_from is null or p_to is null
     or p_to <= p_from
     or p_to - p_from > interval '366 days'
     or p_from < timestamptz '2020-01-01 00:00:00+00'
     or p_to > now() + interval '5 minutes' then
    raise exception 'invalid_compliance_period' using errcode = '22023';
  end if;

  -- Owner/admin of an active tenant, rechecked here under share locks so a
  -- concurrent demotion, expiry or closure cannot slip past the Edge check.
  select m.role into v_role
  from public.tenant_members m
  join public.tenants t on t.id = m.tenant_id
  where m.tenant_id = p_tenant_id
    and m.user_id = p_actor_user_id
    and m.role in ('owner', 'admin')
    and (m.expires_at is null or m.expires_at > now())
    and t.status = 'active'
  for share of m, t;
  if not found then
    raise exception 'compliance_report_forbidden' using errcode = '42501';
  end if;

  -- ── Tenant profile ──────────────────────────────────────────────────────
  select jsonb_build_object(
    'tenant_id', t.id,
    'name', left(t.name, 200),
    'kind', t.kind,
    'status', t.status,
    'region', case when t.region ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' then t.region end,
    'retention_days', t.retention_days,
    'created_at', t.created_at
  ) into v_tenant
  from public.tenants t where t.id = p_tenant_id;

  -- ── Protection coverage ─────────────────────────────────────────────────
  select jsonb_build_object(
    'by_runtime', coalesce((
      select jsonb_agg(jsonb_build_object(
        'runtime', runtime,
        'enrolled', enrolled,
        'active_in_period', active_in_period,
        'first_enrolled_at', first_enrolled_at,
        'last_seen_at', last_seen_at
      ) order by runtime)
      from (
        select
          case when a.agent_runtime ~ '^[a-z0-9][a-z0-9_.-]{0,63}$' then a.agent_runtime else 'unknown' end as runtime,
          count(*) as enrolled,
          count(*) filter (where a.last_seen >= p_from and a.first_seen < p_to) as active_in_period,
          min(a.first_seen) as first_enrolled_at,
          max(a.last_seen) as last_seen_at
        from public.agents a
        where a.tenant_id = p_tenant_id
        group by 1
      ) grouped
    ), '[]'::jsonb),
    'totals', (
      select jsonb_build_object(
        'enrolled', count(*),
        'active_in_period', count(*) filter (where a.last_seen >= p_from and a.first_seen < p_to),
        'browser_installs', count(*) filter (where a.agent_runtime = 'browser_guard'),
        'browser_installs_active_in_period', count(*) filter (
          where a.agent_runtime = 'browser_guard' and a.last_seen >= p_from and a.first_seen < p_to
        ),
        'last_seen_at', max(a.last_seen)
      )
      from public.agents a
      where a.tenant_id = p_tenant_id
    )
  ) into v_coverage;

  -- ── Browser Guard data-protection activity (counts only) ────────────────
  with scans as materialized (
    select
      e.created_at,
      case when e.payload->>'action' in ('masked', 'warned', 'blocked', 'allowed')
        then e.payload->>'action' else 'unknown' end as action,
      case when e.payload->>'site' ~ '^[a-z0-9_-]{1,32}$' then e.payload->>'site' else 'other' end as site,
      case when e.payload->>'channel' in ('prompt', 'paste', 'file')
        then e.payload->>'channel' else 'unknown' end as channel,
      case when jsonb_typeof(e.payload->'entity_counts') = 'object'
        then e.payload->'entity_counts' else '{}'::jsonb end as entity_counts,
      case when e.payload->>'policy_id' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        then e.payload->>'policy_id' end as policy_id
    from public.events e
    where e.tenant_id = p_tenant_id
      and e.type = 'privacy_scan'
      and e.created_at >= p_from
      and e.created_at < p_to
  ),
  entity_rows as (
    select s.action, c.key as entity_type, round((c.value #>> '{}')::numeric)::bigint as items
    from scans s
    cross join lateral jsonb_each(s.entity_counts) c
    where jsonb_typeof(c.value) = 'number' and c.key ~ '^[A-Z][A-Z_]{0,31}$'
  )
  select jsonb_build_object(
    'totals', (
      select jsonb_build_object(
        'scans', count(*),
        'masked', count(*) filter (where action = 'masked'),
        'warned', count(*) filter (where action = 'warned'),
        'blocked', count(*) filter (where action = 'blocked'),
        'allowed', count(*) filter (where action = 'allowed')
      ) from scans
    ),
    'by_entity_type', coalesce((
      select jsonb_agg(jsonb_build_object(
        'entity_type', entity_type, 'items', items, 'masked_items', masked_items,
        'warned_items', warned_items, 'blocked_items', blocked_items
      ) order by items desc, entity_type)
      from (
        select entity_type,
          sum(items) as items,
          coalesce(sum(items) filter (where action = 'masked'), 0) as masked_items,
          coalesce(sum(items) filter (where action = 'warned'), 0) as warned_items,
          coalesce(sum(items) filter (where action = 'blocked'), 0) as blocked_items
        from entity_rows group by entity_type
      ) grouped
    ), '[]'::jsonb),
    'by_site', coalesce((
      select jsonb_agg(jsonb_build_object(
        'site', site, 'scans', scans, 'masked', masked, 'warned', warned, 'blocked', blocked
      ) order by scans desc, site)
      from (
        select site, count(*) as scans,
          count(*) filter (where action = 'masked') as masked,
          count(*) filter (where action = 'warned') as warned,
          count(*) filter (where action = 'blocked') as blocked
        from scans group by site
      ) grouped
    ), '[]'::jsonb),
    'by_channel', coalesce((
      select jsonb_agg(jsonb_build_object('channel', channel, 'scans', scans) order by channel)
      from (select channel, count(*) as scans from scans group by channel) grouped
    ), '[]'::jsonb),
    'by_day', coalesce((
      select jsonb_agg(jsonb_build_object(
        'day', to_char(day, 'YYYY-MM-DD'), 'scans', scans, 'masked', masked,
        'warned', warned, 'blocked', blocked
      ) order by day)
      from (
        select (created_at at time zone 'utc')::date as day, count(*) as scans,
          count(*) filter (where action = 'masked') as masked,
          count(*) filter (where action = 'warned') as warned,
          count(*) filter (where action = 'blocked') as blocked
        from scans group by 1
      ) grouped
    ), '[]'::jsonb),
    'managed_policy_ids', coalesce((
      select jsonb_agg(jsonb_build_object(
        'policy_id', policy_id, 'scans', scans, 'first_seen_at', first_seen_at, 'last_seen_at', last_seen_at
      ) order by scans desc, policy_id)
      from (
        select policy_id, count(*) as scans, min(created_at) as first_seen_at, max(created_at) as last_seen_at
        from scans where policy_id is not null
        group by policy_id
        order by count(*) desc, policy_id
        limit 50
      ) grouped
    ), '[]'::jsonb)
  ) into v_browser;

  -- ── Agent decisions (runtime verdicts; DLP/prompt protection subset) ─────
  with verdicts as materialized (
    select
      coalesce(
        case when e.payload->>'decision' in ('allow', 'ask', 'deny') then e.payload->>'decision' end,
        case when e.payload->>'verdict' in ('allow', 'ask', 'deny') then e.payload->>'verdict' end,
        'unknown'
      ) as decision,
      case when e.payload->>'source' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'
        then lower(e.payload->>'source') else 'unspecified' end as source
    from public.events e
    where e.tenant_id = p_tenant_id
      and e.type = 'runtime_verdict'
      and e.created_at >= p_from
      and e.created_at < p_to
  )
  select jsonb_build_object(
    'totals', (
      select jsonb_build_object(
        'decisions', count(*),
        'allow', count(*) filter (where decision = 'allow'),
        'ask', count(*) filter (where decision = 'ask'),
        'deny', count(*) filter (where decision = 'deny')
      ) from verdicts
    ),
    'data_protection', (
      select jsonb_build_object(
        'decisions', count(*),
        'allow', count(*) filter (where decision = 'allow'),
        'ask', count(*) filter (where decision = 'ask'),
        'deny', count(*) filter (where decision = 'deny')
      ) from verdicts where source ~ '^(dlp|prompt|privacy)'
    ),
    'by_source', coalesce((
      select jsonb_agg(jsonb_build_object(
        'source', source, 'decisions', decisions, 'allow', allow_count, 'ask', ask_count, 'deny', deny_count
      ) order by decisions desc, source)
      from (
        select source, count(*) as decisions,
          count(*) filter (where decision = 'allow') as allow_count,
          count(*) filter (where decision = 'ask') as ask_count,
          count(*) filter (where decision = 'deny') as deny_count
        from verdicts group by source
        order by count(*) desc, source
        limit 50
      ) grouped
    ), '[]'::jsonb)
  ) into v_agent;

  -- ── Policy inventory (versions and digests; never policy bodies) ─────────
  select jsonb_build_object(
    'dlp', jsonb_build_object(
      'current', (
        select jsonb_build_object(
          'version', d.version,
          'updated_at', d.updated_at,
          'sha256', encode(extensions.digest(d.policy::text, 'sha256'), 'hex'),
          'labels', case when jsonb_typeof(d.policy->'labels') = 'array' then jsonb_array_length(d.policy->'labels') else 0 end,
          'rules', case when jsonb_typeof(d.policy->'rules') = 'array' then jsonb_array_length(d.policy->'rules') else 0 end,
          'exceptions', case when jsonb_typeof(d.policy->'exceptions') = 'array' then jsonb_array_length(d.policy->'exceptions') else 0 end
        )
        from public.tenant_dlp_policies d where d.tenant_id = p_tenant_id
      ),
      'revisions_total', (select count(*) from public.dlp_policy_revisions r where r.tenant_id = p_tenant_id),
      'revisions_in_period', coalesce((
        select jsonb_agg(jsonb_build_object(
          'version', version, 'created_at', created_at, 'sha256', sha256
        ) order by version)
        from (
          select r.version, r.created_at, encode(extensions.digest(r.policy::text, 'sha256'), 'hex') as sha256
          from public.dlp_policy_revisions r
          where r.tenant_id = p_tenant_id and r.created_at >= p_from and r.created_at < p_to
          order by r.version desc
          limit 200
        ) recent
      ), '[]'::jsonb)
    ),
    'runtime', jsonb_build_object(
      'current', (
        select jsonb_build_object(
          'version', p.version,
          'updated_at', p.updated_at,
          'sha256', encode(extensions.digest(p.policy::text, 'sha256'), 'hex'),
          'actions', coalesce((
            select jsonb_object_agg(k.key, k.value #>> '{}')
            from jsonb_each(p.policy) k
            where k.key in ('command_default', 'file_default', 'url_default', 'package_default',
                            'output_default', 'mcp_default', 'mcp_unknown', 'mcp_risky')
              and (k.value #>> '{}') in ('allow', 'ask', 'deny')
          ), '{}'::jsonb),
          'list_sizes', coalesce((
            select jsonb_object_agg(k.key, jsonb_array_length(k.value))
            from jsonb_each(p.policy) k
            where k.key in ('mcp_allow_servers', 'mcp_require_approval_servers', 'mcp_deny_servers',
                            'mcp_allow_tools', 'mcp_require_approval_tools', 'mcp_deny_tools')
              and jsonb_typeof(k.value) = 'array'
          ), '{}'::jsonb)
        )
        from public.tenant_runtime_policies p where p.tenant_id = p_tenant_id
      ),
      'revisions_total', (select count(*) from public.runtime_policy_revisions r where r.tenant_id = p_tenant_id),
      'revisions_in_period', coalesce((
        select jsonb_agg(jsonb_build_object(
          'version', version, 'created_at', created_at, 'sha256', sha256
        ) order by version)
        from (
          select r.version, r.created_at, encode(extensions.digest(r.policy::text, 'sha256'), 'hex') as sha256
          from public.runtime_policy_revisions r
          where r.tenant_id = p_tenant_id and r.created_at >= p_from and r.created_at < p_to
          order by r.version desc
          limit 200
        ) recent
      ), '[]'::jsonb)
    ),
    'team_policy', (
      select jsonb_build_object(
        'updated_at', tp.updated_at,
        'sha256', encode(extensions.digest(tp.content, 'sha256'), 'hex')
      )
      from public.team_policies tp
      where tp.tenant_id = p_tenant_id
      order by tp.updated_at desc
      limit 1
    )
  ) into v_policies;

  -- ── Access and identity (minimal owner/admin list) ──────────────────────
  select jsonb_build_object(
    'identity_policy', (
      select jsonb_build_object(
        'require_mfa', ip.require_mfa,
        'sso_required', ip.required_saml_provider_id is not null,
        'break_glass_enabled', ip.break_glass_enabled,
        'updated_at', ip.updated_at
      )
      from public.tenant_identity_policies ip where ip.tenant_id = p_tenant_id
    ),
    'scim', (
      select jsonb_build_object(
        'active_tokens', (
          select count(*) from public.scim_tokens st
          where st.tenant_id = p_tenant_id and st.revoked_at is null
            and (st.expires_at is null or st.expires_at > now())
        ),
        'last_token_use_at', (
          select max(st.last_used_at) from public.scim_tokens st where st.tenant_id = p_tenant_id
        ),
        'provisioned_users_active', (
          select count(*) from public.scim_users su where su.tenant_id = p_tenant_id and su.active
        ),
        'group_role_mappings', (
          select count(*) from public.scim_group_role_mappings gm where gm.tenant_id = p_tenant_id
        )
      )
    ),
    'members_by_role', coalesce((
      select jsonb_agg(jsonb_build_object('role', role, 'members', members) order by role)
      from (
        select m.role, count(*) as members
        from public.tenant_members m
        where m.tenant_id = p_tenant_id and (m.expires_at is null or m.expires_at > now())
        group by m.role
      ) grouped
    ), '[]'::jsonb),
    'admins', coalesce((
      select jsonb_agg(jsonb_build_object(
        'user_id', user_id, 'email', email, 'role', role, 'joined_at', joined_at,
        'expires_at', expires_at, 'mfa_verified', mfa_verified
      ) order by role desc, joined_at, user_id)
      from (
        select m.user_id, left(u.email::text, 254) as email, m.role, m.joined_at, m.expires_at,
          exists (
            select 1 from auth.mfa_factors f
            where f.user_id = m.user_id and f.status::text = 'verified'
          ) as mfa_verified
        from public.tenant_members m
        left join auth.users u on u.id = m.user_id
        where m.tenant_id = p_tenant_id
          and m.role in ('owner', 'admin')
          and (m.expires_at is null or m.expires_at > now())
        order by m.role desc, m.joined_at, m.user_id
        limit 200
      ) admins
    ), '[]'::jsonb),
    'admin_activity', coalesce((
      select jsonb_agg(jsonb_build_object('action', action, 'events', events) order by events desc, action)
      from (
        select l.action, count(*) as events
        from public.admin_audit_logs l
        where l.tenant_id = p_tenant_id
          and l.created_at >= p_from and l.created_at < p_to
          and l.action ~ '^[a-z][a-z0-9_.]{0,63}$'
        group by l.action
        order by count(*) desc, l.action
        limit 100
      ) grouped
    ), '[]'::jsonb)
  ) into v_access;

  -- ── Incidents summary ───────────────────────────────────────────────────
  select jsonb_build_object(
    'incidents', (
      select jsonb_build_object(
        'total', count(*),
        'by_severity', coalesce((
          select jsonb_object_agg(severity, n) from (
            select case when i.payload->>'severity' in ('info', 'warning', 'high', 'critical')
              then i.payload->>'severity' else 'unknown' end as severity, count(*) as n
            from public.events i
            where i.tenant_id = p_tenant_id and i.type = 'incident'
              and i.created_at >= p_from and i.created_at < p_to
            group by 1
          ) s
        ), '{}'::jsonb),
        'by_status', coalesce((
          select jsonb_object_agg(status, n) from (
            select case when i.payload->>'status' in ('open', 'acknowledged', 'contained', 'resolved', 'suppressed')
              then i.payload->>'status' else 'unknown' end as status, count(*) as n
            from public.events i
            where i.tenant_id = p_tenant_id and i.type = 'incident'
              and i.created_at >= p_from and i.created_at < p_to
            group by 1
          ) s
        ), '{}'::jsonb)
      )
      from public.events e
      where e.tenant_id = p_tenant_id and e.type = 'incident'
        and e.created_at >= p_from and e.created_at < p_to
    ),
    'plugin_scans_with_findings', (
      select count(*) from public.events e
      where e.tenant_id = p_tenant_id and e.type = 'plugin_scan'
        and e.created_at >= p_from and e.created_at < p_to
        and jsonb_typeof(e.payload->'findings_count') = 'number'
        and (e.payload->>'findings_count')::numeric > 0
    )
  ) into v_incidents;

  -- ── AI security posture (CVE severities, MCP risks, skill findings) ─────
  with findings as materialized (
    select * from public.posture_findings f
    where f.tenant_id = p_tenant_id and f.observed_at >= p_from and f.observed_at < p_to
  )
  select jsonb_build_object(
    'by_source_severity', coalesce((
      select jsonb_agg(jsonb_build_object('source', source, 'severity', severity, 'findings', n)
        order by source, severity)
      from (select source, severity, count(*) as n from findings group by source, severity) grouped
    ), '[]'::jsonb),
    'cve', (
      select jsonb_build_object(
        'findings', count(*),
        'distinct_vulnerabilities', count(distinct vuln_id),
        'confirmed_applicable', count(*) filter (where applicability = 'confirmed'),
        'max_cvss', max(cvss),
        'by_severity', coalesce((
          select jsonb_object_agg(severity, n)
          from (select severity, count(*) as n from findings where finding_kind = 'cve' group by severity) s
        ), '{}'::jsonb)
      )
      from findings where finding_kind = 'cve'
    ),
    'mcp', (
      select jsonb_build_object(
        'findings', count(*),
        'distinct_servers', count(distinct coalesce(subject_digest, mcp_server_name)),
        'by_attestation', coalesce((
          select jsonb_object_agg(status, n) from (
            select coalesce(attestation_status, 'unknown') as status, count(*) as n
            from findings where source = 'mcp_inventory' group by 1
          ) s
        ), '{}'::jsonb),
        'by_transport', coalesce((
          select jsonb_object_agg(transport, n) from (
            select coalesce(mcp_transport, 'unknown') as transport, count(*) as n
            from findings where source = 'mcp_inventory' group by 1
          ) s
        ), '{}'::jsonb),
        'by_risk_category', coalesce((
          select jsonb_object_agg(category, n) from (
            select c.category, count(*) as n
            from findings f cross join lateral unnest(f.risk_categories) as c(category)
            where f.source = 'mcp_inventory'
            group by c.category
          ) s
        ), '{}'::jsonb)
      )
      from findings where source = 'mcp_inventory'
    ),
    'skills', (
      select jsonb_build_object(
        'findings', count(*),
        'by_risk_type', coalesce((
          select jsonb_object_agg(risk_type, n) from (
            select coalesce(skill_risk_type, 'unknown') as risk_type, count(*) as n
            from findings where source = 'skill_scan' group by 1
          ) s
        ), '{}'::jsonb)
      )
      from findings where source = 'skill_scan'
    )
  ) into v_posture;

  -- ── Retention and deletion evidence ─────────────────────────────────────
  select p.retention_days into v_telemetry_days
  from public.tenant_data_retention_policies p
  where p.tenant_id = p_tenant_id and p.data_class = 'telemetry';
  select min(e.created_at) into v_oldest from public.events e where e.tenant_id = p_tenant_id;

  select jsonb_build_object(
    'policies', coalesce((
      select jsonb_agg(jsonb_build_object(
        'data_class', p.data_class, 'retention_days', p.retention_days,
        'covers_backups', p.covers_backups, 'updated_at', p.updated_at
      ) order by p.data_class)
      from public.tenant_data_retention_policies p where p.tenant_id = p_tenant_id
    ), '[]'::jsonb),
    'telemetry', jsonb_build_object(
      'retention_days', v_telemetry_days,
      'oldest_event_at', v_oldest,
      'oldest_event_age_days', case when v_oldest is null then null
        else floor(extract(epoch from (now() - v_oldest)) / 86400)::integer end,
      'grace_days', 1,
      'within_policy', case
        when v_telemetry_days is null then null
        when v_oldest is null then true
        else v_oldest >= now() - make_interval(days => v_telemetry_days + 1) end
    ),
    'legal_holds', (
      select jsonb_build_object(
        'active', exists (select 1 from public.tenant_legal_holds h where h.tenant_id = p_tenant_id and h.released_at is null),
        'active_since', (select min(h.placed_at) from public.tenant_legal_holds h where h.tenant_id = p_tenant_id and h.released_at is null),
        'placed_in_period', (select count(*) from public.tenant_legal_holds h
          where h.tenant_id = p_tenant_id and h.placed_at >= p_from and h.placed_at < p_to),
        'released_in_period', (select count(*) from public.tenant_legal_holds h
          where h.tenant_id = p_tenant_id and h.released_at >= p_from and h.released_at < p_to)
      )
    ),
    'offboarding_runs', coalesce((
      select jsonb_agg(jsonb_build_object(
        'run_id', r.id, 'status', r.status, 'requested_at', r.requested_at,
        'completed_at', r.completed_at, 'backup_scope', r.backup_scope,
        'phases', (select count(*) from public.tenant_offboarding_phase_receipts x where x.run_id = r.id),
        'phases_completed', (select count(*) from public.tenant_offboarding_phase_receipts x
          where x.run_id = r.id and x.status = 'completed'),
        'rows_deleted', (select coalesce(sum(x.rows_deleted), 0) from public.tenant_offboarding_phase_receipts x
          where x.run_id = r.id)
      ) order by r.requested_at desc)
      from public.tenant_offboarding_runs r where r.tenant_id = p_tenant_id
    ), '[]'::jsonb),
    'audit_exports', (
      select jsonb_build_object(
        'created_in_period', count(*) filter (where o.created_at >= p_from and o.created_at < p_to),
        'stored_now', count(*),
        'expired_pending_cleanup', count(*) filter (where o.expires_at < now())
      )
      from public.audit_export_objects o where o.tenant_id = p_tenant_id
    )
  ) into v_retention;

  return jsonb_build_object(
    'generated_at', now(),
    'actor_role', v_role,
    'tenant_profile', v_tenant,
    'protection_coverage', v_coverage,
    'browser_guard', v_browser,
    'agent_decisions', v_agent,
    'policy_inventory', v_policies,
    'access_identity', v_access,
    'incidents', v_incidents,
    'ai_security_posture', v_posture,
    'retention_deletion', v_retention
  );
end;
$$;

revoke all on function public.compliance_report_evidence(uuid, uuid, timestamptz, timestamptz)
  from public, anon, authenticated;
grant execute on function public.compliance_report_evidence(uuid, uuid, timestamptz, timestamptz)
  to service_role;

-- Issuance receipt: who generated which report (id, period, digest, key id).
-- The admin audit log is append-only (app.reject_admin_audit_mutation), so a
-- later verifier can match a presented report's sha256 against this record.
create or replace function public.record_compliance_report(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_report_id uuid,
  p_from timestamptz,
  p_to timestamptz,
  p_sha256 text,
  p_signature_key_id text
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if p_tenant_id is null or p_actor_user_id is null or p_report_id is null
     or p_from is null or p_to is null or p_to <= p_from
     or p_sha256 is null or p_sha256 !~ '^[a-f0-9]{64}$'
     or (p_signature_key_id is not null and p_signature_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') then
    raise exception 'invalid_compliance_receipt' using errcode = '22023';
  end if;
  perform 1
  from public.tenant_members m
  join public.tenants t on t.id = m.tenant_id
  where m.tenant_id = p_tenant_id
    and m.user_id = p_actor_user_id
    and m.role in ('owner', 'admin')
    and (m.expires_at is null or m.expires_at > now())
    and t.status = 'active'
  for share of m, t;
  if not found then
    raise exception 'compliance_report_forbidden' using errcode = '42501';
  end if;
  insert into public.admin_audit_logs (actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, 'compliance_report.generated', jsonb_build_object(
    'report_id', p_report_id,
    'period_from', p_from,
    'period_to', p_to,
    'sha256', p_sha256,
    'signed', p_signature_key_id is not null,
    'signature_key_id', p_signature_key_id
  ));
end;
$$;

revoke all on function public.record_compliance_report(uuid, uuid, uuid, timestamptz, timestamptz, text, text)
  from public, anon, authenticated;
grant execute on function public.record_compliance_report(uuid, uuid, uuid, timestamptz, timestamptz, text, text)
  to service_role;
