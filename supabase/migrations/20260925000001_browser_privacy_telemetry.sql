-- Browser Guard privacy telemetry (docs/contracts/privacy-telemetry.md).
--
-- Storage: privacy scans are ordinary telemetry rows in public.events with
-- type = 'privacy_scan'. The ingest projection (supabase/functions/ingest/
-- events.ts) stores counts, enums and an optional policy identifier only.
-- Keeping them in public.events means the existing controls apply unchanged:
--   * tenant_events_select / tenant_active_member_restrict RLS (members read,
--     no client writes; inserts come from the service-role ingest function),
--   * app.enforce_event_seat_admission (a browser install is a protected seat),
--   * prune_expired_telemetry_events (the tenant 'telemetry' retention class),
--   * the tenant offboarding 'events' phase.
-- No new table is created, so no retention or offboarding list changes.

-- Dashboard reads filter one tenant's privacy scans by time.
create index if not exists events_privacy_scan_tenant_created_idx
  on public.events (tenant_id, created_at desc)
  where type = 'privacy_scan';

-- Browser installs are agents registered with the browser_guard runtime.
create index if not exists agents_tenant_runtime_last_seen_idx
  on public.agents (tenant_id, agent_runtime, last_seen desc);

-- Aggregates for the dashboard's Browser Privacy Guard page. SECURITY INVOKER
-- keeps every events/agents RLS policy (membership, identity and MFA) in force;
-- the explicit membership check only turns an empty result into a clear error.
create or replace function public.privacy_guard_summary(
  p_tenant_id uuid,
  p_days integer default 30
)
returns jsonb
language plpgsql
stable
security invoker
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_first date;
  v_since timestamptz;
  v_result jsonb;
begin
  if p_tenant_id is null or p_days is null or p_days not in (7, 30) then
    raise exception 'invalid_privacy_summary_window' using errcode = '22023';
  end if;
  if not app.is_tenant_member(p_tenant_id) then
    raise exception 'tenant_forbidden' using errcode = '42501';
  end if;

  -- Whole UTC days, so the totals and the daily series cover the same rows.
  v_first := (now() at time zone 'utc')::date - (p_days - 1);
  v_since := v_first::timestamp at time zone 'utc';

  with scans as materialized (
    select
      e.created_at,
      e.payload->>'action' as action,
      coalesce(nullif(e.payload->>'site', ''), 'other') as site,
      case when jsonb_typeof(e.payload->'findings_count') = 'number'
        then (e.payload->'findings_count')::bigint end as findings,
      case when jsonb_typeof(e.payload->'entity_counts') = 'object'
        then e.payload->'entity_counts' else '{}'::jsonb end as entity_counts
    from public.events e
    where e.tenant_id = p_tenant_id
      and e.type = 'privacy_scan'
      and e.created_at >= v_since
  ),
  entity_rows as (
    select s.action, c.key as entity_type, (c.value)::bigint as items
    from scans s
    cross join lateral jsonb_each(s.entity_counts) c
    where jsonb_typeof(c.value) = 'number'
  ),
  scan_items as (
    -- findings_count is authoritative; fall back to the per-type sum.
    select s.*, coalesce(s.findings, (
      select sum((c.value)::bigint) from jsonb_each(s.entity_counts) c
      where jsonb_typeof(c.value) = 'number'
    ), 0) as items
    from scans s
  ),
  days as (
    select d::date as day
    from generate_series(v_first::timestamp, (v_first + (p_days - 1))::timestamp, interval '1 day') d
  )
  select jsonb_build_object(
    'window_days', p_days,
    'since', v_since,
    'totals', (
      select jsonb_build_object(
        'scans', count(*),
        'prompts_protected', count(*) filter (where action in ('masked', 'warned', 'blocked')),
        'items_masked', coalesce(sum(items) filter (where action = 'masked'), 0),
        'blocked_sends', count(*) filter (where action = 'blocked'),
        'warned_sends', count(*) filter (where action = 'warned'),
        'allowed_sends', count(*) filter (where action = 'allowed')
      )
      from scan_items
    ),
    'browser_installs', (
      select jsonb_build_object(
        'enrolled', count(*),
        'active', count(*) filter (where a.last_seen >= v_since)
      )
      from public.agents a
      where a.tenant_id = p_tenant_id and a.agent_runtime = 'browser_guard'
    ),
    'by_entity', coalesce((
      select jsonb_agg(jsonb_build_object('entity_type', entity_type, 'items', items)
        order by items desc, entity_type)
      from (
        select entity_type, sum(items) as items from entity_rows group by entity_type
      ) grouped
    ), '[]'::jsonb),
    'by_site', coalesce((
      select jsonb_agg(jsonb_build_object(
        'site', site, 'scans', scans, 'items', items, 'blocked', blocked)
        order by scans desc, site)
      from (
        select site, count(*) as scans, sum(items) as items,
          count(*) filter (where action = 'blocked') as blocked
        from scan_items group by site
      ) grouped
    ), '[]'::jsonb),
    'series', (
      select jsonb_agg(jsonb_build_object(
        'day', to_char(d.day, 'YYYY-MM-DD'),
        'scans', coalesce(x.scans, 0),
        'masked', coalesce(x.masked, 0),
        'warned', coalesce(x.warned, 0),
        'blocked', coalesce(x.blocked, 0)
      ) order by d.day)
      from days d
      left join (
        select (created_at at time zone 'utc')::date as day,
          count(*) as scans,
          count(*) filter (where action = 'masked') as masked,
          count(*) filter (where action = 'warned') as warned,
          count(*) filter (where action = 'blocked') as blocked
        from scans group by 1
      ) x on x.day = d.day
    )
  ) into v_result;
  return v_result;
end;
$$;

revoke all on function public.privacy_guard_summary(uuid, integer) from public, anon;
grant execute on function public.privacy_guard_summary(uuid, integer) to authenticated, service_role;
