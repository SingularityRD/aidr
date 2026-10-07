-- Browser Guard Shadow AI usage (docs/contracts/privacy-telemetry.md).
--
-- Storage: aggregated visit/block counts per catalogued AI service are ordinary
-- telemetry rows in public.events with type = 'shadow_ai_usage'. The ingest
-- projection (supabase/functions/ingest/events.ts) stores a catalog service id
-- (or 'other'), its category, visited|blocked, a bounded count, the sanctioned
-- flag and an optional policy identifier: never a URL, host, path or title.
-- Keeping them in public.events means the existing controls apply unchanged
-- (tenant_events_select RLS, no client writes, seat admission on insert,
-- prune_expired_telemetry_events retention, the offboarding 'events' phase), so
-- no table, retention class or offboarding phase is added.

-- Dashboard reads filter one tenant's Shadow AI rows by time.
create index if not exists events_shadow_ai_usage_tenant_created_idx
  on public.events (tenant_id, created_at desc)
  where type = 'shadow_ai_usage';

-- Aggregates for the "Shadow AI" panel of the Browser Privacy Guard page.
-- SECURITY INVOKER keeps every events RLS policy (membership, identity, MFA) in
-- force; the explicit membership check only turns an empty result into a clear
-- error.
create or replace function public.shadow_ai_summary(
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
    raise exception 'invalid_shadow_ai_summary_window' using errcode = '22023';
  end if;
  if not app.is_tenant_member(p_tenant_id) then
    raise exception 'tenant_forbidden' using errcode = '42501';
  end if;

  -- Whole UTC days, so the totals and the daily series cover the same rows.
  v_first := (now() at time zone 'utc')::date - (p_days - 1);
  v_since := v_first::timestamp at time zone 'utc';

  with usage as materialized (
    select
      e.created_at,
      coalesce(nullif(e.payload->>'service_id', ''), 'other') as service_id,
      coalesce(nullif(e.payload->>'category', ''), 'other') as category,
      e.payload->>'action' as action,
      coalesce(e.payload->'sanctioned' = 'true'::jsonb, false) as sanctioned,
      case when jsonb_typeof(e.payload->'count') = 'number'
        then least(greatest((e.payload->'count')::numeric, 0), 100000)::bigint else 0 end as n
    from public.events e
    where e.tenant_id = p_tenant_id
      and e.type = 'shadow_ai_usage'
      and e.created_at >= v_since
      and e.payload->>'action' in ('visited', 'blocked')
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
        'visits', coalesce(sum(n) filter (where action = 'visited'), 0),
        'blocked_attempts', coalesce(sum(n) filter (where action = 'blocked'), 0),
        'sanctioned_visits', coalesce(sum(n) filter (where action = 'visited' and sanctioned), 0),
        'unsanctioned_visits', coalesce(sum(n) filter (where action = 'visited' and not sanctioned), 0),
        'services', count(distinct service_id)
      )
      from usage
    ),
    'by_service', coalesce((
      select jsonb_agg(jsonb_build_object(
        'service_id', service_id, 'category', category, 'visits', visits,
        'blocked', blocked, 'sanctioned', sanctioned)
        order by visits + blocked desc, service_id)
      from (
        select service_id,
          min(category) as category,
          coalesce(sum(n) filter (where action = 'visited'), 0) as visits,
          coalesce(sum(n) filter (where action = 'blocked'), 0) as blocked,
          -- Sanctioned when the latest report for the service says so.
          (array_agg(sanctioned order by created_at desc))[1] as sanctioned
        from usage group by service_id
        order by sum(n) desc, service_id
        limit 50
      ) grouped
    ), '[]'::jsonb),
    'by_category', coalesce((
      select jsonb_agg(jsonb_build_object('category', category, 'visits', visits, 'blocked', blocked)
        order by visits + blocked desc, category)
      from (
        select category,
          coalesce(sum(n) filter (where action = 'visited'), 0) as visits,
          coalesce(sum(n) filter (where action = 'blocked'), 0) as blocked
        from usage group by category
      ) grouped
    ), '[]'::jsonb),
    'series', (
      select jsonb_agg(jsonb_build_object(
        'day', to_char(d.day, 'YYYY-MM-DD'),
        'visits', coalesce(x.visits, 0),
        'unsanctioned_visits', coalesce(x.unsanctioned, 0),
        'blocked', coalesce(x.blocked, 0)
      ) order by d.day)
      from days d
      left join (
        select (created_at at time zone 'utc')::date as day,
          sum(n) filter (where action = 'visited') as visits,
          sum(n) filter (where action = 'visited' and not sanctioned) as unsanctioned,
          sum(n) filter (where action = 'blocked') as blocked
        from usage group by 1
      ) x on x.day = d.day
    )
  ) into v_result;
  return v_result;
end;
$$;

revoke all on function public.shadow_ai_summary(uuid, integer) from public, anon;
grant execute on function public.shadow_ai_summary(uuid, integer) to authenticated, service_role;
