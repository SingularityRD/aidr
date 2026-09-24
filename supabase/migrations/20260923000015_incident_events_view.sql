-- Include correlated incident records in the dashboard's incident feed.
-- security_invoker keeps the events table's tenant, membership and MFA RLS.
create or replace view public.incident_events
with (security_invoker = true)
as
select
  ev.id,
  ev.user_id,
  ev.agent_id,
  ev.type,
  ev.created_at,
  ev.payload,
  ev.tenant_id
from public.events ev
where
  ev.type in ('incident', 'incident_record')
  or (
    ev.type = 'runtime_verdict'
    and (ev.payload->>'verdict') in ('deny', 'ask')
  )
  or (
    ev.type = 'plugin_scan'
    and coalesce(nullif(ev.payload->>'findings_count','')::int, 0) > 0
  );
