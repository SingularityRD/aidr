-- Control plane API v1: entitlement snapshots + derived views for the dashboard.
--
-- Adds:
-- - public.entitlement_snapshots (per-user/per-iid last-seen entitlement)
-- - public.seat_usage view (entitlements + current agent count)
-- - public.incident_events view (incident-like event filter)

create extension if not exists pgcrypto;

-- ── Entitlement snapshots (service role writes; users can read their own) ─────

create table if not exists public.entitlement_snapshots (
  user_id uuid not null references auth.users (id) on delete cascade,
  iid text not null,
  agent_id uuid references public.agents (id) on delete cascade,
  entitlement jsonb not null,
  sig_alg text,
  sig_key_id text,
  sig_b64 text,
  issued_at timestamptz,
  expires_at timestamptz,
  grace_until timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (user_id, iid)
);

drop trigger if exists entitlement_snapshots_touch_updated_at on public.entitlement_snapshots;
create trigger entitlement_snapshots_touch_updated_at
before update on public.entitlement_snapshots
for each row execute procedure public.touch_updated_at();

alter table public.entitlement_snapshots enable row level security;

drop policy if exists entitlement_snapshots_select_own on public.entitlement_snapshots;
create policy entitlement_snapshots_select_own
on public.entitlement_snapshots for select
using (user_id = auth.uid());

-- ── Derived views (security_invoker so RLS applies to the querying user) ──────

create or replace view public.seat_usage
with (security_invoker = true)
as
select
  e.user_id,
  e.included_agents,
  e.extra_agents,
  (e.included_agents + e.extra_agents) as allowed_agents,
  (
    select count(*)::int
    from public.agents a
    where a.user_id = e.user_id
  ) as current_agents
from public.entitlements e;

create or replace view public.incident_events
with (security_invoker = true)
as
select
  ev.id,
  ev.user_id,
  ev.agent_id,
  ev.type,
  ev.created_at,
  ev.payload
from public.events ev
where
  ev.type = 'incident'
  or (
    ev.type = 'runtime_verdict'
    and (ev.payload->>'verdict') in ('deny', 'ask')
  )
  or (
    ev.type = 'plugin_scan'
    and coalesce(nullif(ev.payload->>'findings_count','')::int, 0) > 0
  );

-- PostgREST needs explicit grants for views in many setups.
grant select on public.seat_usage to authenticated;
grant select on public.incident_events to authenticated;

