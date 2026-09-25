-- Alert outbox: bound the privacy-spike count to the rows it counts.
--
-- app.enqueue_event_notifications (20260926000021) counts a tenant's blocked
-- Browser Guard sends inside a channel's window on EVERY blocked privacy_scan
-- insert, until the channel's threshold is met. The only index it could use was
-- events (tenant_id, created_at), so each count visited every event of every
-- type the tenant stored in the window (up to 24 hours) and filtered them. A
-- holder of any ingest credential for the tenant, including the Browser Guard
-- ingest key that any user of a managed browser profile can read, could make
-- each cheap event cost a full-window scan: 200 blocked events against 400k
-- ordinary events took ~8.5 s instead of ~8 ms on PostgreSQL 16.
--
-- A partial index over exactly the rows the count selects makes each count
-- touch at most `privacy_spike_threshold` index entries. The predicate repeats
-- the function's filter literally so the planner can prove it applies.
--
-- Deployment note: the index is built inside the migration transaction and
-- therefore blocks writes to public.events while it scans the table once. On a
-- large production table, create it first out of band with
--   create index concurrently if not exists events_privacy_blocked_tenant_created_idx
--     on public.events (tenant_id, created_at)
--     where type = 'privacy_scan' and (payload ->> 'action') = 'blocked';
-- and this migration becomes a no-op.

create index if not exists events_privacy_blocked_tenant_created_idx
  on public.events (tenant_id, created_at)
  where type = 'privacy_scan' and (payload ->> 'action') = 'blocked';

comment on index public.events_privacy_blocked_tenant_created_idx is
  'Bounds app.enqueue_event_notifications privacy-spike counts to blocked Browser Guard sends (20260928000021).';
