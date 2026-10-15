-- Central SIEM forwarding: the control plane forwards incidents and decision
-- events to the customer's SIEM (syslog TCP/TLS/UDP, Splunk HEC, Elastic,
-- Microsoft Sentinel, signed generic webhook). Contract:
-- docs/contracts/siem-forwarding.md.
--
-- Destinations
--   A destination is configured from the dashboard (SIEM page) through the
--   `siem-destinations` Edge Function. Its connection settings (collector
--   address, tokens, API keys, client secrets, private CA) are a credential:
--   stored only as AES-256-GCM ciphertext produced by that function
--   (AIDR_NOTIFICATION_ENCRYPTION_KEYS keyring, associated data binds tenant,
--   destination and provider), never granted to a client and never returned
--   by any API. `target_hint` is a non-secret label.
--
-- Enqueue (transactional outbox, at-least-once)
--   An AFTER INSERT trigger on public.events writes one siem_deliveries row per
--   matching, enabled destination of an active tenant in the SAME transaction
--   as the telemetry row. The payload is an allow-listed projection of the
--   already-sanitised event (identifiers, enums, bounded counts, digests); raw
--   prompts, commands, paths or URLs are never stored in events and never
--   copied here. A forwarding fault never loses telemetry: the enqueue runs in
--   a subtransaction and reports a failure as a WARNING. A destination whose
--   receiver is down accumulates at most 50 000 pending rows; further events
--   are counted in `dropped_events` (visible on the dashboard) instead of
--   growing the database without bound.
--
-- Delivery
--   `siem-forwarder` (scheduled: Helm CronJob, Compose service, pg_cron) claims
--   due rows per destination under a lease (SKIP LOCKED), delivers them in
--   batches and records each outcome with exponential backoff. After
--   max_attempts a row becomes a dead letter: kept (visible and re-queueable
--   from the dashboard) until the tenant's operational_ephemera retention
--   (at most 7 days) expires, never while a legal hold is active.
--
-- Access model, offboarding: as for notification channels
--   (20260926000020): owners/admins read metadata through RLS with column
--   grants that exclude the ciphertext; every mutation goes through the
--   service-role RPCs below, which re-check the actor's live owner/admin
--   membership and the active tenant under row locks
--   (app.lock_notification_admin) and write the audit rows in the same
--   transaction. Destinations and deliveries are deleted the moment a tenant
--   starts offboarding.

create table if not exists public.siem_destinations (
  id uuid primary key,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  provider text not null check (provider in ('syslog', 'splunk_hec', 'elastic', 'sentinel', 'webhook')),
  format text not null default 'json' check (format in ('json', 'cef', 'leef')),
  name text not null check (length(btrim(name)) between 1 and 80 and name !~ '[[:cntrl:]]'),
  config_ciphertext text not null
    check (length(config_ciphertext) between 48 and 98304
      and config_ciphertext ~ '^v1\.[a-z0-9][a-z0-9_-]{0,31}\.[A-Za-z0-9_-]+$'),
  config_key_id text not null check (config_key_id ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
  target_hint text not null check (length(target_hint) between 1 and 160 and target_hint !~ '[[:cntrl:]]'),
  enabled boolean not null default true,
  forward_incidents boolean not null default true,
  forward_decisions text[] not null default array['deny', 'ask']::text[]
    check (forward_decisions <@ array['allow', 'ask', 'deny']::text[] and cardinality(forward_decisions) <= 3),
  forward_browser boolean not null default false,
  min_severity text not null default 'info' check (min_severity in ('info', 'warning', 'high', 'critical')),
  created_by uuid not null,
  updated_by uuid not null,
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp(),
  last_delivery_at timestamptz,
  last_delivery_status text check (last_delivery_status is null or last_delivery_status in ('delivered', 'retrying', 'dead')),
  last_error text check (last_error is null or last_error ~ '^[a-z][a-z0-9_]{0,63}$'),
  consecutive_failures integer not null default 0 check (consecutive_failures >= 0),
  dropped_events bigint not null default 0 check (dropped_events >= 0),
  constraint siem_destinations_tenant_id_unique unique (tenant_id, id),
  constraint siem_destinations_key_matches_ciphertext check (split_part(config_ciphertext, '.', 2) = config_key_id),
  -- CEF and LEEF are syslog payload formats (QRadar, ArcSight); HTTP providers carry JSON.
  constraint siem_destinations_format_provider check (format = 'json' or provider = 'syslog'),
  constraint siem_destinations_selects_an_event check (
    forward_incidents or cardinality(forward_decisions) > 0 or forward_browser
  )
);

create unique index if not exists siem_destinations_tenant_name_idx
  on public.siem_destinations (tenant_id, lower(btrim(name)));
create index if not exists siem_destinations_tenant_enabled_idx
  on public.siem_destinations (tenant_id) where enabled;

comment on table public.siem_destinations is
  'Tenant SIEM forwarding destinations. config_ciphertext is AES-256-GCM ciphertext from the siem-destinations function and is never granted to clients.';

create table if not exists public.siem_deliveries (
  id bigint generated always as identity primary key,
  tenant_id uuid not null,
  destination_id uuid not null,
  event_row_id bigint,
  kind text not null check (kind in ('incident', 'decision', 'browser', 'test')),
  -- Allow-listed projection only (app.siem_event_payload): identifiers, enums, counts.
  payload jsonb not null check (jsonb_typeof(payload) = 'object' and pg_column_size(payload) <= 4096),
  status text not null default 'pending' check (status in ('pending', 'delivering', 'delivered', 'dead')),
  attempts integer not null default 0 check (attempts between 0 and 50),
  max_attempts integer not null default 12 check (max_attempts between 1 and 20),
  next_attempt_at timestamptz not null default clock_timestamp(),
  lease_token uuid,
  lease_expires_at timestamptz,
  last_attempt_at timestamptz,
  last_error text check (last_error is null or last_error ~ '^[a-z][a-z0-9_]{0,63}$'),
  last_status_code integer check (last_status_code is null or last_status_code between 100 and 599),
  created_at timestamptz not null default clock_timestamp(),
  delivered_at timestamptz,
  dead_at timestamptz,
  constraint siem_deliveries_destination_fk foreign key (tenant_id, destination_id)
    references public.siem_destinations (tenant_id, id) on delete cascade,
  constraint siem_deliveries_event_unique unique (destination_id, event_row_id),
  constraint siem_deliveries_lease_state check (
    (status = 'delivering') = (lease_token is not null and lease_expires_at is not null)
  ),
  constraint siem_deliveries_test_shape check ((kind = 'test') = (event_row_id is null))
);

create index if not exists siem_deliveries_due_idx
  on public.siem_deliveries (destination_id, next_attempt_at, id) where status = 'pending';
create index if not exists siem_deliveries_lease_idx
  on public.siem_deliveries (lease_expires_at) where status = 'delivering';
create index if not exists siem_deliveries_backlog_idx
  on public.siem_deliveries (destination_id, id) where status in ('pending', 'delivering');
create index if not exists siem_deliveries_dead_idx
  on public.siem_deliveries (destination_id, dead_at desc) where status = 'dead';
create index if not exists siem_deliveries_terminal_idx
  on public.siem_deliveries (created_at) where status in ('delivered', 'dead');

comment on table public.siem_deliveries is
  'Transactional outbox for SIEM forwarding (at-least-once). Payloads are allow-listed projections of sanitised telemetry.';

-- ── Access ─────────────────────────────────────────────────────────────────
alter table public.siem_destinations enable row level security;
alter table public.siem_deliveries enable row level security;
revoke all on public.siem_destinations from public, anon, authenticated;
revoke all on public.siem_deliveries from public, anon, authenticated;
grant select (
  id, tenant_id, provider, format, name, target_hint, enabled, forward_incidents, forward_decisions,
  forward_browser, min_severity, created_by, updated_by, created_at, updated_at, last_delivery_at,
  last_delivery_status, last_error, consecutive_failures, dropped_events
) on public.siem_destinations to authenticated;
grant select (
  id, tenant_id, destination_id, event_row_id, kind, status, attempts, max_attempts, next_attempt_at,
  last_attempt_at, last_error, last_status_code, created_at, delivered_at, dead_at
) on public.siem_deliveries to authenticated;
grant select, insert, update, delete on public.siem_destinations to service_role;
grant select, insert, update, delete on public.siem_deliveries to service_role;

drop policy if exists siem_destinations_select_admin on public.siem_destinations;
create policy siem_destinations_select_admin on public.siem_destinations
  for select to authenticated using (app.is_tenant_member_with_role(tenant_id, 'admin'));
drop policy if exists siem_destinations_no_client_writes on public.siem_destinations;
create policy siem_destinations_no_client_writes on public.siem_destinations
  as restrictive for all to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin')) with check (false);
drop policy if exists tenant_identity_access_restrict on public.siem_destinations;
create policy tenant_identity_access_restrict on public.siem_destinations
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

drop policy if exists siem_deliveries_select_admin on public.siem_deliveries;
create policy siem_deliveries_select_admin on public.siem_deliveries
  for select to authenticated using (app.is_tenant_member_with_role(tenant_id, 'admin'));
drop policy if exists siem_deliveries_no_client_writes on public.siem_deliveries;
create policy siem_deliveries_no_client_writes on public.siem_deliveries
  as restrictive for all to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin')) with check (false);
drop policy if exists tenant_identity_access_restrict on public.siem_deliveries;
create policy tenant_identity_access_restrict on public.siem_deliveries
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Views and validation ──────────────────────────────────────────────────
create or replace function app.siem_destination_view(d public.siem_destinations)
returns jsonb
language sql
stable
set search_path = pg_catalog, public, pg_temp
as $$
  select jsonb_build_object(
    'id', d.id,
    'provider', d.provider,
    'format', d.format,
    'name', d.name,
    'target_hint', d.target_hint,
    'enabled', d.enabled,
    'filters', jsonb_build_object(
      'incidents', d.forward_incidents,
      'decisions', to_jsonb(d.forward_decisions),
      'browser', d.forward_browser,
      'min_severity', d.min_severity
    ),
    'created_by', d.created_by,
    'created_at', d.created_at,
    'updated_at', d.updated_at,
    'last_delivery_at', d.last_delivery_at,
    'last_delivery_status', d.last_delivery_status,
    'last_error', d.last_error,
    'consecutive_failures', d.consecutive_failures,
    'dropped_events', d.dropped_events,
    'pending', (select count(*) from (
      select 1 from public.siem_deliveries x
       where x.destination_id = d.id and x.status in ('pending', 'delivering') limit 50001) b),
    'dead', (select count(*) from (
      select 1 from public.siem_deliveries x
       where x.destination_id = d.id and x.status = 'dead' limit 50001) b)
  );
$$;
revoke all on function app.siem_destination_view(public.siem_destinations) from public, anon, authenticated;

-- Filters arrive as one complete object: incidents, decisions, browser, min_severity.
create or replace function app.siem_filters_valid(p_filters jsonb)
returns boolean
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select case
    when p_filters is null or jsonb_typeof(p_filters) <> 'object' then false
    when (select count(*) from jsonb_object_keys(p_filters)) <> 4
      or not (p_filters ?& array['incidents', 'decisions', 'browser', 'min_severity']) then false
    when jsonb_typeof(p_filters->'incidents') <> 'boolean'
      or jsonb_typeof(p_filters->'browser') <> 'boolean'
      or jsonb_typeof(p_filters->'decisions') <> 'array'
      or coalesce(p_filters->>'min_severity', '') not in ('info', 'warning', 'high', 'critical') then false
    when jsonb_array_length(p_filters->'decisions') > 3
      or exists (select 1 from jsonb_array_elements(p_filters->'decisions') e
                  where jsonb_typeof(e) <> 'string' or e #>> '{}' not in ('allow', 'ask', 'deny'))
      or (select count(distinct e #>> '{}') from jsonb_array_elements(p_filters->'decisions') e)
           <> jsonb_array_length(p_filters->'decisions') then false
    else (p_filters->>'incidents')::boolean or (p_filters->>'browser')::boolean
      or jsonb_array_length(p_filters->'decisions') > 0
  end;
$$;
revoke all on function app.siem_filters_valid(jsonb) from public, anon, authenticated;

create or replace function app.siem_filter_decisions(p_filters jsonb)
returns text[]
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select coalesce(array_agg(e order by e), array[]::text[])
    from jsonb_array_elements_text(p_filters->'decisions') e;
$$;
revoke all on function app.siem_filter_decisions(jsonb) from public, anon, authenticated;

-- ── Enqueue ────────────────────────────────────────────────────────────────
-- Allow-listed projection of a stored (already sanitised) event.
create or replace function app.siem_event_payload(p_event public.events, p_kind text)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  p jsonb := coalesce(p_event.payload, '{}'::jsonb);
  v_ident constant text := '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$';
  v_agent record;
  v_entities jsonb;
begin
  select a.iid, a.agent_runtime into v_agent from public.agents a where a.id = p_event.agent_id;
  select jsonb_object_agg(key, value) into v_entities
    from jsonb_each(case when jsonb_typeof(p->'entity_counts') = 'object' then p->'entity_counts' else '{}'::jsonb end)
   where key ~ '^[A-Z][A-Z_]{1,31}$' and jsonb_typeof(value) = 'number' and value::text ~ '^[0-9]{1,7}$';
  return jsonb_strip_nulls(jsonb_build_object(
    'event_row_id', p_event.id::text,
    'kind', p_kind,
    'type', p_event.type,
    'occurred_at', p_event.created_at,
    'client_timestamp', case when p->>'timestamp' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,15}Z$' then p->>'timestamp' end,
    'event_id', case when p->>'event_id' ~ v_ident then p->>'event_id' end,
    'agent_id', p_event.agent_id,
    'agent_iid', case when v_agent.iid ~ v_ident then v_agent.iid end,
    'connector', case when v_agent.agent_runtime ~ v_ident then v_agent.agent_runtime end,
    'decision', case when coalesce(p->>'verdict', p->>'decision') in ('allow', 'ask', 'deny')
      then coalesce(p->>'verdict', p->>'decision') end,
    'severity', case when p->>'severity' in ('info', 'warning', 'high', 'critical') then p->>'severity' end,
    'status', case when p->>'status' in ('open', 'acknowledged', 'contained', 'resolved', 'suppressed') then p->>'status' end,
    'threat_id', case when p->>'matched_threat_id' ~ v_ident then p->>'matched_threat_id' end,
    'incident_id', case when p->>'incident_id' ~ v_ident then p->>'incident_id' end,
    'session_id', case when p->>'session_id' ~ v_ident then p->>'session_id' end,
    'tool_name', case when p->>'tool_name' ~ v_ident then p->>'tool_name' end,
    'source', case when p->>'source' ~ v_ident then p->>'source' end,
    'plugin_key', case when p->>'plugin_key' ~ v_ident then p->>'plugin_key' end,
    'policy_id', case when p->>'policy_id' ~ v_ident then p->>'policy_id' end,
    'findings_count', case when jsonb_typeof(p->'findings_count') = 'number' and (p->>'findings_count') ~ '^[0-9]{1,7}$'
      then (p->>'findings_count')::integer end,
    'user_override', case when jsonb_typeof(p->'user_override') = 'boolean' then (p->>'user_override')::boolean end,
    'tool_input_digest', case when p->>'tool_input_summary' ~ '^sha256:[a-f0-9]{64}$' then p->>'tool_input_summary' end,
    'site', case when p->>'site' ~ '^[a-z0-9][a-z0-9-]{0,31}$' then p->>'site' end,
    'action', case when p->>'action' in ('masked', 'warned', 'blocked', 'allowed', 'visited') then p->>'action' end,
    'channel', case when p->>'channel' in ('prompt', 'paste', 'file') then p->>'channel' end,
    'service_id', case when p->>'service_id' ~ '^[a-z0-9][a-z0-9-]{0,31}$' then p->>'service_id' end,
    'count', case when jsonb_typeof(p->'count') = 'number' and (p->>'count') ~ '^[0-9]{1,6}$' then (p->>'count')::integer end,
    'entity_counts', case when v_entities is not null and v_entities <> '{}'::jsonb then v_entities end
  ));
end;
$$;
revoke all on function app.siem_event_payload(public.events, text) from public, anon, authenticated;

create or replace function app.enqueue_event_siem(p_event public.events)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  p jsonb := coalesce(p_event.payload, '{}'::jsonb);
  v_kind text;
  v_decision text;
  v_severity text;
  v_payload jsonb;
  v_destination record;
  v_queued integer := 0;
  v_rows integer;
begin
  if p_event.tenant_id is null then return 0; end if;
  -- The common case (no destinations) costs one index probe.
  if not exists (select 1 from public.siem_destinations d where d.tenant_id = p_event.tenant_id and d.enabled) then
    return 0;
  end if;
  if not exists (select 1 from public.tenants t where t.id = p_event.tenant_id and t.status = 'active') then
    return 0;
  end if;

  v_decision := coalesce(p->>'verdict', p->>'decision');
  v_severity := case when p->>'severity' in ('info', 'warning', 'high', 'critical') then p->>'severity' else 'info' end;
  if p_event.type in ('incident', 'incident_record') then
    v_kind := 'incident';
  elsif p_event.type = 'runtime_verdict' and v_decision in ('allow', 'ask', 'deny') then
    v_kind := 'decision';
  elsif (p_event.type = 'privacy_scan' and p->>'action' in ('blocked', 'warned'))
     or (p_event.type = 'shadow_ai_usage' and p->>'action' = 'blocked') then
    v_kind := 'browser';
  else
    return 0;
  end if;

  for v_destination in
    select d.id
      from public.siem_destinations d
     where d.tenant_id = p_event.tenant_id
       and d.enabled
       and case v_kind
         when 'incident' then d.forward_incidents
         when 'decision' then v_decision = any (d.forward_decisions)
         else d.forward_browser
       end
       and (v_kind = 'browser'
         or app.notification_severity_rank(v_severity) >= app.notification_severity_rank(d.min_severity))
     order by d.id
  loop
    -- Bounded backlog: a receiver that has been down for a long time must not
    -- grow the database without limit. Overflow is counted, never hidden.
    if exists (
      select 1 from public.siem_deliveries x
       where x.destination_id = v_destination.id and x.status in ('pending', 'delivering')
       order by x.id offset 49999 limit 1
    ) then
      update public.siem_destinations set dropped_events = dropped_events + 1 where id = v_destination.id;
      continue;
    end if;
    v_payload := coalesce(v_payload, app.siem_event_payload(p_event, v_kind));
    insert into public.siem_deliveries (tenant_id, destination_id, event_row_id, kind, payload)
    values (p_event.tenant_id, v_destination.id, p_event.id, v_kind, v_payload)
    on conflict (destination_id, event_row_id) do nothing;
    get diagnostics v_rows = row_count;
    v_queued := v_queued + v_rows;
  end loop;
  return v_queued;
end;
$$;
revoke all on function app.enqueue_event_siem(public.events) from public, anon, authenticated;

create or replace function app.enqueue_event_siem_trigger()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  begin
    perform app.enqueue_event_siem(new);
  exception when others then
    -- Telemetry is the record of truth; never lose it to a forwarding fault.
    raise warning 'siem_enqueue_failed' using detail = sqlstate;
  end;
  return new;
end;
$$;
revoke all on function app.enqueue_event_siem_trigger() from public, anon, authenticated;

drop trigger if exists events_enqueue_siem on public.events;
create trigger events_enqueue_siem
  after insert on public.events
  for each row
  when (new.type in ('incident', 'incident_record', 'runtime_verdict', 'privacy_scan', 'shadow_ai_usage'))
  execute function app.enqueue_event_siem_trigger();

-- ── Forwarder RPCs (service role only) ────────────────────────────────────
-- Claims up to p_per_destination due rows for each of at most p_destinations
-- destinations (oldest due work first, so one tenant's backlog cannot starve
-- another's), retiring first what can never be sent.
create or replace function public.claim_siem_deliveries(
  p_destinations integer,
  p_per_destination integer,
  p_lease_seconds integer,
  p_delivery_id bigint default null
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_result jsonb := '[]'::jsonb;
  v_destination record;
  v_rows jsonb;
begin
  if p_destinations is null or p_destinations not between 1 and 100
     or p_per_destination is null or p_per_destination not between 1 and 500
     or p_lease_seconds is null or p_lease_seconds not between 30 and 900 then
    raise exception 'invalid_siem_claim' using errcode = '22023';
  end if;

  with doomed as (
    select x.id,
      case
        when t.status <> 'active' then 'tenant_inactive'
        when not d.enabled and x.kind <> 'test' then 'destination_disabled'
        else 'lease_expired'
      end as reason
    from public.siem_deliveries x
    join public.siem_destinations d on d.id = x.destination_id
    join public.tenants t on t.id = x.tenant_id
    where (p_delivery_id is null or x.id = p_delivery_id)
      and (x.status = 'pending' or (x.status = 'delivering' and x.lease_expires_at <= clock_timestamp()))
      and (t.status <> 'active' or (not d.enabled and x.kind <> 'test') or x.attempts >= x.max_attempts)
    order by x.id
    limit 1000
    for update of x skip locked
  )
  update public.siem_deliveries x
     set status = 'dead', last_error = doomed.reason, lease_token = null, lease_expires_at = null,
         dead_at = clock_timestamp()
    from doomed
   where x.id = doomed.id;

  for v_destination in
    select d.id, d.tenant_id, d.provider, d.format, d.config_ciphertext
      from public.siem_destinations d
      join public.tenants t on t.id = d.tenant_id and t.status = 'active'
      join lateral (
        select min(x.next_attempt_at) as due
          from public.siem_deliveries x
         where x.destination_id = d.id
           and (p_delivery_id is null or x.id = p_delivery_id)
           and x.attempts < x.max_attempts
           and ((x.status = 'pending' and x.next_attempt_at <= clock_timestamp())
             or (x.status = 'delivering' and x.lease_expires_at <= clock_timestamp()))
      ) work on work.due is not null
     where d.enabled or p_delivery_id is not null
     order by work.due, d.id
     limit p_destinations
  loop
    with picked as (
      select x.id
        from public.siem_deliveries x
       where x.destination_id = v_destination.id
         and (p_delivery_id is null or x.id = p_delivery_id)
         and x.attempts < x.max_attempts
         and ((x.status = 'pending' and x.next_attempt_at <= clock_timestamp())
           or (x.status = 'delivering' and x.lease_expires_at <= clock_timestamp()))
       order by x.id
       limit p_per_destination
       for update of x skip locked
    ),
    claimed as (
      update public.siem_deliveries x
         set status = 'delivering',
             attempts = x.attempts + 1,
             lease_token = gen_random_uuid(),
             lease_expires_at = clock_timestamp() + make_interval(secs => p_lease_seconds),
             last_attempt_at = clock_timestamp()
        from picked
       where x.id = picked.id
      returning x.*
    )
    select coalesce(jsonb_agg(jsonb_build_object(
        'delivery_id', claimed.id::text,
        'lease_token', claimed.lease_token,
        'kind', claimed.kind,
        'payload', claimed.payload,
        'attempts', claimed.attempts,
        'max_attempts', claimed.max_attempts,
        'created_at', claimed.created_at
      ) order by claimed.id), '[]'::jsonb)
      into v_rows
      from claimed;
    if jsonb_array_length(v_rows) > 0 then
      v_result := v_result || jsonb_build_array(jsonb_build_object(
        'destination_id', v_destination.id,
        'tenant_id', v_destination.tenant_id,
        'provider', v_destination.provider,
        'format', v_destination.format,
        'config_ciphertext', v_destination.config_ciphertext,
        'deliveries', v_rows
      ));
    end if;
  end loop;
  return v_result;
end;
$$;
revoke all on function public.claim_siem_deliveries(integer, integer, integer, bigint) from public, anon, authenticated;
grant execute on function public.claim_siem_deliveries(integer, integer, integer, bigint) to service_role;

-- p_results: [{ "delivery_id": "<bigint>", "lease_token": uuid, "outcome": delivered|retry|failed,
--               "error": code|null, "status_code": int|null, "retry_in_seconds": int|null }]
create or replace function public.complete_siem_deliveries(p_results jsonb)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_item jsonb;
  v_delivery public.siem_deliveries;
  v_status text;
  v_error text;
  v_outcome text;
  v_status_code integer;
  v_counts jsonb := jsonb_build_object('delivered', 0, 'pending', 0, 'dead', 0, 'lease_lost', 0);
begin
  if p_results is null or jsonb_typeof(p_results) <> 'array' or jsonb_array_length(p_results) > 1000 then
    raise exception 'invalid_siem_outcome' using errcode = '22023';
  end if;
  for v_item in select value from jsonb_array_elements(p_results)
  loop
    v_outcome := v_item->>'outcome';
    v_error := v_item->>'error';
    if jsonb_typeof(v_item) <> 'object'
       or coalesce(v_item->>'delivery_id', '') !~ '^[0-9]{1,19}$'
       or coalesce(v_item->>'lease_token', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       or v_outcome is null or v_outcome not in ('delivered', 'retry', 'failed')
       or (v_error is not null and v_error !~ '^[a-z][a-z0-9_]{0,63}$')
       or (v_item->'status_code' is not null and jsonb_typeof(v_item->'status_code') not in ('number', 'null'))
       or (v_item->'retry_in_seconds' is not null and jsonb_typeof(v_item->'retry_in_seconds') not in ('number', 'null')) then
      raise exception 'invalid_siem_outcome' using errcode = '22023';
    end if;
    v_status_code := case when jsonb_typeof(v_item->'status_code') = 'number' then (v_item->>'status_code')::integer end;
    if v_status_code is not null and v_status_code not between 100 and 599 then
      raise exception 'invalid_siem_outcome' using errcode = '22023';
    end if;

    select * into v_delivery from public.siem_deliveries
     where id = (v_item->>'delivery_id')::bigint for update;
    if not found or v_delivery.status <> 'delivering'
       or v_delivery.lease_token is distinct from (v_item->>'lease_token')::uuid then
      v_counts := jsonb_set(v_counts, '{lease_lost}', to_jsonb((v_counts->>'lease_lost')::integer + 1));
      continue;
    end if;

    if v_outcome = 'delivered' then
      v_status := 'delivered';
      v_error := null;
    elsif v_outcome = 'retry' and v_delivery.attempts < v_delivery.max_attempts then
      v_status := 'pending';
      v_error := coalesce(v_error, 'delivery_failed');
    else
      v_status := 'dead';
      v_error := coalesce(v_error, 'delivery_failed');
    end if;

    update public.siem_deliveries set
      status = v_status,
      lease_token = null,
      lease_expires_at = null,
      last_error = v_error,
      last_status_code = v_status_code,
      delivered_at = case when v_status = 'delivered' then clock_timestamp() end,
      dead_at = case when v_status = 'dead' then clock_timestamp() end,
      next_attempt_at = case when v_status = 'pending'
        then clock_timestamp() + make_interval(secs => least(greatest(
          coalesce(case when jsonb_typeof(v_item->'retry_in_seconds') = 'number'
            then (v_item->>'retry_in_seconds')::numeric end, 60), 1), 86400)::integer)
        else next_attempt_at end
    where id = v_delivery.id;

    update public.siem_destinations set
      last_delivery_at = clock_timestamp(),
      last_delivery_status = case v_status when 'pending' then 'retrying' else v_status end,
      last_error = v_error,
      consecutive_failures = case when v_status = 'delivered' then 0 else consecutive_failures + 1 end
    where id = v_delivery.destination_id;

    v_counts := jsonb_set(v_counts, array[v_status], to_jsonb((v_counts->>v_status)::integer + 1));
  end loop;
  return v_counts;
end;
$$;
revoke all on function public.complete_siem_deliveries(jsonb) from public, anon, authenticated;
grant execute on function public.complete_siem_deliveries(jsonb) to service_role;

-- Delivered rows and dead letters are operational ephemera: removed after the
-- tenant's operational_ephemera retention (7 days when no policy row exists),
-- never while a legal hold is active.
create or replace function public.prune_siem_deliveries(p_limit integer)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare v_deleted integer;
begin
  if p_limit is null or p_limit not between 1 and 10000 then
    raise exception 'invalid_siem_prune' using errcode = '22023';
  end if;
  with doomed as (
    select x.id
    from public.siem_deliveries x
    left join public.tenant_data_retention_policies p
      on p.tenant_id = x.tenant_id and p.data_class = 'operational_ephemera'
    where x.status in ('delivered', 'dead')
      and x.created_at < clock_timestamp() - make_interval(days => least(coalesce(p.retention_days, 7), 7))
      and not exists (
        select 1 from public.tenant_legal_holds h
         where h.tenant_id = x.tenant_id and h.released_at is null
      )
    order by x.created_at
    limit p_limit
    for update of x skip locked
  )
  delete from public.siem_deliveries x using doomed where x.id = doomed.id;
  get diagnostics v_deleted = row_count;
  return jsonb_build_object('deleted', v_deleted);
end;
$$;
revoke all on function public.prune_siem_deliveries(integer) from public, anon, authenticated;
grant execute on function public.prune_siem_deliveries(integer) to service_role;

-- ── Management RPCs (service role; called by the siem-destinations function) ─
create or replace function public.list_siem_destinations(p_tenant_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if p_tenant_id is null then
    raise exception 'invalid_siem_destination' using errcode = '22023';
  end if;
  return jsonb_build_object(
    'destinations', coalesce((
      select jsonb_agg(app.siem_destination_view(d) order by d.created_at, d.id)
        from public.siem_destinations d where d.tenant_id = p_tenant_id
    ), '[]'::jsonb),
    'dead_letters', coalesce((
      select jsonb_agg(jsonb_build_object(
          'id', x.id::text,
          'destination_id', x.destination_id,
          'kind', x.kind,
          'type', x.payload->>'type',
          'decision', x.payload->>'decision',
          'severity', x.payload->>'severity',
          'attempts', x.attempts,
          'last_error', x.last_error,
          'last_status_code', x.last_status_code,
          'created_at', x.created_at,
          'dead_at', x.dead_at
        ) order by x.dead_at desc, x.id desc)
        from (
          select * from public.siem_deliveries
           where tenant_id = p_tenant_id and status = 'dead'
           order by dead_at desc, id desc
           limit 50
        ) x
    ), '[]'::jsonb)
  );
end;
$$;
revoke all on function public.list_siem_destinations(uuid) from public, anon, authenticated;
grant execute on function public.list_siem_destinations(uuid) to service_role;

create or replace function public.create_siem_destination(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_destination_id uuid,
  p_provider text,
  p_format text,
  p_name text,
  p_config_ciphertext text,
  p_config_key_id text,
  p_target_hint text,
  p_filters jsonb,
  p_enabled boolean
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare v_destination public.siem_destinations;
begin
  if p_destination_id is null or p_provider is null or p_format is null or p_name is null
     or p_config_ciphertext is null or p_config_key_id is null or p_target_hint is null
     or p_enabled is null or not app.siem_filters_valid(p_filters) then
    raise exception 'invalid_siem_destination' using errcode = '22023';
  end if;
  perform app.lock_notification_admin(p_tenant_id, p_actor_user_id);
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2627));
  if (select count(*) from public.siem_destinations where tenant_id = p_tenant_id) >= 10 then
    raise exception 'siem_destination_limit' using errcode = '54000';
  end if;
  insert into public.siem_destinations (
    id, tenant_id, provider, format, name, config_ciphertext, config_key_id, target_hint, enabled,
    forward_incidents, forward_decisions, forward_browser, min_severity, created_by, updated_by
  ) values (
    p_destination_id, p_tenant_id, p_provider, p_format, btrim(p_name), p_config_ciphertext,
    p_config_key_id, p_target_hint, p_enabled,
    (p_filters->>'incidents')::boolean, app.siem_filter_decisions(p_filters),
    (p_filters->>'browser')::boolean, p_filters->>'min_severity', p_actor_user_id, p_actor_user_id
  )
  returning * into v_destination;
  perform app.audit_notification_channel(p_tenant_id, p_actor_user_id, 'siem_destination.created',
    jsonb_build_object('destination_id', v_destination.id, 'provider', v_destination.provider,
      'format', v_destination.format, 'enabled', v_destination.enabled,
      'filters', app.siem_destination_view(v_destination)->'filters'));
  return app.siem_destination_view(v_destination);
end;
$$;
revoke all on function public.create_siem_destination(uuid, uuid, uuid, text, text, text, text, text, text, jsonb, boolean)
  from public, anon, authenticated;
grant execute on function public.create_siem_destination(uuid, uuid, uuid, text, text, text, text, text, text, jsonb, boolean)
  to service_role;

-- NULL arguments mean "unchanged". The provider is fixed: the ciphertext's
-- associated data binds it.
create or replace function public.update_siem_destination(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_destination_id uuid,
  p_expected_provider text,
  p_name text,
  p_enabled boolean,
  p_format text,
  p_filters jsonb,
  p_config_ciphertext text,
  p_config_key_id text,
  p_target_hint text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_before public.siem_destinations;
  v_after public.siem_destinations;
  v_changed text[] := array[]::text[];
begin
  if p_destination_id is null or p_expected_provider is null
     or (p_filters is not null and not app.siem_filters_valid(p_filters))
     or ((p_config_ciphertext is null) <> (p_config_key_id is null))
     or ((p_config_ciphertext is null) <> (p_target_hint is null)) then
    raise exception 'invalid_siem_destination' using errcode = '22023';
  end if;
  perform app.lock_notification_admin(p_tenant_id, p_actor_user_id);
  select * into v_before from public.siem_destinations
   where id = p_destination_id and tenant_id = p_tenant_id for update;
  if not found then
    raise exception 'siem_destination_not_found' using errcode = 'P0002';
  end if;
  if v_before.provider <> p_expected_provider then
    raise exception 'siem_destination_provider_mismatch' using errcode = '22023';
  end if;

  update public.siem_destinations d set
    name = coalesce(btrim(p_name), d.name),
    enabled = coalesce(p_enabled, d.enabled),
    format = coalesce(p_format, d.format),
    forward_incidents = coalesce((p_filters->>'incidents')::boolean, d.forward_incidents),
    forward_decisions = case when p_filters is null then d.forward_decisions else app.siem_filter_decisions(p_filters) end,
    forward_browser = coalesce((p_filters->>'browser')::boolean, d.forward_browser),
    min_severity = coalesce(p_filters->>'min_severity', d.min_severity),
    config_ciphertext = coalesce(p_config_ciphertext, d.config_ciphertext),
    config_key_id = coalesce(p_config_key_id, d.config_key_id),
    target_hint = coalesce(p_target_hint, d.target_hint),
    consecutive_failures = case when p_config_ciphertext is null then d.consecutive_failures else 0 end,
    last_error = case when p_config_ciphertext is null then d.last_error else null end,
    updated_by = p_actor_user_id,
    updated_at = clock_timestamp()
  where d.id = p_destination_id
  returning * into v_after;

  if v_after.name is distinct from v_before.name then v_changed := array_append(v_changed, 'name'); end if;
  if v_after.enabled is distinct from v_before.enabled then v_changed := array_append(v_changed, 'enabled'); end if;
  if v_after.format is distinct from v_before.format then v_changed := array_append(v_changed, 'format'); end if;
  if app.siem_destination_view(v_after)->'filters' is distinct from app.siem_destination_view(v_before)->'filters' then
    v_changed := array_append(v_changed, 'filters');
  end if;
  if p_config_ciphertext is not null then v_changed := array_append(v_changed, 'config'); end if;

  -- A replaced collector keeps its backlog (at-least-once to the new address);
  -- disabling a destination stops delivery: its queued rows become dead letters
  -- that can be re-queued after it is enabled again.
  if 'enabled' = any(v_changed) and not v_after.enabled then
    update public.siem_deliveries
       set status = 'dead', last_error = 'destination_disabled', lease_token = null, lease_expires_at = null,
           dead_at = clock_timestamp()
     where destination_id = p_destination_id and status = 'pending';
  end if;

  if cardinality(v_changed) > 0 then
    perform app.audit_notification_channel(p_tenant_id, p_actor_user_id, 'siem_destination.updated',
      jsonb_build_object('destination_id', p_destination_id, 'provider', v_after.provider,
        'changed', to_jsonb(v_changed), 'enabled', v_after.enabled, 'format', v_after.format,
        'config_replaced', 'config' = any(v_changed),
        'filters', app.siem_destination_view(v_after)->'filters'));
  end if;
  return app.siem_destination_view(v_after) || jsonb_build_object('changed', to_jsonb(v_changed));
end;
$$;
revoke all on function public.update_siem_destination(uuid, uuid, uuid, text, text, boolean, text, jsonb, text, text, text)
  from public, anon, authenticated;
grant execute on function public.update_siem_destination(uuid, uuid, uuid, text, text, boolean, text, jsonb, text, text, text)
  to service_role;

create or replace function public.delete_siem_destination(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_destination_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare v_provider text;
begin
  if p_destination_id is null then
    raise exception 'invalid_siem_destination' using errcode = '22023';
  end if;
  perform app.lock_notification_admin(p_tenant_id, p_actor_user_id);
  delete from public.siem_destinations
   where id = p_destination_id and tenant_id = p_tenant_id
  returning provider into v_provider;
  if v_provider is null then
    raise exception 'siem_destination_not_found' using errcode = 'P0002';
  end if;
  perform app.audit_notification_channel(p_tenant_id, p_actor_user_id, 'siem_destination.deleted',
    jsonb_build_object('destination_id', p_destination_id, 'provider', v_provider));
  return jsonb_build_object('id', p_destination_id, 'deleted', true);
end;
$$;
revoke all on function public.delete_siem_destination(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.delete_siem_destination(uuid, uuid, uuid) to service_role;

-- A test send is an ordinary outbox row with a fixed, content-free payload and
-- a single attempt, so the dashboard reports the collector's real answer.
create or replace function public.enqueue_siem_test(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_destination_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_provider text;
  v_id bigint;
begin
  if p_destination_id is null then
    raise exception 'invalid_siem_destination' using errcode = '22023';
  end if;
  perform app.lock_notification_admin(p_tenant_id, p_actor_user_id);
  select provider into v_provider from public.siem_destinations
   where id = p_destination_id and tenant_id = p_tenant_id for share;
  if v_provider is null then
    raise exception 'siem_destination_not_found' using errcode = 'P0002';
  end if;
  insert into public.siem_deliveries (tenant_id, destination_id, event_row_id, kind, payload, max_attempts)
  values (p_tenant_id, p_destination_id, null, 'test',
    jsonb_build_object('kind', 'test', 'type', 'siem_test', 'occurred_at', clock_timestamp(), 'severity', 'info'), 1)
  returning id into v_id;
  perform app.audit_notification_channel(p_tenant_id, p_actor_user_id, 'siem_destination.test_sent',
    jsonb_build_object('destination_id', p_destination_id, 'provider', v_provider, 'delivery_id', v_id::text));
  return jsonb_build_object('delivery_id', v_id::text, 'destination_id', p_destination_id);
end;
$$;
revoke all on function public.enqueue_siem_test(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.enqueue_siem_test(uuid, uuid, uuid) to service_role;

-- Dead letters back into the queue (operator action after fixing a collector).
create or replace function public.requeue_siem_dead_letters(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_destination_id uuid,
  p_limit integer
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare v_count integer;
begin
  if p_destination_id is null or p_limit is null or p_limit not between 1 and 50000 then
    raise exception 'invalid_siem_destination' using errcode = '22023';
  end if;
  perform app.lock_notification_admin(p_tenant_id, p_actor_user_id);
  perform 1 from public.siem_destinations
   where id = p_destination_id and tenant_id = p_tenant_id and enabled for share;
  if not found then
    raise exception 'siem_destination_not_found' using errcode = 'P0002';
  end if;
  with picked as (
    select x.id from public.siem_deliveries x
     where x.destination_id = p_destination_id and x.status = 'dead' and x.kind <> 'test'
     order by x.id
     limit p_limit
     for update skip locked
  )
  update public.siem_deliveries x
     set status = 'pending', attempts = 0, next_attempt_at = clock_timestamp(),
         last_error = null, last_status_code = null, dead_at = null
    from picked
   where x.id = picked.id;
  get diagnostics v_count = row_count;
  perform app.audit_notification_channel(p_tenant_id, p_actor_user_id, 'siem_destination.dead_letters_requeued',
    jsonb_build_object('destination_id', p_destination_id, 'requeued', v_count));
  return jsonb_build_object('requeued', v_count);
end;
$$;
revoke all on function public.requeue_siem_dead_letters(uuid, uuid, uuid, integer) from public, anon, authenticated;
grant execute on function public.requeue_siem_dead_letters(uuid, uuid, uuid, integer) to service_role;

-- ── Offboarding ────────────────────────────────────────────────────────────
create or replace function app.purge_siem_destinations_on_offboarding()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  delete from public.siem_destinations where tenant_id = new.id;
  return new;
end;
$$;
revoke all on function app.purge_siem_destinations_on_offboarding() from public, anon, authenticated;

drop trigger if exists tenants_purge_siem_destinations on public.tenants;
create trigger tenants_purge_siem_destinations
  after update of status on public.tenants
  for each row
  when (new.status in ('closing', 'closed') and old.status is distinct from new.status)
  execute function app.purge_siem_destinations_on_offboarding();

create or replace function app.assert_no_siem_offboarding_residue()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if new.status <> 'completed' then return new; end if;
  if exists (select 1 from public.siem_destinations where tenant_id = new.tenant_id)
     or exists (select 1 from public.siem_deliveries where tenant_id = new.tenant_id) then
    raise exception 'siem_offboarding_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_no_siem_offboarding_residue() from public, anon, authenticated;

drop trigger if exists offboarding_runs_siem_residue on public.tenant_offboarding_runs;
create trigger offboarding_runs_siem_residue
  before update of status on public.tenant_offboarding_runs
  for each row execute function app.assert_no_siem_offboarding_residue();

create or replace function app.siem_destination_tenant_active()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if not exists (select 1 from public.tenants t where t.id = new.tenant_id and t.status = 'active') then
    raise exception 'workspace_not_active' using errcode = '55000';
  end if;
  if tg_op = 'UPDATE' and new.tenant_id is distinct from old.tenant_id then
    raise exception 'siem_destination_tenant_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.siem_destination_tenant_active() from public, anon, authenticated;

drop trigger if exists siem_destinations_tenant_active on public.siem_destinations;
create trigger siem_destinations_tenant_active
  before insert or update of tenant_id on public.siem_destinations
  for each row execute function app.siem_destination_tenant_active();
