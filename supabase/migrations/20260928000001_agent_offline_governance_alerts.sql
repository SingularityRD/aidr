-- Alert channels: agent offline/recovery, governance events and the governance
-- digest (docs/contracts/notifications.md).
--
-- Everything here rides on the existing tenant alert outbox
-- (20260926000020_notification_channels.sql, 20260926000021_notification_outbox.sql):
-- the same channels, the same encrypted destinations, the same
-- notification_deliveries rows, dispatcher, retries, flood cap, retention and
-- offboarding purge. No new scheduler is introduced.
--
-- New channel filters (all off by default, configurable per channel)
--   agent_offline                  an enrolled agent (public.agents row) has not
--                                  been seen for `agent_offline_minutes`
--                                  (5 minutes to 7 days). One alert per agent per
--                                  outage, and one `agent.recovered` notice when
--                                  the agent reports again. Only outages that
--                                  begin after the filter was armed (created,
--                                  enabled or switched on) alert, so arming a
--                                  channel never floods it with long-dead agents.
--   governance_review_overdue      AI register items past their review date
--                                  (daily count, at most one alert per UTC day).
--   governance_intake_requested    a new AI intake request (one per request).
--   governance_change_pending      a four-eyes policy change request awaiting
--                                  approval (one per request).
--   governance_exception_expiring  approved governance exceptions expiring within
--                                  `governance_exception_days` (1 to 90; daily
--                                  count, at most one alert per UTC day).
--   governance_digest              the scheduled governance digest
--                                  (governance-digest), delivered as counts only
--                                  when the tenant's digest schedule runs.
--
-- Where the work happens
--   * Request events (intake, change) are enqueued by AFTER INSERT triggers in
--     the same transaction as the request row (transactional outbox), isolated
--     in a subtransaction so an alerting fault never fails the request.
--   * Time-based events (offline, recovery, overdue reviews, expiring
--     exceptions) are computed by public.enqueue_scheduled_notifications, which
--     the existing notification-dispatch run calls once a minute before it
--     drains the outbox.
--   * The digest is enqueued by complete_governance_digest, once per period.
--
-- Payload discipline is unchanged: identifiers (UUIDs), enums and bounded
-- counts only. No asset names, justifications, request text, policy content,
-- agent display names, hostnames or user identities are ever copied.

-- ── Channel filters ────────────────────────────────────────────────────────

alter table public.notification_channels
  add column if not exists on_agent_offline boolean not null default false,
  add column if not exists agent_offline_minutes integer not null default 240,
  add column if not exists agent_offline_armed_at timestamptz,
  add column if not exists on_governance_review_overdue boolean not null default false,
  add column if not exists on_governance_intake_requested boolean not null default false,
  add column if not exists on_governance_change_pending boolean not null default false,
  add column if not exists on_governance_exception_expiring boolean not null default false,
  add column if not exists governance_exception_days integer not null default 14,
  add column if not exists on_governance_digest boolean not null default false;

alter table public.notification_channels
  drop constraint if exists notification_channels_agent_offline_minutes;
alter table public.notification_channels
  add constraint notification_channels_agent_offline_minutes
    check (agent_offline_minutes between 5 and 10080);
alter table public.notification_channels
  drop constraint if exists notification_channels_governance_exception_days;
alter table public.notification_channels
  add constraint notification_channels_governance_exception_days
    check (governance_exception_days between 1 and 90);
alter table public.notification_channels
  drop constraint if exists notification_channels_agent_offline_armed;
alter table public.notification_channels
  add constraint notification_channels_agent_offline_armed
    check (not on_agent_offline or agent_offline_armed_at is not null);
alter table public.notification_channels
  drop constraint if exists notification_channels_selects_an_event;
alter table public.notification_channels
  add constraint notification_channels_selects_an_event check (
    on_incident_created or on_runtime_deny_critical or on_approval_requested or on_privacy_blocked_spike
    or on_agent_offline or on_governance_review_overdue or on_governance_intake_requested
    or on_governance_change_pending or on_governance_exception_expiring or on_governance_digest
  );

create index if not exists notification_channels_agent_offline_idx
  on public.notification_channels (tenant_id) where enabled and on_agent_offline;

grant select (
  on_agent_offline, agent_offline_minutes, agent_offline_armed_at, on_governance_review_overdue,
  on_governance_intake_requested, on_governance_change_pending, on_governance_exception_expiring,
  governance_exception_days, on_governance_digest
) on public.notification_channels to authenticated;

-- Arm offline monitoring when it is switched on (or its channel is enabled):
-- only outages that begin afterwards alert.
create or replace function app.arm_notification_agent_offline()
returns trigger
language plpgsql
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if not new.on_agent_offline then
    new.agent_offline_armed_at := null;
  elsif tg_op = 'INSERT' or not old.on_agent_offline or (new.enabled and not old.enabled)
        or old.agent_offline_armed_at is null then
    new.agent_offline_armed_at := clock_timestamp();
  else
    new.agent_offline_armed_at := old.agent_offline_armed_at;
  end if;
  return new;
end;
$$;
revoke all on function app.arm_notification_agent_offline() from public, anon, authenticated;

drop trigger if exists notification_channels_arm_agent_offline on public.notification_channels;
create trigger notification_channels_arm_agent_offline
  before insert or update of on_agent_offline, enabled, agent_offline_armed_at on public.notification_channels
  for each row execute function app.arm_notification_agent_offline();

alter table public.notification_deliveries
  drop constraint if exists notification_deliveries_event_type_check;
alter table public.notification_deliveries
  add constraint notification_deliveries_event_type_check check (event_type in (
    'incident.created', 'runtime.deny_critical', 'approval.requested',
    'privacy.blocked_spike', 'notification.test',
    'agent.offline', 'agent.recovered',
    'governance.review_overdue', 'governance.intake_requested', 'governance.change_pending',
    'governance.exception_expiring', 'governance.digest'
  ));

-- ── Outage state (one open outage per channel and agent) ──────────────────
-- The dedupe key alone cannot remember an outage: delivered rows are pruned
-- after at most 7 days while an agent may stay offline longer. The open
-- outage lives here until the agent reports again (recovery notice), the
-- agent is deleted, or the channel stops monitoring.

create table if not exists public.notification_agent_outages (
  tenant_id uuid not null,
  channel_id uuid not null,
  agent_id uuid not null,
  -- agents.last_seen when the outage was detected.
  offline_since timestamptz not null,
  detected_at timestamptz not null default clock_timestamp(),
  primary key (channel_id, agent_id),
  constraint notification_agent_outages_channel_fk foreign key (tenant_id, channel_id)
    references public.notification_channels (tenant_id, id) on delete cascade,
  constraint notification_agent_outages_agent_fk foreign key (tenant_id, agent_id)
    references public.agents (tenant_id, id) on delete cascade,
  constraint notification_agent_outages_order check (detected_at >= offline_since)
);

create index if not exists notification_agent_outages_tenant_idx
  on public.notification_agent_outages (tenant_id, agent_id);

comment on table public.notification_agent_outages is
  'Open agent outages already alerted per notification channel; identifiers and timestamps only. Service role writes.';

alter table public.notification_agent_outages enable row level security;
revoke all on public.notification_agent_outages from public, anon, authenticated;
grant select (tenant_id, channel_id, agent_id, offline_since, detected_at)
  on public.notification_agent_outages to authenticated;
grant select, insert, update, delete on public.notification_agent_outages to service_role;

drop policy if exists notification_agent_outages_select_admin on public.notification_agent_outages;
create policy notification_agent_outages_select_admin on public.notification_agent_outages
  for select to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'));

drop policy if exists notification_agent_outages_no_client_writes on public.notification_agent_outages;
create policy notification_agent_outages_no_client_writes on public.notification_agent_outages
  as restrictive for all to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.notification_agent_outages;
create policy tenant_identity_access_restrict on public.notification_agent_outages
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Views and validation ───────────────────────────────────────────────────

create or replace function app.notification_channel_view(c public.notification_channels)
returns jsonb
language sql
stable
set search_path = pg_catalog, public, pg_temp
as $$
  select jsonb_build_object(
    'id', c.id,
    'type', c.type,
    'name', c.name,
    'target_hint', c.target_hint,
    'enabled', c.enabled,
    'filters', jsonb_build_object(
      'incident_created', c.on_incident_created,
      'incident_min_severity', c.incident_min_severity,
      'runtime_deny_critical', c.on_runtime_deny_critical,
      'approval_requested', c.on_approval_requested,
      'privacy_blocked_spike', c.on_privacy_blocked_spike,
      'privacy_spike_threshold', c.privacy_spike_threshold,
      'privacy_spike_window_minutes', c.privacy_spike_window_minutes,
      'agent_offline', c.on_agent_offline,
      'agent_offline_minutes', c.agent_offline_minutes,
      'governance_review_overdue', c.on_governance_review_overdue,
      'governance_intake_requested', c.on_governance_intake_requested,
      'governance_change_pending', c.on_governance_change_pending,
      'governance_exception_expiring', c.on_governance_exception_expiring,
      'governance_exception_days', c.governance_exception_days,
      'governance_digest', c.on_governance_digest
    ),
    'created_by', c.created_by,
    'created_at', c.created_at,
    'updated_at', c.updated_at,
    'last_delivery_at', c.last_delivery_at,
    'last_delivery_status', c.last_delivery_status,
    'last_error', c.last_error,
    'consecutive_failures', c.consecutive_failures
  );
$$;
revoke all on function app.notification_channel_view(public.notification_channels) from public, anon, authenticated;

-- The seven original filter keys stay mandatory (older consoles keep working);
-- the extended keys are optional and default to "off" on create and
-- "unchanged" on update. Unknown keys are refused rather than ignored.
create or replace function app.notification_filters_valid(p_filters jsonb)
returns boolean
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  -- CASE (not AND) guards every cast: SQL does not promise left-to-right
  -- evaluation, and a malformed value must yield false, never an error.
  select case
    when p_filters is null or jsonb_typeof(p_filters) <> 'object' then false
    when not (p_filters ?& array['incident_created', 'incident_min_severity', 'runtime_deny_critical',
        'approval_requested', 'privacy_blocked_spike', 'privacy_spike_threshold',
        'privacy_spike_window_minutes'])
      or exists (
        select 1 from jsonb_object_keys(p_filters) k
         where k not in ('incident_created', 'incident_min_severity', 'runtime_deny_critical',
           'approval_requested', 'privacy_blocked_spike', 'privacy_spike_threshold',
           'privacy_spike_window_minutes', 'agent_offline', 'agent_offline_minutes',
           'governance_review_overdue', 'governance_intake_requested', 'governance_change_pending',
           'governance_exception_expiring', 'governance_exception_days', 'governance_digest')
      ) then false
    when jsonb_typeof(p_filters->'incident_created') <> 'boolean'
      or jsonb_typeof(p_filters->'runtime_deny_critical') <> 'boolean'
      or jsonb_typeof(p_filters->'approval_requested') <> 'boolean'
      or jsonb_typeof(p_filters->'privacy_blocked_spike') <> 'boolean'
      or jsonb_typeof(p_filters->'privacy_spike_threshold') <> 'number'
      or jsonb_typeof(p_filters->'privacy_spike_window_minutes') <> 'number'
      or coalesce(p_filters->>'incident_min_severity', '') not in ('info', 'warning', 'high', 'critical')
      or (p_filters->>'privacy_spike_threshold') !~ '^[0-9]{1,5}$'
      or (p_filters->>'privacy_spike_window_minutes') !~ '^[0-9]{1,4}$' then false
    when coalesce(jsonb_typeof(p_filters->'agent_offline'), 'boolean') <> 'boolean'
      or coalesce(jsonb_typeof(p_filters->'governance_review_overdue'), 'boolean') <> 'boolean'
      or coalesce(jsonb_typeof(p_filters->'governance_intake_requested'), 'boolean') <> 'boolean'
      or coalesce(jsonb_typeof(p_filters->'governance_change_pending'), 'boolean') <> 'boolean'
      or coalesce(jsonb_typeof(p_filters->'governance_exception_expiring'), 'boolean') <> 'boolean'
      or coalesce(jsonb_typeof(p_filters->'governance_digest'), 'boolean') <> 'boolean'
      or coalesce(jsonb_typeof(p_filters->'agent_offline_minutes'), 'number') <> 'number'
      or coalesce(jsonb_typeof(p_filters->'governance_exception_days'), 'number') <> 'number'
      or coalesce(p_filters->>'agent_offline_minutes', '240') !~ '^[0-9]{1,5}$'
      or coalesce(p_filters->>'governance_exception_days', '14') !~ '^[0-9]{1,2}$' then false
    else (p_filters->>'privacy_spike_threshold')::integer between 1 and 10000
      and (p_filters->>'privacy_spike_window_minutes')::integer between 5 and 1440
      and coalesce((p_filters->>'agent_offline_minutes')::integer, 240) between 5 and 10080
      and coalesce((p_filters->>'governance_exception_days')::integer, 14) between 1 and 90
      and ((p_filters->>'incident_created')::boolean or (p_filters->>'runtime_deny_critical')::boolean
        or (p_filters->>'approval_requested')::boolean or (p_filters->>'privacy_blocked_spike')::boolean
        or coalesce((p_filters->>'agent_offline')::boolean, false)
        or coalesce((p_filters->>'governance_review_overdue')::boolean, false)
        or coalesce((p_filters->>'governance_intake_requested')::boolean, false)
        or coalesce((p_filters->>'governance_change_pending')::boolean, false)
        or coalesce((p_filters->>'governance_exception_expiring')::boolean, false)
        or coalesce((p_filters->>'governance_digest')::boolean, false))
  end;
$$;
revoke all on function app.notification_filters_valid(jsonb) from public, anon, authenticated;

-- ── Channel RPCs (same signatures; extended filters) ──────────────────────

create or replace function public.create_notification_channel(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_channel_id uuid,
  p_type text,
  p_name text,
  p_target_ciphertext text,
  p_target_key_id text,
  p_target_hint text,
  p_filters jsonb,
  p_enabled boolean
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_channel public.notification_channels;
begin
  if p_channel_id is null or p_type is null or p_name is null or p_target_ciphertext is null
     or p_target_key_id is null or p_target_hint is null or p_enabled is null
     or not app.notification_filters_valid(p_filters) then
    raise exception 'invalid_notification_channel' using errcode = '22023';
  end if;
  perform app.lock_notification_admin(p_tenant_id, p_actor_user_id);
  -- Serialize creation per tenant so the channel cap cannot be raced.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2626));
  if (select count(*) from public.notification_channels where tenant_id = p_tenant_id) >= 20 then
    raise exception 'notification_channel_limit' using errcode = '54000';
  end if;

  insert into public.notification_channels (
    id, tenant_id, type, name, target_ciphertext, target_key_id, target_hint, enabled,
    on_incident_created, incident_min_severity, on_runtime_deny_critical, on_approval_requested,
    on_privacy_blocked_spike, privacy_spike_threshold, privacy_spike_window_minutes,
    on_agent_offline, agent_offline_minutes, on_governance_review_overdue,
    on_governance_intake_requested, on_governance_change_pending, on_governance_exception_expiring,
    governance_exception_days, on_governance_digest,
    created_by, updated_by
  ) values (
    p_channel_id, p_tenant_id, p_type, btrim(p_name), p_target_ciphertext, p_target_key_id,
    p_target_hint, p_enabled,
    (p_filters->>'incident_created')::boolean, p_filters->>'incident_min_severity',
    (p_filters->>'runtime_deny_critical')::boolean, (p_filters->>'approval_requested')::boolean,
    (p_filters->>'privacy_blocked_spike')::boolean, (p_filters->>'privacy_spike_threshold')::integer,
    (p_filters->>'privacy_spike_window_minutes')::integer,
    coalesce((p_filters->>'agent_offline')::boolean, false),
    coalesce((p_filters->>'agent_offline_minutes')::integer, 240),
    coalesce((p_filters->>'governance_review_overdue')::boolean, false),
    coalesce((p_filters->>'governance_intake_requested')::boolean, false),
    coalesce((p_filters->>'governance_change_pending')::boolean, false),
    coalesce((p_filters->>'governance_exception_expiring')::boolean, false),
    coalesce((p_filters->>'governance_exception_days')::integer, 14),
    coalesce((p_filters->>'governance_digest')::boolean, false),
    p_actor_user_id, p_actor_user_id
  )
  returning * into v_channel;

  perform app.audit_notification_channel(p_tenant_id, p_actor_user_id, 'notification_channel.created',
    jsonb_build_object('channel_id', v_channel.id, 'type', v_channel.type, 'enabled', v_channel.enabled,
      'filters', app.notification_channel_view(v_channel)->'filters'));
  return app.notification_channel_view(v_channel);
end;
$$;
revoke all on function public.create_notification_channel(uuid, uuid, uuid, text, text, text, text, text, jsonb, boolean)
  from public, anon, authenticated;
grant execute on function public.create_notification_channel(uuid, uuid, uuid, text, text, text, text, text, jsonb, boolean)
  to service_role;

create or replace function public.update_notification_channel(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_channel_id uuid,
  p_expected_type text,
  p_name text,
  p_enabled boolean,
  p_filters jsonb,
  p_target_ciphertext text,
  p_target_key_id text,
  p_target_hint text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_before public.notification_channels;
  v_after public.notification_channels;
  v_changed text[] := array[]::text[];
begin
  if p_channel_id is null or p_expected_type is null
     or (p_filters is not null and not app.notification_filters_valid(p_filters))
     or ((p_target_ciphertext is null) <> (p_target_key_id is null))
     or ((p_target_ciphertext is null) <> (p_target_hint is null)) then
    raise exception 'invalid_notification_channel' using errcode = '22023';
  end if;
  perform app.lock_notification_admin(p_tenant_id, p_actor_user_id);
  select * into v_before from public.notification_channels
   where id = p_channel_id and tenant_id = p_tenant_id for update;
  if not found then
    raise exception 'notification_channel_not_found' using errcode = 'P0002';
  end if;
  if v_before.type <> p_expected_type then
    raise exception 'notification_channel_type_mismatch' using errcode = '22023';
  end if;

  update public.notification_channels c set
    name = coalesce(btrim(p_name), c.name),
    enabled = coalesce(p_enabled, c.enabled),
    on_incident_created = coalesce((p_filters->>'incident_created')::boolean, c.on_incident_created),
    incident_min_severity = coalesce(p_filters->>'incident_min_severity', c.incident_min_severity),
    on_runtime_deny_critical = coalesce((p_filters->>'runtime_deny_critical')::boolean, c.on_runtime_deny_critical),
    on_approval_requested = coalesce((p_filters->>'approval_requested')::boolean, c.on_approval_requested),
    on_privacy_blocked_spike = coalesce((p_filters->>'privacy_blocked_spike')::boolean, c.on_privacy_blocked_spike),
    privacy_spike_threshold = coalesce((p_filters->>'privacy_spike_threshold')::integer, c.privacy_spike_threshold),
    privacy_spike_window_minutes = coalesce((p_filters->>'privacy_spike_window_minutes')::integer, c.privacy_spike_window_minutes),
    on_agent_offline = coalesce((p_filters->>'agent_offline')::boolean, c.on_agent_offline),
    agent_offline_minutes = coalesce((p_filters->>'agent_offline_minutes')::integer, c.agent_offline_minutes),
    on_governance_review_overdue = coalesce((p_filters->>'governance_review_overdue')::boolean, c.on_governance_review_overdue),
    on_governance_intake_requested = coalesce((p_filters->>'governance_intake_requested')::boolean, c.on_governance_intake_requested),
    on_governance_change_pending = coalesce((p_filters->>'governance_change_pending')::boolean, c.on_governance_change_pending),
    on_governance_exception_expiring = coalesce((p_filters->>'governance_exception_expiring')::boolean, c.on_governance_exception_expiring),
    governance_exception_days = coalesce((p_filters->>'governance_exception_days')::integer, c.governance_exception_days),
    on_governance_digest = coalesce((p_filters->>'governance_digest')::boolean, c.on_governance_digest),
    target_ciphertext = coalesce(p_target_ciphertext, c.target_ciphertext),
    target_key_id = coalesce(p_target_key_id, c.target_key_id),
    target_hint = coalesce(p_target_hint, c.target_hint),
    -- A new destination starts with a clean delivery record.
    consecutive_failures = case when p_target_ciphertext is null then c.consecutive_failures else 0 end,
    last_error = case when p_target_ciphertext is null then c.last_error else null end,
    updated_by = p_actor_user_id,
    updated_at = clock_timestamp()
  where c.id = p_channel_id
  returning * into v_after;

  if v_after.name is distinct from v_before.name then v_changed := array_append(v_changed, 'name'); end if;
  if v_after.enabled is distinct from v_before.enabled then v_changed := array_append(v_changed, 'enabled'); end if;
  if app.notification_channel_view(v_after)->'filters' is distinct from app.notification_channel_view(v_before)->'filters' then
    v_changed := array_append(v_changed, 'filters');
  end if;
  if p_target_ciphertext is not null then v_changed := array_append(v_changed, 'target'); end if;

  -- Deliveries queued for a destination that was just replaced or a channel
  -- that was just disabled must not go out afterwards.
  if 'target' = any(v_changed) or ('enabled' = any(v_changed) and not v_after.enabled) then
    update public.notification_deliveries
       set status = 'dead', last_error = 'channel_changed', lease_token = null, lease_expires_at = null
     where channel_id = p_channel_id and status = 'pending';
  end if;
  -- A channel that stops monitoring agents forgets its open outages.
  if not (v_after.enabled and v_after.on_agent_offline) then
    delete from public.notification_agent_outages where channel_id = p_channel_id;
  end if;

  if cardinality(v_changed) > 0 then
    perform app.audit_notification_channel(p_tenant_id, p_actor_user_id, 'notification_channel.updated',
      jsonb_build_object('channel_id', p_channel_id, 'type', v_after.type, 'changed', to_jsonb(v_changed),
        'enabled', v_after.enabled, 'target_replaced', 'target' = any(v_changed),
        'filters', app.notification_channel_view(v_after)->'filters'));
  end if;
  return app.notification_channel_view(v_after) || jsonb_build_object('changed', to_jsonb(v_changed));
end;
$$;
revoke all on function public.update_notification_channel(uuid, uuid, uuid, text, text, boolean, jsonb, text, text, text)
  from public, anon, authenticated;
grant execute on function public.update_notification_channel(uuid, uuid, uuid, text, text, boolean, jsonb, text, text, text)
  to service_role;

-- ── Shared enqueue helper ─────────────────────────────────────────────────
-- Returns 'queued', 'duplicate' (the dedupe key was already used) or 'capped'
-- (the channel's 30-per-minute flood cap is full; the caller retries later).

create or replace function app.enqueue_channel_notification(
  p_tenant_id uuid,
  p_channel_id uuid,
  p_event_type text,
  p_dedupe_key text,
  p_payload jsonb
)
returns text
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_rows integer;
begin
  if exists (
    select 1 from public.notification_deliveries d
     where d.channel_id = p_channel_id and d.dedupe_key = lower(p_dedupe_key)
  ) then
    return 'duplicate';
  end if;
  if (
    select count(*) from (
      select 1 from public.notification_deliveries d
       where d.channel_id = p_channel_id
         and d.created_at > clock_timestamp() - interval '1 minute'
       limit 30
    ) recent
  ) >= 30 then
    return 'capped';
  end if;
  insert into public.notification_deliveries (tenant_id, channel_id, event_type, dedupe_key, payload)
  values (p_tenant_id, p_channel_id, p_event_type, lower(p_dedupe_key), jsonb_strip_nulls(p_payload))
  on conflict (channel_id, dedupe_key) do nothing;
  get diagnostics v_rows = row_count;
  return case when v_rows = 1 then 'queued' else 'duplicate' end;
end;
$$;
revoke all on function app.enqueue_channel_notification(uuid, uuid, text, text, jsonb) from public, anon, authenticated;

-- ── Governance request events (transactional) ─────────────────────────────

create or replace function app.enqueue_governance_request_notifications(
  p_tenant_id uuid,
  p_event_type text,
  p_request_id uuid,
  p_category text,
  p_occurred_at timestamptz
)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_channel record;
  v_queued integer := 0;
begin
  if p_tenant_id is null or p_request_id is null
     or p_event_type not in ('governance.intake_requested', 'governance.change_pending') then
    return 0;
  end if;
  if not exists (select 1 from public.tenants t where t.id = p_tenant_id and t.status = 'active') then
    return 0;
  end if;
  for v_channel in
    select c.id from public.notification_channels c
     where c.tenant_id = p_tenant_id and c.enabled
       and case p_event_type
         when 'governance.intake_requested' then c.on_governance_intake_requested
         else c.on_governance_change_pending
       end
     order by c.id
  loop
    if app.enqueue_channel_notification(p_tenant_id, v_channel.id, p_event_type,
         p_event_type || ':' || p_request_id,
         jsonb_build_object(
           'request_id', p_request_id::text,
           'occurred_at', p_occurred_at,
           'category', case when p_category ~ '^[a-z][a-z0-9_]{0,63}$' then p_category end
         )) = 'queued' then
      v_queued := v_queued + 1;
    end if;
  end loop;
  return v_queued;
end;
$$;
revoke all on function app.enqueue_governance_request_notifications(uuid, text, uuid, text, timestamptz)
  from public, anon, authenticated;

create or replace function app.enqueue_governance_request_trigger()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if new.status <> 'pending' then return new; end if;
  begin
    if tg_table_name = 'ai_intake_requests' then
      perform app.enqueue_governance_request_notifications(new.tenant_id, 'governance.intake_requested',
        new.id, to_jsonb(new)->>'asset_type', new.created_at);
    else
      perform app.enqueue_governance_request_notifications(new.tenant_id, 'governance.change_pending',
        new.id, to_jsonb(new)->>'change_kind', new.created_at);
    end if;
  exception when others then
    -- The request is the record of truth; never fail it over an alerting fault.
    raise warning 'notification_enqueue_failed' using detail = sqlstate;
  end;
  return new;
end;
$$;
revoke all on function app.enqueue_governance_request_trigger() from public, anon, authenticated;

drop trigger if exists ai_intake_requests_enqueue_notifications on public.ai_intake_requests;
create trigger ai_intake_requests_enqueue_notifications
  after insert on public.ai_intake_requests
  for each row execute function app.enqueue_governance_request_trigger();

drop trigger if exists policy_change_requests_enqueue_notifications on public.policy_change_requests;
create trigger policy_change_requests_enqueue_notifications
  after insert on public.policy_change_requests
  for each row execute function app.enqueue_governance_request_trigger();

-- ── Scheduled scan (called by notification-dispatch every run) ────────────

create or replace function public.enqueue_scheduled_notifications(p_limit integer)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_day text := to_char(clock_timestamp() at time zone 'utc', 'YYYYMMDD');
  v_today date := (clock_timestamp() at time zone 'utc')::date;
  v_row record;
  v_result text;
  v_count integer;
  v_budget integer;
  v_offline integer := 0;
  v_recovered integer := 0;
  v_overdue integer := 0;
  v_expiring integer := 0;
  v_capped integer := 0;
begin
  if p_limit is null or p_limit not between 1 and 5000 then
    raise exception 'invalid_notification_scan' using errcode = '22023';
  end if;
  -- One scan at a time; an overlapping dispatcher run skips it (dedupe keys
  -- would make an overlap harmless, the lock only saves the work).
  if not pg_try_advisory_xact_lock(hashtextextended('aidr:notification-scheduled-scan', 2627)) then
    return jsonb_build_object('skipped', true);
  end if;
  v_budget := p_limit;

  -- Outages of channels that stopped monitoring (disabled, filter off,
  -- inactive tenant) are forgotten.
  delete from public.notification_agent_outages o
   using public.notification_channels c, public.tenants t
   where c.id = o.channel_id and t.id = o.tenant_id
     and (not c.enabled or not c.on_agent_offline or t.status <> 'active');

  -- Recovery: the agent reported again after the outage was alerted.
  for v_row in
    select o.tenant_id, o.channel_id, o.agent_id, o.offline_since, a.last_seen, a.agent_runtime
      from public.notification_agent_outages o
      join public.agents a on a.tenant_id = o.tenant_id and a.id = o.agent_id
     where a.last_seen > o.offline_since
     order by o.detected_at, o.channel_id, o.agent_id
     limit v_budget
     for update of o skip locked
  loop
    v_result := app.enqueue_channel_notification(v_row.tenant_id, v_row.channel_id, 'agent.recovered',
      'agent.recovered:' || v_row.agent_id || ':' || floor(extract(epoch from v_row.offline_since))::bigint,
      jsonb_build_object(
        'agent_id', v_row.agent_id::text,
        'occurred_at', v_row.last_seen,
        'category', case when v_row.agent_runtime ~ '^[a-z][a-z0-9_-]{0,63}$' then v_row.agent_runtime end,
        'offline_minutes', least(greatest(floor(extract(epoch from (v_row.last_seen - v_row.offline_since)) / 60)::bigint, 0), 10000000)
      ));
    if v_result = 'capped' then
      v_capped := v_capped + 1;
      continue;
    end if;
    delete from public.notification_agent_outages
     where channel_id = v_row.channel_id and agent_id = v_row.agent_id;
    if v_result = 'queued' then v_recovered := v_recovered + 1; end if;
  end loop;

  -- Offline: not seen for the channel's threshold, and the outage began after
  -- the channel armed offline monitoring.
  v_budget := greatest(p_limit - v_recovered, 0);
  if v_budget > 0 then
    for v_row in
      select c.tenant_id, c.id as channel_id, a.id as agent_id, a.last_seen, a.agent_runtime,
             c.agent_offline_minutes
        from public.notification_channels c
        join public.tenants t on t.id = c.tenant_id and t.status = 'active'
        join public.agents a on a.tenant_id = c.tenant_id
       where c.enabled and c.on_agent_offline
         and a.last_seen <= v_now - make_interval(mins => c.agent_offline_minutes)
         and a.last_seen + make_interval(mins => c.agent_offline_minutes) > c.agent_offline_armed_at
         and not exists (
           select 1 from public.notification_agent_outages o
            where o.channel_id = c.id and o.agent_id = a.id
         )
       order by a.last_seen desc, c.id, a.id
       limit v_budget
    loop
      v_result := app.enqueue_channel_notification(v_row.tenant_id, v_row.channel_id, 'agent.offline',
        'agent.offline:' || v_row.agent_id || ':' || floor(extract(epoch from v_row.last_seen))::bigint,
        jsonb_build_object(
          'agent_id', v_row.agent_id::text,
          'occurred_at', v_row.last_seen,
          'category', case when v_row.agent_runtime ~ '^[a-z][a-z0-9_-]{0,63}$' then v_row.agent_runtime end,
          'offline_minutes', v_row.agent_offline_minutes
        ));
      if v_result = 'capped' then
        v_capped := v_capped + 1;
        continue;
      end if;
      insert into public.notification_agent_outages (tenant_id, channel_id, agent_id, offline_since, detected_at)
      values (v_row.tenant_id, v_row.channel_id, v_row.agent_id, v_row.last_seen, greatest(v_now, v_row.last_seen))
      on conflict (channel_id, agent_id) do nothing;
      if v_result = 'queued' then v_offline := v_offline + 1; end if;
    end loop;
  end if;

  -- AI register items past their review date: one count per channel per UTC day.
  for v_row in
    select c.tenant_id, c.id as channel_id
      from public.notification_channels c
      join public.tenants t on t.id = c.tenant_id and t.status = 'active'
     where c.enabled and c.on_governance_review_overdue
       and not exists (
         select 1 from public.notification_deliveries d
          where d.channel_id = c.id and d.dedupe_key = 'governance.review_overdue:' || v_day
       )
     order by c.id
     limit 500
  loop
    select count(*) into v_count from public.ai_assets a
     where a.tenant_id = v_row.tenant_id and a.status <> 'retired' and a.review_due_at < v_today;
    continue when v_count = 0;
    v_result := app.enqueue_channel_notification(v_row.tenant_id, v_row.channel_id, 'governance.review_overdue',
      'governance.review_overdue:' || v_day,
      jsonb_build_object('occurred_at', v_now, 'category', 'ai_register', 'items_count', least(v_count, 10000000)));
    if v_result = 'queued' then v_overdue := v_overdue + 1; end if;
    if v_result = 'capped' then v_capped := v_capped + 1; end if;
  end loop;

  -- Approved exceptions expiring within the channel's window: one count per
  -- channel per UTC day.
  for v_row in
    select c.tenant_id, c.id as channel_id, c.governance_exception_days
      from public.notification_channels c
      join public.tenants t on t.id = c.tenant_id and t.status = 'active'
     where c.enabled and c.on_governance_exception_expiring
       and not exists (
         select 1 from public.notification_deliveries d
          where d.channel_id = c.id and d.dedupe_key = 'governance.exception_expiring:' || v_day
       )
     order by c.id
     limit 500
  loop
    select count(*) into v_count from public.ai_governance_exceptions e
     where e.tenant_id = v_row.tenant_id and e.status = 'approved'
       and e.expires_at > v_now
       and e.expires_at <= v_now + make_interval(days => v_row.governance_exception_days);
    continue when v_count = 0;
    v_result := app.enqueue_channel_notification(v_row.tenant_id, v_row.channel_id, 'governance.exception_expiring',
      'governance.exception_expiring:' || v_day,
      jsonb_build_object('occurred_at', v_now, 'category', 'ai_exception', 'items_count', least(v_count, 10000000),
        'window_days', v_row.governance_exception_days));
    if v_result = 'queued' then v_expiring := v_expiring + 1; end if;
    if v_result = 'capped' then v_capped := v_capped + 1; end if;
  end loop;

  return jsonb_build_object(
    'skipped', false,
    'agent_offline', v_offline,
    'agent_recovered', v_recovered,
    'governance_review_overdue', v_overdue,
    'governance_exception_expiring', v_expiring,
    'capped', v_capped
  );
end;
$$;
revoke all on function public.enqueue_scheduled_notifications(integer) from public, anon, authenticated;
grant execute on function public.enqueue_scheduled_notifications(integer) to service_role;

-- ── Governance digest to channels ─────────────────────────────────────────
-- Counts only, from the same summary the e-mail uses (no identities). One
-- delivery per channel per digest period, whatever happens to the e-mail.

create or replace function app.enqueue_governance_digest_notifications(
  p_tenant_id uuid,
  p_cadence text,
  p_period_from timestamptz,
  p_period_to timestamptz
)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_summary jsonb;
  v_digest jsonb;
  v_channel record;
  v_queued integer := 0;
  v_overdue integer;
  v_intake integer;
  v_changes integer;
begin
  if p_tenant_id is null or p_cadence not in ('weekly', 'monthly')
     or p_period_from is null or p_period_to is null or p_period_to <= p_period_from then
    return 0;
  end if;
  if not exists (
    select 1 from public.notification_channels c
     where c.tenant_id = p_tenant_id and c.enabled and c.on_governance_digest
  ) then
    return 0;
  end if;
  v_summary := app.governance_scorecard_data(p_tenant_id, p_period_from, p_period_to, false);
  select count(*) into v_overdue from public.ai_assets a
   where a.tenant_id = p_tenant_id and a.status <> 'retired'
     and a.review_due_at < (clock_timestamp() at time zone 'utc')::date;
  select count(*) into v_intake from public.ai_intake_requests r
   where r.tenant_id = p_tenant_id and r.status = 'pending' and r.expires_at > clock_timestamp();
  select count(*) into v_changes from public.policy_change_requests r
   where r.tenant_id = p_tenant_id and r.status = 'pending' and r.expires_at > clock_timestamp();

  -- Fixed allow-list of non-negative integers; anything missing is omitted.
  select coalesce(jsonb_object_agg(k, v), '{}'::jsonb) into v_digest
  from (
    select k, (least(greatest(v::bigint, 0), 10000000))::integer as v
    from (values
      ('agents_enrolled', v_summary #>> '{usage,agents,enrolled}'),
      ('agents_active', v_summary #>> '{usage,agents,active}'),
      ('decisions_allow', v_summary #>> '{decisions,allow}'),
      ('decisions_ask', v_summary #>> '{decisions,ask}'),
      ('decisions_deny', v_summary #>> '{decisions,deny}'),
      ('approvals_requested', v_summary #>> '{approvals,requested}'),
      ('approvals_pending', v_summary #>> '{approvals,pending}'),
      ('incidents_reported', v_summary #>> '{incidents,reported}'),
      ('incidents_open', v_summary #>> '{incidents,open}'),
      ('incidents_open_critical', v_summary #>> '{incidents,open_by_severity,critical}'),
      ('browser_blocked', v_summary #>> '{browser_guard,blocked}'),
      ('browser_masked', v_summary #>> '{browser_guard,masked}'),
      ('mcp_not_approved', v_summary #>> '{usage,mcp_servers,not_approved}'),
      ('reviews_overdue', v_overdue::text),
      ('intake_pending', v_intake::text),
      ('policy_changes_pending', v_changes::text)
    ) as fields(k, v)
    where v ~ '^[0-9]{1,12}$'
  ) projected;

  for v_channel in
    select c.id from public.notification_channels c
     where c.tenant_id = p_tenant_id and c.enabled and c.on_governance_digest
     order by c.id
  loop
    if app.enqueue_channel_notification(p_tenant_id, v_channel.id, 'governance.digest',
         'governance.digest:' || p_cadence || ':' || floor(extract(epoch from p_period_from))::bigint,
         jsonb_build_object(
           'occurred_at', p_period_to,
           'category', p_cadence,
           'period_from', p_period_from,
           'period_to', p_period_to,
           'digest', v_digest
         )) = 'queued' then
      v_queued := v_queued + 1;
    end if;
  end loop;
  return v_queued;
end;
$$;
revoke all on function app.enqueue_governance_digest_notifications(uuid, text, timestamptz, timestamptz)
  from public, anon, authenticated;

-- Same contract as 20260927000061; additionally enqueues the counts-only
-- channel delivery for the period (isolated: a channel fault never loses the
-- digest receipt or the schedule advance).
create or replace function public.complete_governance_digest(
  p_tenant_id uuid,
  p_claim_id uuid,
  p_status text,
  p_recipients integer,
  p_delivered integer
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_settings public.tenant_governance_settings;
  v_period record;
  v_next timestamptz;
  v_attempts integer;
  v_retry boolean;
  v_channels integer := 0;
begin
  if p_tenant_id is null or p_claim_id is null
     or p_status is null or p_status not in ('sent', 'partial', 'failed', 'no_transport', 'no_recipients')
     or p_recipients is null or p_recipients not between 0 and 1000
     or p_delivered is null or p_delivered not between 0 and p_recipients then
    raise exception 'invalid_governance_digest_result' using errcode = '22023';
  end if;
  select * into v_settings
  from public.tenant_governance_settings s
  where s.tenant_id = p_tenant_id
  for update;
  if not found or v_settings.digest_claim_id is distinct from p_claim_id then
    raise exception 'governance_digest_claim_lost' using errcode = '40001';
  end if;

  select * into v_period from app.governance_digest_period(v_settings.digest_cadence, v_settings.digest_next_at);
  insert into public.governance_digest_deliveries (
    tenant_id, trigger, cadence, period_from, period_to, status, recipients, delivered
  ) values (
    p_tenant_id, 'schedule', v_settings.digest_cadence, v_period.period_from, v_period.period_to,
    p_status, p_recipients, p_delivered
  );

  begin
    v_channels := app.enqueue_governance_digest_notifications(p_tenant_id, v_settings.digest_cadence,
      v_period.period_from, v_period.period_to);
  exception when others then
    raise warning 'governance_digest_channel_enqueue_failed' using detail = sqlstate;
    v_channels := 0;
  end;

  v_attempts := v_settings.digest_attempts + 1;
  -- A failed send is retried by a later maintenance run (after a 30 minute
  -- back-off) until the third attempt; every other outcome is final.
  v_retry := p_status = 'failed' and v_attempts < 3;
  if v_retry then
    update public.tenant_governance_settings
       set digest_attempts = v_attempts,
           digest_last_status = p_status,
           digest_claim_id = gen_random_uuid(),
           digest_claim_expires_at = now() + interval '30 minutes'
     where tenant_id = p_tenant_id;
    v_next := v_settings.digest_next_at;
  else
    v_next := app.governance_digest_next_at(v_settings.digest_cadence, greatest(now(), v_settings.digest_next_at));
    update public.tenant_governance_settings
       set digest_attempts = 0,
           digest_last_at = now(),
           digest_last_status = p_status,
           digest_next_at = v_next,
           digest_claim_id = null,
           digest_claim_expires_at = null
     where tenant_id = p_tenant_id;
  end if;
  return jsonb_build_object('retry', v_retry, 'next_at', v_next, 'attempts', v_attempts,
    'channels_queued', v_channels);
end;
$$;
revoke all on function public.complete_governance_digest(uuid, uuid, text, integer, integer) from public, anon, authenticated;
grant execute on function public.complete_governance_digest(uuid, uuid, text, integer, integer) to service_role;

-- ── Offboarding residue ───────────────────────────────────────────────────
-- Outages cascade with their channel; the residue guard now also proves it.
create or replace function app.assert_no_notification_offboarding_residue()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if new.status <> 'completed' then return new; end if;
  -- Receipts alone never prove deletion: a completed run with any remaining
  -- channel, delivery or open outage for its tenant is refused.
  if exists (select 1 from public.notification_channels where tenant_id = new.tenant_id)
     or exists (select 1 from public.notification_deliveries where tenant_id = new.tenant_id)
     or exists (select 1 from public.notification_agent_outages where tenant_id = new.tenant_id) then
    raise exception 'notification_offboarding_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_no_notification_offboarding_residue() from public, anon, authenticated;
