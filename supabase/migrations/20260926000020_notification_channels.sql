-- Tenant alert integrations: notification channels and their delivery outbox.
--
-- A notification channel is a tenant-owned destination (Slack incoming webhook,
-- Microsoft Teams workflow webhook, signed generic HTTPS webhook, or e-mail
-- recipients) plus the event filters that select what it receives. The
-- destination itself is a credential: a Slack/Teams webhook URL or a generic
-- webhook's HMAC secret lets anyone post into the customer's channel. It is
-- therefore stored only as AES-256-GCM ciphertext produced by the
-- `notification-channels` Edge Function (key: AIDR_NOTIFICATION_ENCRYPTION_KEYS,
-- never in the database), bound to (tenant, channel, type) as associated data,
-- and it is never returned by any API. `target_hint` is a non-secret label
-- (host plus a digest prefix, or masked recipients) for the console.
--
-- Access model
--   * Owners and administrators may READ channel metadata through RLS (column
--     grants exclude the ciphertext). Nobody but the service role writes.
--   * Every mutation goes through the service-role RPCs below, called by the
--     Edge Function after it authenticated the session, applied the identity
--     barrier, the owner/admin role and AAL2. The RPCs re-check the actor's live
--     membership and the tenant status under row locks and write the privileged
--     and customer-visible audit rows in the same transaction.
--   * The restrictive tenant identity barrier applies to both tables.
--
-- Retention and offboarding
--   * Deliveries are `operational_ephemera`; terminal rows are pruned by the
--     dispatcher after the tenant's operational_ephemera retention (<= 7 days,
--     see 20260926000021) unless a legal hold is active.
--   * When a tenant starts offboarding (status `closing`) or is closed, every
--     channel and delivery for it is deleted in the same transaction, so no
--     encrypted destination credential outlives the workspace and no further
--     alert can leave. A channel can only be created for an active tenant,
--     and a residue guard refuses to complete an offboarding run while any
--     channel or delivery for the tenant remains.

create table if not exists public.notification_channels (
  id uuid primary key,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  type text not null check (type in ('slack', 'teams', 'webhook', 'email')),
  name text not null check (length(btrim(name)) between 1 and 80 and name !~ '[[:cntrl:]]'),
  target_ciphertext text not null
    check (length(target_ciphertext) between 48 and 16384
      and target_ciphertext ~ '^v1\.[a-z0-9][a-z0-9_-]{0,31}\.[A-Za-z0-9_-]+$'),
  target_key_id text not null check (target_key_id ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
  target_hint text not null check (length(target_hint) between 1 and 160 and target_hint !~ '[[:cntrl:]]'),
  enabled boolean not null default true,
  on_incident_created boolean not null default false,
  incident_min_severity text not null default 'high'
    check (incident_min_severity in ('info', 'warning', 'high', 'critical')),
  on_runtime_deny_critical boolean not null default false,
  on_approval_requested boolean not null default false,
  on_privacy_blocked_spike boolean not null default false,
  privacy_spike_threshold integer not null default 10 check (privacy_spike_threshold between 1 and 10000),
  privacy_spike_window_minutes integer not null default 15
    check (privacy_spike_window_minutes between 5 and 1440),
  created_by uuid not null,
  updated_by uuid not null,
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp(),
  last_delivery_at timestamptz,
  last_delivery_status text check (last_delivery_status is null or last_delivery_status in ('delivered', 'retrying', 'dead')),
  last_error text check (last_error is null or last_error ~ '^[a-z][a-z0-9_]{0,63}$'),
  consecutive_failures integer not null default 0 check (consecutive_failures >= 0),
  constraint notification_channels_tenant_id_unique unique (tenant_id, id),
  constraint notification_channels_key_matches_ciphertext
    check (split_part(target_ciphertext, '.', 2) = target_key_id),
  constraint notification_channels_selects_an_event check (
    on_incident_created or on_runtime_deny_critical or on_approval_requested or on_privacy_blocked_spike
  )
);

create unique index if not exists notification_channels_tenant_name_idx
  on public.notification_channels (tenant_id, lower(btrim(name)));
create index if not exists notification_channels_tenant_enabled_idx
  on public.notification_channels (tenant_id) where enabled;

comment on table public.notification_channels is
  'Tenant alert destinations. target_ciphertext is AES-256-GCM ciphertext from the notification-channels function and is never granted to clients.';

create table if not exists public.notification_deliveries (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  channel_id uuid not null,
  event_type text not null check (event_type in (
    'incident.created', 'runtime.deny_critical', 'approval.requested',
    'privacy.blocked_spike', 'notification.test'
  )),
  dedupe_key text not null check (dedupe_key ~ '^[a-z][a-z0-9_.:-]{0,190}$'),
  -- Identifiers, enums, bounded counts only (see app.notification_event_payload).
  payload jsonb not null check (jsonb_typeof(payload) = 'object' and pg_column_size(payload) <= 2048),
  status text not null default 'pending' check (status in ('pending', 'delivering', 'delivered', 'dead')),
  attempts integer not null default 0 check (attempts between 0 and 50),
  max_attempts integer not null default 8 check (max_attempts between 1 and 20),
  next_attempt_at timestamptz not null default clock_timestamp(),
  lease_token uuid,
  lease_expires_at timestamptz,
  last_attempt_at timestamptz,
  last_error text check (last_error is null or last_error ~ '^[a-z][a-z0-9_]{0,63}$'),
  last_status_code integer check (last_status_code is null or last_status_code between 100 and 599),
  created_at timestamptz not null default clock_timestamp(),
  delivered_at timestamptz,
  constraint notification_deliveries_channel_fk foreign key (tenant_id, channel_id)
    references public.notification_channels (tenant_id, id) on delete cascade,
  constraint notification_deliveries_dedupe unique (channel_id, dedupe_key),
  constraint notification_deliveries_lease_state check (
    (status = 'delivering') = (lease_token is not null and lease_expires_at is not null)
  )
);

create index if not exists notification_deliveries_due_idx
  on public.notification_deliveries (next_attempt_at, id) where status = 'pending';
create index if not exists notification_deliveries_lease_idx
  on public.notification_deliveries (lease_expires_at) where status = 'delivering';
create index if not exists notification_deliveries_channel_created_idx
  on public.notification_deliveries (channel_id, created_at desc);
create index if not exists notification_deliveries_tenant_created_idx
  on public.notification_deliveries (tenant_id, created_at desc);
create index if not exists notification_deliveries_terminal_idx
  on public.notification_deliveries (created_at) where status in ('delivered', 'dead');

comment on table public.notification_deliveries is
  'Transactional outbox for tenant alerts. Payloads carry identifiers, severities, categories and counts only; never event content.';

-- ── Access ─────────────────────────────────────────────────────────────────
alter table public.notification_channels enable row level security;
alter table public.notification_deliveries enable row level security;
revoke all on public.notification_channels from public, anon, authenticated;
revoke all on public.notification_deliveries from public, anon, authenticated;
-- Column grants: the ciphertext and key id are never readable by a client.
grant select (
  id, tenant_id, type, name, target_hint, enabled, on_incident_created, incident_min_severity,
  on_runtime_deny_critical, on_approval_requested, on_privacy_blocked_spike,
  privacy_spike_threshold, privacy_spike_window_minutes, created_by, updated_by, created_at,
  updated_at, last_delivery_at, last_delivery_status, last_error, consecutive_failures
) on public.notification_channels to authenticated;
grant select (
  id, tenant_id, channel_id, event_type, status, attempts, max_attempts, next_attempt_at,
  last_attempt_at, last_error, last_status_code, created_at, delivered_at
) on public.notification_deliveries to authenticated;
grant select, insert, update, delete on public.notification_channels to service_role;
grant select, insert, update, delete on public.notification_deliveries to service_role;

drop policy if exists notification_channels_select_admin on public.notification_channels;
create policy notification_channels_select_admin on public.notification_channels
  for select to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'));

drop policy if exists notification_channels_no_client_writes on public.notification_channels;
create policy notification_channels_no_client_writes on public.notification_channels
  as restrictive for all to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.notification_channels;
create policy tenant_identity_access_restrict on public.notification_channels
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

drop policy if exists notification_deliveries_select_admin on public.notification_deliveries;
create policy notification_deliveries_select_admin on public.notification_deliveries
  for select to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'));

drop policy if exists notification_deliveries_no_client_writes on public.notification_deliveries;
create policy notification_deliveries_no_client_writes on public.notification_deliveries
  as restrictive for all to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin'))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.notification_deliveries;
create policy tenant_identity_access_restrict on public.notification_deliveries
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Views and validation helpers ──────────────────────────────────────────
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
      'privacy_spike_window_minutes', c.privacy_spike_window_minutes
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

-- Filters arrive as one complete object; anything else is refused rather than
-- partially applied.
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
    when (select count(*) from jsonb_object_keys(p_filters)) <> 7
      or not (p_filters ?& array['incident_created', 'incident_min_severity', 'runtime_deny_critical',
        'approval_requested', 'privacy_blocked_spike', 'privacy_spike_threshold',
        'privacy_spike_window_minutes']) then false
    when jsonb_typeof(p_filters->'incident_created') <> 'boolean'
      or jsonb_typeof(p_filters->'runtime_deny_critical') <> 'boolean'
      or jsonb_typeof(p_filters->'approval_requested') <> 'boolean'
      or jsonb_typeof(p_filters->'privacy_blocked_spike') <> 'boolean'
      or jsonb_typeof(p_filters->'privacy_spike_threshold') <> 'number'
      or jsonb_typeof(p_filters->'privacy_spike_window_minutes') <> 'number'
      or coalesce(p_filters->>'incident_min_severity', '') not in ('info', 'warning', 'high', 'critical')
      or (p_filters->>'privacy_spike_threshold') !~ '^[0-9]{1,5}$'
      or (p_filters->>'privacy_spike_window_minutes') !~ '^[0-9]{1,4}$' then false
    else (p_filters->>'privacy_spike_threshold')::integer between 1 and 10000
      and (p_filters->>'privacy_spike_window_minutes')::integer between 5 and 1440
      and ((p_filters->>'incident_created')::boolean or (p_filters->>'runtime_deny_critical')::boolean
        or (p_filters->>'approval_requested')::boolean or (p_filters->>'privacy_blocked_spike')::boolean)
  end;
$$;
revoke all on function app.notification_filters_valid(jsonb) from public, anon, authenticated;

-- Locks the actor's live owner/admin membership and the active tenant, the same
-- way update_tenant_workspace_settings does, so a concurrent demotion,
-- suspension or closure cannot commit between the function's check and the
-- mutation.
create or replace function app.lock_notification_admin(p_tenant_id uuid, p_actor_user_id uuid)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if p_tenant_id is null or p_actor_user_id is null then
    raise exception 'invalid_notification_channel' using errcode = '22023';
  end if;
  perform 1
    from public.tenant_members m
    join public.teams team on team.id = m.tenant_id
   where m.tenant_id = p_tenant_id
     and m.user_id = p_actor_user_id
     and m.role in ('owner', 'admin')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
   for share of m, team;
  if not found then
    raise exception 'notification_channel_forbidden' using errcode = '42501';
  end if;
  perform 1 from public.tenants t where t.id = p_tenant_id and t.status = 'active' for share;
  if not found then
    raise exception 'workspace_not_active' using errcode = '55000';
  end if;
end;
$$;
revoke all on function app.lock_notification_admin(uuid, uuid) from public, anon, authenticated;

create or replace function app.audit_notification_channel(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_action text,
  p_detail jsonb
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare v_detail jsonb := p_detail || jsonb_build_object('event_id', gen_random_uuid());
begin
  -- Channel names and destinations are customer content or credentials; the
  -- audit records identifiers, the type, the filter selection and which fields
  -- changed, never a name, URL, recipient or secret.
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, p_action, v_detail);
  insert into public.audit_logs(team_id, tenant_id, user_id, action, verdict)
  values (p_tenant_id, p_tenant_id, p_actor_user_id, p_action, v_detail);
end;
$$;
revoke all on function app.audit_notification_channel(uuid, uuid, text, jsonb) from public, anon, authenticated;

-- ── Service-role RPCs (called only by the notification-channels function) ──
create or replace function public.list_notification_channels(p_tenant_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if p_tenant_id is null then
    raise exception 'invalid_notification_channel' using errcode = '22023';
  end if;
  return jsonb_build_object(
    'channels', coalesce((
      select jsonb_agg(app.notification_channel_view(c) order by c.created_at, c.id)
      from public.notification_channels c where c.tenant_id = p_tenant_id
    ), '[]'::jsonb),
    'recent_deliveries', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', d.id,
        'channel_id', d.channel_id,
        'event_type', d.event_type,
        'status', d.status,
        'attempts', d.attempts,
        'last_error', d.last_error,
        'last_status_code', d.last_status_code,
        'created_at', d.created_at,
        'delivered_at', d.delivered_at
      ) order by d.created_at desc, d.id)
      from (
        select * from public.notification_deliveries
        where tenant_id = p_tenant_id
        order by created_at desc, id
        limit 25
      ) d
    ), '[]'::jsonb)
  );
end;
$$;
revoke all on function public.list_notification_channels(uuid) from public, anon, authenticated;
grant execute on function public.list_notification_channels(uuid) to service_role;

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
    created_by, updated_by
  ) values (
    p_channel_id, p_tenant_id, p_type, btrim(p_name), p_target_ciphertext, p_target_key_id,
    p_target_hint, p_enabled,
    (p_filters->>'incident_created')::boolean, p_filters->>'incident_min_severity',
    (p_filters->>'runtime_deny_critical')::boolean, (p_filters->>'approval_requested')::boolean,
    (p_filters->>'privacy_blocked_spike')::boolean, (p_filters->>'privacy_spike_threshold')::integer,
    (p_filters->>'privacy_spike_window_minutes')::integer,
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

-- NULL arguments mean "unchanged". A replacement destination must keep the
-- channel type, because the ciphertext's associated data binds the type.
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

create or replace function public.delete_notification_channel(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_channel_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare v_type text;
begin
  if p_channel_id is null then
    raise exception 'invalid_notification_channel' using errcode = '22023';
  end if;
  perform app.lock_notification_admin(p_tenant_id, p_actor_user_id);
  delete from public.notification_channels
   where id = p_channel_id and tenant_id = p_tenant_id
  returning type into v_type;
  if v_type is null then
    raise exception 'notification_channel_not_found' using errcode = 'P0002';
  end if;
  perform app.audit_notification_channel(p_tenant_id, p_actor_user_id, 'notification_channel.deleted',
    jsonb_build_object('channel_id', p_channel_id, 'type', v_type));
  return jsonb_build_object('id', p_channel_id, 'deleted', true);
end;
$$;
revoke all on function public.delete_notification_channel(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.delete_notification_channel(uuid, uuid, uuid) to service_role;

-- A test send is an ordinary outbox row with a fixed, content-free payload and
-- a single attempt, so the console reports the receiver's real answer.
create or replace function public.enqueue_notification_test(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_channel_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_type text;
  v_delivery uuid := gen_random_uuid();
begin
  if p_channel_id is null then
    raise exception 'invalid_notification_channel' using errcode = '22023';
  end if;
  perform app.lock_notification_admin(p_tenant_id, p_actor_user_id);
  select type into v_type from public.notification_channels
   where id = p_channel_id and tenant_id = p_tenant_id for share;
  if v_type is null then
    raise exception 'notification_channel_not_found' using errcode = 'P0002';
  end if;
  insert into public.notification_deliveries (id, tenant_id, channel_id, event_type, dedupe_key, payload, max_attempts)
  values (v_delivery, p_tenant_id, p_channel_id, 'notification.test', 'notification.test:' || v_delivery,
    jsonb_build_object('occurred_at', clock_timestamp()), 1);
  perform app.audit_notification_channel(p_tenant_id, p_actor_user_id, 'notification_channel.test_sent',
    jsonb_build_object('channel_id', p_channel_id, 'type', v_type, 'delivery_id', v_delivery));
  return jsonb_build_object('delivery_id', v_delivery, 'channel_id', p_channel_id);
end;
$$;
revoke all on function public.enqueue_notification_test(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.enqueue_notification_test(uuid, uuid, uuid) to service_role;

-- ── Offboarding ────────────────────────────────────────────────────────────
-- Destination credentials are revoked with the workspace, like API keys and
-- SCIM tokens: the moment offboarding starts, channels and their outbox are
-- deleted in the same transaction as the status change.
create or replace function app.purge_notification_channels_on_offboarding()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  delete from public.notification_channels where tenant_id = new.id;
  return new;
end;
$$;
revoke all on function app.purge_notification_channels_on_offboarding() from public, anon, authenticated;

drop trigger if exists tenants_purge_notification_channels on public.tenants;
create trigger tenants_purge_notification_channels
  after update of status on public.tenants
  for each row
  when (new.status in ('closing', 'closed') and old.status is distinct from new.status)
  execute function app.purge_notification_channels_on_offboarding();

create or replace function app.assert_no_notification_offboarding_residue()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if new.status <> 'completed' then return new; end if;
  -- Receipts alone never prove deletion: a completed run with any remaining
  -- channel or delivery for its tenant is refused.
  if exists (select 1 from public.notification_channels where tenant_id = new.tenant_id)
     or exists (select 1 from public.notification_deliveries where tenant_id = new.tenant_id) then
    raise exception 'notification_offboarding_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_no_notification_offboarding_residue() from public, anon, authenticated;

drop trigger if exists offboarding_runs_notification_residue on public.tenant_offboarding_runs;
create trigger offboarding_runs_notification_residue
  before update of status on public.tenant_offboarding_runs
  for each row execute function app.assert_no_notification_offboarding_residue();

-- A channel may only be created for, or moved into, an active tenant.
create or replace function app.notification_channel_tenant_active()
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
    raise exception 'notification_channel_tenant_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.notification_channel_tenant_active() from public, anon, authenticated;

drop trigger if exists notification_channels_tenant_active on public.notification_channels;
create trigger notification_channels_tenant_active
  before insert or update of tenant_id on public.notification_channels
  for each row execute function app.notification_channel_tenant_active();
