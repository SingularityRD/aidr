-- Alert outbox: transactional enqueue from telemetry and the dispatcher RPCs.
--
-- Enqueue
--   An AFTER INSERT trigger on public.events writes one notification_deliveries
--   row per matching, enabled channel of an active tenant, in the SAME
--   transaction as the telemetry row (transactional outbox). An alert is
--   therefore queued if and only if the event it describes was stored; a
--   delivery outage never loses it, it only delays it.
--
--   Event paths (all written by the service-role ingest function):
--     incident.created       events.type in ('incident', 'incident_record') with
--                            status open (or absent) and severity >= the
--                            channel's minimum; deduplicated per incident_id.
--     runtime.deny_critical  runtime_verdict, verdict/decision = deny,
--                            severity = critical.
--     approval.requested     runtime_verdict, verdict/decision = ask (a block
--                            pending OUT-OF-BAND human approval; the alert
--                            carries no approval capability).
--     privacy.blocked_spike  privacy_scan, action = blocked, once the tenant's
--                            blocked sends within the channel's window reach
--                            its threshold; at most one alert per channel per
--                            window bucket.
--
--   The payload is built here from validated identifiers, enums and bounded
--   counts only. Prompts, commands, paths, URLs, matched values, reasons and
--   tool inputs are never copied, whatever the event carries.
--
--   A notification failure must never lose telemetry: the trigger isolates the
--   enqueue in a subtransaction and reports a failure as a WARNING. Each
--   channel is additionally capped at 30 queued alerts per minute so an event
--   flood cannot become a message flood.
--
-- Dispatch
--   claim_notification_deliveries leases due rows with SKIP LOCKED (safe for
--   concurrent dispatchers) and reclaims rows whose lease expired (a crashed
--   dispatcher), so delivery is at-least-once. Every delivery carries its row id
--   as the idempotency key. complete_notification_delivery applies the outcome
--   only while the caller still holds the lease.

-- Severity ordering shared by the filters.
create or replace function app.notification_severity_rank(p_severity text)
returns integer
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select case p_severity when 'info' then 1 when 'warning' then 2 when 'high' then 3
    when 'critical' then 4 else 0 end;
$$;
revoke all on function app.notification_severity_rank(text) from public, anon, authenticated;

create or replace function app.enqueue_event_notifications(p_event public.events)
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
  v_category text;
  v_incident text;
  v_findings integer;
  v_channel record;
  v_dedupe text;
  v_payload jsonb;
  v_blocked integer;
  v_bucket bigint;
  v_queued integer := 0;
  v_rows integer;
  v_ident constant text := '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$';
begin
  if p_event.tenant_id is null then return 0; end if;
  -- The common case (no channels) costs one index probe.
  if not exists (
    select 1 from public.notification_channels c
     where c.tenant_id = p_event.tenant_id and c.enabled
  ) then
    return 0;
  end if;
  if not exists (select 1 from public.tenants t where t.id = p_event.tenant_id and t.status = 'active') then
    return 0;
  end if;

  v_decision := coalesce(p->>'verdict', p->>'decision');
  v_severity := case when p->>'severity' in ('info', 'warning', 'high', 'critical') then p->>'severity' end;
  v_category := case when p->>'matched_threat_id' ~ v_ident then p->>'matched_threat_id' end;

  if p_event.type in ('incident', 'incident_record') then
    if coalesce(p->>'status', 'open') <> 'open' then return 0; end if;
    v_kind := 'incident.created';
    v_incident := case when p->>'incident_id' ~ v_ident then p->>'incident_id' end;
    if jsonb_typeof(p->'findings_count') = 'number' and (p->>'findings_count') ~ '^[0-9]{1,7}$' then
      v_findings := (p->>'findings_count')::integer;
    end if;
  elsif p_event.type = 'runtime_verdict' and v_decision = 'deny' and v_severity = 'critical' then
    v_kind := 'runtime.deny_critical';
  elsif p_event.type = 'runtime_verdict' and v_decision = 'ask' then
    v_kind := 'approval.requested';
  elsif p_event.type = 'privacy_scan' and p->>'action' = 'blocked' then
    v_kind := 'privacy.blocked_spike';
    v_category := 'privacy';
  else
    return 0;
  end if;

  for v_channel in
    select c.id, c.privacy_spike_threshold, c.privacy_spike_window_minutes
      from public.notification_channels c
     where c.tenant_id = p_event.tenant_id
       and c.enabled
       and case v_kind
         when 'incident.created' then c.on_incident_created
           and app.notification_severity_rank(coalesce(v_severity, 'info'))
             >= app.notification_severity_rank(c.incident_min_severity)
         when 'runtime.deny_critical' then c.on_runtime_deny_critical
         when 'approval.requested' then c.on_approval_requested
         when 'privacy.blocked_spike' then c.on_privacy_blocked_spike
         else false
       end
     order by c.id
  loop
    v_blocked := null;
    if v_kind = 'privacy.blocked_spike' then
      v_bucket := floor(extract(epoch from p_event.created_at) / (v_channel.privacy_spike_window_minutes * 60));
      v_dedupe := 'privacy.blocked_spike:' || v_bucket;
      -- One alert per window bucket: once sent, later blocked sends in the same
      -- bucket cost one unique-index probe.
      continue when exists (
        select 1 from public.notification_deliveries d
         where d.channel_id = v_channel.id and d.dedupe_key = v_dedupe
      );
      select count(*) into v_blocked from (
        select 1 from public.events e
         where e.tenant_id = p_event.tenant_id
           and e.type = 'privacy_scan'
           and e.created_at > p_event.created_at - make_interval(mins => v_channel.privacy_spike_window_minutes)
           and e.created_at <= p_event.created_at
           and e.payload->>'action' = 'blocked'
         limit v_channel.privacy_spike_threshold
      ) window_rows;
      continue when v_blocked < v_channel.privacy_spike_threshold;
    elsif v_kind = 'incident.created' and v_incident is not null then
      v_dedupe := 'incident.created:' || lower(v_incident);
    else
      v_dedupe := v_kind || ':' || p_event.id;
    end if;

    -- Flood cap per channel.
    continue when (
      select count(*) from (
        select 1 from public.notification_deliveries d
         where d.channel_id = v_channel.id
           and d.created_at > clock_timestamp() - interval '1 minute'
         limit 30
      ) recent
    ) >= 30;

    v_payload := jsonb_strip_nulls(jsonb_build_object(
      'event_row_id', p_event.id::text,
      'agent_id', p_event.agent_id,
      'occurred_at', p_event.created_at,
      'severity', case when v_kind = 'privacy.blocked_spike' then 'high' else v_severity end,
      'category', v_category,
      'incident_id', v_incident,
      'findings_count', v_findings,
      'blocked_count', v_blocked,
      'window_minutes', case when v_kind = 'privacy.blocked_spike' then v_channel.privacy_spike_window_minutes end
    ));

    insert into public.notification_deliveries (tenant_id, channel_id, event_type, dedupe_key, payload)
    values (p_event.tenant_id, v_channel.id, v_kind, lower(v_dedupe), v_payload)
    on conflict (channel_id, dedupe_key) do nothing;
    get diagnostics v_rows = row_count;
    v_queued := v_queued + v_rows;
  end loop;
  return v_queued;
end;
$$;
revoke all on function app.enqueue_event_notifications(public.events) from public, anon, authenticated;

create or replace function app.enqueue_event_notifications_trigger()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  begin
    perform app.enqueue_event_notifications(new);
  exception when others then
    -- Telemetry is the record of truth; never lose it to an alerting fault.
    raise warning 'notification_enqueue_failed' using detail = sqlstate;
  end;
  return new;
end;
$$;
revoke all on function app.enqueue_event_notifications_trigger() from public, anon, authenticated;

drop trigger if exists events_enqueue_notifications on public.events;
create trigger events_enqueue_notifications
  after insert on public.events
  for each row
  when (
    new.type in ('incident', 'incident_record', 'privacy_scan')
    or (new.type = 'runtime_verdict'
      and coalesce(new.payload->>'verdict', new.payload->>'decision') in ('deny', 'ask'))
  )
  execute function app.enqueue_event_notifications_trigger();

-- ── Dispatcher RPCs (service role only) ────────────────────────────────────
create or replace function public.claim_notification_deliveries(
  p_limit integer,
  p_lease_seconds integer,
  p_delivery_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_claimed jsonb;
begin
  if p_limit is null or p_limit not between 1 and 100
     or p_lease_seconds is null or p_lease_seconds not between 30 and 900 then
    raise exception 'invalid_notification_claim' using errcode = '22023';
  end if;

  -- Retire what can never be sent: a suspended/closing tenant, a disabled
  -- channel (tests excepted), or an expired lease with no attempts left.
  with doomed as (
    select d.id,
      case
        when t.status <> 'active' then 'tenant_inactive'
        when not c.enabled and d.event_type <> 'notification.test' then 'channel_disabled'
        else 'lease_expired'
      end as reason
    from public.notification_deliveries d
    join public.notification_channels c on c.id = d.channel_id
    join public.tenants t on t.id = d.tenant_id
    where (p_delivery_id is null or d.id = p_delivery_id)
      and (d.status = 'pending'
        or (d.status = 'delivering' and d.lease_expires_at <= clock_timestamp()))
      and (t.status <> 'active'
        or (not c.enabled and d.event_type <> 'notification.test')
        or d.attempts >= d.max_attempts)
    order by d.id
    limit 500
    for update of d skip locked
  )
  update public.notification_deliveries d
     set status = 'dead', last_error = doomed.reason, lease_token = null, lease_expires_at = null
    from doomed
   where d.id = doomed.id;

  with picked as (
    select d.id
    from public.notification_deliveries d
    join public.notification_channels c on c.id = d.channel_id
    join public.tenants t on t.id = d.tenant_id
    where (p_delivery_id is null or d.id = p_delivery_id)
      and t.status = 'active'
      and (c.enabled or d.event_type = 'notification.test')
      and d.attempts < d.max_attempts
      and (
        (d.status = 'pending' and d.next_attempt_at <= clock_timestamp())
        or (d.status = 'delivering' and d.lease_expires_at <= clock_timestamp())
      )
    order by d.next_attempt_at, d.id
    limit p_limit
    for update of d skip locked
  ),
  claimed as (
    update public.notification_deliveries d
       set status = 'delivering',
           attempts = d.attempts + 1,
           lease_token = gen_random_uuid(),
           lease_expires_at = clock_timestamp() + make_interval(secs => p_lease_seconds),
           last_attempt_at = clock_timestamp()
      from picked
     where d.id = picked.id
    returning d.*
  )
  select coalesce(jsonb_agg(jsonb_build_object(
      'delivery_id', claimed.id,
      'lease_token', claimed.lease_token,
      'tenant_id', claimed.tenant_id,
      'channel_id', claimed.channel_id,
      'channel_type', c.type,
      'target_ciphertext', c.target_ciphertext,
      'event_type', claimed.event_type,
      'payload', claimed.payload,
      'attempts', claimed.attempts,
      'max_attempts', claimed.max_attempts,
      'created_at', claimed.created_at
    ) order by claimed.next_attempt_at, claimed.id), '[]'::jsonb)
    into v_claimed
    from claimed
    join public.notification_channels c on c.id = claimed.channel_id;
  return v_claimed;
end;
$$;
revoke all on function public.claim_notification_deliveries(integer, integer, uuid) from public, anon, authenticated;
grant execute on function public.claim_notification_deliveries(integer, integer, uuid) to service_role;

-- p_outcome: delivered | retry | failed (permanent). A retry after the last
-- attempt is dead. p_retry_in_seconds comes from the dispatcher's exponential
-- backoff (with jitter and the receiver's Retry-After) and is bounded here.
create or replace function public.complete_notification_delivery(
  p_delivery_id uuid,
  p_lease_token uuid,
  p_outcome text,
  p_error text,
  p_status_code integer,
  p_retry_in_seconds integer
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_delivery public.notification_deliveries;
  v_status text;
  v_error text;
begin
  if p_delivery_id is null or p_lease_token is null
     or p_outcome is null or p_outcome not in ('delivered', 'retry', 'failed')
     or (p_error is not null and p_error !~ '^[a-z][a-z0-9_]{0,63}$')
     or (p_status_code is not null and p_status_code not between 100 and 599) then
    raise exception 'invalid_notification_outcome' using errcode = '22023';
  end if;
  select * into v_delivery from public.notification_deliveries
   where id = p_delivery_id for update;
  if not found or v_delivery.status <> 'delivering' or v_delivery.lease_token is distinct from p_lease_token then
    return jsonb_build_object('status', 'lease_lost');
  end if;

  if p_outcome = 'delivered' then
    v_status := 'delivered';
    v_error := null;
  elsif p_outcome = 'retry' and v_delivery.attempts < v_delivery.max_attempts then
    v_status := 'pending';
    v_error := coalesce(p_error, 'delivery_failed');
  else
    v_status := 'dead';
    v_error := coalesce(p_error, 'delivery_failed');
  end if;

  update public.notification_deliveries set
    status = v_status,
    lease_token = null,
    lease_expires_at = null,
    last_error = v_error,
    last_status_code = p_status_code,
    delivered_at = case when v_status = 'delivered' then clock_timestamp() end,
    next_attempt_at = case when v_status = 'pending'
      then clock_timestamp() + make_interval(secs => least(greatest(coalesce(p_retry_in_seconds, 60), 1), 86400))
      else next_attempt_at end
  where id = p_delivery_id;

  update public.notification_channels set
    last_delivery_at = clock_timestamp(),
    last_delivery_status = case v_status when 'pending' then 'retrying' else v_status end,
    last_error = v_error,
    consecutive_failures = case when v_status = 'delivered' then 0 else consecutive_failures + 1 end
  where id = v_delivery.channel_id;

  return jsonb_build_object('status', v_status, 'attempts', v_delivery.attempts);
end;
$$;
revoke all on function public.complete_notification_delivery(uuid, uuid, text, text, integer, integer)
  from public, anon, authenticated;
grant execute on function public.complete_notification_delivery(uuid, uuid, text, text, integer, integer)
  to service_role;

-- Terminal deliveries are operational ephemera: removed after the tenant's
-- operational_ephemera retention (7 days when no policy row exists), never
-- while a legal hold is active. Bounded per call; the dispatcher calls it.
create or replace function public.prune_notification_deliveries(p_limit integer)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare v_deleted integer;
begin
  if p_limit is null or p_limit not between 1 and 5000 then
    raise exception 'invalid_notification_prune' using errcode = '22023';
  end if;
  with doomed as (
    select d.id
    from public.notification_deliveries d
    left join public.tenant_data_retention_policies p
      on p.tenant_id = d.tenant_id and p.data_class = 'operational_ephemera'
    where d.status in ('delivered', 'dead')
      and d.created_at < clock_timestamp() - make_interval(days => least(coalesce(p.retention_days, 7), 7))
      and not exists (
        select 1 from public.tenant_legal_holds h
         where h.tenant_id = d.tenant_id and h.released_at is null
      )
    order by d.created_at
    limit p_limit
    for update of d skip locked
  )
  delete from public.notification_deliveries d using doomed where d.id = doomed.id;
  get diagnostics v_deleted = row_count;
  return jsonb_build_object('deleted', v_deleted);
end;
$$;
revoke all on function public.prune_notification_deliveries(integer) from public, anon, authenticated;
grant execute on function public.prune_notification_deliveries(integer) to service_role;
