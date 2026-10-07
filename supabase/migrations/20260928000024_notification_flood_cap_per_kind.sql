-- Alert outbox: the flood cap no longer lets one kind of alert suppress another.
--
-- app.enqueue_event_notifications (20260926000021) capped each channel at 30
-- queued alerts per minute across ALL event kinds and silently skipped the
-- rest. Anyone holding the tenant's connector key (including a prompt-injected
-- agent that reads it from disk) could send 30 cheap `ask` verdicts and have
-- the critical deny that follows in the same minute never queued for any
-- channel subscribed to both: the alert about the attack was the one dropped.
--
-- The cap is now per channel AND event kind, so a flood of one kind never
-- displaces another. The volume bound stays (at most 30 per kind per minute,
-- four event kinds) and everything else is unchanged.

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
      -- Served by events_privacy_blocked_tenant_created_idx (20260928000021).
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

    -- Flood cap per channel and event kind: a flood of one kind never
    -- displaces another kind's alert.
    continue when (
      select count(*) from (
        select 1 from public.notification_deliveries d
         where d.channel_id = v_channel.id
           and d.event_type = v_kind
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
