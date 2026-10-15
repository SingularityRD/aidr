-- C10: per-connector heartbeat and "hook missing / disabled / untrusted" alerts.
--
-- A hook that a user deletes from ~/.claude/settings.json, disables with the
-- editor command, or that Codex never trusted does not run, so it cannot say
-- that it stopped. `aidr heartbeat` (packages/cli, run hourly by the
-- per-machine installers and after setup) measures every agent host on the
-- device from the outside and reports one state per connector to the
-- `connector-heartbeat` Edge Function, authenticated by the device's tenant
-- API key. This migration stores the latest state per agent and connector and
-- raises an alert when a connector that was protected stops being protected.
--
-- States (what the device measured, never inferred server-side)
--   protected       the AIDR hook is registered where the host loads it and,
--                   for Codex, trusted (or deployed through the host's
--                   system-wide managed configuration, which the host trusts)
--   hook_missing    the host is installed, the AIDR registration is gone
--   hook_disabled   the registration is present but switched off (Claude
--                   Code `disableAllHooks`, Codex per-hook `enabled = false`,
--                   the editor "Disable protection" command)
--   hook_untrusted  Codex: the hook is registered but has no recorded trust,
--                   so Codex drops it silently (fails open)
--   hook_broken     the registration is present but unusable or unreadable
--
-- Alerts ride on the existing outbox and on the channel filter that already
-- watches agent health (`on_agent_offline`, 20260928000001): a heartbeat that
-- stops arriving raises `agent.offline` through agents.last_seen, which this
-- RPC refreshes, and a connector that leaves `protected` raises the new
-- `agent.unprotected` event once per (agent, connector, state, episode). A
-- rising count of blocked "Disable protection" attempts on a policy-locked
-- editor raises it too (state `disable_attempted`). A connector first
-- reported unprotected (never seen protected) is a coverage gap shown on the
-- device, not an alert, so a rollout does not page anyone.
--
-- The payload is identifiers and enums only. The table is bounded (one row
-- per agent and connector) and is removed with its agent (tenant offboarding
-- deletes agents).

create table if not exists public.connector_heartbeats (
  tenant_id uuid not null,
  agent_id uuid not null,
  connector text not null
    check (connector in ('claude-code', 'cursor', 'vscode', 'openclaw', 'opencode', 'codex')),
  state text not null
    check (state in ('protected', 'hook_missing', 'hook_disabled', 'hook_untrusted', 'hook_broken')),
  enforcement text not null default 'user_config'
    check (enforcement in ('machine_policy', 'user_config', 'none')),
  protection_locked boolean not null default false,
  disable_attempts integer not null default 0 check (disable_attempts between 0 and 1000000),
  host_version text check (host_version is null or host_version ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$'),
  reported_at timestamptz not null default clock_timestamp(),
  state_since timestamptz not null default clock_timestamp(),
  primary key (agent_id, connector),
  constraint connector_heartbeats_agent_fk foreign key (tenant_id, agent_id)
    references public.agents (tenant_id, id) on delete cascade
);

create index if not exists connector_heartbeats_tenant_state_idx
  on public.connector_heartbeats (tenant_id, state);

comment on table public.connector_heartbeats is
  'Latest measured hook state per agent and connector (aidr heartbeat). Enums and counts only; written by record_connector_heartbeat.';

alter table public.connector_heartbeats enable row level security;
revoke all on public.connector_heartbeats from public, anon, authenticated;
grant select on public.connector_heartbeats to authenticated;
grant select, insert, update, delete on public.connector_heartbeats to service_role;

drop policy if exists connector_heartbeats_select_member on public.connector_heartbeats;
create policy connector_heartbeats_select_member on public.connector_heartbeats
  for select to authenticated
  using (app.is_tenant_member(tenant_id));

drop policy if exists connector_heartbeats_no_client_writes on public.connector_heartbeats;
create policy connector_heartbeats_no_client_writes on public.connector_heartbeats
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.connector_heartbeats;
create policy tenant_identity_access_restrict on public.connector_heartbeats
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

alter table public.notification_deliveries
  drop constraint if exists notification_deliveries_event_type_check;
alter table public.notification_deliveries
  add constraint notification_deliveries_event_type_check check (event_type in (
    'incident.created', 'runtime.deny_critical', 'approval.requested',
    'privacy.blocked_spike', 'notification.test',
    'agent.offline', 'agent.recovered', 'agent.unprotected',
    'governance.review_overdue', 'governance.intake_requested', 'governance.change_pending',
    'governance.exception_expiring', 'governance.digest'
  ));

-- Records one device report. Called by the connector-heartbeat Edge Function
-- after it authenticated the tenant API key and resolved the agent; the
-- function re-checks the agent and tenant here under a row lock.
create or replace function public.record_connector_heartbeat(
  p_tenant_id uuid,
  p_agent_id uuid,
  p_reports jsonb
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_report jsonb;
  v_connector text;
  v_state text;
  v_enforcement text;
  v_locked boolean;
  v_attempts integer;
  v_version text;
  v_prev public.connector_heartbeats;
  v_since timestamptz;
  v_alert text;
  v_channel record;
  v_seen text[] := array[]::text[];
  v_recorded integer := 0;
  v_alerts integer := 0;
begin
  if p_tenant_id is null or p_agent_id is null or jsonb_typeof(p_reports) is distinct from 'array'
     or jsonb_array_length(p_reports) not between 1 and 6 then
    raise exception 'invalid_connector_heartbeat' using errcode = '22023';
  end if;
  perform 1 from public.tenants t where t.id = p_tenant_id and t.status = 'active';
  if not found then raise exception 'connector_heartbeat_tenant_inactive' using errcode = '42501'; end if;
  perform 1 from public.agents a where a.tenant_id = p_tenant_id and a.id = p_agent_id for update;
  if not found then raise exception 'connector_heartbeat_agent_unknown' using errcode = '42501'; end if;

  for v_report in select value from jsonb_array_elements(p_reports) loop
    if jsonb_typeof(v_report) is distinct from 'object' then
      raise exception 'invalid_connector_heartbeat' using errcode = '22023';
    end if;
    v_connector := v_report->>'connector';
    v_state := v_report->>'state';
    v_enforcement := coalesce(v_report->>'enforcement', 'user_config');
    if v_connector is null or v_connector = any (v_seen)
       or v_connector not in ('claude-code', 'cursor', 'vscode', 'openclaw', 'opencode', 'codex')
       or v_state is null
       or v_state not in ('protected', 'hook_missing', 'hook_disabled', 'hook_untrusted', 'hook_broken')
       or v_enforcement not in ('machine_policy', 'user_config', 'none')
       or coalesce(jsonb_typeof(v_report->'protection_locked'), 'boolean') <> 'boolean'
       or coalesce(jsonb_typeof(v_report->'disable_attempts'), 'number') <> 'number'
       or coalesce(v_report->>'disable_attempts', '0') !~ '^[0-9]{1,7}$'
       or (v_report->>'host_version') !~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$' then
      raise exception 'invalid_connector_heartbeat' using errcode = '22023';
    end if;
    v_seen := v_seen || v_connector;
    v_locked := coalesce((v_report->>'protection_locked')::boolean, false);
    v_attempts := least(coalesce((v_report->>'disable_attempts')::integer, 0), 1000000);
    v_version := v_report->>'host_version';

    select * into v_prev from public.connector_heartbeats h
     where h.agent_id = p_agent_id and h.connector = v_connector for update;
    v_since := case when found and v_prev.state = v_state then v_prev.state_since else v_now end;
    v_alert := null;
    if found and v_prev.state = 'protected' and v_state <> 'protected' then
      v_alert := v_state;
    elsif found and v_attempts > v_prev.disable_attempts then
      v_alert := 'disable_attempted';
    end if;

    insert into public.connector_heartbeats as h
      (tenant_id, agent_id, connector, state, enforcement, protection_locked, disable_attempts,
       host_version, reported_at, state_since)
    values (p_tenant_id, p_agent_id, v_connector, v_state, v_enforcement, v_locked, v_attempts,
       v_version, v_now, v_since)
    on conflict (agent_id, connector) do update set
      state = excluded.state, enforcement = excluded.enforcement,
      protection_locked = excluded.protection_locked, disable_attempts = excluded.disable_attempts,
      host_version = excluded.host_version, reported_at = excluded.reported_at,
      state_since = excluded.state_since;
    v_recorded := v_recorded + 1;

    continue when v_alert is null;
    for v_channel in
      select c.id from public.notification_channels c
       where c.tenant_id = p_tenant_id and c.enabled and c.on_agent_offline
       order by c.id
    loop
      if app.enqueue_channel_notification(p_tenant_id, v_channel.id, 'agent.unprotected',
           'agent.unprotected:' || p_agent_id || ':' || v_connector || ':' || v_alert || ':'
             || case when v_alert = 'disable_attempted' then v_attempts::text
                     else floor(extract(epoch from v_since))::bigint::text end,
           jsonb_build_object(
             'agent_id', p_agent_id::text,
             'occurred_at', v_now,
             'severity', 'high',
             'category', v_connector,
             'connector_state', v_alert)) = 'queued' then
        v_alerts := v_alerts + 1;
      end if;
    end loop;
  end loop;

  -- A heartbeat proves the device is alive: agent.offline then means the
  -- heartbeat itself stopped (machine off, task removed, AIDR uninstalled).
  update public.agents set last_seen = greatest(last_seen, v_now)
   where tenant_id = p_tenant_id and id = p_agent_id;

  return jsonb_build_object('recorded', v_recorded, 'alerts', v_alerts);
end;
$$;
revoke all on function public.record_connector_heartbeat(uuid, uuid, jsonb) from public, anon, authenticated;
grant execute on function public.record_connector_heartbeat(uuid, uuid, jsonb) to service_role;
