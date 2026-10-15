-- Incident triage for the dashboard's Security incidents page (E1/A2).
--
-- An incident on that page is one incident-like event (a deny/ask runtime
-- verdict, a connector incident or correlated incident record, a plugin scan
-- with findings). Triage adds the SOC workflow on top of the event, without
-- touching the event itself or any enforcement decision:
--
--   status            open -> acknowledged -> resolved | false_positive, and
--                     back to open (reopen)
--   owner             an active workspace member (owner, admin or member)
--   resolution note   required to close (resolved / false_positive)
--   snooze            hides an open or acknowledged incident from the default
--                     queue until a time at most 30 days ahead; closing clears it
--
-- Triage never changes what a connector enforces. Marking an incident a false
-- positive does NOT create a detection exception: the dashboard only offers a
-- pre-filled exception form, which still goes through the detection-exceptions
-- Edge Function (owner/admin, AAL2, 30-day bound, self-defense rules refused).
--
-- Write path: the `incidents` Edge Function (session, identity barrier,
-- owner/admin, AAL2, tenant rate limit) calls update_incident_triage, which
-- re-checks the role and every field under a tenant lock, applies optimistic
-- concurrency (version) and writes the append-only history row and the admin
-- audit row in the same transaction. There is no browser or API-key write path.
--
-- Read path: the same Edge Function lists triage rows and history through the
-- service role for any active member (viewers included); the tables have no
-- browser grant. incident_triage_summary feeds the executive report and the
-- scheduled governance summary (counts only).
--
-- Retention: triage state follows its event (ON DELETE CASCADE, so telemetry
-- retention removes it with the event). The history is security audit and is
-- removed by tenant offboarding (phases 60 and 61 below).

-- ── Tables ─────────────────────────────────────────────────────────────────

create table if not exists public.incident_triage (
  event_id bigint primary key references public.events (id) on delete cascade,
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  status text not null check (status in ('open', 'acknowledged', 'resolved', 'false_positive')),
  owner_user_id uuid,
  resolution_note text,
  snoozed_until timestamptz,
  version integer not null check (version between 1 and 1000000),
  updated_by uuid not null,
  updated_at timestamptz not null,
  created_at timestamptz not null default now(),
  constraint incident_triage_note_text
    check (resolution_note is null or app.ai_governance_text_valid(resolution_note, 1000, true)),
  constraint incident_triage_closed_needs_note
    check (status not in ('resolved', 'false_positive') or resolution_note is not null),
  constraint incident_triage_snooze_open_only
    check (snoozed_until is null or status in ('open', 'acknowledged'))
);

comment on table public.incident_triage is
  'SOC triage state of one incident-like event: status, owner, resolution note, snooze. Written only by update_incident_triage; never changes enforcement.';

create index if not exists incident_triage_tenant_updated_idx
  on public.incident_triage (tenant_id, updated_at desc);
create index if not exists incident_triage_tenant_status_idx
  on public.incident_triage (tenant_id, status);

create table if not exists public.incident_triage_history (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  event_id bigint not null,
  actor_user_id uuid not null,
  from_status text check (from_status is null or from_status in ('open', 'acknowledged', 'resolved', 'false_positive')),
  to_status text not null check (to_status in ('open', 'acknowledged', 'resolved', 'false_positive')),
  from_owner_user_id uuid,
  to_owner_user_id uuid,
  note text check (note is null or app.ai_governance_text_valid(note, 1000, true)),
  snoozed_until timestamptz,
  version integer not null,
  self_closure boolean not null default false,
  created_at timestamptz not null default now()
);

comment on table public.incident_triage_history is
  'Append-only audit trail of incident triage changes (who, when, status/owner/snooze transitions, note). Kept after the event expires; removed by tenant offboarding.';

create index if not exists incident_triage_history_event_idx
  on public.incident_triage_history (tenant_id, event_id, id desc);

alter table public.incident_triage enable row level security;
alter table public.incident_triage_history enable row level security;
revoke all on public.incident_triage from public, anon, authenticated, service_role;
revoke all on public.incident_triage_history from public, anon, authenticated, service_role;
-- The Edge Function reads through the service role; writes are RPC-only.
grant select on public.incident_triage to service_role;
grant select on public.incident_triage_history to service_role;

drop policy if exists incident_triage_member_restrict on public.incident_triage;
create policy incident_triage_member_restrict on public.incident_triage
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.incident_triage;
create policy tenant_identity_access_restrict on public.incident_triage
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

drop policy if exists incident_triage_history_member_restrict on public.incident_triage_history;
create policy incident_triage_history_member_restrict on public.incident_triage_history
  as restrictive for all to authenticated
  using (app.is_tenant_member(tenant_id))
  with check (false);

drop policy if exists tenant_identity_access_restrict on public.incident_triage_history;
create policy tenant_identity_access_restrict on public.incident_triage_history
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

-- ── Incident-like events ───────────────────────────────────────────────────

-- The same event classes the Security incidents page lists.
create or replace function app.incident_like_event(p_type text, p_payload jsonb)
returns boolean
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select p_type in ('incident', 'incident_record', 'plugin_scan')
    or (p_type = 'runtime_verdict' and p_payload->>'verdict' in ('deny', 'ask'))
$$;
revoke all on function app.incident_like_event(text, jsonb) from public, anon, authenticated;

create or replace function app.incident_severity(p_payload jsonb)
returns text
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select case
    when lower(coalesce(p_payload->>'severity', p_payload->'incident'->>'severity', '')) in ('critical', 'high', 'medium', 'warning', 'low', 'info')
      then lower(coalesce(p_payload->>'severity', p_payload->'incident'->>'severity'))
    else 'unknown' end
$$;
revoke all on function app.incident_severity(jsonb) from public, anon, authenticated;

-- ── RPC: update (owner/admin) ──────────────────────────────────────────────

-- p_fields: { status, owner_user_id, resolution_note, snoozed_until } is the
-- complete desired triage state; p_expected_version is the version the caller
-- saw (0 when the incident has never been triaged).
create or replace function public.update_incident_triage(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_event_id bigint,
  p_expected_version integer,
  p_fields jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_role text;
  v_key text;
  v_event record;
  v_existing public.incident_triage;
  v_status text;
  v_owner uuid;
  v_note text;
  v_snooze timestamptz;
  v_version integer;
  v_self boolean;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_event_id is null or p_expected_version is null
     or p_expected_version < 0 or p_fields is null or jsonb_typeof(p_fields) <> 'object' then
    raise exception 'invalid_incident_triage' using errcode = '22023';
  end if;
  for v_key in select jsonb_object_keys(p_fields) loop
    if v_key not in ('status', 'owner_user_id', 'resolution_note', 'snoozed_until') then
      raise exception 'invalid_incident_triage:%', v_key using errcode = '22023';
    end if;
    if jsonb_typeof(p_fields->v_key) not in ('string', 'null') then
      raise exception 'invalid_incident_triage:%', v_key using errcode = '22023';
    end if;
  end loop;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'incident_triage_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':incident-triage', 0));

  select e.id, e.user_id, e.type, e.payload into v_event
    from public.events e
   where e.id = p_event_id and e.tenant_id = p_tenant_id;
  if not found or not app.incident_like_event(v_event.type, v_event.payload) then
    raise exception 'incident_not_found' using errcode = 'P0002';
  end if;

  select * into v_existing from public.incident_triage t
   where t.event_id = p_event_id and t.tenant_id = p_tenant_id
   for update;
  if coalesce(v_existing.version, 0) <> p_expected_version then
    raise exception 'incident_triage_conflict' using errcode = '40001';
  end if;

  v_status := p_fields->>'status';
  if v_status is null or v_status not in ('open', 'acknowledged', 'resolved', 'false_positive') then
    raise exception 'invalid_incident_triage:status' using errcode = '22023';
  end if;

  if p_fields->>'owner_user_id' is not null then
    if p_fields->>'owner_user_id' !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
      raise exception 'invalid_incident_triage:owner_user_id' using errcode = '22023';
    end if;
    v_owner := (p_fields->>'owner_user_id')::uuid;
    -- Reassigning to someone who has since left keeps nothing stale: the owner
    -- must be an active, non-viewer member at the time of every change.
    if not exists (
      select 1 from public.tenant_members m
       where m.tenant_id = p_tenant_id and m.user_id = v_owner
         and m.role in ('owner', 'admin', 'member')
         and (m.expires_at is null or m.expires_at > v_now)) then
      raise exception 'incident_owner_not_member' using errcode = '22023';
    end if;
  end if;

  v_note := nullif(btrim(coalesce(p_fields->>'resolution_note', '')), '');
  if v_note is not null and not app.ai_governance_text_valid(v_note, 1000, true) then
    raise exception 'invalid_incident_triage:resolution_note' using errcode = '22023';
  end if;
  if v_status in ('resolved', 'false_positive') and v_note is null then
    raise exception 'incident_resolution_note_required' using errcode = '22023';
  end if;

  if p_fields->>'snoozed_until' is not null then
    begin
      v_snooze := (p_fields->>'snoozed_until')::timestamptz;
    exception when others then
      raise exception 'invalid_incident_triage:snoozed_until' using errcode = '22023';
    end;
    if v_status not in ('open', 'acknowledged') then
      raise exception 'incident_snooze_closed' using errcode = '22023';
    end if;
    if v_snooze <= v_now + interval '5 minutes' or v_snooze > v_now + interval '30 days' then
      raise exception 'invalid_incident_triage:snoozed_until' using errcode = '22023';
    end if;
  end if;

  if v_existing.event_id is not null
     and v_existing.status = v_status
     and v_existing.owner_user_id is not distinct from v_owner
     and v_existing.resolution_note is not distinct from v_note
     and v_existing.snoozed_until is not distinct from v_snooze then
    raise exception 'incident_triage_unchanged' using errcode = '22023';
  end if;

  v_version := coalesce(v_existing.version, 0) + 1;
  -- Closing an incident raised by one's own agent is allowed (single-admin
  -- workspaces) but recorded as such in both audit trails.
  v_self := v_status in ('resolved', 'false_positive') and v_event.user_id = p_actor_user_id;

  insert into public.incident_triage as t (
    event_id, tenant_id, status, owner_user_id, resolution_note, snoozed_until,
    version, updated_by, updated_at, created_at
  ) values (
    p_event_id, p_tenant_id, v_status, v_owner, v_note, v_snooze,
    v_version, p_actor_user_id, v_now, v_now
  )
  on conflict (event_id) do update set
    status = excluded.status,
    owner_user_id = excluded.owner_user_id,
    resolution_note = excluded.resolution_note,
    snoozed_until = excluded.snoozed_until,
    version = excluded.version,
    updated_by = excluded.updated_by,
    updated_at = excluded.updated_at;

  insert into public.incident_triage_history (
    tenant_id, event_id, actor_user_id, from_status, to_status, from_owner_user_id, to_owner_user_id,
    note, snoozed_until, version, self_closure, created_at
  ) values (
    p_tenant_id, p_event_id, p_actor_user_id,
    case when v_existing.event_id is null then null else v_existing.status end,
    v_status, v_existing.owner_user_id, v_owner,
    case when v_note is distinct from v_existing.resolution_note then v_note end,
    v_snooze, v_version, v_self, v_now
  );

  -- The administrative audit row carries no note text.
  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'incident.triaged',
    jsonb_build_object('event_id', p_event_id, 'event_type', v_event.type,
      'from_status', case when v_existing.event_id is null then 'untriaged' else v_existing.status end,
      'to_status', v_status, 'owner_changed', v_owner is distinct from v_existing.owner_user_id,
      'snoozed', v_snooze is not null, 'note_changed', v_note is distinct from v_existing.resolution_note,
      'self_closure', v_self, 'version', v_version));

  return jsonb_build_object(
    'event_id', p_event_id, 'status', v_status, 'owner_user_id', v_owner,
    'resolution_note', v_note, 'snoozed_until', v_snooze, 'version', v_version,
    'updated_by', p_actor_user_id, 'updated_at', v_now, 'self_closure', v_self);
end;
$$;
revoke all on function public.update_incident_triage(uuid, uuid, bigint, integer, jsonb) from public, anon, authenticated;
grant execute on function public.update_incident_triage(uuid, uuid, bigint, integer, jsonb) to service_role;

-- ── RPC: counts for the executive report and the governance summary ────────

-- Incident-like events created in [p_from, p_to) by effective triage status
-- (no triage row = open). Counts only; no payloads, notes or identities.
create or replace function public.incident_triage_summary(p_tenant_id uuid, p_from timestamptz, p_to timestamptz)
returns jsonb
language sql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
  with incidents as (
    select coalesce(t.status, 'open') as status,
           t.owner_user_id,
           t.snoozed_until,
           app.incident_severity(e.payload) as severity,
           t.updated_at,
           e.created_at
      from public.events e
      left join public.incident_triage t on t.event_id = e.id and t.tenant_id = e.tenant_id
     where e.tenant_id = p_tenant_id
       and e.created_at >= p_from and e.created_at < p_to
       and e.type in ('incident', 'incident_record', 'plugin_scan', 'runtime_verdict')
       and app.incident_like_event(e.type, e.payload)
  )
  select jsonb_build_object(
    'total', count(*),
    'open', count(*) filter (where status = 'open'),
    'acknowledged', count(*) filter (where status = 'acknowledged'),
    'resolved', count(*) filter (where status = 'resolved'),
    'false_positive', count(*) filter (where status = 'false_positive'),
    'snoozed', count(*) filter (where status in ('open', 'acknowledged') and snoozed_until > now()),
    'unassigned_active', count(*) filter (where status in ('open', 'acknowledged') and owner_user_id is null),
    'active_critical', count(*) filter (where status in ('open', 'acknowledged') and severity = 'critical'),
    'active_high', count(*) filter (where status in ('open', 'acknowledged') and severity = 'high'),
    'median_close_seconds', (
      select percentile_cont(0.5) within group (order by extract(epoch from (i.updated_at - i.created_at)))
        from incidents i where i.status in ('resolved', 'false_positive') and i.updated_at >= i.created_at)
  )
  from incidents
$$;
revoke all on function public.incident_triage_summary(uuid, timestamptz, timestamptz) from public, anon, authenticated;
grant execute on function public.incident_triage_summary(uuid, timestamptz, timestamptz) to service_role;

-- ── Offboarding ────────────────────────────────────────────────────────────

-- Same seeding/backfill/dispatch pattern as 20261009000100. Triage state goes
-- first (phase 60); the history (security_audit) after it (phase 61).
create or replace function app.seed_incident_triage_offboarding_phases()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  select new.id, c.phase_order, c.phase, c.data_class, 'delete_records', p.retention_days,
    new.requested_at + make_interval(days => p.retention_days)
  from (values (60, 'incident_triage', 'telemetry'), (61, 'incident_triage_history', 'security_audit'))
    c(phase_order, phase, data_class)
  join public.tenant_data_retention_policies p
    on p.tenant_id = new.tenant_id and p.data_class = c.data_class;
  if (select count(*) from public.tenant_offboarding_phase_receipts r
       where r.run_id = new.id and r.phase in ('incident_triage', 'incident_triage_history')) <> 2 then
    raise exception 'incident_triage_retention_policy_missing' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.seed_incident_triage_offboarding_phases() from public, anon, authenticated, service_role;
drop trigger if exists tenant_offboarding_incident_triage_phases on public.tenant_offboarding_runs;
create trigger tenant_offboarding_incident_triage_phases after insert on public.tenant_offboarding_runs
for each row execute function app.seed_incident_triage_offboarding_phases();

insert into public.tenant_offboarding_phase_receipts
  (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at, status, attempts, completed_at)
select r.id, c.phase_order, c.phase, c.data_class, 'delete_records', p.retention_days,
  r.requested_at + make_interval(days => p.retention_days),
  case when r.status = 'completed' then 'completed' else 'pending' end,
  case when r.status = 'completed' then 1 else 0 end,
  case when r.status = 'completed' then now() else null end
from public.tenant_offboarding_runs r
cross join (values (60, 'incident_triage', 'telemetry'), (61, 'incident_triage_history', 'security_audit'))
  c(phase_order, phase, data_class)
join public.tenant_data_retention_policies p on p.tenant_id = r.tenant_id and p.data_class = c.data_class
on conflict do nothing;

do $migration$
declare
  v_definition text;
  v_old text := 'when ''rate_limits'' then ''public.rate_limits''';
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure) into v_definition;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_incident_triage_offboarding_definition';
  end if;
  execute replace(v_definition, v_old,
    'when ''incident_triage'' then ''public.incident_triage''
    when ''incident_triage_history'' then ''public.incident_triage_history''
    ' || v_old);
end;
$migration$;
