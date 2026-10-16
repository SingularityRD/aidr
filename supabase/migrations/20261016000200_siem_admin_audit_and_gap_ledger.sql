-- SIEM forwarding, follow-up to 20261014000130_siem_forwarding.sql:
--
-- 1. Admin audit forwarding. Administrative actions and sign-ins are recorded
--    in public.admin_audit_logs, never in public.events, so a SOC never saw
--    them. A destination may now opt in (forward_admin_audit, default false,
--    exposed as filters.admin_audit) to kind 'admin_audit': an AFTER INSERT
--    trigger on admin_audit_logs (tenant rows only) enqueues an allow-listed
--    projection (audit row id, action identifier, actor and target user ids,
--    time) under its own dedupe key (destination_id, audit_row_id); events and
--    audit rows have independent id sequences, so event_row_id cannot carry it.
--    The detail jsonb (free text) is never copied. Same fault isolation and
--    bounded backlog as the events trigger.
--
-- 2. Enqueue gap ledger. A forwarding fault never loses telemetry, but it used
--    to leave only a server WARNING. Each failure is now counted durably in
--    public.siem_enqueue_failures (tenant, UTC day, source table, SQLSTATE):
--    one row per combination, so the ledger stays bounded however many events
--    fail, RLS on, pruned with the operational_ephemera retention. The SIEM
--    page shows "N events could not be queued" from list_siem_destinations.
--
-- 3. prune_siem_deliveries honours the tenant's operational_ephemera retention
--    (7 days when no policy row exists) instead of capping it at 7 days.

-- ── Destinations: admin audit opt-in ──────────────────────────────────────
alter table public.siem_destinations
  add column if not exists forward_admin_audit boolean not null default false;

alter table public.siem_destinations drop constraint if exists siem_destinations_selects_an_event;
alter table public.siem_destinations add constraint siem_destinations_selects_an_event check (
  forward_incidents or cardinality(forward_decisions) > 0 or forward_browser or forward_admin_audit
);

grant select (forward_admin_audit) on public.siem_destinations to authenticated;

-- ── Deliveries: admin_audit kind with its own dedupe key ──────────────────
alter table public.siem_deliveries add column if not exists audit_row_id bigint;

alter table public.siem_deliveries drop constraint if exists siem_deliveries_kind_check;
alter table public.siem_deliveries add constraint siem_deliveries_kind_check
  check (kind in ('incident', 'decision', 'browser', 'admin_audit', 'test'));

-- Exactly one source key per kind: events rows carry event_row_id, admin audit
-- rows carry audit_row_id, test sends carry neither.
alter table public.siem_deliveries drop constraint if exists siem_deliveries_test_shape;
alter table public.siem_deliveries drop constraint if exists siem_deliveries_source_shape;
alter table public.siem_deliveries add constraint siem_deliveries_source_shape check (
  case kind
    when 'test' then event_row_id is null and audit_row_id is null
    when 'admin_audit' then event_row_id is null and audit_row_id is not null
    else event_row_id is not null and audit_row_id is null
  end
);

create unique index if not exists siem_deliveries_audit_unique
  on public.siem_deliveries (destination_id, audit_row_id);

grant select (audit_row_id) on public.siem_deliveries to authenticated;

-- ── Enqueue gap ledger ────────────────────────────────────────────────────
create table if not exists public.siem_enqueue_failures (
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  day date not null,
  source text not null check (source in ('events', 'admin_audit_logs')),
  sqlstate text not null check (sqlstate ~ '^[0-9A-Z]{5}$'),
  failures bigint not null default 0 check (failures >= 0),
  first_failed_at timestamptz not null default clock_timestamp(),
  last_failed_at timestamptz not null default clock_timestamp(),
  last_source_row_id bigint,
  primary key (tenant_id, day, source, sqlstate)
);
create index if not exists siem_enqueue_failures_last_idx
  on public.siem_enqueue_failures (last_failed_at);

comment on table public.siem_enqueue_failures is
  'Count of telemetry/admin-audit rows that could not be queued for SIEM forwarding, per tenant, UTC day, source and SQLSTATE. Bounded by construction; pruned with operational_ephemera retention.';

alter table public.siem_enqueue_failures enable row level security;
revoke all on public.siem_enqueue_failures from public, anon, authenticated;
grant select (tenant_id, day, source, sqlstate, failures, first_failed_at, last_failed_at, last_source_row_id)
  on public.siem_enqueue_failures to authenticated;
grant select, insert, update, delete on public.siem_enqueue_failures to service_role;

drop policy if exists siem_enqueue_failures_select_admin on public.siem_enqueue_failures;
create policy siem_enqueue_failures_select_admin on public.siem_enqueue_failures
  for select to authenticated using (app.is_tenant_member_with_role(tenant_id, 'admin'));
drop policy if exists siem_enqueue_failures_no_client_writes on public.siem_enqueue_failures;
create policy siem_enqueue_failures_no_client_writes on public.siem_enqueue_failures
  as restrictive for all to authenticated
  using (app.is_tenant_member_with_role(tenant_id, 'admin')) with check (false);
drop policy if exists tenant_identity_access_restrict on public.siem_enqueue_failures;
create policy tenant_identity_access_restrict on public.siem_enqueue_failures
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));

create or replace function app.record_siem_enqueue_failure(
  p_tenant_id uuid,
  p_source text,
  p_source_row_id bigint,
  p_sqlstate text
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  -- An offboarding workspace keeps no SIEM state (assert_no_siem_offboarding_residue).
  if p_tenant_id is null
     or not exists (select 1 from public.tenants t where t.id = p_tenant_id and t.status = 'active') then
    return;
  end if;
  insert into public.siem_enqueue_failures as f
    (tenant_id, day, source, sqlstate, failures, last_source_row_id)
  values (
    p_tenant_id, (clock_timestamp() at time zone 'UTC')::date, p_source,
    case when p_sqlstate ~ '^[0-9A-Z]{5}$' then p_sqlstate else 'XX000' end, 1, p_source_row_id
  )
  on conflict (tenant_id, day, source, sqlstate) do update
    set failures = f.failures + 1,
        last_failed_at = clock_timestamp(),
        last_source_row_id = excluded.last_source_row_id;
end;
$$;
revoke all on function app.record_siem_enqueue_failure(uuid, text, bigint, text) from public, anon, authenticated;

-- Shared failure path of both enqueue triggers: count the gap durably, then
-- warn. Recording is itself isolated so it can never cost the source row.
create or replace function app.siem_enqueue_failed(
  p_tenant_id uuid,
  p_source text,
  p_source_row_id bigint,
  p_sqlstate text
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  begin
    perform app.record_siem_enqueue_failure(p_tenant_id, p_source, p_source_row_id, p_sqlstate);
  exception when others then
    raise warning 'siem_enqueue_failure_unrecorded' using detail = sqlstate;
  end;
  raise warning 'siem_enqueue_failed' using detail = p_sqlstate;
end;
$$;
revoke all on function app.siem_enqueue_failed(uuid, text, bigint, text) from public, anon, authenticated;

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
    -- Telemetry is the record of truth; never lose it to a forwarding fault,
    -- but never hide the gap either.
    perform app.siem_enqueue_failed(new.tenant_id, 'events', new.id, sqlstate);
  end;
  return new;
end;
$$;
revoke all on function app.enqueue_event_siem_trigger() from public, anon, authenticated;

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
      'admin_audit', d.forward_admin_audit,
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

-- Tenant-wide count of rows that could not be queued (within retention).
create or replace function app.siem_enqueue_failure_summary(p_tenant_id uuid)
returns jsonb
language sql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
  select jsonb_build_object(
    'count', coalesce(sum(f.failures), 0)::bigint,
    'last_failed_at', max(f.last_failed_at)
  )
  from public.siem_enqueue_failures f
  where f.tenant_id = p_tenant_id;
$$;
revoke all on function app.siem_enqueue_failure_summary(uuid) from public, anon, authenticated;

-- Filters arrive as one object: incidents, decisions, browser, min_severity and
-- the optional admin_audit (absent: false on create, unchanged on update).
create or replace function app.siem_filters_valid(p_filters jsonb)
returns boolean
language sql
immutable
set search_path = pg_catalog, pg_temp
as $$
  select case
    when p_filters is null or jsonb_typeof(p_filters) <> 'object' then false
    when exists (select 1 from jsonb_object_keys(p_filters) k
                  where k not in ('incidents', 'decisions', 'browser', 'admin_audit', 'min_severity'))
      or not (p_filters ?& array['incidents', 'decisions', 'browser', 'min_severity']) then false
    when jsonb_typeof(p_filters->'incidents') <> 'boolean'
      or jsonb_typeof(p_filters->'browser') <> 'boolean'
      or (p_filters ? 'admin_audit' and jsonb_typeof(p_filters->'admin_audit') <> 'boolean')
      or jsonb_typeof(p_filters->'decisions') <> 'array'
      or coalesce(p_filters->>'min_severity', '') not in ('info', 'warning', 'high', 'critical') then false
    when jsonb_array_length(p_filters->'decisions') > 3
      or exists (select 1 from jsonb_array_elements(p_filters->'decisions') e
                  where jsonb_typeof(e) <> 'string' or e #>> '{}' not in ('allow', 'ask', 'deny'))
      or (select count(distinct e #>> '{}') from jsonb_array_elements(p_filters->'decisions') e)
           <> jsonb_array_length(p_filters->'decisions') then false
    else (p_filters->>'incidents')::boolean or (p_filters->>'browser')::boolean
      or coalesce((p_filters->>'admin_audit')::boolean, false)
      or jsonb_array_length(p_filters->'decisions') > 0
  end;
$$;
revoke all on function app.siem_filters_valid(jsonb) from public, anon, authenticated;

-- ── Admin audit enqueue ───────────────────────────────────────────────────
-- Allow-listed projection: identifiers only. `detail` is free text and is
-- never copied; an action that is not a plain identifier is dropped.
create or replace function app.siem_admin_audit_payload(p_row public.admin_audit_logs)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  return jsonb_strip_nulls(jsonb_build_object(
    'audit_row_id', p_row.id::text,
    'kind', 'admin_audit',
    'type', 'admin_audit',
    'occurred_at', p_row.created_at,
    'action', case when p_row.action ~ '^[A-Za-z][A-Za-z0-9_.:-]{0,95}$' then p_row.action end,
    'actor_user_id', p_row.actor_user_id,
    'target_user_id', p_row.target_user_id
  ));
end;
$$;
revoke all on function app.siem_admin_audit_payload(public.admin_audit_logs) from public, anon, authenticated;

create or replace function app.enqueue_admin_audit_siem(p_row public.admin_audit_logs)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_payload jsonb;
  v_destination record;
  v_queued integer := 0;
  v_rows integer;
begin
  if p_row.tenant_id is null then return 0; end if;
  if not exists (select 1 from public.siem_destinations d
                  where d.tenant_id = p_row.tenant_id and d.enabled and d.forward_admin_audit) then
    return 0;
  end if;
  if not exists (select 1 from public.tenants t where t.id = p_row.tenant_id and t.status = 'active') then
    return 0;
  end if;

  for v_destination in
    select d.id
      from public.siem_destinations d
     where d.tenant_id = p_row.tenant_id and d.enabled and d.forward_admin_audit
     order by d.id
  loop
    -- Same bounded backlog as events: overflow is counted, never hidden.
    if exists (
      select 1 from public.siem_deliveries x
       where x.destination_id = v_destination.id and x.status in ('pending', 'delivering')
       order by x.id offset 49999 limit 1
    ) then
      update public.siem_destinations set dropped_events = dropped_events + 1 where id = v_destination.id;
      continue;
    end if;
    v_payload := coalesce(v_payload, app.siem_admin_audit_payload(p_row));
    insert into public.siem_deliveries (tenant_id, destination_id, event_row_id, audit_row_id, kind, payload)
    values (p_row.tenant_id, v_destination.id, null, p_row.id, 'admin_audit', v_payload)
    on conflict (destination_id, audit_row_id) do nothing;
    get diagnostics v_rows = row_count;
    v_queued := v_queued + v_rows;
  end loop;
  return v_queued;
end;
$$;
revoke all on function app.enqueue_admin_audit_siem(public.admin_audit_logs) from public, anon, authenticated;

create or replace function app.enqueue_admin_audit_siem_trigger()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  begin
    perform app.enqueue_admin_audit_siem(new);
  exception when others then
    -- The audit row is the record of truth; never lose it to a forwarding fault.
    perform app.siem_enqueue_failed(new.tenant_id, 'admin_audit_logs', new.id, sqlstate);
  end;
  return new;
end;
$$;
revoke all on function app.enqueue_admin_audit_siem_trigger() from public, anon, authenticated;

drop trigger if exists admin_audit_logs_enqueue_siem on public.admin_audit_logs;
create trigger admin_audit_logs_enqueue_siem
  after insert on public.admin_audit_logs
  for each row
  when (new.tenant_id is not null)
  execute function app.enqueue_admin_audit_siem_trigger();

-- ── Retention: the tenant's operational_ephemera retention, default 7 days ─
create or replace function public.prune_siem_deliveries(p_limit integer)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_deleted integer;
  v_failures integer;
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
      and x.created_at < clock_timestamp() - make_interval(days => coalesce(p.retention_days, 7))
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

  with doomed as (
    select f.tenant_id, f.day, f.source, f.sqlstate
    from public.siem_enqueue_failures f
    left join public.tenant_data_retention_policies p
      on p.tenant_id = f.tenant_id and p.data_class = 'operational_ephemera'
    where f.last_failed_at < clock_timestamp() - make_interval(days => coalesce(p.retention_days, 7))
      and not exists (
        select 1 from public.tenant_legal_holds h
         where h.tenant_id = f.tenant_id and h.released_at is null
      )
    order by f.last_failed_at
    limit p_limit
    for update of f skip locked
  )
  delete from public.siem_enqueue_failures f using doomed
   where f.tenant_id = doomed.tenant_id and f.day = doomed.day
     and f.source = doomed.source and f.sqlstate = doomed.sqlstate;
  get diagnostics v_failures = row_count;
  return jsonb_build_object('deleted', v_deleted, 'enqueue_failures_deleted', v_failures);
end;
$$;
revoke all on function public.prune_siem_deliveries(integer) from public, anon, authenticated;
grant execute on function public.prune_siem_deliveries(integer) to service_role;

-- ── Management RPCs ───────────────────────────────────────────────────────
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
    'enqueue_failures', app.siem_enqueue_failure_summary(p_tenant_id),
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
    forward_incidents, forward_decisions, forward_browser, forward_admin_audit, min_severity,
    created_by, updated_by
  ) values (
    p_destination_id, p_tenant_id, p_provider, p_format, btrim(p_name), p_config_ciphertext,
    p_config_key_id, p_target_hint, p_enabled,
    (p_filters->>'incidents')::boolean, app.siem_filter_decisions(p_filters),
    (p_filters->>'browser')::boolean, coalesce((p_filters->>'admin_audit')::boolean, false),
    p_filters->>'min_severity', p_actor_user_id, p_actor_user_id
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

-- NULL arguments mean "unchanged"; so does a filters object without admin_audit.
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
    forward_admin_audit = coalesce((p_filters->>'admin_audit')::boolean, d.forward_admin_audit),
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

-- ── Offboarding: the ledger goes with the workspace ───────────────────────
create or replace function app.purge_siem_enqueue_failures_on_offboarding()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  delete from public.siem_enqueue_failures where tenant_id = new.id;
  return new;
end;
$$;
revoke all on function app.purge_siem_enqueue_failures_on_offboarding() from public, anon, authenticated;

drop trigger if exists tenants_purge_siem_enqueue_failures on public.tenants;
create trigger tenants_purge_siem_enqueue_failures
  after update of status on public.tenants
  for each row
  when (new.status in ('closing', 'closed') and old.status is distinct from new.status)
  execute function app.purge_siem_enqueue_failures_on_offboarding();

create or replace function app.assert_no_siem_offboarding_residue()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if new.status <> 'completed' then return new; end if;
  if exists (select 1 from public.siem_destinations where tenant_id = new.tenant_id)
     or exists (select 1 from public.siem_deliveries where tenant_id = new.tenant_id)
     or exists (select 1 from public.siem_enqueue_failures where tenant_id = new.tenant_id) then
    raise exception 'siem_offboarding_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_no_siem_offboarding_residue() from public, anon, authenticated;
