-- Tenant-scoped managed discovery observations. Only origin-level targets and
-- bounded status codes are stored; scanned paths, credentials and raw scan
-- responses never enter the control plane.

create table public.tenant_discovery_collectors (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  collector_id text not null check (collector_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  cycle_id uuid not null,
  sequence bigint not null check (sequence > 0),
  stale_after_ms bigint not null check (stale_after_ms between 60000 and 2592000000),
  complete boolean not null,
  expected_targets integer not null check (expected_targets between 1 and 100),
  observed_targets integer not null check (observed_targets between 0 and 100 and observed_targets <= expected_targets),
  reported_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null,
  primary key (tenant_id, collector_id),
  check (not complete or observed_targets = expected_targets)
);
create index tenant_discovery_collectors_reported_idx
  on public.tenant_discovery_collectors(tenant_id, reported_at desc);

create table public.tenant_discovery_items (
  tenant_id uuid not null,
  collector_id text not null,
  target text not null check (
    octet_length(target) between 8 and 512
    and target ~ '^https?://[^/?#@[:space:]]+/$'
  ),
  first_reported_at timestamptz not null default now(),
  last_reported_at timestamptz not null default now(),
  last_reachable_at timestamptz,
  last_cycle_id uuid not null,
  reachable boolean not null,
  attempts smallint not null check (attempts between 1 and 5),
  error_code text check (error_code in (
    'timeout', 'unreachable', 'target_not_allowed',
    'invalid_target_url', 'collector_exception', 'other'
  )),
  primary key (tenant_id, collector_id, target),
  foreign key (tenant_id, collector_id)
    references public.tenant_discovery_collectors(tenant_id, collector_id) on delete cascade,
  check ((reachable and error_code is null) or (not reachable and error_code is not null))
);
create index tenant_discovery_items_alert_idx
  on public.tenant_discovery_items(tenant_id, collector_id, last_reachable_at);

alter table public.tenant_discovery_collectors enable row level security;
alter table public.tenant_discovery_items enable row level security;
revoke all on public.tenant_discovery_collectors, public.tenant_discovery_items
  from public, anon, authenticated;
grant select, insert, update, delete on public.tenant_discovery_collectors,
  public.tenant_discovery_items to service_role;

-- One transaction covers the collector cursor and every observation. An
-- incomplete cycle is visible as incomplete and never deletes omitted targets.
create function public.ingest_tenant_discovery_cycle(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_collector_id text,
  p_cycle_id uuid,
  p_sequence bigint,
  p_stale_after_ms bigint,
  p_complete boolean,
  p_expected_targets integer,
  p_items jsonb
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_previous_sequence bigint;
  v_count integer;
  v_item jsonb;
  v_target text;
  v_reachable boolean;
  v_attempts integer;
  v_error text;
  v_now timestamptz := now();
begin
  if p_tenant_id is null or p_actor_user_id is null or p_cycle_id is null
    or p_collector_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    or p_sequence is null or p_sequence < 1
    or p_stale_after_ms not between 60000 and 2592000000
    or p_complete is null or p_expected_targets not between 1 and 100
    or jsonb_typeof(p_items) is distinct from 'array'
  then raise exception 'invalid_discovery_cycle' using errcode = '22023'; end if;
  v_count := jsonb_array_length(p_items);
  if v_count > p_expected_targets or (p_complete and v_count <> p_expected_targets)
  then raise exception 'incomplete_discovery_cycle' using errcode = '22023'; end if;

  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || p_collector_id, 2611));
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
      and m.role in ('owner', 'admin')
      and (m.expires_at is null or m.expires_at > v_now) and t.status = 'active'
  ) then raise exception 'discovery_forbidden' using errcode = '42501'; end if;
  select c.sequence into v_previous_sequence from public.tenant_discovery_collectors c
    where c.tenant_id = p_tenant_id and c.collector_id = p_collector_id for update;
  if v_previous_sequence is not null and p_sequence <= v_previous_sequence
  then raise exception 'discovery_cycle_replayed' using errcode = 'PT409'; end if;

  -- Validate the complete input before the first mutation. A malformed later
  -- element cannot leave an earlier target updated.
  if exists (
    select 1 from jsonb_array_elements(p_items) item
    where jsonb_typeof(item) <> 'object'
      or (select count(*) from jsonb_object_keys(item)) <> 4
      or not (item ?& array['target','reachable','attempts','error_code'])
      or jsonb_typeof(item->'target') <> 'string'
      or octet_length(item->>'target') not between 8 and 512
      or (item->>'target') !~ '^https?://[^/?#@[:space:]]+/$'
      or jsonb_typeof(item->'reachable') <> 'boolean'
      or jsonb_typeof(item->'attempts') <> 'number'
      or (item->>'attempts') !~ '^[1-5]$'
      or not (
        ((item->>'reachable')::boolean and item->'error_code' = 'null'::jsonb)
        or (not (item->>'reachable')::boolean and item->>'error_code' in (
          'timeout','unreachable','target_not_allowed','invalid_target_url','collector_exception','other'
        ))
      )
  ) then raise exception 'invalid_discovery_item' using errcode = '22023'; end if;
  if (select count(distinct item->>'target') from jsonb_array_elements(p_items) item) <> v_count
  then raise exception 'duplicate_discovery_target' using errcode = '22023'; end if;

  insert into public.tenant_discovery_collectors
    (tenant_id, collector_id, cycle_id, sequence, stale_after_ms, complete,
     expected_targets, observed_targets, reported_at, updated_by)
  values (p_tenant_id, p_collector_id, p_cycle_id, p_sequence, p_stale_after_ms,
    p_complete, p_expected_targets, v_count, v_now, p_actor_user_id)
  on conflict (tenant_id, collector_id) do update set
    cycle_id = excluded.cycle_id, sequence = excluded.sequence,
    stale_after_ms = excluded.stale_after_ms, complete = excluded.complete,
    expected_targets = excluded.expected_targets,
    observed_targets = excluded.observed_targets,
    reported_at = excluded.reported_at, updated_by = excluded.updated_by;

  for v_item in select value from jsonb_array_elements(p_items) loop
    v_target := v_item->>'target';
    v_reachable := (v_item->>'reachable')::boolean;
    v_attempts := (v_item->>'attempts')::integer;
    v_error := v_item->>'error_code';
    insert into public.tenant_discovery_items
      (tenant_id, collector_id, target, first_reported_at, last_reported_at,
       last_reachable_at, last_cycle_id, reachable, attempts, error_code)
    values (p_tenant_id, p_collector_id, v_target, v_now, v_now,
      case when v_reachable then v_now else null end,
      p_cycle_id, v_reachable, v_attempts, v_error)
    on conflict (tenant_id, collector_id, target) do update set
      last_reported_at = excluded.last_reported_at,
      last_reachable_at = case when excluded.reachable then v_now
        else public.tenant_discovery_items.last_reachable_at end,
      last_cycle_id = excluded.last_cycle_id,
      reachable = excluded.reachable, attempts = excluded.attempts,
      error_code = excluded.error_code;
  end loop;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_actor_user_id, p_tenant_id, p_actor_user_id, 'discovery.cycle.ingested',
    jsonb_build_object('collector_id', p_collector_id, 'cycle_id', p_cycle_id,
      'sequence', p_sequence, 'complete', p_complete,
      'expected_targets', p_expected_targets, 'observed_targets', v_count));
  return jsonb_build_object('collector_id', p_collector_id, 'cycle_id', p_cycle_id,
    'sequence', p_sequence, 'complete', p_complete, 'observed_targets', v_count,
    'reported_at', v_now);
end;
$$;
revoke all on function public.ingest_tenant_discovery_cycle(
  uuid, uuid, text, uuid, bigint, bigint, boolean, integer, jsonb
) from public, anon, authenticated;
grant execute on function public.ingest_tenant_discovery_cycle(
  uuid, uuid, text, uuid, bigint, bigint, boolean, integer, jsonb
) to service_role;

create function public.read_tenant_discovery_summary(
  p_tenant_id uuid, p_actor_user_id uuid
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_collectors bigint;
  v_partial bigint;
  v_stale_collectors bigint;
  v_observations bigint;
  v_unreachable bigint;
  v_never_seen bigint;
  v_stale bigint;
  v_not_reported bigint;
begin
  if p_tenant_id is null or p_actor_user_id is null then
    raise exception 'invalid_discovery_scope' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
      and (m.expires_at is null or m.expires_at > now()) and t.status = 'active'
  ) then raise exception 'discovery_forbidden' using errcode = '42501'; end if;
  select count(*), count(*) filter (where not complete),
    count(*) filter (where extract(epoch from (now() - reported_at)) * 1000 > stale_after_ms)
  into v_collectors, v_partial, v_stale_collectors
  from public.tenant_discovery_collectors where tenant_id = p_tenant_id;
  select count(*),
    count(*) filter (where i.last_cycle_id = c.cycle_id and not i.reachable),
    count(*) filter (where i.last_reachable_at is null),
    count(*) filter (where i.last_reachable_at is not null
      and extract(epoch from (now() - i.last_reachable_at)) * 1000 > c.stale_after_ms),
    count(*) filter (where c.complete and i.last_cycle_id <> c.cycle_id)
  into v_observations, v_unreachable, v_never_seen, v_stale, v_not_reported
  from public.tenant_discovery_items i
  join public.tenant_discovery_collectors c
    on c.tenant_id = i.tenant_id and c.collector_id = i.collector_id
  where i.tenant_id = p_tenant_id;
  return jsonb_build_object(
    'collector_count', v_collectors,
    'partial_collector_count', v_partial,
    'stale_collector_count', v_stale_collectors,
    'observation_count', v_observations,
    'unreachable_count', v_unreachable,
    'never_seen_count', v_never_seen,
    'stale_observation_count', v_stale,
    'not_reported_count', v_not_reported,
    'coverage_scope', 'reported_collectors_only',
    'reported_scope_state', case when v_collectors = 0 then 'unknown'
      when v_partial > 0 or v_stale_collectors > 0 or v_observations = 0
        or v_unreachable > 0 or v_never_seen > 0 or v_stale > 0 or v_not_reported > 0
      then 'attention' else 'current' end
  );
end;
$$;
revoke all on function public.read_tenant_discovery_summary(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.read_tenant_discovery_summary(uuid, uuid)
  to service_role;

-- Offboarding retains a tenant tombstone. Drop discovery observations in the
-- same transaction that marks all retained phases complete and closes it.
create function app.purge_discovery_on_tenant_close() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if old.status is distinct from 'closed' and new.status = 'closed' then
    delete from public.tenant_discovery_collectors where tenant_id = new.id;
  end if;
  return new;
end;
$$;
revoke all on function app.purge_discovery_on_tenant_close() from public, anon, authenticated;
create trigger tenants_purge_discovery_on_close
after update of status on public.tenants
for each row execute function app.purge_discovery_on_tenant_close();
