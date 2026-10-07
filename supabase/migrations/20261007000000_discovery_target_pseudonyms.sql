-- Discovery target pseudonymisation.
--
-- Product promise: only CVE id, severity, component, version and rule id reach
-- the panel; addresses, paths and matched text stay on the device. Collectors
-- therefore report each target as a keyed, tenant-scoped pseudonym
-- (`tid1_` + hex HMAC-SHA256 under a per-installation key that never leaves the
-- collector) instead of its origin.
--
-- * New ingests accept ONLY pseudonyms; a raw origin is rejected
--   (invalid_discovery_item), so an older collector fails loudly instead of
--   storing an address.
-- * Rows stored before this migration keep their origin and stay readable; the
--   column constraint accepts both forms. A collector's next complete cycle
--   reconciles (deletes) its omitted legacy origin rows, outside legal hold.
alter table public.tenant_discovery_items drop constraint tenant_discovery_items_target_check;
alter table public.tenant_discovery_items add constraint tenant_discovery_items_target_check check (
  target ~ '^tid1_[a-f0-9]{64}$'
  or (octet_length(target) between 8 and 512 and target ~ '^https?://[^/?#@[:space:]]+/$')
);

create or replace function public.ingest_tenant_discovery_cycle(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_collector_id text,
  p_cycle_id uuid,
  p_sequence bigint,
  p_stale_after_ms bigint,
  p_complete boolean,
  p_expected_targets integer,
  p_items jsonb,
  p_provider_resources jsonb
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_previous_sequence bigint;
  v_count integer;
  v_item jsonb;
  v_target text;
  v_reachable boolean;
  v_attempts integer;
  v_error text;
  v_provider_item jsonb;
  v_provider_count integer;
  v_now timestamptz := clock_timestamp();
begin
  if p_tenant_id is null or p_actor_user_id is null or p_cycle_id is null
    or p_collector_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    or p_sequence is null or p_sequence < 1
    or p_stale_after_ms not between 60000 and 2592000000
    or p_complete is null or p_expected_targets not between 0 and 100
    or (p_expected_targets = 0 and p_provider_resources is null)
    or jsonb_typeof(p_items) is distinct from 'array'
  then raise exception 'invalid_discovery_cycle' using errcode = '22023'; end if;
  v_count := jsonb_array_length(p_items);
  if v_count > p_expected_targets or (p_complete and v_count <> p_expected_targets)
  then raise exception 'incomplete_discovery_cycle' using errcode = '22023'; end if;

  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  perform 1 from public.tenants where id=p_tenant_id and status='active' for share;
  if not found then raise exception 'discovery_forbidden' using errcode='42501'; end if;
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

  -- Validate the full input before mutating either the cursor or observations.
  if exists (
    select 1 from jsonb_array_elements(p_items) item
    where jsonb_typeof(item) <> 'object'
      or (select count(*) from jsonb_object_keys(item)) <> 4
      or not (item ?& array['target','reachable','attempts','error_code'])
      or jsonb_typeof(item->'target') <> 'string'
      or (item->>'target') !~ '^tid1_[a-f0-9]{64}$'
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


  if p_provider_resources is not null then
    if jsonb_typeof(p_provider_resources) is distinct from 'object'
      or (select count(*) from jsonb_object_keys(p_provider_resources)) <> 6
      or not (p_provider_resources ?& array['provider','scope_hash','coverage','complete','observed_at','items'])
      or not coalesce(app.valid_discovery_provider_scope(p_provider_resources - array['coverage','complete','observed_at','items']),false)
      or p_provider_resources->>'coverage' is distinct from (case p_provider_resources->>'provider'
        when 'aws' then 'tagged_resources' when 'azure' then 'resource_groups'
        when 'gcp' then 'project_asset_types' when 'intune' then 'managed_devices' end)
      or jsonb_typeof(p_provider_resources->'complete') is distinct from 'boolean'
      or (p_complete and p_provider_resources->'complete' <> 'true'::jsonb)
      or jsonb_typeof(p_provider_resources->'observed_at') is distinct from 'string'
      or (p_provider_resources->>'observed_at')::timestamptz > v_now + interval '5 minutes'
      or jsonb_typeof(p_provider_resources->'items') is distinct from 'array'
    then raise exception 'invalid_discovery_provider' using errcode='22023'; end if;
    v_provider_count := jsonb_array_length(p_provider_resources->'items');
    if v_provider_count > 1000 or octet_length(p_provider_resources::text)>524288
    then raise exception 'invalid_discovery_provider' using errcode='22023'; end if;
    for v_provider_item in select value from jsonb_array_elements(p_provider_resources->'items') loop
      if jsonb_typeof(v_provider_item) is distinct from 'object'
        or (select count(*) from jsonb_object_keys(v_provider_item))<>5
        or not (v_provider_item ?& array['resource_id','resource_type','scope_id','region','observed_at'])
        or jsonb_typeof(v_provider_item->'resource_id') is distinct from 'string'
        or length(v_provider_item->>'resource_id') not between 1 and 1024
        or jsonb_typeof(v_provider_item->'resource_type') is distinct from 'string'
        or length(v_provider_item->>'resource_type') not between 1 and 256
        or jsonb_typeof(v_provider_item->'scope_id') is distinct from 'string'
        or length(v_provider_item->>'scope_id') not between 1 and 256
        or exists(select 1 from jsonb_each_text(v_provider_item) x where x.value ~ '[[:cntrl:]]')
        or not (v_provider_item->'region'='null'::jsonb or (jsonb_typeof(v_provider_item->'region')='string' and length(v_provider_item->>'region') between 1 and 64))
        or jsonb_typeof(v_provider_item->'observed_at') is distinct from 'string'
        or (v_provider_item->>'observed_at')::timestamptz > (p_provider_resources->>'observed_at')::timestamptz
      then raise exception 'invalid_discovery_resource' using errcode='22023'; end if;
    end loop;
    if (select count(distinct item->>'resource_id') from jsonb_array_elements(p_provider_resources->'items') item) <> v_provider_count
    then raise exception 'duplicate_discovery_resource' using errcode='22023'; end if;
  end if;

  insert into public.tenant_discovery_collectors
    (tenant_id, collector_id, cycle_id, sequence, stale_after_ms, complete,
     expected_targets, observed_targets, reported_at, updated_by, provider_evidence)
  values (p_tenant_id, p_collector_id, p_cycle_id, p_sequence, p_stale_after_ms,
    p_complete, p_expected_targets, v_count, v_now, p_actor_user_id, p_provider_resources - 'items')
  on conflict (tenant_id, collector_id) do update set
    cycle_id = excluded.cycle_id, sequence = excluded.sequence,
    stale_after_ms = excluded.stale_after_ms, complete = excluded.complete,
    expected_targets = excluded.expected_targets,
    observed_targets = excluded.observed_targets,
    reported_at = excluded.reported_at, updated_by = excluded.updated_by, provider_evidence = excluded.provider_evidence;

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

  if p_complete and not exists(select 1 from public.tenant_legal_holds where tenant_id=p_tenant_id and released_at is null) then
    delete from public.tenant_discovery_items i
    where i.tenant_id = p_tenant_id and i.collector_id = p_collector_id
      and not exists (
        select 1 from jsonb_array_elements(p_items) item
        where item->>'target' = i.target
      );
  end if;


  if p_provider_resources is not null then
    for v_provider_item in select value from jsonb_array_elements(p_provider_resources->'items') loop
      insert into public.tenant_discovery_provider_resources
        (tenant_id,collector_id,provider,scope_hash,resource_id,resource_type,scope_id,region,observed_at,last_cycle_id)
      values(p_tenant_id,p_collector_id,p_provider_resources->>'provider',p_provider_resources->>'scope_hash',
        v_provider_item->>'resource_id',v_provider_item->>'resource_type',v_provider_item->>'scope_id',
        v_provider_item->>'region',(v_provider_item->>'observed_at')::timestamptz,p_cycle_id)
      on conflict(tenant_id,collector_id,resource_id) do update set provider=excluded.provider,scope_hash=excluded.scope_hash,
        resource_type=excluded.resource_type,scope_id=excluded.scope_id,region=excluded.region,
        observed_at=excluded.observed_at,last_cycle_id=excluded.last_cycle_id;
    end loop;
  end if;
  if p_complete and not exists(select 1 from public.tenant_legal_holds where tenant_id=p_tenant_id and released_at is null) then
    delete from public.tenant_discovery_provider_resources r where r.tenant_id=p_tenant_id and r.collector_id=p_collector_id
      and not exists(select 1 from jsonb_array_elements(coalesce(p_provider_resources->'items','[]'::jsonb)) item where item->>'resource_id'=r.resource_id);
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_actor_user_id, p_tenant_id, p_actor_user_id, 'discovery.cycle.ingested',
    jsonb_build_object('collector_id', p_collector_id, 'cycle_id', p_cycle_id,
      'sequence', p_sequence, 'complete', p_complete,
      'expected_targets', p_expected_targets, 'observed_targets', v_count,
      'provider_scope', case when p_provider_resources is null then null else p_provider_resources - array['coverage','complete','observed_at','items'] end,
      'provider_resource_count', coalesce(v_provider_count,0)));
  return jsonb_build_object('collector_id', p_collector_id, 'cycle_id', p_cycle_id,
    'sequence', p_sequence, 'complete', p_complete, 'observed_targets', v_count,
    'reported_at', v_now);
end;
$$;
revoke all on function public.ingest_tenant_discovery_cycle(uuid,uuid,text,uuid,bigint,bigint,boolean,integer,jsonb,jsonb) from public,anon,authenticated;
grant execute on function public.ingest_tenant_discovery_cycle(uuid,uuid,text,uuid,bigint,bigint,boolean,integer,jsonb,jsonb) to service_role;
