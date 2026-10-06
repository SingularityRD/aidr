-- Cloud resource evidence remains separate from HTTP-origin reachability.
-- Collector grants bind a reviewed provider configuration; metadata is not provider attestation.
alter table public.tenant_discovery_collectors add column provider_evidence jsonb;
alter table public.tenant_discovery_collectors drop constraint tenant_discovery_collectors_expected_targets_check;
alter table public.tenant_discovery_collectors add constraint tenant_discovery_collectors_expected_targets_check check (expected_targets between 0 and 100);
alter table public.tenant_discovery_collectors add constraint tenant_discovery_collectors_cloud_only_check check (expected_targets > 0 or provider_evidence is not null);
alter table public.tenant_discovery_credentials add column allowed_provider_scope jsonb;
create table public.tenant_discovery_provider_resources (
 tenant_id uuid not null, collector_id text not null, provider text not null check(provider in ('aws','azure','gcp','intune')),
 scope_hash text not null check(scope_hash ~ '^[a-f0-9]{64}$'),
 resource_id text not null check(length(resource_id) between 1 and 1024 and resource_id !~ '[[:cntrl:]]'),
 resource_type text not null check(length(resource_type) between 1 and 256 and resource_type !~ '[[:cntrl:]]'),
 scope_id text not null check(length(scope_id) between 1 and 256 and scope_id !~ '[[:cntrl:]]'),
 region text check(region is null or (length(region) between 1 and 64 and region !~ '[[:cntrl:]]')),
 observed_at timestamptz not null, last_cycle_id uuid not null,
 primary key(tenant_id,collector_id,resource_id),
 foreign key(tenant_id,collector_id) references public.tenant_discovery_collectors(tenant_id,collector_id) on delete cascade
);
alter table public.tenant_discovery_provider_resources enable row level security;
revoke all on public.tenant_discovery_provider_resources from public,anon,authenticated;
grant select,insert,update,delete on public.tenant_discovery_provider_resources to service_role;
create function app.valid_discovery_provider_scope(v jsonb) returns boolean
language sql immutable set search_path = public,pg_temp as $$
 select case when jsonb_typeof(v)='object' then (select count(*) from jsonb_object_keys(v))=2
 and v ?& array['provider','scope_hash'] and v->>'provider' in ('aws','azure','gcp','intune')
 and jsonb_typeof(v->'scope_hash')='string' and v->>'scope_hash' ~ '^[a-f0-9]{64}$' else false end;
$$;
revoke all on function app.valid_discovery_provider_scope(jsonb) from public,anon,authenticated;
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
create function public.issue_tenant_discovery_credential(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_collector_id text,
  p_token_hash text,
  p_expires_in_days integer,
  p_allowed_provider_scope jsonb
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_now timestamptz;
  v_credential_id uuid := gen_random_uuid();
  v_expires_at timestamptz;
  v_last_sequence bigint;
  v_tenant_status text;
begin
  if p_tenant_id is null or p_actor_user_id is null
    or p_collector_id is null or p_collector_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$'
    or p_expires_in_days is null or p_expires_in_days not between 1 and 90
  then raise exception 'invalid_discovery_credential' using errcode = '22023'; end if;

  if p_allowed_provider_scope is not null and not coalesce(app.valid_discovery_provider_scope(p_allowed_provider_scope),false) then raise exception 'invalid_provider_scope' using errcode='22023'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text,2606));
  select t.status into v_tenant_status from public.tenants t
    where t.id = p_tenant_id for share;
  if v_tenant_status is distinct from 'active'
  then raise exception 'discovery_credential_forbidden' using errcode = '42501'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || p_collector_id, 2611));
  v_now := clock_timestamp();
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
      and m.role in ('owner', 'admin')
      and (m.expires_at is null or m.expires_at > v_now) and t.status = 'active'
    for share of m
  ) then raise exception 'discovery_credential_forbidden' using errcode = '42501'; end if;

  v_expires_at := v_now + make_interval(days => p_expires_in_days);
  select c.sequence into v_last_sequence from public.tenant_discovery_collectors c
    where c.tenant_id = p_tenant_id and c.collector_id = p_collector_id;
  if coalesce(v_last_sequence, 0) >= 9007199254740991
  then raise exception 'discovery_sequence_exhausted' using errcode = 'PT409'; end if;

  insert into public.tenant_discovery_credentials
    (tenant_id, collector_id, credential_id, token_hash, issued_by, issued_at, expires_at, revoked_at, allowed_provider_scope)
  values (p_tenant_id, p_collector_id, v_credential_id, p_token_hash, p_actor_user_id, v_now, v_expires_at, null, p_allowed_provider_scope)
  on conflict (tenant_id, collector_id) do update set
    credential_id = excluded.credential_id, token_hash = excluded.token_hash,
    issued_by = excluded.issued_by, issued_at = excluded.issued_at,
    expires_at = excluded.expires_at, revoked_at = null, allowed_provider_scope = excluded.allowed_provider_scope;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_actor_user_id, p_tenant_id, p_actor_user_id, 'discovery.credential.issued',
    jsonb_build_object('collector_id', p_collector_id, 'credential_id', v_credential_id,
      'expires_at', v_expires_at, 'rotation', true,
      'allowed_provider_scope', p_allowed_provider_scope));
  return jsonb_build_object('collector_id', p_collector_id, 'credential_id', v_credential_id,
    'expires_at', v_expires_at, 'next_sequence', coalesce(v_last_sequence, 0) + 1);
end;
$$;
revoke all on function public.issue_tenant_discovery_credential(uuid,uuid,text,text,integer,jsonb) from public,anon,authenticated;
grant execute on function public.issue_tenant_discovery_credential(uuid,uuid,text,text,integer,jsonb) to service_role;
create or replace function public.issue_tenant_discovery_credential(p_tenant_id uuid,p_actor_user_id uuid,p_collector_id text,p_token_hash text,p_expires_in_days integer)
returns jsonb language sql security definer set search_path=public,pg_temp as $$
 select public.issue_tenant_discovery_credential(p_tenant_id,p_actor_user_id,p_collector_id,p_token_hash,p_expires_in_days,null);
$$;
create function public.ingest_tenant_discovery_cycle_machine(
  p_tenant_id uuid,
  p_collector_id text,
  p_token_hash text,
  p_cycle_id uuid,
  p_sequence bigint,
  p_stale_after_ms bigint,
  p_complete boolean,
  p_expected_targets integer,
  p_items jsonb,
  p_provider_resources jsonb
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_now timestamptz;
  v_credential_id uuid;
  v_issued_by uuid;
  v_result jsonb;
  v_tenant_status text;
  v_provider_scope jsonb;
begin
  if p_tenant_id is null or p_collector_id is null
    or p_collector_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$'
  then raise exception 'invalid_discovery_credential' using errcode = '22023'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text,2606));
  select t.status into v_tenant_status from public.tenants t
    where t.id = p_tenant_id for share;
  if v_tenant_status is distinct from 'active'
  then raise exception 'invalid_discovery_credential' using errcode = '42501'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || p_collector_id, 2611));
  v_now := clock_timestamp();
  select c.credential_id, c.issued_by, c.allowed_provider_scope into v_credential_id, v_issued_by, v_provider_scope
    from public.tenant_discovery_credentials c
    join public.tenants t on t.id = c.tenant_id
    join public.tenant_members m on m.tenant_id = c.tenant_id and m.user_id = c.issued_by
    where c.tenant_id = p_tenant_id and c.collector_id = p_collector_id
      and c.token_hash = p_token_hash and c.revoked_at is null and c.expires_at > v_now
      and t.status = 'active' and m.role in ('owner', 'admin')
      and (m.expires_at is null or m.expires_at > v_now)
    for share of m;
  if v_credential_id is null
  then raise exception 'invalid_discovery_credential' using errcode = '42501'; end if;
  if p_provider_resources is not null and (v_provider_scope is null or
    p_provider_resources->>'provider' is distinct from v_provider_scope->>'provider' or
    p_provider_resources->>'scope_hash' is distinct from v_provider_scope->>'scope_hash')
  then raise exception 'invalid_collector_provider_scope' using errcode='42501'; end if;
  -- Reuse the existing atomic validation, target bounds and monotonic replay
  -- check. The issuing admin remains the durable authorization sponsor.
  v_result := public.ingest_tenant_discovery_cycle(p_tenant_id, v_issued_by,
    p_collector_id, p_cycle_id, p_sequence, p_stale_after_ms, p_complete,
    p_expected_targets, p_items, p_provider_resources);
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (v_issued_by, p_tenant_id, v_issued_by, 'discovery.machine_cycle.ingested',
    jsonb_build_object('collector_id', p_collector_id, 'credential_id', v_credential_id,
      'cycle_id', p_cycle_id, 'sequence', p_sequence));
  return v_result;
end;
$$;
revoke all on function public.ingest_tenant_discovery_cycle_machine(uuid,text,text,uuid,bigint,bigint,boolean,integer,jsonb,jsonb) from public,anon,authenticated;
grant execute on function public.ingest_tenant_discovery_cycle_machine(uuid,text,text,uuid,bigint,bigint,boolean,integer,jsonb,jsonb) to service_role;
create or replace function app.purge_discovery_at_endpoint_identity_phase() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_tenant uuid;
  v_status text;
  v_items bigint;
  v_collectors bigint;
begin
  if new.phase <> 'agents' or new.data_class <> 'endpoint_identity'
    or new.status <> 'completed' or old.status = 'completed'
  then return new; end if;
  select r.tenant_id, r.status into v_tenant, v_status
  from public.tenant_offboarding_runs r where r.id = new.run_id;
  if v_tenant is null or v_status <> 'running' or new.eligible_at > now() then
    raise exception 'discovery_offboarding_phase_invalid' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  if exists (
    select 1 from public.tenant_legal_holds h
    where h.tenant_id = v_tenant and h.released_at is null
  ) then raise exception 'discovery_offboarding_legal_hold' using errcode = '42501'; end if;
  select count(*) into v_items from public.tenant_discovery_items
    where tenant_id = v_tenant;
  v_items := v_items + (select count(*) from public.tenant_discovery_provider_resources where tenant_id=v_tenant);
  delete from public.tenant_discovery_collectors where tenant_id = v_tenant;
  get diagnostics v_collectors = row_count;
  -- The phase receipt counts the dependent discovery observations removed by
  -- this trigger as well as the agents deleted by the offboarding RPC.
  update public.tenant_offboarding_phase_receipts
    set rows_deleted = rows_deleted + v_items + v_collectors
    where run_id = new.run_id and phase = new.phase and status = 'completed';
  return new;
end;
$$;
create or replace function public.read_tenant_discovery_summary(
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
  v_resources bigint;
  v_resource_stale bigint;
  v_resource_not_reported bigint;
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
  select count(*),count(*) filter(where r.observed_at>now() or extract(epoch from (now()-r.observed_at))*1000>c.stale_after_ms),
    count(*) filter(where r.last_cycle_id<>c.cycle_id)
  into v_resources,v_resource_stale,v_resource_not_reported
  from public.tenant_discovery_provider_resources r join public.tenant_discovery_collectors c
    on c.tenant_id=r.tenant_id and c.collector_id=r.collector_id where r.tenant_id=p_tenant_id;
  return jsonb_build_object(
    'collector_count', v_collectors,
    'partial_collector_count', v_partial,
    'stale_collector_count', v_stale_collectors,
    'observation_count', v_observations,
    'unreachable_count', v_unreachable,
    'never_seen_count', v_never_seen,
    'stale_observation_count', v_stale,
    'not_reported_count', v_not_reported,
    'provider_resource_count',v_resources, 'stale_provider_resource_count',v_resource_stale, 'not_reported_provider_resource_count',v_resource_not_reported,
    'coverage_scope', 'reported_collectors_only',
    'reported_scope_state', case when v_collectors = 0 then 'unknown'
      when v_partial > 0 or v_stale_collectors > 0 or (v_observations = 0 and v_resources = 0) or v_resource_stale > 0 or v_resource_not_reported > 0
        or v_unreachable > 0 or v_never_seen > 0 or v_stale > 0 or v_not_reported > 0
      then 'attention' else 'current' end
  );
end;
$$;

-- Legacy HTTP signatures use the same transaction and lock order; cloud-only
-- zero-target input remains unavailable through these signatures.
create or replace function public.ingest_tenant_discovery_cycle(
 p_tenant_id uuid,p_actor_user_id uuid,p_collector_id text,p_cycle_id uuid,p_sequence bigint,
 p_stale_after_ms bigint,p_complete boolean,p_expected_targets integer,p_items jsonb
) returns jsonb language plpgsql security definer set search_path=public,pg_temp as $$
begin
 if p_expected_targets is null or p_expected_targets<1 then raise exception 'invalid_discovery_cycle' using errcode='22023'; end if;
 return public.ingest_tenant_discovery_cycle(p_tenant_id,p_actor_user_id,p_collector_id,p_cycle_id,p_sequence,p_stale_after_ms,p_complete,p_expected_targets,p_items,null);
end;
$$;
create or replace function public.ingest_tenant_discovery_cycle_machine(
 p_tenant_id uuid,p_collector_id text,p_token_hash text,p_cycle_id uuid,p_sequence bigint,
 p_stale_after_ms bigint,p_complete boolean,p_expected_targets integer,p_items jsonb
) returns jsonb language plpgsql security definer set search_path=public,pg_temp as $$
begin
 if p_expected_targets is null or p_expected_targets<1 then raise exception 'invalid_discovery_cycle' using errcode='22023'; end if;
 return public.ingest_tenant_discovery_cycle_machine(p_tenant_id,p_collector_id,p_token_hash,p_cycle_id,p_sequence,p_stale_after_ms,p_complete,p_expected_targets,p_items,null);
end;
$$;
