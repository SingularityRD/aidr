-- Run inside BEGIN/ROLLBACK after the discovery migration on a local seeded
-- database. This exercises RPC authorization, partial cycles and replay order.
do $$
declare
  v_tenant uuid;
  v_actor uuid;
  v_collector text := 'smoke-' || replace(gen_random_uuid()::text, '-', '');
  v_first uuid := gen_random_uuid();
  v_second uuid := gen_random_uuid();
  v_third uuid := gen_random_uuid();
  v_result jsonb;
  v_complete boolean;
  v_count integer;
  v_run uuid;
begin
  select m.tenant_id, m.user_id into v_tenant, v_actor
  from public.tenant_members m join public.tenants t on t.id = m.tenant_id
  where m.role in ('owner', 'admin') and t.status = 'active'
    and (m.expires_at is null or m.expires_at > now())
    and not exists(select 1 from public.tenant_legal_holds h
      where h.tenant_id = m.tenant_id and h.released_at is null)
    and not exists(select 1 from public.tenant_offboarding_runs r
      where r.tenant_id = m.tenant_id and r.status <> 'completed')
  limit 1;
  if v_tenant is null then
    raise exception 'seeded active tenant owner required for discovery smoke';
  end if;
  if has_table_privilege('authenticated', 'public.tenant_discovery_items', 'SELECT')
    or has_function_privilege('authenticated',
      'public.ingest_tenant_discovery_cycle(uuid,uuid,text,uuid,bigint,bigint,boolean,integer,jsonb)',
      'EXECUTE')
  then raise exception 'discovery storage or mutation exposed to authenticated role'; end if;

  v_result := public.ingest_tenant_discovery_cycle(
    v_tenant, v_actor, v_collector, v_first, 1, 60000, true, 1,
    '[{"target":"https://example.test/","reachable":true,"attempts":1,"error_code":null}]'::jsonb
  );
  if v_result->>'complete' <> 'true' then
    raise exception 'complete cycle not recorded';
  end if;

  v_result := public.ingest_tenant_discovery_cycle(
    v_tenant, v_actor, v_collector, v_second, 2, 60000, false, 1, '[]'::jsonb
  );
  select complete into v_complete from public.tenant_discovery_collectors
  where tenant_id = v_tenant and collector_id = v_collector;
  select count(*) into v_count from public.tenant_discovery_items
  where tenant_id = v_tenant and collector_id = v_collector;
  if v_complete or v_count <> 1 then
    raise exception 'partial cycle hid an existing observation';
  end if;

  v_result := public.read_tenant_discovery_summary(v_tenant, v_actor);
  if v_result->>'reported_scope_state' <> 'attention'
    or v_result->>'coverage_scope' <> 'reported_collectors_only'
    or (v_result->>'partial_collector_count')::integer < 1 then
    raise exception 'partial cycle was reported healthy';
  end if;

  v_result := public.ingest_tenant_discovery_cycle(
    v_tenant, v_actor, v_collector, v_third, 3, 60000, true, 1,
    '[{"target":"https://replacement.example.test/","reachable":true,"attempts":1,"error_code":null}]'::jsonb
  );
  select count(*) into v_count from public.tenant_discovery_items
  where tenant_id = v_tenant and collector_id = v_collector;
  if v_count <> 1 or exists (
    select 1 from public.tenant_discovery_items
    where tenant_id = v_tenant and collector_id = v_collector
      and target = 'https://example.test/'
  ) or not exists (
    select 1 from public.tenant_discovery_items
    where tenant_id = v_tenant and collector_id = v_collector
      and target = 'https://replacement.example.test/'
  ) then raise exception 'complete cycle did not reconcile omitted observations'; end if;

  begin
    perform public.ingest_tenant_discovery_cycle(
      v_tenant, v_actor, v_collector, v_first, 1, 60000, true, 1,
      '[{"target":"https://example.test/","reachable":true,"attempts":1,"error_code":null}]'::jsonb
    );
    raise exception 'replayed sequence was accepted';
  exception when sqlstate 'PT409' then null;
  end;

  v_result := public.read_tenant_discovery_summary(v_tenant, v_actor);
  if v_result->>'reported_scope_state' <> 'current'
    or (v_result->>'not_reported_count')::integer <> 0
    or (v_result->>'observation_count')::integer <> 1 then
    raise exception 'completed target reconciliation left stale observations';
  end if;

  begin
    perform public.read_tenant_discovery_summary(gen_random_uuid(), v_actor);
    raise exception 'cross-tenant summary accepted';
  exception when insufficient_privilege then null;
  end;

  insert into public.tenant_offboarding_runs(tenant_id, requested_by, status)
  values (v_tenant, v_actor, 'running') returning id into v_run;
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at, status)
  values (v_run, 12, 'agents', 'endpoint_identity', 'delete_records', 0,
    now() - interval '1 second', 'running');
  update public.tenant_offboarding_phase_receipts
    set status = 'completed', completed_at = now()
    where run_id = v_run and phase = 'agents';
  select count(*) into v_count from public.tenant_discovery_collectors
    where tenant_id = v_tenant and collector_id = v_collector;
  if v_count <> 0 then raise exception 'endpoint identity phase retained discovery'; end if;
  select rows_deleted into v_count from public.tenant_offboarding_phase_receipts
    where run_id = v_run and phase = 'agents';
  if v_count <> 2 then raise exception 'discovery deletion absent from phase receipt'; end if;
end;
$$;
