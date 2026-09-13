-- Run with both fleet migrations loaded in one rollback-only psql session.
do $test$
declare
  v_tenant uuid := gen_random_uuid();
  v_actor uuid := gen_random_uuid();
  v_command uuid;
  v_run uuid;
  v_hold uuid;
  v_phase public.tenant_offboarding_phase_receipts;
  v_result jsonb;
begin
  insert into public.tenants(id,name,kind,status)
  values(v_tenant,'Fleet offboarding smoke','enterprise','active');
  insert into public.fleet_response_commands(
    tenant_id,agent_id,actor_user_id,command_type,reason,idempotency_key,
    request_fingerprint,expires_at
  ) values (
    v_tenant,gen_random_uuid(),v_actor,'agent_pause',
    'Preserve incident response evidence','fleet-offboarding-smoke-20260912',
    repeat('a',64),now()+interval '5 minutes'
  ) returning id into v_command;
  insert into public.tenant_offboarding_runs(tenant_id,requested_by,status)
  values(v_tenant,v_actor,'requested') returning id into v_run;
  select * into v_phase from public.tenant_offboarding_phase_receipts
    where run_id=v_run and phase='fleet_response_commands';
  if not found or v_phase.phase_order<>40 or v_phase.data_class<>'security_audit'
     or v_phase.retention_days<365 or v_phase.operation<>'delete_records'
  then raise exception 'fleet retention receipt missing or misclassified'; end if;

  insert into public.tenant_legal_holds(
    tenant_id,hold_reference,reason,placed_by
  ) values (
    v_tenant,'fleet-smoke-hold','Legal preservation for smoke',v_actor
  ) returning id into v_hold;
  v_result := public.run_tenant_offboarding_batch(v_run,100);
  if v_result->>'status'<>'blocked_legal_hold'
     or not exists(select 1 from public.fleet_response_commands where id=v_command)
  then raise exception 'legal hold did not block fleet deletion'; end if;
  update public.tenant_legal_holds
  set released_by=v_actor,released_at=now(),
      release_reason='Test release after preservation check'
  where id=v_hold;
  update public.tenant_offboarding_phase_receipts
  set eligible_at=now()-interval '1 second'
  where run_id=v_run and phase='fleet_response_commands';
  v_result := public.run_tenant_offboarding_batch(v_run,100);
  select * into v_phase from public.tenant_offboarding_phase_receipts
    where run_id=v_run and phase='fleet_response_commands';
  if v_result->>'phase'<>'fleet_response_commands'
     or v_phase.status<>'completed' or v_phase.rows_deleted<>1
     or exists(select 1 from public.fleet_response_commands where id=v_command)
  then raise exception 'fleet deletion receipt did not match deleted records'; end if;
  v_result := public.run_tenant_offboarding_batch(v_run,100);
  if v_result->>'status'<>'completed' then raise exception 'offboarding completion failed'; end if;
  raise notice 'fleet offboarding smoke passed';
end;
$test$;
