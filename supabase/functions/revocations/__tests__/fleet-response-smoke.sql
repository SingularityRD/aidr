-- Run in a rollback-only psql session after applying the fleet response
-- migration: psql -v ON_ERROR_STOP=1 -c BEGIN -f fleet-response-smoke.sql -c ROLLBACK
-- Requires one enrolled, bound, active agent and owner/admin in the test DB.
do $test$
declare
  v_tenant uuid;
  v_agent uuid;
  v_operator uuid;
  v_key_hash text;
  v_command public.fleet_response_commands;
  v_again public.fleet_response_commands;
  v_poll public.fleet_response_commands;
  v_rollback public.fleet_response_commands;
begin
  if has_table_privilege('authenticated','public.fleet_response_commands','SELECT')
     or has_function_privilege(
       'authenticated',
       'public.queue_fleet_response_command(uuid,uuid,uuid,text,text,text,integer,uuid)',
       'EXECUTE')
  then raise exception 'browser role can bypass response service boundary'; end if;
  select a.tenant_id,a.id,m.user_id,k.key_hash
    into v_tenant,v_agent,v_operator,v_key_hash
  from public.agents a
  join public.api_keys k on k.agent_id=a.id and k.tenant_id=a.tenant_id and not k.revoked
  join public.tenant_members m on m.tenant_id=a.tenant_id
    and m.role in ('owner','admin') and (m.expires_at is null or m.expires_at>now())
  join public.tenants t on t.id=a.tenant_id and t.status='active'
  limit 1;
  if v_agent is null then raise exception 'fleet smoke requires a bound enrolled agent'; end if;

  v_command := public.queue_fleet_response_command(
    v_tenant,v_operator,v_agent,'agent_pause',
    'Contained suspicious agent activity','smoke-fleet-queue-20260912',300,null);
  if v_command.state<>'pending' then raise exception 'queue state'; end if;
  v_again := public.queue_fleet_response_command(
    v_tenant,v_operator,v_agent,'agent_pause',
    'Contained suspicious agent activity','smoke-fleet-queue-20260912',300,null);
  if v_again.id<>v_command.id then raise exception 'idempotent retry changed id'; end if;
  begin
    perform public.queue_fleet_response_command(
      v_tenant,v_operator,v_agent,'agent_pause',
      'Different incident justification','smoke-fleet-queue-20260912',300,null);
    raise exception 'conflicting idempotency key was accepted';
  exception when sqlstate 'PT409' then null; end;

  v_poll := public.poll_fleet_response_command(v_key_hash,v_tenant,v_agent);
  if v_poll.id<>v_command.id or v_poll.state<>'delivered' or v_poll.attempts<>1
  then raise exception 'poll did not lease the targeted command'; end if;
  begin
    perform public.cancel_fleet_response_command(v_tenant,v_operator,v_command.id);
    raise exception 'delivered command was falsely cancelled';
  exception when sqlstate 'PT409' then null; end;
  begin
    perform public.record_fleet_response_command(
      v_key_hash,v_tenant,gen_random_uuid(),v_command.id,'ack','accepted',null);
    raise exception 'key impersonated another agent';
  exception when sqlstate '42501' then null; end;
  v_again := public.record_fleet_response_command(
    v_key_hash,v_tenant,v_agent,v_command.id,'ack','accepted',null);
  if v_again.state<>'acknowledged' then raise exception 'ack transition'; end if;
  v_again := public.record_fleet_response_command(
    v_key_hash,v_tenant,v_agent,v_command.id,'result','succeeded','agent_paused');
  if v_again.state<>'succeeded' then raise exception 'result transition'; end if;
  v_again := public.record_fleet_response_command(
    v_key_hash,v_tenant,v_agent,v_command.id,'result','succeeded','agent_paused');
  if v_again.state<>'succeeded' then raise exception 'result retry'; end if;

  v_rollback := public.queue_fleet_response_command(
    v_tenant,v_operator,v_agent,'agent_resume',
    'Incident cleared after investigation','smoke-fleet-rollback-20260912',300,v_command.id);
  if v_rollback.rollback_of<>v_command.id or v_rollback.state<>'pending'
  then raise exception 'rollback link'; end if;
  begin
    perform public.queue_fleet_response_command(
      v_tenant,v_operator,v_agent,'agent_resume',
      'Second rollback is forbidden','smoke-fleet-rollback2-20260912',300,v_command.id);
    raise exception 'duplicate rollback accepted';
  exception when sqlstate 'PT409' then null; end;
  v_poll := public.poll_fleet_response_command(v_key_hash,v_tenant,v_agent);
  if v_poll.id<>v_rollback.id then raise exception 'rollback delivery'; end if;
  v_again := public.record_fleet_response_command(
    v_key_hash,v_tenant,v_agent,v_rollback.id,'ack','accepted',null);
  v_again := public.record_fleet_response_command(
    v_key_hash,v_tenant,v_agent,v_rollback.id,'result','failed','os_permission_denied');
  if v_again.state<>'failed' or v_again.result_code<>'os_permission_denied'
  then raise exception 'rollback failure not explicit'; end if;

  v_again := public.queue_fleet_response_command(
    v_tenant,v_operator,v_agent,'agent_pause',
    'Cancel this queued response test','smoke-fleet-cancel-20260912',300,null);
  v_again := public.cancel_fleet_response_command(v_tenant,v_operator,v_again.id);
  if v_again.state<>'cancelled' then raise exception 'cancel transition'; end if;

  v_again := public.queue_fleet_response_command(
    v_tenant,v_operator,v_agent,'agent_pause',
    'Expire before delivery testing','smoke-fleet-expire-20260912',30,null);
  update public.fleet_response_commands set expires_at=now()-interval '1 second'
    where id=v_again.id;
  v_poll := public.poll_fleet_response_command(v_key_hash,v_tenant,v_agent);
  select * into v_again from public.fleet_response_commands where id=v_again.id;
  if v_again.state<>'expired' then raise exception 'undelivered expiry'; end if;

  v_again := public.queue_fleet_response_command(
    v_tenant,v_operator,v_agent,'agent_pause',
    'Unknown outcome after delivery','smoke-fleet-unknown-20260912',30,null);
  v_poll := public.poll_fleet_response_command(v_key_hash,v_tenant,v_agent);
  if v_poll.id<>v_again.id then raise exception 'unknown-case delivery'; end if;
  update public.fleet_response_commands set expires_at=now()-interval '1 second'
    where id=v_again.id;
  v_poll := public.poll_fleet_response_command(v_key_hash,v_tenant,v_agent);
  select * into v_again from public.fleet_response_commands where id=v_again.id;
  if v_again.state<>'outcome_unknown' then raise exception 'delivered expiry falsely claims failure'; end if;

  begin
    perform public.poll_fleet_response_command(repeat('0',64),v_tenant,v_agent);
    raise exception 'invalid agent credential was accepted';
  exception when sqlstate '42501' then null; end;
  raise notice 'fleet response smoke passed';
end;
$test$;
