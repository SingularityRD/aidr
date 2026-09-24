-- Run against a disposable, fully migrated Supabase database.
begin;
do $checks$
declare
  v_user uuid := gen_random_uuid();
  v_other_user uuid := gen_random_uuid();
  v_first uuid;
  v_second uuid;
  v_result record;
begin
  insert into auth.users(id, email) values
    (v_user, 'events-seat-' || v_user || '@test.invalid'),
    (v_other_user, 'events-seat-' || v_other_user || '@test.invalid');
  -- Seat-write serialization needs two admitted agents. Keep this isolated
  -- from the one-agent cloud trial by enabling pilot mode only in rollback.
  update app.tenant_admission_config set mode = 'pilot' where singleton;
  insert into public.pilot_applications(user_id, tenant_id, status)
  values (v_user, v_user, 'approved');
  update public.entitlements set included_agents = 2, extra_agents = 0
   where tenant_id = v_user;
  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-a', null, null, v_user);
  if v_result.seat_exceeded then raise exception 'first agent rejected'; end if;
  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-b', null, null, v_user);
  if v_result.seat_exceeded then raise exception 'second agent rejected'; end if;
  update public.agents set first_seen = '2020-01-01 00:00:00+00'
   where tenant_id = v_user;
  select id into v_first from public.agents
   where tenant_id = v_user order by first_seen, id limit 1;
  select id into v_second from public.agents
   where tenant_id = v_user order by first_seen desc, id desc limit 1;
  insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
  values (v_user, v_user, v_first, 'seat-first', 'runtime_verdict', '{}'::jsonb),
         (v_user, v_user, v_second, 'seat-second', 'runtime_verdict', '{}'::jsonb);
  begin
    insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
    values (v_other_user, v_user, v_first, 'seat-wrong-user', 'runtime_verdict', '{}'::jsonb);
    raise exception 'another user attributed telemetry to the agent';
  exception when sqlstate '42501' then null;
  end;

  update public.entitlements set included_agents = 1 where tenant_id = v_user;
  insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
  values (v_user, v_user, v_first, 'seat-first-after-shrink', 'runtime_verdict', '{}'::jsonb);
  begin
    insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
    values (v_user, v_user, v_second, 'seat-second-after-shrink', 'runtime_verdict', '{}'::jsonb);
    raise exception 'over-quota agent inserted a new event';
  exception when sqlstate '42501' then null;
  end;

  -- An already stored event may be acknowledged again, but its ID cannot
  -- be reused by another agent or user.
  insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
  values (v_user, v_user, v_second, 'seat-second', 'runtime_verdict', '{}'::jsonb)
  on conflict (tenant_id, event_id) do nothing;
  begin
    insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
    values (v_user, v_user, v_second, 'seat-first', 'runtime_verdict', '{}'::jsonb)
    on conflict (tenant_id, event_id) do nothing;
    raise exception 'cross-agent event ID reuse was accepted';
  exception when sqlstate '42501' then null;
  end;
  begin
    insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
    values (v_other_user, v_user, v_second, 'seat-second', 'runtime_verdict', '{}'::jsonb)
    on conflict (tenant_id, event_id) do nothing;
    raise exception 'cross-user event ID reuse was accepted';
  exception when sqlstate '42501' then null;
  end;

  update public.entitlements set included_agents = 0 where tenant_id = v_user;
  begin
    insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
    values (v_user, v_user, v_first, 'seat-first-zero', 'runtime_verdict', '{}'::jsonb);
    raise exception 'zero-seat agent inserted a new event';
  exception when sqlstate '42501' then null;
  end;
  if (select count(*) from public.events where tenant_id = v_user) <> 3 then
    raise exception 'seat guard stored or lost an unexpected event';
  end if;
  raise notice 'EVENTS_SEAT_ADMISSION_OK';
end;
$checks$;
rollback;
