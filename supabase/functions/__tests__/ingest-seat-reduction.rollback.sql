-- Run against a disposable, fully migrated Supabase database; rollback keeps
-- the fixture out of customer data.
begin;
do $checks$
declare
  v_user uuid := gen_random_uuid();
  v_team uuid := gen_random_uuid();
  v_first text;
  v_excess text;
  v_excess_id uuid;
  v_last_seen timestamptz;
  v_result record;
begin
  insert into auth.users(id, email)
  values (v_user, 'ingest-seat-' || v_user || '@test.invalid');
  -- This fixture exercises deterministic seat rank, not the cloud trial
  -- admission limit. The production default remains unconfigured/denied.
  update app.tenant_admission_config set mode = 'pilot' where singleton;
  if not exists (select 1 from public.entitlements
                  where tenant_id = v_user and included_agents = 1) then
    raise exception 'personal free seat was not explicitly provisioned';
  end if;
  insert into public.pilot_applications(user_id, tenant_id, status)
  values (v_user, v_user, 'approved');
  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-a', null, null, v_user);
  if v_result.seat_exceeded or not v_result.created or v_result.allowed_agents <> 1
  then raise exception 'personal free seat rejected'; end if;

  insert into public.tenants(id, name, kind, created_by)
  values (v_team, 'Missing entitlement regression', 'team', v_user);
  insert into public.tenant_members(tenant_id, user_id, role)
  values (v_team, v_user, 'owner');
  if exists (select 1 from public.entitlements where tenant_id = v_team)
  then raise exception 'fixture unexpectedly provisioned team entitlement'; end if;
  select * into v_result from public.register_agent_for_ingest(v_user, 'team-iid', null, null, v_team);
  if not v_result.seat_exceeded or v_result.agent_id is not null
     or v_result.allowed_agents <> 0
     or exists (select 1 from public.agents where tenant_id = v_team)
  then raise exception 'missing team entitlement failed open'; end if;

  update public.entitlements
     set included_agents = 3, extra_agents = 0
   where tenant_id = v_user;
  if not found then raise exception 'missing test entitlement'; end if;

  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-b', null, null, v_user);
  if v_result.seat_exceeded or not v_result.created then raise exception 'second agent rejected'; end if;
  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-c', null, null, v_user);
  if v_result.seat_exceeded or not v_result.created then raise exception 'third agent rejected'; end if;

  -- Equal timestamps prove the UUID tie-break remains deterministic.
  update public.agents set first_seen = '2020-01-01 00:00:00+00'
   where tenant_id = v_user;
  select iid into v_first from public.agents
   where tenant_id = v_user order by first_seen, id limit 1;
  select id, iid, last_seen into v_excess_id, v_excess, v_last_seen
    from public.agents where tenant_id = v_user
   order by first_seen desc, id desc limit 1;
  update public.entitlements set included_agents = 1 where tenant_id = v_user;

  select * into v_result from public.register_agent_for_ingest(v_user, v_first, null, null, v_user);
  if v_result.seat_exceeded or v_result.agent_id is null or v_result.allowed_agents <> 1
  then raise exception 'highest-ranked existing agent rejected'; end if;
  select * into v_result from public.register_agent_for_ingest(v_user, v_excess, 'should-not-touch', null, v_user);
  if not v_result.seat_exceeded or v_result.agent_id is not null
     or v_result.current_agents <> 3 or v_result.allowed_agents <> 1
  then raise exception 'excess existing agent kept ingesting'; end if;
  if exists (select 1 from public.agents
              where id = v_excess_id
                and (last_seen is distinct from v_last_seen or agent_runtime is not null))
  then raise exception 'rejected agent state was touched'; end if;
  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-new', null, null, v_user);
  if not v_result.seat_exceeded or v_result.agent_id is not null
  then raise exception 'new agent bypassed reduced quota'; end if;

  update public.entitlements set included_agents = 0 where tenant_id = v_user;
  select * into v_result from public.register_agent_for_ingest(v_user, v_first, null, null, v_user);
  if not v_result.seat_exceeded or v_result.agent_id is not null
     or v_result.allowed_agents <> 0
  then raise exception 'zero-seat entitlement allowed existing agent'; end if;

  update public.entitlements set included_agents = 3 where tenant_id = v_user;
  select * into v_result from public.register_agent_for_ingest(v_user, v_excess, null, null, v_user);
  if v_result.seat_exceeded or v_result.agent_id <> v_excess_id
  then raise exception 'restored seat did not restore existing agent'; end if;
  raise notice 'INGEST_SEAT_REDUCTION_OK';
end;
$checks$;
rollback;
