-- Run against a disposable, fully migrated Supabase database (after
-- 20261014120100_agent_retirement.sql). Everything is rolled back.
--   psql -X -qAt -v ON_ERROR_STOP=1 -d postgres < supabase/functions/__tests__/agent-retirement.rollback.sql
begin;
do $setup$
declare
  v_owner uuid := gen_random_uuid();
  v_admin uuid := gen_random_uuid();
  v_member uuid := gen_random_uuid();
begin
  perform set_config('aidr.fixture.owner', v_owner::text, true);
  perform set_config('aidr.fixture.admin', v_admin::text, true);
  perform set_config('aidr.fixture.member', v_member::text, true);
  insert into auth.users(id, email, email_confirmed_at) values
    (v_owner, 'retire-owner-' || v_owner || '@test.invalid', clock_timestamp()),
    (v_admin, 'retire-admin-' || v_admin || '@test.invalid', clock_timestamp()),
    (v_member, 'retire-member-' || v_member || '@test.invalid', clock_timestamp());
  insert into public.tenant_members(tenant_id, user_id, role) values
    (v_owner, v_admin, 'admin'), (v_owner, v_member, 'member');
  update app.tenant_admission_config set mode = 'onprem', configured_at = clock_timestamp() where singleton;
  update public.entitlements set included_agents = 2, extra_agents = 0 where tenant_id = v_owner;
  insert into public.tenant_admissions
    (tenant_id, owner_user_id, kind, seats, starts_at, expires_at, grant_reference)
  values (v_owner, v_owner, 'licensed', 2, clock_timestamp() - interval '1 day',
    clock_timestamp() + interval '300 days', 'LIC-RETIRE-TEST');
end;
$setup$;

do $checks$
declare
  v_owner uuid := current_setting('aidr.fixture.owner')::uuid;
  v_admin uuid := current_setting('aidr.fixture.admin')::uuid;
  v_member uuid := current_setting('aidr.fixture.member')::uuid;
  v_reg record;
  v_first uuid;
  v_second uuid;
  v_third uuid;
  v_result jsonb;
  v_first_seen_before timestamptz;
  v_first_seen_after timestamptz;
  v_third_seen timestamptz;
begin
  select * into v_reg from public.register_agent_for_ingest(v_owner, 'iid-one', 'claude_code', '1.0', v_owner);
  if v_reg.seat_exceeded or v_reg.agent_id is null then raise exception 'first agent rejected'; end if;
  v_first := v_reg.agent_id;
  select * into v_reg from public.register_agent_for_ingest(v_owner, 'iid-two', 'claude_code', '1.0', v_owner);
  if v_reg.seat_exceeded then raise exception 'second agent rejected'; end if;
  v_second := v_reg.agent_id;
  select * into v_reg from public.register_agent_for_ingest(v_owner, 'iid-three', 'claude_code', '1.0', v_owner);
  if not v_reg.seat_exceeded or v_reg.current_agents <> 2 then
    raise exception 'third agent admitted past two seats';
  end if;

  -- The device key the enrollment issued for the first agent, plus a
  -- tenant-wide key that retirement must leave alone.
  insert into public.api_keys(user_id, tenant_id, label, agent_id, key_hash)
  values (v_owner, v_owner, 'enroll:iid-one', v_first, repeat('a', 64)),
         (v_owner, v_owner, 'shared', null, repeat('b', 64));
  update public.agents set first_seen = clock_timestamp() - interval '10 days' where id = v_first;
  select first_seen into v_first_seen_before from public.agents where id = v_first;

  -- A member may not retire; an unknown agent is reported, not ignored.
  begin
    perform public.retire_agent(v_member, v_owner, v_first, null);
    raise exception 'member retired an agent';
  exception when sqlstate '42501' then null;
  end;
  begin
    perform public.retire_agent(v_admin, v_owner, gen_random_uuid(), null);
    raise exception 'unknown agent retired';
  exception when sqlstate 'P0002' then null;
  end;
  begin
    perform public.retire_agent(v_admin, v_owner, v_first, repeat('x', 201));
    raise exception 'oversized note accepted';
  exception when sqlstate '22023' then null;
  end;

  v_result := public.retire_agent(v_admin, v_owner, v_first, 'laptop reimaged');
  if v_result->>'status' <> 'retired' or (v_result->>'revoked_keys')::int <> 1 then
    raise exception 'retirement result wrong: %', v_result;
  end if;
  if not (select revoked from public.api_keys where key_hash = repeat('a', 64)) then
    raise exception 'device key still active after retirement';
  end if;
  if (select revoked from public.api_keys where key_hash = repeat('b', 64)) then
    raise exception 'tenant-wide key revoked by device retirement';
  end if;
  if (select retired_reason from public.agents where id = v_first) <> 'manual'
     or (select retired_by from public.agents where id = v_first) <> v_admin then
    raise exception 'retirement not attributed';
  end if;
  if not exists (select 1 from public.admin_audit_logs where tenant_id = v_owner
                  and action = 'agent.retired' and actor_user_id = v_admin
                  and detail->>'agent_id' = v_first::text and detail->>'reason' = 'manual') then
    raise exception 'retirement not audited';
  end if;
  if public.retire_agent(v_admin, v_owner, v_first, null)->>'status' <> 'already_retired' then
    raise exception 'second retirement not idempotent';
  end if;

  -- A retired agent's telemetry is refused.
  begin
    insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
    values (v_owner, v_owner, v_first, 'retired-event', 'runtime_verdict', '{}'::jsonb);
    raise exception 'retired agent inserted an event';
  exception when sqlstate '42501' then null;
  end;

  -- The freed seat admits a new device.
  select * into v_reg from public.register_agent_for_ingest(v_owner, 'iid-three', 'claude_code', '1.0', v_owner);
  if v_reg.seat_exceeded or v_reg.agent_id is null or v_reg.current_agents <> 2 then
    raise exception 'freed seat not reusable: %', row_to_json(v_reg);
  end if;
  v_third := v_reg.agent_id;
  insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
  values (v_owner, v_owner, v_third, 'third-event', 'runtime_verdict', '{}'::jsonb);

  -- Re-enrolling the retired iid while both seats are taken is refused.
  select * into v_reg from public.register_agent_for_ingest(v_owner, 'iid-one', 'claude_code', '1.1', v_owner);
  if not v_reg.seat_exceeded then raise exception 'retired agent displaced an active one'; end if;
  if (select retired_at from public.agents where id = v_first) is null then
    raise exception 'refused re-enrollment reactivated the agent';
  end if;

  -- After another seat is freed, the same iid re-enrolls into its old row as
  -- the newest agent.
  perform public.retire_agent(v_owner, v_owner, v_second, null);
  select first_seen into v_third_seen from public.agents where id = v_third;
  select * into v_reg from public.register_agent_for_ingest(v_owner, 'iid-one', 'claude_code', '1.1', v_owner);
  if v_reg.seat_exceeded or v_reg.agent_id is distinct from v_first or v_reg.created then
    raise exception 're-enrollment of the same iid did not reuse its row: %', row_to_json(v_reg);
  end if;
  select first_seen into v_first_seen_after from public.agents where id = v_first;
  if v_first_seen_after <= v_first_seen_before or v_first_seen_after <= v_third_seen then
    raise exception 'reactivated agent kept its old seat rank';
  end if;
  if (select retired_at from public.agents where id = v_first) is not null
     or (select agent_runtime_version from public.agents where id = v_first) <> '1.1' then
    raise exception 'reactivation incomplete';
  end if;
  if not exists (select 1 from public.admin_audit_logs where tenant_id = v_owner
                  and action = 'agent.reactivated' and detail->>'agent_id' = v_first::text) then
    raise exception 'reactivation not audited';
  end if;
  insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
  values (v_owner, v_owner, v_first, 'reactivated-event', 'runtime_verdict', '{}'::jsonb);

  -- Retirement state is writable only through the lifecycle functions.
  begin
    update public.agents set retired_at = null, retired_reason = null, retired_by = null where id = v_second;
    raise exception 'direct un-retire accepted';
  exception when sqlstate '42501' then null;
  end;
  begin
    insert into public.agents(user_id, tenant_id, iid, retired_at, retired_reason)
    values (v_owner, v_owner, 'iid-forged', clock_timestamp(), 'offline');
    raise exception 'pre-retired insert accepted';
  exception when sqlstate '42501' then null;
  end;

  -- Automatic retirement after N days offline, configured per tenant.
  begin
    perform public.set_agent_auto_retirement(v_member, v_owner, 30);
    raise exception 'member configured auto-retirement';
  exception when sqlstate '42501' then null;
  end;
  begin
    perform public.set_agent_auto_retirement(v_admin, v_owner, 3);
    raise exception 'out-of-range auto-retirement accepted';
  exception when sqlstate '22023' then null;
  end;
  v_result := public.set_agent_auto_retirement(v_admin, v_owner, 30);
  if v_result->>'status' <> 'configured' then raise exception 'auto-retirement not configured'; end if;
  update public.agents set last_seen = clock_timestamp() - interval '45 days' where id = v_third;
  update public.agents set last_seen = clock_timestamp() - interval '29 days' where id = v_first;
  v_result := public.retire_offline_agents(100, false);
  if (v_result->>'eligible')::int <> 1 or (v_result->>'retired')::int <> 0 then
    raise exception 'dry run wrong: %', v_result;
  end if;
  if (select retired_at from public.agents where id = v_third) is not null then
    raise exception 'dry run retired an agent';
  end if;
  v_result := public.retire_offline_agents(100, true);
  if (v_result->>'retired')::int <> 1 or (v_result->>'remaining')::int <> 0 then
    raise exception 'offline sweep wrong: %', v_result;
  end if;
  if (select retired_reason from public.agents where id = v_third) <> 'offline'
     or (select retired_by from public.agents where id = v_third) is not null
     or (select retired_at from public.agents where id = v_first) is not null then
    raise exception 'offline sweep retired the wrong agents';
  end if;
  -- Disabled again: nothing more is retired.
  perform public.set_agent_auto_retirement(v_owner, v_owner, null);
  update public.agents set last_seen = clock_timestamp() - interval '400 days' where id = v_first;
  if (public.retire_offline_agents(100, true)->>'eligible')::int <> 0 then
    raise exception 'disabled auto-retirement still retired agents';
  end if;
  -- The scheduled job wrapper runs the sweep and records a receipt.
  if (app.run_retention_job('agent_retirement')->>'ok')::boolean is not true then
    raise exception 'scheduled auto-retirement job failed';
  end if;
end;
$checks$;

-- Browser seat view: active agents only, retired agents counted separately.
select set_config('request.jwt.claim.sub', current_setting('aidr.fixture.owner'), true);
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claims', jsonb_build_object(
  'sub', current_setting('aidr.fixture.owner'), 'role', 'authenticated',
  'aal', 'aal2', 'iat', extract(epoch from clock_timestamp())::bigint)::text, true);
set local role authenticated;
do $browser$
declare
  v_owner uuid := current_setting('aidr.fixture.owner')::uuid;
  v_current integer;
  v_retired integer;
  v_plan jsonb;
begin
  select current_agents, retired_agents into v_current, v_retired
    from public.seat_usage where tenant_id = v_owner;
  if v_current is distinct from 1 or v_retired is distinct from 2 then
    raise exception 'seat view counted retired agents: current %, retired %', v_current, v_retired;
  end if;
  v_plan := public.get_tenant_plan(v_owner);
  if (v_plan->>'current_agents')::int <> 1 then
    raise exception 'plan view counted retired agents: %', v_plan;
  end if;
  if not exists (select 1 from public.agent_retirement_settings where tenant_id = v_owner) then
    raise exception 'member cannot read the auto-retirement setting';
  end if;
  begin
    update public.agent_retirement_settings set auto_retire_offline_days = 7 where tenant_id = v_owner;
    raise exception 'browser wrote the auto-retirement setting';
  exception when sqlstate '42501' then null;
  end;
  begin
    perform public.retire_agent(v_owner, v_owner, gen_random_uuid(), null);
    raise exception 'browser called retire_agent directly';
  exception when sqlstate '42501' then null;
  end;
end;
$browser$;
reset role;
do $$ begin raise notice 'AGENT_RETIREMENT_OK'; end; $$;
rollback;
