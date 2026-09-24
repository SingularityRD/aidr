-- A bounded local response playbook that advances only after a fleet command
-- has reached a terminal state through the existing authenticated consumer.
create table public.fleet_response_playbook_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  actor_user_id uuid not null,
  agent_id uuid not null,
  incident_id uuid not null,
  playbook_id text not null check (playbook_id = 'agent_containment_v1'),
  reason text not null check (length(btrim(reason)) between 12 and 500),
  idempotency_key text not null check
    (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$'),
  request_fingerprint text not null check (request_fingerprint ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz not null,
  state text not null default 'running' check (state in
    ('running', 'succeeded', 'failed', 'partial', 'expired', 'outcome_unknown', 'cancelled')),
  current_step smallint not null default 1 check (current_step between 1 and 2),
  result_code text check (result_code is null or result_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  unique (tenant_id, idempotency_key),
  unique (id, tenant_id, actor_user_id, agent_id, incident_id)
);

create table public.fleet_response_playbook_steps (
  run_id uuid not null,
  tenant_id uuid not null,
  actor_user_id uuid not null,
  agent_id uuid not null,
  incident_id uuid not null,
  step_id text not null check (step_id in ('pause_agent', 'isolate_network')),
  ordinal smallint not null check (ordinal in (1, 2)),
  command_type text not null check (command_type in ('agent_pause', 'network_isolate')),
  command_id uuid not null unique references public.fleet_response_commands(id) on delete restrict,
  state text not null default 'pending' check (state in
    ('pending', 'delivered', 'acknowledged', 'succeeded', 'failed', 'expired', 'outcome_unknown', 'cancelled')),
  result_code text check (result_code is null or result_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  primary key (run_id, ordinal),
  unique (run_id, step_id),
  foreign key (run_id, tenant_id, actor_user_id, agent_id, incident_id)
    references public.fleet_response_playbook_runs(id, tenant_id, actor_user_id, agent_id, incident_id)
    on delete cascade,
  check (
    (ordinal = 1 and step_id = 'pause_agent' and command_type = 'agent_pause') or
    (ordinal = 2 and step_id = 'isolate_network' and command_type = 'network_isolate')
  )
);

create index fleet_response_playbook_tenant_history_idx
  on public.fleet_response_playbook_runs (tenant_id, created_at desc, id desc);
alter table public.fleet_response_playbook_runs enable row level security;
alter table public.fleet_response_playbook_steps enable row level security;
revoke all on public.fleet_response_playbook_runs from public, anon, authenticated;
revoke all on public.fleet_response_playbook_steps from public, anon, authenticated;
grant select, insert, update on public.fleet_response_playbook_runs to service_role;
grant select, insert, update on public.fleet_response_playbook_steps to service_role;

create function public.get_fleet_response_playbook(p_tenant_id uuid, p_run_id uuid)
returns jsonb
language sql stable security definer set search_path = public, pg_temp as $$
  select jsonb_build_object(
    'id', r.id,
    'tenant_id', r.tenant_id,
    'actor_user_id', r.actor_user_id,
    'agent_id', r.agent_id,
    'incident_reference', r.incident_id,
    'playbook_id', r.playbook_id,
    'reason', r.reason,
    'state', r.state,
    'current_step', r.current_step,
    'expires_at', r.expires_at,
    'result_code', r.result_code,
    'created_at', r.created_at,
    'completed_at', r.completed_at,
    'steps', coalesce((
      select jsonb_agg(jsonb_build_object(
        'step_id', s.step_id,
        'ordinal', s.ordinal,
        'command_type', s.command_type,
        'command_id', s.command_id,
        'state', s.state,
        'result_code', s.result_code,
        'expires_at', c.expires_at
      ) order by s.ordinal)
      from public.fleet_response_playbook_steps s
      join public.fleet_response_commands c on c.id = s.command_id
      where s.run_id = r.id
    ), '[]'::jsonb)
  )
  from public.fleet_response_playbook_runs r
  where r.tenant_id = p_tenant_id and r.id = p_run_id;
$$;
revoke all on function public.get_fleet_response_playbook(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.get_fleet_response_playbook(uuid, uuid) to service_role;

create function public.start_fleet_response_playbook(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_agent_id uuid,
  p_incident_id uuid,
  p_playbook_id text,
  p_reason text,
  p_idempotency_key text,
  p_ttl_seconds integer
)
returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_run public.fleet_response_playbook_runs;
  v_command public.fleet_response_commands;
  v_fingerprint text;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_agent_id is null or p_incident_id is null
     or p_playbook_id is distinct from 'agent_containment_v1'
     or p_reason is null or length(btrim(p_reason)) not between 12 and 500
     or p_idempotency_key is null
     or p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$'
     or p_ttl_seconds is null or p_ttl_seconds not between 30 and 3600
  then raise exception 'invalid_response_playbook' using errcode='22023'; end if;

  perform 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
      and m.role in ('owner', 'admin')
      and (m.expires_at is null or m.expires_at > now()) and t.status = 'active'
    for share of m, t;
  if not found then raise exception 'response_playbook_operator_forbidden' using errcode='42501'; end if;
  if not exists (
    select 1 from public.agents a where a.id = p_agent_id and a.tenant_id = p_tenant_id
  ) then raise exception 'fleet_agent_not_found' using errcode='22023'; end if;

  perform pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':response-playbook:' || p_idempotency_key, 73923));
  v_fingerprint := encode(extensions.digest(
    p_actor_user_id::text || ':' || p_agent_id::text || ':' || p_incident_id::text || ':' ||
      p_playbook_id || ':' || btrim(p_reason) || ':' || p_ttl_seconds::text,
    'sha256'), 'hex');
  select * into v_run from public.fleet_response_playbook_runs
    where tenant_id = p_tenant_id and idempotency_key = p_idempotency_key for update;
  if found then
    if v_run.request_fingerprint <> v_fingerprint or v_run.actor_user_id <> p_actor_user_id
    then raise exception 'response_playbook_idempotency_conflict' using errcode='PT409'; end if;
    return public.get_fleet_response_playbook(p_tenant_id, v_run.id);
  end if;

  insert into public.fleet_response_playbook_runs(
    tenant_id, actor_user_id, agent_id, incident_id, playbook_id, reason,
    idempotency_key, request_fingerprint, expires_at
  ) values (
    p_tenant_id, p_actor_user_id, p_agent_id, p_incident_id, p_playbook_id, btrim(p_reason),
    p_idempotency_key, v_fingerprint, now() + make_interval(secs => p_ttl_seconds)
  ) returning * into v_run;

  v_command := public.queue_bounded_fleet_response_command(
    p_tenant_id, p_actor_user_id, p_agent_id, 'agent_pause', btrim(p_reason),
    'pb:' || v_run.id::text || ':1', p_ttl_seconds, null);
  insert into public.fleet_response_playbook_steps(
    run_id, tenant_id, actor_user_id, agent_id, incident_id, step_id, ordinal,
    command_type, command_id, state, result_code
  ) values (
    v_run.id, v_run.tenant_id, v_run.actor_user_id, v_run.agent_id, v_run.incident_id,
    'pause_agent', 1, v_command.command_type, v_command.id, v_command.state, v_command.result_code
  );
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, 'fleet.response.playbook_started',
    jsonb_build_object('run_id', v_run.id, 'incident_reference', p_incident_id,
      'agent_id', p_agent_id, 'playbook_id', p_playbook_id));
  return public.get_fleet_response_playbook(p_tenant_id, v_run.id);
end;
$$;
revoke all on function public.start_fleet_response_playbook(uuid, uuid, uuid, uuid, text, text, text, integer)
  from public, anon, authenticated;
grant execute on function public.start_fleet_response_playbook(uuid, uuid, uuid, uuid, text, text, text, integer)
  to service_role;

create function public.advance_fleet_response_playbook_step()
returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_step public.fleet_response_playbook_steps;
  v_run public.fleet_response_playbook_runs;
  v_next public.fleet_response_commands;
  v_remaining integer;
  v_has_applied boolean;
begin
  if new.state is not distinct from old.state
     or new.state not in ('succeeded', 'failed', 'expired', 'outcome_unknown', 'cancelled')
  then return new; end if;

  select * into v_step from public.fleet_response_playbook_steps
    where command_id = new.id for update;
  if not found then return new; end if;
  select * into v_run from public.fleet_response_playbook_runs
    where id = v_step.run_id for update;
  if not found or v_run.state <> 'running' or v_run.current_step <> v_step.ordinal then
    return new;
  end if;
  if new.tenant_id <> v_run.tenant_id or new.actor_user_id <> v_run.actor_user_id
     or new.agent_id <> v_run.agent_id or v_step.incident_id <> v_run.incident_id
  then raise exception 'response_playbook_command_binding_mismatch'; end if;

  update public.fleet_response_playbook_steps
  set state = new.state, result_code = new.result_code,
      completed_at = case when new.state in ('succeeded', 'failed', 'expired', 'outcome_unknown', 'cancelled')
        then coalesce(new.completed_at, now()) else completed_at end
  where run_id = v_step.run_id and ordinal = v_step.ordinal;

  if new.state = 'succeeded' then
    if v_step.ordinal = 2 then
      update public.fleet_response_playbook_runs
      set state = 'succeeded', current_step = 2, completed_at = now(), result_code = null
      where id = v_run.id;
      return new;
    end if;

    v_remaining := floor(extract(epoch from (v_run.expires_at - now())))::integer;
    if v_remaining < 30 then
      update public.fleet_response_playbook_runs
      set state = 'partial', completed_at = now(), result_code = 'ttl_elapsed'
      where id = v_run.id;
      return new;
    end if;

    v_next := public.queue_bounded_fleet_response_command(
      v_run.tenant_id, v_run.actor_user_id, v_run.agent_id, 'network_isolate', v_run.reason,
      'pb:' || v_run.id::text || ':2', least(3600, v_remaining), null);
    insert into public.fleet_response_playbook_steps(
      run_id, tenant_id, actor_user_id, agent_id, incident_id, step_id, ordinal,
      command_type, command_id, state, result_code
    ) values (
      v_run.id, v_run.tenant_id, v_run.actor_user_id, v_run.agent_id, v_run.incident_id,
      'isolate_network', 2, v_next.command_type, v_next.id, v_next.state, v_next.result_code
    );
    update public.fleet_response_playbook_runs
    set current_step = 2 where id = v_run.id;
    return new;
  end if;

  select exists (
    select 1 from public.fleet_response_playbook_steps s
    where s.run_id = v_run.id and s.ordinal < v_step.ordinal and s.state = 'succeeded'
  ) into v_has_applied;
  update public.fleet_response_playbook_runs
  set state = case
        when v_has_applied then 'partial'
        when new.state = 'expired' then 'expired'
        when new.state = 'outcome_unknown' then 'outcome_unknown'
        when new.state = 'cancelled' then 'cancelled'
        else 'failed'
      end,
      completed_at = now(),
      result_code = coalesce(new.result_code, case new.state
        when 'expired' then 'ttl_elapsed'
        when 'outcome_unknown' then 'outcome_unknown'
        when 'cancelled' then 'operator_cancelled'
        else 'step_failed' end)
  where id = v_run.id;
  return new;
end;
$$;

create trigger fleet_response_playbook_advance
after update of state on public.fleet_response_commands
for each row execute function public.advance_fleet_response_playbook_step();

revoke all on function public.advance_fleet_response_playbook_step() from public, anon, authenticated;
