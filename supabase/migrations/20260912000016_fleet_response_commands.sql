-- Tenant-scoped, bounded, auditable fleet response transport. Device execution
-- is deliberately separate: a reported result is not an OS/provider attestation.
create table public.fleet_response_commands (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  -- Preserve immutable target/actor identifiers after shorter-lived agent
  -- and account rows are removed during tenant offboarding.
  agent_id uuid not null,
  actor_user_id uuid not null,
  command_type text not null check (command_type in
    ('agent_pause', 'agent_resume', 'network_isolate', 'network_release')),
  reason text not null check (length(btrim(reason)) between 12 and 500),
  idempotency_key text not null check
    (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$'),
  request_fingerprint text not null check (request_fingerprint ~ '^[a-f0-9]{64}$'),
  rollback_of uuid,
  state text not null default 'pending' check (state in
    ('pending', 'delivered', 'acknowledged', 'succeeded', 'failed',
     'expired', 'outcome_unknown', 'cancelled')),
  attempts integer not null default 0 check (attempts between 0 and 5),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  delivered_at timestamptz,
  delivery_lease_until timestamptz,
  acknowledged_at timestamptz,
  completed_at timestamptz,
  result_code text check (result_code is null or result_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  unique(tenant_id, idempotency_key),
  unique(rollback_of)
);
create index fleet_response_agent_queue_idx on public.fleet_response_commands
  (tenant_id, agent_id, created_at, id)
  where state in ('pending', 'delivered', 'acknowledged');
create index fleet_response_tenant_history_idx on public.fleet_response_commands
  (tenant_id, created_at desc, id desc);
alter table public.fleet_response_commands enable row level security;
revoke all on public.fleet_response_commands from public, anon, authenticated;
grant select, insert, update on public.fleet_response_commands to service_role;

create function public.queue_fleet_response_command(
  p_tenant_id uuid, p_actor_user_id uuid, p_agent_id uuid,
  p_command_type text, p_reason text, p_idempotency_key text,
  p_ttl_seconds integer, p_rollback_of uuid default null
)
returns public.fleet_response_commands
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_existing public.fleet_response_commands;
  v_original public.fleet_response_commands;
  v_created public.fleet_response_commands;
  v_fingerprint text;
  v_expected_reverse text;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_agent_id is null
     or p_command_type is null
     or p_command_type not in ('agent_pause','agent_resume','network_isolate','network_release')
     or p_reason is null or length(btrim(p_reason)) not between 12 and 500
     or p_idempotency_key is null
     or p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$'
     or p_ttl_seconds is null or p_ttl_seconds not between 30 and 3600
  then raise exception 'invalid_fleet_command' using errcode='22023'; end if;
  perform 1 from public.tenant_members m join public.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=p_actor_user_id
      and m.role in ('owner','admin')
      and (m.expires_at is null or m.expires_at>now()) and t.status='active'
    for share of m,t;
  if not found then raise exception 'fleet_operator_forbidden' using errcode='42501'; end if;
  if not exists (
    select 1 from public.agents a where a.id=p_agent_id and a.tenant_id=p_tenant_id
  ) then raise exception 'fleet_agent_not_found' using errcode='22023'; end if;

  -- Serialize this idempotency key, including retries before the first insert.
  perform pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':' || p_idempotency_key, 4723));
  v_fingerprint := encode(extensions.digest(
    p_agent_id::text || ':' || p_command_type || ':' || btrim(p_reason) || ':'
      || p_ttl_seconds::text || ':' || coalesce(p_rollback_of::text,''),
    'sha256'), 'hex');
  select * into v_existing from public.fleet_response_commands
    where tenant_id=p_tenant_id and idempotency_key=p_idempotency_key;
  if found then
    if v_existing.request_fingerprint <> v_fingerprint
       or v_existing.actor_user_id <> p_actor_user_id
    then raise exception 'fleet_idempotency_conflict' using errcode='PT409'; end if;
    if v_existing.state in ('pending','delivered','acknowledged')
       and v_existing.expires_at<=now() then
      update public.fleet_response_commands
      set state=case when state='pending' then 'expired' else 'outcome_unknown' end,
          completed_at=now(), result_code='ttl_elapsed'
      where id=v_existing.id returning * into v_existing;
    end if;
    return v_existing;
  end if;

  if p_rollback_of is null then
    if p_command_type not in ('agent_pause','network_isolate')
    then raise exception 'rollback_reference_required' using errcode='22023'; end if;
  else
    select * into v_original from public.fleet_response_commands
      where id=p_rollback_of and tenant_id=p_tenant_id and agent_id=p_agent_id
      for update;
    if not found or v_original.state <> 'succeeded'
    then raise exception 'rollback_source_unavailable' using errcode='PT409'; end if;
    v_expected_reverse := case v_original.command_type
      when 'agent_pause' then 'agent_resume'
      when 'network_isolate' then 'network_release'
      else null end;
    if v_expected_reverse is distinct from p_command_type then
      raise exception 'rollback_action_mismatch' using errcode='22023'; end if;
    if exists(select 1 from public.fleet_response_commands where rollback_of=p_rollback_of)
    then raise exception 'rollback_already_requested' using errcode='PT409'; end if;
  end if;

  insert into public.fleet_response_commands(
    tenant_id, agent_id, actor_user_id, command_type, reason, idempotency_key,
    request_fingerprint, rollback_of, expires_at
  ) values (
    p_tenant_id, p_agent_id, p_actor_user_id, p_command_type, btrim(p_reason),
    p_idempotency_key, v_fingerprint, p_rollback_of,
    now() + make_interval(secs => p_ttl_seconds)
  ) returning * into v_created;
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
  values(p_actor_user_id,p_tenant_id,'fleet.response.queued',
    jsonb_build_object('command_id',v_created.id,'agent_id',p_agent_id,
      'command_type',p_command_type,'rollback_of',p_rollback_of));
  return v_created;
end;
$$;
revoke all on function public.queue_fleet_response_command(uuid,uuid,uuid,text,text,text,integer,uuid)
  from public, anon, authenticated;
grant execute on function public.queue_fleet_response_command(uuid,uuid,uuid,text,text,text,integer,uuid)
  to service_role;

create function public.poll_fleet_response_command(p_key_hash text, p_tenant_id uuid, p_agent_id uuid)
returns public.fleet_response_commands
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_command public.fleet_response_commands;
begin
  if p_key_hash is null or p_tenant_id is null or p_agent_id is null
  then raise exception 'fleet_agent_forbidden' using errcode='42501'; end if;
  perform 1 from public.api_keys k
    join public.tenant_members m on m.tenant_id=k.tenant_id and m.user_id=k.user_id
    join public.agents a on a.id=k.agent_id and a.tenant_id=k.tenant_id
    join public.tenants t on t.id=k.tenant_id
    where k.key_hash=p_key_hash and not k.revoked
      and k.tenant_id=p_tenant_id and k.agent_id=p_agent_id
      and (m.expires_at is null or m.expires_at>now()) and t.status='active'
    for share of k,m,a,t;
  if not found then raise exception 'fleet_agent_forbidden' using errcode='42501'; end if;

  update public.fleet_response_commands
  set state=case when state='pending' then 'expired' else 'outcome_unknown' end,
      completed_at=now(), result_code='ttl_elapsed'
  where tenant_id=p_tenant_id and agent_id=p_agent_id
    and state in ('pending','delivered','acknowledged') and expires_at<=now();
  update public.fleet_response_commands
  set state='outcome_unknown', completed_at=now(), result_code='delivery_attempts_exhausted'
  where tenant_id=p_tenant_id and agent_id=p_agent_id and state='delivered'
    and delivery_lease_until<=now() and attempts>=5;

  select * into v_command from public.fleet_response_commands
  where tenant_id=p_tenant_id and agent_id=p_agent_id and expires_at>now()
    and (state='pending' or (state='delivered' and delivery_lease_until<=now() and attempts<5))
  order by created_at,id
  for update skip locked limit 1;
  if not found then return null; end if;
  update public.fleet_response_commands
  set state='delivered', delivered_at=now(), delivery_lease_until=now()+interval '30 seconds',
      attempts=attempts+1
  where id=v_command.id returning * into v_command;
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
  values(null,p_tenant_id,'fleet.response.delivered',
    jsonb_build_object('command_id',v_command.id,'agent_id',p_agent_id,
      'attempt',v_command.attempts));
  return v_command;
end;
$$;
revoke all on function public.poll_fleet_response_command(text,uuid,uuid)
  from public, anon, authenticated;
grant execute on function public.poll_fleet_response_command(text,uuid,uuid) to service_role;

create function public.record_fleet_response_command(
  p_key_hash text, p_tenant_id uuid, p_agent_id uuid, p_command_id uuid,
  p_stage text, p_outcome text, p_result_code text default null
)
returns public.fleet_response_commands
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_command public.fleet_response_commands; v_state text;
begin
  if p_key_hash is null or p_tenant_id is null or p_agent_id is null or p_command_id is null
     or p_stage is null or p_stage not in ('ack','result')
     or p_outcome is null
     or (p_stage='ack' and p_outcome not in ('accepted','rejected'))
     or (p_stage='result' and p_outcome not in ('succeeded','failed'))
     or (p_result_code is not null and p_result_code !~ '^[a-z][a-z0-9_]{0,63}$')
  then raise exception 'invalid_fleet_result' using errcode='22023'; end if;
  perform 1 from public.api_keys k
    join public.tenant_members m on m.tenant_id=k.tenant_id and m.user_id=k.user_id
    join public.agents a on a.id=k.agent_id and a.tenant_id=k.tenant_id
    join public.tenants t on t.id=k.tenant_id
    where k.key_hash=p_key_hash and not k.revoked
      and k.tenant_id=p_tenant_id and k.agent_id=p_agent_id
      and (m.expires_at is null or m.expires_at>now()) and t.status='active'
    for share of k,m,a,t;
  if not found then raise exception 'fleet_agent_forbidden' using errcode='42501'; end if;
  select * into v_command from public.fleet_response_commands
    where id=p_command_id and tenant_id=p_tenant_id and agent_id=p_agent_id for update;
  if not found then raise exception 'fleet_command_not_found' using errcode='42501'; end if;
  if v_command.state in ('pending','delivered','acknowledged') and v_command.expires_at<=now() then
    update public.fleet_response_commands
    set state=case when state='pending' then 'expired' else 'outcome_unknown' end,
        completed_at=now(), result_code='ttl_elapsed'
    where id=p_command_id returning * into v_command;
    return v_command;
  end if;
  v_state := case when p_stage='ack' then
    case when p_outcome='accepted' then 'acknowledged' else 'failed' end
    else p_outcome end;
  if v_command.state=v_state
     and v_command.result_code is not distinct from p_result_code then
    return v_command; end if;
  if (p_stage='ack' and v_command.state<>'delivered')
     or (p_stage='result' and v_command.state<>'acknowledged')
  then raise exception 'fleet_command_state_conflict' using errcode='PT409'; end if;
  update public.fleet_response_commands
  set state=v_state,
      acknowledged_at=case when p_stage='ack' then now() else acknowledged_at end,
      completed_at=case when v_state in ('succeeded','failed') then now() else completed_at end,
      result_code=p_result_code
  where id=p_command_id returning * into v_command;
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
  values(null,p_tenant_id,'fleet.response.'||p_stage,
    jsonb_build_object('command_id',p_command_id,'agent_id',p_agent_id,
      'state',v_state,'result_code',p_result_code));
  return v_command;
end;
$$;
revoke all on function public.record_fleet_response_command(text,uuid,uuid,uuid,text,text,text)
  from public, anon, authenticated;
grant execute on function public.record_fleet_response_command(text,uuid,uuid,uuid,text,text,text)
  to service_role;

create function public.cancel_fleet_response_command(
  p_tenant_id uuid, p_actor_user_id uuid, p_command_id uuid
)
returns public.fleet_response_commands
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_command public.fleet_response_commands;
begin
  perform 1 from public.tenant_members m join public.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=p_actor_user_id
      and m.role in ('owner','admin') and (m.expires_at is null or m.expires_at>now())
      and t.status='active'
    for share of m,t;
  if not found then raise exception 'fleet_operator_forbidden' using errcode='42501'; end if;
  select * into v_command from public.fleet_response_commands
    where id=p_command_id and tenant_id=p_tenant_id for update;
  if not found then raise exception 'fleet_command_not_found' using errcode='42501'; end if;
  if v_command.state in ('pending','delivered','acknowledged')
     and v_command.expires_at<=now() then
    update public.fleet_response_commands
    set state=case when state='pending' then 'expired' else 'outcome_unknown' end,
        completed_at=now(), result_code='ttl_elapsed'
    where id=p_command_id returning * into v_command;
    return v_command;
  end if;
  if v_command.state='cancelled' then return v_command; end if;
  if v_command.state<>'pending' then
    raise exception 'fleet_command_outcome_uncertain' using errcode='PT409'; end if;
  update public.fleet_response_commands
  set state='cancelled',completed_at=now(),result_code='operator_cancelled'
  where id=p_command_id returning * into v_command;
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
  values(p_actor_user_id,p_tenant_id,'fleet.response.cancelled',
    jsonb_build_object('command_id',p_command_id,'agent_id',v_command.agent_id));
  return v_command;
end;
$$;
revoke all on function public.cancel_fleet_response_command(uuid,uuid,uuid)
  from public, anon, authenticated;
grant execute on function public.cancel_fleet_response_command(uuid,uuid,uuid) to service_role;
