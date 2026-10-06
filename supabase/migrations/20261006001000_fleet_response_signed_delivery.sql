-- Keep the signed delivery target and the presented live credential in one
-- locked snapshot. The current API key has no TTL; retired hashes do.
create function app.lock_fleet_response_agent(
  p_key_hash text, p_tenant_id uuid, p_agent_id uuid,
  p_installation_id text default null
)
returns text language plpgsql security definer
set search_path = pg_catalog, public, auth, pg_temp as $$
declare
  v_key_id uuid;
  v_user_id uuid;
  v_key public.api_keys;
  v_member public.tenant_members;
  v_agent public.agents;
  v_tenant public.tenants;
begin
  if p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$'
     or p_tenant_id is null or p_agent_id is null
     or (p_installation_id is not null and
       (length(p_installation_id) not between 1 and 128
        or length(btrim(p_installation_id)) = 0 or p_installation_id ~ '[[:cntrl:]]')) then
    raise exception 'fleet_agent_forbidden' using errcode = '42501';
  end if;
  select k.id,k.user_id into v_key_id,v_user_id from public.api_keys k
    where k.tenant_id = p_tenant_id and k.agent_id = p_agent_id
      and (k.key_hash = p_key_hash or k.previous_hash = p_key_hash)
    order by (k.key_hash = p_key_hash) desc,k.id limit 1;
  if not found then raise exception 'fleet_agent_forbidden' using errcode = '42501'; end if;

  -- Parent before child: Auth deletion, tenant closing and membership
  -- revocation cannot invert a key-first authentication lock.
  perform 1 from auth.users where id = v_user_id for share;
  if not found then raise exception 'fleet_agent_forbidden' using errcode = '42501'; end if;
  select * into v_tenant from public.tenants where id = p_tenant_id for share;
  if not found then raise exception 'fleet_agent_forbidden' using errcode = '42501'; end if;
  select * into v_member from public.tenant_members
    where tenant_id = p_tenant_id and user_id = v_user_id for share;
  if not found then raise exception 'fleet_agent_forbidden' using errcode = '42501'; end if;
  select * into v_agent from public.agents
    where id = p_agent_id and tenant_id = p_tenant_id for share;
  if not found then raise exception 'fleet_agent_forbidden' using errcode = '42501'; end if;
  select * into v_key from public.api_keys where id = v_key_id for share;
  if not found or v_key.revoked or v_key.user_id is distinct from v_user_id
     or v_key.tenant_id is distinct from p_tenant_id or v_key.agent_id is distinct from p_agent_id
     or (v_key.key_hash = p_key_hash or
       (v_key.previous_hash = p_key_hash and v_key.previous_hash_expires_at > clock_timestamp())) is not true
     or v_tenant.status <> 'active' or v_member.role not in ('owner','admin','member')
     or (v_member.expires_at is not null and v_member.expires_at <= clock_timestamp())
     or v_agent.user_id is distinct from v_user_id
     or length(v_agent.iid) not between 1 and 128 or v_agent.iid ~ '[[:cntrl:]]'
     or (p_installation_id is not null and v_agent.iid is distinct from p_installation_id) then
    raise exception 'fleet_agent_forbidden' using errcode = '42501';
  end if;
  return v_agent.iid;
end;
$$;
revoke all on function app.lock_fleet_response_agent(text,uuid,uuid,text)
  from public, anon, authenticated, service_role;

-- Keep both existing transport state machines. They share the locked live
-- credential check and use the actual clock after any authentication/row wait.
do $migration$
declare
  v_signature text;
  v_definition text;
  v_start text := 'perform 1 from public.api_keys k';
  v_end text := 'if not found then raise exception ''fleet_agent_forbidden'' using errcode=''42501''; end if;';
  v_old text;
  v_first integer;
  v_last integer;
begin
  foreach v_signature in array array[
    'public.poll_fleet_response_command(text,uuid,uuid)',
    'public.record_fleet_response_command(text,uuid,uuid,uuid,text,text,text)'
  ] loop
    select pg_get_functiondef(v_signature::regprocedure) into v_definition;
    if cardinality(string_to_array(v_definition,v_start)) <> 2
       or cardinality(string_to_array(v_definition,v_end)) <> 2
       or position('now()' in v_definition) = 0 then
      raise exception 'unexpected_fleet_delivery_definition: %',v_signature;
    end if;
    v_first := position(v_start in v_definition);
    v_last := position(v_end in v_definition);
    if v_last <= v_first then raise exception 'unexpected_fleet_delivery_auth_order'; end if;
    v_old := substring(v_definition from v_first for v_last + length(v_end) - v_first);
    v_definition := replace(v_definition,v_old,
      'perform app.lock_fleet_response_agent(p_key_hash,p_tenant_id,p_agent_id);');
    -- A command/receipt or audit wait may also cross a credential deadline.
    -- Refuse and roll back every return path if its locked authority expired.
    if cardinality(string_to_array(v_definition,'return v_command;')) < 2 then
      raise exception 'unexpected_fleet_delivery_return_definition: %',v_signature;
    end if;
    v_definition := replace(v_definition,'return v_command;',
      'perform app.lock_fleet_response_agent(p_key_hash,p_tenant_id,p_agent_id); return v_command;');
    v_definition := replace(v_definition,'return null;',
      'perform app.lock_fleet_response_agent(p_key_hash,p_tenant_id,p_agent_id); return null;');
    execute replace(v_definition,'now()','clock_timestamp()');
  end loop;
end
$migration$;

create function public.poll_bound_fleet_response_command(
  p_key_hash text, p_tenant_id uuid, p_agent_id uuid, p_installation_id text
)
returns jsonb language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp as $$
declare v_iid text; v_command public.fleet_response_commands;
begin
  if p_installation_id is null then raise exception 'fleet_agent_forbidden' using errcode = '42501'; end if;
  v_iid := app.lock_fleet_response_agent(p_key_hash,p_tenant_id,p_agent_id,p_installation_id);
  v_command := public.poll_fleet_response_command(p_key_hash,p_tenant_id,p_agent_id);
  return jsonb_build_object('command',case when v_command.id is null then null else to_jsonb(v_command) end,
    'tenant_id',p_tenant_id,'agent_id',p_agent_id,'installation_id',v_iid,'key_hash',p_key_hash);
end;
$$;
revoke all on function public.poll_bound_fleet_response_command(text,uuid,uuid,text)
  from public, anon, authenticated;
grant execute on function public.poll_bound_fleet_response_command(text,uuid,uuid,text) to service_role;

-- Delivery/result updates may change only mutable execution fields. The bytes
-- signed for a command, its idempotency identity and its TTL never change.
create function app.fleet_response_command_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public, pg_temp as $$
begin
  if (new.id,new.tenant_id,new.agent_id,new.actor_user_id,new.command_type,new.reason,
      new.idempotency_key,new.request_fingerprint,new.rollback_of,new.created_at,new.expires_at)
     is distinct from
     (old.id,old.tenant_id,old.agent_id,old.actor_user_id,old.command_type,old.reason,
      old.idempotency_key,old.request_fingerprint,old.rollback_of,old.created_at,old.expires_at) then
    raise exception 'fleet_command_binding_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.fleet_response_command_immutable() from public, anon, authenticated, service_role;
create trigger fleet_response_command_immutable before update on public.fleet_response_commands
for each row execute function app.fleet_response_command_immutable();

-- An alarm/SOAR trigger is an explicitly authorized operator start with a
-- separate stable namespace and one atomic provenance audit, never a relabel.
create function public.trigger_fleet_response_playbook(
  p_tenant_id uuid, p_actor_user_id uuid, p_agent_id uuid, p_incident_id uuid,
  p_playbook_id text, p_reason text, p_idempotency_key text, p_ttl_seconds integer,
  p_trigger_source text
)
returns jsonb language plpgsql security definer
set search_path = pg_catalog, public, extensions, pg_temp as $$
declare v_key text; v_existing public.fleet_response_playbook_runs; v_result jsonb;
begin
  if p_trigger_source is null or p_trigger_source not in ('alarm','soar')
     or p_idempotency_key is null or p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$' then
    raise exception 'invalid_response_playbook_trigger' using errcode = '22023';
  end if;
  v_key := 'trigger:' || p_trigger_source || ':' || encode(extensions.digest(p_idempotency_key,'sha256'),'hex');
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':response-playbook:' || v_key,73923));
  select * into v_existing from public.fleet_response_playbook_runs
    where tenant_id = p_tenant_id and idempotency_key = v_key;
  if found and not exists (
    select 1 from public.admin_audit_logs a where a.tenant_id = p_tenant_id
      and a.action = 'fleet.response.playbook_triggered' and a.actor_user_id = v_existing.actor_user_id
      and a.detail->>'run_id' = v_existing.id::text
      and a.detail->>'trigger_source' = p_trigger_source
      and a.detail->>'incident_reference' = v_existing.incident_id::text
  ) then raise exception 'response_playbook_trigger_provenance_conflict' using errcode = 'PT409'; end if;
  v_result := public.start_fleet_response_playbook(p_tenant_id,p_actor_user_id,p_agent_id,p_incident_id,
    p_playbook_id,p_reason,v_key,p_ttl_seconds);
  -- start holds the membership/tenant rows; evaluate its time-sensitive
  -- authority again after its idempotency, quota and row-lock waits.
  if not exists (select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id and m.role in ('owner','admin')
      and (m.expires_at is null or m.expires_at > clock_timestamp()) and t.status = 'active') then
    raise exception 'response_playbook_operator_forbidden' using errcode = '42501';
  end if;
  if v_existing.id is null then
    insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
      values(p_actor_user_id,p_tenant_id,'fleet.response.playbook_triggered',jsonb_build_object(
        'run_id',v_result->>'id','trigger_source',p_trigger_source,'incident_reference',p_incident_id,
        'agent_id',p_agent_id,'playbook_id',p_playbook_id));
  end if;
  return v_result;
end;
$$;
revoke all on function public.trigger_fleet_response_playbook(uuid,uuid,uuid,uuid,text,text,text,integer,text)
  from public, anon, authenticated;
grant execute on function public.trigger_fleet_response_playbook(uuid,uuid,uuid,uuid,text,text,text,integer,text)
  to service_role;
