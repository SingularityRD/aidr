-- Explicit machine authority reuses the existing grant, revocation and
-- security-audit offboarding lifecycle. The Edge route returns the secret once;
-- PostgreSQL receives only its digest and the verified creator-session time.
alter table public.delegated_credential_grants
  add column automation_secret_hash text,
  add column automation_session_issued_at timestamptz,
  add column automation_target_identity jsonb,
  add constraint response_automation_proof_check check (
    (automation_secret_hash is null and automation_session_issued_at is null
      and automation_target_identity is null)
    or coalesce(
      automation_secret_hash ~ '^[a-f0-9]{64}$'
      and automation_session_issued_at is not null
      and automation_session_issued_at > to_timestamp(0)
      and subject_user_id = created_by
      and tool_server_id = 'aidr-response' and tool_name in ('alarm','soar')
      and resource_type = 'response_playbook' and resource_id = 'agent_containment_v1'
      and audience = 'aidr-response-playbooks' and scopes = array['fleet:containment']::text[]
      and max_delegation_depth = 0 and expires_at > created_at
      and expires_at <= created_at + interval '90 days'
      and case when jsonb_typeof(automation_target_identity) = 'object' then
        automation_target_identity = jsonb_build_object(
          'user_id',automation_target_identity->'user_id','iid',automation_target_identity->'iid')
        and automation_target_identity ?& array['user_id','iid']
        and jsonb_typeof(automation_target_identity->'user_id') = 'string'
        and automation_target_identity->>'user_id' ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
        and jsonb_typeof(automation_target_identity->'iid') = 'string'
        and length(automation_target_identity->>'iid') between 1 and 128
        and length(btrim(automation_target_identity->>'iid')) > 0
        and automation_target_identity->>'iid' !~ '[[:cntrl:]]'
      else false end,
      false)
  );
create unique index response_automation_secret_unique
  on public.delegated_credential_grants(automation_secret_hash)
  where automation_secret_hash is not null;

-- Every production writer already uses a definer RPC. Keep direct service
-- access read-only: the general grant RPC cannot populate automation proof.
revoke all on public.delegated_credential_grants from service_role;
grant select on public.delegated_credential_grants to service_role;

create function app.response_automation_grant_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public, pg_temp as $$
begin
  if old.automation_secret_hash is null then
    if new.automation_secret_hash is not null then
      raise exception 'response_automation_binding_immutable' using errcode = '42501';
    end if;
  elsif (to_jsonb(new) - 'revoked_at') is distinct from (to_jsonb(old) - 'revoked_at')
    or (old.revoked_at is not null and new.revoked_at is distinct from old.revoked_at) then
    raise exception 'response_automation_binding_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.response_automation_grant_immutable() from public, anon, authenticated, service_role;
create trigger response_automation_grant_immutable
before update on public.delegated_credential_grants
for each row execute function app.response_automation_grant_immutable();

create function app.response_automation_grant_json(p_grant public.delegated_credential_grants)
returns jsonb language sql immutable set search_path = pg_catalog, public, pg_temp as $$
  select jsonb_build_object('grant_id',p_grant.id,'tenant_id',p_grant.tenant_id,
    'agent_id',p_grant.agent_id,'playbook_id',p_grant.resource_id,'trigger_source',p_grant.tool_name,
    'created_by',p_grant.created_by,'max_ttl_seconds',p_grant.max_ttl_seconds,
    'created_at',p_grant.created_at,'expires_at',p_grant.expires_at,'revoked_at',p_grant.revoked_at);
$$;
revoke all on function app.response_automation_grant_json(public.delegated_credential_grants)
  from public, anon, authenticated, service_role;

-- The target is optional only for the human revoke operation. Sorted Auth
-- parents precede tenant/member/agent children; the creator's 2611 lock also
-- serializes the mint-session barrier with global sign-out and recovery.
create function app.response_automation_require_authority(
  p_tenant_id uuid, p_actor_user_id uuid, p_validated_session_issued_at timestamptz,
  p_agent_id uuid, p_target_identity jsonb
)
returns void language plpgsql security definer set search_path = pg_catalog, public, auth, pg_temp as $$
declare v_target_user uuid; v_agent public.agents;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_validated_session_issued_at is null
    or p_validated_session_issued_at <= to_timestamp(0)
    or p_validated_session_issued_at > clock_timestamp() + interval '1 minute'
    or ((p_agent_id is null) <> (p_target_identity is null)) then
    raise exception 'response_automation_forbidden' using errcode = '42501';
  end if;
  v_target_user := coalesce((p_target_identity->>'user_id')::uuid,p_actor_user_id);
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text,2606));
  perform pg_advisory_xact_lock(hashtextextended(p_actor_user_id::text,2611));
  perform 1 from auth.users u where u.id in (p_actor_user_id,v_target_user) order by u.id for share;
  if not exists (select 1 from auth.users where id = p_actor_user_id)
    or not exists (select 1 from auth.users where id = v_target_user) then
    raise exception 'response_automation_forbidden' using errcode = '42501';
  end if;
  perform 1 from public.tenants where id = p_tenant_id for share;
  perform 1 from public.tenant_members m where m.tenant_id = p_tenant_id
    and m.user_id in (p_actor_user_id,v_target_user) order by m.user_id for share;
  if p_agent_id is not null then
    select * into v_agent from public.agents where id = p_agent_id and tenant_id = p_tenant_id for share;
    if not found or v_agent.user_id is distinct from v_target_user
      or v_agent.iid is distinct from p_target_identity->>'iid' then
      raise exception 'response_automation_target_changed' using errcode = '42501';
    end if;
  end if;
  -- Evaluate deadlines after every parent/authority/target row-lock wait.
  if not exists (select 1 from public.tenants where id = p_tenant_id and status = 'active')
    or not exists (select 1 from public.tenant_members m where m.tenant_id = p_tenant_id
      and m.user_id = p_actor_user_id and m.role in ('owner','admin')
      and (m.expires_at is null or m.expires_at > clock_timestamp()))
    or not exists (select 1 from public.tenant_members m where m.tenant_id = p_tenant_id
      and m.user_id = v_target_user and m.role in ('owner','admin','member')
      and (m.expires_at is null or m.expires_at > clock_timestamp())) then
    raise exception 'response_automation_forbidden' using errcode = '42501';
  end if;
  if exists (select 1 from public.identity_user_session_state s where s.user_id = p_actor_user_id
    and (s.global_revoke_pending_session_id is not null
      or (s.revoked_before is not null and p_validated_session_issued_at <= s.revoked_before))) then
    raise exception 'response_automation_session_revoked' using errcode = '42501';
  end if;
end;
$$;
revoke all on function app.response_automation_require_authority(uuid,uuid,timestamptz,uuid,jsonb)
  from public, anon, authenticated, service_role;

create function public.create_response_automation_grant(
  p_tenant_id uuid, p_actor_user_id uuid, p_agent_id uuid, p_source text, p_reason text,
  p_max_ttl_seconds integer, p_grant_expires_in_seconds integer, p_secret_hash text,
  p_validated_session_issued_at timestamptz
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, auth, app, pg_temp as $$
declare v_target jsonb; v_grant public.delegated_credential_grants; v_now timestamptz;
begin
  if p_agent_id is null or p_source is null or p_source not in ('alarm','soar')
    or p_reason is null or length(btrim(p_reason)) not between 12 and 500 or p_reason ~ '[[:cntrl:]]'
    or p_max_ttl_seconds is null or p_max_ttl_seconds not between 30 and 900
    or p_grant_expires_in_seconds is null or p_grant_expires_in_seconds not between 60 and 7776000
    or p_secret_hash is null or p_secret_hash !~ '^[a-f0-9]{64}$' then
    raise exception 'invalid_response_automation_grant' using errcode = '22023';
  end if;
  select jsonb_build_object('user_id',user_id,'iid',iid) into v_target from public.agents
    where id = p_agent_id and tenant_id = p_tenant_id;
  if not found then raise exception 'response_automation_target_changed' using errcode = '42501'; end if;
  perform app.response_automation_require_authority(p_tenant_id,p_actor_user_id,
    p_validated_session_issued_at,p_agent_id,v_target);
  v_now := clock_timestamp();
  insert into public.delegated_credential_grants(tenant_id,subject_user_id,agent_id,tool_server_id,tool_name,
    resource_type,resource_id,audience,scopes,max_ttl_seconds,max_delegation_depth,expires_at,created_by,
    created_at,automation_secret_hash,automation_session_issued_at,automation_target_identity)
  values(p_tenant_id,p_actor_user_id,p_agent_id,'aidr-response',p_source,'response_playbook','agent_containment_v1',
    'aidr-response-playbooks',array['fleet:containment'],p_max_ttl_seconds,0,
    v_now + make_interval(secs => p_grant_expires_in_seconds),p_actor_user_id,v_now,p_secret_hash,
    p_validated_session_issued_at,v_target) returning * into v_grant;
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
    values(p_actor_user_id,p_tenant_id,'fleet.response.automation_grant_created',jsonb_build_object(
      'grant_id',v_grant.id,'agent_id',p_agent_id,'playbook_id',v_grant.resource_id,'trigger_source',p_source,
      'reason',btrim(p_reason),'max_ttl_seconds',p_max_ttl_seconds,'expires_at',v_grant.expires_at));
  perform app.response_automation_require_authority(p_tenant_id,p_actor_user_id,
    p_validated_session_issued_at,p_agent_id,v_target);
  if v_grant.expires_at <= clock_timestamp() then
    raise exception 'response_automation_grant_inactive' using errcode = '42501';
  end if;
  return app.response_automation_grant_json(v_grant);
end;
$$;
revoke all on function public.create_response_automation_grant(uuid,uuid,uuid,text,text,integer,integer,text,timestamptz)
  from public, anon, authenticated;
grant execute on function public.create_response_automation_grant(uuid,uuid,uuid,text,text,integer,integer,text,timestamptz)
  to service_role;

create function public.revoke_response_automation_grant(
  p_tenant_id uuid, p_actor_user_id uuid, p_grant_id uuid, p_reason text,
  p_validated_session_issued_at timestamptz
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, app, pg_temp as $$
declare v_grant public.delegated_credential_grants;
begin
  if p_grant_id is null or p_reason is null or length(btrim(p_reason)) not between 12 and 500
    or p_reason ~ '[[:cntrl:]]' then
    raise exception 'invalid_response_automation_grant' using errcode = '22023';
  end if;
  perform app.response_automation_require_authority(p_tenant_id,p_actor_user_id,
    p_validated_session_issued_at,null,null);
  select * into v_grant from public.delegated_credential_grants
    where id = p_grant_id and tenant_id = p_tenant_id and automation_secret_hash is not null for update;
  if not found then raise exception 'response_automation_grant_not_found' using errcode = 'P0002'; end if;
  if v_grant.revoked_at is null then
    update public.delegated_credential_grants set revoked_at = clock_timestamp()
      where id = p_grant_id returning * into v_grant;
    update public.delegated_credential_receipts set state = 'revoked',revoked_at = coalesce(revoked_at,clock_timestamp())
      where grant_id = p_grant_id and state <> 'revoked';
    insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
      values(p_actor_user_id,p_tenant_id,'fleet.response.automation_grant_revoked',jsonb_build_object(
        'grant_id',p_grant_id,'agent_id',v_grant.agent_id,'trigger_source',v_grant.tool_name,'reason',btrim(p_reason)));
  end if;
  perform app.response_automation_require_authority(p_tenant_id,p_actor_user_id,
    p_validated_session_issued_at,null,null);
  return app.response_automation_grant_json(v_grant);
end;
$$;
revoke all on function public.revoke_response_automation_grant(uuid,uuid,uuid,text,timestamptz)
  from public, anon, authenticated;
grant execute on function public.revoke_response_automation_grant(uuid,uuid,uuid,text,timestamptz) to service_role;

create function public.trigger_response_automation_playbook(
  p_tenant_id uuid, p_grant_id uuid, p_secret_hash text, p_incident_id uuid,
  p_reason text, p_ttl_seconds integer
)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, app, pg_temp as $$
declare
  v_grant public.delegated_credential_grants;
  v_initial public.delegated_credential_grants;
  v_existing public.fleet_response_playbook_runs;
  v_key text;
  v_result jsonb;
begin
  if p_tenant_id is null or p_grant_id is null or p_incident_id is null
    or p_secret_hash is null or p_secret_hash !~ '^[a-f0-9]{64}$'
    or p_reason is null or length(btrim(p_reason)) not between 12 and 500 or p_reason ~ '[[:cntrl:]]'
    or p_ttl_seconds is null or p_ttl_seconds not between 30 and 900 then
    raise exception 'response_automation_invalid_trigger' using errcode = '22023';
  end if;
  select * into v_initial from public.delegated_credential_grants
    where id = p_grant_id and tenant_id = p_tenant_id and automation_secret_hash = p_secret_hash;
  if not found then raise exception 'response_automation_grant_inactive' using errcode = '42501'; end if;
  perform app.response_automation_require_authority(p_tenant_id,v_initial.created_by,
    v_initial.automation_session_issued_at,v_initial.agent_id,v_initial.automation_target_identity);
  select * into v_grant from public.delegated_credential_grants
    where id = p_grant_id and tenant_id = p_tenant_id for update;
  if not found or v_grant.automation_secret_hash is distinct from p_secret_hash
    or v_grant.revoked_at is not null or v_grant.expires_at <= clock_timestamp() then
    raise exception 'response_automation_grant_inactive' using errcode = '42501';
  end if;
  if p_ttl_seconds > v_grant.max_ttl_seconds then
    raise exception 'response_automation_ttl_exceeded' using errcode = '42501';
  end if;
  v_key := 'automation:' || p_grant_id::text || ':' || p_incident_id::text;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':response-playbook:' || v_key,73923));
  select * into v_existing from public.fleet_response_playbook_runs
    where tenant_id = p_tenant_id and idempotency_key = v_key;
  if found and not exists (select 1 from public.admin_audit_logs a where a.tenant_id = p_tenant_id
    and a.actor_user_id = v_grant.created_by and a.action = 'fleet.response.playbook_triggered'
    and a.detail->>'run_id' = v_existing.id::text and a.detail->>'grant_id' = p_grant_id::text
    and a.detail->>'trigger_source' = v_grant.tool_name and a.detail->>'incident_reference' = p_incident_id::text
    and a.detail->>'agent_id' = v_grant.agent_id::text and a.detail->>'playbook_id' = v_grant.resource_id) then
    raise exception 'response_playbook_trigger_provenance_conflict' using errcode = 'PT409';
  end if;
  if v_existing.id is null and v_grant.expires_at < clock_timestamp() + make_interval(secs => p_ttl_seconds) then
    raise exception 'response_automation_ttl_exceeded' using errcode = '42501';
  end if;
  v_result := public.start_fleet_response_playbook(p_tenant_id,v_grant.created_by,v_grant.agent_id,p_incident_id,
    v_grant.resource_id,p_reason,v_key,p_ttl_seconds);
  if v_existing.id is null then
    insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
      values(v_grant.created_by,p_tenant_id,'fleet.response.playbook_triggered',jsonb_build_object(
        'run_id',v_result->>'id','grant_id',p_grant_id,'trigger_source',v_grant.tool_name,
        'incident_reference',p_incident_id,'agent_id',v_grant.agent_id,'playbook_id',v_grant.resource_id));
  end if;
  perform app.response_automation_require_authority(p_tenant_id,v_grant.created_by,
    v_grant.automation_session_issued_at,v_grant.agent_id,v_grant.automation_target_identity);
  if v_grant.expires_at <= clock_timestamp()
    or (v_existing.id is null and v_grant.expires_at < clock_timestamp() + make_interval(secs => p_ttl_seconds)) then
    raise exception 'response_automation_grant_inactive' using errcode = '42501';
  end if;
  return v_result;
end;
$$;
revoke all on function public.trigger_response_automation_playbook(uuid,uuid,text,uuid,text,integer)
  from public, anon, authenticated;
grant execute on function public.trigger_response_automation_playbook(uuid,uuid,text,uuid,text,integer) to service_role;

-- Automation proof is not an ordinary delegated JWT grant. Do not allow the
-- general issue/redelegate broker to mint or relabel this machine authority.
do $migration$
declare v_signature text; v_definition text;
  v_old text := 'if not found or v_grant.revoked_at is not null';
begin
  foreach v_signature in array array[
    'public.reserve_delegated_credential(uuid,text,jsonb)',
    'public.reserve_child_delegated_credential(text,jsonb,text,jsonb)'
  ] loop
    select pg_get_functiondef(v_signature::regprocedure) into v_definition;
    if cardinality(string_to_array(v_definition,v_old)) <> 2 then
      raise exception 'unexpected_response_automation_broker_definition: %',v_signature;
    end if;
    execute replace(v_definition,v_old,
      'if not found or v_grant.automation_secret_hash is not null or v_grant.revoked_at is not null');
  end loop;
end;
$migration$;
