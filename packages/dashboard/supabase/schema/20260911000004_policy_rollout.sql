-- Enrollment-issued keys identify one agent. Unbound manually issued keys stay
-- tenant credentials and cannot claim a per-agent policy loading receipt.
alter table public.agents add constraint agents_id_tenant_unique unique(id, tenant_id);
alter table public.api_keys add column agent_id uuid;
alter table public.api_keys add constraint api_keys_bound_agent_fkey foreign key(agent_id, tenant_id) references public.agents(id, tenant_id) on delete cascade;
create function app.protect_api_key_agent_binding() returns trigger language plpgsql set search_path=public,pg_temp as $$
begin
  if current_user in ('authenticated','anon') and (new.agent_id is not null or (tg_op='UPDATE' and old.agent_id is not null)) then
    raise exception 'agent_key_binding_is_server_managed' using errcode='42501';
  end if;
  if new.agent_id is not null and not exists(select 1 from public.agents where id=new.agent_id and tenant_id=new.tenant_id and user_id=new.user_id) then
    raise exception 'agent_key_owner_mismatch' using errcode='23514';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_api_key_agent_binding() from public, anon, authenticated;
create trigger api_key_agent_binding before insert or update of agent_id,user_id,tenant_id on public.api_keys for each row execute function app.protect_api_key_agent_binding();

create table public.agent_policy_assignments (
  tenant_id uuid not null references public.tenants(id),
  agent_id uuid primary key,
  version bigint not null,
  assigned_by uuid not null references auth.users(id),
  assigned_at timestamptz not null default now(),
  foreign key(agent_id, tenant_id) references public.agents(id, tenant_id) on delete cascade,
  foreign key(tenant_id, version) references public.runtime_policy_revisions(tenant_id, version)
);
create table public.agent_policy_receipts (
  tenant_id uuid not null references public.tenants(id),
  agent_id uuid primary key,
  version bigint not null,
  policy_sha256 text not null check(policy_sha256 ~ '^[a-f0-9]{64}$'),
  received_at timestamptz not null default now(),
  foreign key(agent_id, tenant_id) references public.agents(id, tenant_id) on delete cascade,
  foreign key(tenant_id, version) references public.runtime_policy_revisions(tenant_id, version)
);
alter table public.agent_policy_assignments enable row level security;
alter table public.agent_policy_receipts enable row level security;
revoke all on public.agent_policy_assignments, public.agent_policy_receipts from anon, authenticated;
grant all on public.agent_policy_assignments, public.agent_policy_receipts to service_role;

-- All publication paths share the existing advisory lock. New versions must be
-- greater than staged versions too. Publishing to everyone ends targeted stages.
do $migration$
declare definition text;
begin
  select pg_get_functiondef('public.publish_runtime_policy(uuid,uuid,bigint,jsonb)'::regprocedure) into definition;
  if position('values(p_tenant_id, p_expected_version + 1, p_policy, p_user_id)' in definition) = 0 then raise exception 'unexpected publish function definition'; end if;
  definition := replace(definition, 'values(p_tenant_id, p_expected_version + 1, p_policy, p_user_id)', 'values(p_tenant_id, (select coalesce(max(version),0)+1 from public.runtime_policy_revisions where tenant_id=p_tenant_id), p_policy, p_user_id)');
  definition := replace(definition, 'return result;', 'delete from public.agent_policy_assignments where tenant_id = p_tenant_id; return result;');
  execute definition;
end;
$migration$;

create function public.stage_runtime_policy(p_tenant_id uuid, p_user_id uuid, p_expected_version bigint, p_policy jsonb, p_agent_ids uuid[])
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_current bigint; v_version bigint; v_count integer;
begin
  if not exists(select 1 from public.tenant_members m join public.tenants t on t.id=m.tenant_id where m.user_id=p_user_id and m.tenant_id=p_tenant_id and m.role in ('owner','admin') and (m.expires_at is null or m.expires_at>now()) and t.status='active') then
    raise exception 'policy_forbidden' using errcode='42501';
  end if;
  if p_expected_version is null or p_expected_version < 0 or p_policy is null or jsonb_typeof(p_policy)<>'object' or octet_length(p_policy::text)>65536 or coalesce(cardinality(p_agent_ids),0) not between 1 and 200 then
    raise exception 'invalid_stage' using errcode='22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text,911));
  select version into v_current from public.tenant_runtime_policies where tenant_id=p_tenant_id;
  if coalesce(v_current,0) <> p_expected_version then raise exception 'policy_version_conflict' using errcode='PT409'; end if;
  select count(*) into v_count from public.agents where tenant_id=p_tenant_id and id=any(p_agent_ids);
  if v_count <> cardinality(p_agent_ids) then raise exception 'invalid_stage_agents' using errcode='22023'; end if;
  select coalesce(max(version),0)+1 into v_version from public.runtime_policy_revisions where tenant_id=p_tenant_id;
  insert into public.runtime_policy_revisions(tenant_id,version,policy,updated_by) values(p_tenant_id,v_version,p_policy,p_user_id);
  insert into public.agent_policy_assignments(tenant_id,agent_id,version,assigned_by)
    select p_tenant_id,unnest(p_agent_ids),v_version,p_user_id
    on conflict(agent_id) do update set version=excluded.version, assigned_by=excluded.assigned_by, assigned_at=now();
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail) values(p_user_id,p_tenant_id,'policy.stage',jsonb_build_object('version',v_version,'agent_count',v_count));
  return jsonb_build_object('version',v_version,'target_count',v_count);
end;
$$;
revoke all on function public.stage_runtime_policy(uuid,uuid,bigint,jsonb,uuid[]) from public, anon, authenticated;
grant execute on function public.stage_runtime_policy(uuid,uuid,bigint,jsonb,uuid[]) to service_role;

create function public.record_policy_receipt(p_key_hash text, p_version bigint, p_policy_sha256 text)
returns boolean language plpgsql security definer set search_path = public, pg_temp as $$
declare v_key public.api_keys;
begin
  select * into v_key from public.api_keys where key_hash=p_key_hash and not revoked for share;
  if not found or v_key.agent_id is null then return false; end if;
  if not exists(select 1 from public.tenant_members m join public.tenants t on t.id=m.tenant_id where m.user_id=v_key.user_id and m.tenant_id=v_key.tenant_id and (m.expires_at is null or m.expires_at>now()) and t.status='active') then return false; end if;
  if not exists(select 1 from public.runtime_policy_revisions where tenant_id=v_key.tenant_id and version=p_version) then return false; end if;
  if p_version > coalesce((select version from public.agent_policy_assignments where agent_id=v_key.agent_id), (select version from public.tenant_runtime_policies where tenant_id=v_key.tenant_id), 0) then return false; end if;
  insert into public.agent_policy_receipts(tenant_id,agent_id,version,policy_sha256) values(v_key.tenant_id,v_key.agent_id,p_version,p_policy_sha256)
    on conflict(agent_id) do update set version=excluded.version, policy_sha256=excluded.policy_sha256, received_at=now()
    where public.agent_policy_receipts.version <= excluded.version;
  return found;
end;
$$;
revoke all on function public.record_policy_receipt(text,bigint,text) from public, anon, authenticated;
grant execute on function public.record_policy_receipt(text,bigint,text) to service_role;
