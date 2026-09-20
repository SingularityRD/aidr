-- Scoped, short-lived user -> agent -> tool -> resource delegation.
-- Signing stays in the Edge broker; PostgreSQL owns grants, attenuation,
-- membership checks, revocation and the immutable identity lineage.

create table public.delegated_credential_grants (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  subject_user_id uuid not null,
  agent_id uuid not null,
  tool_server_id text not null check(tool_server_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$'),
  tool_name text not null check(tool_name ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$'),
  resource_type text not null check(resource_type ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$'),
  resource_id text not null check(length(resource_id) between 1 and 2048 and resource_id !~ '[[:cntrl:]]'),
  audience text not null check(audience ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$'),
  scopes text[] not null check(cardinality(scopes) between 1 and 32),
  max_ttl_seconds integer not null default 300 check(max_ttl_seconds between 30 and 900),
  max_delegation_depth integer not null default 0 check(max_delegation_depth between 0 and 4),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_by uuid not null,
  created_at timestamptz not null default now(),
  foreign key(agent_id, tenant_id) references public.agents(id, tenant_id) on delete cascade
);

create index delegated_credential_grants_subject_idx
  on public.delegated_credential_grants(tenant_id, subject_user_id, agent_id)
  where revoked_at is null;
create index delegated_credential_grants_expiry_idx
  on public.delegated_credential_grants(expires_at)
  where revoked_at is null;

create table public.delegated_credential_receipts (
  token_id uuid primary key,
  grant_id uuid not null references public.delegated_credential_grants(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  subject_user_id uuid not null,
  agent_id uuid not null,
  parent_token_id uuid references public.delegated_credential_receipts(token_id),
  delegation_depth integer not null check(delegation_depth between 0 and 4),
  claims jsonb not null check(jsonb_typeof(claims) = 'object'),
  claims_sha256 text check(claims_sha256 ~ '^[a-f0-9]{64}$'),
  state text not null default 'reserved' check(state in ('reserved', 'active', 'revoked')),
  issued_at timestamptz not null,
  not_before timestamptz not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  foreign key(agent_id, tenant_id) references public.agents(id, tenant_id) on delete cascade,
  check((delegation_depth = 0 and parent_token_id is null) or (delegation_depth > 0 and parent_token_id is not null)),
  check(issued_at <= not_before and not_before < expires_at),
  check(expires_at <= issued_at + interval '15 minutes'),
  check((state = 'active' and claims_sha256 is not null) or state <> 'active')
);

create index delegated_credential_receipts_lineage_idx
  on public.delegated_credential_receipts(parent_token_id, token_id);
create index delegated_credential_receipts_active_expiry_idx
  on public.delegated_credential_receipts(expires_at)
  where state = 'active' and revoked_at is null;

alter table public.delegated_credential_grants enable row level security;
alter table public.delegated_credential_receipts enable row level security;
revoke all on public.delegated_credential_grants, public.delegated_credential_receipts from public, anon, authenticated;
grant all on public.delegated_credential_grants, public.delegated_credential_receipts to service_role;

create function app.valid_delegated_scopes(p_scopes text[])
returns boolean language sql immutable set search_path=pg_catalog as $$
  select coalesce(cardinality(p_scopes) between 1 and 32
    and not exists (
      select 1 from unnest(p_scopes) scope
      where scope !~ '^[a-z0-9][a-z0-9._:/-]{0,127}$'
    )
    and cardinality(p_scopes) = (select count(distinct scope) from unnest(p_scopes) scope),false);
$$;
revoke all on function app.valid_delegated_scopes(text[]) from public, anon, authenticated;
grant execute on function app.valid_delegated_scopes(text[]) to service_role;

create function app.active_delegation_member(p_tenant_id uuid, p_user_id uuid)
returns boolean language sql stable security definer set search_path=public,pg_temp as $$
  select exists(
    select 1 from public.tenant_members m
    join public.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=p_user_id
      and (m.expires_at is null or m.expires_at > now())
      and t.status='active'
  );
$$;
revoke all on function app.active_delegation_member(uuid,uuid) from public, anon, authenticated;
grant execute on function app.active_delegation_member(uuid,uuid) to service_role;

create function public.create_delegated_credential_grant(p_actor_user_id uuid, p_request jsonb)
returns jsonb language plpgsql security definer set search_path=public,app,pg_temp as $$
declare
  v_tenant uuid;
  v_subject uuid;
  v_agent uuid;
  v_scopes text[];
  v_ttl integer;
  v_depth integer;
  v_grant_seconds integer;
  v_row public.delegated_credential_grants;
begin
  if p_request is null or jsonb_typeof(p_request)<>'object' then raise exception 'invalid_grant' using errcode='22023'; end if;
  begin
    v_tenant := (p_request->>'tenant_id')::uuid;
    v_subject := (p_request->>'subject_user_id')::uuid;
    v_agent := (p_request->>'agent_id')::uuid;
    v_ttl := coalesce((p_request->>'max_ttl_seconds')::integer,300);
    v_depth := coalesce((p_request->>'max_delegation_depth')::integer,0);
    v_grant_seconds := coalesce((p_request->>'grant_expires_in_seconds')::integer,604800);
  exception when others then raise exception 'invalid_grant' using errcode='22023'; end;
  if jsonb_typeof(p_request->'scopes') <> 'array' then raise exception 'invalid_grant' using errcode='22023'; end if;
  select array_agg(value order by value) into v_scopes from jsonb_array_elements_text(p_request->'scopes');
  if not app.valid_delegated_scopes(v_scopes) or v_ttl not between 30 and 900 or v_depth not between 0 and 4 or v_grant_seconds not between 60 and 7776000 then
    raise exception 'invalid_grant' using errcode='22023';
  end if;
  if not exists(
    select 1 from public.tenant_members m join public.tenants t on t.id=m.tenant_id
    where m.tenant_id=v_tenant and m.user_id=p_actor_user_id and m.role in ('owner','admin')
      and (m.expires_at is null or m.expires_at>now()) and t.status='active'
  ) then raise exception 'delegation_grant_forbidden' using errcode='42501'; end if;
  if not app.active_delegation_member(v_tenant,v_subject) then raise exception 'delegation_subject_inactive' using errcode='42501'; end if;
  if not exists(select 1 from public.agents where id=v_agent and tenant_id=v_tenant) then raise exception 'delegation_agent_not_found' using errcode='22023'; end if;

  insert into public.delegated_credential_grants(
    tenant_id,subject_user_id,agent_id,tool_server_id,tool_name,resource_type,resource_id,
    audience,scopes,max_ttl_seconds,max_delegation_depth,expires_at,created_by
  ) values(
    v_tenant,v_subject,v_agent,p_request->>'tool_server_id',p_request->>'tool_name',
    p_request->>'resource_type',p_request->>'resource_id',p_request->>'audience',v_scopes,
    v_ttl,v_depth,now()+make_interval(secs=>v_grant_seconds),p_actor_user_id
  ) returning * into v_row;
  insert into public.admin_audit_logs(actor_user_id,tenant_id,target_user_id,action,detail)
    values(p_actor_user_id,v_tenant,v_subject,'delegated_credential.grant_created',
      jsonb_build_object('grant_id',v_row.id,'agent_id',v_agent,'tool_server_id',v_row.tool_server_id,
        'tool_name',v_row.tool_name,'resource_type',v_row.resource_type,'resource_id',v_row.resource_id,
        'audience',v_row.audience,'scopes',v_row.scopes,'expires_at',v_row.expires_at));
  return jsonb_build_object('grant_id',v_row.id,'expires_at',v_row.expires_at);
end;
$$;
revoke all on function public.create_delegated_credential_grant(uuid,jsonb) from public, anon, authenticated;
grant execute on function public.create_delegated_credential_grant(uuid,jsonb) to service_role;

create function public.reserve_delegated_credential(p_actor_user_id uuid, p_issuer text, p_request jsonb)
returns jsonb language plpgsql security definer set search_path=public,app,pg_temp as $$
declare
  v_grant public.delegated_credential_grants;
  v_tenant uuid;
  v_grant_id uuid;
  v_scopes text[];
  v_ttl integer;
  v_token uuid := gen_random_uuid();
  v_now timestamptz := date_trunc('second',clock_timestamp());
  v_expires timestamptz;
  v_claims jsonb;
begin
  begin v_tenant := (p_request->>'tenant_id')::uuid; v_grant_id := (p_request->>'grant_id')::uuid; v_ttl := coalesce((p_request->>'ttl_seconds')::integer,300);
  exception when others then raise exception 'invalid_delegation_request' using errcode='22023'; end;
  if p_issuer !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$' or jsonb_typeof(p_request->'scopes')<>'array' then raise exception 'invalid_delegation_request' using errcode='22023'; end if;
  select array_agg(value order by value) into v_scopes from jsonb_array_elements_text(p_request->'scopes');
  if not app.valid_delegated_scopes(v_scopes) then raise exception 'invalid_delegation_request' using errcode='22023'; end if;
  select * into v_grant from public.delegated_credential_grants where id=v_grant_id and tenant_id=v_tenant for update;
  if not found or v_grant.revoked_at is not null or v_grant.expires_at<=v_now then raise exception 'delegation_grant_inactive' using errcode='42501'; end if;
  if v_grant.subject_user_id<>p_actor_user_id or not app.active_delegation_member(v_tenant,p_actor_user_id) then raise exception 'delegation_subject_inactive' using errcode='42501'; end if;
  if v_ttl not between 1 and v_grant.max_ttl_seconds or not(v_scopes <@ v_grant.scopes) then raise exception 'delegation_scope_escalation' using errcode='42501'; end if;
  if not exists(select 1 from public.agents where id=v_grant.agent_id and tenant_id=v_tenant) then raise exception 'delegation_agent_inactive' using errcode='42501'; end if;
  v_expires := least(v_now+make_interval(secs=>v_ttl),v_grant.expires_at);
  if v_expires<=v_now then raise exception 'delegation_grant_inactive' using errcode='42501'; end if;
  v_claims := jsonb_build_object(
    'version',1,'issuer',p_issuer,'subjectUserId',p_actor_user_id,'tenantId',v_tenant,'agentId',v_grant.agent_id,
    'tool',jsonb_build_object('serverId',v_grant.tool_server_id,'name',v_grant.tool_name),
    'resource',jsonb_build_object('type',v_grant.resource_type,'id',v_grant.resource_id),
    'audience',v_grant.audience,'scopes',to_jsonb(v_scopes),
    'issuedAt',extract(epoch from v_now)::bigint,'notBefore',extract(epoch from v_now)::bigint,
    'expiresAt',extract(epoch from v_expires)::bigint,'tokenId',v_token,'delegationDepth',0
  );
  insert into public.delegated_credential_receipts(token_id,grant_id,tenant_id,subject_user_id,agent_id,delegation_depth,claims,issued_at,not_before,expires_at)
    values(v_token,v_grant.id,v_tenant,p_actor_user_id,v_grant.agent_id,0,v_claims,v_now,v_now,v_expires);
  return jsonb_build_object('claims',v_claims);
end;
$$;
revoke all on function public.reserve_delegated_credential(uuid,text,jsonb) from public, anon, authenticated;
grant execute on function public.reserve_delegated_credential(uuid,text,jsonb) to service_role;

create function public.reserve_child_delegated_credential(p_issuer text, p_parent_claims jsonb, p_parent_sha256 text, p_request jsonb)
returns jsonb language plpgsql security definer set search_path=public,app,pg_temp as $$
declare
  v_parent public.delegated_credential_receipts;
  v_grant public.delegated_credential_grants;
  v_parent_id uuid;
  v_scopes text[];
  v_ttl integer;
  v_token uuid := gen_random_uuid();
  v_now timestamptz := date_trunc('second',clock_timestamp());
  v_expires timestamptz;
  v_claims jsonb;
begin
  begin v_parent_id := (p_parent_claims->>'tokenId')::uuid; v_ttl := coalesce((p_request->>'ttl_seconds')::integer,300);
  exception when others then raise exception 'invalid_parent_delegation' using errcode='22023'; end;
  if p_issuer !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$' or p_parent_claims->>'issuer'<>p_issuer or p_parent_sha256 !~ '^[a-f0-9]{64}$' or jsonb_typeof(p_request->'scopes')<>'array' then raise exception 'invalid_parent_delegation' using errcode='22023'; end if;
  select array_agg(value order by value) into v_scopes from jsonb_array_elements_text(p_request->'scopes');
  if not app.valid_delegated_scopes(v_scopes) then raise exception 'invalid_parent_delegation' using errcode='22023'; end if;
  select * into v_parent from public.delegated_credential_receipts where token_id=v_parent_id for update;
  if not found or v_parent.state<>'active' or v_parent.revoked_at is not null or v_parent.expires_at<=v_now or v_parent.claims<>p_parent_claims or v_parent.claims_sha256<>p_parent_sha256 then raise exception 'parent_delegation_inactive' using errcode='42501'; end if;
  select * into v_grant from public.delegated_credential_grants where id=v_parent.grant_id for update;
  if not found or v_grant.revoked_at is not null or v_grant.expires_at<=v_now or not app.active_delegation_member(v_parent.tenant_id,v_parent.subject_user_id) then raise exception 'parent_delegation_inactive' using errcode='42501'; end if;
  if v_parent.delegation_depth+1>v_grant.max_delegation_depth or v_parent.delegation_depth+1>4 or v_ttl<1 or not(v_scopes <@ array(select jsonb_array_elements_text(v_parent.claims->'scopes'))) then raise exception 'delegation_scope_escalation' using errcode='42501'; end if;
  v_expires := least(v_now+make_interval(secs=>v_ttl),v_parent.expires_at,v_grant.expires_at);
  if v_expires<=v_now then raise exception 'parent_delegation_inactive' using errcode='42501'; end if;
  v_claims := (v_parent.claims - 'tokenId' - 'parentTokenId' - 'delegationDepth' - 'issuedAt' - 'notBefore' - 'expiresAt') || jsonb_build_object(
    'tokenId',v_token,'parentTokenId',v_parent.token_id,'delegationDepth',v_parent.delegation_depth+1,
    'scopes',to_jsonb(v_scopes),'issuedAt',extract(epoch from v_now)::bigint,
    'notBefore',extract(epoch from v_now)::bigint,'expiresAt',extract(epoch from v_expires)::bigint
  );
  insert into public.delegated_credential_receipts(token_id,grant_id,tenant_id,subject_user_id,agent_id,parent_token_id,delegation_depth,claims,issued_at,not_before,expires_at)
    values(v_token,v_grant.id,v_parent.tenant_id,v_parent.subject_user_id,v_parent.agent_id,v_parent.token_id,v_parent.delegation_depth+1,v_claims,v_now,v_now,v_expires);
  return jsonb_build_object('claims',v_claims);
end;
$$;
revoke all on function public.reserve_child_delegated_credential(text,jsonb,text,jsonb) from public, anon, authenticated;
grant execute on function public.reserve_child_delegated_credential(text,jsonb,text,jsonb) to service_role;

create function public.finalize_delegated_credential(p_claims jsonb, p_claims_sha256 text)
returns boolean language plpgsql security definer set search_path=public,pg_temp as $$
declare v_token uuid;
begin
  begin v_token := (p_claims->>'tokenId')::uuid; exception when others then return false; end;
  if p_claims_sha256 !~ '^[a-f0-9]{64}$' then return false; end if;
  update public.delegated_credential_receipts set state='active',claims_sha256=p_claims_sha256
    where token_id=v_token and state='reserved' and claims=p_claims and expires_at>clock_timestamp();
  if not found then return false; end if;
  insert into public.admin_audit_logs(actor_user_id,tenant_id,target_user_id,action,detail)
    select subject_user_id,tenant_id,subject_user_id,'delegated_credential.issued',
      jsonb_build_object('token_id',token_id,'grant_id',grant_id,'agent_id',agent_id,'parent_token_id',parent_token_id,
        'delegation_depth',delegation_depth,'audience',claims->>'audience','tool',claims->'tool','resource',claims->'resource',
        'scopes',claims->'scopes','expires_at',expires_at)
    from public.delegated_credential_receipts where token_id=v_token;
  return true;
end;
$$;
revoke all on function public.finalize_delegated_credential(jsonb,text) from public, anon, authenticated;
grant execute on function public.finalize_delegated_credential(jsonb,text) to service_role;

create function public.validate_delegated_credential(p_claims jsonb, p_claims_sha256 text)
returns jsonb language plpgsql security definer set search_path=public,app,pg_temp as $$
declare v_token uuid; v_row public.delegated_credential_receipts; v_grant public.delegated_credential_grants;
begin
  begin v_token := (p_claims->>'tokenId')::uuid; exception when others then return jsonb_build_object('active',false); end;
  select * into v_row from public.delegated_credential_receipts where token_id=v_token;
  if not found or v_row.state<>'active' or v_row.revoked_at is not null or v_row.expires_at<=clock_timestamp() or v_row.claims<>p_claims or v_row.claims_sha256<>p_claims_sha256 then return jsonb_build_object('active',false); end if;
  select * into v_grant from public.delegated_credential_grants where id=v_row.grant_id;
  if not found or v_grant.revoked_at is not null or v_grant.expires_at<=clock_timestamp() or not app.active_delegation_member(v_row.tenant_id,v_row.subject_user_id) then return jsonb_build_object('active',false); end if;
  return jsonb_build_object('active',true,'token_id',v_row.token_id,'grant_id',v_row.grant_id,'tenant_id',v_row.tenant_id,
    'subject_user_id',v_row.subject_user_id,'agent_id',v_row.agent_id,'parent_token_id',v_row.parent_token_id,
    'delegation_depth',v_row.delegation_depth,'expires_at',v_row.expires_at);
end;
$$;
revoke all on function public.validate_delegated_credential(jsonb,text) from public, anon, authenticated;
grant execute on function public.validate_delegated_credential(jsonb,text) to service_role;

create function public.read_delegated_credential_lineage(p_actor_user_id uuid, p_tenant_id uuid, p_token_id uuid)
returns jsonb language plpgsql security definer set search_path=public,pg_temp as $$
declare v_lineage jsonb;
begin
  if not exists(
    select 1 from public.tenant_members m join public.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=p_actor_user_id
      and m.role in ('owner','admin','support_jit')
      and (m.expires_at is null or m.expires_at>now()) and t.status='active'
  ) then raise exception 'delegation_lineage_forbidden' using errcode='42501'; end if;
  with recursive chain as (
    select r.* from public.delegated_credential_receipts r
      where r.token_id=p_token_id and r.tenant_id=p_tenant_id
    union all
    select parent.* from public.delegated_credential_receipts parent
      join chain child on child.parent_token_id=parent.token_id
      where parent.tenant_id=p_tenant_id
  )
  select jsonb_agg(jsonb_build_object(
    'token_id',token_id,'grant_id',grant_id,'parent_token_id',parent_token_id,
    'subject_user_id',subject_user_id,'agent_id',agent_id,'delegation_depth',delegation_depth,
    'tool',claims->'tool','resource',claims->'resource','audience',claims->>'audience',
    'scopes',claims->'scopes','issued_at',issued_at,'expires_at',expires_at,'state',state,
    'revoked_at',revoked_at
  ) order by delegation_depth) into v_lineage from chain;
  if v_lineage is null then return jsonb_build_object('found',false); end if;
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail)
    values(p_actor_user_id,p_tenant_id,'delegated_credential.lineage_read',jsonb_build_object('token_id',p_token_id));
  return jsonb_build_object('found',true,'lineage',v_lineage);
end;
$$;
revoke all on function public.read_delegated_credential_lineage(uuid,uuid,uuid) from public, anon, authenticated;
grant execute on function public.read_delegated_credential_lineage(uuid,uuid,uuid) to service_role;

create function public.revoke_delegated_credential_grant(p_actor_user_id uuid, p_tenant_id uuid, p_grant_id uuid)
returns boolean language plpgsql security definer set search_path=public,pg_temp as $$
begin
  if not exists(select 1 from public.tenant_members m join public.tenants t on t.id=m.tenant_id where m.tenant_id=p_tenant_id and m.user_id=p_actor_user_id and m.role in ('owner','admin') and (m.expires_at is null or m.expires_at>now()) and t.status='active') then raise exception 'delegation_revoke_forbidden' using errcode='42501'; end if;
  update public.delegated_credential_grants set revoked_at=coalesce(revoked_at,now()) where id=p_grant_id and tenant_id=p_tenant_id;
  if not found then return false; end if;
  update public.delegated_credential_receipts set state='revoked',revoked_at=coalesce(revoked_at,now()) where grant_id=p_grant_id and state<>'revoked';
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail) values(p_actor_user_id,p_tenant_id,'delegated_credential.grant_revoked',jsonb_build_object('grant_id',p_grant_id));
  return true;
end;
$$;
revoke all on function public.revoke_delegated_credential_grant(uuid,uuid,uuid) from public, anon, authenticated;
grant execute on function public.revoke_delegated_credential_grant(uuid,uuid,uuid) to service_role;
