-- Carry the authenticated Supabase session issuance time into each signed
-- delegated credential and check it against the global identity revocation
-- barrier before issuing or introspecting a credential.

create or replace function public.reserve_delegated_credential(p_actor_user_id uuid, p_issuer text, p_request jsonb)
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
  v_session_issued_at timestamptz;
  v_revoked_before timestamptz;
  v_revoke_pending uuid;
  v_claims jsonb;
begin
  begin
    v_tenant := (p_request->>'tenant_id')::uuid;
    v_grant_id := (p_request->>'grant_id')::uuid;
    v_ttl := coalesce((p_request->>'ttl_seconds')::integer,300);
    v_session_issued_at := (p_request->>'validated_session_issued_at')::timestamptz;
  exception when others then
    raise exception 'invalid_delegation_request' using errcode='22023';
  end;
  if p_issuer !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$'
     or v_session_issued_at is null
     or v_session_issued_at <= to_timestamp(0)
     or v_session_issued_at > v_now
     or jsonb_typeof(p_request->'scopes')<>'array' then
    raise exception 'invalid_delegation_request' using errcode='22023';
  end if;

  -- Serialize issuance with sign-out/password-recovery barrier writes. The
  -- timestamp came from the authenticated JWT after auth.getUser succeeded;
  -- an old Edge session cannot mint a token after a concurrent sign-out.
  perform pg_advisory_xact_lock(hashtextextended(p_actor_user_id::text, 2611));
  select s.revoked_before, s.global_revoke_pending_session_id
    into v_revoked_before, v_revoke_pending
    from public.identity_user_session_state s
    where s.user_id=p_actor_user_id;
  if v_revoke_pending is not null
     or (v_revoked_before is not null and v_session_issued_at <= v_revoked_before) then
    raise exception 'delegation_session_revoked' using errcode='42501';
  end if;

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
    'expiresAt',extract(epoch from v_expires)::bigint,'authSessionIssuedAt',extract(epoch from v_session_issued_at)::bigint,
    'tokenId',v_token,'delegationDepth',0
  );
  insert into public.delegated_credential_receipts(token_id,grant_id,tenant_id,subject_user_id,agent_id,delegation_depth,claims,issued_at,not_before,expires_at)
    values(v_token,v_grant.id,v_tenant,p_actor_user_id,v_grant.agent_id,0,v_claims,v_now,v_now,v_expires);
  return jsonb_build_object('claims',v_claims);
end;
$$;
revoke all on function public.reserve_delegated_credential(uuid,text,jsonb) from public, anon, authenticated;
grant execute on function public.reserve_delegated_credential(uuid,text,jsonb) to service_role;

create or replace function public.reserve_child_delegated_credential(p_issuer text, p_parent_claims jsonb, p_parent_sha256 text, p_request jsonb)
returns jsonb language plpgsql security definer set search_path=public,app,pg_temp as $$
declare
  v_parent public.delegated_credential_receipts;
  v_grant public.delegated_credential_grants;
  v_parent_id uuid;
  v_user_id uuid;
  v_session_issued_at bigint;
  v_parent_issued_at bigint;
  v_revoked_before timestamptz;
  v_revoke_pending uuid;
  v_scopes text[];
  v_ttl integer;
  v_token uuid := gen_random_uuid();
  v_now timestamptz := date_trunc('second',clock_timestamp());
  v_expires timestamptz;
  v_claims jsonb;
begin
  begin
    v_parent_id := (p_parent_claims->>'tokenId')::uuid;
    v_user_id := (p_parent_claims->>'subjectUserId')::uuid;
    v_session_issued_at := (p_parent_claims->>'authSessionIssuedAt')::bigint;
    v_parent_issued_at := (p_parent_claims->>'issuedAt')::bigint;
    v_ttl := coalesce((p_request->>'ttl_seconds')::integer,300);
  exception when others then
    raise exception 'invalid_parent_delegation' using errcode='22023';
  end;
  if p_issuer !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$'
     or p_parent_claims->>'issuer'<>p_issuer
     or p_parent_sha256 !~ '^[a-f0-9]{64}$'
     or v_session_issued_at is null
     or v_session_issued_at <= 0
     or v_parent_issued_at is null
     or v_session_issued_at > v_parent_issued_at
     or jsonb_typeof(p_request->'scopes')<>'array' then
    raise exception 'invalid_parent_delegation' using errcode='22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611));
  select s.revoked_before, s.global_revoke_pending_session_id
    into v_revoked_before, v_revoke_pending
    from public.identity_user_session_state s
    where s.user_id=v_user_id;
  if v_revoke_pending is not null
     or (v_revoked_before is not null and to_timestamp(v_session_issued_at) <= v_revoked_before) then
    raise exception 'parent_delegation_inactive' using errcode='42501';
  end if;

  select array_agg(value order by value) into v_scopes from jsonb_array_elements_text(p_request->'scopes');
  if not app.valid_delegated_scopes(v_scopes) then raise exception 'invalid_parent_delegation' using errcode='22023'; end if;
  select * into v_parent from public.delegated_credential_receipts where token_id=v_parent_id for update;
  if not found or v_parent.subject_user_id<>v_user_id or v_parent.state<>'active' or v_parent.revoked_at is not null or v_parent.expires_at<=v_now or v_parent.claims<>p_parent_claims or v_parent.claims_sha256<>p_parent_sha256 then raise exception 'parent_delegation_inactive' using errcode='42501'; end if;
  select * into v_grant from public.delegated_credential_grants where id=v_parent.grant_id for update;
  if not found or v_grant.revoked_at is not null or v_grant.expires_at<=v_now or not app.active_delegation_member(v_parent.tenant_id,v_parent.subject_user_id) then raise exception 'parent_delegation_inactive' using errcode='42501'; end if;
  if v_parent.delegation_depth+1>v_grant.max_delegation_depth or v_parent.delegation_depth+1>4 or v_ttl<1 or not(v_scopes <@ array(select jsonb_array_elements_text(v_parent.claims->'scopes'))) then raise exception 'delegation_scope_escalation' using errcode='42501'; end if;
  v_expires := least(v_now+make_interval(secs=>v_ttl),v_parent.expires_at,v_grant.expires_at);
  if v_expires<=v_now then raise exception 'parent_delegation_inactive' using errcode='42501'; end if;
  v_claims := (v_parent.claims - 'tokenId' - 'parentTokenId' - 'delegationDepth' - 'issuedAt' - 'notBefore' - 'expiresAt') || jsonb_build_object(
    'tokenId',v_token,'parentTokenId',v_parent.token_id,'delegationDepth',v_parent.delegation_depth+1,
    'scopes',to_jsonb(v_scopes),'issuedAt',extract(epoch from v_now)::bigint,
    'notBefore',extract(epoch from v_now)::bigint,'expiresAt',extract(epoch from v_expires)::bigint,
    'authSessionIssuedAt',v_session_issued_at
  );
  insert into public.delegated_credential_receipts(token_id,grant_id,tenant_id,subject_user_id,agent_id,parent_token_id,delegation_depth,claims,issued_at,not_before,expires_at)
    values(v_token,v_grant.id,v_parent.tenant_id,v_parent.subject_user_id,v_parent.agent_id,v_parent.token_id,v_parent.delegation_depth+1,v_claims,v_now,v_now,v_expires);
  return jsonb_build_object('claims',v_claims);
end;
$$;
revoke all on function public.reserve_child_delegated_credential(text,jsonb,text,jsonb) from public, anon, authenticated;
grant execute on function public.reserve_child_delegated_credential(text,jsonb,text,jsonb) to service_role;

create or replace function public.validate_delegated_credential(p_claims jsonb, p_claims_sha256 text)
returns jsonb language plpgsql security definer set search_path=public,app,pg_temp as $$
declare
  v_token uuid;
  v_session_issued_at bigint;
  v_issued_at bigint;
  v_row public.delegated_credential_receipts;
  v_grant public.delegated_credential_grants;
  v_revoked_before timestamptz;
  v_revoke_pending uuid;
begin
  begin
    v_token := (p_claims->>'tokenId')::uuid;
    v_session_issued_at := (p_claims->>'authSessionIssuedAt')::bigint;
    v_issued_at := (p_claims->>'issuedAt')::bigint;
  exception when others then
    return jsonb_build_object('active',false);
  end;
  select * into v_row from public.delegated_credential_receipts where token_id=v_token;
  if not found or v_row.state<>'active' or v_row.revoked_at is not null or v_row.expires_at<=clock_timestamp() or v_row.claims<>p_claims or v_row.claims_sha256<>p_claims_sha256 or v_session_issued_at is null or v_session_issued_at<=0 or v_issued_at is null or v_session_issued_at>v_issued_at then return jsonb_build_object('active',false); end if;
  select s.revoked_before, s.global_revoke_pending_session_id
    into v_revoked_before, v_revoke_pending
    from public.identity_user_session_state s
    where s.user_id=v_row.subject_user_id;
  if v_revoke_pending is not null
     or (v_revoked_before is not null and to_timestamp(v_session_issued_at) <= v_revoked_before) then
    return jsonb_build_object('active',false);
  end if;
  select * into v_grant from public.delegated_credential_grants where id=v_row.grant_id;
  if not found or v_grant.revoked_at is not null or v_grant.expires_at<=clock_timestamp() or not app.active_delegation_member(v_row.tenant_id,v_row.subject_user_id) then return jsonb_build_object('active',false); end if;
  return jsonb_build_object('active',true,'token_id',v_row.token_id,'grant_id',v_row.grant_id,'tenant_id',v_row.tenant_id,
    'subject_user_id',v_row.subject_user_id,'agent_id',v_row.agent_id,'parent_token_id',v_row.parent_token_id,
    'delegation_depth',v_row.delegation_depth,'expires_at',v_row.expires_at);
end;
$$;
revoke all on function public.validate_delegated_credential(jsonb,text) from public, anon, authenticated;
grant execute on function public.validate_delegated_credential(jsonb,text) to service_role;
