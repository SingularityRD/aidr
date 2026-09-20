-- A targeted stage does not advance the tenant-wide published version. Require
-- the operator to compare against the newest revision under the same tenant
-- advisory lock so two stages from one stale view cannot overwrite a target.
drop function public.stage_runtime_policy(uuid, uuid, bigint, jsonb, uuid[]);

create function public.stage_runtime_policy(
  p_tenant_id uuid,
  p_user_id uuid,
  p_expected_version bigint,
  p_expected_revision_version bigint,
  p_policy jsonb,
  p_agent_ids uuid[]
)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_current bigint; v_latest bigint; v_version bigint; v_count integer;
begin
  if not exists(select 1 from public.tenant_members m join public.tenants t on t.id=m.tenant_id where m.user_id=p_user_id and m.tenant_id=p_tenant_id and m.role in ('owner','admin') and (m.expires_at is null or m.expires_at>now()) and t.status='active') then
    raise exception 'policy_forbidden' using errcode='42501';
  end if;
  if p_expected_version is null or p_expected_version < 0
     or p_expected_revision_version is null or p_expected_revision_version < p_expected_version
     or p_policy is null or jsonb_typeof(p_policy)<>'object' or octet_length(p_policy::text)>65536
     or coalesce(cardinality(p_agent_ids),0) not between 1 and 200 then
    raise exception 'invalid_stage' using errcode='22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text,911));
  select version into v_current from public.tenant_runtime_policies where tenant_id=p_tenant_id;
  if coalesce(v_current,0) <> p_expected_version then raise exception 'policy_version_conflict' using errcode='PT409'; end if;
  select coalesce(max(version),0) into v_latest from public.runtime_policy_revisions where tenant_id=p_tenant_id;
  if v_latest <> p_expected_revision_version then raise exception 'policy_revision_conflict' using errcode='PT409'; end if;
  select count(*) into v_count from public.agents where tenant_id=p_tenant_id and id=any(p_agent_ids);
  if v_count <> cardinality(p_agent_ids) then raise exception 'invalid_stage_agents' using errcode='22023'; end if;
  v_version := v_latest + 1;
  insert into public.runtime_policy_revisions(tenant_id,version,policy,updated_by) values(p_tenant_id,v_version,p_policy,p_user_id);
  insert into public.agent_policy_assignments(tenant_id,agent_id,version,assigned_by)
    select p_tenant_id,unnest(p_agent_ids),v_version,p_user_id
    on conflict(agent_id) do update set version=excluded.version, assigned_by=excluded.assigned_by, assigned_at=now();
  insert into public.admin_audit_logs(actor_user_id,tenant_id,action,detail) values(p_user_id,p_tenant_id,'policy.stage',jsonb_build_object('version',v_version,'agent_count',v_count));
  return jsonb_build_object('version',v_version,'target_count',v_count);
end;
$$;
revoke all on function public.stage_runtime_policy(uuid,uuid,bigint,bigint,jsonb,uuid[]) from public, anon, authenticated;
grant execute on function public.stage_runtime_policy(uuid,uuid,bigint,bigint,jsonb,uuid[]) to service_role;
