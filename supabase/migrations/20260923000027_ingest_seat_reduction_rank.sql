-- Seat reductions must also stop previously registered agents. Keep the
-- earliest installations; UUID breaks equal first_seen timestamps stably.
create or replace function public.register_agent_for_ingest(
  p_user_id uuid,
  p_iid text,
  p_agent_runtime text default null,
  p_agent_runtime_version text default null,
  p_tenant_id uuid default null
)
returns table (
  agent_id uuid,
  tenant_id uuid,
  created boolean,
  current_agents integer,
  allowed_agents integer,
  seat_exceeded boolean
)
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_tenant_id uuid := coalesce(p_tenant_id, p_user_id);
  v_allowed integer := 1;
  v_current integer := 0;
  v_agent_id uuid;
  v_agent_rank bigint;
  v_included integer;
  v_extra integer;
begin
  if p_user_id is null or nullif(trim(p_iid), '') is null then
    raise exception 'invalid agent identity';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 0));
  select e.included_agents, e.extra_agents
    into v_included, v_extra
    from public.entitlements e
   where e.tenant_id = v_tenant_id
   for update;
  -- A tenant without an entitlement row has no seats; personal free tenants
  -- receive their one seat from an explicit bootstrap row.
  v_allowed := greatest(0, coalesce(v_included, 0) + coalesce(v_extra, 0));
  select a.id into v_agent_id
    from public.agents a
   where a.tenant_id = v_tenant_id and a.iid = trim(p_iid)
   for update;
  select count(*)::integer into v_current
    from public.agents a where a.tenant_id = v_tenant_id;
  if v_agent_id is null and v_current >= v_allowed then
    return query select null::uuid, v_tenant_id, false, v_current, v_allowed, true;
    return;
  end if;
  if v_agent_id is null then
    insert into public.agents (user_id, tenant_id, iid, agent_runtime, agent_runtime_version, last_seen)
    values (p_user_id, v_tenant_id, trim(p_iid), p_agent_runtime, p_agent_runtime_version, now())
    returning id into v_agent_id;
    v_current := v_current + 1;
    return query select v_agent_id, v_tenant_id, true, v_current, v_allowed, false;
    return;
  end if;
  if v_current > v_allowed then
    -- ponytail: rank only while over quota; add an index if this rare scan becomes hot.
    select ranked.agent_rank into v_agent_rank
      from (
        select a.id, row_number() over (order by a.first_seen, a.id) as agent_rank
          from public.agents a where a.tenant_id = v_tenant_id
      ) ranked
     where ranked.id = v_agent_id;
    if v_agent_rank is null or v_agent_rank > v_allowed then
      return query select null::uuid, v_tenant_id, false, v_current, v_allowed, true;
      return;
    end if;
  end if;
  update public.agents
     set agent_runtime = coalesce(p_agent_runtime, agent_runtime),
         agent_runtime_version = coalesce(p_agent_runtime_version, agent_runtime_version),
         last_seen = now()
   where id = v_agent_id;
  return query select v_agent_id, v_tenant_id, false, v_current, v_allowed, false;
end;
$$;

revoke all on function public.register_agent_for_ingest(uuid, text, text, text, uuid)
  from public, anon, authenticated;
grant execute on function public.register_agent_for_ingest(uuid, text, text, text, uuid)
  to service_role;
