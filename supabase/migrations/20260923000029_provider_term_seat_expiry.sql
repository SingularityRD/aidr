-- A missing cancellation webhook must not leave provider-funded seats active
-- after the provider's last verified subscription period. Invoice and explicit
-- non-provider allocations have no inferred term; finance owns their lifecycle.
create or replace function public.effective_tenant_seats(p_tenant_id uuid)
returns table (extra_agents integer, provider_valid_until timestamptz)
language sql
volatile
security definer
set search_path = public, pg_catalog, pg_temp
as $$
  with channel as (
    select
      exists (select 1 from public.enterprise_invoice_approvals a
              where a.tenant_id = p_tenant_id and a.status = 'paid') as has_invoice,
      exists (select 1 from public.subscriptions s
              where s.tenant_id = p_tenant_id and s.provider in ('stripe', 'paddle')) as has_provider
  ),
  paid_invoice as (
    select coalesce(sum(a.agents_granted), 0)::integer as seats
      from public.enterprise_invoice_approvals a
     where a.tenant_id = p_tenant_id and a.status = 'paid'
  ),
  valid_provider as (
    select coalesce(sum(s.extra_agents), 0)::integer as seats,
           min(s.current_period_end) as valid_until
      from public.subscriptions s
     where s.tenant_id = p_tenant_id
       and s.provider in ('stripe', 'paddle')
       and s.status in ('active', 'trialing')
       and s.extra_agents > 0
       and s.current_period_end > clock_timestamp()
  )
  select case when c.has_invoice then i.seats
              when c.has_provider then p.seats
              else coalesce(e.extra_agents, 0) end,
         case when not c.has_invoice and c.has_provider then p.valid_until
              else null::timestamptz end
    from channel c cross join paid_invoice i cross join valid_provider p
    left join public.entitlements e on e.tenant_id = p_tenant_id;
$$;
revoke all on function public.effective_tenant_seats(uuid) from public, anon, authenticated;
grant execute on function public.effective_tenant_seats(uuid) to service_role;

-- Rebase on migration 27's deterministic over-quota rank: old agents beyond
-- the now-effective cap cannot continue ingestion simply because they exist.
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
  v_allowed integer := 0;
  v_current integer := 0;
  v_agent_id uuid;
  v_agent_rank bigint;
  v_included integer;
  v_extra integer;
  v_has_entitlement boolean;
begin
  if p_user_id is null or nullif(trim(p_iid), '') is null then
    raise exception 'invalid agent identity';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 0));
  select e.included_agents into v_included
    from public.entitlements e
   where e.tenant_id = v_tenant_id
   for update;
  v_has_entitlement := found;
  -- The row must exist for even the included seat to count. Positive provider
  -- seats require a current_period_end strictly later than wall-clock time.
  select s.extra_agents into v_extra
    from public.effective_tenant_seats(v_tenant_id) s;
  v_allowed := case when v_has_entitlement
    then greatest(0, coalesce(v_included, 0) + coalesce(v_extra, 0)) else 0 end;
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

-- Migration 28 established the team/pilot admission boundary. Retain both
-- requirements while preventing an expired provider row from issuing new
-- credentials or creating a fresh agent directly.
create or replace function public.require_enrollment_admission()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_included integer;
  v_extra integer;
begin
  perform 1 from public.tenants t
    where t.id = new.tenant_id and t.status = 'active' for share;
  if not found then
    raise exception 'tenant_enrollment_not_approved' using errcode = '42501';
  end if;
  perform 1 from public.pilot_applications p
    where p.tenant_id = new.tenant_id and p.status = 'approved' for share;
  if not found then
    raise exception 'tenant_enrollment_not_approved' using errcode = '42501';
  end if;
  select e.included_agents into v_included from public.entitlements e
    where e.tenant_id = new.tenant_id for share;
  if not found then
    raise exception 'tenant_enrollment_not_approved' using errcode = '42501';
  end if;
  select s.extra_agents into v_extra from public.effective_tenant_seats(new.tenant_id) s;
  if coalesce(v_included, 0) + coalesce(v_extra, 0) <= 0 then
    raise exception 'tenant_enrollment_not_approved' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function public.require_enrollment_admission()
  from public, anon, authenticated;
