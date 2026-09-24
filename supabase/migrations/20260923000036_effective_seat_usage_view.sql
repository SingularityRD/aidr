-- Keep browser seat counts in sync with admitted capacity without exposing
-- admission/billing rows or weakening the invoker-RLS view. This mirrors the
-- write-path capacity check without FOR SHARE: PostgREST GET is READ ONLY.
create function app.visible_tenant_admission_capacity(p_tenant_id uuid)
returns integer
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_mode text;
  v_admission_seats integer;
  v_included integer;
  v_extra integer;
begin
  if auth.role() is distinct from 'authenticated'
     or auth.uid() is null
     or p_tenant_id is null
     or not app.is_tenant_member(p_tenant_id)
     or not public.tenant_identity_access_allowed(p_tenant_id) then
    raise exception 'seat_usage_access_denied' using errcode = '42501';
  end if;
  select c.mode into v_mode from app.tenant_admission_config c where c.singleton;
  if v_mode is null or v_mode = 'unconfigured' then return 0; end if;
  if not exists (select 1 from public.tenants t
                 where t.id = p_tenant_id and t.status = 'active') then return 0; end if;
  if v_mode = 'pilot' then
    if not exists (select 1 from public.pilot_applications p
                   where p.tenant_id = p_tenant_id and p.status = 'approved') then return 0; end if;
  else
    select a.seats into v_admission_seats from public.tenant_admissions a
      where a.tenant_id = p_tenant_id and a.revoked_at is null
        and a.starts_at <= clock_timestamp() and a.expires_at > clock_timestamp();
    if not found then return 0; end if;
  end if;
  select e.included_agents into v_included from public.entitlements e
    where e.tenant_id = p_tenant_id;
  if not found then return 0; end if;
  select s.extra_agents into v_extra from public.effective_tenant_seats(p_tenant_id) s;
  if not found or v_extra is null then
    raise exception 'seat_usage_unavailable' using errcode = '55000';
  end if;
  if v_mode = 'pilot' then
    return greatest(0, coalesce(v_included, 0) + v_extra);
  end if;
  return least(greatest(0, coalesce(v_included, 0) + v_extra), v_admission_seats);
end;
$$;
revoke all on function app.visible_tenant_admission_capacity(uuid)
  from public, anon, authenticated, service_role;
grant execute on function app.visible_tenant_admission_capacity(uuid) to authenticated;

create or replace view public.seat_usage
with (security_invoker = true)
as
select
  e.user_id,
  least(greatest(e.included_agents, 0), admitted.allowed_agents) as included_agents,
  admitted.allowed_agents - least(greatest(e.included_agents, 0), admitted.allowed_agents) as extra_agents,
  admitted.allowed_agents,
  (
    select count(*)::int
    from public.agents a
    where a.tenant_id = e.tenant_id
  ) as current_agents,
  e.tenant_id
from public.entitlements e
cross join lateral app.visible_tenant_admission_capacity(e.tenant_id) as admitted(allowed_agents);
