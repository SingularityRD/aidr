-- Explicit pilot approval is an enrollment grant, but a newly created team has
-- no entitlement row. Give that approved tenant one agent seat in the same
-- transaction; never reduce a customer/bootstrap or finance allocation.
create or replace function public.provision_approved_pilot_seat()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_owner_id uuid;
begin
  if new.status <> 'approved' then return new; end if;

  select m.user_id into v_owner_id
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = new.tenant_id
     and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > now())
     and t.status = 'active'
   order by m.user_id
   limit 1
   for share of m, t;
  if v_owner_id is null then
    raise exception 'pilot_tenant_owner_unavailable' using errcode = '42501';
  end if;

  insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents)
  values (v_owner_id, new.tenant_id, 1, 0)
  on conflict (tenant_id) do update
    set included_agents = greatest(public.entitlements.included_agents, 1);
  return new;
end;
$$;

revoke all on function public.provision_approved_pilot_seat()
  from public, anon, authenticated;

create trigger pilot_approval_seat
after insert or update of status on public.pilot_applications
for each row
when (new.status = 'approved')
execute function public.provision_approved_pilot_seat();

-- Pre-existing approved pilots receive the same minimum without reducing any
-- customer/bootstrap allocation. Pending and denied tenants receive nothing.
insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents)
select owner.user_id, tenant.id, 1, 0
  from public.tenants tenant
  join lateral (
    select member.user_id
      from public.tenant_members member
     where member.tenant_id = tenant.id
       and member.role = 'owner'
       and (member.expires_at is null or member.expires_at > now())
     order by member.user_id
     limit 1
  ) owner on true
 where tenant.status = 'active'
   and exists (
     select 1 from public.pilot_applications application
      where application.tenant_id = tenant.id and application.status = 'approved'
   )
on conflict (tenant_id) do update
  set included_agents = greatest(public.entitlements.included_agents, 1);
