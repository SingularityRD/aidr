-- Rollout: deploy the tenant-aware pilot Edge Functions first, then apply this
-- migration. Before the migration, new cross-tenant inserts fail closed on the
-- old user-only key; applying the migration before the new handlers would make
-- the old user-keyed upsert fail for all applications.
-- Keep tenant_id immutable on each row; scope uniqueness to the user/tenant pair.
alter table public.pilot_applications
  drop constraint pilot_applications_pkey;
alter table public.pilot_applications
  add constraint pilot_applications_pkey primary key (user_id, tenant_id);

-- Older customer bootstraps could approve a user's personal row while recording
-- the enterprise tenant in the receipt. Materialize the tenant-scoped approval
-- from that authoritative bootstrap audit record without moving the old row.
insert into public.pilot_applications (user_id, tenant_id, status, cohort)
select distinct l.target_user_id, (l.detail ->> 'tenant_id')::uuid, 'approved', 'customer'
from public.admin_audit_logs l
where l.action = 'customer.bootstrap'
  and l.target_user_id is not null
  and (l.detail ->> 'tenant_id') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
on conflict (user_id, tenant_id) do update
  set status = 'approved', cohort = 'customer';

-- Service-role-only provisioning remains idempotent, but its pilot approval is
-- now bound to the provisioned enterprise tenant rather than only user_id.
create or replace function public.bootstrap_customer(
  p_user_id uuid,
  p_bootstrap_id uuid,
  p_name text,
  p_seats integer
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_team_id uuid;
  v_record jsonb;
begin
  if p_name is null or length(trim(p_name)) not between 1 and 120
     or p_seats is null or p_seats not between 1 and 100000 then
    raise exception 'invalid_customer_configuration' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 912));
  if not exists (
    select 1 from auth.users
    where id = p_user_id
      and email_confirmed_at is not null
      and raw_app_meta_data ->> 'aidr_bootstrap_id' = p_bootstrap_id::text
  ) then
    raise exception 'bootstrap_account_mismatch' using errcode = '42501';
  end if;

  select detail into v_record
  from public.admin_audit_logs
  where action = 'customer.bootstrap' and target_user_id = p_user_id
  limit 1;
  if found then
    if v_record ->> 'name' <> trim(p_name)
       or (v_record ->> 'seats')::integer <> p_seats then
      raise exception 'bootstrap_already_completed_with_different_configuration' using errcode = '22023';
    end if;
    insert into public.pilot_applications (user_id, tenant_id, status, cohort)
    values (p_user_id, (v_record ->> 'tenant_id')::uuid, 'approved', 'customer')
    on conflict (user_id, tenant_id) do update
      set status = 'approved', cohort = 'customer';
    return v_record;
  end if;

  select t.id into strict v_team_id
  from public.tenants t
  join public.team_members m on m.team_id = t.id
  where t.created_by = p_user_id
    and t.kind = 'team'
    and t.status = 'active'
    and m.user_id = p_user_id
    and m.role = 'owner';

  update public.tenants set name = trim(p_name), kind = 'enterprise' where id = v_team_id;
  update public.teams set name = trim(p_name), plan = 'enterprise' where id = v_team_id;
  insert into public.entitlements (user_id, tenant_id, included_agents, extra_agents)
  values (p_user_id, v_team_id, p_seats, 0)
  on conflict (tenant_id) do update
    set included_agents = excluded.included_agents, extra_agents = 0;
  insert into public.pilot_applications (user_id, tenant_id, status, cohort)
  values (p_user_id, v_team_id, 'approved', 'customer')
  on conflict (user_id, tenant_id) do update
    set status = 'approved', cohort = 'customer';

  v_record := jsonb_build_object(
    'tenant_id', v_team_id,
    'user_id', p_user_id,
    'name', trim(p_name),
    'seats', p_seats
  );
  insert into public.admin_audit_logs (actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_user_id, v_team_id, p_user_id, 'customer.bootstrap', v_record);
  return v_record;
end;
$$;

revoke all on function public.bootstrap_customer(uuid, uuid, text, integer)
  from public, anon, authenticated;
grant execute on function public.bootstrap_customer(uuid, uuid, text, integer)
  to service_role;
