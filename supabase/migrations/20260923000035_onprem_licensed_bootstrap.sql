-- On-prem customer bootstrap is an explicit licensed admission, not a pilot
-- approval. A contract reference and finite expiry are required from the
-- accountable deployment operator; a service role alone cannot invent a term.
drop function public.bootstrap_customer(uuid, uuid, text, integer);

create function public.bootstrap_customer(
  p_user_id uuid,
  p_bootstrap_id uuid,
  p_name text,
  p_seats integer,
  p_license_expires_at timestamptz,
  p_license_reference text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, auth, pg_temp
as $$
declare
  v_team_id uuid;
  v_record jsonb;
  v_entitlement_seats integer;
  v_admission public.tenant_admissions%rowtype;
  v_existing boolean := false;
  v_now timestamptz := clock_timestamp();
  v_mode text;
begin
  if p_user_id is null or p_bootstrap_id is null
     or p_name is null or length(trim(p_name)) not between 1 and 120
     or p_seats is null or p_seats not between 1 and 100000
     or p_license_expires_at is null or not isfinite(p_license_expires_at)
     or p_license_expires_at <= v_now
     or p_license_reference is null
     or length(trim(p_license_reference)) not between 1 and 200
     or p_license_reference ~ '[[:cntrl:]]' then
    raise exception 'invalid_customer_configuration' using errcode = '22023';
  end if;

  select mode into v_mode from app.tenant_admission_config where singleton for share;
  if v_mode is distinct from 'onprem' then
    raise exception 'onprem_admission_mode_required' using errcode = '42501';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 912));
  if not exists (
    select 1 from auth.users u where u.id = p_user_id
      and u.email_confirmed_at is not null
      and u.raw_app_meta_data ->> 'aidr_bootstrap_id' = p_bootstrap_id::text
  ) then
    raise exception 'bootstrap_account_mismatch' using errcode = '42501';
  end if;

  select detail into v_record from public.admin_audit_logs
   where action = 'customer.bootstrap' and target_user_id = p_user_id limit 1;
  v_existing := found;
  if v_existing then
    if v_record ->> 'name' <> trim(p_name)
       or (v_record ->> 'seats')::integer <> p_seats
       or (v_record ->> 'tenant_id') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
      raise exception 'bootstrap_already_completed_with_different_configuration' using errcode = '22023';
    end if;
    v_team_id := (v_record ->> 'tenant_id')::uuid;
    perform pg_advisory_xact_lock(hashtextextended(v_team_id::text, 0));
    select e.included_agents + e.extra_agents into v_entitlement_seats
      from public.entitlements e where e.tenant_id = v_team_id for share;
    if v_entitlement_seats is null or v_entitlement_seats < p_seats then
      raise exception 'bootstrap_entitlement_changed' using errcode = '42501';
    end if;
  else
    select t.id into strict v_team_id
      from public.tenants t
      join public.team_members m on m.team_id = t.id
     where t.created_by = p_user_id and t.kind = 'team'
       and t.status = 'active' and m.user_id = p_user_id and m.role = 'owner';
    perform pg_advisory_xact_lock(hashtextextended(v_team_id::text, 0));
    update public.tenants set name = trim(p_name), kind = 'enterprise'
      where id = v_team_id;
    update public.teams set name = trim(p_name), plan = 'enterprise'
      where id = v_team_id;
    insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents)
    values (p_user_id, v_team_id, p_seats, 0)
    on conflict (tenant_id) do update
      set included_agents = excluded.included_agents, extra_agents = 0;
  end if;
  perform 1 from public.tenants t
   where t.id = v_team_id and t.status = 'active' and t.kind = 'enterprise'
   for share;
  if not found then
    raise exception 'bootstrap_tenant_unavailable' using errcode = '42501';
  end if;
  perform 1 from public.tenant_members m
   where m.tenant_id = v_team_id and m.user_id = p_user_id and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > v_now)
   for share;
  if not found then
    raise exception 'bootstrap_owner_unavailable' using errcode = '42501';
  end if;

  insert into public.tenant_admissions
    (tenant_id, owner_user_id, kind, seats, starts_at, expires_at,
     grant_reference)
  values (v_team_id, p_user_id, 'licensed', p_seats, v_now,
    p_license_expires_at, trim(p_license_reference))
  on conflict (tenant_id) do nothing;
  select * into v_admission from public.tenant_admissions
   where tenant_id = v_team_id for share;
  if v_admission.owner_user_id is distinct from p_user_id
     or v_admission.kind is distinct from 'licensed'
     or v_admission.seats is distinct from p_seats
     or v_admission.expires_at is distinct from p_license_expires_at
     or v_admission.grant_reference is distinct from trim(p_license_reference)
     or v_admission.revoked_at is not null then
    raise exception 'bootstrap_admission_conflict' using errcode = '42501';
  end if;

  if not v_existing then
    v_record := jsonb_build_object('tenant_id', v_team_id, 'user_id', p_user_id,
      'name', trim(p_name), 'seats', p_seats);
    insert into public.admin_audit_logs
      (actor_user_id, tenant_id, target_user_id, action, detail)
    values (p_user_id, v_team_id, p_user_id, 'customer.bootstrap', v_record);
  end if;
  insert into public.admin_audit_logs
    (actor_user_id, tenant_id, target_user_id, action, detail)
  select p_user_id, v_team_id, p_user_id, 'admission.bootstrap_licensed',
    jsonb_build_object('seats', p_seats, 'expires_at', p_license_expires_at,
      'reference', trim(p_license_reference))
   where not exists (
     select 1 from public.admin_audit_logs l
      where l.tenant_id = v_team_id and l.action = 'admission.bootstrap_licensed'
   );
  return v_record;
end;
$$;

revoke all on function public.bootstrap_customer(
  uuid, uuid, text, integer, timestamptz, text)
  from public, anon, authenticated;
grant execute on function public.bootstrap_customer(
  uuid, uuid, text, integer, timestamptz, text)
  to service_role;
