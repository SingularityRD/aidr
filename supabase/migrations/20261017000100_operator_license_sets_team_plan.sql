-- Operator licence grants set the plan the tenant is entitled to.
--
-- operator_grant_license (also reached by operator_apply_license for signed
-- licence imports) stored the granted plan in tenant_admissions.plan_id only.
-- The plan resolvers read the billing-managed team label (teams.plan) while a
-- licensed admission is active, so a tenant licensed for Business or
-- Enterprise by an operator stayed on Free: SIEM export, SCIM and AI security
-- posture were refused and telemetry retention was capped at 7 days.
--
-- 1. The grant now also writes teams.plan, in the same transaction and under
--    the same platform-operator, admission-operator and separation-of-duty
--    checks (all enforced before this point, unchanged).
-- 2. Backfill: an active, unrevoked, operator-issued (non-Stripe) licensed
--    admission that recorded a plan gives its team that plan. Stripe-bound
--    admissions are left to the Stripe plan path.

create or replace function public.operator_grant_license(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_plan_id text,
  p_seats integer,
  p_expires_at timestamptz,
  p_grant_reference text,
  p_owner_user_id uuid default null
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_owner uuid := p_owner_user_id;
  v_owners uuid[];
  v_result jsonb;
begin
  perform app.require_platform_operator(p_actor_user_id);
  if p_tenant_id is null then
    raise exception 'invalid_admission_grant' using errcode = '22023';
  end if;
  if not app.operator_plan_known(p_plan_id) then
    raise exception 'invalid_plan' using errcode = '22023';
  end if;
  perform 1 from public.tenants where id = p_tenant_id;
  if not found then
    raise exception 'tenant_not_found' using errcode = 'P0002';
  end if;
  if v_owner is null then
    -- Only an unambiguous current owner may be inferred.
    select array_agg(m.user_id order by m.user_id) into v_owners
      from public.tenant_members m
     where m.tenant_id = p_tenant_id and m.role = 'owner'
       and (m.expires_at is null or m.expires_at > clock_timestamp());
    if coalesce(cardinality(v_owners), 0) = 0 then
      raise exception 'admission_owner_forbidden' using errcode = '42501';
    end if;
    if cardinality(v_owners) > 1 then
      raise exception 'owner_required' using errcode = '22023';
    end if;
    v_owner := v_owners[1];
  end if;

  -- Tenant-scoped admission operator, separation of duty, mode, owner and
  -- seat/expiry bounds are all enforced by the existing RPC.
  v_result := public.grant_licensed_tenant_admission(p_actor_user_id,
    p_tenant_id, v_owner, p_seats, p_expires_at, p_grant_reference);
  update public.tenant_admissions
     set plan_id = p_plan_id
   where tenant_id = p_tenant_id and kind = 'licensed' and revoked_at is null;
  if not found then
    raise exception 'admission_grant_conflict' using errcode = '40001';
  end if;
  -- The plan resolvers (app.tenant_plan_entitlements, get_tenant_plan) read
  -- the billing-managed team label while a licensed admission is active, as
  -- the Stripe plan path does. Without this the licensed plan was recorded on
  -- the admission only and the tenant stayed on Free features and retention.
  update public.teams set plan = p_plan_id where tenant_id = p_tenant_id;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id,
    action, detail)
  values (p_actor_user_id, p_tenant_id, v_owner, 'operator.license_granted',
    jsonb_build_object('plan_id', p_plan_id, 'seats', p_seats,
      'expires_at', p_expires_at, 'reference', trim(p_grant_reference)));
  return v_result || jsonb_build_object('plan_id', p_plan_id,
    'owner_user_id', v_owner);
end;
$$;

update public.teams t
   set plan = a.plan_id
  from public.tenant_admissions a
 where a.tenant_id = t.tenant_id
   and a.kind = 'licensed'
   and a.plan_id is not null
   and a.revoked_at is null
   and a.expires_at > clock_timestamp()
   and coalesce(a.grant_reference, '') not like 'stripe:%'
   and t.plan is distinct from a.plan_id;
