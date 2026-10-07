-- Member-only projection of a tenant's catalog plan, admission and usage.
--
-- The browser never reads tenant_admissions or billing_plan_subscriptions
-- directly. This SECURITY DEFINER function re-checks the caller's active
-- membership and identity barrier, then returns only the fields the billing
-- page renders. It never grants or changes anything.

create or replace function public.get_tenant_plan(p_tenant_id uuid)
returns jsonb
language plpgsql
volatile
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_mode text;
  v_label text;
  v_plan_id text;
  v_source text;
  v_plan public.plans%rowtype;
  v_admission public.tenant_admissions%rowtype;
  v_has_admission boolean;
  v_admission_status text := 'none';
  v_sub public.billing_plan_subscriptions%rowtype;
  v_has_sub boolean;
  v_allowed integer;
  v_current integer;
begin
  if auth.uid() is null
     or p_tenant_id is null
     or not app.is_tenant_member(p_tenant_id)
     or not public.tenant_identity_access_allowed(p_tenant_id) then
    raise exception 'tenant_plan_access_denied' using errcode = '42501';
  end if;

  select mode into v_mode from app.tenant_admission_config where singleton;

  select * into v_admission from public.tenant_admissions where tenant_id = p_tenant_id;
  v_has_admission := found;
  if v_has_admission then
    v_admission_status := case
      when v_admission.revoked_at is not null then 'revoked'
      when v_admission.expires_at <= v_now then 'expired'
      when v_admission.starts_at > v_now then 'pending'
      else 'active' end;
  end if;

  select * into v_sub from public.billing_plan_subscriptions
   where tenant_id = p_tenant_id
   order by (admission_state = 'granted') desc, updated_at desc
   limit 1;
  v_has_sub := found;

  if v_has_sub and v_sub.admission_state = 'granted' and v_has_admission
     and v_admission_status = 'active'
     and v_admission.grant_reference = 'stripe:' || v_sub.provider_subscription_id then
    v_plan_id := v_sub.plan_id;
    v_source := 'stripe_subscription';
  else
    select t.plan into v_label from public.teams t where t.tenant_id = p_tenant_id limit 1;
    if v_label is not null then
      v_plan_id := app.catalog_plan_id(v_label);
      v_source := 'team_record';
    else
      v_plan_id := 'free';
      v_source := 'default';
    end if;
  end if;

  select * into v_plan from public.plans where id = v_plan_id;
  if not found then
    raise exception 'tenant_plan_unavailable' using errcode = '55000';
  end if;

  v_allowed := app.visible_tenant_admission_capacity(p_tenant_id);
  select count(*)::int into v_current from public.agents a where a.tenant_id = p_tenant_id;

  return jsonb_build_object(
    'tenant_id', p_tenant_id,
    'plan_id', v_plan.id,
    'display_name', v_plan.display_name,
    'plan_source', v_source,
    'included_agents_per_seat', v_plan.included_agents,
    'min_seats', v_plan.min_seats,
    'self_serve', v_plan.self_serve,
    'retention_days', v_plan.retention_days,
    'allowed_agents', v_allowed,
    'current_agents', v_current,
    'admission', jsonb_build_object(
      'mode', coalesce(v_mode, 'unconfigured'),
      'status', v_admission_status,
      'kind', case when v_has_admission then v_admission.kind else null end,
      'expires_at', case when v_has_admission then v_admission.expires_at else null end),
    'subscription', case when v_has_sub then jsonb_build_object(
      'plan_id', v_sub.plan_id,
      'billing_interval', v_sub.billing_interval,
      'seats', v_sub.seats,
      'status', v_sub.status,
      'admission_state', v_sub.admission_state,
      'current_period_end', v_sub.current_period_end) else null end);
end;
$$;
revoke all on function public.get_tenant_plan(uuid) from public, anon;
grant execute on function public.get_tenant_plan(uuid) to authenticated;
