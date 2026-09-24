-- Audited, idempotent Stripe plan -> tenant admission path.
--
-- Payment alone never silently admits a tenant. A verified Stripe subscription
-- event whose price is mapped (AIDR_STRIPE_PRICE_MAP) to a catalog plan may
-- grant or revoke a *licensed* admission only through this function, which:
--
--   * runs as service_role only (the stripe-webhook Edge Function),
--   * serializes on the same per-tenant advisory lock as every admission
--     transition (hashtextextended(tenant, 0)),
--   * rejects stale and replayed provider events per subscription,
--   * binds the admission to grant_reference 'stripe:<subscription id>' and
--     never overwrites an operator/invoice licence with another reference,
--   * revokes only the admission that carries its own reference, and
--   * writes an admin_audit_logs row for every decision, including refusals.
--
-- A cancelled/deleted subscription is terminal: later events for the same
-- subscription id cannot re-grant (Stripe never reactivates a cancelled
-- subscription; a new purchase creates a new subscription id).

create table if not exists public.billing_plan_subscriptions (
  provider text not null default 'stripe' check (provider = 'stripe'),
  provider_subscription_id text primary key
    check (provider_subscription_id ~ '^sub_[A-Za-z0-9_]{1,252}$'),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  plan_id text not null references public.plans(id),
  billing_interval text not null check (billing_interval in ('monthly', 'yearly')),
  seats integer not null check (seats between 0 and 100000),
  status text not null check (status ~ '^[a-z_]{1,40}$'),
  current_period_end timestamptz,
  admission_state text not null
    check (admission_state in ('granted', 'held', 'rejected', 'conflict', 'closed')),
  admission_reason text not null check (admission_reason ~ '^[a-z_]{1,64}$'),
  last_event_id text not null check (last_event_id ~ '^[A-Za-z0-9_]{1,255}$'),
  last_event_created_at timestamptz not null,
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp()
);
create index if not exists billing_plan_subscriptions_tenant_idx
  on public.billing_plan_subscriptions (tenant_id, updated_at desc);

-- Server-only ledger. Members read the projection through get_tenant_plan.
alter table public.billing_plan_subscriptions enable row level security;
revoke all on public.billing_plan_subscriptions from public, anon, authenticated;

create or replace function public.apply_stripe_plan_subscription(
  p_event_id text,
  p_event_created_at timestamptz,
  p_user_id uuid,
  p_tenant_id uuid,
  p_subscription_id text,
  p_plan_id text,
  p_billing_interval text,
  p_seats integer,
  p_status text,
  p_current_period_end timestamptz,
  p_action text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz;
  v_reference text;
  v_row public.billing_plan_subscriptions%rowtype;
  v_exists boolean;
  v_plan public.plans%rowtype;
  v_mode text;
  v_admission public.tenant_admissions%rowtype;
  v_has_admission boolean;
  v_owner uuid;
  v_state text;
  v_reason text;
  v_audit_action text;
  v_agents integer;
  v_admission_changed boolean := false;
  v_plan_id text;
  v_interval text;
begin
  if p_event_id is null or p_event_id !~ '^[A-Za-z0-9_]{1,255}$'
     or p_event_created_at is null or not isfinite(p_event_created_at)
     or p_tenant_id is null
     or p_subscription_id is null or p_subscription_id !~ '^sub_[A-Za-z0-9_]{1,252}$'
     or (p_billing_interval is not null and p_billing_interval not in ('monthly', 'yearly'))
     or p_seats is null or p_seats not between 0 and 100000
     or p_status is null or p_status !~ '^[a-z_]{1,40}$'
     or (p_current_period_end is not null and not isfinite(p_current_period_end))
     or p_action is null or p_action not in ('grant', 'revoke', 'hold') then
    raise exception 'invalid_plan_subscription_event' using errcode = '22023';
  end if;
  if p_action <> 'revoke' and (p_plan_id is null or p_billing_interval is null) then
    raise exception 'invalid_plan_subscription_event' using errcode = '22023';
  end if;
  if p_action = 'grant' and (p_user_id is null or p_current_period_end is null) then
    raise exception 'invalid_plan_subscription_event' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
  v_now := clock_timestamp();
  v_reference := 'stripe:' || p_subscription_id;

  select * into v_row from public.billing_plan_subscriptions
    where provider_subscription_id = p_subscription_id for update;
  v_exists := found;

  if v_exists then
    if v_row.tenant_id <> p_tenant_id then
      insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
      values (null, p_tenant_id, p_user_id, 'billing.stripe_plan_tenant_conflict',
        jsonb_build_object('event_id', p_event_id, 'subscription_id', p_subscription_id));
      return jsonb_build_object('applied', false, 'state', 'conflict',
        'reason', 'subscription_tenant_conflict');
    end if;
    if v_row.last_event_id = p_event_id then
      return jsonb_build_object('applied', false, 'state', v_row.admission_state,
        'reason', 'duplicate_event');
    end if;
    if v_row.last_event_created_at > p_event_created_at then
      return jsonb_build_object('applied', false, 'state', v_row.admission_state,
        'reason', 'stale_event');
    end if;
    if v_row.admission_state = 'closed' then
      return jsonb_build_object('applied', false, 'state', 'closed',
        'reason', 'subscription_closed');
    end if;
  end if;

  -- A terminal event may no longer carry the mapped price; revocation is bound
  -- to the stored subscription row, never to the price map.
  v_plan_id := coalesce(p_plan_id, case when v_exists then v_row.plan_id end);
  v_interval := coalesce(p_billing_interval, case when v_exists then v_row.billing_interval end);
  if v_plan_id is null or v_interval is null then
    return jsonb_build_object('applied', false, 'state', 'closed',
      'reason', 'unknown_subscription');
  end if;
  select * into v_plan from public.plans where id = v_plan_id;
  if not found then
    raise exception 'invalid_plan_subscription_event' using errcode = '22023';
  end if;

  select * into v_admission from public.tenant_admissions where tenant_id = p_tenant_id for update;
  v_has_admission := found;

  if p_action = 'revoke' then
    v_state := 'closed';
    if v_has_admission and v_admission.grant_reference = v_reference
       and v_admission.revoked_at is null then
      update public.entitlements
         set revocation_epoch = revocation_epoch + 1
       where tenant_id = p_tenant_id;
      update public.tenant_admissions
         set revoked_at = greatest(starts_at, v_now), updated_at = v_now
       where tenant_id = p_tenant_id and grant_reference = v_reference and revoked_at is null;
      update public.teams set plan = 'free'
       where tenant_id = p_tenant_id and plan = v_plan_id;
      v_admission_changed := true;
      v_reason := 'subscription_ended';
      v_audit_action := 'admission.stripe_plan_revoked';
    else
      -- Never touch an admission this subscription did not grant.
      v_reason := 'no_bound_admission';
      v_audit_action := 'billing.stripe_plan_closed';
    end if;
  elsif p_action = 'hold' then
    -- past_due / incomplete / trialing: no new grant. A previously granted
    -- admission keeps its fixed term, which ends at the paid period end.
    v_state := case when v_exists and v_row.admission_state = 'granted' then 'granted' else 'held' end;
    v_reason := 'status_' || p_status;
    v_audit_action := 'billing.stripe_plan_status_recorded';
  else
    select mode into v_mode from app.tenant_admission_config where singleton for share;
    v_state := 'rejected';
    v_audit_action := 'billing.stripe_plan_rejected';
    if v_mode is distinct from 'cloud' then
      v_reason := 'admission_mode_not_cloud';
    elsif not v_plan.active or v_plan_id not in ('team', 'business')
       or not ('cloud' = any(v_plan.deployment)) then
      v_reason := 'plan_not_purchasable';
    elsif p_seats < v_plan.min_seats then
      v_reason := 'seats_below_plan_minimum';
    elsif p_seats::bigint * v_plan.included_agents > 100000 then
      v_reason := 'seats_above_limit';
    elsif p_current_period_end <= v_now then
      v_reason := 'period_expired';
    elsif not exists (select 1 from public.tenants t where t.id = p_tenant_id and t.status = 'active') then
      v_reason := 'tenant_inactive';
    elsif not exists (
      select 1 from public.tenant_members m
       where m.tenant_id = p_tenant_id and m.user_id = p_user_id
         and m.role in ('owner', 'admin')
         and (m.expires_at is null or m.expires_at > v_now)
    ) then
      v_reason := 'purchaser_not_billing_admin';
    else
      select m.user_id into v_owner from public.tenant_members m
       where m.tenant_id = p_tenant_id and m.role = 'owner'
         and (m.expires_at is null or m.expires_at > v_now)
       order by (m.user_id = p_user_id) desc, m.joined_at, m.user_id
       limit 1;
      if v_owner is null then
        v_reason := 'tenant_owner_missing';
      elsif v_has_admission and v_admission.revoked_at is not null
         and not exists (
           -- The only revocation a payment may supersede is this path's own
           -- revocation of an ended subscription. An operator revocation (abuse,
           -- offboarding, or of this very subscription) needs an operator.
           select 1 from public.billing_plan_subscriptions s
            where s.tenant_id = p_tenant_id
              and v_admission.grant_reference = 'stripe:' || s.provider_subscription_id
              and s.admission_state = 'closed'
              and s.admission_reason = 'subscription_ended'
         ) then
        v_reason := 'admission_revoked_requires_operator';
      elsif v_has_admission and v_admission.kind = 'licensed'
         and v_admission.revoked_at is null and v_admission.expires_at > v_now
         and v_admission.grant_reference is distinct from v_reference then
        -- An operator/invoice licence stands; a card payment never replaces it.
        v_state := 'conflict';
        v_reason := 'licensed_admission_exists';
        v_audit_action := 'billing.stripe_plan_conflict';
      else
        v_agents := p_seats * v_plan.included_agents;
        insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents)
        values (v_owner, p_tenant_id, v_agents, 0)
        on conflict (tenant_id) do update set included_agents = excluded.included_agents;
        if v_has_admission and v_admission.grant_reference = v_reference
           and v_admission.revoked_at is null then
          update public.tenant_admissions
             set seats = v_agents, expires_at = p_current_period_end,
                 owner_user_id = v_owner, updated_at = v_now
           where tenant_id = p_tenant_id;
        else
          insert into public.tenant_admissions
            (tenant_id, owner_user_id, kind, seats, starts_at, expires_at,
             revoked_at, grant_reference, granted_by)
          values (p_tenant_id, v_owner, 'licensed', v_agents, v_now,
            p_current_period_end, null, v_reference, null)
          on conflict (tenant_id) do update
            set owner_user_id = excluded.owner_user_id, kind = 'licensed',
                seats = excluded.seats, starts_at = excluded.starts_at,
                expires_at = excluded.expires_at, revoked_at = null,
                grant_reference = excluded.grant_reference,
                granted_by = null, updated_at = v_now;
        end if;
        update public.teams set plan = v_plan_id where tenant_id = p_tenant_id;
        v_admission_changed := true;
        v_state := 'granted';
        v_reason := 'subscription_active';
        v_audit_action := 'admission.stripe_plan_granted';
      end if;
    end if;
  end if;

  insert into public.billing_plan_subscriptions
    (provider, provider_subscription_id, tenant_id, plan_id, billing_interval, seats,
     status, current_period_end, admission_state, admission_reason,
     last_event_id, last_event_created_at, created_at, updated_at)
  values ('stripe', p_subscription_id, p_tenant_id, v_plan_id, v_interval, p_seats,
     p_status, p_current_period_end, v_state, v_reason,
     p_event_id, p_event_created_at, v_now, v_now)
  on conflict (provider_subscription_id) do update set
    plan_id = excluded.plan_id, billing_interval = excluded.billing_interval,
    seats = excluded.seats, status = excluded.status,
    current_period_end = excluded.current_period_end,
    admission_state = excluded.admission_state,
    admission_reason = excluded.admission_reason,
    last_event_id = excluded.last_event_id,
    last_event_created_at = excluded.last_event_created_at,
    updated_at = v_now;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (null, p_tenant_id, p_user_id, v_audit_action, jsonb_build_object(
    'event_id', p_event_id,
    'subscription_id', p_subscription_id,
    'reference', v_reference,
    'plan_id', v_plan_id,
    'billing_interval', v_interval,
    'seats', p_seats,
    'status', p_status,
    'current_period_end', p_current_period_end,
    'state', v_state,
    'reason', v_reason,
    'admission_changed', v_admission_changed));

  return jsonb_build_object('applied', true, 'state', v_state, 'reason', v_reason,
    'admission_changed', v_admission_changed);
end;
$$;
revoke all on function public.apply_stripe_plan_subscription(
  text, timestamptz, uuid, uuid, text, text, text, integer, text, timestamptz, text)
  from public, anon, authenticated;
grant execute on function public.apply_stripe_plan_subscription(
  text, timestamptz, uuid, uuid, text, text, text, integer, text, timestamptz, text)
  to service_role;
