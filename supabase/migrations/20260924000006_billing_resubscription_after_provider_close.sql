-- A closed checkout is historical evidence, not an active billing channel.
-- Only a verified Stripe webhook may close it; local clocks never expire intents.
alter table public.billing_checkout_intents
  drop constraint if exists billing_checkout_intents_status_check,
  add column if not exists closed_at timestamptz,
  add column if not exists closed_event_id text,
  add column if not exists closed_reason text;

alter table public.billing_checkout_intents
  add constraint billing_checkout_intents_status_check
    check (status in ('claimed', 'checkout_created', 'paid', 'closed')),
  add constraint billing_checkout_intents_closed_state_check
    check (
      (status = 'closed' and closed_at is not null and closed_event_id is not null
        and closed_reason is not null
        and closed_reason in ('checkout_expired', 'subscription_terminated'))
      or (status <> 'closed' and closed_at is null and closed_event_id is null and closed_reason is null)
    );

create or replace function public.close_billing_checkout_intent(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_settlement_id uuid,
  p_request_id text,
  p_provider_event_id text,
  p_event_type text,
  p_checkout_session_id text default null,
  p_subscription_id text default null
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_intent public.billing_checkout_intents%rowtype;
  v_subscription public.subscriptions%rowtype;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_settlement_id is null
     or p_request_id is null or p_request_id !~ '^[A-Za-z0-9_-]{16,80}$'
     or p_provider_event_id is null or char_length(p_provider_event_id) not between 1 and 255 then
    raise exception 'invalid_billing_checkout_closure' using errcode = '22023';
  end if;
  if p_event_type = 'checkout.session.expired' then
    if p_checkout_session_id is null or p_checkout_session_id !~ '^cs_[A-Za-z0-9_]{1,252}$'
       or p_subscription_id is not null then
      raise exception 'invalid_billing_checkout_closure' using errcode = '22023';
    end if;
  elsif p_event_type in ('customer.subscription.deleted', 'customer.subscription.updated') then
    if p_subscription_id is null or p_subscription_id !~ '^sub_[A-Za-z0-9_]{1,252}$'
       or p_checkout_session_id is not null then
      raise exception 'invalid_billing_checkout_closure' using errcode = '22023';
    end if;
  else
    raise exception 'invalid_billing_checkout_closure' using errcode = '22023';
  end if;

  -- Serialize with checkout claims and finance channel changes.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2617));
  select * into v_intent from public.billing_checkout_intents
    where tenant_id = p_tenant_id and settlement_id = p_settlement_id
      and request_id = p_request_id for update;
  if not found or v_intent.actor_user_id <> p_actor_user_id or v_intent.provider <> 'stripe' then
    return false;
  end if;
  if v_intent.status = 'closed' then return true; end if;

  if p_event_type = 'checkout.session.expired' then
    if v_intent.status <> 'checkout_created'
       or v_intent.checkout_session_id is distinct from p_checkout_session_id
       or exists (select 1 from public.billing_provider_payments where settlement_id = p_settlement_id) then
      return false;
    end if;
    update public.billing_checkout_intents
      set status = 'closed', closed_at = now(), closed_event_id = p_provider_event_id,
          closed_reason = 'checkout_expired', updated_at = now()
      where settlement_id = p_settlement_id;
    return true;
  end if;

  select * into v_subscription from public.subscriptions
    where provider = 'stripe' and provider_subscription_id = p_subscription_id
      and tenant_id = p_tenant_id and user_id = p_actor_user_id for update;
  if not found or v_subscription.provider_event_id is distinct from p_provider_event_id
     or v_subscription.extra_agents <> 0 then
    return false;
  end if;
  if p_event_type <> 'customer.subscription.deleted'
     and lower(v_subscription.status) not in ('canceled', 'cancelled', 'deleted', 'incomplete_expired') then
    return false;
  end if;

  update public.billing_checkout_intents
    set status = 'closed', closed_at = now(), closed_event_id = p_provider_event_id,
        closed_reason = 'subscription_terminated', updated_at = now()
    where settlement_id = p_settlement_id;
  return true;
end;
$$;
revoke all on function public.close_billing_checkout_intent(uuid, uuid, uuid, text, text, text, text, text)
  from public, anon, authenticated;
grant execute on function public.close_billing_checkout_intent(uuid, uuid, uuid, text, text, text, text, text)
  to service_role;

create or replace function public.claim_billing_checkout_intent(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_request_id text,
  p_request_hash text,
  p_seats integer,
  p_billing_interval text,
  p_price_id text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_intent public.billing_checkout_intents%rowtype;
  v_existing boolean;
begin
  perform public.assert_billing_actor(p_tenant_id, p_actor_user_id, array['owner', 'admin']);
  if p_request_id !~ '^[A-Za-z0-9_-]{16,80}$'
     or p_request_hash !~ '^[0-9a-f]{64}$'
     or p_seats not between 1 and 10000
     or p_billing_interval not in ('monthly', 'yearly')
     or p_price_id !~ '^price_[A-Za-z0-9]+$' then
    raise exception 'invalid_billing_checkout_intent' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2617));
  perform pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':' || p_request_id, 2621
  ));

  select * into v_intent from public.billing_checkout_intents
    where tenant_id = p_tenant_id and request_id = p_request_id for update;
  v_existing := found;
  if v_existing and (
    v_intent.actor_user_id <> p_actor_user_id
    or v_intent.request_hash <> p_request_hash
    or v_intent.seats <> p_seats
    or v_intent.billing_interval <> p_billing_interval
    or v_intent.price_id <> p_price_id
  ) then
    raise exception 'billing_request_conflict' using errcode = '23505';
  end if;

  if exists (
    select 1 from public.enterprise_invoice_approvals
    where tenant_id = p_tenant_id and status = 'paid'
  ) or exists (
    select 1 from public.subscriptions
    where tenant_id = p_tenant_id and extra_agents > 0
  ) or exists (
    select 1 from public.billing_checkout_intents
    where tenant_id = p_tenant_id and request_id <> p_request_id and status <> 'closed'
  ) then
    raise exception 'billing_channel_conflict' using errcode = '23505';
  end if;

  if v_existing then
    return jsonb_build_object(
      'settlement_id', v_intent.settlement_id,
      'status', v_intent.status,
      'checkout_session_id', v_intent.checkout_session_id
    );
  end if;
  insert into public.billing_checkout_intents (
    tenant_id, actor_user_id, request_id, request_hash, seats,
    billing_interval, price_id
  ) values (
    p_tenant_id, p_actor_user_id, p_request_id, p_request_hash, p_seats,
    p_billing_interval, p_price_id
  ) returning * into v_intent;
  return jsonb_build_object(
    'settlement_id', v_intent.settlement_id,
    'status', v_intent.status,
    'checkout_session_id', v_intent.checkout_session_id
  );
end;
$$;
revoke all on function public.claim_billing_checkout_intent(uuid, uuid, text, text, integer, text, text)
  from public, anon, authenticated;
grant execute on function public.claim_billing_checkout_intent(uuid, uuid, text, text, integer, text, text)
  to service_role;

create or replace function app.prevent_invoice_provider_billing_overlap()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 2617));
  if exists (
    select 1 from public.subscriptions
    where tenant_id = new.tenant_id and extra_agents > 0
  ) or exists (
    select 1 from public.billing_checkout_intents
    where tenant_id = new.tenant_id and status <> 'closed'
  ) then
    raise exception 'billing_channel_conflict' using errcode = '23505';
  end if;
  return new;
end;
$$;
revoke all on function app.prevent_invoice_provider_billing_overlap()
  from public, anon, authenticated, service_role;
