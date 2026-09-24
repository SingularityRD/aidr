-- Choose exactly one commercial channel per tenant. A checkout session can
-- remain payable after it is created, so invoice approval must not race it.
-- Do not expire or delete an intent merely because a local clock advanced:
-- channel transfer requires a separately reviewed provider-state workflow.
do $$
begin
  if exists (
    select 1 from public.enterprise_invoice_approvals a
    join public.billing_checkout_intents i on i.tenant_id = a.tenant_id
    where a.status = 'paid'
  ) then
    raise exception 'existing_billing_channel_conflict' using errcode = '23505';
  end if;
end;
$$;

-- Switching online payment providers must first close the old allocation.
-- Otherwise the existing entitlement projection sums both subscriptions.
do $$
begin
  if exists (
    select tenant_id from public.subscriptions
    where extra_agents > 0
    group by tenant_id
    having count(distinct provider) > 1
  ) then
    raise exception 'existing_billing_provider_conflict' using errcode = '23505';
  end if;
end;
$$;

create or replace function app.prevent_subscription_provider_overlap()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if tg_op = 'UPDATE' then
    if old.provider <> new.provider then
      raise exception 'billing_provider_conflict' using errcode = '23505';
    end if;
  end if;
  if new.extra_agents > 0 then
    perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 2617));
    if exists (
      select 1 from public.subscriptions s
      where s.tenant_id = new.tenant_id
        and s.provider <> new.provider
        and s.id is distinct from new.id
        and s.extra_agents > 0
    ) then
      raise exception 'billing_provider_conflict' using errcode = '23505';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function app.prevent_subscription_provider_overlap()
  from public, anon, authenticated, service_role;
drop trigger if exists subscriptions_provider_overlap_guard on public.subscriptions;
create trigger subscriptions_provider_overlap_guard
before insert or update of provider, tenant_id, extra_agents on public.subscriptions
for each row execute function app.prevent_subscription_provider_overlap();

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
    where tenant_id = new.tenant_id
  ) then
    raise exception 'billing_channel_conflict' using errcode = '23505';
  end if;
  return new;
end;
$$;
revoke all on function app.prevent_invoice_provider_billing_overlap()
  from public, anon, authenticated, service_role;

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

  -- Same lock as invoice approval and signed subscription events. The request
  -- lock then preserves same-key idempotency without a cross-channel race.
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
    where tenant_id = p_tenant_id and request_id <> p_request_id
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
