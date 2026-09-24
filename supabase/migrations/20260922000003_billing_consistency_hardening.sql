-- Billing consistency hardening: provider-event ordering, durable portal
-- idempotency, tenant serialization, and mutually-exclusive commercial modes.

alter table public.subscriptions
  add column if not exists provider_event_created_at timestamptz,
  add column if not exists provider_event_id text;

-- Existing subscriptions predate provider cursors. Bootstrap them from the
-- local row clock so a genuinely newer provider event can advance state while
-- older deliveries remain fail-closed.
update public.subscriptions
  set provider_event_created_at = coalesce(updated_at, created_at, now()),
      provider_event_id = 'migration-bootstrap:' || provider_subscription_id
  where provider_event_created_at is null;

alter table public.billing_webhook_events
  add column if not exists processing_status text not null default 'completed'
    check (processing_status in ('processing', 'completed', 'failed')),
  add column if not exists claim_updated_at timestamptz not null default now();
alter table public.billing_webhook_events
  alter column processing_status set default 'processing';

create or replace function public.record_billing_webhook_event(
  p_provider text,
  p_event_id text,
  p_payload jsonb,
  p_tenant_id uuid default null
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  v_status text;
  v_updated timestamptz;
begin
  if p_provider not in ('stripe', 'paddle')
     or p_event_id is null or char_length(p_event_id) not between 1 and 255
     or p_payload is null then
    raise exception 'invalid_billing_webhook_event' using errcode = '22023';
  end if;
  select processing_status, claim_updated_at into v_status, v_updated
    from public.billing_webhook_events where event_id = p_event_id for update;
  if not found then
    insert into public.billing_webhook_events
      (provider, event_id, payload, tenant_id, processing_status, claim_updated_at)
    values (p_provider, p_event_id, p_payload, p_tenant_id, 'processing', now());
    return true;
  end if;
  if v_status = 'failed' or (v_status = 'processing' and v_updated < now() - interval '10 minutes') then
    update public.billing_webhook_events
      set processing_status = 'processing', claim_updated_at = now(), payload = p_payload,
          tenant_id = coalesce(p_tenant_id, tenant_id)
      where event_id = p_event_id and provider = p_provider;
    return found;
  end if;
  return false;
end;
$$;

create or replace function public.finish_billing_webhook_event(
  p_provider text,
  p_event_id text,
  p_status text
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
begin
  if p_status not in ('completed', 'failed') then
    raise exception 'invalid_billing_webhook_status' using errcode = '22023';
  end if;
  update public.billing_webhook_events
    set processing_status = p_status, claim_updated_at = now()
    where provider = p_provider and event_id = p_event_id and processing_status = 'processing';
  return found;
end;
$$;
revoke all on function public.finish_billing_webhook_event(text, text, text)
  from public, anon, authenticated;
grant execute on function public.finish_billing_webhook_event(text, text, text)
  to service_role;

create table if not exists public.billing_portal_operations (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  request_id text not null check (request_id ~ '^[A-Za-z0-9_-]{16,80}$'),
  action text not null check (action in ('request_seats', 'cancel', 'refund')),
  resource_id text not null check (char_length(resource_id) between 1 and 255),
  request_hash text not null check (request_hash ~ '^[0-9a-f]{64}$'),
  request_payload jsonb not null check (jsonb_typeof(request_payload) = 'object'),
  status text not null default 'processing' check (status in ('processing', 'completed', 'failed')),
  created_at timestamptz not null default now(),
  claim_updated_at timestamptz not null default now(),
  completed_at timestamptz,
  result jsonb,
  primary key (tenant_id, request_id)
);
create unique index if not exists billing_portal_operations_processing_resource_idx
  on public.billing_portal_operations(tenant_id, resource_id)
  where status = 'processing';
alter table public.billing_portal_operations enable row level security;
revoke all on public.billing_portal_operations from public, anon, authenticated;
grant select, insert, update on public.billing_portal_operations to service_role;

create or replace function public.claim_billing_portal_operation(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_request_id text,
  p_action text,
  p_resource_id text,
  p_request_hash text,
  p_request_payload jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_existing public.billing_portal_operations%rowtype;
begin
  perform public.assert_billing_actor(p_tenant_id, p_actor_user_id, array['owner', 'admin']);
  if p_request_id !~ '^[A-Za-z0-9_-]{16,80}$'
     or p_action not in ('request_seats', 'cancel', 'refund')
     or p_resource_id is null or char_length(p_resource_id) not between 1 and 255
     or p_request_hash !~ '^[0-9a-f]{64}$'
     or jsonb_typeof(p_request_payload) <> 'object'
     or octet_length(p_request_payload::text) > 4096 then
    raise exception 'invalid_billing_operation' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':' || p_resource_id, 2620
  ));
  select * into v_existing
    from public.billing_portal_operations
    where tenant_id = p_tenant_id and request_id = p_request_id;
  if found then
    if v_existing.action <> p_action
       or v_existing.resource_id <> p_resource_id
       or v_existing.request_hash <> p_request_hash
       or v_existing.request_payload <> p_request_payload then
      raise exception 'billing_request_conflict' using errcode = '23505';
    end if;
    if v_existing.status = 'failed'
       or (v_existing.status = 'processing'
           and v_existing.claim_updated_at < now() - interval '10 minutes') then
      update public.billing_portal_operations
        set status = 'processing', claim_updated_at = now(), completed_at = null
        where tenant_id = p_tenant_id and request_id = p_request_id;
      return jsonb_build_object('state', 'retry', 'result', null, 'effective_request_id', v_existing.request_id);
    end if;
    if v_existing.status = 'processing' then
      raise exception 'billing_operation_in_progress' using errcode = '55P03';
    end if;
    return jsonb_build_object('state', 'completed', 'result', v_existing.result, 'effective_request_id', v_existing.request_id);
  end if;

  select * into v_existing from public.billing_portal_operations
    where tenant_id = p_tenant_id and resource_id = p_resource_id and status = 'processing'
    for update;
  if found then
    if v_existing.claim_updated_at < now() - interval '10 minutes'
       and v_existing.action = p_action
       and v_existing.request_hash = p_request_hash then
      update public.billing_portal_operations
        set claim_updated_at = now()
        where tenant_id = v_existing.tenant_id and request_id = v_existing.request_id;
      return jsonb_build_object(
        'state', 'retry', 'result', null,
        'effective_request_id', v_existing.request_id
      );
    end if;
    if v_existing.claim_updated_at < now() - interval '10 minutes' then
      return jsonb_build_object(
        'state', 'recovery_required',
        'result', null,
        'effective_request_id', v_existing.request_id,
        'recovery_action', v_existing.action,
        'recovery_request_hash', v_existing.request_hash,
        'recovery_payload', v_existing.request_payload
      );
    end if;
    raise exception 'billing_operation_in_progress' using errcode = '55P03';
  end if;

  insert into public.billing_portal_operations
    (tenant_id, request_id, action, resource_id, request_hash, request_payload)
  values (p_tenant_id, p_request_id, p_action, p_resource_id, p_request_hash, p_request_payload);
  return jsonb_build_object('state', 'new', 'result', null, 'effective_request_id', p_request_id);
end;
$$;
revoke all on function public.claim_billing_portal_operation(uuid, uuid, text, text, text, text, jsonb)
  from public, anon, authenticated;
grant execute on function public.claim_billing_portal_operation(uuid, uuid, text, text, text, text, jsonb)
  to service_role;

create or replace function public.complete_billing_portal_operation(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_request_id text,
  p_request_hash text,
  p_result jsonb default null
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  perform public.assert_billing_actor(p_tenant_id, p_actor_user_id, array['owner', 'admin']);
  update public.billing_portal_operations
    set status = 'completed', claim_updated_at = now(),
        completed_at = coalesce(completed_at, now()),
        result = coalesce(result, p_result)
    where tenant_id = p_tenant_id and request_id = p_request_id
      and request_hash = p_request_hash and status in ('processing', 'completed');
  return found;
end;
$$;
revoke all on function public.complete_billing_portal_operation(uuid, uuid, text, text, jsonb)
  from public, anon, authenticated;
grant execute on function public.complete_billing_portal_operation(uuid, uuid, text, text, jsonb)
  to service_role;

create or replace function public.fail_billing_portal_operation(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_request_id text,
  p_request_hash text
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  perform public.assert_billing_actor(p_tenant_id, p_actor_user_id, array['owner', 'admin']);
  update public.billing_portal_operations
    set status = 'failed', claim_updated_at = now()
    where tenant_id = p_tenant_id and request_id = p_request_id
      and request_hash = p_request_hash and status = 'processing';
  return found;
end;
$$;
revoke all on function public.fail_billing_portal_operation(uuid, uuid, text, text)
  from public, anon, authenticated;
grant execute on function public.fail_billing_portal_operation(uuid, uuid, text, text)
  to service_role;

-- Provider webhooks use one atomic transition. The stored event clock prevents
-- an older delivery from restoring state after a newer cancellation.
create or replace function public.apply_billing_subscription_event(
  p_provider text,
  p_event_id text,
  p_event_created_at timestamptz,
  p_user_id uuid,
  p_tenant_id uuid,
  p_subscription_id text,
  p_status text,
  p_extra_agents integer,
  p_current_period_end timestamptz,
  p_cancel_at_period_end boolean
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_existing public.subscriptions%rowtype;
  v_owner uuid;
  v_total integer;
begin
  if p_provider not in ('stripe', 'paddle')
     or p_event_id is null or char_length(p_event_id) not between 1 and 255
     or p_event_created_at is null
     or p_user_id is null or p_tenant_id is null
     or p_subscription_id is null or char_length(p_subscription_id) not between 1 and 255
     or p_status is null or char_length(p_status) not between 1 and 64
     or p_extra_agents is null or p_extra_agents not between 0 and 100000
     or p_cancel_at_period_end is null then
    raise exception 'invalid_billing_subscription_event' using errcode = '22023';
  end if;

  -- Shared with invoice approval. A tenant can never have two commercial
  -- channels racing to overwrite the same entitlement allocation.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2617));
  perform pg_advisory_xact_lock(hashtextextended(
    p_provider || ':' || p_subscription_id, 2619
  ));

  select * into v_existing from public.subscriptions
    where provider_subscription_id = p_subscription_id
    for update;
  if found then
    if v_existing.provider <> p_provider
       or v_existing.tenant_id <> p_tenant_id
       or v_existing.user_id <> p_user_id then
      raise exception 'billing_subscription_binding_conflict' using errcode = '23505';
    end if;
    if v_existing.provider_event_created_at is null
       and p_extra_agents > v_existing.extra_agents then
      return jsonb_build_object('applied', false, 'reason', 'missing_provider_event_cursor');
    end if;
    if v_existing.provider_event_created_at is not null then
      if p_event_created_at < v_existing.provider_event_created_at then
        return jsonb_build_object('applied', false, 'reason', 'stale_provider_event');
      end if;
      if p_event_created_at = v_existing.provider_event_created_at then
        if v_existing.provider_event_id = p_event_id
           or p_extra_agents >= v_existing.extra_agents then
          return jsonb_build_object('applied', false, 'reason', 'stale_provider_event');
        end if;
        -- Provider timestamps are only second-resolution. When two distinct
        -- events tie, accept only the more restrictive entitlement transition.
      end if;
    end if;
  end if;

  if not found or p_extra_agents > v_existing.extra_agents then
    select m.user_id into v_owner
      from public.tenants t
      join public.tenant_members m on m.tenant_id = t.id
      where t.id = p_tenant_id and t.status = 'active'
        and m.user_id = p_user_id and m.role in ('owner', 'admin')
        and (m.expires_at is null or m.expires_at > now())
      for share of t, m;
    if not found then
      raise exception 'billing_subscription_forbidden' using errcode = '42501';
    end if;
  end if;

  if p_extra_agents > 0 and exists (
    select 1 from public.enterprise_invoice_approvals
    where tenant_id = p_tenant_id and status = 'paid'
  ) then
    raise exception 'billing_channel_conflict' using errcode = '23505';
  end if;

  insert into public.subscriptions (
    user_id, tenant_id, provider, provider_subscription_id, status,
    extra_agents, current_period_end, cancel_at_period_end,
    provider_event_created_at, provider_event_id
  ) values (
    p_user_id, p_tenant_id, p_provider, p_subscription_id, p_status,
    p_extra_agents, p_current_period_end, p_cancel_at_period_end,
    p_event_created_at, p_event_id
  )
  on conflict (provider_subscription_id) do update set
    status = excluded.status,
    extra_agents = excluded.extra_agents,
    current_period_end = excluded.current_period_end,
    cancel_at_period_end = excluded.cancel_at_period_end,
    provider_event_created_at = excluded.provider_event_created_at,
    provider_event_id = excluded.provider_event_id,
    updated_at = now();

  if exists (
    select 1 from public.enterprise_invoice_approvals
    where tenant_id = p_tenant_id and status = 'paid'
  ) then
    select coalesce(e.extra_agents, 0) into v_total
      from public.entitlements e where e.tenant_id = p_tenant_id;
    return jsonb_build_object(
      'applied', true,
      'extra_agents', coalesce(v_total, 0),
      'reason', 'invoice_entitlement_preserved'
    );
  end if;

  select coalesce(sum(s.extra_agents), 0)::integer into v_total
    from public.subscriptions s where s.tenant_id = p_tenant_id;
  update public.entitlements
    set extra_agents = v_total, updated_at = now()
    where tenant_id = p_tenant_id;
  if found then
    return jsonb_build_object('applied', true, 'extra_agents', v_total);
  end if;
  select m.user_id into v_owner from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and t.status = 'active' and m.role = 'owner'
      and (m.expires_at is null or m.expires_at > now())
    order by m.user_id limit 1;
  if v_owner is null then
    raise exception 'billing_subscription_forbidden' using errcode = '42501';
  end if;
  insert into public.entitlements (user_id, tenant_id, extra_agents)
  values (v_owner, p_tenant_id, v_total)
  on conflict (tenant_id) do update set
    extra_agents = excluded.extra_agents, updated_at = now();

  return jsonb_build_object('applied', true, 'extra_agents', v_total);
end;
$$;
revoke all on function public.apply_billing_subscription_event(
  text, text, timestamptz, uuid, uuid, text, text, integer, timestamptz, boolean
) from public, anon, authenticated;
grant execute on function public.apply_billing_subscription_event(
  text, text, timestamptz, uuid, uuid, text, text, integer, timestamptz, boolean
) to service_role;

-- Invoice approvals and self-service subscriptions are explicit mutually
-- exclusive modes. The same tenant advisory lock closes the cross-table race.
do $$
begin
  if exists (
    select 1
    from public.enterprise_invoice_approvals a
    join public.subscriptions s on s.tenant_id = a.tenant_id
    where a.status = 'paid' and s.extra_agents > 0
  ) then
    raise exception 'existing_billing_channel_conflict' using errcode = '23505';
  end if;
end;
$$;

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
  ) then
    raise exception 'billing_channel_conflict' using errcode = '23505';
  end if;
  return new;
end;
$$;
revoke all on function app.prevent_invoice_provider_billing_overlap()
  from public, anon, authenticated, service_role;
drop trigger if exists enterprise_invoice_approvals_provider_overlap_guard
  on public.enterprise_invoice_approvals;
create trigger enterprise_invoice_approvals_provider_overlap_guard
before insert on public.enterprise_invoice_approvals
for each row execute function app.prevent_invoice_provider_billing_overlap();

-- A request id is a permanent financial idempotency key. Pruning it permits a
-- later action to rebind the same name (ABA), so retain all existing keys.
update public.billing_settlement_requests set expires_at = 'infinity'::timestamptz;
alter table public.billing_settlement_requests
  alter column expires_at set default 'infinity'::timestamptz;

create or replace function public.prune_expired_billing_records(
  p_limit integer default 100,
  p_apply boolean default true
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_events_eligible integer := 0;
  v_events_deleted integer := 0;
begin
  if p_limit is null or p_limit < 1 or p_limit > 1000 then
    raise exception 'invalid_retention_batch' using errcode = '22023';
  end if;
  select count(*)::integer into v_events_eligible from (
    select 1 from public.billing_webhook_events
    where expires_at <= now() order by expires_at limit p_limit
  ) expired_events;
  if p_apply then
    delete from public.billing_webhook_events e using (
      select event_id from public.billing_webhook_events
      where expires_at <= now() order by expires_at limit p_limit
    ) expired where e.event_id = expired.event_id;
    get diagnostics v_events_deleted = row_count;
  end if;
  return jsonb_build_object(
    'applied', p_apply,
    'settlement_requests_eligible', 0,
    'webhook_events_eligible', v_events_eligible,
    'settlement_requests_deleted', 0,
    'webhook_events_deleted', v_events_deleted
  );
end;
$$;

-- The transition sequence is authoritative. Provider clocks are evidence, not
-- ordering controls, and may be skewed.
create or replace function public.recompute_billing_projection(
  p_tenant_id uuid,
  p_actor_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_result jsonb;
begin
  perform public.assert_billing_actor(p_tenant_id, p_actor_user_id, array['owner', 'admin']);
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2617));
  delete from public.billing_entitlement_projections where tenant_id = p_tenant_id;
  insert into public.billing_entitlement_projections (tenant_id, sku, seats, source_settlement_ids)
  select p_tenant_id, line ->> 'sku', sum((line ->> 'quantity')::integer),
    jsonb_agg(distinct s.settlement_id)
  from (
    select distinct on (settlement_id) settlement_id, lines, status
    from public.billing_settlements
    where tenant_id = p_tenant_id
    order by settlement_id, sequence desc
  ) s
  cross join lateral jsonb_array_elements(s.lines) as line
  where s.status = 'settled'
  group by line ->> 'sku';
  select coalesce(jsonb_agg(jsonb_build_object(
    'sku', sku, 'seats', seats, 'sources', source_settlement_ids
  ) order by sku), '[]'::jsonb) into v_result
  from public.billing_entitlement_projections where tenant_id = p_tenant_id;
  return v_result;
end;
$$;

-- Self-service checkout is given a permanent local settlement identity before
-- Stripe is contacted. Signed invoice events may only attach payment evidence
-- to that immutable tenant/user/request tuple.
create table if not exists public.billing_checkout_intents (
  settlement_id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  actor_user_id uuid not null references auth.users(id) on delete restrict,
  request_id text not null check (request_id ~ '^[A-Za-z0-9_-]{16,80}$'),
  request_hash text not null check (request_hash ~ '^[0-9a-f]{64}$'),
  seats integer not null check (seats between 1 and 10000),
  billing_interval text not null check (billing_interval in ('monthly', 'yearly')),
  price_id text not null check (price_id ~ '^price_[A-Za-z0-9]+$'),
  provider text not null default 'stripe' check (provider = 'stripe'),
  checkout_session_id text check (checkout_session_id ~ '^cs_[A-Za-z0-9_]{1,252}$'),
  status text not null default 'claimed' check (status in ('claimed', 'checkout_created', 'paid')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, request_id),
  unique (checkout_session_id)
);
alter table public.billing_checkout_intents enable row level security;
revoke all on public.billing_checkout_intents from public, anon, authenticated, service_role;

create table if not exists public.billing_provider_payments (
  provider text not null check (provider = 'stripe'),
  provider_payment_id text not null,
  provider_payment_kind text not null check (provider_payment_kind in ('payment_intent', 'charge')),
  settlement_id uuid not null references public.billing_checkout_intents(settlement_id) on delete restrict,
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  request_id text not null check (request_id ~ '^[A-Za-z0-9_-]{16,80}$'),
  user_id uuid not null references auth.users(id) on delete restrict,
  provider_customer_id text not null check (provider_customer_id ~ '^cus_[A-Za-z0-9_]{1,252}$'),
  provider_subscription_id text not null check (provider_subscription_id ~ '^sub_[A-Za-z0-9_]{1,252}$'),
  provider_invoice_id text not null unique check (provider_invoice_id ~ '^in_[A-Za-z0-9_]{1,252}$'),
  provider_event_id text not null unique check (char_length(provider_event_id) between 1 and 255),
  event_created_at timestamptz not null,
  amount_minor bigint not null check (amount_minor > 0),
  currency text not null check (currency ~ '^[a-z]{3}$'),
  created_at timestamptz not null default now(),
  primary key (provider, provider_payment_id),
  unique (settlement_id, provider_invoice_id),
  check (
    (provider_payment_kind = 'payment_intent' and provider_payment_id ~ '^pi_[A-Za-z0-9_]{1,252}$')
    or (provider_payment_kind = 'charge' and provider_payment_id ~ '^ch_[A-Za-z0-9_]{1,252}$')
  )
);
alter table public.billing_provider_payments enable row level security;
revoke all on public.billing_provider_payments from public, anon, authenticated, service_role;

create table if not exists public.billing_provider_refunds (
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  settlement_id uuid not null references public.billing_checkout_intents(settlement_id) on delete restrict,
  request_id text not null check (request_id ~ '^[A-Za-z0-9_-]{16,80}$'),
  request_hash text not null check (request_hash ~ '^[0-9a-f]{64}$'),
  provider text not null check (provider = 'stripe'),
  provider_payment_id text not null,
  provider_refund_id text not null unique check (provider_refund_id ~ '^re_[A-Za-z0-9_]{1,252}$'),
  amount_minor bigint not null check (amount_minor > 0),
  created_at timestamptz not null default now(),
  primary key (tenant_id, request_id),
  foreign key (provider, provider_payment_id)
    references public.billing_provider_payments(provider, provider_payment_id) on delete restrict
);
alter table public.billing_provider_refunds enable row level security;
revoke all on public.billing_provider_refunds from public, anon, authenticated, service_role;

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
begin
  perform public.assert_billing_actor(p_tenant_id, p_actor_user_id, array['owner', 'admin']);
  if p_request_id !~ '^[A-Za-z0-9_-]{16,80}$'
     or p_request_hash !~ '^[0-9a-f]{64}$'
     or p_seats not between 1 and 10000
     or p_billing_interval not in ('monthly', 'yearly')
     or p_price_id !~ '^price_[A-Za-z0-9]+$' then
    raise exception 'invalid_billing_checkout_intent' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':' || p_request_id, 2621
  ));
  select * into v_intent from public.billing_checkout_intents
    where tenant_id = p_tenant_id and request_id = p_request_id for update;
  if found then
    if v_intent.actor_user_id <> p_actor_user_id
       or v_intent.request_hash <> p_request_hash
       or v_intent.seats <> p_seats
       or v_intent.billing_interval <> p_billing_interval
       or v_intent.price_id <> p_price_id then
      raise exception 'billing_request_conflict' using errcode = '23505';
    end if;
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

create or replace function public.bind_billing_checkout_session(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_settlement_id uuid,
  p_request_id text,
  p_checkout_session_id text
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_intent public.billing_checkout_intents%rowtype;
begin
  perform public.assert_billing_actor(p_tenant_id, p_actor_user_id, array['owner', 'admin']);
  if p_checkout_session_id !~ '^cs_[A-Za-z0-9_]{1,252}$' then
    raise exception 'invalid_checkout_session' using errcode = '22023';
  end if;
  select * into v_intent from public.billing_checkout_intents
    where settlement_id = p_settlement_id for update;
  if not found or v_intent.tenant_id <> p_tenant_id
     or v_intent.actor_user_id <> p_actor_user_id
     or v_intent.request_id <> p_request_id then
    raise exception 'billing_checkout_binding_conflict' using errcode = '23505';
  end if;
  if v_intent.checkout_session_id is not null
     and v_intent.checkout_session_id <> p_checkout_session_id then
    raise exception 'billing_checkout_binding_conflict' using errcode = '23505';
  end if;
  update public.billing_checkout_intents
    set checkout_session_id = p_checkout_session_id,
        status = case when status = 'claimed' then 'checkout_created' else status end,
        updated_at = now()
    where settlement_id = p_settlement_id;
  return true;
end;
$$;
revoke all on function public.bind_billing_checkout_session(uuid, uuid, uuid, text, text)
  from public, anon, authenticated;
grant execute on function public.bind_billing_checkout_session(uuid, uuid, uuid, text, text)
  to service_role;

create or replace function public.record_stripe_payment_evidence(
  p_event_id text,
  p_event_created_at timestamptz,
  p_settlement_id uuid,
  p_request_id text,
  p_user_id uuid,
  p_tenant_id uuid,
  p_customer_id text,
  p_subscription_id text,
  p_invoice_id text,
  p_payment_kind text,
  p_payment_id text,
  p_amount_minor bigint,
  p_currency text
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_intent public.billing_checkout_intents%rowtype;
  v_payment public.billing_provider_payments%rowtype;
begin
  if p_event_id is null or char_length(p_event_id) not between 1 and 255
     or p_event_created_at is null
     or p_request_id !~ '^[A-Za-z0-9_-]{16,80}$'
     or p_customer_id !~ '^cus_[A-Za-z0-9_]{1,252}$'
     or p_subscription_id !~ '^sub_[A-Za-z0-9_]{1,252}$'
     or p_invoice_id !~ '^in_[A-Za-z0-9_]{1,252}$'
     or p_amount_minor <= 0 or p_currency !~ '^[a-z]{3}$'
     or not (
       (p_payment_kind = 'payment_intent' and p_payment_id ~ '^pi_[A-Za-z0-9_]{1,252}$')
       or (p_payment_kind = 'charge' and p_payment_id ~ '^ch_[A-Za-z0-9_]{1,252}$')
     ) then
    raise exception 'invalid_stripe_payment_evidence' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_settlement_id::text, 2622));
  select * into v_intent from public.billing_checkout_intents
    where settlement_id = p_settlement_id for update;
  if not found or v_intent.provider <> 'stripe'
     or v_intent.tenant_id <> p_tenant_id
     or v_intent.actor_user_id <> p_user_id
     or v_intent.request_id <> p_request_id then
    raise exception 'stripe_payment_binding_conflict' using errcode = '23505';
  end if;
  select * into v_payment from public.billing_provider_payments
    where provider_event_id = p_event_id;
  if found then
    if v_payment.settlement_id <> p_settlement_id
       or v_payment.tenant_id <> p_tenant_id
       or v_payment.user_id <> p_user_id
       or v_payment.request_id <> p_request_id
       or v_payment.provider_payment_id <> p_payment_id
       or v_payment.provider_payment_kind <> p_payment_kind
       or v_payment.provider_customer_id <> p_customer_id
       or v_payment.provider_subscription_id <> p_subscription_id
       or v_payment.provider_invoice_id <> p_invoice_id
       or v_payment.provider_event_id <> p_event_id
       or v_payment.event_created_at <> p_event_created_at
       or v_payment.amount_minor <> p_amount_minor
       or v_payment.currency <> p_currency then
      raise exception 'stripe_payment_binding_conflict' using errcode = '23505';
    end if;
    return true;
  end if;
  insert into public.billing_provider_payments (
    provider, provider_payment_id, provider_payment_kind, settlement_id,
    tenant_id, request_id, user_id, provider_customer_id,
    provider_subscription_id, provider_invoice_id, provider_event_id,
    event_created_at, amount_minor, currency
  ) values (
    'stripe', p_payment_id, p_payment_kind, p_settlement_id,
    p_tenant_id, p_request_id, p_user_id, p_customer_id,
    p_subscription_id, p_invoice_id, p_event_id,
    p_event_created_at, p_amount_minor, p_currency
  );
  update public.billing_checkout_intents
    set status = 'paid', updated_at = now()
    where settlement_id = p_settlement_id;
  return true;
end;
$$;
revoke all on function public.record_stripe_payment_evidence(
  text, timestamptz, uuid, text, uuid, uuid, text, text, text, text, text, bigint, text
) from public, anon, authenticated;
grant execute on function public.record_stripe_payment_evidence(
  text, timestamptz, uuid, text, uuid, uuid, text, text, text, text, text, bigint, text
) to service_role;

create or replace function public.get_billing_provider_payment(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_settlement_id uuid,
  p_provider_payment_id text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_result jsonb;
  v_count integer;
begin
  perform public.assert_billing_actor(p_tenant_id, p_actor_user_id, array['owner', 'admin']);
  if p_provider_payment_id is not null
     and p_provider_payment_id !~ '^(pi|ch)_[A-Za-z0-9_]{1,252}$' then
    raise exception 'invalid_provider_payment_id' using errcode = '22023';
  end if;
  select count(*)::integer into v_count
    from public.billing_provider_payments p
    where p.tenant_id = p_tenant_id and p.settlement_id = p_settlement_id
      and (p_provider_payment_id is null or p.provider_payment_id = p_provider_payment_id);
  if p_provider_payment_id is null and v_count > 1 then
    return jsonb_build_object('selection_required', true);
  end if;
  select jsonb_build_object(
    'provider', p.provider,
    'provider_payment_kind', p.provider_payment_kind,
    'provider_payment_id', p.provider_payment_id,
    'provider_customer_id', p.provider_customer_id,
    'provider_subscription_id', p.provider_subscription_id,
    'amount_minor', p.amount_minor,
    'refunded_amount_minor', coalesce(sum(r.amount_minor), 0),
    'currency', p.currency
  ) into v_result
  from public.billing_provider_payments p
  left join public.billing_provider_refunds r
    on r.provider = p.provider and r.provider_payment_id = p.provider_payment_id
  where p.tenant_id = p_tenant_id and p.settlement_id = p_settlement_id
    and (p_provider_payment_id is null or p.provider_payment_id = p_provider_payment_id)
  group by p.provider, p.provider_payment_kind, p.provider_payment_id,
    p.provider_customer_id, p.provider_subscription_id, p.amount_minor, p.currency;
  return v_result;
end;
$$;
revoke all on function public.get_billing_provider_payment(uuid, uuid, uuid, text)
  from public, anon, authenticated;
grant execute on function public.get_billing_provider_payment(uuid, uuid, uuid, text)
  to service_role;

create or replace function public.record_billing_provider_refund(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_settlement_id uuid,
  p_provider_payment_id text,
  p_request_id text,
  p_request_hash text,
  p_provider_refund_id text,
  p_amount_minor bigint
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_payment public.billing_provider_payments%rowtype;
  v_existing public.billing_provider_refunds%rowtype;
  v_refunded bigint;
begin
  perform public.assert_billing_actor(p_tenant_id, p_actor_user_id, array['owner', 'admin']);
  if p_request_id !~ '^[A-Za-z0-9_-]{16,80}$'
     or p_provider_payment_id !~ '^(pi|ch)_[A-Za-z0-9_]{1,252}$'
     or p_request_hash !~ '^[0-9a-f]{64}$'
     or p_provider_refund_id !~ '^re_[A-Za-z0-9_]{1,252}$'
     or p_amount_minor <= 0 then
    raise exception 'invalid_provider_refund' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_settlement_id::text, 2623));
  select * into v_payment from public.billing_provider_payments
    where tenant_id = p_tenant_id and settlement_id = p_settlement_id
      and provider_payment_id = p_provider_payment_id for update;
  if not found then
    raise exception 'provider_payment_not_found' using errcode = 'P0002';
  end if;
  select * into v_existing from public.billing_provider_refunds
    where tenant_id = p_tenant_id and request_id = p_request_id;
  if found then
    if v_existing.settlement_id <> p_settlement_id
       or v_existing.request_hash <> p_request_hash
       or v_existing.provider_refund_id <> p_provider_refund_id
       or v_existing.amount_minor <> p_amount_minor then
      raise exception 'billing_request_conflict' using errcode = '23505';
    end if;
  else
    select coalesce(sum(amount_minor), 0) into v_refunded
      from public.billing_provider_refunds
      where provider = v_payment.provider
        and provider_payment_id = v_payment.provider_payment_id;
    if v_refunded + p_amount_minor > v_payment.amount_minor then
      raise exception 'refund_exceeds_payment' using errcode = '22023';
    end if;
    insert into public.billing_provider_refunds (
      tenant_id, settlement_id, request_id, request_hash, provider,
      provider_payment_id, provider_refund_id, amount_minor
    ) values (
      p_tenant_id, p_settlement_id, p_request_id, p_request_hash,
      v_payment.provider, v_payment.provider_payment_id,
      p_provider_refund_id, p_amount_minor
    );
  end if;
  select coalesce(sum(amount_minor), 0) into v_refunded
    from public.billing_provider_refunds
    where provider = v_payment.provider
      and provider_payment_id = v_payment.provider_payment_id;
  update public.billing_portal_operations
    set status = 'completed', claim_updated_at = now(), completed_at = coalesce(completed_at, now()),
        result = jsonb_build_object(
          'ok', true,
          'refund_id', p_provider_refund_id,
          'refunded_amount_minor', v_refunded,
          'external_validation', true
        )
    where tenant_id = p_tenant_id and request_id = p_request_id
      and request_hash = p_request_hash and action = 'refund'
      and status in ('processing', 'completed');
  if not found then
    raise exception 'billing_operation_missing' using errcode = 'P0002';
  end if;
  return jsonb_build_object('refunded_amount_minor', v_refunded);
end;
$$;
revoke all on function public.record_billing_provider_refund(uuid, uuid, uuid, text, text, text, text, bigint)
  from public, anon, authenticated;
grant execute on function public.record_billing_provider_refund(uuid, uuid, uuid, text, text, text, text, bigint)
  to service_role;
