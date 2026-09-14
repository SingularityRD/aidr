-- Provider-of-record settlement ledger for the self-service subscription
-- portal (BIL-03 / T33).
--
-- Two things this migration deliberately does NOT do:
--
--   1. It never derives an entitlement from a request body. Every transition
--      re-checks the actor's active tenant, active membership and role inside
--      the same transaction that writes the ledger row.
--   2. It never marks a receipt externally validated. A locally produced
--      receipt is bookkeeping; reconciliation against a live provider account
--      is a named Finance responsibility and stays an open external gate.

create table if not exists public.billing_settlements (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  settlement_id uuid not null,
  request_id text not null check (request_id ~ '^[A-Za-z0-9_-]{16,80}$'),
  provider text not null check (provider in ('provider_fixture', 'stripe')),
  -- Server-resolved provider customer id. A client can never supply this.
  provider_customer_id text not null check (provider_customer_id ~ '^[A-Za-z][A-Za-z0-9_]{2,254}$'),
  provider_subscription_id text check (
    provider_subscription_id is null or
    provider_subscription_id ~ '^[A-Za-z][A-Za-z0-9_]{2,254}$'
  ),
  status text not null check (status in (
    'quote_issued', 'order_placed', 'settlement_pending',
    'settled', 'cancelled', 'refunded'
  )),
  currency text not null check (currency in ('USD', 'EUR', 'GBP')),
  lines jsonb not null check (jsonb_typeof(lines) = 'array' and jsonb_array_length(lines) between 1 and 32),
  total_amount_minor bigint not null check (total_amount_minor >= 0),
  quote_reference text check (
    quote_reference is null or
    (char_length(quote_reference) between 1 and 120 and quote_reference !~ '[[:cntrl:]]')
  ),
  settled_amount_minor bigint not null default 0 check (settled_amount_minor >= 0),
  refunded_amount_minor bigint not null default 0 check (refunded_amount_minor >= 0),
  occurred_at timestamptz not null,
  recorded_at timestamptz not null default now(),
  sequence integer not null check (sequence >= 0),
  -- Canonical hash input over the immutable fields plus its SHA-256 digest, so
  -- a caller can verify the stored record was not rewritten between read and
  -- use without trusting the database to reproduce the encoding.
  hash_input text not null check (char_length(hash_input) between 1 and 16384),
  receipt_hash text not null check (receipt_hash ~ '^[0-9a-f]{64}$'),
  external_validation boolean not null default false check (external_validation = false),
  created_at timestamptz not null default now(),
  unique (tenant_id, settlement_id, sequence),
  check (refunded_amount_minor <= settled_amount_minor),
  check (status not in ('settled', 'cancelled', 'refunded') or quote_reference is not null),
  check (status <> 'settled' or settled_amount_minor = total_amount_minor),
  check (status not in ('quote_issued', 'order_placed') or settled_amount_minor = 0)
);

create index if not exists billing_settlements_tenant_occurred_idx
  on public.billing_settlements(tenant_id, occurred_at desc, sequence desc);
create index if not exists billing_settlements_request_idx
  on public.billing_settlements(tenant_id, request_id);

-- Append-only: a receipt row may never be updated or deleted by a customer
-- route. Corrections are new rows that advance the state machine.
create or replace function public.reject_billing_settlement_mutation()
returns trigger language plpgsql as $$
begin
  raise exception 'billing_settlement_is_append_only' using errcode = '42501';
end;
$$;
revoke all on function public.reject_billing_settlement_mutation() from public, anon, authenticated;

drop trigger if exists billing_settlements_append_only on public.billing_settlements;
create trigger billing_settlements_append_only
before update or delete on public.billing_settlements
for each row execute procedure public.reject_billing_settlement_mutation();

alter table public.billing_settlements enable row level security;
revoke all on public.billing_settlements from public, anon, authenticated;
grant select, insert on public.billing_settlements to service_role;

-- Request-keyed idempotency: the first successful application of
-- (tenant, request_id) is authoritative; an identical replay returns the stored
-- receipt, a divergent replay is refused instead of silently overwriting.
create table if not exists public.billing_settlement_requests (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  request_id text not null check (request_id ~ '^[A-Za-z0-9_-]{16,80}$'),
  settlement_id uuid not null,
  receipt_hash text not null check (receipt_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  primary key (tenant_id, request_id)
);
alter table public.billing_settlement_requests enable row level security;
revoke all on public.billing_settlement_requests from public, anon, authenticated;
grant select, insert on public.billing_settlement_requests to service_role;

-- Current projected seat allocation per tenant, one row per SKU. Derived from
-- settled receipts only; never written directly from a client.
create table if not exists public.billing_entitlement_projections (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  sku text not null check (sku ~ '^[a-z][a-z0-9_.-]{1,63}$'),
  seats integer not null check (seats >= 0),
  source_settlement_ids jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (tenant_id, sku)
);
alter table public.billing_entitlement_projections enable row level security;
revoke all on public.billing_entitlement_projections from public, anon, authenticated;
grant select, insert, update, delete on public.billing_entitlement_projections to service_role;

-- ---------------------------------------------------------------------------
-- Authorization helper. Runs under the caller's transaction so a concurrent
-- membership revoke or tenant suspension serializes against the write.
-- ---------------------------------------------------------------------------
create or replace function public.assert_billing_actor(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_allowed_roles text[] default array['owner', 'admin']
)
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if p_tenant_id is null or p_actor_user_id is null then
    raise exception 'billing_forbidden' using errcode = '42501';
  end if;
  perform 1
    from public.tenants t
    join public.tenant_members m on m.tenant_id = t.id
    where t.id = p_tenant_id
      and t.status = 'active'
      and m.user_id = p_actor_user_id
      and m.role = any (p_allowed_roles)
      and (m.expires_at is null or m.expires_at > now())
    for share of t, m;
  if not found then
    raise exception 'billing_forbidden' using errcode = '42501';
  end if;
end;
$$;
revoke all on function public.assert_billing_actor(uuid, uuid, text[]) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- Transition RPC. The caller (Edge Function) supplies the already-validated
-- receipt fields; everything that decides *authorization* or *derived seats* is
-- recomputed here from stored state.
-- ---------------------------------------------------------------------------
create or replace function public.apply_billing_settlement(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_settlement_id uuid,
  p_request_id text,
  p_provider text,
  p_provider_customer_id text,
  p_provider_subscription_id text,
  p_status text,
  p_currency text,
  p_lines jsonb,
  p_total_amount_minor bigint,
  p_quote_reference text,
  p_settled_amount_minor bigint,
  p_refunded_amount_minor bigint,
  p_occurred_at timestamptz,
  p_sequence integer,
  p_hash_input text,
  p_receipt_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_quote text;
  v_current text;
  v_existing_hash text;
  v_existing public.billing_settlements%rowtype;
  v_row public.billing_settlements%rowtype;
begin
  v_quote := nullif(btrim(p_quote_reference), '');
  if p_settlement_id is null or p_request_id is null
     or p_request_id !~ '^[A-Za-z0-9_-]{16,80}$'
     or p_provider not in ('provider_fixture', 'stripe')
     or p_status not in ('quote_issued', 'order_placed', 'settlement_pending', 'settled', 'cancelled', 'refunded')
     or p_currency not in ('USD', 'EUR', 'GBP')
     or p_lines is null or jsonb_typeof(p_lines) <> 'array'
     or jsonb_array_length(p_lines) < 1 or jsonb_array_length(p_lines) > 32
     or p_total_amount_minor is null or p_total_amount_minor < 0
     or p_settled_amount_minor is null or p_settled_amount_minor < 0
     or p_refunded_amount_minor is null or p_refunded_amount_minor < 0
     or p_refunded_amount_minor > p_settled_amount_minor
     or p_occurred_at is null
     or p_sequence is null or p_sequence < 0
     or p_receipt_hash is null or p_receipt_hash !~ '^[0-9a-f]{64}$'
     or p_hash_input is null or char_length(p_hash_input) > 16384
     or (p_status = 'settled' and p_settled_amount_minor <> p_total_amount_minor)
     or (p_status in ('quote_issued', 'order_placed') and p_settled_amount_minor <> 0)
     or (p_status in ('settled', 'cancelled', 'refunded') and v_quote is null) then
    raise exception 'invalid_billing_settlement' using errcode = '22023';
  end if;

  perform public.assert_billing_actor(p_tenant_id, p_actor_user_id, array['owner', 'admin']);

  perform pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':' || p_request_id, 2614
  ));

  -- Idempotent replay: the same request id may only ever produce one receipt.
  select s.* into v_existing
    from public.billing_settlement_requests r
    join public.billing_settlements s
      on s.tenant_id = r.tenant_id and s.settlement_id = r.settlement_id and s.sequence = p_sequence
    where r.tenant_id = p_tenant_id and r.request_id = p_request_id
    limit 1;
  if found then
    if v_existing.receipt_hash <> p_receipt_hash then
      raise exception 'billing_request_conflict' using errcode = '23505';
    end if;
    return to_jsonb(v_existing);
  end if;
  select r.receipt_hash into v_existing_hash
    from public.billing_settlement_requests r
    where r.tenant_id = p_tenant_id and r.request_id = p_request_id;
  if found then
    raise exception 'billing_request_conflict' using errcode = '23505';
  end if;

  -- The state machine reads the stored current status, never the request body.
  select s.status into v_current
    from public.billing_settlements s
    where s.tenant_id = p_tenant_id and s.settlement_id = p_settlement_id
    order by s.sequence desc
    limit 1;
  if v_current is null then
    if p_status not in ('quote_issued', 'order_placed') then
      raise exception 'billing_ledger_must_start_at_quote' using errcode = '22023';
    end if;
  elsif v_current = 'refunded' then
    raise exception 'billing_settlement_terminal' using errcode = '22023';
  elsif v_current <> p_status and not (
    (v_current = 'quote_issued' and p_status in ('order_placed', 'cancelled')) or
    (v_current = 'order_placed' and p_status in ('settlement_pending', 'cancelled')) or
    (v_current = 'settlement_pending' and p_status in ('settled', 'cancelled')) or
    (v_current = 'settled' and p_status in ('cancelled', 'refunded')) or
    (v_current = 'cancelled' and p_status = 'refunded')
  ) then
    raise exception 'billing_transition_not_allowed' using errcode = '22023';
  end if;

  -- A refund may never exceed what was actually captured on the settled row.
  if p_status = 'refunded' then
    if p_settled_amount_minor <> (
      select s.settled_amount_minor from public.billing_settlements s
      where s.tenant_id = p_tenant_id and s.settlement_id = p_settlement_id
      order by s.sequence desc limit 1
    ) then
      raise exception 'billing_refund_amount_changed' using errcode = '22023';
    end if;
  end if;

  insert into public.billing_settlements (
    tenant_id, settlement_id, request_id, provider, provider_customer_id,
    provider_subscription_id, status, currency, lines, total_amount_minor,
    quote_reference, settled_amount_minor, refunded_amount_minor, occurred_at,
    sequence, hash_input, receipt_hash
  ) values (
    p_tenant_id, p_settlement_id, p_request_id, p_provider, p_provider_customer_id,
    p_provider_subscription_id, p_status, p_currency, p_lines, p_total_amount_minor,
    v_quote, p_settled_amount_minor, p_refunded_amount_minor, p_occurred_at,
    p_sequence, p_hash_input, p_receipt_hash
  ) returning * into v_row;

  insert into public.billing_settlement_requests (tenant_id, request_id, settlement_id, receipt_hash)
  values (p_tenant_id, p_request_id, p_settlement_id, p_receipt_hash)
  on conflict (tenant_id, request_id) do nothing;

  insert into public.admin_audit_logs (actor_user_id, tenant_id, action, detail)
  values (
    p_actor_user_id, p_tenant_id, 'billing_settlement.applied',
    jsonb_build_object(
      'settlement_id', v_row.settlement_id,
      'request_id', v_row.request_id,
      'status', v_row.status,
      'currency', v_row.currency,
      'total_amount_minor', v_row.total_amount_minor,
      'settled_amount_minor', v_row.settled_amount_minor,
      'refunded_amount_minor', v_row.refunded_amount_minor,
      'receipt_hash', v_row.receipt_hash,
      'external_validation', v_row.external_validation
    )
  );

  return to_jsonb(v_row);
end;
$$;
revoke all on function public.apply_billing_settlement(
  uuid, uuid, uuid, text, text, text, text, text, text, jsonb, bigint, text, bigint, bigint, timestamptz, integer, text, text
) from public, anon, authenticated;
grant execute on function public.apply_billing_settlement(
  uuid, uuid, uuid, text, text, text, text, text, text, jsonb, bigint, text, bigint, bigint, timestamptz, integer, text, text
) to service_role;

-- ---------------------------------------------------------------------------
-- Ledger read for the portal view and for the seat reconciler.
-- ---------------------------------------------------------------------------
create or replace function public.list_billing_settlements(
  p_tenant_id uuid,
  p_actor_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_rows jsonb;
begin
  perform public.assert_billing_actor(p_tenant_id, p_actor_user_id, array['owner', 'admin']);
  select coalesce(jsonb_agg(to_jsonb(s) order by s.occurred_at asc, s.sequence asc), '[]'::jsonb)
    into v_rows
    from (
      select id, tenant_id, settlement_id, request_id, provider,
        provider_customer_id, provider_subscription_id, status, currency,
        lines, total_amount_minor, quote_reference, settled_amount_minor,
        refunded_amount_minor, occurred_at, recorded_at, sequence,
        hash_input, receipt_hash, external_validation
      from public.billing_settlements
      where tenant_id = p_tenant_id
      order by occurred_at desc, sequence desc
      limit 500
    ) s;
  return v_rows;
end;
$$;
revoke all on function public.list_billing_settlements(uuid, uuid) from public, anon, authenticated;
grant execute on function public.list_billing_settlements(uuid, uuid) to service_role;

-- The portal must never present a seat count that was inferred from an
-- unauthorized read. This helper is used by the seat reconciler and by the
-- `billing-portal` handler's audit trail.
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
  delete from public.billing_entitlement_projections where tenant_id = p_tenant_id;
  insert into public.billing_entitlement_projections (tenant_id, sku, seats, source_settlement_ids)
  select p_tenant_id,
    line ->> 'sku',
    sum((line ->> 'quantity')::integer),
    jsonb_agg(distinct s.settlement_id)
  from (
    select distinct on (settlement_id) settlement_id, lines
    from public.billing_settlements
    where tenant_id = p_tenant_id
    order by settlement_id, occurred_at desc, sequence desc
  ) s
  cross join lateral jsonb_array_elements(s.lines) as line
  where (
    select st.status from public.billing_settlements st
    where st.tenant_id = p_tenant_id and st.settlement_id = s.settlement_id
    order by st.occurred_at desc, st.sequence desc limit 1
  ) = 'settled'
  group by line ->> 'sku';
  select coalesce(jsonb_agg(jsonb_build_object(
    'sku', sku, 'seats', seats, 'sources', source_settlement_ids
  ) order by sku), '[]'::jsonb) into v_result
  from public.billing_entitlement_projections where tenant_id = p_tenant_id;
  return v_result;
end;
$$;
revoke all on function public.recompute_billing_projection(uuid, uuid) from public, anon, authenticated;
grant execute on function public.recompute_billing_projection(uuid, uuid) to service_role;

-- Commercial records must not outlive the tenant's retention boundary. This
-- mirrors the invoice-order purge: the settlement ledger is billing evidence,
-- so it is deleted only once the offboarding run reaches the entitlements phase.
create or replace function public.purge_billing_settlements_at_commercial_retention()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_tenant_id uuid;
  v_deleted bigint;
begin
  if new.phase = 'entitlements' and new.status = 'completed'
     and old.status is distinct from 'completed' then
    select tenant_id into strict v_tenant_id
      from public.tenant_offboarding_runs where id = new.run_id;
    delete from public.billing_settlements where tenant_id = v_tenant_id;
    get diagnostics v_deleted = row_count;
    delete from public.billing_settlement_requests where tenant_id = v_tenant_id;
    delete from public.billing_entitlement_projections where tenant_id = v_tenant_id;
    insert into public.tenant_offboarding_phase_receipts
      (run_id, phase_order, phase, data_class, operation, retention_days,
       eligible_at, status, rows_deleted, attempts, started_at, completed_at)
    values
      (new.run_id, 91, 'billing_settlements', 'commercial_records',
       'delete_records', new.retention_days, new.eligible_at,
       'completed', v_deleted, 1, now(), now());
  end if;
  return new;
end;
$$;
revoke all on function public.purge_billing_settlements_at_commercial_retention()
  from public, anon, authenticated;

drop trigger if exists tenant_offboarding_purge_billing_settlements on public.tenant_offboarding_phase_receipts;
create trigger tenant_offboarding_purge_billing_settlements
after update of status on public.tenant_offboarding_phase_receipts
for each row execute procedure public.purge_billing_settlements_at_commercial_retention();

create or replace function public.purge_billing_settlements_on_tenant_close()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if old.status is distinct from 'closed' and new.status = 'closed' then
    delete from public.billing_settlements where tenant_id = new.id;
    delete from public.billing_settlement_requests where tenant_id = new.id;
    delete from public.billing_entitlement_projections where tenant_id = new.id;
  end if;
  return new;
end;
$$;
revoke all on function public.purge_billing_settlements_on_tenant_close() from public, anon, authenticated;

drop trigger if exists tenants_purge_billing_settlements_on_close on public.tenants;
create trigger tenants_purge_billing_settlements_on_close
before update of status on public.tenants
for each row execute procedure public.purge_billing_settlements_on_tenant_close();
