-- Enterprise invoice/order intake. This is deliberately a pending-finance
-- ledger, not a payment provider or an entitlement provisioning path.
-- A later provider-of-record integration must add a separately verified,
-- auditable transition before it can change public.entitlements.

create table public.enterprise_invoice_orders (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  request_id text not null check (request_id ~ '^[A-Za-z0-9_-]{16,80}$'),
  created_by uuid references auth.users(id) on delete set null,
  requested_agents integer not null check (requested_agents between 1 and 100000),
  quote_reference text check (
    quote_reference is null or
    (char_length(quote_reference) between 1 and 120 and quote_reference !~ '[[:cntrl:]]')
  ),
  status text not null default 'pending_finance'
    check (status = 'pending_finance'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, request_id)
);
create index enterprise_invoice_orders_tenant_created_idx
  on public.enterprise_invoice_orders(tenant_id, created_at desc);
create trigger enterprise_invoice_orders_touch_updated_at
before update on public.enterprise_invoice_orders
for each row execute procedure public.touch_updated_at();

alter table public.enterprise_invoice_orders enable row level security;
revoke all on public.enterprise_invoice_orders from public, anon, authenticated;
grant select, insert on public.enterprise_invoice_orders to service_role;

-- One database transaction owns idempotency, active-tenant/role rechecks,
-- creation and audit. The Edge route additionally checks the Auth-issued
-- token, session revocation and the tenant MFA policy before calling this RPC.
create function public.request_enterprise_invoice_order(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_request_id text,
  p_requested_agents integer,
  p_quote_reference text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_quote_reference text;
  v_order public.enterprise_invoice_orders%rowtype;
begin
  v_quote_reference := nullif(btrim(p_quote_reference), '');
  if p_tenant_id is null or p_actor_user_id is null
     or p_request_id is null or p_request_id !~ '^[A-Za-z0-9_-]{16,80}$'
     or p_requested_agents is null or p_requested_agents not between 1 and 100000
     or (v_quote_reference is not null and
       (char_length(v_quote_reference) > 120 or v_quote_reference ~ '[[:cntrl:]]')) then
    raise exception 'invalid_invoice_order_request' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':' || p_request_id, 2613
  ));
  -- Hold both authorization rows until the request transaction ends. A
  -- concurrent membership revoke or tenant suspension must serialize here.
  perform 1 from public.tenants t
    join public.tenant_members m on m.tenant_id = t.id
    where t.id = p_tenant_id and t.status = 'active'
      and m.user_id = p_actor_user_id
      and m.role in ('owner', 'admin')
      and (m.expires_at is null or m.expires_at > now())
    for share of t, m;
  if not found then
    raise exception 'invoice_order_forbidden' using errcode = '42501';
  end if;

  select * into v_order from public.enterprise_invoice_orders
    where tenant_id = p_tenant_id and request_id = p_request_id;
  if found then
    if v_order.requested_agents <> p_requested_agents
       or v_order.quote_reference is distinct from v_quote_reference then
      raise exception 'invoice_order_request_conflict' using errcode = '23505';
    end if;
    return to_jsonb(v_order);
  end if;

  insert into public.enterprise_invoice_orders
    (tenant_id, request_id, created_by, requested_agents, quote_reference)
  values (p_tenant_id, p_request_id, p_actor_user_id,
    p_requested_agents, v_quote_reference)
  returning * into v_order;

  insert into public.admin_audit_logs
    (actor_user_id, tenant_id, action, detail)
  values (
    p_actor_user_id, p_tenant_id, 'invoice_order.requested',
    jsonb_build_object(
      'order_id', v_order.id,
      'request_id', v_order.request_id,
      'requested_agents', v_order.requested_agents,
      'quote_reference', v_order.quote_reference,
      'status', v_order.status
    )
  );
  return to_jsonb(v_order);
end;
$$;
revoke all on function public.request_enterprise_invoice_order(uuid, uuid, text, integer, text)
  from public, anon, authenticated;
grant execute on function public.request_enterprise_invoice_order(uuid, uuid, text, integer, text)
  to service_role;

-- Privileged reads also recheck membership in the same database transaction.
create function public.list_enterprise_invoice_orders(
  p_tenant_id uuid,
  p_actor_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_orders jsonb;
begin
  if p_tenant_id is null or p_actor_user_id is null then
    raise exception 'invalid_invoice_order_request' using errcode = '22023';
  end if;
  perform 1 from public.tenants t
    join public.tenant_members m on m.tenant_id = t.id
    where t.id = p_tenant_id and t.status = 'active'
      and m.user_id = p_actor_user_id
      and m.role in ('owner', 'admin')
      and (m.expires_at is null or m.expires_at > now())
    for share of t, m;
  if not found then
    raise exception 'invoice_order_forbidden' using errcode = '42501';
  end if;
  select coalesce(jsonb_agg(to_jsonb(o) order by o.created_at desc, o.id desc), '[]'::jsonb)
    into v_orders from (
      select id, tenant_id, request_id, requested_agents,
        quote_reference, status, created_at, updated_at
      from public.enterprise_invoice_orders
      where tenant_id = p_tenant_id
      order by created_at desc, id desc
      limit 100
    ) o;
  return v_orders;
end;
$$;
revoke all on function public.list_enterprise_invoice_orders(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.list_enterprise_invoice_orders(uuid, uuid)
  to service_role;

-- The existing commercial-record phase finishes only when its retention date
-- is reached and legal holds have been released. Purge order requests at that
-- boundary, in the same transaction, and record their own deletion count.
create function public.purge_invoice_orders_at_commercial_retention()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_tenant_id uuid;
  v_deleted bigint;
begin
  if new.phase = 'entitlements' and new.status = 'completed'
     and old.status is distinct from 'completed' then
    select tenant_id into strict v_tenant_id
      from public.tenant_offboarding_runs where id = new.run_id;
    delete from public.enterprise_invoice_orders where tenant_id = v_tenant_id;
    get diagnostics v_deleted = row_count;
    insert into public.tenant_offboarding_phase_receipts
      (run_id, phase_order, phase, data_class, operation, retention_days,
       eligible_at, status, rows_deleted, attempts, started_at, completed_at)
    values
      (new.run_id, 90, 'enterprise_invoice_orders', 'commercial_records',
       'delete_records', new.retention_days, new.eligible_at,
       'completed', v_deleted, 1, now(), now());
  end if;
  return new;
end;
$$;
revoke all on function public.purge_invoice_orders_at_commercial_retention()
  from public, anon, authenticated;
create trigger tenant_offboarding_purge_invoice_orders
after update of status on public.tenant_offboarding_phase_receipts
for each row execute procedure public.purge_invoice_orders_at_commercial_retention();

-- Defensive cleanup if a tenant reaches closed through a future path that
-- does not execute the commercial phase. No customer route can issue orders
-- once a tenant is closing or closed.
create function public.purge_invoice_orders_on_tenant_close()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if old.status is distinct from 'closed' and new.status = 'closed' then
    delete from public.enterprise_invoice_orders where tenant_id = new.id;
  end if;
  return new;
end;
$$;
revoke all on function public.purge_invoice_orders_on_tenant_close()
  from public, anon, authenticated;
create trigger tenants_purge_invoice_orders_on_close
before update of status on public.tenants
for each row execute procedure public.purge_invoice_orders_on_tenant_close();
