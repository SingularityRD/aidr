-- ---------------------------------------------------------------------------
-- Finance approval -> paid transition for the invoice-only commercial flow.
-- ---------------------------------------------------------------------------
-- `20260913000003_invoice_entitlement.sql` is deliberately a pending_finance
-- only intake ledger and stays exactly as shipped: no request to the
-- `invoice-entitlement` Edge route can mark an invoice paid through it, and its
-- status check constraint is not widened here.
--
-- This migration adds the *separate* paid state and the single RPC that may
-- enter it. The approval DECISION is human and external and stays an operator
-- input: the approver identity, the approved amount, the currency and the
-- evidence digest are supplied by the operator. Nothing in this migration
-- derives, guesses or invents a price, a tax figure or an approval.
--
-- Three properties are local code and are implemented here:
--   1. the transition itself (`record_invoice_approval`), which also grants the
--      tenant's paid agent entitlement;
--   2. idempotency: a second approval for the same order is REFUSED with a
--      machine-readable conflict (errcode 23505, 'invoice_approval_conflict')
--      instead of being applied twice;
--   3. auditability: the approver, the amount, the currency and the evidence
--      digest are written to `public.admin_audit_logs` in the same transaction.

create table public.enterprise_invoice_approvals (
  -- One finance decision per order. The primary key *is* the idempotency
  -- guarantee: a replay cannot create a second row.
  order_id uuid primary key references public.enterprise_invoice_orders(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  -- The only value this table can represent. The intake ledger keeps its own
  -- 'pending_finance'-only constraint untouched.
  status text not null default 'paid' check (status = 'paid'),
  -- Operator-supplied external identity of the human who approved the invoice.
  approver text not null check (
    char_length(approver) between 1 and 200 and approver !~ '[[:cntrl:]]'
  ),
  -- Operator-supplied approved commercial amount, in minor units. Never
  -- computed from a line item, a plan or a tax rate.
  amount_minor bigint not null check (amount_minor > 0),
  currency text not null check (currency in ('USD', 'EUR', 'GBP')),
  -- Digest of the out-of-band payment evidence the approver relied on. The
  -- evidence itself never enters this database.
  evidence_sha256 text not null check (evidence_sha256 ~ '^[0-9a-f]{64}$'),
  -- The entitlement granted by this approval: the quantity the order requested.
  agents_granted integer not null check (agents_granted between 1 and 100000),
  approved_at timestamptz not null default now()
);
create index enterprise_invoice_approvals_tenant_idx
  on public.enterprise_invoice_approvals(tenant_id, approved_at desc);

alter table public.enterprise_invoice_approvals enable row level security;
revoke all on public.enterprise_invoice_approvals from public, anon, authenticated;
-- select + insert only: a recorded finance decision is never rewritten or
-- removed through the API. Offboarding removes it through the order cascade.
grant select, insert on public.enterprise_invoice_approvals to service_role;

-- ---------------------------------------------------------------------------
-- Tenant scoping for the approval action. `record_invoice_approval` takes the
-- order id only (a fixed signature), so the caller must first prove that the
-- order belongs to the tenant it is authenticated for, under the same
-- active-tenant/active-role recheck the intake and list RPCs perform.
-- ---------------------------------------------------------------------------
create function public.get_enterprise_invoice_order_for_approval(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_order_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_order public.enterprise_invoice_orders%rowtype;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_order_id is null then
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
  select * into v_order from public.enterprise_invoice_orders
    where id = p_order_id and tenant_id = p_tenant_id;
  if not found then
    return null;
  end if;
  return to_jsonb(v_order);
end;
$$;
revoke all on function public.get_enterprise_invoice_order_for_approval(uuid, uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.get_enterprise_invoice_order_for_approval(uuid, uuid, uuid)
  to service_role;

-- ---------------------------------------------------------------------------
-- The ONLY transition from pending_finance to paid. One database transaction
-- owns the single-decision guarantee, the entitlement grant and the audit row.
-- ---------------------------------------------------------------------------
create function public.record_invoice_approval(
  p_order_id uuid,
  p_approver text,
  p_amount_minor bigint,
  p_currency text,
  p_evidence_sha256 text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_approver text;
  v_order public.enterprise_invoice_orders%rowtype;
  v_owner uuid;
  v_approval public.enterprise_invoice_approvals%rowtype;
begin
  v_approver := btrim(coalesce(p_approver, ''));
  if p_order_id is null
     or v_approver = '' or char_length(v_approver) > 200 or v_approver ~ '[[:cntrl:]]'
     or p_amount_minor is null or p_amount_minor < 1
     or p_currency is null or p_currency not in ('USD', 'EUR', 'GBP')
     or p_evidence_sha256 is null
     or p_evidence_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_invoice_approval' using errcode = '22023';
  end if;

  -- Serialize per order so two concurrent approvals cannot both observe
  -- "not yet approved" and both write a decision.
  perform pg_advisory_xact_lock(hashtextextended(p_order_id::text, 2615));

  select * into v_order from public.enterprise_invoice_orders
    where id = p_order_id
    for update;
  if not found then
    raise exception 'invoice_order_not_found' using errcode = 'P0002';
  end if;

  -- Idempotency is a refusal, not a silent second application: the first
  -- recorded decision stays the only decision an auditor can see.
  if exists (select 1 from public.enterprise_invoice_approvals where order_id = p_order_id)
     or v_order.status <> 'pending_finance' then
    raise exception 'invoice_approval_conflict' using errcode = '23505';
  end if;

  -- The entitlement may only move for an active tenant that still has an
  -- active owner to hold the allocation row.
  perform 1 from public.tenants t
    join public.tenant_members m on m.tenant_id = t.id
    where t.id = v_order.tenant_id and t.status = 'active'
      and m.role = 'owner'
      and (m.expires_at is null or m.expires_at > now())
    for share of t, m;
  if not found then
    raise exception 'invoice_approval_forbidden' using errcode = '42501';
  end if;

  insert into public.enterprise_invoice_approvals
    (order_id, tenant_id, status, approver, amount_minor, currency,
     evidence_sha256, agents_granted)
  values
    (p_order_id, v_order.tenant_id, 'paid', v_approver, p_amount_minor,
     p_currency, p_evidence_sha256, v_order.requested_agents)
  returning * into v_approval;

  -- The recorded approvals are the only source of the tenant's paid agent
  -- count, so the entitlement is recomputed from them and never from a request
  -- body. A later approval for the same tenant adds to the sum.
  select tm.user_id into v_owner
    from public.tenant_members tm
    where tm.tenant_id = v_order.tenant_id and tm.role = 'owner'
    order by tm.user_id
    limit 1;
  insert into public.entitlements (user_id, tenant_id, extra_agents)
  values (
    coalesce(v_order.created_by, v_owner),
    v_order.tenant_id,
    (select coalesce(sum(a.agents_granted), 0)::integer
       from public.enterprise_invoice_approvals a
      where a.tenant_id = v_order.tenant_id and a.status = 'paid')
  )
  on conflict (tenant_id) do update
    set extra_agents = excluded.extra_agents,
        updated_at = now();

  -- The approver is a human identity, not an AIDR session: no local actor is
  -- asserted here, and the order requester is never presented as the approver.
  insert into public.admin_audit_logs (actor_user_id, tenant_id, action, detail)
  values (
    null, v_approval.tenant_id, 'invoice_approval.recorded',
    jsonb_build_object(
      'order_id', v_approval.order_id,
      'request_id', v_order.request_id,
      'tenant_id', v_approval.tenant_id,
      'status', v_approval.status,
      'approver', v_approval.approver,
      'amount_minor', v_approval.amount_minor,
      'currency', v_approval.currency,
      'evidence_sha256', v_approval.evidence_sha256,
      'agents_granted', v_approval.agents_granted,
      'approved_at', v_approval.approved_at
    )
  );

  return jsonb_build_object(
    'order_id', v_approval.order_id,
    'tenant_id', v_approval.tenant_id,
    'request_id', v_order.request_id,
    'quote_reference', v_order.quote_reference,
    'status', v_approval.status,
    'approver', v_approval.approver,
    'amount_minor', v_approval.amount_minor,
    'currency', v_approval.currency,
    'evidence_sha256', v_approval.evidence_sha256,
    'agents_granted', v_approval.agents_granted,
    'approved_at', v_approval.approved_at
  );
end;
$$;
revoke all on function public.record_invoice_approval(uuid, text, bigint, text, text)
  from public, anon, authenticated;
grant execute on function public.record_invoice_approval(uuid, text, bigint, text, text)
  to service_role;

-- ---------------------------------------------------------------------------
-- Privileged read of the recorded decisions, for the reconciliation surface.
-- It carries the order's request id and quote reference so an approved order
-- can be correlated with settled settlements without a second privileged read.
-- ---------------------------------------------------------------------------
create function public.list_enterprise_invoice_approvals(
  p_tenant_id uuid,
  p_actor_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_approvals jsonb;
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
  select coalesce(jsonb_agg(jsonb_build_object(
      'order_id', a.order_id,
      'tenant_id', a.tenant_id,
      'request_id', o.request_id,
      'quote_reference', o.quote_reference,
      'status', a.status,
      'approver', a.approver,
      'amount_minor', a.amount_minor,
      'currency', a.currency,
      'evidence_sha256', a.evidence_sha256,
      'agents_granted', a.agents_granted,
      'approved_at', a.approved_at
    ) order by a.approved_at desc, a.order_id desc), '[]'::jsonb)
    into v_approvals
    from public.enterprise_invoice_approvals a
    join public.enterprise_invoice_orders o on o.id = a.order_id
    where a.tenant_id = p_tenant_id;
  return v_approvals;
end;
$$;
revoke all on function public.list_enterprise_invoice_approvals(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.list_enterprise_invoice_approvals(uuid, uuid)
  to service_role;
