-- Finance authority is independent of customer owner/admin membership.
-- Intentionally empty: only a database administrator provisions or revokes an
-- explicitly reviewed (tenant, authenticated user) grant. Neither customer RPCs
-- nor the Edge service role can provision themselves. No historical approver
-- label is backfilled into an authenticated identity.
create table public.invoice_finance_operators (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete restrict,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);
alter table public.invoice_finance_operators enable row level security;
revoke all on public.invoice_finance_operators from public, anon, authenticated, service_role;
grant select on public.invoice_finance_operators to service_role;

alter table public.enterprise_invoice_approvals
  add column approver_user_id uuid references auth.users(id) on delete restrict;
comment on column public.enterprise_invoice_approvals.approver_user_id is
  'Authenticated finance actor. NULL on legacy approvals, whose claimed approver was not verified.';
-- New approvals must go through the authority-checking transition, not a direct
-- PostgREST insert. Historical rows remain readable without rewriting evidence.
revoke all on public.enterprise_invoice_approvals from service_role;
grant select on public.enterprise_invoice_approvals to service_role;

create function public.assert_invoice_finance_operator(p_tenant_id uuid, p_actor_user_id uuid)
returns void language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if p_tenant_id is null or p_actor_user_id is null then
    raise exception 'invoice_approval_forbidden' using errcode = '42501';
  end if;
  -- Lock the authority rows until the caller's transaction commits. A concurrent
  -- revocation, expiry change or tenant suspension cannot race a paid transition.
  perform 1 from public.invoice_finance_operators f
    join public.tenants t on t.id = f.tenant_id
    where f.tenant_id = p_tenant_id and f.user_id = p_actor_user_id
      and f.revoked_at is null
      and (f.expires_at is null or f.expires_at > now())
      and t.status = 'active'
    for share of f, t;
  if not found then
    raise exception 'invoice_approval_forbidden' using errcode = '42501';
  end if;
end;
$$;
revoke all on function public.assert_invoice_finance_operator(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.assert_invoice_finance_operator(uuid, uuid) to service_role;

-- Early read-only check for the Edge route, before even consuming quota. This
-- is not the authorization boundary for writes: the transition repeats it.
create or replace function public.get_enterprise_invoice_order_for_approval(
  p_tenant_id uuid, p_actor_user_id uuid, p_order_id uuid
)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_order public.enterprise_invoice_orders%rowtype;
begin
  perform public.assert_invoice_finance_operator(p_tenant_id, p_actor_user_id);
  if p_order_id is null then
    raise exception 'invalid_invoice_order_request' using errcode = '22023';
  end if;
  select * into v_order from public.enterprise_invoice_orders
    where id = p_order_id and tenant_id = p_tenant_id;
  if not found then return null; end if;
  return to_jsonb(v_order);
end;
$$;
revoke all on function public.get_enterprise_invoice_order_for_approval(uuid, uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.get_enterprise_invoice_order_for_approval(uuid, uuid, uuid)
  to service_role;

-- Remove the old actor-less RPC completely: leaving an overload executable
-- would retain the original self-asserted approval path.
drop function public.record_invoice_approval(uuid, text, bigint, text, text);
create function public.record_invoice_approval(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_order_id uuid,
  p_amount_minor bigint,
  p_currency text,
  p_evidence_sha256 text
)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_order public.enterprise_invoice_orders%rowtype;
  v_owner uuid;
  v_approval public.enterprise_invoice_approvals%rowtype;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_order_id is null
     or p_amount_minor is null or p_amount_minor < 1
     or p_currency is null or p_currency not in ('USD', 'EUR', 'GBP')
     or p_evidence_sha256 is null or p_evidence_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_invoice_approval' using errcode = '22023';
  end if;

  -- Tenant -> authority rows -> order. Different orders affect the SAME tenant
  -- allocation: a per-order lock alone lets ON CONFLICT overwrite a concurrent
  -- approval with a stale subtotal. Lock before insertion AND aggregate read.
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2617));
  perform public.assert_invoice_finance_operator(p_tenant_id, p_actor_user_id);
  select * into v_order from public.enterprise_invoice_orders
    where id = p_order_id and tenant_id = p_tenant_id for update;
  if not found then
    raise exception 'invoice_order_not_found' using errcode = 'P0002';
  end if;
  if exists (select 1 from public.enterprise_invoice_approvals where order_id = p_order_id)
     or v_order.status <> 'pending_finance' then
    raise exception 'invoice_approval_conflict' using errcode = '23505';
  end if;

  -- The allocation must still have an active customer owner; that owner's role
  -- is not finance authority and never supplies the approver identity.
  select m.user_id into v_owner from public.tenant_members m
    where m.tenant_id = p_tenant_id and m.role = 'owner'
      and (m.expires_at is null or m.expires_at > now())
    order by m.user_id limit 1 for share;
  if not found then
    raise exception 'invoice_approval_forbidden' using errcode = '42501';
  end if;

  insert into public.enterprise_invoice_approvals
    (order_id, tenant_id, status, approver, approver_user_id, amount_minor,
     currency, evidence_sha256, agents_granted)
  values
    (p_order_id, p_tenant_id, 'paid', p_actor_user_id::text, p_actor_user_id,
     p_amount_minor, p_currency, p_evidence_sha256, v_order.requested_agents)
  returning * into v_approval;

  insert into public.entitlements (user_id, tenant_id, extra_agents)
  values (
    v_owner, p_tenant_id,
    (select coalesce(sum(a.agents_granted), 0)::integer
       from public.enterprise_invoice_approvals a
      where a.tenant_id = p_tenant_id and a.status = 'paid')
  )
  on conflict (tenant_id) do update
    set extra_agents = excluded.extra_agents, updated_at = now();

  insert into public.admin_audit_logs (actor_user_id, tenant_id, action, detail)
  values (
    p_actor_user_id, p_tenant_id, 'invoice_approval.recorded',
    jsonb_build_object(
      'order_id', v_approval.order_id, 'request_id', v_order.request_id,
      'tenant_id', p_tenant_id, 'status', v_approval.status,
      'approver', v_approval.approver, 'approver_user_id', p_actor_user_id,
      'amount_minor', v_approval.amount_minor, 'currency', v_approval.currency,
      'evidence_sha256', v_approval.evidence_sha256,
      'agents_granted', v_approval.agents_granted, 'approved_at', v_approval.approved_at
    )
  );
  return jsonb_build_object(
    'order_id', v_approval.order_id, 'tenant_id', p_tenant_id,
    'request_id', v_order.request_id, 'quote_reference', v_order.quote_reference,
    'status', v_approval.status, 'approver', v_approval.approver,
    'amount_minor', v_approval.amount_minor, 'currency', v_approval.currency,
    'evidence_sha256', v_approval.evidence_sha256,
    'agents_granted', v_approval.agents_granted, 'approved_at', v_approval.approved_at
  );
end;
$$;
revoke all on function public.record_invoice_approval(uuid, uuid, uuid, bigint, text, text)
  from public, anon, authenticated;
grant execute on function public.record_invoice_approval(uuid, uuid, uuid, bigint, text, text)
  to service_role;
