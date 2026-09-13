-- Run inside a transaction that the caller rolls back. Requires an initialized
-- local stack with at least two active tenants and an owner/admin member.
do $test$
declare
  v_tenant uuid;
  v_actor uuid;
  v_other_tenant uuid;
  v_request_id text := 'invsmoke_' || replace(gen_random_uuid()::text, '-', '');
  v_offboarding_run uuid;
  v_first jsonb;
  v_replay jsonb;
  v_list jsonb;
  v_entitlement_before jsonb;
  v_entitlement_after jsonb;
  v_count integer;
begin
  select m.tenant_id, m.user_id into v_tenant, v_actor
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
    where t.status = 'active' and m.role in ('owner', 'admin')
      and (m.expires_at is null or m.expires_at > now())
      and exists (select 1 from public.entitlements e where e.tenant_id = t.id)
    order by m.tenant_id, m.user_id limit 1;
  if v_actor is null then raise exception 'invoice smoke needs active owner fixture'; end if;
  select to_jsonb(e) into v_entitlement_before
    from public.entitlements e where e.tenant_id = v_tenant;

  v_first := public.request_enterprise_invoice_order(
    v_tenant, v_actor, v_request_id, 125, 'Q-SMOKE'
  );
  v_replay := public.request_enterprise_invoice_order(
    v_tenant, v_actor, v_request_id, 125, 'Q-SMOKE'
  );
  if v_first is distinct from v_replay
     or v_first ->> 'status' <> 'pending_finance'
     or (v_first ->> 'requested_agents')::integer <> 125 then
    raise exception 'invoice order replay or pending state mismatch';
  end if;

  select count(*) into v_count from public.enterprise_invoice_orders
    where tenant_id = v_tenant and request_id = v_request_id;
  if v_count <> 1 then raise exception 'invoice order was not idempotent'; end if;
  select count(*) into v_count from public.admin_audit_logs
    where tenant_id = v_tenant and action = 'invoice_order.requested'
      and detail ->> 'request_id' = v_request_id;
  if v_count <> 1 then raise exception 'invoice order audit was not atomic'; end if;
  v_list := public.list_enterprise_invoice_orders(v_tenant, v_actor);
  if jsonb_array_length(v_list) < 1
     or not exists (
       select 1 from jsonb_array_elements(v_list) item
       where item ->> 'request_id' = v_request_id
         and item ->> 'tenant_id' = v_tenant::text
     ) then
    raise exception 'invoice order read was not tenant bound';
  end if;

  begin
    perform public.request_enterprise_invoice_order(
      v_tenant, v_actor, v_request_id, 126, 'Q-SMOKE'
    );
    raise exception 'changed replay did not conflict';
  exception when unique_violation then
    if sqlerrm <> 'invoice_order_request_conflict' then raise; end if;
  end;

  select t.id into v_other_tenant from public.tenants t
    where t.id <> v_tenant and t.status = 'active'
      and not exists (
        select 1 from public.tenant_members m
        where m.tenant_id = t.id and m.user_id = v_actor
          and m.role in ('owner', 'admin')
      )
    order by t.id limit 1;
  if v_other_tenant is null then raise exception 'invoice smoke needs second tenant fixture'; end if;
  begin
    perform public.request_enterprise_invoice_order(
      v_other_tenant, v_actor, v_request_id, 125, 'Q-SMOKE'
    );
    raise exception 'cross-tenant request was accepted';
  exception when insufficient_privilege then
    if sqlerrm <> 'invoice_order_forbidden' then raise; end if;
  end;
  begin
    perform public.list_enterprise_invoice_orders(v_other_tenant, v_actor);
    raise exception 'cross-tenant read was accepted';
  exception when insufficient_privilege then
    if sqlerrm <> 'invoice_order_forbidden' then raise; end if;
  end;

  select to_jsonb(e) into v_entitlement_after
    from public.entitlements e where e.tenant_id = v_tenant;
  if v_entitlement_before is distinct from v_entitlement_after then
    raise exception 'pending invoice request changed entitlement';
  end if;

  -- Exercise the commercial-retention transition trigger and its separate
  -- deletion receipt. The caller rolls back this fixture and its changes.
  if exists (select 1 from public.tenant_offboarding_runs
             where tenant_id = v_tenant and status <> 'completed') then
    raise exception 'invoice smoke needs tenant without active offboarding';
  end if;
  insert into public.tenant_offboarding_runs(tenant_id, requested_by)
    values (v_tenant, v_actor) returning id into v_offboarding_run;
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation,
     retention_days, eligible_at)
  values (v_offboarding_run, 23, 'entitlements', 'commercial_records',
    'delete_records', 2555, now());
  update public.tenant_offboarding_phase_receipts
    set status = 'completed', completed_at = now()
    where run_id = v_offboarding_run and phase = 'entitlements';
  select count(*) into v_count from public.enterprise_invoice_orders
    where tenant_id = v_tenant and request_id = v_request_id;
  if v_count <> 0 then raise exception 'invoice order survived retention purge'; end if;
  select rows_deleted::integer into v_count
    from public.tenant_offboarding_phase_receipts
    where run_id = v_offboarding_run and phase = 'enterprise_invoice_orders';
  if v_count <> 1 then raise exception 'invoice deletion receipt count mismatch'; end if;
end;
$test$;
