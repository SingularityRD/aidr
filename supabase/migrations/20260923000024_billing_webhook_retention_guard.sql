-- Restore the tenant and legal-hold boundary after billing consistency
-- made settlement request ids permanent financial idempotency keys.
-- Routine retention only removes completed, attributed webhook claims.
create or replace function public.prune_expired_billing_records(
  p_limit integer default 100,
  p_apply boolean default true
)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_tenant uuid;
  v_events_eligible integer := 0;
  v_events_deleted integer := 0;
  v_count integer;
  v_contended integer := 0;
  v_unattributed integer;
begin
  if p_limit is null or p_limit not between 1 and 1000 or p_apply is null then
    raise exception 'invalid_retention_batch' using errcode = '22023';
  end if;
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;

  for v_tenant in
    select distinct e.tenant_id
    from public.billing_webhook_events e
    join public.tenants t on t.id = e.tenant_id and t.status = 'active'
    where e.expires_at <= now() and e.processing_status = 'completed'
      and not exists (
        select 1 from public.tenant_legal_holds h
        where h.tenant_id = e.tenant_id and h.released_at is null
      )
    order by e.tenant_id
  loop
    exit when v_events_eligible >= p_limit;
    if not pg_try_advisory_xact_lock(hashtextextended(v_tenant::text, 2606)) then
      v_contended := v_contended + 1;
      continue;
    end if;
    -- Hold placement uses this lock. Check both tenant state and hold again
    -- with a fresh READ COMMITTED snapshot before selecting rows.
    if not exists (select 1 from public.tenants where id = v_tenant and status = 'active')
      or exists (select 1 from public.tenant_legal_holds
        where tenant_id = v_tenant and released_at is null) then
      continue;
    end if;

    if p_apply then
      delete from public.billing_webhook_events e using (
        select event_id from public.billing_webhook_events
        where tenant_id = v_tenant and expires_at <= now()
          and processing_status = 'completed'
        order by expires_at, event_id limit (p_limit - v_events_eligible)
        for update
      ) expired where e.event_id = expired.event_id and e.tenant_id = v_tenant;
      get diagnostics v_count = row_count;
      v_events_deleted := v_events_deleted + v_count;
    else
      select count(*) into v_count from (
        select 1 from public.billing_webhook_events
        where tenant_id = v_tenant and expires_at <= now()
          and processing_status = 'completed'
        order by expires_at, event_id limit (p_limit - v_events_eligible)
      ) expired;
    end if;
    v_events_eligible := v_events_eligible + v_count;
  end loop;

  select count(*) into v_unattributed from public.billing_webhook_events
    where tenant_id is null and expires_at <= now();
  return jsonb_build_object(
    'applied', p_apply,
    'settlement_requests_eligible', 0,
    'webhook_events_eligible', v_events_eligible,
    'settlement_requests_deleted', 0,
    'webhook_events_deleted', v_events_deleted,
    'contended_tenants', v_contended,
    'unattributed_webhooks_retained', v_unattributed
  );
end;
$$;
revoke all on function public.prune_expired_billing_records(integer, boolean)
  from public, anon, authenticated;
grant execute on function public.prune_expired_billing_records(integer, boolean)
  to service_role;
