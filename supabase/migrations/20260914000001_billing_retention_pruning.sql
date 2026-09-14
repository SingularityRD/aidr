-- ---------------------------------------------------------------------------
-- Bounded lifetime for the billing request-key and webhook-dedup stores.
-- ---------------------------------------------------------------------------
-- `public.billing_settlement_requests` (request-keyed idempotency) and
-- `public.billing_webhook_events` (processed webhook ids) previously had no
-- expiry at all: only tenant offboarding removed them. They now carry an
-- explicit `expires_at` and a service-role-only pruning function the
-- maintenance job runs on a schedule.
--
-- Scope: this function deletes expired idempotency keys and processed webhook
-- ids ONLY. The settlement ledger (`public.billing_settlements`) is the
-- append-only financial evidence and is never selected, updated or deleted
-- here; a settled record can therefore not be reached by pruning. Replaying a
-- pruned request id still cannot write a second row for a stored
-- (tenant_id, settlement_id, sequence), which `billing_settlements` keeps
-- unique.

alter table public.billing_settlement_requests
  add column if not exists expires_at timestamptz not null default now() + interval '90 days';
create index if not exists billing_settlement_requests_expiry_idx
  on public.billing_settlement_requests(expires_at);

alter table public.billing_webhook_events
  add column if not exists expires_at timestamptz not null default now() + interval '30 days';
create index if not exists billing_webhook_events_expiry_idx
  on public.billing_webhook_events(expires_at, event_id);

-- `p_apply = false` counts what a run would remove without deleting anything,
-- so the maintenance job can report a dry run. The returned counts are the
-- observability surface: they land in the maintenance evidence file.
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
  v_requests_eligible integer := 0;
  v_events_eligible integer := 0;
  v_requests_deleted integer := 0;
  v_events_deleted integer := 0;
begin
  if p_limit is null or p_limit < 1 or p_limit > 1000 then
    raise exception 'invalid_retention_batch' using errcode = '22023';
  end if;

  select count(*)::integer into v_requests_eligible
    from (
      select 1 from public.billing_settlement_requests
      where expires_at <= now()
      order by expires_at
      limit p_limit
    ) expired_requests;
  select count(*)::integer into v_events_eligible
    from (
      select 1 from public.billing_webhook_events
      where expires_at <= now()
      order by expires_at
      limit p_limit
    ) expired_events;

  if p_apply then
    delete from public.billing_settlement_requests r
      using (
        select tenant_id, request_id
        from public.billing_settlement_requests
        where expires_at <= now()
        order by expires_at
        limit p_limit
      ) expired
      where r.tenant_id = expired.tenant_id and r.request_id = expired.request_id;
    get diagnostics v_requests_deleted = row_count;

    delete from public.billing_webhook_events e
      using (
        select event_id
        from public.billing_webhook_events
        where expires_at <= now()
        order by expires_at
        limit p_limit
      ) expired
      where e.event_id = expired.event_id;
    get diagnostics v_events_deleted = row_count;
  end if;

  return jsonb_build_object(
    'applied', p_apply,
    'settlement_requests_eligible', v_requests_eligible,
    'webhook_events_eligible', v_events_eligible,
    'settlement_requests_deleted', v_requests_deleted,
    'webhook_events_deleted', v_events_deleted
  );
end;
$$;
revoke all on function public.prune_expired_billing_records(integer, boolean)
  from public, anon, authenticated;
grant execute on function public.prune_expired_billing_records(integer, boolean)
  to service_role;
