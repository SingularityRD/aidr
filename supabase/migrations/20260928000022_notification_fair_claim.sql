-- Alert dispatcher: claim deliveries fairly across tenants.
--
-- claim_notification_deliveries (20260926000021) leased the globally oldest due
-- rows. Receivers are tenant-controlled HTTPS endpoints and each send may take
-- up to the 10 s delivery timeout, so one tenant whose endpoints stall (or that
-- simply queues a large backlog: 30 alerts per channel per minute, 20
-- channels) occupied every lease of every dispatcher run, and the alerts of
-- every other tenant waited behind that backlog.
--
-- A claim is now filled in two passes:
--   1. fair pass: up to 5 due rows of EVERY tenant with something due, oldest
--      first within the tenant, tenants ordered by their oldest due row;
--   2. top-up: when the fair pass leaves room, the globally oldest remaining
--      due rows, so a single busy tenant still drains at full batch size.
-- The rows come back in that order (fair pass first), so the dispatcher's
-- workers start on every tenant's oldest alerts before any tenant's backlog.
-- Everything else (retirement of undeliverable rows, lease semantics, the row
-- shape, the single-row console test path) is unchanged.

create or replace function public.claim_notification_deliveries(
  p_limit integer,
  p_lease_seconds integer,
  p_delivery_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_claimed jsonb;
  v_per_tenant constant integer := 5;
begin
  if p_limit is null or p_limit not between 1 and 100
     or p_lease_seconds is null or p_lease_seconds not between 30 and 900 then
    raise exception 'invalid_notification_claim' using errcode = '22023';
  end if;

  -- Retire what can never be sent: a suspended/closing tenant, a disabled
  -- channel (tests excepted), or an expired lease with no attempts left.
  with doomed as (
    select d.id,
      case
        when t.status <> 'active' then 'tenant_inactive'
        when not c.enabled and d.event_type <> 'notification.test' then 'channel_disabled'
        else 'lease_expired'
      end as reason
    from public.notification_deliveries d
    join public.notification_channels c on c.id = d.channel_id
    join public.tenants t on t.id = d.tenant_id
    where (p_delivery_id is null or d.id = p_delivery_id)
      and (d.status = 'pending'
        or (d.status = 'delivering' and d.lease_expires_at <= clock_timestamp()))
      and (t.status <> 'active'
        or (not c.enabled and d.event_type <> 'notification.test')
        or d.attempts >= d.max_attempts)
    order by d.id
    limit 500
    for update of d skip locked
  )
  update public.notification_deliveries d
     set status = 'dead', last_error = doomed.reason, lease_token = null, lease_expires_at = null
    from doomed
   where d.id = doomed.id;

  with due as materialized (
    select d.id, d.tenant_id, d.next_attempt_at
      from public.notification_deliveries d
      join public.notification_channels ch on ch.id = d.channel_id
      join public.tenants t on t.id = d.tenant_id
     where (p_delivery_id is null or d.id = p_delivery_id)
       and t.status = 'active'
       and (ch.enabled or d.event_type = 'notification.test')
       and d.attempts < d.max_attempts
       and (
         (d.status = 'pending' and d.next_attempt_at <= clock_timestamp())
         or (d.status = 'delivering' and d.lease_expires_at <= clock_timestamp())
       )
  ),
  ranked as (
    select due.*,
      row_number() over (partition by due.tenant_id order by due.next_attempt_at, due.id) as tenant_rank,
      min(due.next_attempt_at) over (partition by due.tenant_id) as tenant_oldest
    from due
  ),
  candidates as (
    select r.id,
      -- Fair pass first, round-robin by per-tenant rank (every tenant's oldest,
      -- then every tenant's second...), tenants by their oldest due row; then
      -- the top-up in plain due order.
      row_number() over (
        order by (r.tenant_rank > v_per_tenant),
                 least(r.tenant_rank, v_per_tenant + 1),
                 case when r.tenant_rank <= v_per_tenant then r.tenant_oldest end,
                 r.next_attempt_at, r.id
      ) as claim_order
    from ranked r
  ),
  wanted as (
    select c.id, c.claim_order from candidates c order by c.claim_order limit p_limit
  ),
  picked as (
    select d.id, w.claim_order
      from public.notification_deliveries d
      join wanted w on w.id = d.id
     -- Re-check under the row lock: a concurrent dispatcher may have leased it.
     where d.attempts < d.max_attempts
       and (
         (d.status = 'pending' and d.next_attempt_at <= clock_timestamp())
         or (d.status = 'delivering' and d.lease_expires_at <= clock_timestamp())
       )
     for update of d skip locked
  ),
  claimed as (
    update public.notification_deliveries d
       set status = 'delivering',
           attempts = d.attempts + 1,
           lease_token = gen_random_uuid(),
           lease_expires_at = clock_timestamp() + make_interval(secs => p_lease_seconds),
           last_attempt_at = clock_timestamp()
      from picked
     where d.id = picked.id
    returning d.*, picked.claim_order
  )
  select coalesce(jsonb_agg(jsonb_build_object(
      'delivery_id', claimed.id,
      'lease_token', claimed.lease_token,
      'tenant_id', claimed.tenant_id,
      'channel_id', claimed.channel_id,
      'channel_type', c.type,
      'target_ciphertext', c.target_ciphertext,
      'event_type', claimed.event_type,
      'payload', claimed.payload,
      'attempts', claimed.attempts,
      'max_attempts', claimed.max_attempts,
      'created_at', claimed.created_at
    ) order by claimed.claim_order), '[]'::jsonb)
    into v_claimed
    from claimed
    join public.notification_channels c on c.id = claimed.channel_id;
  return v_claimed;
end;
$$;
revoke all on function public.claim_notification_deliveries(integer, integer, uuid) from public, anon, authenticated;
grant execute on function public.claim_notification_deliveries(integer, integer, uuid) to service_role;
