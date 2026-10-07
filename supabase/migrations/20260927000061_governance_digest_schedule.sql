-- Scheduled governance summary (supabase/functions/governance-digest).
--
-- The deployment maintenance run (scripts/deployment-maintenance.mjs, hourly
-- systemd timer deploy/maintenance/aidr-export-retention.timer) calls the
-- governance-digest Edge Function with the service credential. The function:
--   1. claims due schedules (claim_due_governance_digests): a 15-minute lease
--      per tenant, FOR UPDATE SKIP LOCKED, active tenants only;
--   2. reads the counts-only summary (governance_digest_summary);
--   3. sends one e-mail per recipient through the deployment mailer;
--   4. records the outcome (complete_governance_digest), which advances the
--      schedule, or keeps it for a retry after a failed send (at most three
--      attempts per period).
-- Owners/admins can also send a test summary to themselves and the other
-- recipients (governance_digest_test_context + record_governance_digest_test).
--
-- Every function here is service-role only and re-checks the tenant state.
-- Recipient addresses are returned to the Edge Function only; delivery receipts
-- store counts and status, never addresses or content.

-- Recipients: active owners (and admins) with an address, at most 50.
create or replace function app.governance_digest_recipient_emails(p_tenant_id uuid, p_recipients text)
returns jsonb
language sql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
  select coalesce(jsonb_agg(email order by email), '[]'::jsonb)
  from (
    select distinct lower(u.email::text) as email
    from public.tenant_members m
    join auth.users u on u.id = m.user_id
    where m.tenant_id = p_tenant_id
      and (m.expires_at is null or m.expires_at > now())
      and (m.role = 'owner' or (p_recipients = 'owners_admins' and m.role = 'admin'))
      and u.email is not null
      and char_length(u.email::text) between 3 and 254
      and u.email::text ~ '^[^[:space:]@<>"]+@[^[:space:]@<>"]+\.[^[:space:]@<>"]+$'
    order by 1
    limit 50
  ) recipients
$$;
revoke all on function app.governance_digest_recipient_emails(uuid, text) from public, anon, authenticated;

-- Period covered by the summary delivered at p_due: the previous whole week
-- (Monday 00:00 UTC to Monday 00:00 UTC) or the previous calendar month.
create or replace function app.governance_digest_period(p_cadence text, p_due timestamptz)
returns table (period_from timestamptz, period_to timestamptz)
language sql
stable
set search_path = pg_catalog, pg_temp
as $$
  select
    case p_cadence
      when 'weekly' then (date_trunc('day', p_due at time zone 'utc') - interval '7 days') at time zone 'utc'
      else (date_trunc('month', p_due at time zone 'utc') - interval '1 month') at time zone 'utc'
    end,
    case p_cadence
      when 'weekly' then date_trunc('day', p_due at time zone 'utc') at time zone 'utc'
      else date_trunc('month', p_due at time zone 'utc') at time zone 'utc'
    end
$$;
revoke all on function app.governance_digest_period(text, timestamptz) from public, anon, authenticated;

create or replace function public.claim_due_governance_digests(p_limit integer, p_apply boolean)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_due_count bigint;
  v_claims jsonb := '[]'::jsonb;
  v_row record;
  v_claim uuid;
  v_due timestamptz;
  v_period record;
begin
  if p_limit is null or p_limit not between 1 and 200 or p_apply is null then
    raise exception 'invalid_governance_digest_claim' using errcode = '22023';
  end if;

  select count(*) into v_due_count
  from public.tenant_governance_settings s
  join public.tenants t on t.id = s.tenant_id
  where s.digest_enabled and s.digest_next_at <= now() and t.status = 'active'
    and (s.digest_claim_expires_at is null or s.digest_claim_expires_at < now());
  if not p_apply then
    return jsonb_build_object('applied', false, 'due', v_due_count, 'claims', '[]'::jsonb);
  end if;

  for v_row in
    select s.tenant_id, s.digest_cadence, s.digest_recipients, s.digest_next_at, left(t.name, 200) as tenant_name
    from public.tenant_governance_settings s
    join public.tenants t on t.id = s.tenant_id
    where s.digest_enabled and s.digest_next_at <= now() and t.status = 'active'
      and (s.digest_claim_expires_at is null or s.digest_claim_expires_at < now())
    order by s.digest_next_at, s.tenant_id
    limit p_limit
    for update of s skip locked
  loop
    v_claim := gen_random_uuid();
    -- After an outage, summarise the most recent completed period only: skip
    -- the missed deliveries instead of sending a backlog of stale summaries.
    v_due := v_row.digest_next_at;
    while app.governance_digest_next_at(v_row.digest_cadence, v_due) <= now() loop
      v_due := app.governance_digest_next_at(v_row.digest_cadence, v_due);
    end loop;
    update public.tenant_governance_settings
       set digest_claim_id = v_claim, digest_claim_expires_at = now() + interval '15 minutes',
           digest_next_at = v_due,
           digest_attempts = case when v_due = v_row.digest_next_at then digest_attempts else 0 end
     where tenant_id = v_row.tenant_id;
    select * into v_period from app.governance_digest_period(v_row.digest_cadence, v_due);
    v_claims := v_claims || jsonb_build_array(jsonb_build_object(
      'tenant_id', v_row.tenant_id,
      'tenant_name', v_row.tenant_name,
      'claim_id', v_claim,
      'cadence', v_row.digest_cadence,
      'period_from', v_period.period_from,
      'period_to', v_period.period_to,
      'recipients', app.governance_digest_recipient_emails(v_row.tenant_id, v_row.digest_recipients)
    ));
  end loop;
  return jsonb_build_object('applied', true, 'due', v_due_count, 'claims', v_claims);
end;
$$;
revoke all on function public.claim_due_governance_digests(integer, boolean) from public, anon, authenticated;
grant execute on function public.claim_due_governance_digests(integer, boolean) to service_role;

create or replace function public.governance_digest_summary(p_tenant_id uuid, p_from timestamptz, p_to timestamptz)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
begin
  if not exists (select 1 from public.tenants t where t.id = p_tenant_id and t.status = 'active') then
    raise exception 'governance_tenant_not_active' using errcode = '42501';
  end if;
  -- No identities: the summary leaves the control plane by e-mail.
  return app.governance_scorecard_data(p_tenant_id, p_from, p_to, false);
end;
$$;
revoke all on function public.governance_digest_summary(uuid, timestamptz, timestamptz) from public, anon, authenticated;
grant execute on function public.governance_digest_summary(uuid, timestamptz, timestamptz) to service_role;

create or replace function public.complete_governance_digest(
  p_tenant_id uuid,
  p_claim_id uuid,
  p_status text,
  p_recipients integer,
  p_delivered integer
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_settings public.tenant_governance_settings;
  v_period record;
  v_next timestamptz;
  v_attempts integer;
  v_retry boolean;
begin
  if p_tenant_id is null or p_claim_id is null
     or p_status is null or p_status not in ('sent', 'partial', 'failed', 'no_transport', 'no_recipients')
     or p_recipients is null or p_recipients not between 0 and 1000
     or p_delivered is null or p_delivered not between 0 and p_recipients then
    raise exception 'invalid_governance_digest_result' using errcode = '22023';
  end if;
  select * into v_settings
  from public.tenant_governance_settings s
  where s.tenant_id = p_tenant_id
  for update;
  if not found or v_settings.digest_claim_id is distinct from p_claim_id then
    raise exception 'governance_digest_claim_lost' using errcode = '40001';
  end if;

  select * into v_period from app.governance_digest_period(v_settings.digest_cadence, v_settings.digest_next_at);
  insert into public.governance_digest_deliveries (
    tenant_id, trigger, cadence, period_from, period_to, status, recipients, delivered
  ) values (
    p_tenant_id, 'schedule', v_settings.digest_cadence, v_period.period_from, v_period.period_to,
    p_status, p_recipients, p_delivered
  );

  v_attempts := v_settings.digest_attempts + 1;
  -- A failed send is retried by a later maintenance run (after a 30 minute
  -- back-off) until the third attempt; every other outcome is final.
  v_retry := p_status = 'failed' and v_attempts < 3;
  if v_retry then
    update public.tenant_governance_settings
       set digest_attempts = v_attempts,
           digest_last_status = p_status,
           digest_claim_id = gen_random_uuid(),
           digest_claim_expires_at = now() + interval '30 minutes'
     where tenant_id = p_tenant_id;
    v_next := v_settings.digest_next_at;
  else
    v_next := app.governance_digest_next_at(v_settings.digest_cadence, greatest(now(), v_settings.digest_next_at));
    update public.tenant_governance_settings
       set digest_attempts = 0,
           digest_last_at = now(),
           digest_last_status = p_status,
           digest_next_at = v_next,
           digest_claim_id = null,
           digest_claim_expires_at = null
     where tenant_id = p_tenant_id;
  end if;
  return jsonb_build_object('retry', v_retry, 'next_at', v_next, 'attempts', v_attempts);
end;
$$;
revoke all on function public.complete_governance_digest(uuid, uuid, text, integer, integer) from public, anon, authenticated;
grant execute on function public.complete_governance_digest(uuid, uuid, text, integer, integer) to service_role;

-- Test send context: the caller must be an active owner/admin of an active
-- tenant (checked under share locks). The period is the last cadence window
-- ending now.
create or replace function public.governance_digest_test_context(p_tenant_id uuid, p_actor_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_name text;
  v_cadence text;
  v_recipients text;
begin
  if p_tenant_id is null or p_actor_user_id is null then
    raise exception 'invalid_governance_digest_test' using errcode = '22023';
  end if;
  select left(t.name, 200) into v_name
  from public.tenant_members m
  join public.tenants t on t.id = m.tenant_id
  where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
    and m.role in ('owner', 'admin')
    and (m.expires_at is null or m.expires_at > now())
    and t.status = 'active'
  for share of m, t;
  if not found then
    raise exception 'governance_forbidden' using errcode = '42501';
  end if;
  select s.digest_cadence, s.digest_recipients into v_cadence, v_recipients
  from public.tenant_governance_settings s where s.tenant_id = p_tenant_id;
  v_cadence := coalesce(v_cadence, 'weekly');
  v_recipients := coalesce(v_recipients, 'owners_admins');
  return jsonb_build_object(
    'tenant_name', v_name,
    'cadence', v_cadence,
    'period_from', case v_cadence when 'weekly' then now() - interval '7 days' else now() - interval '30 days' end,
    'period_to', now(),
    'recipients', app.governance_digest_recipient_emails(p_tenant_id, v_recipients)
  );
end;
$$;
revoke all on function public.governance_digest_test_context(uuid, uuid) from public, anon, authenticated;
grant execute on function public.governance_digest_test_context(uuid, uuid) to service_role;

create or replace function public.record_governance_digest_test(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_cadence text,
  p_period_from timestamptz,
  p_period_to timestamptz,
  p_status text,
  p_recipients integer,
  p_delivered integer
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
begin
  if p_tenant_id is null or p_actor_user_id is null
     or p_cadence is null or p_cadence not in ('weekly', 'monthly')
     or p_period_from is null or p_period_to is null or p_period_to <= p_period_from
     or p_status is null or p_status not in ('sent', 'partial', 'failed', 'no_transport', 'no_recipients')
     or p_recipients is null or p_recipients not between 0 and 1000
     or p_delivered is null or p_delivered not between 0 and p_recipients then
    raise exception 'invalid_governance_digest_test' using errcode = '22023';
  end if;
  perform 1
  from public.tenant_members m
  join public.tenants t on t.id = m.tenant_id
  where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
    and m.role in ('owner', 'admin')
    and (m.expires_at is null or m.expires_at > now())
    and t.status = 'active'
  for share of m, t;
  if not found then
    raise exception 'governance_forbidden' using errcode = '42501';
  end if;
  insert into public.governance_digest_deliveries (
    tenant_id, trigger, cadence, period_from, period_to, status, recipients, delivered, requested_by
  ) values (
    p_tenant_id, 'test', p_cadence, p_period_from, p_period_to, p_status, p_recipients, p_delivered, p_actor_user_id
  );
  insert into public.admin_audit_logs (actor_user_id, tenant_id, action, detail)
  values (p_actor_user_id, p_tenant_id, 'governance_digest.test_sent', jsonb_build_object(
    'status', p_status, 'recipients', p_recipients, 'delivered', p_delivered
  ));
end;
$$;
revoke all on function public.record_governance_digest_test(uuid, uuid, text, timestamptz, timestamptz, text, integer, integer)
  from public, anon, authenticated;
grant execute on function public.record_governance_digest_test(uuid, uuid, text, timestamptz, timestamptz, text, integer, integer)
  to service_role;

-- ── Offboarding ────────────────────────────────────────────────────────────
-- Request time: the summary stops immediately. Deletion rides on the existing
-- `events` (telemetry) phase, under the same tenant lock and legal-hold check,
-- and is counted in that phase receipt.

create or replace function app.disable_governance_digest_on_offboarding()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
begin
  update public.tenant_governance_settings
     set digest_enabled = false, digest_next_at = null,
         digest_claim_id = null, digest_claim_expires_at = null
   where tenant_id = new.tenant_id and digest_enabled;
  return new;
end;
$$;
revoke all on function app.disable_governance_digest_on_offboarding() from public, anon, authenticated, service_role;

drop trigger if exists tenant_offboarding_disable_governance_digest on public.tenant_offboarding_runs;
create trigger tenant_offboarding_disable_governance_digest
  after insert on public.tenant_offboarding_runs
  for each row execute function app.disable_governance_digest_on_offboarding();

update public.tenant_governance_settings s
   set digest_enabled = false, digest_next_at = null, digest_claim_id = null, digest_claim_expires_at = null
 where s.digest_enabled
   and exists (select 1 from public.tenant_offboarding_runs r where r.tenant_id = s.tenant_id);

create or replace function app.purge_governance_at_offboarding_phase()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_tenant uuid;
  v_status text;
  v_rows bigint;
  v_more bigint;
begin
  if new.phase <> 'events' or new.status <> 'completed' or old.status = 'completed' then
    return new;
  end if;
  select r.tenant_id, r.status into v_tenant, v_status
    from public.tenant_offboarding_runs r where r.id = new.run_id;
  if v_tenant is null or v_status <> 'running' or new.eligible_at > now() then
    raise exception 'governance_offboarding_phase_invalid' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  if exists (
    select 1 from public.tenant_legal_holds h
     where h.tenant_id = v_tenant and h.released_at is null
  ) then
    raise exception 'governance_offboarding_legal_hold' using errcode = '42501';
  end if;
  delete from public.governance_digest_deliveries where tenant_id = v_tenant;
  get diagnostics v_rows = row_count;
  delete from public.tenant_governance_settings where tenant_id = v_tenant;
  get diagnostics v_more = row_count;
  v_rows := v_rows + v_more;
  if v_rows > 0 then
    update public.tenant_offboarding_phase_receipts
       set rows_deleted = rows_deleted + v_rows
     where run_id = new.run_id and phase = new.phase and status = 'completed';
  end if;
  return new;
end;
$$;
revoke all on function app.purge_governance_at_offboarding_phase() from public, anon, authenticated, service_role;

drop trigger if exists tenant_offboarding_purge_governance on public.tenant_offboarding_phase_receipts;
create trigger tenant_offboarding_purge_governance
  after update of status on public.tenant_offboarding_phase_receipts
  for each row execute function app.purge_governance_at_offboarding_phase();
