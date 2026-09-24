-- Run against a disposable database after GA admission migration 34, then roll back.
-- No provider callback is delivered after the recorded period ends: every read
-- must still use the effective allocation rather than stale entitlements.
begin;
do $checks$
declare
  v_user uuid := gen_random_uuid();
  v_invoice_user uuid := gen_random_uuid();
  v_order uuid := gen_random_uuid();
  v_subscription_id text;
  v_token_hash text;
  v_first text;
  v_excess text;
  v_excess_id uuid;
  v_last_seen timestamptz;
  v_effective record;
  v_result record;
begin
  v_subscription_id := 'sub_test_' || replace(v_user::text, '-', '');
  v_token_hash := encode(digest(v_user::text || ':expired-token', 'sha256'), 'hex');
  insert into auth.users(id, email) values
    (v_user, 'provider-expiry-' || v_user || '@test.invalid'),
    (v_invoice_user, 'invoice-seats-' || v_invoice_user || '@test.invalid');
  insert into public.pilot_applications(user_id, tenant_id, status) values
    (v_user, v_user, 'approved'),
    (v_invoice_user, v_invoice_user, 'approved');

  -- GA defaults to unconfigured/denied. A provider record or old pilot approval
  -- must not silently turn it on; the rest of this fixture uses explicit pilot.
  if (select mode from app.tenant_admission_config where singleton) <> 'unconfigured' then
    raise exception 'fixture requires default unconfigured admission mode';
  end if;
  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-unconfigured', null, null, v_user);
  if not v_result.seat_exceeded or v_result.allowed_agents <> 0 then
    raise exception 'unconfigured deployment admitted an agent';
  end if;
  update app.tenant_admission_config
     set mode = 'pilot', configured_at = clock_timestamp() where singleton;

  -- A provider row takes precedence over a stale materialized entitlement.
  update public.entitlements set included_agents = 1, extra_agents = 2
   where tenant_id = v_user;
  insert into public.subscriptions
    (user_id, tenant_id, provider, provider_subscription_id, status, extra_agents)
  values (v_user, v_user, 'stripe', v_subscription_id, 'active', 2);
  select * into v_effective from public.effective_tenant_seats(v_user);
  if v_effective.extra_agents is distinct from 0 or v_effective.provider_valid_until is not null then
    raise exception 'missing provider period granted seats';
  end if;
  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-first', null, null, v_user);
  if v_result.seat_exceeded or v_result.allowed_agents <> 1 then
    raise exception 'free seat rejected while provider period is missing';
  end if;
  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-second', null, null, v_user);
  if not v_result.seat_exceeded or v_result.allowed_agents <> 1 then
    raise exception 'missing provider period admitted paid agent';
  end if;

  update public.subscriptions set current_period_end = clock_timestamp() - interval '1 hour'
   where provider_subscription_id = v_subscription_id;
  select * into v_effective from public.effective_tenant_seats(v_user);
  if v_effective.extra_agents is distinct from 0 or v_effective.provider_valid_until is not null then
    raise exception 'expired provider period granted seats';
  end if;

  update public.subscriptions set current_period_end = clock_timestamp() + interval '1 day'
   where provider_subscription_id = v_subscription_id;
  select * into v_effective from public.effective_tenant_seats(v_user);
  if v_effective.extra_agents is distinct from 2 or v_effective.provider_valid_until is null
     or v_effective.provider_valid_until <= clock_timestamp() then
    raise exception 'current provider period failed to grant two seats';
  end if;
  update public.subscriptions set status = 'canceled'
   where provider_subscription_id = v_subscription_id;
  select * into v_effective from public.effective_tenant_seats(v_user);
  if v_effective.extra_agents is distinct from 0 then
    raise exception 'canceled provider subscription granted seats';
  end if;
  update public.subscriptions set status = 'active'
   where provider_subscription_id = v_subscription_id;
  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-second', null, null, v_user);
  if v_result.seat_exceeded or v_result.allowed_agents <> 3 then
    raise exception 'current provider period rejected second agent';
  end if;
  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-third', null, null, v_user);
  if v_result.seat_exceeded or v_result.allowed_agents <> 3 then
    raise exception 'current provider period rejected third agent';
  end if;

  -- Equal timestamps exercise the existing deterministic UUID rank policy.
  update public.agents set first_seen = '2020-01-01 00:00:00+00' where tenant_id = v_user;
  select iid into v_first from public.agents where tenant_id = v_user
   order by first_seen, id limit 1;
  select id, iid, last_seen into v_excess_id, v_excess, v_last_seen
    from public.agents where tenant_id = v_user
   order by first_seen desc, id desc limit 1;
  update public.subscriptions set current_period_end = clock_timestamp() - interval '1 hour'
   where provider_subscription_id = v_subscription_id;
  select * into v_result from public.register_agent_for_ingest(v_user, v_first, null, null, v_user);
  if v_result.seat_exceeded or v_result.allowed_agents <> 1 then
    raise exception 'highest-ranked agent rejected after provider expiry';
  end if;
  select * into v_result from public.register_agent_for_ingest(v_user, v_excess, 'must-not-touch', null, v_user);
  if not v_result.seat_exceeded or v_result.agent_id is not null or v_result.allowed_agents <> 1
     or v_result.current_agents <> 3 then
    raise exception 'over-quota existing agent admitted after provider expiry';
  end if;
  if exists (select 1 from public.agents where id = v_excess_id
             and (last_seen is distinct from v_last_seen or agent_runtime is not null)) then
    raise exception 'rejected agent state changed after provider expiry';
  end if;
  select * into v_result from public.register_agent_for_ingest(v_user, 'iid-fourth', null, null, v_user);
  if not v_result.seat_exceeded or v_result.agent_id is not null or v_result.allowed_agents <> 1 then
    raise exception 'new agent admitted after provider expiry';
  end if;

  -- With no included seat, an expired provider term cannot authorize a new
  -- enrollment token through the admission trigger.
  update public.entitlements set included_agents = 0 where tenant_id = v_user;
  begin
    insert into public.enrollment_tokens(user_id, tenant_id, token_hash, expires_at)
    values (v_user, v_user, v_token_hash, clock_timestamp() + interval '1 hour');
    raise exception 'expired provider term admitted an enrollment token';
  exception when sqlstate '42501' then null;
  end;
  if exists (select 1 from public.enrollment_tokens where token_hash = v_token_hash) then
    raise exception 'rejected enrollment token persisted';
  end if;

  -- Finance-approved invoice seats are independent of provider period dates.
  update public.entitlements set extra_agents = 2 where tenant_id = v_invoice_user;
  select * into v_effective from public.effective_tenant_seats(v_invoice_user);
  if v_effective.extra_agents is distinct from 2 then
    raise exception 'manual legacy allocation was not preserved';
  end if;
  insert into public.enterprise_invoice_orders
    (id, tenant_id, request_id, created_by, requested_agents)
  values (v_order, v_invoice_user, 'test_invoice_term_01', v_invoice_user, 3);
  insert into public.enterprise_invoice_approvals
    (order_id, tenant_id, status, approver, approver_user_id,
     amount_minor, currency, evidence_sha256, agents_granted)
  values (v_order, v_invoice_user, 'paid', v_invoice_user::text, v_invoice_user,
          1000, 'USD', repeat('a', 64), 3);
  select * into v_effective from public.effective_tenant_seats(v_invoice_user);
  if v_effective.extra_agents is distinct from 3 or v_effective.provider_valid_until is not null then
    raise exception 'finance-approved invoice seats were affected by provider expiry';
  end if;
  select * into v_result from public.register_agent_for_ingest(v_invoice_user, 'invoice-iid', null, null, v_invoice_user);
  if v_result.seat_exceeded or v_result.allowed_agents <> 4 then
    raise exception 'finance-approved invoice seats did not reach registration';
  end if;
  raise notice 'PROVIDER_TERM_SEAT_EXPIRY_OK';
end;
$checks$;
rollback;
