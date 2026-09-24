-- Run on a disposable database after migration 36. Browser reads must reflect
-- provider expiry without making the service-only billing source public.
begin;
do $setup$
declare
  v_provider uuid := gen_random_uuid();
  v_invoice uuid := gen_random_uuid();
  v_reader uuid := gen_random_uuid();
  v_order uuid := gen_random_uuid();
  v_trial_start timestamptz := clock_timestamp() - interval '15 days';
begin
  perform set_config('aidr.fixture.provider_tenant', v_provider::text, true);
  perform set_config('aidr.fixture.invoice_tenant', v_invoice::text, true);
  perform set_config('aidr.fixture.reader', v_reader::text, true);
  insert into auth.users(id, email, email_confirmed_at) values
    (v_provider, 'seat-view-provider-' || v_provider || '@test.invalid', null),
    (v_invoice, 'seat-view-invoice-' || v_invoice || '@test.invalid', clock_timestamp()),
    (v_reader, 'seat-view-reader-' || v_reader || '@test.invalid', null);
  insert into public.tenant_members(tenant_id, user_id, role)
  values (v_invoice, v_reader, 'viewer');
  update app.tenant_admission_config
     set mode = 'cloud', configured_at = clock_timestamp() where singleton;
  insert into public.tenant_admissions
    (tenant_id, owner_user_id, kind, seats, starts_at, expires_at, grant_reference)
  values (v_provider, v_provider, 'licensed', 3,
          clock_timestamp() - interval '1 day', clock_timestamp() + interval '30 days', 'seat-view-provider-license'),
         (v_invoice, v_invoice, 'trial', 1,
          v_trial_start, v_trial_start + interval '14 days', null);
  update public.entitlements set included_agents = 1, extra_agents = 2
   where tenant_id = v_provider;
  insert into public.subscriptions
    (user_id, tenant_id, provider, provider_subscription_id, status,
     extra_agents, current_period_end)
  values (v_provider, v_provider, 'stripe', 'sub_seat_view_' || replace(v_provider::text, '-', ''),
          'active', 2, clock_timestamp() - interval '1 hour');

  -- Old zero-seat subscription rows may coexist with a later paid invoice.
  update public.entitlements set included_agents = 1, extra_agents = 3
   where tenant_id = v_invoice;
  insert into public.subscriptions
    (user_id, tenant_id, provider, provider_subscription_id, status,
     extra_agents, current_period_end)
  values (v_invoice, v_invoice, 'stripe', 'sub_seat_view_' || replace(v_invoice::text, '-', ''),
          'canceled', 0, clock_timestamp() - interval '1 hour');
  insert into public.enterprise_invoice_orders
    (id, tenant_id, request_id, created_by, requested_agents)
  values (v_order, v_invoice, 'seat_view_invoice_01', v_invoice, 3);
  insert into public.enterprise_invoice_approvals
    (order_id, tenant_id, status, approver, approver_user_id,
     amount_minor, currency, evidence_sha256, agents_granted)
  values (v_order, v_invoice, 'paid', v_invoice::text, v_invoice,
          1000, 'USD', repeat('b', 64), 3);
end;
$setup$;

select set_config('request.jwt.claim.sub', current_setting('aidr.fixture.provider_tenant'), true);
select set_config('request.jwt.claim.tenant_id', current_setting('aidr.fixture.provider_tenant'), true);
select set_config('request.jwt.claim.role', 'authenticated', true);
set local role authenticated;
do $provider$
declare
  v_provider uuid := current_setting('aidr.fixture.provider_tenant')::uuid;
  v_invoice uuid := current_setting('aidr.fixture.invoice_tenant')::uuid;
  v_extra integer;
  v_allowed integer;
begin
  select extra_agents, allowed_agents into v_extra, v_allowed
    from public.seat_usage where tenant_id = v_provider;
  if not found or v_extra is distinct from 0 or v_allowed is distinct from 1 then
    raise exception 'expired provider term overstated browser seats';
  end if;
  if exists (select 1 from public.seat_usage where tenant_id = v_invoice) then
    raise exception 'foreign tenant seat row leaked';
  end if;
  begin
    perform app.visible_tenant_admission_capacity(v_invoice);
    raise exception 'foreign tenant wrapper call succeeded';
  exception when sqlstate '42501' then null;
  end;
end;
$provider$;
reset role;
do $$
declare v_tenant uuid := current_setting('aidr.fixture.provider_tenant')::uuid;
begin
  if app.visible_tenant_admission_capacity(v_tenant)
     is distinct from public.tenant_admission_capacity(v_tenant) then
    raise exception 'provider view/write capacity diverged';
  end if;
end;
$$;

select set_config('request.jwt.claim.sub', current_setting('aidr.fixture.invoice_tenant'), true);
select set_config('request.jwt.claim.tenant_id', current_setting('aidr.fixture.invoice_tenant'), true);
set local role authenticated;
do $invoice$
declare
  v_invoice uuid := current_setting('aidr.fixture.invoice_tenant')::uuid;
  v_extra integer;
  v_allowed integer;
begin
  select extra_agents, allowed_agents into v_extra, v_allowed
    from public.seat_usage where tenant_id = v_invoice;
  if not found or v_extra is distinct from 0 or v_allowed is distinct from 0 then
    raise exception 'expired trial was admitted by paid invoice alone';
  end if;
end;
$invoice$;
reset role;
do $$
declare v_tenant uuid := current_setting('aidr.fixture.invoice_tenant')::uuid;
begin
  if app.visible_tenant_admission_capacity(v_tenant)
     is distinct from public.tenant_admission_capacity(v_tenant) then
    raise exception 'expired trial view/write capacity diverged';
  end if;
end;
$$;

-- A reviewed licensed admission, not the expired trial or invoice alone,
-- releases the paid capacity. The old zero-seat provider row remains.
update public.tenant_admissions set kind = 'licensed', seats = 4,
  starts_at = clock_timestamp(), expires_at = clock_timestamp() + interval '30 days',
  grant_reference = 'seat-view-invoice-license'
 where tenant_id = current_setting('aidr.fixture.invoice_tenant')::uuid;
set local role authenticated;
do $licensed$
declare
  v_invoice uuid := current_setting('aidr.fixture.invoice_tenant')::uuid;
  v_extra integer;
  v_allowed integer;
begin
  select extra_agents, allowed_agents into v_extra, v_allowed
    from public.seat_usage where tenant_id = v_invoice;
  if not found or v_extra is distinct from 3 or v_allowed is distinct from 4 then
    raise exception 'licensed invoice seats hidden or trial-capped';
  end if;
end;
$licensed$;
reset role;
do $$
declare v_tenant uuid := current_setting('aidr.fixture.invoice_tenant')::uuid;
begin
  if app.visible_tenant_admission_capacity(v_tenant)
     is distinct from public.tenant_admission_capacity(v_tenant) then
    raise exception 'licensed invoice view/write capacity diverged';
  end if;
end;
$$;

-- Browser JWTs do not carry a selected-tenant claim. Live team membership,
-- not a matching claim, authorizes the viewer's invoice tenant only.
select set_config('request.jwt.claim.sub', current_setting('aidr.fixture.reader'), true);
select set_config('request.jwt.claim.tenant_id', '', true);
select set_config('request.jwt.claims', jsonb_build_object(
  'sub', current_setting('aidr.fixture.reader'), 'role', 'authenticated',
  'aal', 'aal2', 'iat', extract(epoch from clock_timestamp())::bigint)::text, true);
set local role authenticated;
do $claimless$
declare
  v_invoice uuid := current_setting('aidr.fixture.invoice_tenant')::uuid;
  v_provider uuid := current_setting('aidr.fixture.provider_tenant')::uuid;
  v_allowed integer;
begin
  select allowed_agents into v_allowed from public.seat_usage where tenant_id = v_invoice;
  if not found or v_allowed is distinct from 4 then
    raise exception 'claimless active member could not read team seats';
  end if;
  if exists (select 1 from public.seat_usage where tenant_id = v_provider) then
    raise exception 'claimless member read foreign tenant seats';
  end if;
end;
$claimless$;
reset role;

insert into public.tenant_identity_policies(tenant_id, require_mfa)
values (current_setting('aidr.fixture.invoice_tenant')::uuid, true);
select set_config('request.jwt.claims', jsonb_build_object(
  'sub', current_setting('aidr.fixture.reader'), 'role', 'authenticated',
  'aal', 'aal1', 'iat', extract(epoch from clock_timestamp())::bigint)::text, true);
set local role authenticated;
do $identity_barrier$
declare v_invoice uuid := current_setting('aidr.fixture.invoice_tenant')::uuid;
begin
  if exists (select 1 from public.seat_usage where tenant_id = v_invoice) then
    raise exception 'MFA identity barrier bypassed by seat view';
  end if;
end;
$identity_barrier$;
reset role;

update public.tenant_admissions set revoked_at = clock_timestamp()
 where tenant_id = current_setting('aidr.fixture.provider_tenant')::uuid;
select set_config('request.jwt.claim.sub', current_setting('aidr.fixture.provider_tenant'), true);
select set_config('request.jwt.claim.tenant_id', current_setting('aidr.fixture.provider_tenant'), true);
set local role authenticated;
do $revoked$
declare
  v_provider uuid := current_setting('aidr.fixture.provider_tenant')::uuid;
  v_allowed integer;
begin
  select allowed_agents into v_allowed from public.seat_usage where tenant_id = v_provider;
  if not found or v_allowed is distinct from 0 then
    raise exception 'revoked license still displayed capacity';
  end if;
end;
$revoked$;
reset role;
do $$
declare v_tenant uuid := current_setting('aidr.fixture.provider_tenant')::uuid;
begin
  if app.visible_tenant_admission_capacity(v_tenant)
     is distinct from public.tenant_admission_capacity(v_tenant) then
    raise exception 'revoked license view/write capacity diverged';
  end if;
end;
$$;

update public.tenants set status = 'suspended'
 where id = current_setting('aidr.fixture.provider_tenant')::uuid;
select set_config('request.jwt.claim.sub', current_setting('aidr.fixture.provider_tenant'), true);
select set_config('request.jwt.claim.tenant_id', current_setting('aidr.fixture.provider_tenant'), true);
set local role authenticated;
do $suspended$
declare v_provider uuid := current_setting('aidr.fixture.provider_tenant')::uuid;
begin
  if exists (select 1 from public.seat_usage where tenant_id = v_provider) then
    raise exception 'suspended tenant seat row visible';
  end if;
end;
$suspended$;
reset role;

set local role anon;
do $anon$
begin
  begin
    perform 1 from public.seat_usage limit 1;
    raise exception 'anon could read seat usage';
  exception when sqlstate '42501' then null;
  end;
end;
$anon$;
reset role;

-- Supabase/PostgREST GET runs in READ ONLY mode. The display helper must not
-- call the write-path capacity RPC, which takes persistent row locks.
select set_config('request.jwt.claim.sub', current_setting('aidr.fixture.invoice_tenant'), true);
select set_config('request.jwt.claim.tenant_id', current_setting('aidr.fixture.invoice_tenant'), true);
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claims', jsonb_build_object(
  'sub', current_setting('aidr.fixture.invoice_tenant'), 'role', 'authenticated',
  'aal', 'aal2', 'iat', extract(epoch from clock_timestamp())::bigint)::text, true);
set local transaction_read_only = on;
set local role authenticated;
do $read_only$
declare
  v_invoice uuid := current_setting('aidr.fixture.invoice_tenant')::uuid;
  v_allowed integer;
begin
  select allowed_agents into v_allowed from public.seat_usage where tenant_id = v_invoice;
  if not found or v_allowed is distinct from 4 then
    raise exception 'read-only browser query lost licensed capacity';
  end if;
end;
$read_only$;
reset role;
do $$ begin raise notice 'SEAT_USAGE_EFFECTIVE_VIEW_OK'; end; $$;
rollback;
