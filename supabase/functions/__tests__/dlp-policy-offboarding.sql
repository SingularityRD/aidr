-- Continues the disposable storage fixture; executes the REAL shipped retention
-- dispatcher and fleet/cache extensions with minimal unrelated table fixtures.
\set ON_ERROR_STOP on
create schema app;
alter table public.tenants add column retention_days integer not null default 0;
alter table public.tenants add column name text default 'Fixture';
alter table public.tenants add column created_by uuid;
alter table public.tenants add column closed_at timestamptz;
create function public.touch_updated_at() returns trigger language plpgsql as $$ begin new.updated_at=now(); return new; end $$;
create table public.teams(tenant_id uuid, name text, github_org text, gitlab_group text);
create table public.agents(tenant_id uuid, id uuid, unique(tenant_id,id));
create table public.entitlement_snapshots(tenant_id uuid, agent_id uuid);
create table public.api_keys(tenant_id uuid, revoked boolean);
create table public.scim_tokens(tenant_id uuid, revoked_at timestamptz);
create table public.delegated_credential_grants(tenant_id uuid, revoked_at timestamptz);
create table public.delegated_credential_receipts(tenant_id uuid, revoked_at timestamptz, state text, delegation_depth integer);
create table public.audit_export_objects(tenant_id uuid, path text);
do $$ declare t text; begin
  foreach t in array array['agent_policy_receipts','agent_policy_assignments','events','enrollment_tokens','device_sessions',
    'identity_recovery_codes','identity_password_recovery_grants','url_reputation','file_reputation','tenant_runtime_policies',
    'runtime_policy_revisions','team_policies','pack_versions','tenant_identity_policies','subscriptions','billing_customers',
    'billing_webhook_events','entitlements','revocations','audit_logs','team_invitations','pilot_applications',
    'scim_group_memberships','scim_managed_memberships','scim_group_role_mappings','scim_groups','scim_users','team_members',
    'waitlist_signups','rate_limits','fleet_response_commands'] loop
    execute format('create table public.%I(tenant_id uuid)',t);
  end loop;
end $$;
\ir ../../migrations/20260912140000_tenant_offboarding_retention.sql
\ir ../../migrations/20260912140002_fleet_response_offboarding.sql
\ir ../../migrations/20260913000006_tenant_cache_invalidation_offboarding.sql

-- A real service role can publish; browser roles cannot call or bypass the RPC.
set role service_role;
select public.publish_dlp_policy('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111',2,public.test_dlp_policy(3));
reset role;
set role authenticated;
do $$ begin
  begin perform public.publish_dlp_policy('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111',3,public.test_dlp_policy(4));
    raise exception 'authenticated called RPC'; exception when insufficient_privilege then null; end;
  begin perform * from public.tenant_dlp_policies; raise exception 'authenticated read table';
    exception when insufficient_privilege then null; end;
end $$;
reset role;
set role anon;
do $$ begin
  begin perform public.publish_dlp_policy('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111',3,public.test_dlp_policy(4));
    raise exception 'anon called RPC'; exception when insufficient_privilege then null; end;
end $$;
reset role;

-- Neighbor data survives this tenant's entire offboarding run. Its already
-- in-flight run exercises append-only phase backfill without resetting receipts.
insert into public.tenant_members values('33333333-3333-4333-8333-333333333333','11111111-1111-4111-8111-111111111111','owner',null);
select public.publish_dlp_policy('33333333-3333-4333-8333-333333333333','11111111-1111-4111-8111-111111111111',0,
  replace(public.test_dlp_policy(1)::text,'22222222-2222-4222-8222-222222222222','33333333-3333-4333-8333-333333333333')::jsonb);
select public.request_tenant_offboarding('33333333-3333-4333-8333-333333333333','11111111-1111-4111-8111-111111111111');
\ir ../../migrations/20260916000006_dlp_policy_offboarding.sql

create temp table dlp_offboard_fixture(run_id uuid);
do $$
declare r jsonb; run uuid; neighbor uuid; i integer;
begin
  select id into neighbor from public.tenant_offboarding_runs where tenant_id='33333333-3333-4333-8333-333333333333';
  if (select count(*) from public.tenant_offboarding_phase_receipts where run_id=neighbor and phase in ('dlp_policy_revisions','tenant_dlp_policies')) <> 2 then raise exception 'inflight run not backfilled'; end if;
  if (select count(*) from public.tenant_data_retention_policies where tenant_id='22222222-2222-4222-8222-222222222222') <> 10 then raise exception 'data classes changed'; end if;
  update public.tenant_data_retention_policies set retention_days=5 where tenant_id='22222222-2222-4222-8222-222222222222' and data_class='policy_configuration';
  r := public.request_tenant_offboarding('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111');
  run := (r->>'run_id')::uuid;
  insert into dlp_offboard_fixture values(run);
  if r->>'backup_scope' <> 'excluded_external_retention' then raise exception 'backup exclusion changed'; end if;
  if (select count(*) from public.tenant_offboarding_phase_receipts where run_id=run and phase in ('dlp_policy_revisions','tenant_dlp_policies') and data_class='policy_configuration' and retention_days=5 and eligible_at>now()) <> 2 then raise exception 'DLP retention phases incorrect'; end if;
  if (public.request_tenant_offboarding('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111')->>'run_id')::uuid <> run then raise exception 'request not idempotent'; end if;
  begin update public.dlp_policy_revisions set policy=policy where tenant_id='22222222-2222-4222-8222-222222222222'; raise exception 'history mutable';
    exception when insufficient_privilege then null; end;
  begin delete from public.dlp_policy_revisions where tenant_id='22222222-2222-4222-8222-222222222222'; raise exception 'unscoped history delete';
    exception when insufficient_privilege then null; end;
  begin update public.tenants set status='closed' where id='22222222-2222-4222-8222-222222222222'; raise exception 'closed with residue';
    exception when check_violation then if sqlerrm <> 'dlp_policy_offboarding_residue' then raise; end if; end;
  begin update public.tenant_offboarding_runs set status='completed',completed_at=now() where id=run; raise exception 'completed with residue';
    exception when check_violation then if sqlerrm <> 'dlp_policy_offboarding_residue' then raise; end if; end;
  -- A real hold stops dispatch and even a spoofed running-phase deletion context.
  insert into public.tenant_legal_holds(tenant_id,hold_reference,reason,placed_by)
    values('22222222-2222-4222-8222-222222222222','DLP-test','Preserve policy evidence','11111111-1111-4111-8111-111111111111');
  r := public.run_tenant_offboarding_batch(run,1);
  if r->>'status' <> 'blocked_legal_hold' then raise exception 'hold bypassed'; end if;
  perform set_config('app.aidr_dlp_offboarding_run_id',run::text,true);
  begin delete from public.dlp_policy_revisions where tenant_id='22222222-2222-4222-8222-222222222222'; raise exception 'hold deletion bypassed';
    exception when insufficient_privilege then null; end;
  update public.tenant_legal_holds set released_at=now(), released_by='11111111-1111-4111-8111-111111111111',release_reason='Test release'
    where tenant_id='22222222-2222-4222-8222-222222222222';
  for i in 1..100 loop
    r := public.run_tenant_offboarding_batch(run,1);
    if r->>'action'='invalidate_cache' then perform public.ack_tenant_offboarding_cache(run,array['fixture-cache'],1); end if;
    exit when r->>'status'='waiting_retention';
  end loop;
  if r->>'status' <> 'waiting_retention' then raise exception 'retention wait missing'; end if;
  if (select count(*) from public.dlp_policy_revisions where tenant_id='22222222-2222-4222-8222-222222222222') <> 3 then raise exception 'retention removed history early'; end if;
  -- Advance this disposable fixture's eligibility, not the policy or system clock.
  update public.tenant_offboarding_phase_receipts set eligible_at=now()-interval '1 second' where run_id=run;
  for i in 1..100 loop
    r := public.run_tenant_offboarding_batch(run,1);
    if r->>'action'='invalidate_cache' then perform public.ack_tenant_offboarding_cache(run,array['fixture-cache'],1); end if;
    exit when r->>'phase'='dlp_policy_revisions';
  end loop;
  if (r->>'rows_deleted')::integer <> 1 or (r->>'phase_complete')::boolean then raise exception 'history batch unbounded'; end if;
  if not exists(select 1 from public.tenant_dlp_policies where tenant_id='22222222-2222-4222-8222-222222222222') then raise exception 'current deleted before history'; end if;
  -- Tenant binding still applies when the operator holds a valid running phase.
  begin delete from public.dlp_policy_revisions where tenant_id='33333333-3333-4333-8333-333333333333'; raise exception 'foreign history deleted';
    exception when insufficient_privilege then null; end;
  for i in 1..100 loop
    r := public.run_tenant_offboarding_batch(run,1);
    exit when r->>'status'='completed';
  end loop;
  if r->>'status' <> 'completed' then raise exception 'DLP offboarding failed to finish'; end if;
  if exists(select 1 from public.tenant_dlp_policies where tenant_id='22222222-2222-4222-8222-222222222222')
    or exists(select 1 from public.dlp_policy_revisions where tenant_id='22222222-2222-4222-8222-222222222222') then raise exception 'DLP residue'; end if;
  if (select rows_deleted from public.tenant_offboarding_phase_receipts where run_id=run and phase='dlp_policy_revisions') <> 3
    or (select attempts from public.tenant_offboarding_phase_receipts where run_id=run and phase='dlp_policy_revisions') <> 3
    or (select rows_deleted from public.tenant_offboarding_phase_receipts where run_id=run and phase='tenant_dlp_policies') <> 1 then raise exception 'bad DLP deletion receipts'; end if;
  if (select status from public.tenants where id='22222222-2222-4222-8222-222222222222') <> 'closed' then raise exception 'tenant not closed'; end if;
  if (select count(*) from public.tenant_dlp_policies where tenant_id='33333333-3333-4333-8333-333333333333') <> 1
    or (select count(*) from public.dlp_policy_revisions where tenant_id='33333333-3333-4333-8333-333333333333') <> 1 then raise exception 'neighbor touched'; end if;
  if public.run_tenant_offboarding_batch(run,1)->>'status' <> 'completed' then raise exception 'completed retry not idempotent'; end if;
end $$;
select 'DLP real offboarding dispatch, retention, hold, isolation and receipts passed' as result;
