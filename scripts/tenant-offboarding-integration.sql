\set ON_ERROR_STOP on

-- Never leave fixture users, admission mode, or offboarding receipts behind.
begin;
do $mode$
begin
  if to_regclass('app.tenant_admission_config') is not null then
    execute 'update app.tenant_admission_config set mode = ''pilot'' where singleton';
  end if;
end
$mode$;

create temp table offboarding_fixture(tenant_id uuid, user_id uuid, run_id uuid, object_path text);

insert into auth.users(id,email,raw_user_meta_data)
values('71000000-0000-4000-8000-000000000001','offboarding-fixture@example.test','{}'::jsonb);

insert into offboarding_fixture(tenant_id,user_id,object_path)
select t.id, '71000000-0000-4000-8000-000000000001'::uuid,
  t.id::text||'/72000000-0000-4000-8000-000000000001.json'
from public.tenants t
where t.created_by='71000000-0000-4000-8000-000000000001' and t.kind='team'
order by t.created_at limit 1;

update public.tenant_data_retention_policies p set retention_days=0
from offboarding_fixture f where p.tenant_id=f.tenant_id;

-- The offboarding fixture represents an admitted one-seat pilot, not an
-- unapproved free team that cannot enroll agents or issue keys.
insert into public.entitlements(user_id,tenant_id,included_agents)
select user_id,tenant_id,1 from offboarding_fixture
on conflict (tenant_id) do update set included_agents=1;
insert into public.pilot_applications(user_id,tenant_id,status)
select user_id,tenant_id,'approved' from offboarding_fixture
on conflict (user_id,tenant_id) do update set status='approved';

insert into public.agents(id,user_id,tenant_id,iid)
select '73000000-0000-4000-8000-000000000001',user_id,tenant_id,'offboarding-agent' from offboarding_fixture;
insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
select f.user_id,f.tenant_id,'73000000-0000-4000-8000-000000000001',
  'offboarding-event-'||n,'runtime_verdict','{"verdict":"deny"}'::jsonb
from offboarding_fixture f cross join generate_series(1,3) n;
insert into public.api_keys(user_id,tenant_id,label,key_hash)
select user_id,tenant_id,'offboarding-key',repeat('a',64) from offboarding_fixture;
-- New SCIM credentials must name their source directory (20261007000050).
insert into public.scim_tokens(tenant_id,token_hash,label,directory_id)
select tenant_id,repeat('b',64),'offboarding-scim','offboarding-idp' from offboarding_fixture;
insert into public.audit_logs(team_id,tenant_id,user_id,action,verdict)
select tenant_id,tenant_id,user_id,'offboarding.fixture','{"decision":"deny"}'::jsonb from offboarding_fixture;
insert into public.audit_export_objects(path,tenant_id,created_by)
select object_path,tenant_id,user_id from offboarding_fixture;

do $test$
declare
  f offboarding_fixture;
  result jsonb;
  initial_run uuid;
  authorization_id uuid;
  blocked boolean := false;
  i integer;
  missing_phases text;
begin
  select * into f from offboarding_fixture;
  if f.tenant_id is null then raise exception 'fixture team tenant missing'; end if;
  if has_function_privilege('authenticated','public.request_tenant_offboarding(uuid,uuid)','execute') then
    raise exception 'authenticated role can execute offboarding';
  end if;
  begin
    delete from public.audit_logs where tenant_id=f.tenant_id;
  exception when others then
    blocked := sqlerrm = 'audit_logs are append-only';
  end;
  if not blocked then raise exception 'ordinary audit deletion was not blocked'; end if;

  result := public.request_tenant_offboarding(f.tenant_id,f.user_id);
  initial_run := (result->>'run_id')::uuid;
  update offboarding_fixture set run_id=initial_run;
  select string_agg(c.table_name, ', ' order by c.table_name) into missing_phases
  from (
    select distinct c.table_name
    from information_schema.columns c
    join information_schema.tables t on t.table_schema=c.table_schema and t.table_name=c.table_name
    where c.table_schema='public' and c.column_name='tenant_id' and t.table_type='BASE TABLE'
      and c.table_name not in (
        'teams','tenant_data_retention_policies','tenant_legal_holds','tenant_offboarding_runs'
      )
      and not exists(
        select 1 from public.tenant_offboarding_phase_receipts r
        where r.run_id=initial_run and r.phase=c.table_name
      )
      and not exists(
        -- These tables have an explicit parent phase, a phase-completion hook,
        -- or a retained-evidence receipt created at commercial cleanup.
        select 1 from (values
          ('audit_export_deletion_authorizations','audit_export_objects'),
          ('tenant_saml_policy_change_requests','admin_audit_logs'),
		  ('tenant_saml_outage_recoveries','admin_audit_logs'),
          ('tenant_pack_deletion_authorizations','pack_versions'),
          ('tenant_pack_deletion_receipts','pack_versions'),
          ('billing_entitlement_projections','entitlements'),
          ('billing_checkout_intents','billing_portal_operations'),
          ('billing_provider_payments','billing_portal_operations'),
          ('billing_provider_refunds','billing_portal_operations'),
          ('billing_settlement_requests','entitlements'),
          ('billing_settlements','entitlements'),
          ('enterprise_invoice_approvals','entitlements'),
          ('enterprise_invoice_orders','entitlements'),
          ('policy_rollout_batches','runtime_policy_revisions'),
          ('policy_rollout_targets','runtime_policy_revisions'),
          ('policy_rollouts','runtime_policy_revisions'),
          ('tenant_discovery_collectors','agents'),
          ('tenant_discovery_credentials','agents'),
		  ('tenant_discovery_provider_resources','agents'),
          ('tenant_discovery_items','agents'),
          -- Purged by a phase-completion hook on the named phase.
          ('agent_profile_revisions','tenant_dlp_policies'),
          ('tenant_agent_profiles','tenant_dlp_policies'),
          ('ai_assets','tenant_runtime_policies'),
          ('ai_asset_evidence','tenant_runtime_policies'),
          ('ai_governance_exceptions','tenant_runtime_policies'),
          ('ai_governance_reviewers','tenant_runtime_policies'),
          ('ai_intake_requests','tenant_runtime_policies'),
          ('policy_change_requests','tenant_runtime_policies'),
          ('tenant_ai_governance_settings','tenant_runtime_policies'),
          ('approval_requests','events'),
          ('tenant_approval_signing_keys','events'),
          ('governance_digest_deliveries','events'),
          ('tenant_governance_settings','events'),
          -- Deleted by foreign-key cascade from the named phase's table.
          ('posture_findings','events'),
          ('api_key_ingest_installations','api_keys'),
          ('tenant_directory_break_glass_owners','tenant_directory_authority'),
          -- Notification channels are deleted when offboarding starts (trigger on
          -- tenants.status, with credentials); deliveries and outages cascade.
          ('notification_channels','api_keys'),
          ('notification_deliveries','api_keys'),
          ('notification_agent_outages','api_keys'),
          -- Commercial evidence retained with the entitlement ledger.
          ('billing_plan_subscriptions','entitlements')
        ) covered(table_name,parent_phase)
        join public.tenant_offboarding_phase_receipts r
          on r.run_id=initial_run and r.phase=covered.parent_phase
        where covered.table_name=c.table_name
      )
  ) c;
  if missing_phases is not null then
    raise exception 'tenant-scoped table missing from offboarding phases: %', missing_phases;
  end if;
  if result->>'backup_scope' <> 'excluded_external_retention' then raise exception 'backup exception missing'; end if;
  if (select status from public.tenants where id=f.tenant_id) <> 'closing' then raise exception 'tenant not closing'; end if;
  if not (select revoked from public.api_keys where tenant_id=f.tenant_id) then raise exception 'API key not revoked'; end if;
  if not (select revoked_at is not null from public.scim_tokens where tenant_id=f.tenant_id) then raise exception 'SCIM token not revoked'; end if;

  insert into public.tenant_legal_holds(tenant_id,hold_reference,reason,placed_by)
    values(f.tenant_id,'CASE-VALIDATION','Validation hold',f.user_id);
  result := public.run_tenant_offboarding_batch(initial_run,2);
  if result->>'status' <> 'blocked_legal_hold' then raise exception 'legal hold did not block storage authorization'; end if;
  if not exists(select 1 from public.audit_export_objects where path=f.object_path) then raise exception 'blocked object ledger was deleted'; end if;
  update public.tenant_legal_holds set released_at=now(),released_by=f.user_id,release_reason='Validation release'
    where tenant_id=f.tenant_id and released_at is null;
  result := public.run_tenant_offboarding_batch(initial_run,2);
  if result->>'action' <> 'delete_storage_objects' or jsonb_array_length(result->'objects') <> 1
     or result->'objects'->0->>'path' <> f.object_path then
    raise exception 'storage authorization was not exact';
  end if;
  authorization_id := (result->'objects'->0->>'authorization_id')::uuid;
  begin
    perform public.ack_tenant_offboarding_objects(initial_run,array[f.object_path]);
    raise exception 'paths-only storage ack unexpectedly succeeded';
  exception when others then
    if sqlerrm <> 'offboarding_storage_authorization_required' then raise; end if;
  end;
  begin
    insert into public.tenant_legal_holds(tenant_id,hold_reference,reason,placed_by)
      values(f.tenant_id,'CASE-LATE','Late hold',f.user_id);
    raise exception 'hold bypassed pending storage authorization';
  exception when others then
    if sqlerrm <> 'legal_hold_refused_pending_export_deletion' then raise; end if;
  end;
  result := public.ack_tenant_offboarding_objects(initial_run,array[f.object_path],array[authorization_id]);
  if result->>'phase_complete' <> 'true' then raise exception 'storage phase did not complete'; end if;

  for i in 1..200 loop
    result := public.run_tenant_offboarding_batch(initial_run,2);
    if result->>'action'='invalidate_cache' then
      perform public.ack_tenant_offboarding_cache(initial_run,array['tenant:'||f.tenant_id::text||':*'],0);
    end if;
    exit when result->>'status'='completed';
  end loop;
  if result->>'status' <> 'completed' then raise exception 'offboarding did not complete'; end if;
  if (select status from public.tenants where id=f.tenant_id) <> 'closed' then raise exception 'tenant not closed'; end if;
  if exists(select 1 from public.events where tenant_id=f.tenant_id) then raise exception 'events remain'; end if;
  if exists(select 1 from public.audit_logs where tenant_id=f.tenant_id) then raise exception 'audit rows remain'; end if;
  if exists(select 1 from public.tenant_pack_deletion_authorizations where tenant_id=f.tenant_id)
    or exists(select 1 from public.pack_versions where tenant_id=f.tenant_id)
    or exists(select 1 from storage.objects where bucket_id='aidr-packs' and name like f.tenant_id::text || '/%') then
    raise exception 'pack storage offboarding residue';
  end if;
  if (select rows_deleted from public.tenant_offboarding_phase_receipts where run_id=initial_run and phase='events') <> 3 then
    raise exception 'event receipt count mismatch';
  end if;
  if (select attempts from public.tenant_offboarding_phase_receipts where run_id=initial_run and phase='events') <> 2 then
    raise exception 'event batch was not bounded';
  end if;
  if (select count(*) from public.tenant_offboarding_phase_receipts where run_id=initial_run and status='completed') <> 62 then
    raise exception 'phase receipt set incomplete: % completed, missing %',
      (select count(*) from public.tenant_offboarding_phase_receipts where run_id=initial_run and status='completed'),
      (select string_agg(phase || '=' || status, ', ' order by phase_order) from public.tenant_offboarding_phase_receipts
        where run_id=initial_run and status <> 'completed');
  end if;
  if exists(
    select 1 from (values
      ('fleet_response_playbook_steps',40),('fleet_response_playbook_runs',41),
      ('fleet_response_commands',42),('tenant_cache',43),
      ('dlp_policy_revisions',44),('tenant_dlp_policies',45),
      ('admission_operators',46),('tenant_admissions',47),
      ('billing_portal_operations',48),('invoice_finance_operators',49),
      ('oidc_auth_requests',50),('oidc_login_tickets',51),
      ('oidc_sso_sessions',52),('oidc_identities',53),
      ('oidc_tenant_domains',54),('oidc_providers',55),
	  ('saml_recovery_operator_keys',56),
      ('enterprise_invoice_orders',90),('billing_settlements',91),
      ('billing_finance_evidence',92)
    ) expected(phase,phase_order)
    where not exists(select 1 from public.tenant_offboarding_phase_receipts p
      where p.run_id=initial_run and p.phase=expected.phase and p.phase_order=expected.phase_order and p.status='completed')
  ) then raise exception 'playbook and downstream phase ordering mismatch'; end if;
  result := public.request_tenant_offboarding(f.tenant_id,f.user_id);
  if (result->>'run_id')::uuid <> initial_run or result->>'resumed' <> 'true' then
    raise exception 'completed request was not idempotent';
  end if;
  begin
    delete from public.tenant_legal_holds where tenant_id=f.tenant_id;
    raise exception 'legal hold history deletion unexpectedly succeeded';
  exception when others then
    if sqlerrm <> 'legal_hold_history_is_immutable' then raise; end if;
  end;
end;
$test$;

select 'tenant offboarding integration passed' as result;
rollback;
