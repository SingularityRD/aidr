\set ON_ERROR_STOP on

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

insert into public.agents(id,user_id,tenant_id,iid)
select '73000000-0000-4000-8000-000000000001',user_id,tenant_id,'offboarding-agent' from offboarding_fixture;
insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload)
select f.user_id,f.tenant_id,'73000000-0000-4000-8000-000000000001',
  'offboarding-event-'||n,'runtime_verdict','{"verdict":"deny"}'::jsonb
from offboarding_fixture f cross join generate_series(1,3) n;
insert into public.api_keys(user_id,tenant_id,label,key_hash)
select user_id,tenant_id,'offboarding-key',repeat('a',64) from offboarding_fixture;
insert into public.scim_tokens(tenant_id,token_hash,label)
select tenant_id,repeat('b',64),'offboarding-scim' from offboarding_fixture;
insert into public.audit_logs(team_id,tenant_id,user_id,action,verdict)
select tenant_id,tenant_id,user_id,'offboarding.fixture','{"decision":"deny"}'::jsonb from offboarding_fixture;
insert into public.audit_export_objects(path,tenant_id,created_by)
select object_path,tenant_id,user_id from offboarding_fixture;

do $test$
declare
  f offboarding_fixture;
  result jsonb;
  initial_run uuid;
  blocked boolean := false;
  i integer;
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
  if exists(
    select 1
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
  ) then raise exception 'tenant-scoped table missing from offboarding phases'; end if;
  if result->>'backup_scope' <> 'excluded_external_retention' then raise exception 'backup exception missing'; end if;
  if (select status from public.tenants where id=f.tenant_id) <> 'closing' then raise exception 'tenant not closing'; end if;
  if not (select revoked from public.api_keys where tenant_id=f.tenant_id) then raise exception 'API key not revoked'; end if;
  if not (select revoked_at is not null from public.scim_tokens where tenant_id=f.tenant_id) then raise exception 'SCIM token not revoked'; end if;

  result := public.run_tenant_offboarding_batch(initial_run,2);
  if result->>'action' <> 'delete_storage_objects' then raise exception 'storage phase not first'; end if;
  insert into public.tenant_legal_holds(tenant_id,hold_reference,reason,placed_by)
    values(f.tenant_id,'CASE-VALIDATION','Validation hold',f.user_id);
  result := public.ack_tenant_offboarding_objects(initial_run,array[f.object_path]);
  if result->>'status' <> 'blocked_legal_hold' then raise exception 'legal hold did not block object ack'; end if;
  if not exists(select 1 from public.audit_export_objects where path=f.object_path) then raise exception 'blocked object ledger was deleted'; end if;
  update public.tenant_legal_holds set released_at=now(),released_by=f.user_id,release_reason='Validation release'
    where tenant_id=f.tenant_id and released_at is null;
  result := public.ack_tenant_offboarding_objects(initial_run,array[f.object_path]);
  if result->>'phase_complete' <> 'true' then raise exception 'storage phase did not complete'; end if;

  for i in 1..200 loop
    result := public.run_tenant_offboarding_batch(initial_run,2);
    exit when result->>'status'='completed';
  end loop;
  if result->>'status' <> 'completed' then raise exception 'offboarding did not complete'; end if;
  if (select status from public.tenants where id=f.tenant_id) <> 'closed' then raise exception 'tenant not closed'; end if;
  if exists(select 1 from public.events where tenant_id=f.tenant_id) then raise exception 'events remain'; end if;
  if exists(select 1 from public.audit_logs where tenant_id=f.tenant_id) then raise exception 'audit rows remain'; end if;
  if (select rows_deleted from public.tenant_offboarding_phase_receipts where run_id=initial_run and phase='events') <> 3 then
    raise exception 'event receipt count mismatch';
  end if;
  if (select attempts from public.tenant_offboarding_phase_receipts where run_id=initial_run and phase='events') <> 2 then
    raise exception 'event batch was not bounded';
  end if;
  if (select count(*) from public.tenant_offboarding_phase_receipts where run_id=initial_run and status='completed') <> 39 then
    raise exception 'phase receipt set incomplete';
  end if;
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
