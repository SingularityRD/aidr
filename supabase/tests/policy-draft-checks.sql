-- Run after the real migration against policy-draft-fixture.sql, never production.
\set ON_ERROR_STOP on
\set VERBOSITY verbose
select draft_test.check_result('legacy row count, IDs, content, timestamps and attribution preserved',
 not exists(select id,team_id,tenant_id,content,updated_at,updated_by from public.team_policies
            except select * from draft_test.legacy_before)
 and not exists(select * from draft_test.legacy_before
            except select id,team_id,tenant_id,content,updated_at,updated_by from public.team_policies));
select draft_test.check_result('legacy head remains newest timestamp, not largest UUID',
 (select id from public.team_policies order by updated_at desc,id desc limit 1)='00000000-0000-0000-0000-000000000001'::uuid);
select draft_test.check_result('legacy versions and exact-source hashes backfilled',
 (select bool_and(version=1 and source_sha256=encode(sha256(convert_to(content,'UTF8')),'hex')) from public.team_policies));
select draft_test.check_result('timestamp trigger enabled after migration',
 (select tgenabled='O' from pg_trigger where tgrelid='public.team_policies'::regclass and tgname='team_policies_touch_updated_at'));
select draft_test.check_result('only service role can execute save RPC',
 has_function_privilege('service_role','public.save_policy_document_draft(uuid,uuid,text,text,uuid,bigint,text)','EXECUTE')
 and not has_function_privilege('authenticated','public.save_policy_document_draft(uuid,uuid,text,text,uuid,bigint,text)','EXECUTE')
 and not has_function_privilege('anon','public.save_policy_document_draft(uuid,uuid,text,text,uuid,bigint,text)','EXECUTE'));
select draft_test.check_result('authenticated insert/update revoked while select/delete preserved',
 not has_table_privilege('authenticated','public.team_policies','INSERT')
 and not has_table_privilege('authenticated','public.team_policies','UPDATE')
 and has_table_privilege('authenticated','public.team_policies','SELECT')
 and has_table_privilege('authenticated','public.team_policies','DELETE'));
select draft_test.check_result('authenticated cannot truncate all tenant history or install triggers/references',
 not has_table_privilege('authenticated','public.team_policies','TRUNCATE')
 and not has_table_privilege('authenticated','public.team_policies','TRIGGER')
 and not has_table_privilege('authenticated','public.team_policies','REFERENCES'));

do $$
declare
 tenant uuid := '10000000-0000-0000-0000-000000000001';
 actor uuid := '20000000-0000-0000-0000-000000000001';
 source text := E'# café 👋\r\nname: İstanbul\r\n';
 -- Independently calculated with .NET SHA256 over the UTF-8 bytes, not SQL digest.
 fingerprint text := 'd42a86e0fc6548a5e8aab7e8460a1dd07addca543c8f096179f163a487218bb1';
 expected_bytes text := '2320636166c3a920f09f918b0d0a6e616d653a20c4b07374616e62756c0d0a';
 first_result jsonb;
 updated_result jsonb;
 statement text;
 who text;
begin
 set local role service_role;
 first_result := public.save_policy_document_draft(tenant,actor,source,fingerprint,null,null,null);
 reset role;
 perform draft_test.check_result('member can first-save with version 1 and exact independently hashed UTF8/CRLF',
   (first_result->>'version')::bigint=1 and first_result->>'source_sha256'=fingerprint
   and exists(select 1 from public.team_policies where id=(first_result->>'id')::uuid
     and content=source and encode(convert_to(content,'UTF8'),'hex')=expected_bytes and updated_by=actor));
 statement := format('select public.save_policy_document_draft(%L,%L,%L,%L,null,null,null)',tenant,actor,source,fingerprint);
 perform draft_test.expect_state('repeat absent-head CAS conflicts',statement,'PT409');
 perform draft_test.expect_state('authenticated RPC denied',statement,'42501','authenticated');
 perform draft_test.expect_state('anonymous RPC denied',statement,'42501','anon');
 perform draft_test.expect_state('authenticated direct insert denied',format('insert into public.team_policies(team_id,tenant_id,content) values(%L,%L,''bypass'')',tenant,tenant),'42501','authenticated');
 perform draft_test.expect_state('authenticated direct update denied','update public.team_policies set content=''bypass''','42501','authenticated');
 perform draft_test.expect_state('anonymous direct insert denied',format('insert into public.team_policies(team_id,tenant_id,content) values(%L,%L,''bypass'')',tenant,tenant),'42501','anon');
 foreach who in array array['20000000-0000-0000-0000-000000000002','20000000-0000-0000-0000-000000000003','20000000-0000-0000-0000-000000000005'] loop
   perform draft_test.expect_state('viewer/expired/nonmember denied: '||who,
     format('select public.save_policy_document_draft(%L,%L,%L,%L,null,null,null)',tenant,who,source,fingerprint),'42501');
 end loop;
 perform draft_test.expect_state('inactive tenant denied',
   format('select public.save_policy_document_draft(%L,%L,%L,%L,null,null,null)','10000000-0000-0000-0000-000000000003',actor,source,fingerprint),'42501');
 perform draft_test.expect_state('wrong submitted fingerprint rejected',
   format('select public.save_policy_document_draft(%L,%L,%L,%L,null,null,null)',tenant,actor,source,repeat('0',64)),'22023');
 perform draft_test.expect_state('newline-normalized hash rejected against exact CRLF content',
   format('select public.save_policy_document_draft(%L,%L,%L,%L,null,null,null)',tenant,actor,source,encode(sha256(convert_to(replace(source,E'\r\n',E'\n'),'UTF8')),'hex')),'22023');
 perform draft_test.expect_state('empty content rejected',
   format('select public.save_policy_document_draft(%L,%L,'''',%L,null,null,null)',tenant,actor,encode(sha256(''::bytea),'hex')),'22023');
 perform draft_test.expect_state('UTF8 byte limit enforced rather than character limit',
   format('select public.save_policy_document_draft(%L,%L,repeat(''é'',32769),encode(sha256(convert_to(repeat(''é'',32769),''UTF8'')),''hex''),null,null,null)',tenant,actor),'22023');
 perform draft_test.expect_state('null expected ID with version rejected',
   format('select public.save_policy_document_draft(%L,%L,%L,%L,null,1,null)',tenant,actor,source,fingerprint),'22023');
 perform draft_test.expect_state('stale source hash conflicts independently of revision',
   format('select public.save_policy_document_draft(%L,%L,%L,%L,%L,1,%L)',tenant,actor,source,fingerprint,first_result->>'id',repeat('0',64)),'PT409');
 perform draft_test.expect_state('wrong expected row ID conflicts',
   format('select public.save_policy_document_draft(%L,%L,%L,%L,%L,1,%L)',tenant,actor,source,fingerprint,'99999999-0000-0000-0000-000000000001',fingerprint),'PT409');
 set local role service_role;
 updated_result := public.save_policy_document_draft(tenant,'20000000-0000-0000-0000-000000000004',source,fingerprint,(first_result->>'id')::uuid,1,fingerprint);
 reset role;
 perform draft_test.check_result('admin update succeeds and increments revision even for identical content',
   (updated_result->>'version')::bigint=2 and updated_result->>'id'=first_result->>'id');
 perform draft_test.expect_state('stale revision conflicts independently of hash',
   format('select public.save_policy_document_draft(%L,%L,%L,%L,%L,1,%L)',tenant,actor,source,fingerprint,first_result->>'id',fingerprint),'PT409');
 perform draft_test.check_result('all rejected calls left saved content and revision unchanged',
   exists(select 1 from public.team_policies where id=(first_result->>'id')::uuid and content=source and version=2 and source_sha256=fingerprint));
 -- Service maintenance cannot forge hash/revision because the trigger owns them.
 set local role service_role;
 update public.team_policies set content='maintenance',version=999,source_sha256=repeat('0',64) where id=(first_result->>'id')::uuid;
 reset role;
 perform draft_test.check_result('service update cannot forge version/hash',
   exists(select 1 from public.team_policies where id=(first_result->>'id')::uuid and version=3 and source_sha256=encode(sha256(convert_to('maintenance','UTF8')),'hex')));
end; $$;

do $$
declare old_head public.team_policies%rowtype; result jsonb;
begin
 select * into old_head from public.team_policies where tenant_id='10000000-0000-0000-0000-000000000002' order by updated_at desc,id desc limit 1;
 set local role service_role;
 result := public.save_policy_document_draft(old_head.tenant_id,'20000000-0000-0000-0000-000000000001','owner update',encode(sha256(convert_to('owner update','UTF8')),'hex'),old_head.id,old_head.version,old_head.source_sha256);
 reset role;
 perform draft_test.check_result('owner updates correct legacy head and timestamp trigger still runs',
   result->>'id'='00000000-0000-0000-0000-000000000001' and (result->>'version')::bigint=2 and (result->>'updated_at')::timestamptz>old_head.updated_at);
 perform draft_test.check_result('older legacy row remains entirely unchanged after head save',
   exists(select 1 from public.team_policies p join draft_test.legacy_before b using(id)
     where p.id='ffffffff-0000-0000-0000-000000000001' and p.content=b.content and p.updated_at=b.updated_at and p.updated_by=b.updated_by and p.version=1)
   and (select count(*) from public.team_policies where tenant_id=old_head.tenant_id)=2);
end; $$;
-- Inject a failure after the row and version trigger have been changed, proving
-- that a late database failure does not partially persist the attempted draft.
create function draft_test.fail_after_update() returns trigger language plpgsql as $$
begin
 if new.content='force-storage-failure' then
   insert into draft_test.rollback_probe values(99);
   raise exception 'injected storage failure' using errcode='XX001';
 end if;
 return new;
end; $$;
create trigger fixture_fail_after_update after update on public.team_policies
 for each row execute function draft_test.fail_after_update();
do $$
declare old_head public.team_policies%rowtype;
begin
 select * into old_head from public.team_policies where tenant_id='10000000-0000-0000-0000-000000000001';
 perform draft_test.expect_state('late storage failure propagated',
   format('select public.save_policy_document_draft(%L,%L,%L,%L,%L,%s,%L)',old_head.tenant_id,'20000000-0000-0000-0000-000000000001','force-storage-failure',encode(sha256(convert_to('force-storage-failure','UTF8')),'hex'),old_head.id,old_head.version,old_head.source_sha256),'XX001');
 perform draft_test.check_result('late failure rolls back content, revision, hash, timestamp and other writes',
   exists(select 1 from public.team_policies p where p.id=old_head.id and p.content=old_head.content and p.version=old_head.version and p.source_sha256=old_head.source_sha256 and p.updated_at=old_head.updated_at)
   and not exists(select 1 from draft_test.rollback_probe));
end; $$;
-- An advisory/row-lock wait can outlive an expiring membership. Authorization
-- must use wall-clock time when checked, not the transaction-start timestamp.
do $$
declare old_head public.team_policies%rowtype;
begin
 select * into old_head from public.team_policies where tenant_id='10000000-0000-0000-0000-000000000001';
 update public.tenant_members set expires_at=clock_timestamp()+interval '100 milliseconds'
   where tenant_id=old_head.tenant_id and user_id='20000000-0000-0000-0000-000000000001';
 perform pg_sleep(0.2);
 perform draft_test.expect_state('membership expiring during transaction is denied at authorization time',
   format('select public.save_policy_document_draft(%L,%L,%L,%L,%L,%s,%L)',old_head.tenant_id,'20000000-0000-0000-0000-000000000001',old_head.content,old_head.source_sha256,old_head.id,old_head.version,old_head.source_sha256),'42501');
 update public.tenant_members set expires_at=null
   where tenant_id=old_head.tenant_id and user_id='20000000-0000-0000-0000-000000000001';
end; $$;

-- Publication reviews an exact document tuple. The second call proves that a
-- draft edit between review and publish cannot advance runtime policy.
do $$
declare
 tenant uuid := '10000000-0000-0000-0000-000000000002';
 actor uuid := '20000000-0000-0000-0000-000000000001';
 old_head public.team_policies%rowtype;
 first_publish public.tenant_runtime_policies%rowtype;
 latest public.team_policies%rowtype;
 published public.tenant_runtime_policies%rowtype;
 new_source text := 'reviewed next source';
 new_hash text := encode(sha256(convert_to(new_source,'UTF8')),'hex');
begin
 select * into old_head from public.team_policies
   where tenant_id=tenant order by updated_at desc,id desc limit 1;
 set local role service_role;
 select * into first_publish from public.publish_runtime_policy_document(
   tenant,actor,0,'{"command_default":"deny"}'::jsonb,
   old_head.id,old_head.version,old_head.source_sha256);
 reset role;
 perform draft_test.check_result('publish succeeds for exact reviewed draft id, version and hash',
   first_publish.version=1 and first_publish.policy='{"command_default":"deny"}'::jsonb
   and exists(select 1 from public.runtime_policy_revisions where tenant_id=tenant and version=1));

 set local role service_role;
 perform public.save_policy_document_draft(tenant,actor,new_source,new_hash,
   old_head.id,old_head.version,old_head.source_sha256);
 reset role;
 select * into latest from public.team_policies
   where tenant_id=tenant order by updated_at desc,id desc limit 1;
 perform draft_test.expect_state('publication conflicts when reviewed source hash/version is stale',
   format('select * from public.publish_runtime_policy_document(%L,%L,1,%L,%L,%s,%L)',
     tenant,actor,'{"command_default":"ask"}',old_head.id,old_head.version,old_head.source_sha256),'PT409');
 perform draft_test.check_result('stale source publication leaves the runtime policy untouched',
   latest.id=old_head.id and latest.version=old_head.version+1 and latest.source_sha256=new_hash
   and exists(select 1 from public.tenant_runtime_policies where tenant_id=tenant and version=1
     and policy='{"command_default":"deny"}'::jsonb)
   and (select count(*)=1 from public.runtime_policy_revisions where tenant_id=tenant));

 set local role service_role;
 select * into published from public.publish_runtime_policy_document(
   tenant,actor,1,'{"command_default":"ask"}'::jsonb,
   latest.id,latest.version,latest.source_sha256);
 reset role;
 perform draft_test.check_result('publish succeeds after reviewing the new exact source head',
   published.version=2 and published.policy='{"command_default":"ask"}'::jsonb
   and (select count(*)=2 from public.runtime_policy_revisions where tenant_id=tenant));
end; $$;
select label, passed from draft_test.results order by label;
