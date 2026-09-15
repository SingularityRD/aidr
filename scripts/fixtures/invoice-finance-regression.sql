-- Run only through test-invoice-finance-postgres.mjs, in its disposable DB.
-- Every statement autocommits: preflight and transition are separate transactions.
create function test.approve(actor uuid, order_id uuid) returns jsonb
language sql security invoker as $$
  select public.record_invoice_approval(
    '00000000-0000-0000-0000-000000000001', actor, order_id,
    12345, 'USD', repeat('b', 64));
$$;
create function test.preflight(actor uuid, order_id uuid) returns jsonb
language sql security invoker as $$
  select public.get_enterprise_invoice_order_for_approval(
    '00000000-0000-0000-0000-000000000001', actor, order_id);
$$;
select test.assert((select count(*) = 0 from public.invoice_finance_operators),
  'authority must be empty despite existing owner/admin and historical approval');
select test.assert((select approver_user_id is null and approver = :'owner'
  from public.enterprise_invoice_approvals where order_id = :'legacy'),
  'legacy claimed label must remain unverified');
select test.assert((select actor_user_id is null from public.admin_audit_logs
  where detail ->> 'order_id' = :'legacy' and action = 'invoice_approval.recorded'),
  'legacy audit identity must remain unchanged');
\echo PASS empty default and no historical authority/identity backfill

-- Exercise the service RPC with customer owner/admin IDs (not just direct DB
-- authenticated execution). A customer membership must confer no finance power.
set role service_role;
select test.expect_error(format('select test.preflight(%L,%L)', :'owner', :'pending'),
  '42501', 'invoice_approval_forbidden');
select test.expect_error(format('select test.approve(%L,%L)', :'owner', :'pending'),
  '42501', 'invoice_approval_forbidden');
select test.expect_error(format('select test.preflight(%L,%L)', :'admin', :'pending'),
  '42501', 'invoice_approval_forbidden');
select test.expect_error(format('select test.approve(%L,%L)', :'admin', :'pending'),
  '42501', 'invoice_approval_forbidden');
select test.expect_error(format('select test.approve(%L,%L)', :'finance', :'pending'),
  '42501', 'invoice_approval_forbidden');
reset role;
select test.assert((select count(*) = 1 from public.enterprise_invoice_approvals)
  and (select extra_agents = 3 from public.entitlements)
  and (select count(*) = 1 from public.admin_audit_logs),
  'rejected customer approvals must leave ledger, entitlement, and audit unchanged');
\echo PASS customer owner/admin and unprovisioned finance rejected

-- Catalog assertions check all API roles, PUBLIC ACL inheritance, and overloads.
select test.assert(to_regprocedure('public.record_invoice_approval(uuid,text,bigint,text,text)') is null,
  'old actor-less RPC must be dropped, not merely hidden');
select test.assert((select count(*) = 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.proname = 'record_invoice_approval'),
  'no alternate approval overload may remain');
select test.assert(not has_function_privilege(r, f, 'EXECUTE'), r || ' can execute ' || f)
from (values ('anon'), ('authenticated')) roles(r)
cross join (values
 ('public.record_invoice_approval(uuid,uuid,uuid,bigint,text,text)'),
 ('public.get_enterprise_invoice_order_for_approval(uuid,uuid,uuid)'),
 ('public.assert_invoice_finance_operator(uuid,uuid)')) funcs(f);
select test.assert(has_function_privilege('service_role', f, 'EXECUTE'), 'service role lacks ' || f)
from (values
 ('public.record_invoice_approval(uuid,uuid,uuid,bigint,text,text)'),
 ('public.get_enterprise_invoice_order_for_approval(uuid,uuid,uuid)'),
 ('public.assert_invoice_finance_operator(uuid,uuid)')) funcs(f);
select test.assert(not has_table_privilege(r, 'public.invoice_finance_operators', privilege),
  r || ' can change finance authority with ' || privilege)
from (values ('anon'), ('authenticated'), ('service_role')) roles(r)
cross join (values ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) privileges(privilege);
select test.assert(not has_table_privilege(r, 'public.enterprise_invoice_approvals', privilege),
  r || ' can write approval ledger with ' || privilege)
from (values ('anon'), ('authenticated'), ('service_role')) roles(r)
cross join (values ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE')) privileges(privilege);
select test.assert((select relrowsecurity from pg_class
  where oid = 'public.invoice_finance_operators'::regclass), 'authority RLS must be enabled');
set role authenticated;
select test.expect_error(format('select test.approve(%L,%L)', :'owner', :'pending'), '42501');
select test.expect_error(format('insert into public.invoice_finance_operators(tenant_id,user_id) values (%L,%L)',
  :'tenant', :'owner'), '42501');
reset role;
set role anon;
select test.expect_error(format('select test.approve(%L,%L)', :'owner', :'pending'), '42501');
reset role;
set role service_role;
select test.expect_error(format('insert into public.invoice_finance_operators(tenant_id,user_id) values (%L,%L)',
  :'tenant', :'finance'), '42501');
select test.expect_error(format('insert into public.enterprise_invoice_approvals
  (order_id,tenant_id,approver,amount_minor,currency,evidence_sha256,agents_granted)
  values (%L,%L,%L,100,''USD'',repeat(''c'',64),999)', :'pending', :'tenant', :'owner'), '42501');
reset role;
\echo PASS old RPC removed; API role function/table privileges deny bypass and self-provisioning

-- Provision ONLY as database administrator. Finance has no customer membership.
insert into public.invoice_finance_operators(tenant_id, user_id) values (:'tenant', :'finance');
select test.assert(not exists (select 1 from public.tenant_members where user_id = :'finance'),
  'positive finance actor must be independent of customer membership');
set role service_role;
select test.assert(test.preflight(:'finance', :'pending') ->> 'id' = :'pending', 'finance preflight');
select test.assert(test.approve(:'finance', :'pending') ->> 'status' = 'paid', 'finance paid transition');
select test.expect_error(format('select test.approve(%L,%L)', :'finance', :'pending'),
  '23505', 'invoice_approval_conflict');
-- Owner/admin remain forbidden even after a different person is provisioned.
select test.expect_error(format('select test.approve(%L,%L)', :'owner', :'revoked'),
  '42501', 'invoice_approval_forbidden');
select test.expect_error(format('select test.approve(%L,%L)', :'admin', :'revoked'),
  '42501', 'invoice_approval_forbidden');
reset role;
select test.assert((select approver_user_id = :'finance'::uuid and approver = :'finance'
  and agents_granted = 7 and amount_minor = 12345 and currency = 'USD'
  from public.enterprise_invoice_approvals where order_id = :'pending'), 'verified approval actor and amount');
select test.assert((select count(*) = 1 from public.admin_audit_logs
  where action = 'invoice_approval.recorded' and actor_user_id = :'finance'::uuid
    and detail ->> 'order_id' = :'pending' and detail ->> 'approver_user_id' = :'finance'
    and detail ->> 'approver' = :'finance' and detail ->> 'amount_minor' = '12345'),
  'exact authenticated UUID must be in audit actor and detail');
select test.assert((select extra_agents = 10 and user_id = :'owner'::uuid from public.entitlements),
  'owner holds allocation, distinct from finance actor');
\echo PASS separately provisioned finance actor; exact audit UUID; duplicate rejected

-- Each successful preflight commits before authority/tenant state changes.
set role service_role;
select test.assert(test.preflight(:'finance', :'revoked') is not null, 'pre-revocation preflight');
reset role;
update public.invoice_finance_operators set revoked_at = now() where user_id = :'finance';
set role service_role;
select test.expect_error(format('select test.approve(%L,%L)', :'finance', :'revoked'),
  '42501', 'invoice_approval_forbidden');
reset role;
update public.invoice_finance_operators set revoked_at = null where user_id = :'finance';
set role service_role;
select test.assert(test.preflight(:'finance', :'suspended') is not null, 'pre-suspension preflight');
reset role;
update public.tenants set status = 'suspended' where id = :'tenant';
set role service_role;
select test.expect_error(format('select test.approve(%L,%L)', :'finance', :'suspended'),
  '42501', 'invoice_approval_forbidden');
reset role;
update public.tenants set status = 'active' where id = :'tenant';
set role service_role;
select test.assert(test.preflight(:'finance', :'expired') is not null, 'pre-expiration preflight');
reset role;
update public.invoice_finance_operators set expires_at = now() - interval '1 second' where user_id = :'finance';
set role service_role;
select test.expect_error(format('select test.approve(%L,%L)', :'finance', :'expired'),
  '42501', 'invoice_approval_forbidden');
reset role;
update public.invoice_finance_operators set expires_at = null where user_id = :'finance';
select test.assert((select count(*) = 2 from public.enterprise_invoice_approvals)
  and (select count(*) = 2 from public.admin_audit_logs)
  and (select extra_agents = 10 from public.entitlements),
  'post-preflight denial must leave approval, audit, entitlement unchanged');
\echo PASS revoked/expired authority and suspended tenant after committed preflight rejected atomically
