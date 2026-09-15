-- Apply after the two shipped invoice migrations, BEFORE finance authority.
\set tenant '00000000-0000-0000-0000-000000000001'
\set owner '00000000-0000-0000-0000-000000000011'
\set admin '00000000-0000-0000-0000-000000000012'
\set finance '00000000-0000-0000-0000-000000000013'
\set legacy '00000000-0000-0000-0000-000000000100'
\set pending '00000000-0000-0000-0000-000000000101'
\set revoked '00000000-0000-0000-0000-000000000102'
\set suspended '00000000-0000-0000-0000-000000000103'
\set expired '00000000-0000-0000-0000-000000000104'

insert into public.enterprise_invoice_orders
 (id, tenant_id, request_id, created_by, requested_agents)
select ('00000000-0000-0000-0000-' || lpad(i::text, 12, '0'))::uuid,
 :'tenant', 'finance_regression_' || i, :'owner',
 case i when 100 then 3 when 101 then 7 when 105 then 11 when 106 then 13 else 19 end
from generate_series(100, 106) i;
-- A claimed historical label matching a customer UUID MUST NOT become authority
-- or be backfilled as verified approver_user_id by the new migration.
set role service_role;
select public.record_invoice_approval(:'legacy', :'owner', 500, 'USD', repeat('a', 64));
reset role;
