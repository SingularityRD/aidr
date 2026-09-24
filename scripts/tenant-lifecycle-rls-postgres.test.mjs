// Execute against a disposable/self-hosted Supabase PostgreSQL container:
//   $env:AIDR_RLS_TEST_DB_CONTAINER='<container>'; node scripts/tenant-lifecycle-rls-postgres.test.mjs
// Default mode expects the pre-upgrade schema, reproduces the exploit, and
// applies the candidate migration. --installed runs the post-upgrade suite
// against a database where the migration has already been applied. Both modes
// roll back every fixture. SET ROLE and JWT GUCs evaluate real PostgreSQL RLS.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
const installed = process.argv.includes('--installed');
assert.ok(container, 'AIDR_RLS_TEST_DB_CONTAINER must name a disposable/self-hosted Supabase db container');
assert.match(container, /^[A-Za-z0-9_.-]+$/, 'invalid Docker container name');

const migration = readFileSync('supabase/migrations/20260912000019_tenant_lifecycle_rls.sql', 'utf8');
const reputationWritesMigration = readFileSync('supabase/migrations/20260924000002_reputation_provenance_write_lockdown.sql', 'utf8');
const reputationAudit = readFileSync('scripts/legacy-reputation-row-audit.sql', 'utf8').trim().replace(/;$/, '');
const a = randomUUID();
const b = randomUUID();
const admin = randomUUID();
const tenantA = randomUUID();
const tenantB = randomUUID();
const marker = randomUUID().replaceAll('-', '');
const url = `https://rls-${marker}.invalid/attack`;
const ownUrl = `https://rls-${marker}.invalid/own`;
const memberUrl = `https://rls-${marker}.invalid/member`;
const cleanUrl = `https://rls-${marker}.invalid/member-clean`;
const sha = marker.padEnd(64, 'a');
const ownSha = marker.padEnd(64, 'b');
const memberSha = marker.padEnd(64, 'c');

const context = (user, tenant) => `
select set_config('request.jwt.claim.sub', '${user}', true);
select set_config('request.jwt.claim.tenant_id', '${tenant}', true);
select set_config('request.jwt.claims', '{"sub":"${user}","role":"authenticated","aal":"aal2","iat":${Math.floor(Date.now() / 1000)}}', true);
set role authenticated;
`;
const fixtureWhere = (table) => table === 'url_reputation'
  ? `tenant_id = '${tenantB}' and url = '${url}'`
  : table === 'file_reputation'
    ? `tenant_id = '${tenantB}' and sha256 = '${sha}'`
    : `tenant_id = '${tenantB}'`;
const assertCount = (table, expected, where = fixtureWhere(table)) => `
do $$ begin
  if (select count(*) from public.${table} where ${where}) <> ${expected} then
    raise exception 'RLS ${table}: expected ${expected} visible row(s), got %',
      (select count(*) from public.${table} where ${where});
  end if;
end $$;
`;
const assertInsertDenied = (table, value) => `
do $$ begin
  begin
    insert into public.${table}(tenant_id, user_id, ${table === 'url_reputation' ? 'url' : 'sha256'})
      values ('${tenantB}', '${a}', '${value}');
    raise exception 'RLS ${table}: cross-tenant insert unexpectedly succeeded';
  exception when insufficient_privilege then null;
  end;
end $$;
`;
const assertNoRowsChanged = (statement, label) => `
do $$ declare v_rows integer; begin
  ${statement};
  get diagnostics v_rows = row_count;
  if v_rows <> 0 then raise exception 'RLS ${label}: changed % row(s)', v_rows; end if;
end $$;
`;
const assertOneRowChanged = (statement, label) => `
do $$ declare v_rows integer; begin
  ${statement};
  get diagnostics v_rows = row_count;
  if v_rows <> 1 then raise exception 'RLS ${label}: expected one changed row, got %', v_rows; end if;
end $$;
`;
const assertStatementDenied = (statement, label) => `
do $$ begin
  begin
    ${statement};
    raise exception 'RLS ${label}: statement unexpectedly succeeded';
  exception when insufficient_privilege then null;
  end;
end $$;
`;
const scopedTables = [
  'entitlements', 'api_keys', 'agents', 'events', 'url_reputation',
  'file_reputation', 'enrollment_tokens', 'billing_customers',
  'subscriptions', 'pilot_applications', 'entitlement_snapshots',
];
const directReadDenied = new Set(['api_keys', 'enrollment_tokens', 'billing_customers', 'pilot_applications']);
const assertAuthenticatedReads = (expected) => scopedTables.map((table) => installed && directReadDenied.has(table)
  ? assertStatementDenied(`select count(*) from public.${table}`, `direct ${table} read`)
  : assertCount(table, expected)).join('\n');

const sql = String.raw`
\set ON_ERROR_STOP on
begin;
insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values
  ('${a}', 'rls-a-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${b}', 'rls-b-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${admin}', 'rls-admin-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
insert into public.tenants(id, name, kind, created_by)
values ('${tenantA}', 'RLS A ${marker}', 'enterprise', '${a}'),
       ('${tenantB}', 'RLS B ${marker}', 'enterprise', '${b}');
insert into public.tenant_members(tenant_id, user_id, role)
values ('${tenantA}', '${a}', 'owner'),
       ('${tenantB}', '${b}', 'owner'),
       ('${tenantB}', '${admin}', 'admin');

${installed ? `
-- This mode verifies an already-upgraded database and seeds historical rows
-- as the service owner so the authenticated role cannot manufacture them.
-- The fixture's approved pilot is admitted only in explicit pilot mode.
update app.tenant_admission_config set mode = 'pilot' where singleton;
do $$ begin
  if not exists (
    select 1 from pg_policies where schemaname = 'public'
      and tablename = 'url_reputation' and policyname = 'tenant_active_member_restrict'
  ) then raise exception 'tenant lifecycle RLS migration is not installed'; end if;
end $$;
insert into public.url_reputation(tenant_id, user_id, url) values ('${tenantB}', '${a}', '${url}');
insert into public.file_reputation(tenant_id, user_id, sha256) values ('${tenantB}', '${a}', '${sha}');
` : `
-- Reproduce the shipping vulnerability before applying the candidate.
${context(a, tenantA)}
insert into public.url_reputation(tenant_id, user_id, url) values ('${tenantB}', '${a}', '${url}');
insert into public.file_reputation(tenant_id, user_id, sha256) values ('${tenantB}', '${a}', '${sha}');
${assertCount('url_reputation', 1, `tenant_id = '${tenantB}' and url = '${url}'`)}
${assertCount('file_reputation', 1, `tenant_id = '${tenantB}' and sha256 = '${sha}'`)}
reset role;
`}

-- A legacy owner column can remain after removing a membership. Populate all
-- pre-hybrid owned tables to exercise their actual RLS policies.
-- New credential admission requires a live member at issue time. Seed one,
-- then remove it before testing whether old user_id grants foreign access.
insert into public.tenant_members(tenant_id, user_id, role)
values ('${tenantB}', '${a}', 'member');
insert into public.entitlements(tenant_id, user_id, included_agents) values ('${tenantB}', '${a}', 1);
-- Keep exactly one legacy cross-tenant row while satisfying the newer
-- enrollment admission boundary for fixture credentials and agents.
insert into public.pilot_applications(tenant_id, user_id, status) values ('${tenantB}', '${a}', 'approved');
insert into public.api_keys(tenant_id, user_id, key_hash) values ('${tenantB}', '${a}', 'rls-key-${marker}');
insert into public.agents(tenant_id, user_id, iid) values ('${tenantB}', '${a}', 'rls-agent-${marker}');
insert into public.events(tenant_id, user_id, agent_id, type, payload, event_id)
select '${tenantB}', '${a}', id, 'rls_test', '{}'::jsonb, 'rls-event-${marker}'
from public.agents where tenant_id = '${tenantB}' and iid = 'rls-agent-${marker}';
insert into public.enrollment_tokens(tenant_id, user_id, token_hash, expires_at)
values ('${tenantB}', '${a}', 'rls-token-${marker}', now() + interval '1 day');
insert into public.billing_customers(tenant_id, user_id) values ('${tenantB}', '${a}');
insert into public.subscriptions(tenant_id, user_id, provider_subscription_id, status)
values ('${tenantB}', '${a}', 'rls-sub-${marker}', 'active');
insert into public.entitlement_snapshots(tenant_id, user_id, iid, entitlement)
values ('${tenantB}', '${a}', 'rls-agent-${marker}', '{}'::jsonb);
delete from public.tenant_members where tenant_id = '${tenantB}' and user_id = '${a}';

-- The old policy left no trustworthy writer provenance. The field audit must
-- surface both seeded cross-tenant rows, without deleting legitimate rows.
do $$ begin
  if (select count(*) from (${reputationAudit}) audited
      where tenant_id = '${tenantB}' and user_id = '${a}'
        and review_reason = 'no_current_membership_origin_unproven') <> 2 then
    raise exception 'historical reputation audit missed cross-tenant rows';
  end if;
end $$;

${installed ? '' : `
${context(a, tenantA)}
${scopedTables.map((table) => assertCount(table, 1)).join('\n')}
reset role;
`}

${installed ? '' : `
-- Apply the actual candidate migration inside this rollback-only transaction.
${migration}
`}

${installed ? '' : `
-- Before trusted-ingestion-only grants are applied, a normal tenant member can
-- add a fresh clean URL row that downstream checks may mistake for feed data.
${context(b, tenantB)}
insert into public.url_reputation(tenant_id, user_id, url, is_malicious)
  values ('${tenantB}', '${b}', '${cleanUrl}', false);
${assertCount('url_reputation', 1, `tenant_id = '${tenantB}' and url = '${cleanUrl}' and is_malicious = false`)}
reset role;
delete from public.url_reputation where tenant_id = '${tenantB}' and url = '${cleanUrl}';
`}

-- Apply idempotently in both modes so the installed path also exercises the
-- forward migration while preserving all fixtures through transaction rollback.
${reputationWritesMigration}

-- Catalog checks supplement the role-level behavior tests: all eleven
-- exposed resource tables have an AND-ed guard and no legacy own-row OR path.
do $$ begin
  if (
    select count(*) from pg_policies
    where schemaname = 'public'
      and tablename = any (array[${scopedTables.map((table) => `'${table}'`).join(', ')}])
      and policyname = 'tenant_active_member_restrict'
      and permissive = 'RESTRICTIVE'
  ) <> 11 then raise exception 'tenant active-member restrictive policy missing'; end if;
  if exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = any (array[${scopedTables.map((table) => `'${table}'`).join(', ')}])
      and right(policyname, 4) = '_own'
  ) then raise exception 'legacy own-row policy remains'; end if;
  if exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename in ('api_keys', 'enrollment_tokens')
      and cmd in ('INSERT', 'UPDATE', 'DELETE') and permissive = 'PERMISSIVE'
  ) then raise exception 'direct credential write policy remains'; end if;
  if exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename in ('url_reputation', 'file_reputation')
      and cmd in ('INSERT', 'UPDATE', 'DELETE')
  ) then raise exception 'browser reputation write policy remains'; end if;
  if not has_table_privilege('authenticated', 'public.url_reputation', 'SELECT')
    or not has_table_privilege('authenticated', 'public.file_reputation', 'SELECT')
  then raise exception 'authenticated reputation SELECT was not preserved'; end if;
  if has_table_privilege('anon', 'public.url_reputation', 'INSERT')
    or has_table_privilege('anon', 'public.url_reputation', 'UPDATE')
    or has_table_privilege('anon', 'public.url_reputation', 'DELETE')
    or has_table_privilege('authenticated', 'public.url_reputation', 'INSERT')
    or has_table_privilege('authenticated', 'public.url_reputation', 'UPDATE')
    or has_table_privilege('authenticated', 'public.url_reputation', 'DELETE')
    or has_table_privilege('anon', 'public.file_reputation', 'INSERT')
    or has_table_privilege('anon', 'public.file_reputation', 'UPDATE')
    or has_table_privilege('anon', 'public.file_reputation', 'DELETE')
    or has_table_privilege('authenticated', 'public.file_reputation', 'INSERT')
    or has_table_privilege('authenticated', 'public.file_reputation', 'UPDATE')
    or has_table_privilege('authenticated', 'public.file_reputation', 'DELETE')
  then raise exception 'browser role retains reputation DML privilege'; end if;
  if not has_table_privilege('service_role', 'public.url_reputation', 'INSERT')
    or not has_table_privilege('service_role', 'public.url_reputation', 'UPDATE')
    or not has_table_privilege('service_role', 'public.url_reputation', 'DELETE')
    or not has_table_privilege('service_role', 'public.file_reputation', 'INSERT')
    or not has_table_privilege('service_role', 'public.file_reputation', 'UPDATE')
    or not has_table_privilege('service_role', 'public.file_reputation', 'DELETE')
  then raise exception 'service_role reputation DML grant is incomplete'; end if;
  if has_sequence_privilege('anon', 'public.url_reputation_id_seq', 'USAGE')
    or has_sequence_privilege('authenticated', 'public.url_reputation_id_seq', 'USAGE')
    or has_sequence_privilege('anon', 'public.file_reputation_id_seq', 'USAGE')
    or has_sequence_privilege('authenticated', 'public.file_reputation_id_seq', 'USAGE')
    or not has_sequence_privilege('service_role', 'public.url_reputation_id_seq', 'USAGE')
    or not has_sequence_privilege('service_role', 'public.file_reputation_id_seq', 'USAGE')
  then raise exception 'reputation identity sequence privileges are unsafe'; end if;
end $$;

-- The attacker still has a valid JWT, but no victim membership. Every legacy
-- own-row read is denied and both reputation poisoning inserts fail.
${context(a, tenantA)}
${assertAuthenticatedReads(0)}
${assertInsertDenied('url_reputation', `https://rls-${marker}.invalid/after`)}
${assertInsertDenied('file_reputation', marker.padEnd(64, 'd'))}
${assertStatementDenied(`update public.url_reputation set severity_name = 'critical' where tenant_id = '${tenantB}' and url = '${url}'`, 'foreign URL update')}
${assertStatementDenied(`delete from public.url_reputation where tenant_id = '${tenantB}' and url = '${url}'`, 'foreign URL delete')}
${assertStatementDenied(`update public.file_reputation set severity = 'critical' where tenant_id = '${tenantB}' and sha256 = '${sha}'`, 'foreign file update')}
${assertStatementDenied(`delete from public.file_reputation where tenant_id = '${tenantB}' and sha256 = '${sha}'`, 'foreign file delete')}
${assertStatementDenied(`update public.api_keys set revoked = true where tenant_id = '${tenantB}' and key_hash = 'rls-key-${marker}'`, 'direct API key update')}
${assertStatementDenied(`delete from public.api_keys where tenant_id = '${tenantB}' and key_hash = 'rls-key-${marker}'`, 'direct API key delete')}
do $$ begin
  begin
    insert into public.api_keys(tenant_id, user_id, key_hash)
      values ('${tenantB}', '${a}', 'rls-cross-key-${marker}');
    raise exception 'RLS API key cross-tenant insert unexpectedly succeeded';
  exception when insufficient_privilege then null;
  end;
end $$;
do $$ begin
  begin
    insert into public.enrollment_tokens(tenant_id, user_id, token_hash, expires_at)
      values ('${tenantB}', '${a}', 'rls-cross-token-${marker}', now() + interval '1 day');
    raise exception 'RLS enrollment token cross-tenant insert unexpectedly succeeded';
  exception when insufficient_privilege then null;
  end;
end $$;
reset role;

-- A forged tenant claim must not grant access without a live membership.
-- This isolates the membership predicate from the claim-mismatch predicate.
${context(a, tenantB)}
${assertAuthenticatedReads(0)}
${assertInsertDenied('url_reputation', `https://rls-${marker}.invalid/forged-claim`)}
${assertInsertDenied('file_reputation', marker.padEnd(64, 'e'))}
reset role;

-- Tenant owners/admins retain tenant-scoped reads, but normal authenticated
-- members cannot create or mutate trusted reputation feed rows.
${context(b, tenantB)}
${assertAuthenticatedReads(1)}
${assertStatementDenied(`insert into public.url_reputation(tenant_id, user_id, url, is_malicious) values ('${tenantB}', '${b}', '${ownUrl}', false)`, 'owner clean URL insert')}
${assertStatementDenied(`insert into public.file_reputation(tenant_id, user_id, sha256) values ('${tenantB}', '${b}', '${ownSha}')`, 'owner file insert')}
${assertStatementDenied(`update public.url_reputation set severity_name = 'critical' where tenant_id = '${tenantB}' and url = '${url}'`, 'owner URL update')}
${assertStatementDenied(`update public.file_reputation set severity = 'critical' where tenant_id = '${tenantB}' and sha256 = '${sha}'`, 'owner file update')}
reset role;
${context(admin, tenantB)}
${assertAuthenticatedReads(1)}
${assertStatementDenied(`delete from public.url_reputation where tenant_id = '${tenantB}' and url = '${url}'`, 'admin URL delete')}
reset role;

-- A personal tenant remains usable when no explicit tenant claim is selected.
${context(admin, '')}
${assertStatementDenied(`insert into public.url_reputation(tenant_id, user_id, url, is_malicious) values ('${admin}', '${admin}', 'https://rls-${marker}.invalid/personal', false)`, 'personal clean URL insert')}
reset role;

-- A current member reads their tenant, but cannot add a fresh clean URL entry.
insert into public.tenant_members(tenant_id, user_id, role) values ('${tenantB}', '${a}', 'member');
${context(a, tenantB)}
${assertAuthenticatedReads(1)}
${assertStatementDenied(`insert into public.url_reputation(tenant_id, user_id, url, is_malicious) values ('${tenantB}', '${a}', '${memberUrl}', false)`, 'member clean URL insert')}
${assertStatementDenied(`insert into public.file_reputation(tenant_id, user_id, sha256) values ('${tenantB}', '${a}', '${memberSha}')`, 'member file insert')}
${assertStatementDenied(`delete from public.url_reputation where tenant_id = '${tenantB}' and url = '${url}'`, 'member URL delete')}
${assertStatementDenied(`delete from public.file_reputation where tenant_id = '${tenantB}' and sha256 = '${sha}'`, 'member file delete')}
reset role;

-- An expired membership must fail immediately with the same JWT.
update public.tenant_members set expires_at = now() - interval '1 second'
where tenant_id = '${tenantB}' and user_id = '${a}';
${context(a, tenantB)}
${assertAuthenticatedReads(0)}
${assertInsertDenied('url_reputation', `https://rls-${marker}.invalid/expired`)}
${assertInsertDenied('file_reputation', marker.padEnd(64, 'f'))}
reset role;

-- Deleting the membership is also immediate; no JWT refresh is needed.
delete from public.tenant_members where tenant_id = '${tenantB}' and user_id = '${a}';
${context(a, tenantB)}
${assertAuthenticatedReads(0)}
reset role;

-- Tenant suspension blocks even its owner. The service role retains its
-- operational access for controlled offboarding/recovery.
update public.tenants set status = 'suspended' where id = '${tenantB}';
${context(b, tenantB)}
${assertAuthenticatedReads(0)}
${assertInsertDenied('url_reputation', `https://rls-${marker}.invalid/suspended`)}
${assertInsertDenied('file_reputation', marker.padEnd(64, '1'))}
reset role;
set role service_role;
${scopedTables.map((table) => assertCount(table, 1)).join('\n')}
insert into public.url_reputation(tenant_id, user_id, url)
  values ('${tenantB}', '${b}', 'https://rls-${marker}.invalid/service-role');
insert into public.file_reputation(tenant_id, user_id, sha256)
  values ('${tenantB}', '${b}', '${memberSha}');
${assertCount('url_reputation', 1, `tenant_id = '${tenantB}' and url = 'https://rls-${marker}.invalid/service-role'`)}
${assertCount('file_reputation', 1, `tenant_id = '${tenantB}' and sha256 = '${memberSha}'`)}
reset role;
rollback;
select 'RLS_TEST_ROLLBACK';
`;

const result = spawnSync('docker', [
  'exec', '-i', container, 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
  '-U', 'postgres', '-d', 'postgres', '-q', '-At',
], { input: sql, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `PostgreSQL RLS regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /RLS_TEST_ROLLBACK/);
console.log(`PostgreSQL RLS regression passed (${installed ? 'installed' : 'before/after'}): 11 resource boundaries, cross-tenant and forged-claim reputation writes, API-key/enrollment writes, expired/removed members, tenant suspension, personal fallback, owner/admin/member, service_role read/write; transaction rolled back (${container}). Existing customer rows and PostgREST HTTP remain separate field acceptance checks.`);
