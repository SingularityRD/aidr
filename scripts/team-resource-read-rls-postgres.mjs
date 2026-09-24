// Run after `supabase start && supabase db reset --local --no-seed`:
//   AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr node scripts/team-resource-read-rls-postgres.mjs
// Fixtures are rolled back. A real authenticated role/JWT context exercises RLS.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name the disposable Supabase db container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");

const [ownerA, ownerB, reader, outsider, teamA, teamB] = Array.from({ length: 6 }, () => randomUUID());
const marker = randomUUID().replaceAll("-", "");
const now = Math.floor(Date.now() / 1000);
const tables = ["entitlements", "subscriptions", "entitlement_snapshots", "url_reputation", "file_reputation"];
const context = (user, aal = "aal2") => `
select set_config('request.jwt.claim.sub', '${user}', true);
select set_config('request.jwt.claim.tenant_id', '', true);
select set_config('request.jwt.claims', '{"sub":"${user}","role":"authenticated","aal":"${aal}","iat":${now}}', true);
set role authenticated;
`;
const expectCount = (table, tenant, count) => `
do $$ begin
  if (select count(*) from public.${table} where tenant_id = '${tenant}') <> ${count} then
    raise exception '${table}: expected ${count} rows in tenant ${tenant}';
  end if;
end $$;
`;
const readMatrix = (tenant, count) => tables.map(table => expectCount(table, tenant, count)).join("\n");

const sql = String.raw`
\set ON_ERROR_STOP on
begin;

do $$ begin
  if (
    select count(*) from pg_policies
    where schemaname = 'public'
      and tablename = any (array[${tables.map(table => `'${table}'`).join(", ")}])
      and policyname = 'tenant_active_member_restrict'
      and permissive = 'RESTRICTIVE'
      and qual like '%is_tenant_member%'
      and with_check like '%current_tenant_id%'
  ) <> 5 then raise exception 'team-resource RLS migration not installed'; end if;
  if has_table_privilege('authenticated', 'public.api_keys', 'SELECT')
    or has_table_privilege('authenticated', 'public.enrollment_tokens', 'SELECT')
  then raise exception 'credential tables unexpectedly exposed to browser role'; end if;
end $$;

insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values
  ('${ownerA}', 'resource-owner-a-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${ownerB}', 'resource-owner-b-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${reader}', 'resource-reader-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${outsider}', 'resource-outsider-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
insert into public.tenants(id, name, kind, created_by)
values ('${teamA}', 'Resource A ${marker}', 'team', '${ownerA}'),
       ('${teamB}', 'Resource B ${marker}', 'team', '${ownerB}');
insert into public.tenant_members(tenant_id, user_id, role)
values ('${teamA}', '${ownerA}', 'owner'),
       ('${teamA}', '${reader}', 'viewer'),
       ('${teamB}', '${ownerB}', 'owner');
insert into public.entitlements(tenant_id, user_id, included_agents)
values ('${teamA}', '${ownerA}', 3), ('${teamB}', '${ownerB}', 9);
insert into public.subscriptions(tenant_id, user_id, provider_subscription_id, status)
values ('${teamA}', '${ownerA}', 'resource-a-${marker}', 'active'),
       ('${teamB}', '${ownerB}', 'resource-b-${marker}', 'active');
insert into public.entitlement_snapshots(tenant_id, user_id, iid, entitlement)
values ('${teamA}', '${ownerA}', 'resource-a-${marker}', '{}'::jsonb),
       ('${teamB}', '${ownerB}', 'resource-b-${marker}', '{}'::jsonb);
insert into public.url_reputation(tenant_id, user_id, url)
values ('${teamA}', '${ownerA}', 'https://resource-a-${marker}.invalid'),
       ('${teamB}', '${ownerB}', 'https://resource-b-${marker}.invalid');
insert into public.file_reputation(tenant_id, user_id, sha256)
values ('${teamA}', '${ownerA}', '${marker.padEnd(64, "a")}'),
       ('${teamB}', '${ownerB}', '${marker.padEnd(64, "b")}');

-- No selected-tenant claim: the active member reads the selected team and
-- their own personal tenant, but never an unrelated team.
${context(reader)}
${readMatrix(teamA, 1)}
${readMatrix(teamB, 0)}
${expectCount("entitlements", reader, 1)}
do $$ begin
  if (select count(*) from public.seat_usage where tenant_id = '${teamA}') <> 1 then
    raise exception 'seat_usage did not inherit team entitlement RLS';
  end if;
end $$;
-- Membership never silently enables a team write without a selected tenant
-- claim; authenticated reputation writes remain tied to current_tenant_id().
do $$ begin
  begin
    insert into public.url_reputation(tenant_id, user_id, url)
    values ('${teamA}', '${reader}', 'https://denied-${marker}.invalid');
    raise exception 'claimless team reputation write unexpectedly succeeded';
  exception when insufficient_privilege then null;
  end;
end $$;
reset role;

${context(outsider)}
${readMatrix(teamA, 0)}
reset role;

-- An expired or removed membership must disappear without a JWT refresh.
update public.tenant_members set expires_at = now() - interval '1 second'
where tenant_id = '${teamA}' and user_id = '${reader}';
${context(reader)}
${readMatrix(teamA, 0)}
reset role;
delete from public.tenant_members
where tenant_id = '${teamA}' and user_id = '${reader}';
${context(reader)}
${readMatrix(teamA, 0)}
reset role;
insert into public.tenant_members(tenant_id, user_id, role)
values ('${teamA}', '${reader}', 'viewer');

-- The independent identity barrier still enforces the team's MFA policy.
insert into public.tenant_identity_policies(tenant_id, require_mfa)
values ('${teamA}', true);
${context(reader, "aal1")}
${readMatrix(teamA, 0)}
reset role;
${context(reader)}
${readMatrix(teamA, 1)}
reset role;

-- Suspending a tenant removes access even for its owner.
update public.tenants set status = 'suspended' where id = '${teamA}';
${context(ownerA)}
${readMatrix(teamA, 0)}
reset role;

rollback;
select 'TEAM_RESOURCE_READ_RLS_ROLLBACK';
`;

const result = spawnSync("docker", [
  "exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
  "-U", "postgres", "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `team-resource RLS regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /TEAM_RESOURCE_READ_RLS_ROLLBACK/);
console.log("Team-resource PostgreSQL RLS passed: claimless active member, wrong team, revoked membership, personal tenant, MFA, suspension, write separation; fixtures rolled back.");
