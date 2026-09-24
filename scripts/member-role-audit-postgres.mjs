// Run after resetting a disposable local Supabase database:
//   AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr AIDR_TEST_DISPOSABLE_DB=1 node scripts/member-role-audit-postgres.mjs
// The transaction rolls back every fixture and audit record.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.equal(process.env.AIDR_TEST_DISPOSABLE_DB, "1", "confirm a disposable database with AIDR_TEST_DISPOSABLE_DB=1");
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name a disposable local Supabase db container");
assert.match(container, /^supabase_db_[A-Za-z0-9_.-]+$/, "refusing a non-Supabase database container");

const [ownerA, adminA, memberA, ownerB, memberB, tenantA, tenantB] =
  Array.from({ length: 7 }, () => randomUUID());
const marker = randomUUID().replaceAll("-", "");
const issuedAt = Math.floor(Date.now() / 1000);
const context = (userId, aal = "aal2") => `
select set_config('request.jwt.claim.sub', '${userId}', true);
select set_config('request.jwt.claims', '{"sub":"${userId}","role":"authenticated","aal":"${aal}","iat":${issuedAt}}', true);
set session authorization authenticator;
set role authenticated;
`;
const resetContext = "reset role;\nreset session authorization;";

const sql = String.raw`
\set ON_ERROR_STOP on
begin;

do $$ begin
  if not exists (select 1 from pg_trigger
    where tgrelid = 'public.team_members'::regclass
      and not tgisinternal and tgname = 'team_members_member_role_audit')
  then raise exception 'member-role audit migration is not installed'; end if;
end $$;

insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values
  ('${ownerA}', 'role-owner-a-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${adminA}', 'role-admin-a-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${memberA}', 'role-member-a-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${ownerB}', 'role-owner-b-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${memberB}', 'role-member-b-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
insert into public.tenants(id, name, kind, created_by)
values ('${tenantA}', 'Member role A ${marker}', 'team', '${ownerA}'),
       ('${tenantB}', 'Member role B ${marker}', 'team', '${ownerB}');
insert into public.teams(id, tenant_id, name, plan)
values ('${tenantA}', '${tenantA}', 'Member role A ${marker}', 'free'),
       ('${tenantB}', '${tenantB}', 'Member role B ${marker}', 'free');
insert into public.team_members(team_id, tenant_id, user_id, role)
values ('${tenantA}', '${tenantA}', '${ownerA}', 'owner'),
       ('${tenantA}', '${tenantA}', '${adminA}', 'admin'),
       ('${tenantA}', '${tenantA}', '${memberA}', 'member'),
       ('${tenantB}', '${tenantB}', '${ownerB}', 'owner'),
       ('${tenantB}', '${tenantB}', '${memberB}', 'member');
do $$ begin
  perform set_config('aidr.test.member_audit_baseline',
    (select count(*)::text from public.admin_audit_logs
      where tenant_id = '${tenantA}' and target_user_id = '${memberA}'
        and action = 'team.member.role_changed'), true);
  perform set_config('aidr.test.foreign_audit_baseline',
    (select count(*)::text from public.admin_audit_logs
      where tenant_id = '${tenantB}' and target_user_id = '${memberB}'
        and action = 'team.member.role_changed'), true);
  perform set_config('aidr.test.owner_audit_baseline',
    (select count(*)::text from public.admin_audit_logs
      where tenant_id = '${tenantA}' and target_user_id = '${memberA}'
        and action = 'team.owner.role_changed'), true);
end $$;

-- Ordinary role edits keep working at AAL1 when tenant MFA is not required.
${context(adminA, "aal1")}
do $$ declare v_rows integer; begin
  update public.team_members set role = 'viewer'
    where team_id = '${tenantA}' and user_id = '${memberA}';
  get diagnostics v_rows = row_count;
  if v_rows <> 1 then raise exception 'admin role update changed % rows', v_rows; end if;
end $$;
${resetContext}
do $$ begin
  if (select role from public.team_members where team_id = '${tenantA}' and user_id = '${memberA}') is distinct from 'viewer'
     or (select role from public.tenant_members where tenant_id = '${tenantA}' and user_id = '${memberA}') is distinct from 'viewer'
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${memberA}'
         and action = 'team.member.role_changed'
         and actor_user_id = '${adminA}'
         and detail ->> 'old_role' = 'member' and detail ->> 'new_role' = 'viewer') <> 1
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${memberA}'
         and action = 'team.member.role_changed') <> current_setting('aidr.test.member_audit_baseline')::integer + 1
     or (select count(*) from public.audit_logs c
       join public.admin_audit_logs a on a.detail ->> 'event_id' = c.verdict ->> 'event_id'
       where c.tenant_id = '${tenantA}' and c.team_id = '${tenantA}'
         and c.user_id = '${adminA}' and c.action = 'team.member.role_changed'
         and c.verdict ->> 'target_user_id' = '${memberA}'
         and c.verdict ->> 'old_role' = 'member' and c.verdict ->> 'new_role' = 'viewer'
         and a.tenant_id = '${tenantA}' and a.target_user_id = '${memberA}'
         and a.action = c.action and a.actor_user_id = c.user_id) <> 1
     or (select count(*) from public.audit_logs
       where tenant_id = '${tenantA}' and action = 'team.member.role_changed'
         and verdict ->> 'target_user_id' = '${memberA}') <> 1
  then raise exception 'member role change was not synchronized and audited exactly once'; end if;
end $$;

${context(ownerA, "aal1")}
do $$ begin
  if (select count(*) from public.audit_logs
    where tenant_id = '${tenantA}' and action = 'team.member.role_changed'
      and verdict ->> 'target_user_id' = '${memberA}') <> 1
  then raise exception 'owner cannot read customer-visible member-role audit'; end if;
end $$;
${resetContext}
${context(memberA, "aal1")}
do $$ begin
  if (select count(*) from public.audit_logs
    where tenant_id = '${tenantA}' and action = 'team.member.role_changed'
      and verdict ->> 'target_user_id' = '${memberA}') <> 1
  then raise exception 'member cannot read customer-visible member-role audit'; end if;
end $$;
${resetContext}

${context(adminA)}
do $$ declare v_rows integer; begin
  update public.team_members set role = 'viewer'
    where team_id = '${tenantA}' and user_id = '${memberA}';
  get diagnostics v_rows = row_count;
  if v_rows <> 1 then raise exception 'no-op role update changed % rows', v_rows; end if;
end $$;
${resetContext}
do $$ begin
  if (select count(*) from public.admin_audit_logs
    where tenant_id = '${tenantA}' and target_user_id = '${memberA}'
      and action = 'team.member.role_changed') <> current_setting('aidr.test.member_audit_baseline')::integer + 1
     or (select count(*) from public.audit_logs
       where tenant_id = '${tenantA}' and action = 'team.member.role_changed'
         and verdict ->> 'target_user_id' = '${memberA}') <> 1
  then raise exception 'no-op role update emitted an audit'; end if;
end $$;

${context(adminA)}
do $$ declare v_rows integer; begin
  begin
    update public.team_members set role = 'viewer'
      where team_id = '${tenantB}' and user_id = '${memberB}';
    get diagnostics v_rows = row_count;
    if v_rows <> 0 then raise exception 'cross-tenant admin updated % rows', v_rows; end if;
  exception when insufficient_privilege then null;
  end;
end $$;
${resetContext}
do $$ begin
  if (select role from public.team_members where team_id = '${tenantB}' and user_id = '${memberB}') is distinct from 'member'
     or (select role from public.tenant_members where tenant_id = '${tenantB}' and user_id = '${memberB}') is distinct from 'member'
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantB}' and target_user_id = '${memberB}'
         and action = 'team.member.role_changed') <> current_setting('aidr.test.foreign_audit_baseline')::integer
     or exists (select 1 from public.audit_logs
       where tenant_id = '${tenantB}' and action = 'team.member.role_changed'
         and verdict ->> 'target_user_id' = '${memberB}')
  then raise exception 'cross-tenant role attempt changed membership or audit'; end if;
end $$;

${context(ownerA)}
do $$ declare v_rows integer; begin
  update public.team_members set role = 'owner'
    where team_id = '${tenantA}' and user_id = '${memberA}';
  get diagnostics v_rows = row_count;
  if v_rows <> 1 then raise exception 'owner transition changed % rows', v_rows; end if;
end $$;
${resetContext}
do $$ begin
  if (select role from public.team_members where team_id = '${tenantA}' and user_id = '${memberA}') is distinct from 'owner'
     or (select role from public.tenant_members where tenant_id = '${tenantA}' and user_id = '${memberA}') is distinct from 'owner'
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${memberA}'
         and action = 'team.owner.role_changed'
         and actor_user_id = '${ownerA}'
         and detail ->> 'old_role' = 'viewer' and detail ->> 'new_role' = 'owner') <> 1
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${memberA}'
         and action = 'team.owner.role_changed') <> current_setting('aidr.test.owner_audit_baseline')::integer + 1
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${memberA}'
         and action = 'team.member.role_changed') <> current_setting('aidr.test.member_audit_baseline')::integer + 1
     or (select count(*) from public.audit_logs
       where tenant_id = '${tenantA}' and action = 'team.member.role_changed'
         and verdict ->> 'target_user_id' = '${memberA}') <> 1
  then raise exception 'owner transition double-logged or lost its owner audit'; end if;
end $$;

rollback;
select 'MEMBER_ROLE_AUDIT_ROLLBACK';
`;

const result = spawnSync("docker", [
  "exec", "-i", "-e", "PGPASSWORD=postgres", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
  "-U", "supabase_admin", "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `member-role PostgreSQL regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /MEMBER_ROLE_AUDIT_ROLLBACK/);
console.log("Member-role PostgreSQL test passed: admin change audited once, no-op and cross-tenant denied from audit, owner transition logged only by owner guard; fixtures rolled back.");
