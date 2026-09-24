// Run after resetting a disposable local Supabase database:
//   AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr AIDR_TEST_DISPOSABLE_DB=1 node scripts/member-removal-audit-postgres.mjs
// The transaction rolls back every fixture and audit record.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.equal(process.env.AIDR_TEST_DISPOSABLE_DB, "1", "confirm a disposable database with AIDR_TEST_DISPOSABLE_DB=1");
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name a disposable local Supabase db container");
assert.match(container, /^supabase_db_[A-Za-z0-9_.-]+$/, "refusing a non-Supabase database container");

const [ownerA, secondOwner, adminA, memberA, ownerB, memberB, tenantA, tenantB] =
  Array.from({ length: 8 }, () => randomUUID());
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
      and not tgisinternal and tgname = 'team_members_member_removal_audit')
  then raise exception 'member-removal audit migration is not installed'; end if;
end $$;

insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values
  ('${ownerA}', 'removal-owner-a-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${secondOwner}', 'removal-owner-2-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${adminA}', 'removal-admin-a-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${memberA}', 'removal-member-a-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${ownerB}', 'removal-owner-b-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${memberB}', 'removal-member-b-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
insert into public.tenants(id, name, kind, created_by)
values ('${tenantA}', 'Member removal A ${marker}', 'team', '${ownerA}'),
       ('${tenantB}', 'Member removal B ${marker}', 'team', '${ownerB}');
insert into public.teams(id, tenant_id, name, plan)
values ('${tenantA}', '${tenantA}', 'Member removal A ${marker}', 'free'),
       ('${tenantB}', '${tenantB}', 'Member removal B ${marker}', 'free');
insert into public.team_members(team_id, tenant_id, user_id, role)
values ('${tenantA}', '${tenantA}', '${ownerA}', 'owner'),
       ('${tenantA}', '${tenantA}', '${secondOwner}', 'owner'),
       ('${tenantA}', '${tenantA}', '${adminA}', 'admin'),
       ('${tenantA}', '${tenantA}', '${memberA}', 'member'),
       ('${tenantB}', '${tenantB}', '${ownerB}', 'owner'),
       ('${tenantB}', '${tenantB}', '${memberB}', 'member');
do $$ begin
  perform set_config('aidr.test.member_removal_baseline',
    (select count(*)::text from public.admin_audit_logs
      where tenant_id = '${tenantA}' and target_user_id = '${memberA}'
        and action = 'team.member.removed'), true);
  perform set_config('aidr.test.foreign_removal_baseline',
    (select count(*)::text from public.admin_audit_logs
      where tenant_id = '${tenantB}' and target_user_id = '${memberB}'
        and action = 'team.member.removed'), true);
  perform set_config('aidr.test.second_owner_audit_baseline',
    (select count(*)::text from public.admin_audit_logs
      where tenant_id = '${tenantA}' and target_user_id = '${secondOwner}'
        and action = 'team.owner.role_changed'), true);
  perform set_config('aidr.test.owner_audit_baseline',
    (select count(*)::text from public.admin_audit_logs
      where tenant_id = '${tenantA}' and target_user_id = '${ownerA}'
        and action = 'team.owner.role_changed'), true);
end $$;

-- Ordinary removals keep working at AAL1 when tenant MFA is not required.
${context(adminA, "aal1")}
do $$ declare v_rows integer; begin
  delete from public.team_members
    where team_id = '${tenantA}' and user_id = '${memberA}';
  get diagnostics v_rows = row_count;
  if v_rows <> 1 then raise exception 'admin removal deleted % rows', v_rows; end if;
end $$;
${resetContext}
do $$ begin
  if exists (select 1 from public.team_members where team_id = '${tenantA}' and user_id = '${memberA}')
     or exists (select 1 from public.tenant_members where tenant_id = '${tenantA}' and user_id = '${memberA}')
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${memberA}'
         and action = 'team.member.removed' and actor_user_id = '${adminA}'
         and detail ->> 'old_role' = 'member') <> 1
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${memberA}'
         and action = 'team.member.removed') <> current_setting('aidr.test.member_removal_baseline')::integer + 1
     or (select count(*) from public.audit_logs c
       join public.admin_audit_logs a on a.detail ->> 'event_id' = c.verdict ->> 'event_id'
       where c.tenant_id = '${tenantA}' and c.team_id = '${tenantA}'
         and c.user_id = '${adminA}' and c.action = 'team.member.removed'
         and c.verdict ->> 'target_user_id' = '${memberA}'
         and c.verdict ->> 'old_role' = 'member'
         and a.tenant_id = '${tenantA}' and a.target_user_id = '${memberA}'
         and a.action = c.action and a.actor_user_id = c.user_id) <> 1
     or (select count(*) from public.audit_logs
       where tenant_id = '${tenantA}' and action = 'team.member.removed'
         and verdict ->> 'target_user_id' = '${memberA}') <> 1
  then raise exception 'member removal was not synchronized and audited exactly once'; end if;
end $$;

${context(ownerA, "aal1")}
do $$ begin
  if (select count(*) from public.audit_logs
    where tenant_id = '${tenantA}' and action = 'team.member.removed'
      and verdict ->> 'target_user_id' = '${memberA}') <> 1
  then raise exception 'owner cannot read customer-visible removal audit'; end if;
end $$;
${resetContext}
${context(memberA, "aal1")}
do $$ begin
  if exists (select 1 from public.audit_logs
    where tenant_id = '${tenantA}' and action = 'team.member.removed'
      and verdict ->> 'target_user_id' = '${memberA}')
  then raise exception 'removed member can still read customer audit'; end if;
end $$;
${resetContext}

${context(adminA)}
do $$ declare v_rows integer; begin
  begin
    delete from public.team_members
      where team_id = '${tenantB}' and user_id = '${memberB}';
    get diagnostics v_rows = row_count;
    if v_rows <> 0 then raise exception 'cross-tenant admin deleted % rows', v_rows; end if;
  exception when insufficient_privilege then null;
  end;
end $$;
${resetContext}
do $$ begin
  if not exists (select 1 from public.team_members where team_id = '${tenantB}' and user_id = '${memberB}' and role = 'member')
     or not exists (select 1 from public.tenant_members where tenant_id = '${tenantB}' and user_id = '${memberB}' and role = 'member')
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantB}' and target_user_id = '${memberB}'
         and action = 'team.member.removed') <> current_setting('aidr.test.foreign_removal_baseline')::integer
     or exists (select 1 from public.audit_logs
       where tenant_id = '${tenantB}' and action = 'team.member.removed'
         and verdict ->> 'target_user_id' = '${memberB}')
  then raise exception 'cross-tenant removal changed membership or audit'; end if;
end $$;

-- Deleting a non-final owner belongs to the owner transition stream, never
-- the ordinary member removal stream.
${context(ownerA)}
do $$ declare v_rows integer; begin
  delete from public.team_members
    where team_id = '${tenantA}' and user_id = '${secondOwner}';
  get diagnostics v_rows = row_count;
  if v_rows <> 1 then raise exception 'second-owner removal deleted % rows', v_rows; end if;
end $$;
${resetContext}
do $$ begin
  if exists (select 1 from public.team_members where team_id = '${tenantA}' and user_id = '${secondOwner}')
     or exists (select 1 from public.tenant_members where tenant_id = '${tenantA}' and user_id = '${secondOwner}')
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${secondOwner}'
         and action = 'team.owner.role_changed' and actor_user_id = '${ownerA}'
         and detail ->> 'old_role' = 'owner' and detail ->> 'new_role' is null) <> 1
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${secondOwner}'
         and action = 'team.owner.role_changed') <> current_setting('aidr.test.second_owner_audit_baseline')::integer + 1
     or exists (select 1 from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${secondOwner}'
         and action = 'team.member.removed')
     or (select count(*) from public.audit_logs c
       join public.admin_audit_logs a on a.detail ->> 'event_id' = c.verdict ->> 'event_id'
       where c.tenant_id = '${tenantA}' and c.team_id = '${tenantA}'
         and c.user_id = '${ownerA}' and c.action = 'team.owner.role_changed'
         and c.verdict ->> 'target_user_id' = '${secondOwner}'
         and c.verdict ->> 'old_role' = 'owner'
         and c.verdict ->> 'new_role' is null
         and a.tenant_id = '${tenantA}' and a.target_user_id = '${secondOwner}'
         and a.action = c.action and a.actor_user_id = c.user_id) <> 1
     or exists (select 1 from public.audit_logs
       where tenant_id = '${tenantA}' and action = 'team.member.removed'
         and verdict ->> 'target_user_id' = '${secondOwner}')
  then raise exception 'owner removal lost its owner audit or double-logged member removal'; end if;
end $$;

${context(ownerA)}
do $$ declare v_rows integer; begin
  begin
    delete from public.team_members
      where team_id = '${tenantA}' and user_id = '${ownerA}';
    get diagnostics v_rows = row_count;
    raise exception 'final-owner removal returned % rows without denial', v_rows;
  exception when others then
    if sqlstate <> '23514' then raise; end if;
  end;
end $$;
${resetContext}
do $$ begin
  if not exists (select 1 from public.team_members where team_id = '${tenantA}' and user_id = '${ownerA}' and role = 'owner')
     or not exists (select 1 from public.tenant_members where tenant_id = '${tenantA}' and user_id = '${ownerA}' and role = 'owner')
     or (select count(*) from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${ownerA}'
         and action = 'team.owner.role_changed') <> current_setting('aidr.test.owner_audit_baseline')::integer
     or (select count(*) from public.audit_logs
       where tenant_id = '${tenantA}' and action = 'team.owner.role_changed'
         and verdict ->> 'target_user_id' = '${ownerA}') <> current_setting('aidr.test.owner_audit_baseline')::integer
     or exists (select 1 from public.admin_audit_logs
       where tenant_id = '${tenantA}' and target_user_id = '${ownerA}'
         and action = 'team.member.removed')
  then raise exception 'final owner was removed or audibly changed'; end if;
end $$;

rollback;
select 'MEMBER_REMOVAL_AUDIT_ROLLBACK';
`;

const result = spawnSync("docker", [
  "exec", "-i", "-e", "PGPASSWORD=postgres", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
  "-U", "supabase_admin", "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `member-removal PostgreSQL regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /MEMBER_REMOVAL_AUDIT_ROLLBACK/);
console.log("Member-removal PostgreSQL test passed: synchronized deletion and one audit, cross-tenant denial, owner stream separation and final-owner preservation; fixtures rolled back.");
