// Run only against a disposable, locally reset Supabase database:
//   AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr AIDR_TEST_DISPOSABLE_DB=1 node scripts/owner-role-audit-postgres.mjs
// Every fixture and audit row is rolled back, including on a failed assertion.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.equal(process.env.AIDR_TEST_DISPOSABLE_DB, "1", "confirm a disposable database with AIDR_TEST_DISPOSABLE_DB=1");
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name the disposable local Supabase db container");
assert.match(container, /^supabase_db_[A-Za-z0-9_.-]+$/, "refusing a non-Supabase database container");

const [owner, admin, member, bootstrap, tenant] = Array.from({ length: 5 }, () => randomUUID());
const marker = randomUUID().replaceAll("-", "");
const issuedAt = Math.floor(Date.now() / 1000);
const context = (userId, aal) => `
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
  if not exists (
    select 1 from pg_trigger
    where tgrelid = 'public.team_members'::regclass
      and not tgisinternal and tgname = 'team_members_owner_guard'
  ) then raise exception 'owner guard migration is not installed'; end if;
end $$;

insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values
  ('${owner}', 'owner-role-owner-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${admin}', 'owner-role-admin-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${member}', 'owner-role-member-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${bootstrap}', 'owner-role-bootstrap-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
insert into public.tenants(id, name, kind, created_by)
values ('${tenant}', 'Owner role ${marker}', 'team', '${owner}');
insert into public.teams(id, tenant_id, name, plan)
values ('${tenant}', '${tenant}', 'Owner role ${marker}', 'free');
insert into public.team_members(team_id, tenant_id, user_id, role)
values ('${tenant}', '${tenant}', '${owner}', 'owner'),
       ('${tenant}', '${tenant}', '${admin}', 'admin'),
       ('${tenant}', '${tenant}', '${member}', 'member');
do $$ begin
  perform set_config('aidr.test.owner_audit_baseline',
    (select count(*)::text from public.admin_audit_logs
      where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
        and target_user_id = '${member}'), true);
  perform set_config('aidr.test.original_owner_audit_baseline',
    (select count(*)::text from public.admin_audit_logs
      where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
        and target_user_id = '${owner}'), true);
end $$;

-- The optional tenant-wide MFA policy is off. Owner-role mutation must still
-- require AAL2; the ordinary membership RLS must not be the only barrier.
${context(owner, "aal1")}
do $$ declare v_rows integer; begin
  begin
    update public.team_members set role = 'owner'
      where team_id = '${tenant}' and user_id = '${member}';
    get diagnostics v_rows = row_count;
    raise exception 'AAL1 owner promotion returned % rows without denial', v_rows;
  exception when others then
    if sqlstate <> '42501' then raise; end if;
  end;
end $$;
${resetContext}

-- A JWT that says AAL2 but has no subject cannot borrow an owner identity.
select set_config('request.jwt.claim.sub', '', true);
select set_config('request.jwt.claims', '{"role":"authenticated","aal":"aal2","iat":${issuedAt}}', true);
set session authorization authenticator;
set role authenticated;
do $$ declare v_rows integer; begin
  if auth.uid() is not null then raise exception 'missing subject unexpectedly resolved to a user'; end if;
  begin
    update public.team_members set role = 'owner'
      where team_id = '${tenant}' and user_id = '${member}';
    get diagnostics v_rows = row_count;
    if v_rows <> 0 then raise exception 'subjectless AAL2 promoted % rows', v_rows; end if;
  exception when insufficient_privilege then null;
  end;
end $$;
${resetContext}

${context(admin, "aal2")}
do $$ declare v_rows integer; begin
  begin
    update public.team_members set role = 'owner'
      where team_id = '${tenant}' and user_id = '${member}';
    get diagnostics v_rows = row_count;
    raise exception 'admin owner-promotion returned % rows without denial', v_rows;
  exception when others then
    if sqlstate <> '42501' then raise; end if;
  end;
end $$;
${resetContext}

-- Browser clients may edit a role, never a membership identity/key.
${context(owner, "aal2")}
do $$ begin
  begin
    update public.team_members set user_id = '${bootstrap}'
      where team_id = '${tenant}' and user_id = '${member}';
    raise exception 'browser owner changed a membership key';
  exception when insufficient_privilege then null;
  end;
end $$;
${resetContext}

-- A trusted service-role caller also cannot rebind a membership identity.
-- Otherwise the AFTER sync upserts the new canonical row and leaves the old
-- tenant_members row authorized.
select set_config('request.jwt.claim.sub', '', true);
select set_config('request.jwt.claims', '{"role":"service_role"}', true);
set session authorization authenticator;
set role service_role;
do $$ declare v_key text; begin
  if session_user <> 'authenticator' or current_user <> 'service_role'
     or not has_column_privilege('service_role', 'public.team_members', 'user_id', 'UPDATE')
     or not has_column_privilege('service_role', 'public.team_members', 'team_id', 'UPDATE')
     or not has_column_privilege('service_role', 'public.team_members', 'tenant_id', 'UPDATE')
  then raise exception 'service-role identity test did not reach the trigger'; end if;
  foreach v_key in array array['user_id', 'team_id', 'tenant_id'] loop
    begin
      if v_key = 'user_id' then
        update public.team_members set user_id = '${bootstrap}'
          where team_id = '${tenant}' and user_id = '${member}';
      elsif v_key = 'team_id' then
        update public.team_members set team_id = gen_random_uuid()
          where team_id = '${tenant}' and user_id = '${member}';
      else
        update public.team_members set tenant_id = gen_random_uuid()
          where team_id = '${tenant}' and user_id = '${member}';
      end if;
      raise exception 'service role changed % without denial', v_key;
    exception when others then
      if sqlstate <> '42501' then raise; end if;
    end;
  end loop;
end $$;
${resetContext}

do $$ begin
  if (select role from public.team_members where team_id = '${tenant}' and user_id = '${member}') is distinct from 'member'
     or (select role from public.tenant_members where tenant_id = '${tenant}' and user_id = '${member}') is distinct from 'member'
     or exists (select 1 from public.team_members where user_id = '${bootstrap}' and tenant_id = '${tenant}')
     or exists (select 1 from public.tenant_members where user_id = '${bootstrap}' and tenant_id = '${tenant}')
     or (select count(*) from public.team_members where user_id = '${member}' and tenant_id = '${tenant}') <> 1
     or (select count(*) from public.tenant_members where user_id = '${member}' and tenant_id = '${tenant}') <> 1
     or (select count(*) from public.admin_audit_logs
         where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
           and target_user_id = '${member}') <> current_setting('aidr.test.owner_audit_baseline')::integer
     or exists (select 1 from public.audit_logs
         where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
           and verdict ->> 'target_user_id' = '${member}')
  then raise exception 'denied promotion changed membership or wrote an audit'; end if;
end $$;

${context(owner, "aal2")}
do $$ declare v_rows integer; begin
  update public.team_members set role = 'owner'
    where team_id = '${tenant}' and user_id = '${member}';
  get diagnostics v_rows = row_count;
  if v_rows <> 1 then raise exception 'owner promotion changed % rows', v_rows; end if;
end $$;
${resetContext}
do $$ begin
  if (select role from public.team_members where team_id = '${tenant}' and user_id = '${member}') is distinct from 'owner'
     or (select role from public.tenant_members where tenant_id = '${tenant}' and user_id = '${member}') is distinct from 'owner'
     or (select count(*) from public.admin_audit_logs
         where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
           and actor_user_id = '${owner}' and target_user_id = '${member}'
           and detail ->> 'old_role' = 'member' and detail ->> 'new_role' = 'owner') <> 1
     or (select count(*) from public.admin_audit_logs
         where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
           and target_user_id = '${member}') <> current_setting('aidr.test.owner_audit_baseline')::integer + 1
     or (select count(*) from public.audit_logs c
         join public.admin_audit_logs a on a.detail ->> 'event_id' = c.verdict ->> 'event_id'
         where c.tenant_id = '${tenant}' and c.team_id = '${tenant}'
           and c.user_id = '${owner}' and c.action = 'team.owner.role_changed'
           and c.verdict ->> 'target_user_id' = '${member}'
           and c.verdict ->> 'old_role' = 'member' and c.verdict ->> 'new_role' = 'owner'
           and a.tenant_id = '${tenant}' and a.target_user_id = '${member}'
           and a.action = c.action and a.actor_user_id = c.user_id) <> 1
     or (select count(*) from public.audit_logs
         where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
           and verdict ->> 'target_user_id' = '${member}') <> 1
  then raise exception 'owner promotion was not synchronized and audited exactly once'; end if;
end $$;

${context(owner, "aal2")}
do $$ declare v_rows integer; begin
  update public.team_members set role = 'member'
    where team_id = '${tenant}' and user_id = '${member}';
  get diagnostics v_rows = row_count;
  if v_rows <> 1 then raise exception 'owner demotion changed % rows', v_rows; end if;
end $$;
${resetContext}
do $$ begin
  if (select role from public.team_members where team_id = '${tenant}' and user_id = '${member}') is distinct from 'member'
     or (select role from public.tenant_members where tenant_id = '${tenant}' and user_id = '${member}') is distinct from 'member'
     or (select count(*) from public.admin_audit_logs
         where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
           and actor_user_id = '${owner}' and target_user_id = '${member}'
           and detail ->> 'old_role' = 'owner' and detail ->> 'new_role' = 'member') <> 1
     or (select count(*) from public.admin_audit_logs
         where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
           and target_user_id = '${member}') <> current_setting('aidr.test.owner_audit_baseline')::integer + 2
     or (select count(*) from public.audit_logs c
         join public.admin_audit_logs a on a.detail ->> 'event_id' = c.verdict ->> 'event_id'
         where c.tenant_id = '${tenant}' and c.team_id = '${tenant}'
           and c.user_id = '${owner}' and c.action = 'team.owner.role_changed'
           and c.verdict ->> 'target_user_id' = '${member}'
           and c.verdict ->> 'old_role' = 'owner' and c.verdict ->> 'new_role' = 'member'
           and a.tenant_id = '${tenant}' and a.target_user_id = '${member}'
           and a.action = c.action and a.actor_user_id = c.user_id) <> 1
     or (select count(*) from public.audit_logs
         where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
           and verdict ->> 'target_user_id' = '${member}') <> 2
  then raise exception 'owner demotion was not synchronized and audited exactly once'; end if;
end $$;

${context(owner, "aal2")}
do $$ begin
  if (select count(*) from public.audit_logs
    where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
      and verdict ->> 'target_user_id' = '${member}') <> 2
  then raise exception 'owner cannot read customer-visible owner audit'; end if;
end $$;
${resetContext}
${context(member, "aal1")}
do $$ begin
  if (select count(*) from public.audit_logs
    where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
      and verdict ->> 'target_user_id' = '${member}') <> 2
  then raise exception 'member cannot read customer-visible owner audit'; end if;
end $$;
${resetContext}

${context(owner, "aal2")}
do $$ declare v_rows integer; begin
  begin
    delete from public.team_members where team_id = '${tenant}' and user_id = '${owner}';
    get diagnostics v_rows = row_count;
    raise exception 'last-owner deletion returned % rows without denial', v_rows;
  exception when others then
    if sqlstate <> '23514' then raise; end if;
  end;
end $$;
${resetContext}
do $$ begin
  if not exists (select 1 from public.team_members where team_id = '${tenant}' and user_id = '${owner}' and role = 'owner')
     or not exists (select 1 from public.tenant_members where tenant_id = '${tenant}' and user_id = '${owner}' and role = 'owner')
     or (select count(*) from public.admin_audit_logs
         where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
           and target_user_id = '${owner}') <> current_setting('aidr.test.original_owner_audit_baseline')::integer
     or (select count(*) from public.audit_logs
         where tenant_id = '${tenant}' and action = 'team.owner.role_changed'
           and verdict ->> 'target_user_id' = '${owner}') <> current_setting('aidr.test.original_owner_audit_baseline')::integer
  then raise exception 'last-owner denial lost owner or changed audit'; end if;
end $$;

-- First-owner creation stays possible at AAL1; this is not an owner transfer.
${context(bootstrap, "aal1")}
do $$ declare v_team public.teams; begin
  v_team := public.create_team_tenant('Bootstrap ${marker}', gen_random_uuid(), 'free');
  perform set_config('aidr.test.bootstrap_team', v_team.id::text, true);
end $$;
${resetContext}
do $$ begin
  if not exists (select 1 from public.team_members
      where team_id = current_setting('aidr.test.bootstrap_team')::uuid
        and user_id = '${bootstrap}' and role = 'owner')
     or not exists (select 1 from public.tenant_members
      where tenant_id = current_setting('aidr.test.bootstrap_team')::uuid
        and user_id = '${bootstrap}' and role = 'owner')
     or (select count(*) from public.audit_logs c
       join public.admin_audit_logs a on a.detail ->> 'event_id' = c.verdict ->> 'event_id'
       where c.tenant_id = current_setting('aidr.test.bootstrap_team')::uuid
         and c.team_id = c.tenant_id and c.user_id = '${bootstrap}'
         and c.action = 'team.owner.role_changed'
         and c.verdict ->> 'target_user_id' = '${bootstrap}'
         and c.verdict ->> 'old_role' is null
         and c.verdict ->> 'new_role' = 'owner'
         and c.verdict ->> 'bootstrap' = 'true'
         and a.tenant_id = c.tenant_id and a.target_user_id = '${bootstrap}'
         and a.action = c.action and a.actor_user_id = c.user_id) <> 1
  then raise exception 'AAL1 creator bootstrap failed'; end if;
end $$;

rollback;
select 'OWNER_ROLE_AUDIT_ROLLBACK';
`;

const result = spawnSync("docker", [
  "exec", "-i", "-e", "PGPASSWORD=postgres", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
  "-U", "supabase_admin", "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `owner-role PostgreSQL regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /OWNER_ROLE_AUDIT_ROLLBACK/);
console.log("Owner-role PostgreSQL test passed: AAL1 and admin denied, AAL2 promotion/demotion audited once, final owner retained, creator bootstrap allowed; fixtures rolled back.");
