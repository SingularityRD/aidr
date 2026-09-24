// Run after `supabase start && supabase db reset --local --no-seed`:
//   AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr node scripts/pilot-application-atomic-audit-postgres.mjs
// Exercises the shipped RPCs and real roles; the fixture transaction is rolled back.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name the disposable Supabase db container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");

const [target, admin, outsider] = Array.from({ length: 3 }, () => randomUUID());
const marker = randomUUID().replaceAll("-", "");
const team = "current_setting('aidr.pilot_test.team')::uuid";
const sql = String.raw`
\set ON_ERROR_STOP on
begin;

do $$ begin
  if not has_function_privilege('service_role', 'public.submit_pilot_application(uuid,uuid,text)', 'EXECUTE')
     or not has_function_privilege('service_role', 'public.decide_pilot_application(uuid,uuid,uuid,text,text,text)', 'EXECUTE')
     or has_function_privilege('anon', 'public.submit_pilot_application(uuid,uuid,text)', 'EXECUTE')
     or has_function_privilege('authenticated', 'public.submit_pilot_application(uuid,uuid,text)', 'EXECUTE')
     or has_function_privilege('anon', 'public.decide_pilot_application(uuid,uuid,uuid,text,text,text)', 'EXECUTE')
     or has_function_privilege('authenticated', 'public.decide_pilot_application(uuid,uuid,uuid,text,text,text)', 'EXECUTE')
  then raise exception 'pilot RPC privilege boundary failed'; end if;
end $$;

insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values
  ('${target}', 'pilot-target-${marker}@example.invalid', 'authenticated', 'authenticated',
   '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${admin}', 'pilot-admin-${marker}@example.invalid', 'authenticated', 'authenticated',
   '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${outsider}', 'pilot-outsider-${marker}@example.invalid', 'authenticated', 'authenticated',
   '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
insert into public.pilot_admins(user_id) values ('${admin}');
do $$ begin
  if not exists (
    select 1 from public.tenant_members
    where tenant_id = '${target}' and user_id = '${target}' and role = 'owner'
  ) or (select count(*) from public.tenants
          where created_by = '${target}' and kind = 'team') <> 1 then
    raise exception 'pilot fixture tenant bootstrap failed';
  end if;
end $$;
select set_config('aidr.pilot_test.team',
  (select id::text from public.tenants where created_by = '${target}' and kind = 'team'), true);

create function pg_temp.expect_error(statement text, expected_state text, expected_message text)
returns void language plpgsql as $$
declare actual_state text; actual_message text;
begin
  begin
    execute statement;
  exception when others then
    get stacked diagnostics actual_state = returned_sqlstate, actual_message = message_text;
    if actual_state <> expected_state or actual_message <> expected_message then
      raise exception 'expected % / %, got % / %',
        expected_state, expected_message, actual_state, actual_message;
    end if;
    return;
  end;
  raise exception 'expected % / %, statement succeeded', expected_state, expected_message;
end $$;

create function pg_temp.fail_pilot_audit()
returns trigger language plpgsql as $$
begin
  raise exception 'pilot_audit_failure' using errcode = 'P0001';
end $$;
create trigger pilot_atomic_audit_reject
before insert on public.admin_audit_logs
for each row when (new.action like 'pilot.%')
execute function pg_temp.fail_pilot_audit();

-- A failed audit on a new application cannot leave a pending row behind.
set role service_role;
select pg_temp.expect_error(
  $call$select public.submit_pilot_application('${target}', '${target}', 'initial use case')$call$,
  'P0001', 'pilot_audit_failure');
reset role;
do $$ begin
  if exists (select 1 from public.pilot_applications
             where user_id = '${target}' and tenant_id = '${target}')
     or exists (select 1 from public.admin_audit_logs
                 where action = 'pilot.apply' and target_user_id = '${target}'
                   and tenant_id = '${target}') then
    raise exception 'failed pilot apply left a row or audit';
  end if;
end $$;

drop trigger pilot_atomic_audit_reject on public.admin_audit_logs;
set role service_role;
do $$ begin
  if public.submit_pilot_application('${target}', '${target}', 'initial use case')
       <> '{"status":"pending"}'::jsonb then
    raise exception 'pilot apply returned the wrong status';
  end if;
end $$;
reset role;
do $$ begin
  if (select count(*) from public.pilot_applications
      where user_id = '${target}' and tenant_id = '${target}'
        and status = 'pending' and notes = 'initial use case') <> 1
     or (select count(*) from public.admin_audit_logs
         where action = 'pilot.apply' and actor_user_id = '${target}'
           and target_user_id = '${target}' and tenant_id = '${target}'
           and detail ->> 'has_use_case' = 'true') <> 1 then
    raise exception 'successful pilot apply needs one row and one matching audit';
  end if;
end $$;

-- A failed audit on an existing row cannot change its notes or status.
create trigger pilot_atomic_audit_reject
before insert on public.admin_audit_logs
for each row when (new.action like 'pilot.%')
execute function pg_temp.fail_pilot_audit();
set role service_role;
select pg_temp.expect_error(
  $call$select public.submit_pilot_application('${target}', '${target}', 'uncommitted update')$call$,
  'P0001', 'pilot_audit_failure');
select pg_temp.expect_error(
  $call$select public.decide_pilot_application('${admin}', '${target}', '${target}', 'approve', 'cohort-a', 'reviewed')$call$,
  'P0001', 'pilot_audit_failure');
reset role;
do $$ begin
  if (select count(*) from public.pilot_applications
      where user_id = '${target}' and tenant_id = '${target}'
        and status = 'pending' and cohort is null and notes = 'initial use case') <> 1
     or (select count(*) from public.admin_audit_logs
         where target_user_id = '${target}' and tenant_id = '${target}'
           and action = 'pilot.apply') <> 1
     or exists (select 1 from public.admin_audit_logs
                 where target_user_id = '${target}' and tenant_id = '${target}'
                   and action = 'pilot.approve') then
    raise exception 'failed pilot audit changed the application or receipt count';
  end if;
end $$;

drop trigger pilot_atomic_audit_reject on public.admin_audit_logs;
set role service_role;
do $$ begin
  if public.decide_pilot_application('${admin}', '${target}', '${target}',
       'approve', 'cohort-a', 'reviewed')
       <> jsonb_build_object('tenant_id', '${target}'::uuid, 'status', 'approved') then
    raise exception 'pilot approval returned the wrong tenant or status';
  end if;
end $$;
reset role;
do $$ begin
  if (select count(*) from public.pilot_applications
      where user_id = '${target}' and tenant_id = '${target}'
        and status = 'approved' and cohort = 'cohort-a' and notes = 'reviewed') <> 1
     or (select count(*) from public.admin_audit_logs
         where action = 'pilot.approve' and actor_user_id = '${admin}'
           and target_user_id = '${target}' and tenant_id = '${target}'
           and detail ->> 'cohort' = 'cohort-a'
           and detail ->> 'notes' = 'reviewed') <> 1 then
    raise exception 'pilot approval needs one changed row and one matching audit';
  end if;
end $$;

-- Accepted retries add receipts without multiplying the tenant-scoped row.
-- Submitting again after approval must preserve the approved status.
set role service_role;
do $$ begin
  if public.submit_pilot_application('${target}', '${target}', 'follow-up use case')
       <> '{"status":"approved"}'::jsonb then
    raise exception 'repeated pilot apply changed the approved status';
  end if;
  if public.decide_pilot_application('${admin}', '${target}', '${target}',
       'approve', 'cohort-a', 'reviewed')
       <> jsonb_build_object('tenant_id', '${target}'::uuid, 'status', 'approved') then
    raise exception 'repeated pilot approval returned the wrong result';
  end if;
end $$;
reset role;
do $$ begin
  if (select count(*) from public.pilot_applications
      where user_id = '${target}' and tenant_id = '${target}'
        and status = 'approved' and cohort = 'cohort-a' and notes = 'reviewed') <> 1
     or (select count(*) from public.admin_audit_logs
         where action = 'pilot.apply' and actor_user_id = '${target}'
           and target_user_id = '${target}' and tenant_id = '${target}') <> 2
     or (select count(*) from public.admin_audit_logs
         where action = 'pilot.approve' and actor_user_id = '${admin}'
           and target_user_id = '${target}' and tenant_id = '${target}') <> 2 then
    raise exception 'accepted pilot retries need one row and one receipt each';
  end if;
end $$;

-- Authorization and tenant checks must reject before a row or audit is written.
set role service_role;
select pg_temp.expect_error(
  $call$select public.decide_pilot_application('${outsider}', '${target}', '${target}', 'deny', null, null)$call$,
  '42501', 'pilot_admin_forbidden');
select pg_temp.expect_error(
  $call$select public.submit_pilot_application('${target}', '${admin}', 'wrong tenant')$call$,
  '42501', 'tenant_access_denied');
select pg_temp.expect_error(
  $call$select public.decide_pilot_application('${admin}', '${target}', '${admin}', 'deny', null, null)$call$,
  '42501', 'tenant_access_denied');
reset role;
do $$ begin
  if exists (select 1 from public.pilot_applications
              where user_id = '${target}' and tenant_id = '${admin}')
     or exists (select 1 from public.admin_audit_logs
                 where target_user_id = '${target}' and tenant_id = '${admin}'
                   and action like 'pilot.%')
     or (select status from public.pilot_applications
         where user_id = '${target}' and tenant_id = '${target}') <> 'approved' then
    raise exception 'pilot authorization or tenant rejection changed state';
  end if;
end $$;

-- A user with two applications must name the tenant; an explicit team decision
-- cannot overwrite the personal tenant's approval.
set role service_role;
do $$ begin
  if public.submit_pilot_application('${target}', ${team}, 'team use case')
       <> '{"status":"pending"}'::jsonb then
    raise exception 'team pilot apply returned the wrong status';
  end if;
end $$;
select pg_temp.expect_error(
  $call$select public.decide_pilot_application('${admin}', '${target}', null, 'deny', null, null)$call$,
  '22023', 'tenant_required');
do $$ begin
  if public.decide_pilot_application('${admin}', '${target}', ${team},
       'deny', 'later', 'not ready')
       <> jsonb_build_object('tenant_id', ${team}, 'status', 'denied') then
    raise exception 'team pilot decision returned the wrong tenant or status';
  end if;
end $$;
reset role;
do $$ begin
  if (select count(*) from public.pilot_applications
       where user_id = '${target}' and tenant_id = '${target}'
         and status = 'approved' and cohort = 'cohort-a') <> 1
     or (select count(*) from public.pilot_applications
         where user_id = '${target}' and tenant_id = ${team}
           and status = 'denied' and cohort = 'later') <> 1
     or (select count(*) from public.admin_audit_logs
         where action = 'pilot.deny' and actor_user_id = '${admin}'
           and target_user_id = '${target}' and tenant_id = ${team}) <> 1
     or (select count(*) from public.admin_audit_logs
         where action = 'pilot.apply' and target_user_id = '${target}'
           and tenant_id = ${team}) <> 1 then
    raise exception 'tenant-scoped pilot decision or audit is incorrect';
  end if;
end $$;

rollback;
select 'PILOT_APPLICATION_ATOMIC_AUDIT_ROLLBACK';
`;

const result = spawnSync("docker", [
	"exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
	"-U", "postgres", "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `pilot application atomic audit regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /PILOT_APPLICATION_ATOMIC_AUDIT_ROLLBACK/);
console.log("Pilot application PostgreSQL audit passed: apply/update/decision rollback, service role, admin and tenant checks; fixtures rolled back.");
