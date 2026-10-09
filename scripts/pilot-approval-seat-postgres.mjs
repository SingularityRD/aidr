// Run after an isolated `supabase db reset --local --no-seed`.
// The fixture transaction is rolled back, including its users and pilot grants.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name the disposable Supabase db container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");

const [owner, admin] = [randomUUID(), randomUUID()];
const marker = randomUUID().replaceAll("-", "");
const team = "current_setting('aidr.pilot_seat.team')::uuid";
const sql = String.raw`
\set ON_ERROR_STOP on
begin;

insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values
  ('${owner}', 'pilot-seat-owner-${marker}@example.invalid', 'authenticated', 'authenticated',
   '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
  ('${admin}', 'pilot-seat-admin-${marker}@example.invalid', 'authenticated', 'authenticated',
   '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
insert into public.pilot_admins(user_id) values ('${admin}');
select set_config('aidr.pilot_seat.team',
  (select id::text from public.tenants where created_by = '${owner}' and kind = 'team'), true);

do $$ begin
  if exists (select 1 from public.entitlements where tenant_id = ${team}) then
    raise exception 'new free team unexpectedly has an entitlement';
  end if;
end $$;

create function pg_temp.expect_forbidden(statement text)
returns void language plpgsql as $$
declare actual_state text;
begin
  begin
    execute statement;
  exception when others then
    get stacked diagnostics actual_state = returned_sqlstate;
    if actual_state <> '42501' then
      raise exception 'expected SQLSTATE 42501, got %', actual_state;
    end if;
    return;
  end;
  raise exception 'authenticated caller forged pilot approval';
end $$;
grant execute on function pg_temp.expect_forbidden(text) to anon, authenticated, service_role;

set role authenticated;
select set_config('request.jwt.claim.sub', '${owner}', true);
select set_config('request.jwt.claim.role', 'authenticated', true);
select pg_temp.expect_forbidden(
  $call$insert into public.pilot_applications(user_id, tenant_id, status)
        values ('${owner}', ${team}, 'approved')$call$);
reset role;

set role service_role;
select public.submit_pilot_application('${owner}', ${team}, 'pilot seat request');
reset role;
set role authenticated;
select set_config('request.jwt.claim.sub', '${owner}', true);
select set_config('request.jwt.claim.role', 'authenticated', true);
select pg_temp.expect_forbidden(
  $call$update public.pilot_applications set status = 'approved'
        where user_id = '${owner}' and tenant_id = ${team}$call$);
reset role;

set role service_role;
select public.decide_pilot_application('${admin}', '${owner}', ${team}, 'deny', null, 'not ready');
reset role;
do $$ begin
  if exists (select 1 from public.entitlements where tenant_id = ${team}) then
    raise exception 'denied pilot received an agent seat';
  end if;
end $$;

create function pg_temp.reject_pilot_audit()
returns trigger language plpgsql as $$
begin
  raise exception 'pilot_audit_failure' using errcode = 'P0001';
end $$;
create trigger reject_pilot_approval_audit
before insert on public.admin_audit_logs
for each row when (new.action = 'pilot.approve')
execute function pg_temp.reject_pilot_audit();

set role service_role;
do $$ begin
  begin
    perform public.decide_pilot_application('${admin}', '${owner}', ${team}, 'approve', 'pilot', 'reviewed');
    raise exception 'approval should have failed with its audit' using errcode = 'ZX001';
  exception when sqlstate 'P0001' then
    null;
  end;
end $$;
reset role;
do $$ begin
  if exists (select 1 from public.entitlements where tenant_id = ${team})
     or (select status from public.pilot_applications
          where user_id = '${owner}' and tenant_id = ${team}) <> 'denied' then
    raise exception 'failed approval committed a seat or pilot status';
  end if;
end $$;

drop trigger reject_pilot_approval_audit on public.admin_audit_logs;
set role service_role;
select public.decide_pilot_application('${admin}', '${owner}', ${team}, 'approve', 'pilot', 'reviewed');
reset role;
do $$ begin
  if (select status from public.pilot_applications
       where user_id = '${owner}' and tenant_id = ${team}) <> 'approved'
     or (select included_agents from public.entitlements
          where tenant_id = ${team}) <> 1
     or (select extra_agents from public.entitlements
          where tenant_id = ${team}) <> 0 then
    raise exception 'approved pilot did not receive exactly one tenant seat';
  end if;
end $$;

update public.entitlements set included_agents = 7, extra_agents = 3 where tenant_id = ${team};
set role service_role;
select public.decide_pilot_application('${admin}', '${owner}', ${team}, 'approve', 'pilot', 'retry');
reset role;
do $$ begin
  if (select included_agents from public.entitlements
       where tenant_id = ${team}) <> 7
     or (select extra_agents from public.entitlements
          where tenant_id = ${team}) <> 3 then
    raise exception 'repeat pilot approval reduced an existing customer allocation';
  end if;
end $$;

rollback;
select 'PILOT_APPROVAL_SEAT_ROLLBACK';
`;

const result = spawnSync("docker", [
	"exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
	"-U", "postgres", "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `pilot approval seat regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /PILOT_APPROVAL_SEAT_ROLLBACK/);
console.log("Pilot approval PostgreSQL seat grant passed: deny, audit rollback, one-seat grant, and allocation preservation.");
