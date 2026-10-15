// Run only against a disposable, fully migrated Supabase PostgreSQL container
// (CI: the pinned local Supabase stack after `supabase db reset`). Fixtures and
// assertions share one transaction and are rolled back.
//
// Fleet enrollment keys (C3, 20261014000210_fleet_enrollment_keys.sql):
//   * only an active owner/admin can issue or revoke; every change is audited,
//   * the exchange registers machines up to the key's seat cap, re-enrolls a
//     known machine without using the cap, and still stops at the tenant's own
//     seat admission,
//   * a revoked, expired or orphaned (creator demoted) key never resolves,
//   * browsers see only owners'/admins' rows and never the hash; nobody writes
//     directly.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const container = process.env.AIDR_POSTGRES_DOCKER_CONTAINER;
assert.ok(container, "AIDR_POSTGRES_DOCKER_CONTAINER must name a disposable PostgreSQL container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");
const dockerDesktop = process.env.LOCALAPPDATA
	? resolve(process.env.LOCALAPPDATA, "Programs/DockerDesktop/resources/bin/docker.exe")
	: null;
const docker = process.env.AIDR_DOCKER_BIN ?? (dockerDesktop && existsSync(dockerDesktop) ? dockerDesktop : "docker");
const dbUser = process.env.AIDR_POSTGRES_DB_USER ?? "postgres";
assert.match(dbUser, /^[A-Za-z_][A-Za-z0-9_]*$/, "invalid PostgreSQL role");

const owner = randomUUID();
const admin = randomUUID();
const member = randomUUID();
const team = randomUUID();
const marker = randomUUID().replaceAll("-", "");
const hash = () => randomBytes(32).toString("hex");
const fleetA = hash();
const fleetB = hash();
const now = Math.floor(Date.now() / 1000);
const claims = (user) =>
	`select set_config('request.jwt.claims', '{"sub":"${user}","role":"authenticated","aal":"aal2","iat":${now}}', true);`;

function exchange(fleetHash, iid) {
	return `public.exchange_fleet_enrollment_key('${fleetHash}', '${iid}-${marker}', 'claude-code', null, '${hash()}')`;
}

const sql = String.raw`
\set ON_ERROR_STOP on
begin;

create function pg_temp.expect(actual jsonb, field text, expected text, context text) returns void
language plpgsql as $function$
begin
  if actual ->> field is distinct from expected then
    raise exception '%: expected %=% but got %', context, field, expected, actual;
  end if;
end;
$function$;

-- Start from pilot mode with a tenant-scoped approval and three seats.
update app.tenant_admission_config set mode = 'pilot', configured_at = now() where singleton;
insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values ('${owner}', 'fleet-owner-${marker}@example.invalid', 'authenticated', 'authenticated',
        '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
       ('${admin}', 'fleet-admin-${marker}@example.invalid', 'authenticated', 'authenticated',
        '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb),
       ('${member}', 'fleet-member-${marker}@example.invalid', 'authenticated', 'authenticated',
        '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
insert into public.tenants(id, name, kind, created_by)
values ('${team}', 'Fleet team ${marker}', 'team', '${owner}');
insert into public.teams(id, tenant_id, name, plan)
values ('${team}', '${team}', 'Fleet team ${marker}', 'free');
insert into public.tenant_members(tenant_id, user_id, role)
values ('${team}', '${owner}', 'owner'), ('${team}', '${admin}', 'admin'), ('${team}', '${member}', 'member');
insert into public.team_members(team_id, tenant_id, user_id, role)
values ('${team}', '${team}', '${owner}', 'owner'), ('${team}', '${team}', '${admin}', 'admin'),
       ('${team}', '${team}', '${member}', 'member');
insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents)
values ('${owner}', '${team}', 3, 0);
insert into public.pilot_applications(user_id, tenant_id, status)
values ('${owner}', '${team}', 'approved');

do $checks$
declare r jsonb;
begin
  -- Members cannot issue; admins can, once per hash, with an audit row.
  r := public.issue_fleet_enrollment_key_with_audit('${member}', '${team}', 'm', 5, 30, '${hash()}', 'abcd');
  perform pg_temp.expect(r, 'status', 'forbidden', 'member issue');
  r := public.issue_fleet_enrollment_key_with_audit('${admin}', '${team}', 'laptops', 2, 90, '${fleetA}', 'Ab_-');
  perform pg_temp.expect(r, 'status', 'issued', 'admin issue');
  r := public.issue_fleet_enrollment_key_with_audit('${admin}', '${team}', 'laptops', 2, 90, '${fleetA}', 'Ab_-');
  perform pg_temp.expect(r, 'status', 'issued', 'replayed issue');
  r := public.issue_fleet_enrollment_key_with_audit('${owner}', '${team}', 'servers', 10, 30, '${fleetB}', 'wxyz');
  perform pg_temp.expect(r, 'status', 'issued', 'owner issue');
  if (select count(*) from public.fleet_enrollment_keys where tenant_id = '${team}') <> 2
    or (select count(*) from public.admin_audit_logs where tenant_id = '${team}' and action = 'fleet_key.create') <> 2 then
    raise exception 'issue must create one key and one audit row per hash';
  end if;
  begin
    perform public.issue_fleet_enrollment_key_with_audit('${admin}', '${team}', null, 0, 30, '${hash()}', 'abcd');
    raise exception 'a zero seat cap was accepted';
  exception when invalid_parameter_value then null;
  end;
  begin
    perform public.issue_fleet_enrollment_key_with_audit('${admin}', '${team}', null, 5, 366, '${hash()}', 'abcd');
    raise exception 'a lifetime over 365 days was accepted';
  exception when invalid_parameter_value then null;
  end;

  -- Resolve names the key, tenant and creator; unknown hashes resolve to null.
  r := public.resolve_fleet_enrollment_key('${fleetA}');
  perform pg_temp.expect(r, 'user_id', '${admin}', 'resolve');
  perform pg_temp.expect(r, 'tenant_id', '${team}', 'resolve');
  if public.resolve_fleet_enrollment_key('${hash()}') is not null then
    raise exception 'an unknown fleet key resolved';
  end if;

  -- Seat cap 2: two new machines, re-enrollment is free, a third is refused.
  perform pg_temp.expect(${exchange(fleetA, "host-1")}, 'status', 'enrolled', 'first machine');
  r := ${exchange(fleetA, "host-1")};
  perform pg_temp.expect(r, 'status', 'enrolled', 're-enroll');
  perform pg_temp.expect(r, 'new_agent', 'false', 're-enroll');
  perform pg_temp.expect(${exchange(fleetA, "host-2")}, 'status', 'enrolled', 'second machine');
  r := ${exchange(fleetA, "host-3")};
  perform pg_temp.expect(r, 'status', 'fleet_key_exhausted', 'over the key cap');
  perform pg_temp.expect(${exchange(fleetA, "host-2")}, 'status', 'enrolled', 're-enroll at cap');
  if (select enrolled_count from public.fleet_enrollment_keys where key_hash = '${fleetA}') <> 2
    or (select use_count from public.fleet_enrollment_keys where key_hash = '${fleetA}') <> 4
    or (select count(*) from public.api_keys where tenant_id = '${team}' and user_id = '${admin}') <> 4
    or (select count(*) from public.admin_audit_logs where tenant_id = '${team}' and action = 'fleet_key.enroll') <> 4 then
    raise exception 'fleet exchange counters, keys or audit rows are wrong';
  end if;

  -- The tenant's three seats still bind a key with a larger cap.
  perform pg_temp.expect(${exchange(fleetB, "host-3")}, 'status', 'enrolled', 'third tenant seat');
  r := ${exchange(fleetB, "host-4")};
  perform pg_temp.expect(r, 'status', 'seat_exceeded', 'tenant seat limit');
  if (select enrolled_count from public.fleet_enrollment_keys where key_hash = '${fleetB}') <> 1 then
    raise exception 'a refused seat must not count against the key';
  end if;

  -- Revocation: members cannot, admins can (idempotently, audited once).
  r := public.revoke_fleet_enrollment_key_with_audit('${member}', '${team}',
    (select id from public.fleet_enrollment_keys where key_hash = '${fleetB}'));
  perform pg_temp.expect(r, 'status', 'forbidden', 'member revoke');
  r := public.revoke_fleet_enrollment_key_with_audit('${admin}', '${team}',
    (select id from public.fleet_enrollment_keys where key_hash = '${fleetB}'));
  perform pg_temp.expect(r, 'status', 'revoked', 'admin revoke');
  r := public.revoke_fleet_enrollment_key_with_audit('${admin}', '${team}',
    (select id from public.fleet_enrollment_keys where key_hash = '${fleetB}'));
  perform pg_temp.expect(r, 'status', 'revoked', 'repeated revoke');
  if (select count(*) from public.admin_audit_logs where tenant_id = '${team}' and action = 'fleet_key.revoke') <> 1 then
    raise exception 'revocation must be audited exactly once';
  end if;
  if public.resolve_fleet_enrollment_key('${fleetB}') is not null then
    raise exception 'a revoked fleet key resolved';
  end if;
  perform pg_temp.expect(${exchange(fleetB, "host-3")}, 'status', 'invalid_token', 'revoked exchange');

  -- A creator who loses the admin role takes the key down with them.
  update public.tenant_members set role = 'member' where tenant_id = '${team}' and user_id = '${admin}';
  if public.resolve_fleet_enrollment_key('${fleetA}') is not null then
    raise exception 'a key whose creator was demoted resolved';
  end if;
  perform pg_temp.expect(${exchange(fleetA, "host-1")}, 'status', 'tenant_not_authorized', 'demoted creator');
  update public.tenant_members set role = 'admin' where tenant_id = '${team}' and user_id = '${admin}';

  -- Expiry.
  update public.fleet_enrollment_keys
     set created_at = now() - interval '2 days', expires_at = now() - interval '1 day'
   where key_hash = '${fleetA}';
  if public.resolve_fleet_enrollment_key('${fleetA}') is not null then
    raise exception 'an expired fleet key resolved';
  end if;
  perform pg_temp.expect(${exchange(fleetA, "host-1")}, 'status', 'invalid_token', 'expired exchange');

  -- Issuance counter scope is admitted by the reviewed rate-limit RPC.
  perform public.increment_rate_limit('fleetkey_create:${team}:${admin}', 1, 1);
end $checks$;

-- Browser reads: owners/admins see the rows but never the hash; members see nothing.
${claims(admin)}
set role authenticated;
do $checks$ begin
  if (select count(*) from public.fleet_enrollment_keys where tenant_id = '${team}') <> 2 then
    raise exception 'an admin must see the team fleet keys';
  end if;
  begin
    perform key_hash from public.fleet_enrollment_keys;
    raise exception 'key_hash was readable from a browser session';
  exception when insufficient_privilege then null;
  end;
  begin
    insert into public.fleet_enrollment_keys(tenant_id, created_by, key_hash, key_hint, seat_cap, expires_at)
    values ('${team}', '${admin}', '${hash()}', 'abcd', 5, now() + interval '1 day');
    raise exception 'a browser session inserted a fleet key';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.exchange_fleet_enrollment_key('${fleetA}', 'x', null, null, '${hash()}');
    raise exception 'a browser session called the exchange RPC';
  exception when insufficient_privilege then null;
  end;
end $checks$;
reset role;
${claims(member)}
set role authenticated;
do $checks$ begin
  if (select count(*) from public.fleet_enrollment_keys where tenant_id = '${team}') <> 0 then
    raise exception 'a member must not see fleet keys';
  end if;
end $checks$;
reset role;

rollback;
select 'FLEET_ENROLLMENT_KEYS_ROLLBACK_OK';
`;

const result = spawnSync(docker, [
	"exec", "-i", container, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1",
	"-U", dbUser, "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `fleet enrollment key PostgreSQL regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /FLEET_ENROLLMENT_KEYS_ROLLBACK_OK/);
console.log("Fleet enrollment keys PostgreSQL passed (installed schema): admin-only issue/revoke with audit, seat cap with free re-enrollment, tenant seat admission, revoked/expired/demoted-creator keys refused, browser reads admin-only without the hash; rolled back.");
