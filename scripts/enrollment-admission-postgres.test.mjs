// Run only against a disposable, fully migrated Supabase PostgreSQL container
// (CI: the pinned local Supabase stack after `supabase db reset`). Fixtures and
// assertions share one transaction and are rolled back.
//
// Migration 28 installed the enrollment admission triggers on api_keys,
// enrollment_tokens and agents; migration 34 (tenant GA admission) replaced
// their function so every write consumes public.tenant_admission_capacity()
// and fails with `tenant_not_admitted`. This suite exercises the installed
// schema in the pilot admission mode those triggers were introduced for.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
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
const team = randomUUID();
const marker = randomUUID().replaceAll("-", "");
const hash = () => randomBytes(32).toString("hex");
const legacy = {
	personalKey: hash(), personalToken: hash(), teamKey: hash(), teamToken: hash(),
};
const approved = { key: hash(), token: hash(), iid: `approved-${marker}` };
const admissionTriggers = [
	["public.api_keys", "api_keys_enrollment_admission"],
	["public.enrollment_tokens", "enrollment_tokens_admission"],
	["public.agents", "agents_enrollment_admission"],
];
const setTriggers = (state) => admissionTriggers
	.map(([table, trigger]) => `alter table ${table} ${state} trigger ${trigger};`).join("\n");

function deniedWrites(tenant, label) {
	return `
-- ${label}: every new credential or agent registration must fail closed.
select pg_temp.expect_denied($statement$
  insert into public.api_keys(user_id, tenant_id, key_hash)
  values ('${owner}', '${tenant}', '${hash()}')
$statement$);
select pg_temp.expect_denied($statement$
  insert into public.enrollment_tokens(user_id, tenant_id, token_hash, expires_at)
  values ('${owner}', '${tenant}', '${hash()}', now() + interval '1 hour')
$statement$);
select pg_temp.expect_denied($statement$
  insert into public.agents(user_id, tenant_id, iid)
  values ('${owner}', '${tenant}', '${label}-${marker}')
$statement$);
`;
}

function deniedRotations(keys, tokens) {
	return [
		...keys.map((key) => `select pg_temp.expect_denied($statement$
  update public.api_keys set key_hash = '${hash()}' where key_hash = '${key}'
$statement$);`),
		...tokens.map((token) => `select pg_temp.expect_denied($statement$
  update public.enrollment_tokens set token_hash = '${hash()}' where token_hash = '${token}'
$statement$);`),
	].join("\n");
}

const sql = String.raw`
\set ON_ERROR_STOP on
begin;

create function pg_temp.expect_error(statement text, expected text) returns void
language plpgsql as $function$
declare actual text;
begin
  begin
    execute statement;
  exception when insufficient_privilege then
    get stacked diagnostics actual = message_text;
    if actual = expected then return; end if;
    raise;
  end;
  raise exception 'expected %: %', expected, statement;
end;
$function$;
create function pg_temp.expect_denied(statement text) returns void
language sql as $function$ select pg_temp.expect_error(statement, 'tenant_not_admitted') $function$;

do $checks$ begin
  if (select count(*) from pg_trigger
      where tgfoid = 'public.require_enrollment_admission()'::regprocedure
        and tgname in ('api_keys_enrollment_admission', 'enrollment_tokens_admission',
          'agents_enrollment_admission')
        and not tgisinternal) <> 3 then
    raise exception 'enrollment admission triggers are not installed';
  end if;
  if to_regprocedure('public.tenant_admission_capacity(uuid)') is null
    or position('tenant_admission_capacity' in
      pg_get_functiondef('public.require_enrollment_admission()'::regprocedure)) = 0 then
    raise exception 'enrollment admission does not consume tenant admission capacity (migration 34+ required)';
  end if;
end $checks$;

-- Start from the fail-closed default; other suites may share this database.
update app.tenant_admission_config set mode = 'unconfigured', configured_at = null where singleton;

-- The Auth trigger supplies the one-seat personal tenant and entitlement.
insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values ('${owner}', 'enrollment-admission-${marker}@example.invalid',
  'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000',
  '{}'::jsonb, '{}'::jsonb);
insert into public.tenants(id, name, kind, created_by)
values ('${team}', 'Admission team ${marker}', 'team', '${owner}');
insert into public.teams(id, tenant_id, name, plan)
values ('${team}', '${team}', 'Admission team ${marker}', 'free');
insert into public.tenant_members(tenant_id, user_id, role)
values ('${team}', '${owner}', 'owner');
insert into public.team_members(team_id, tenant_id, user_id, role)
values ('${team}', '${team}', '${owner}', 'owner');
insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents)
values ('${owner}', '${team}', 1, 0);

-- Credentials issued before the admission gate existed: seed them with only
-- the admission triggers suspended (inside this rolled-back transaction).
-- A legacy key/token must not rotate while its tenant is not admitted.
${setTriggers("disable")}
insert into public.api_keys(user_id, tenant_id, key_hash)
values ('${owner}', '${owner}', '${legacy.personalKey}'),
       ('${owner}', '${team}', '${legacy.teamKey}');
insert into public.enrollment_tokens(user_id, tenant_id, token_hash, expires_at)
values ('${owner}', '${owner}', '${legacy.personalToken}', now() + interval '1 hour'),
       ('${owner}', '${team}', '${legacy.teamToken}', now() + interval '1 hour');
insert into public.agents(user_id, tenant_id, iid)
values ('${owner}', '${owner}', 'legacy-${marker}');
${setTriggers("enable")}

do $checks$ begin
  if not exists (select 1 from public.entitlements
      where tenant_id = '${owner}' and included_agents + extra_agents > 0) then
    raise exception 'fixture has no free personal entitlement';
  end if;
end $checks$;

-- No admission mode configured: nothing is admitted, not even a seated tenant.
${deniedWrites(owner, "unconfigured-personal")}
${deniedWrites(team, "unconfigured-team")}

-- Pilot mode without a tenant-scoped approval: seats alone admit nothing.
update app.tenant_admission_config set mode = 'pilot', configured_at = now() where singleton;
${deniedWrites(owner, "unapproved-personal")}
${deniedWrites(team, "unapproved-team")}
${deniedRotations([legacy.personalKey, legacy.teamKey], [legacy.personalToken, legacy.teamToken])}

-- A tenant-scoped approval AND a positive seat permit all three registration
-- paths. The browser's plan label grants nothing by itself.
insert into public.pilot_applications(user_id, tenant_id, status)
values ('${owner}', '${team}', 'approved');
insert into public.api_keys(user_id, tenant_id, key_hash)
values ('${owner}', '${team}', '${approved.key}');
insert into public.enrollment_tokens(user_id, tenant_id, token_hash, expires_at)
values ('${owner}', '${team}', '${approved.token}', now() + interval '1 hour');
insert into public.agents(user_id, tenant_id, iid)
values ('${owner}', '${team}', '${approved.iid}');
insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
select '${owner}', '${team}', id, 'admitted-${marker}', 'admission_test', '{}'::jsonb
from public.agents where tenant_id = '${team}' and iid = '${approved.iid}';
-- The team's approval does not leak to the owner's personal tenant.
${deniedWrites(owner, "approved-team-only")}

-- A pilot approval is not an admission in any other deployment mode.
update app.tenant_admission_config set mode = 'cloud' where singleton;
${deniedWrites(team, "cloud-mode-pilot-only")}
update app.tenant_admission_config set mode = 'pilot' where singleton;

-- Withdrawal blocks new writes attempted even with a previously issued key.
-- An already registered agent row can still be touched, but since migration
-- 34 its telemetry is refused until the tenant is admitted again.
update public.pilot_applications set status = 'pending'
where user_id = '${owner}' and tenant_id = '${team}';
${deniedWrites(team, "revoked-approval")}
${deniedRotations([approved.key], [approved.token])}
update public.agents set last_seen = last_seen + interval '1 minute'
where tenant_id = '${team}' and iid = '${approved.iid}';
select pg_temp.expect_error(format($statement$
  insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
  values ('${owner}', '${team}', %L, 'withdrawn-${marker}', 'admission_test', '{}'::jsonb)
$statement$, (select id from public.agents where tenant_id = '${team}' and iid = '${approved.iid}')),
  'agent_seat_not_authorized');

update public.pilot_applications set status = 'approved'
where user_id = '${owner}' and tenant_id = '${team}';
delete from public.entitlements where tenant_id = '${team}';
${deniedWrites(team, "missing-entitlement")}
insert into public.entitlements(user_id, tenant_id, included_agents, extra_agents)
values ('${owner}', '${team}', 0, 0);
${deniedWrites(team, "zero-seats")}

do $checks$ begin
  if (select count(*) from public.api_keys where tenant_id = '${owner}') <> 1
    or (select count(*) from public.enrollment_tokens where tenant_id = '${owner}') <> 1
    or (select count(*) from public.agents where tenant_id = '${owner}') <> 1
    or (select count(*) from public.api_keys where tenant_id = '${team}') <> 2
    or (select count(*) from public.enrollment_tokens where tenant_id = '${team}') <> 2
    or (select count(*) from public.agents where tenant_id = '${team}') <> 1 then
    raise exception 'a denied enrollment write leaked or an approved write failed';
  end if;
  if not exists (select 1 from public.api_keys where key_hash = '${legacy.personalKey}')
    or not exists (select 1 from public.enrollment_tokens where token_hash = '${legacy.personalToken}')
    or not exists (select 1 from public.api_keys where key_hash = '${legacy.teamKey}')
    or not exists (select 1 from public.enrollment_tokens where token_hash = '${legacy.teamToken}')
    or not exists (select 1 from public.api_keys where key_hash = '${approved.key}')
    or not exists (select 1 from public.enrollment_tokens where token_hash = '${approved.token}') then
    raise exception 'a denied credential rotation changed its hash';
  end if;
  if (select count(*) from public.events where tenant_id = '${team}'
      and event_id in ('admitted-${marker}', 'withdrawn-${marker}')) <> 1
    or not exists (select 1 from public.events where tenant_id = '${team}'
      and event_id = 'admitted-${marker}') then
    raise exception 'admitted telemetry was blocked or withdrawn telemetry leaked';
  end if;
end $checks$;

rollback;
select 'ENROLLMENT_ADMISSION_ROLLBACK_OK';
`;

const result = spawnSync(docker, [
	"exec", "-i", container, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1",
	"-U", dbUser, "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `enrollment admission PostgreSQL regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /ENROLLMENT_ADMISSION_ROLLBACK_OK/);
console.log("Enrollment admission PostgreSQL passed (installed schema): unconfigured and unapproved writes/rotations denied, approved pilot seat path, cloud-mode/withdrawal/no-seat gates, withdrawn telemetry refused; rolled back.");
