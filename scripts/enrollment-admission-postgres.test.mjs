// Run only against a disposable Supabase PostgreSQL container. The migration,
// fixtures, and assertions all share one transaction and are rolled back.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const container = process.env.AIDR_POSTGRES_DOCKER_CONTAINER;
assert.ok(container, "AIDR_POSTGRES_DOCKER_CONTAINER must name a disposable PostgreSQL container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");
const dockerDesktop = process.env.LOCALAPPDATA
	? resolve(process.env.LOCALAPPDATA, "Programs/DockerDesktop/resources/bin/docker.exe")
	: null;
const docker = process.env.AIDR_DOCKER_BIN ?? (dockerDesktop && existsSync(dockerDesktop) ? dockerDesktop : "docker");
const dbUser = process.env.AIDR_POSTGRES_DB_USER ?? "postgres";
assert.match(dbUser, /^[A-Za-z_][A-Za-z0-9_]*$/, "invalid PostgreSQL role");

const migration = readFileSync(
	resolve(dirname(fileURLToPath(import.meta.url)), "../supabase/migrations/20260923000028_enrollment_admission.sql"),
	"utf8",
);
const owner = randomUUID();
const team = randomUUID();
const marker = randomUUID().replaceAll("-", "");
const hash = () => randomBytes(32).toString("hex");
const legacy = {
	personalKey: hash(), personalToken: hash(), teamKey: hash(), teamToken: hash(),
};
const approved = { key: hash(), token: hash(), iid: `approved-${marker}` };

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

const sql = String.raw`
\set ON_ERROR_STOP on
begin;

-- Seed pre-migration credentials too: a legacy key/token must not rotate after
-- admission is withdrawn. The Auth trigger supplies the one-seat personal row.
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
insert into public.api_keys(user_id, tenant_id, key_hash)
values ('${owner}', '${owner}', '${legacy.personalKey}'),
       ('${owner}', '${team}', '${legacy.teamKey}');
insert into public.enrollment_tokens(user_id, tenant_id, token_hash, expires_at)
values ('${owner}', '${owner}', '${legacy.personalToken}', now() + interval '1 hour'),
       ('${owner}', '${team}', '${legacy.teamToken}', now() + interval '1 hour');
insert into public.agents(user_id, tenant_id, iid)
values ('${owner}', '${owner}', 'legacy-${marker}');

${migration}

create function pg_temp.expect_denied(statement text) returns void
language plpgsql as $function$
declare actual text;
begin
  begin
    execute statement;
  exception when insufficient_privilege then
    get stacked diagnostics actual = message_text;
    if actual = 'tenant_enrollment_not_approved' then return; end if;
    raise;
  end;
  raise exception 'expected tenant_enrollment_not_approved: %', statement;
end;
$function$;

do $checks$ begin
  if (select count(*) from pg_trigger where tgname in
      ('api_keys_enrollment_admission', 'enrollment_tokens_admission', 'agents_enrollment_admission')
      and not tgisinternal) <> 3 then
    raise exception 'enrollment admission triggers were not installed';
  end if;
  if not exists (select 1 from public.entitlements
      where tenant_id = '${owner}' and included_agents + extra_agents > 0) then
    raise exception 'fixture has no free personal entitlement';
  end if;
end $checks$;

${deniedWrites(owner, "unapproved-personal")}
${deniedWrites(team, "unapproved-team")}
select pg_temp.expect_denied($statement$
  update public.api_keys set key_hash = '${hash()}'
  where key_hash = '${legacy.personalKey}'
$statement$);
select pg_temp.expect_denied($statement$
  update public.enrollment_tokens set token_hash = '${hash()}'
  where token_hash = '${legacy.personalToken}'
$statement$);
select pg_temp.expect_denied($statement$
  update public.api_keys set key_hash = '${hash()}'
  where key_hash = '${legacy.teamKey}'
$statement$);
select pg_temp.expect_denied($statement$
  update public.enrollment_tokens set token_hash = '${hash()}'
  where token_hash = '${legacy.teamToken}'
$statement$);

-- A tenant-scoped approval AND explicitly allocated positive seat permit all
-- three registration paths. The browser's plan label grants nothing by itself.
insert into public.pilot_applications(user_id, tenant_id, status)
values ('${owner}', '${team}', 'approved');
insert into public.api_keys(user_id, tenant_id, key_hash)
values ('${owner}', '${team}', '${approved.key}');
insert into public.enrollment_tokens(user_id, tenant_id, token_hash, expires_at)
values ('${owner}', '${team}', '${approved.token}', now() + interval '1 hour');
insert into public.agents(user_id, tenant_id, iid)
values ('${owner}', '${team}', '${approved.iid}');

-- Withdrawal blocks even new writes attempted with a previously issued key,
-- while an already connected agent can continue normal telemetry updates.
update public.pilot_applications set status = 'pending'
where user_id = '${owner}' and tenant_id = '${team}';
${deniedWrites(team, "revoked-approval")}
select pg_temp.expect_denied($statement$
  update public.api_keys set key_hash = '${hash()}' where key_hash = '${approved.key}'
$statement$);
select pg_temp.expect_denied($statement$
  update public.enrollment_tokens set token_hash = '${hash()}'
  where token_hash = '${approved.token}'
$statement$);
update public.agents set last_seen = last_seen + interval '1 minute'
where tenant_id = '${team}' and iid = '${approved.iid}';
insert into public.events(user_id, tenant_id, agent_id, event_id, type, payload)
select '${owner}', '${team}', id, 'admission-${marker}', 'admission_test', '{}'::jsonb
from public.agents where tenant_id = '${team}' and iid = '${approved.iid}';

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
      and event_id = 'admission-${marker}') <> 1 then
    raise exception 'existing agent telemetry was blocked';
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
console.log("Enrollment admission PostgreSQL passed: denied free personal/team writes and rotations, approved seat path, withdrawal/no-seat gates, existing telemetry; rolled back.");
