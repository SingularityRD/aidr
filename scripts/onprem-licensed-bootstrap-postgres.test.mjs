// Run only against a disposable Supabase PostgreSQL container. If migrations
// 34/35 are absent, apply them with fixtures in a rolled-back transaction.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
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
const migrationRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../supabase/migrations");
const migrations = [34, 35].map((number) => {
	const name = number === 34 ? "tenant_ga_admission" : "onprem_licensed_bootstrap";
	return readFileSync(resolve(migrationRoot, `202609230000${number}_${name}.sql`), "utf8");
});
const probe = spawnSync(docker, [
	"exec", container, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1",
	"-U", dbUser, "-d", "postgres", "-At", "-c",
	"select to_regclass('app.tenant_admission_config') is not null, " +
	"to_regprocedure('public.bootstrap_customer(uuid,uuid,text,integer,timestamptz,text)') is not null",
], { encoding: "utf8", timeout: 20_000 });
if (probe.error) throw probe.error;
assert.equal(probe.status, 0, `PostgreSQL schema probe failed:\n${probe.stderr}`);
const installed = probe.stdout.trim();
assert.match(installed, /^(f\|f|t\|f|t\|t)$/, `unsupported admission schema state: ${installed}`);
const pendingMigrations = installed === "f|f" ? migrations.join("\n")
	: installed === "t|f" ? migrations[1] : "";

const helpers = String.raw`
create function pg_temp.expect_error(statement text, expected_state text, expected_message text default null)
returns void language plpgsql as $fn$
declare actual_state text; actual_message text;
begin
  begin
    execute statement;
  exception when others then
    get stacked diagnostics actual_state = returned_sqlstate, actual_message = message_text;
    if actual_state = expected_state
       and (expected_message is null or actual_message = expected_message) then return; end if;
    raise exception 'expected SQLSTATE % message %, got SQLSTATE % message %',
      expected_state, expected_message, actual_state, actual_message;
  end;
  raise exception 'expected SQLSTATE % but statement succeeded: %', expected_state, statement;
end $fn$;
`;

function runCase(label, mode, testBody) {
	const owner = randomUUID();
	const bootstrap = randomUUID();
	const reference = `license-${randomUUID()}`;
	const name = `Licensed ${randomUUID()}`;
	const expiry = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
	const changedExpiry = new Date(Date.now() + 730 * 24 * 60 * 60 * 1000).toISOString();
	const call = (seats = 5, licenseExpiry = expiry, licenseReference = reference, tenantName = name) =>
		`public.bootstrap_customer('${owner}','${bootstrap}','${tenantName}',${seats},'${licenseExpiry}'::timestamptz,'${licenseReference}')`;
	const fixture = `
insert into auth.users(id,email,aud,role,instance_id,email_confirmed_at,
  raw_app_meta_data,raw_user_meta_data)
values ('${owner}','bootstrap-${owner}@example.invalid','authenticated','authenticated',
  '00000000-0000-0000-0000-000000000000',clock_timestamp(),
  jsonb_build_object('aidr_bootstrap_id','${bootstrap}'),'{}'::jsonb);
`;
	const sql = `\\set ON_ERROR_STOP on\nbegin;\n${fixture}\n${pendingMigrations}\n${helpers}\n${mode ? `select public.configure_tenant_admission_mode('${mode}');` : ""}\n${testBody({ owner, bootstrap, reference, name, expiry, changedExpiry, call })}\nrollback;\nselect 'ONPREM_BOOTSTRAP_${label}_ROLLED_BACK';\n`;
	const result = spawnSync(docker, [
		"exec", "-i", container, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1",
		"-U", dbUser, "-d", "postgres", "-q", "-At",
	], { input: sql, encoding: "utf8", maxBuffer: 12 * 1024 * 1024, timeout: 120_000 });
	if (result.error) throw result.error;
	assert.equal(result.status, 0, `${label} PostgreSQL bootstrap regression failed:\n${result.stdout}\n${result.stderr}`);
	assert.match(result.stdout, new RegExp(`ONPREM_BOOTSTRAP_${label}_ROLLED_BACK`));
}

for (const [label, mode] of [["UNCONFIGURED", null], ["CLOUD", "cloud"], ["PILOT", "pilot"]]) {
	runCase(label, mode, ({ call }) => `
select pg_temp.expect_error($stmt$select ${call()}$stmt$, '42501', 'onprem_admission_mode_required');
do $check$ begin
  if exists (select 1 from public.admin_audit_logs where action='customer.bootstrap')
     or exists (select 1 from public.tenant_admissions) then
    raise exception 'wrong deployment mode mutated admission'; end if;
end $check$;`);
}

runCase("LICENSED", "onprem", ({ owner, bootstrap, reference, name, expiry, changedExpiry, call }) => `
select pg_temp.expect_error($stmt$
  select public.bootstrap_customer('${owner}','${bootstrap}','${name}',5)
$stmt$, '42883');
select pg_temp.expect_error($stmt$select ${call(5, "infinity")}$stmt$,
  '22023','invalid_customer_configuration');
select pg_temp.expect_error($stmt$select ${call(5, "2020-01-01T00:00:00Z")}$stmt$,
  '22023','invalid_customer_configuration');
select pg_temp.expect_error($stmt$select ${call(5, expiry, " ")}$stmt$,
  '22023','invalid_customer_configuration');
select pg_temp.expect_error($stmt$
  select public.bootstrap_customer('${owner}','${randomUUID()}','${name}',5,
    '${expiry}'::timestamptz,'${reference}')
$stmt$,'42501','bootstrap_account_mismatch');
do $check$ declare receipt jsonb; team_id uuid; agent record; begin
  receipt := ${call()};
  team_id := (receipt ->> 'tenant_id')::uuid;
  if receipt ->> 'user_id' <> '${owner}' or receipt ->> 'name' <> '${name}'
     or (receipt ->> 'seats')::integer <> 5
     or (select kind from public.tenants where id=team_id) <> 'enterprise'
     or (select plan from public.teams where tenant_id=team_id) <> 'enterprise'
     or public.tenant_admission_capacity(team_id) <> 5
     or public.tenant_admission_capacity('${owner}') <> 0
     or (select kind from public.tenant_admissions where tenant_id=team_id) <> 'licensed'
     or (select expires_at from public.tenant_admissions where tenant_id=team_id)
       <> '${expiry}'::timestamptz
     or (select grant_reference from public.tenant_admissions where tenant_id=team_id)
       <> '${reference}'
     or exists (select 1 from public.pilot_applications
       where tenant_id=team_id and status='approved') then
    raise exception 'bootstrap failed to create isolated licensed admission: %', receipt;
  end if;
  if ${call()} <> receipt then raise exception 'bootstrap retry changed receipt'; end if;
  if (select count(*) from public.admin_audit_logs
      where action='customer.bootstrap' and tenant_id=team_id) <> 1
     or (select count(*) from public.admin_audit_logs
      where action='admission.bootstrap_licensed' and tenant_id=team_id) <> 1 then
    raise exception 'bootstrap retry duplicated audit'; end if;
  insert into public.api_keys(user_id,tenant_id,key_hash)
    values ('${owner}',team_id,encode(gen_random_bytes(32),'hex'));
  select * into agent from public.register_agent_for_ingest('${owner}',
    'bootstrap-test-${randomUUID()}','test','1',team_id);
  if agent.created is distinct from true or agent.allowed_agents <> 5 then
    raise exception 'licensed team registration failed'; end if;
end $check$;
select pg_temp.expect_error($stmt$select ${call(6)}$stmt$,
  '22023','bootstrap_already_completed_with_different_configuration');
select pg_temp.expect_error($stmt$select ${call(5, expiry, `different-${reference}`)}$stmt$,
  '42501','bootstrap_admission_conflict');
select pg_temp.expect_error($stmt$
  select ${call(5, changedExpiry)}
$stmt$,'42501','bootstrap_admission_conflict');
do $check$ begin
  if has_function_privilege('authenticated',
      'public.bootstrap_customer(uuid,uuid,text,integer,timestamptz,text)','EXECUTE')
     or to_regprocedure('public.bootstrap_customer(uuid,uuid,text,integer)') is not null then
    raise exception 'legacy/browser bootstrap access remains'; end if;
end $check$;`);

console.log("On-prem licensed bootstrap PostgreSQL passed: deployment mode, explicit finite license, idempotent receipt, conflict and capacity; all transactions rolled back.");
