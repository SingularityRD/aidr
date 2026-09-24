// Isolated PostgreSQL only. Both sessions and every fixture end in ROLLBACK.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const container = process.env.AIDR_POSTGRES_DOCKER_CONTAINER;
assert.match(container ?? "", /^[A-Za-z0-9_.-]+$/, "isolated PostgreSQL container required");
const desktopDocker = process.env.LOCALAPPDATA
	? resolve(process.env.LOCALAPPDATA, "Programs/DockerDesktop/resources/bin/docker.exe")
	: null;
const docker = process.env.AIDR_DOCKER_BIN ?? (desktopDocker && existsSync(desktopDocker) ? desktopDocker : "docker");
const args = ["exec", "-i", container, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres", "-q", "-At"];
const owner = randomUUID();
const operator = randomUUID();
const tenant = randomUUID();
const agent = randomUUID();
const hex = () => randomBytes(32).toString("hex");
const deviceHash = hex();
const keyHash = hex();

const probe = spawnSync(docker, args, {
	input: "select to_regprocedure('public.start_verified_trial(uuid,uuid,jsonb,jsonb)') is not null;\n",
	encoding: "utf8",
	timeout: 30_000,
});
if (probe.error) throw probe.error;
assert.equal(probe.status, 0, probe.stderr);
const legal = probe.stdout.trim() === "t";
const trial = legal
	? `public.start_verified_trial('${owner}','${tenant}',
	  '{"version":"race-1","sha256":"${"a".repeat(64)}"}'::jsonb,
	  '{"version":"race-1","sha256":"${"b".repeat(64)}"}'::jsonb)`
	: `public.start_verified_trial('${owner}','${tenant}')`;
const legalSetup = legal ? `select public.configure_ga_legal_documents(
  'race-1','${"a".repeat(64)}','https://aidr-test.invalid/terms',
  'race-1','${"b".repeat(64)}','https://aidr-test.invalid/privacy','rollback-race-test');` : "";

function session() {
	const child = spawn(docker, args, { stdio: ["pipe", "pipe", "pipe"] });
	const state = { child, stdout: "", stderr: "", closed: false, code: null, error: null };
	child.stdout.setEncoding("utf8").on("data", (chunk) => { state.stdout += chunk; });
	child.stderr.setEncoding("utf8").on("data", (chunk) => { state.stderr += chunk; });
	child.on("error", (error) => { state.error = error; state.closed = true; });
	child.on("close", (code) => { state.code = code; state.closed = true; });
	return state;
}

async function until(state, marker) {
	const deadline = Date.now() + 30_000;
	while (!state.stdout.includes(marker)) {
		if (state.error) throw state.error;
		if (state.closed || Date.now() > deadline) {
			throw new Error(`Timed out waiting for ${marker}:\n${state.stdout}\n${state.stderr}`);
		}
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
}

async function finish(state) {
	state.child.stdin.end();
	const deadline = Date.now() + 10_000;
	while (!state.closed && Date.now() <= deadline) {
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
	if (!state.closed || state.error || state.code !== 0) {
		throw state.error ?? new Error(`PostgreSQL session failed:\n${state.stdout}\n${state.stderr}`);
	}
}

function expectsTenantLock(label, statement) {
	return `do $race$ begin
  begin
    ${statement}
    raise exception '${label}_did_not_take_tenant_lock';
  exception when lock_not_available then null;
  end;
end $race$;
`;
}

const holder = session();
let contender;
try {
	holder.child.stdin.write(`begin;
select pg_advisory_xact_lock(hashtextextended('${tenant}'::text,0));
\\echo HOLDER_READY
`);
	await until(holder, "HOLDER_READY");
	contender = session();
	contender.child.stdin.write(`begin;
set local lock_timeout='200ms';
insert into auth.users(id,email,aud,role,instance_id,email_confirmed_at,raw_app_meta_data,raw_user_meta_data)
values ('${owner}','race-${owner}@example.invalid','authenticated','authenticated',
  '00000000-0000-0000-0000-000000000000',clock_timestamp(),'{}'::jsonb,'{}'::jsonb);
insert into public.tenants(id,name,kind,created_by) values ('${tenant}','GA Race','team','${owner}');
insert into public.teams(id,tenant_id,name,plan) values ('${tenant}','${tenant}','GA Race','free');
insert into public.tenant_members(tenant_id,user_id,role) values ('${tenant}','${owner}','owner');
insert into public.team_members(team_id,tenant_id,user_id,role)
values ('${tenant}','${tenant}','${owner}','owner');
insert into public.device_sessions(device_code_hash,user_code,status,user_id,tenant_id,authorized_at,expires_at)
values ('${deviceHash}','RACE1234','authorized','${owner}','${tenant}',now(),now()+interval '10 minutes');
update app.tenant_admission_config set mode='cloud',configured_at=clock_timestamp() where singleton;
${legalSetup}
${expectsTenantLock("capacity", `perform public.tenant_admission_capacity('${tenant}');`)}
${expectsTenantLock("trial", `perform ${trial};`)}
${expectsTenantLock("grant", `perform public.grant_licensed_tenant_admission('${operator}','${tenant}','${owner}',1,now()+interval '1 year','race-test');`)}
${expectsTenantLock("revoke", `perform public.revoke_licensed_tenant_admission('${operator}','${tenant}','race-test');`)}
${expectsTenantLock("register", `perform public.register_agent_for_ingest('${owner}','race-agent','test','1','${tenant}');`)}
${expectsTenantLock("key", `insert into public.api_keys(user_id,tenant_id,key_hash) values ('${owner}','${tenant}','${keyHash}');`)}
${expectsTenantLock("event", `insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload) values ('${owner}','${tenant}','${agent}','race-${tenant}','ga_test','{}'::jsonb);`)}
${expectsTenantLock("device", `perform public.issue_device_enrollment_token('${deviceHash}','${hex()}',now()+interval '1 hour');`)}
\\echo BLOCKED_PROBES_OK
`);
	await until(contender, "BLOCKED_PROBES_OK");
	holder.child.stdin.write("rollback;\n");
	await finish(holder);
	contender.child.stdin.write(`do $check$ declare result jsonb; begin
  result := ${trial};
  if result ->> 'status' <> 'started' or public.tenant_admission_capacity('${tenant}') <> 1 then
    raise exception 'trial_did_not_start_after_lock_release: %', result;
  end if;
end $check$;
rollback;
\\echo AFTER_RELEASE_OK
`);
	await until(contender, "AFTER_RELEASE_OK");
	await finish(contender);
	console.log(`GA admission concurrency passed (${legal ? "with legal consent" : "pre-legal"}): eight tenant-lock probes and trial after release; both sessions rolled back.`);
} finally {
	for (const state of [holder, contender]) {
		if (state && !state.closed) {
			state.child.stdin.end("rollback;\n");
			state.child.kill();
		}
	}
}
