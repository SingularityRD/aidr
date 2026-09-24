// Disposable, isolated PostgreSQL only. Never point this at a shared stack.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";

const container = process.env.AIDR_T46_TEST_DB_CONTAINER;
assert.match(container ?? "", /^aidr-t46-disposable-[0-9]{8}$/, "T46 disposable container required");
const args = ["exec", "-i", container, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres", "-q", "-At"];
const owner = randomUUID();
const member = randomUUID();
const tenant = randomUUID();
const deviceHash = randomBytes(32).toString("hex");
const tokenHash = randomBytes(32).toString("hex");
const hex = () => randomBytes(32).toString("hex");

function run(sql) {
	const result = spawnSync("docker", args, { input: sql, encoding: "utf8", timeout: 30_000 });
	if (result.error) throw result.error;
	assert.equal(result.status, 0, result.stderr);
	return result.stdout.trim();
}

function session() {
	const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"] });
	const state = { child, stdout: "", stderr: "", closed: false, code: null };
	child.stdout.setEncoding("utf8").on("data", (chunk) => { state.stdout += chunk; });
	child.stderr.setEncoding("utf8").on("data", (chunk) => { state.stderr += chunk; });
	child.on("close", (code) => { state.closed = true; state.code = code; });
	return state;
}

async function until(state, marker) {
	const deadline = Date.now() + 10_000;
	while (!state.stdout.includes(marker)) {
		if (state.closed || Date.now() > deadline) {
			throw new Error(`Timed out waiting for ${marker}: ${state.stdout} ${state.stderr}`);
		}
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
}

let holder;
let contender;
try {
	run(`begin;
update app.tenant_admission_config set mode='pilot' where singleton;
insert into auth.users(id,email) values
 ('${owner}','t46-owner-${owner}@test.invalid'),
 ('${member}','t46-member-${member}@test.invalid');
insert into public.tenants(id,name,kind,created_by) values
 ('${tenant}','T46 disposable','team','${owner}');
insert into public.teams(id,tenant_id,name,plan) values
 ('${tenant}','${tenant}','T46 disposable','free');
insert into public.tenant_members(tenant_id,user_id,role) values
 ('${tenant}','${owner}','owner'),('${tenant}','${member}','member');
insert into public.entitlements(user_id,tenant_id,included_agents,extra_agents) values
 ('${owner}','${tenant}',2,0);
insert into public.pilot_applications(user_id,tenant_id,status) values
 ('${owner}','${tenant}','approved');
insert into public.device_sessions(device_code_hash,user_code,status,user_id,tenant_id,authorized_at,expires_at) values
 ('${deviceHash}','T46${deviceHash.slice(0, 10).toUpperCase()}','authorized',
  '${member}','${tenant}',now(),now()+interval '10 minutes');
commit;`);
	holder = session();
	holder.child.stdin.write(`begin;
select 1 from public.tenant_members where tenant_id='${tenant}' and user_id='${member}' for update;
\\echo MEMBER_LOCK_HELD
`);
	await until(holder, "MEMBER_LOCK_HELD");
	contender = session();
	contender.child.stdin.write(`begin;
set local lock_timeout='250ms';
do $probe$ begin
  begin
    insert into public.enrollment_tokens(user_id,tenant_id,token_hash,expires_at)
      values ('${member}','${tenant}','${hex()}',now()+interval '1 hour');
    raise exception 'token_insert_did_not_lock_member';
  exception when lock_not_available then null;
  end;
end $probe$;
\\echo TOKEN_MEMBER_LOCK_OK
rollback;
`);
	await until(contender, "TOKEN_MEMBER_LOCK_OK");
	contender.child.stdin.end();
	holder.child.stdin.write(`delete from public.tenant_members where tenant_id='${tenant}' and user_id='${member}';
commit;
\\echo MEMBER_REMOVED
`);
	await until(holder, "MEMBER_REMOVED");
	holder.child.stdin.end();
	const result = run(`select public.issue_device_enrollment_token('${deviceHash}','${tokenHash}',now()+interval '1 hour')->>'status';
select count(*) from public.enrollment_tokens where tenant_id='${tenant}' and user_id='${member}' and expires_at>now();`);
	assert.equal(result, "already_exchanged_or_invalid\n0", result);
	console.log("T46 real two-session member lock, revocation, and no-token checks passed.");
} finally {
	for (const state of [holder, contender]) {
		if (state && !state.closed) {
			if (!state.child.stdin.writableEnded) state.child.stdin.end("rollback;\n");
			state.child.kill();
		}
	}
	// Offboarding guards intentionally forbid ad hoc row deletion. The whole
	// uniquely named disposable database/container is the cleanup boundary.
	const inspected = spawnSync("docker", ["inspect", "--format", "{{.Name}} {{.Config.Image}}", container], { encoding: "utf8" });
	assert.equal(inspected.status, 0, inspected.stderr);
	assert.match(inspected.stdout.trim(), new RegExp(`^/${container} supabase/postgres:17\\.`));
	const removed = spawnSync("docker", ["rm", "-f", container], { encoding: "utf8" });
	assert.equal(removed.status, 0, removed.stderr);
	const absent = spawnSync("docker", ["ps", "-a", "--filter", `name=^/${container}$`, "--format", "{{.Names}}"], { encoding: "utf8" });
	assert.equal(absent.status, 0, absent.stderr);
	assert.equal(absent.stdout.trim(), "", "disposable database container remains");
}
