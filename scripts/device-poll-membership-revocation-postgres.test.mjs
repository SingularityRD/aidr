// Runs the real device-poll RPC and credential/membership triggers in an
// isolated, no-network PostgreSQL container; never points at a shared stack.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

const container = `aidr-device-poll-race-${randomUUID().slice(0, 8)}`;
const migrations = [
	["supabase/migrations/20260923000034_tenant_ga_admission.sql", ["public.tenant_admission_capacity", "public.require_enrollment_admission"]],
	["supabase/migrations/20260923000047_membership_api_key_revocation.sql", ["app.require_credential_member"]],
	["supabase/migrations/20260923000051_device_membership_token_revocation.sql", ["app.expire_member_enrollment"]],
	["supabase/migrations/20260924000008_device_enrollment_issue_lock_order.sql", ["public.issue_device_enrollment_token"]],
];

function functionSql(path, name) {
	const source = readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
	const escaped = name.replaceAll(".", "\\.");
	const match = new RegExp(`create(?: or replace)? function ${escaped}\\(`, "i").exec(source);
	assert.ok(match, `missing function ${name} in ${path}`);
	const end = source.indexOf("\n$$;", match.index);
	assert.ok(end > match.index, `unterminated function ${name} in ${path}`);
	return source.slice(match.index, end + 4);
}

const functions = migrations.flatMap(([path, names]) => names.map((name) => functionSql(path, name))).join("\n");
const dockerArgs = ["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"];

function docker(args, input = "") {
	const result = spawnSync("docker", args, { input, encoding: "utf8", timeout: 60_000, maxBuffer: 4 * 1024 * 1024 });
	if (result.error) throw result.error;
	return result;
}

function sql(script, applicationName) {
	const args = applicationName
		? ["exec", "-i", "-e", `PGAPPNAME=${applicationName}`, container, ...dockerArgs.slice(3)]
		: dockerArgs;
	const result = docker(args, script);
	assert.equal(result.status, 0, `PostgreSQL regression failed:\n${result.stdout}\n${result.stderr}`);
	return result.stdout.trim();
}

function startPsql(script, applicationName, endInput = false) {
	const child = spawn("docker", ["exec", "-i", "-e", `PGAPPNAME=${applicationName}`, container, ...dockerArgs.slice(3)], {
		stdio: ["pipe", "pipe", "pipe"],
	});
	const state = { child, stdout: "", stderr: "", closed: false };
	child.stdout.setEncoding("utf8").on("data", (chunk) => { state.stdout += chunk; });
	child.stderr.setEncoding("utf8").on("data", (chunk) => { state.stderr += chunk; });
	child.on("close", () => { state.closed = true; });
	if (endInput) child.stdin.end(script);
	else child.stdin.write(script);
	return state;
}

async function waitFor(state, marker) {
	const deadline = Date.now() + 8_000;
	while (!state.stdout.includes(marker)) {
		if (state.closed || Date.now() > deadline) throw new Error(`Timed out waiting for ${marker}: ${state.stdout} ${state.stderr}`);
		await delay(20);
	}
}

async function waitForLock(applicationName) {
	const deadline = Date.now() + 8_000;
	while (Date.now() < deadline) {
		const count = sql(`select count(*) from pg_stat_activity where application_name='${applicationName}' and wait_event_type='Lock';`);
		if (count === "1") return;
		await delay(25);
	}
	throw new Error(`device-poll did not reach a database lock wait for ${applicationName}`);
}

function schemaSql() {
	return `
create extension if not exists pgcrypto;
create schema app;
create table public.tenants(id uuid primary key, status text not null);
create table public.tenant_members(tenant_id uuid not null, user_id uuid not null,
  role text not null, expires_at timestamptz, primary key(tenant_id,user_id));
create table public.pilot_applications(tenant_id uuid primary key, status text not null);
create table public.entitlements(tenant_id uuid primary key, included_agents integer not null);
create table public.tenant_admissions(tenant_id uuid primary key, revoked_at timestamptz,
  starts_at timestamptz, expires_at timestamptz, seats integer);
create table public.device_sessions(id uuid primary key default gen_random_uuid(),
  device_code_hash text not null unique, user_code text, user_id uuid, tenant_id uuid,
  authorized_at timestamptz, exchanged_at timestamptz, expires_at timestamptz not null,
  status text not null);
create table public.enrollment_tokens(id uuid primary key default gen_random_uuid(),
  user_id uuid not null, tenant_id uuid not null, label text, token_hash text not null unique,
  expires_at timestamptz not null, consumed_at timestamptz, previous_hash text,
  previous_hash_expires_at timestamptz);
create table public.identity_user_session_state(user_id uuid primary key, revoked_before timestamptz);
create table app.tenant_admission_config(singleton boolean primary key, mode text not null);
insert into app.tenant_admission_config values(true,'pilot');
create function public.effective_tenant_seats(p_tenant_id uuid)
returns table(extra_agents integer) language sql stable as $$ select 0 $$;
${functions}
create trigger enrollment_tokens_admission
before insert or update of token_hash on public.enrollment_tokens
for each row execute function public.require_enrollment_admission();
create trigger enrollment_tokens_owner_membership
before insert or update of token_hash on public.enrollment_tokens
for each row execute function app.require_credential_member();
create trigger tenant_members_expire_enrollment
after update or delete on public.tenant_members
for each row execute function app.expire_member_enrollment();
`;
}

test("device enrollment issue serializes with membership removal without holding the session row first", { timeout: 180_000 }, async () => {
	const started = docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=device-poll-fixture-only", "postgres:17-alpine"]);
	assert.equal(started.status, 0, started.stderr);
	let remover;
	let poller;
	let issuer;
	let tenantHolder;
	try {
	let ready = false;
		for (let attempt = 0; attempt < 100; attempt += 1) {
			if (docker(["exec", container, "psql", "-X", "-qAt", "-U", "postgres", "-c", "select 1"]).status === 0) { ready = true; break; }
			await delay(100);
		}
		assert.ok(ready, "isolated PostgreSQL did not start");
		sql(schemaSql());

		const member = randomUUID();
		const tenant = randomUUID();
		const deviceHash = randomBytes(32).toString("hex");
		const tokenHash = randomBytes(32).toString("hex");
		const seed = (tenantId, user, hash) => sql(`
insert into public.tenants values ('${tenantId}','active');
insert into public.tenant_members values ('${tenantId}','${user}','member',null);
insert into public.pilot_applications values ('${tenantId}','approved');
insert into public.entitlements values ('${tenantId}',2);
insert into public.device_sessions(device_code_hash,user_code,user_id,tenant_id,authorized_at,expires_at,status)
values ('${hash}','TEST-${user.slice(0,8)}','${user}','${tenantId}',clock_timestamp(),clock_timestamp()+interval '10 minutes','authorized');
`);
		seed(tenant, member, deviceHash);

		// Removal takes the member row first and its AFTER trigger later expires
		// the device row. The poller must wait at membership, not hold device row.
		const lockName = `member-holder-${member.replaceAll("-", "")}`;
		remover = startPsql(`begin;
select 1 from public.tenant_members where tenant_id='${tenant}' and user_id='${member}' for update;
\\echo MEMBER_LOCK_HELD
`, lockName);
		await waitFor(remover, "MEMBER_LOCK_HELD");

		const pollName = `device-poller-${member.replaceAll("-", "")}`;
		poller = startPsql(`begin;
set local lock_timeout='6s';
select public.issue_device_enrollment_token('${deviceHash}','${tokenHash}',clock_timestamp()+interval '1 hour')->>'status';
commit;
`, pollName);
		await waitForLock(pollName);

		// Regression assertion: a competing session can still lock the device
		// row while the poll RPC waits for membership. The old lock order failed.
		sql(`begin;
do $probe$ begin
  perform id from public.device_sessions where device_code_hash='${deviceHash}' for update nowait;
exception when lock_not_available then
  raise exception 'device-poll locked device session before waiting on membership';
end $probe$;
rollback;`);

		remover.child.stdin.write(`delete from public.tenant_members where tenant_id='${tenant}' and user_id='${member}';
commit;
\\echo MEMBER_REMOVAL_COMMITTED
`);
		remover.child.stdin.end();
		await waitFor(remover, "MEMBER_REMOVAL_COMMITTED");
		await waitFor(poller, "tenant_not_admitted");
		poller.child.stdin.end();

		assert.match(poller.stdout, /tenant_not_admitted/);
		assert.equal(sql(`select count(*) from public.enrollment_tokens where token_hash='${tokenHash}';`), "0");
		assert.equal(sql(`select status='revoked' and expires_at<=clock_timestamp() from public.device_sessions where device_code_hash='${deviceHash}';`), "t");

		// A small bounded retry proves the removed member cannot recover or mint
		// a token by replaying the same device-code RPC.
		for (let attempt = 0; attempt < 3; attempt += 1) {
			assert.equal(sql(`select public.issue_device_enrollment_token('${deviceHash}','${tokenHash}',clock_timestamp()+interval '1 hour')->>'status';`), "tenant_not_admitted");
		}
		assert.equal(sql(`select count(*) from public.enrollment_tokens where user_id='${member}' and tenant_id='${tenant}' and expires_at>clock_timestamp() and consumed_at is null;`), "0");

		// The opposite linearization: issue owns the shared membership lock,
		// removal waits, then its trigger expires the just-issued token before
		// removal commits.
		const winnerTenant = randomUUID();
		const winner = randomUUID();
		const winnerHash = randomBytes(32).toString("hex");
		const winnerToken = randomBytes(32).toString("hex");
		seed(winnerTenant, winner, winnerHash);
		const issueName = `issue-wins-${winner.replaceAll("-", "")}`;
		issuer = startPsql(`begin;
select public.issue_device_enrollment_token('${winnerHash}','${winnerToken}',clock_timestamp()+interval '1 hour')->>'status';
\\echo ISSUE_COMMITTED_ROW_LOCK_HELD
`, issueName);
		await waitFor(issuer, "ISSUE_COMMITTED_ROW_LOCK_HELD");
		const removeName = `remove-after-issue-${winner.replaceAll("-", "")}`;
		remover = startPsql(`begin;
delete from public.tenant_members where tenant_id='${winnerTenant}' and user_id='${winner}';
commit;
\\echo REMOVAL_AFTER_ISSUE_COMMITTED
`, removeName, true);
		await waitForLock(removeName);
		issuer.child.stdin.end(`commit;\n\\echo ISSUE_TRANSACTION_COMMITTED\n`);
		await waitFor(issuer, "ISSUE_TRANSACTION_COMMITTED");
		await waitFor(remover, "REMOVAL_AFTER_ISSUE_COMMITTED");
		assert.match(issuer.stdout, /issued/);
		assert.equal(sql(`select count(*) from public.enrollment_tokens where token_hash='${winnerToken}' and expires_at>clock_timestamp() and consumed_at is null;`), "0");
		assert.equal(sql(`select status='revoked' and expires_at<=clock_timestamp() from public.device_sessions where device_code_hash='${winnerHash}';`), "t");
		for (let attempt = 0; attempt < 3; attempt += 1) {
			assert.equal(sql(`select public.issue_device_enrollment_token('${winnerHash}','${winnerToken}',clock_timestamp()+interval '1 hour')->>'status';`), "tenant_not_admitted");
		}

		// Tenant suspension is also serialized by admission capacity before the
		// session row: while issuance waits on tenant status, its device row stays
		// available and the suspended tenant cannot receive a token.
		const suspendedTenant = randomUUID();
		const suspendedUser = randomUUID();
		const suspendedHash = randomBytes(32).toString("hex");
		const suspendedToken = randomBytes(32).toString("hex");
		seed(suspendedTenant, suspendedUser, suspendedHash);
		const tenantHolderName = `tenant-holder-${suspendedTenant.replaceAll("-", "")}`;
		tenantHolder = startPsql(`begin;
select 1 from public.tenants where id='${suspendedTenant}' for update;
\\echo TENANT_LOCK_HELD
`, tenantHolderName);
		await waitFor(tenantHolder, "TENANT_LOCK_HELD");
		const tenantPollName = `tenant-poller-${suspendedTenant.replaceAll("-", "")}`;
		poller = startPsql(`begin;
set local lock_timeout='6s';
select public.issue_device_enrollment_token('${suspendedHash}','${suspendedToken}',clock_timestamp()+interval '1 hour')->>'status';
commit;
`, tenantPollName);
		await waitForLock(tenantPollName);
		sql(`begin;
do $probe$ begin
  perform id from public.device_sessions where device_code_hash='${suspendedHash}' for update nowait;
exception when lock_not_available then
  raise exception 'device-poll locked session before admission status';
end $probe$;
rollback;`);
		tenantHolder.child.stdin.end(`update public.tenants set status='suspended' where id='${suspendedTenant}';\ncommit;\n\\echo TENANT_SUSPENSION_COMMITTED\n`);
		await waitFor(tenantHolder, "TENANT_SUSPENSION_COMMITTED");
		await waitFor(poller, "tenant_not_admitted");
		poller.child.stdin.end();
		assert.equal(sql(`select count(*) from public.enrollment_tokens where token_hash='${suspendedToken}';`), "0");
		assert.equal(sql(`select exchanged_at is null from public.device_sessions where device_code_hash='${suspendedHash}';`), "t");
		for (let attempt = 0; attempt < 3; attempt += 1) {
			assert.equal(sql(`select public.issue_device_enrollment_token('${suspendedHash}','${suspendedToken}',clock_timestamp()+interval '1 hour')->>'status';`), "tenant_not_admitted");
		}
	} finally {
		for (const state of [remover, poller, issuer, tenantHolder]) {
			if (state && !state.closed) {
				if (!state.child.stdin.writableEnded) state.child.stdin.end("rollback;\n");
				state.child.kill();
			}
		}
		docker(["rm", "--force", container]);
	}
});
