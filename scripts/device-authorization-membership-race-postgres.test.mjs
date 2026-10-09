// Isolated PostgreSQL regression for membership removal racing device approval.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

const container = `aidr-device-auth-${randomUUID().slice(0, 8)}`;
const migration = readFileSync(
	new URL("../supabase/migrations/20260924000003_device_authorization_membership_lock.sql", import.meta.url),
	"utf8",
);
const revocationMigration = readFileSync(
	new URL("../supabase/migrations/20260923000051_device_membership_token_revocation.sql", import.meta.url),
	"utf8",
);
const tenant = randomUUID();
const removalWinsUser = randomUUID();
const removalWinsCode = `REMOVE${randomUUID().replaceAll("-", "").slice(0, 10).toUpperCase()}`;
const authorizationWinsUser = randomUUID();
const authorizationWinsCode = `AUTHOR${randomUUID().replaceAll("-", "").slice(0, 10).toUpperCase()}`;

function docker(args, input = "") {
	const result = spawnSync("docker", args, { input, encoding: "utf8", timeout: 60_000, maxBuffer: 4 * 1024 * 1024 });
	if (result.error) throw result.error;
	return result;
}

function sql(script) {
	const result = docker(["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"], script);
	assert.equal(result.status, 0, `PostgreSQL test failed:\n${result.stdout}\n${result.stderr}`);
	return result.stdout.trim();
}

function startPsql(script) {
	const child = spawn("docker", ["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"], {
		stdio: ["pipe", "pipe", "pipe"],
	});
	let stdout = "";
	let stderr = "";
	child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
	child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
	child.stdin.end(script);
	const closed = new Promise((resolve, reject) => {
		child.on("error", reject);
		child.on("close", (code) => code === 0 ? resolve(stdout) : reject(new Error(`${stderr}\n${stdout}`)));
	});
	void closed.catch(() => undefined);
	return { child, get stdout() { return stdout; }, closed };
}

async function waitFor(state, marker) {
	const deadline = Date.now() + 10_000;
	while (!state.stdout.includes(marker)) {
		if (Date.now() > deadline) throw new Error(`Timed out waiting for ${marker}: ${state.stdout}`);
		await delay(20);
	}
}

test("device authorization and membership removal serialize in both orders", { timeout: 180_000 }, async () => {
	const started = docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=device-auth-fixture-only", "postgres:17-alpine"]);
	assert.equal(started.status, 0, started.stderr);
	let remover;
	let authorizer;
	try {
		let ready = false;
		for (let i = 0; i < 100; i += 1) {
			if (docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"]).status === 0) { ready = true; break; }
			await delay(100);
		}
		assert.ok(ready, "isolated PostgreSQL did not start");
		sql(`create role anon; create role authenticated; create role service_role;
			create schema app;
			create table public.tenants(id uuid primary key, status text not null);
			create table public.tenant_members(tenant_id uuid not null, user_id uuid not null,
				role text not null, expires_at timestamptz, primary key(tenant_id,user_id));
			create table public.identity_user_session_state(user_id uuid primary key, revoked_before timestamptz);
			create table public.device_sessions(id uuid primary key default gen_random_uuid(), user_code text unique not null,
				user_id uuid, tenant_id uuid, authorized_at timestamptz, exchanged_at timestamptz,
				expires_at timestamptz not null, status text not null);
			create table public.enrollment_tokens(user_id uuid, tenant_id uuid, token_hash text,
				previous_hash text, previous_hash_expires_at timestamptz, consumed_at timestamptz,
				expires_at timestamptz, label text);
			create table public.admin_audit_logs(actor_user_id uuid, tenant_id uuid, action text,
				target_user_id uuid, detail jsonb);
			create function app.require_credential_member() returns trigger language plpgsql as $$
			begin return new; end $$;
			insert into public.tenants values ('${tenant}', 'active');
			insert into public.tenant_members(tenant_id,user_id,role) values
				('${tenant}','${removalWinsUser}','member'), ('${tenant}','${authorizationWinsUser}','member');
			insert into public.device_sessions(user_code,expires_at,status) values
				('${removalWinsCode}',now()+interval '10 minutes','pending'),
				('${authorizationWinsCode}',now()+interval '10 minutes','pending');
			${revocationMigration}
			${migration}`);

		// A removal that owns the membership row first must make the waiting
		// authorization return no row, not bind a stale code.
		remover = startPsql(`begin;
			delete from public.tenant_members where tenant_id='${tenant}' and user_id='${removalWinsUser}';
			\\echo REMOVAL_FIRST_LOCKED
			select pg_sleep(0.5);
			commit;
			\\echo REMOVAL_FIRST_COMMITTED\n`);
		await waitFor(remover, "REMOVAL_FIRST_LOCKED");
		authorizer = startPsql(`begin;
			set local lock_timeout='8s';
			select 'REMOVAL_FIRST_AUTH_COUNT=' || count(*) from public.authorize_device_session(
				'${removalWinsCode}','${removalWinsUser}','${tenant}',clock_timestamp()-interval '1 minute');
			commit;\n`);
		const [removalOutput, authorizationOutput] = await Promise.all([remover.closed, authorizer.closed]);
		assert.match(removalOutput, /REMOVAL_FIRST_COMMITTED/);
		assert.match(authorizationOutput, /REMOVAL_FIRST_AUTH_COUNT=0/);
		assert.equal(sql(`select user_id is null and authorized_at is null from public.device_sessions where user_code='${removalWinsCode}';`), "t");

		// If approval owns the canonical row first, removal waits for that
		// transaction. The two operations cannot observe an interleaved state.
		authorizer = startPsql(`begin;
			select 'AUTH_FIRST_COUNT=' || count(*) from public.authorize_device_session(
				'${authorizationWinsCode}','${authorizationWinsUser}','${tenant}',clock_timestamp()-interval '1 minute');
			\\echo AUTHORIZATION_FIRST_LOCKED
			select pg_sleep(0.5);
			commit;\n`);
		await waitFor(authorizer, "AUTHORIZATION_FIRST_LOCKED");
		remover = startPsql(`begin;
			delete from public.tenant_members where tenant_id='${tenant}' and user_id='${authorizationWinsUser}';
			commit;
			\\echo AUTHORIZATION_FIRST_REMOVAL_COMMITTED\n`);
		const [authorizationFirstOutput, removalAfterOutput] = await Promise.all([authorizer.closed, remover.closed]);
		assert.match(authorizationFirstOutput, /AUTH_FIRST_COUNT=1/);
		assert.match(removalAfterOutput, /AUTHORIZATION_FIRST_REMOVAL_COMMITTED/);
		assert.equal(sql(`select count(*) from public.admin_audit_logs where action='device.verify' and target_user_id='${authorizationWinsUser}';`), "1");
		assert.equal(sql(`select status='revoked' and expires_at<=now() from public.device_sessions where user_code='${authorizationWinsCode}';`), "t");
	} finally {
		for (const process of [remover, authorizer]) if (process && process.child.exitCode === null) process.child.kill();
		docker(["rm", "--force", container]);
	}
});
