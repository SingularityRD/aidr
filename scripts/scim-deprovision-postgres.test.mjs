// Isolated PostgreSQL regression for D12: a SCIM deprovision revokes the
// person's device access (migration 20261014000100).
//
// The migration runs against fixture tables that carry only the columns it
// touches, so the behaviour is proven in isolation from the full chain.
//
// Backend: a disposable database on AIDR_PG_TEST_DSN (libpq keyword/value
// form, on a server you own), otherwise an isolated postgres:17-alpine
// container like the other *-postgres tests.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MIGRATION = readFileSync(
	resolve(root, "supabase/migrations/20261014000100_scim_deprovision_revokes_device_access.sql"),
	"utf8",
);

function run(command, args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"], timeout: 60_000 });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => { stdout += chunk; });
		child.stderr.on("data", (chunk) => { stderr += chunk; });
		child.on("error", reject);
		child.on("close", (code) => done({ code, stdout: stdout.trim(), stderr }));
		child.stdin.on("error", () => {});
		child.stdin.end(input);
	});
}

async function database(t) {
	const dsn = process.env.AIDR_PG_TEST_DSN;
	let raw;
	if (dsn) {
		const name = `aidr_scim_${randomUUID().slice(0, 8)}`;
		const admin = (query) => run("psql", ["-X", "-qAt", "-v", "ON_ERROR_STOP=1", dsn], query);
		const created = await admin(`create database ${name};`);
		assert.equal(created.code, 0, created.stderr);
		t.after(() => admin(`drop database if exists ${name} with (force);`));
		raw = (query) => run("psql", ["-X", "-qAt", "-v", "ON_ERROR_STOP=1", `${dsn} dbname=${name}`], query);
	} else {
		const container = `aidr-scim-${randomUUID().slice(0, 8)}`;
		const started = await run("docker", ["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
			"-e", "POSTGRES_PASSWORD=scim-fixture-only", "postgres:17-alpine"]);
		assert.equal(started.code, 0, started.stderr);
		t.after(() => run("docker", ["rm", "-f", container]));
		for (let i = 0; i < 100; i++) {
			if ((await run("docker", ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0) break;
			await new Promise((done) => setTimeout(done, 100));
		}
		raw = (query) => run("docker", ["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"], query);
	}
	const sql = async (query) => {
		const result = await raw(query);
		assert.equal(result.code, 0, result.stderr);
		return result.stdout;
	};
	await sql(`do $$ begin
		if not exists (select 1 from pg_roles where rolname='service_role') then create role service_role; end if;
		if not exists (select 1 from pg_roles where rolname='anon') then create role anon; end if;
		if not exists (select 1 from pg_roles where rolname='authenticated') then create role authenticated; end if;
	end $$;
	create schema app;
	create table public.scim_users(id uuid primary key, tenant_id uuid not null, auth_user_id uuid,
		active boolean not null default true, display_name text);
	create table public.api_keys(id uuid primary key default gen_random_uuid(), tenant_id uuid not null,
		user_id uuid not null, revoked boolean not null default false, previous_hash text,
		previous_hash_expires_at timestamptz);
	create table public.approval_requests(id uuid primary key default gen_random_uuid(), tenant_id uuid not null,
		requested_by uuid not null, status text not null default 'pending'
		check (status in ('pending', 'approved', 'denied', 'expired')));
	create table public.enrollment_tokens(id uuid primary key default gen_random_uuid(), tenant_id uuid not null,
		user_id uuid not null, consumed_at timestamptz, expires_at timestamptz not null);
	create table public.device_sessions(id uuid primary key default gen_random_uuid(), user_id uuid,
		exchanged_at timestamptz, expires_at timestamptz not null);
	create table public.admin_audit_logs(id bigint generated always as identity, actor_user_id uuid, tenant_id uuid,
		target_user_id uuid, action text not null, detail jsonb not null default '{}');`);
	await sql(MIGRATION);
	return sql;
}

const TENANT = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT = "22222222-2222-4222-8222-222222222222";
const LEAVER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const STAYER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const LEAVER_SCIM = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const STAYER_SCIM = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

async function seed(sql) {
	await sql(`
	insert into public.scim_users(id, tenant_id, auth_user_id, active) values
		('${LEAVER_SCIM}', '${TENANT}', '${LEAVER}', true),
		('${STAYER_SCIM}', '${TENANT}', '${STAYER}', true);
	insert into public.api_keys(tenant_id, user_id, revoked, previous_hash, previous_hash_expires_at) values
		('${TENANT}', '${LEAVER}', false, repeat('a', 64), now() + interval '1 day'),
		('${TENANT}', '${LEAVER}', false, null, null),
		('${TENANT}', '${LEAVER}', true, null, null),
		('${OTHER_TENANT}', '${LEAVER}', false, null, null),
		('${TENANT}', '${STAYER}', false, null, null);
	insert into public.approval_requests(tenant_id, requested_by, status) values
		('${TENANT}', '${LEAVER}', 'pending'),
		('${TENANT}', '${LEAVER}', 'approved'),
		('${TENANT}', '${STAYER}', 'pending');
	insert into public.enrollment_tokens(tenant_id, user_id, consumed_at, expires_at) values
		('${TENANT}', '${LEAVER}', null, now() + interval '1 day'),
		('${TENANT}', '${LEAVER}', now(), now() + interval '1 day'),
		('${TENANT}', '${STAYER}', null, now() + interval '1 day');
	insert into public.device_sessions(user_id, exchanged_at, expires_at) values
		('${LEAVER}', null, now() + interval '10 minutes'),
		('${STAYER}', null, now() + interval '10 minutes');`);
}

test("deactivating a SCIM user revokes their device access in that tenant only", async (t) => {
	const sql = await database(t);
	await seed(sql);
	await sql(`update public.scim_users set active = false where id = '${LEAVER_SCIM}';`);

	assert.equal(await sql(`select count(*) from public.api_keys where tenant_id = '${TENANT}' and user_id = '${LEAVER}' and not revoked;`), "0");
	assert.equal(await sql(`select count(*) from public.api_keys where user_id = '${LEAVER}' and previous_hash is not null;`), "0",
		"a renewed key's retired secret must not survive the revocation");
	assert.equal(await sql(`select count(*) from public.api_keys where tenant_id = '${OTHER_TENANT}' and not revoked;`), "1",
		"keys in another tenant are untouched");
	assert.equal(await sql(`select count(*) from public.api_keys where user_id = '${STAYER}' and not revoked;`), "1");

	assert.equal(await sql(`select string_agg(status, ',' order by status) from public.approval_requests where requested_by = '${LEAVER}';`),
		"approved,expired", "only the pending request expires; a decided one keeps its record");
	assert.equal(await sql(`select status from public.approval_requests where requested_by = '${STAYER}';`), "pending");

	assert.equal(await sql(`select count(*) from public.enrollment_tokens where user_id = '${LEAVER}' and consumed_at is null and expires_at > clock_timestamp();`), "0");
	assert.equal(await sql(`select count(*) from public.enrollment_tokens where user_id = '${STAYER}' and expires_at > clock_timestamp();`), "1");
	assert.equal(await sql(`select count(*) from public.device_sessions where user_id = '${LEAVER}' and expires_at > clock_timestamp();`), "0");
	assert.equal(await sql(`select count(*) from public.device_sessions where user_id = '${STAYER}' and expires_at > clock_timestamp();`), "1");

	const audit = JSON.parse(await sql(`select detail from public.admin_audit_logs where action = 'scim.user.deprovisioned';`));
	assert.deepEqual(audit, {
		scim_user_id: LEAVER_SCIM,
		api_keys_revoked: 2,
		approval_requests_expired: 1,
		enrollment_codes_expired: 1,
		device_sessions_expired: 1,
	});
});

test("only an active-to-inactive change of a bound SCIM user deprovisions", async (t) => {
	const sql = await database(t);
	await seed(sql);
	// A display-name change, an already-inactive user and reactivation do nothing.
	await sql(`update public.scim_users set display_name = 'renamed' where id = '${LEAVER_SCIM}';`);
	assert.equal(await sql("select count(*) from public.admin_audit_logs;"), "0");
	assert.equal(await sql(`select count(*) from public.api_keys where user_id = '${LEAVER}' and not revoked;`), "3");

	await sql(`update public.scim_users set active = false where id = '${LEAVER_SCIM}';`);
	await sql(`update public.scim_users set active = true where id = '${LEAVER_SCIM}';`);
	assert.equal(await sql(`select count(*) from public.api_keys where tenant_id = '${TENANT}' and user_id = '${LEAVER}' and not revoked;`), "0",
		"reactivation never revives a revoked key; the person re-enrolls");
	assert.equal(await sql("select count(*) from public.admin_audit_logs;"), "1");

	// A provisional (unbound) SCIM user owns no credentials yet.
	await sql(`insert into public.scim_users(id, tenant_id, auth_user_id, active)
		values ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', '${TENANT}', null, true);
		update public.scim_users set active = false where id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';`);
	assert.equal(await sql("select count(*) from public.admin_audit_logs;"), "1");
});

test("the deprovision function is not callable by API roles", async (t) => {
	const sql = await database(t);
	for (const role of ["anon", "authenticated", "service_role"]) {
		assert.equal(
			await sql(`select has_function_privilege('${role}', 'app.scim_deprovision_device_access(uuid, uuid, uuid)', 'execute');`),
			"f",
		);
	}
});
