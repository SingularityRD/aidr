// Isolated PostgreSQL regression for public waitlist retention and the
// waitlist/pilot DSAR routine (CP-4, migration 20261013000100).
//
// Backend: a disposable database on AIDR_PG_TEST_DSN (libpq keyword/value
// form, e.g. "host=/run/postgresql port=5432 user=postgres dbname=postgres", on
// a server you own; the test creates and drops its own database), otherwise an isolated
// postgres:17-alpine container like the other *-postgres tests.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MIGRATION = "supabase/migrations/20261013000100_waitlist_pilot_retention_erasure.sql";

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
	if (dsn) {
		const name = `aidr_waitlist_${randomUUID().slice(0, 8)}`;
		const admin = (query) => run("psql", ["-X", "-qAt", "-v", "ON_ERROR_STOP=1", dsn], query);
		const created = await admin(`create database ${name};`);
		assert.equal(created.code, 0, created.stderr);
		t.after(() => admin(`drop database if exists ${name} with (force);`));
		// libpq keyword/value form: a later dbname overrides the earlier one.
		return (query) => run("psql", ["-X", "-qAt", "-v", "ON_ERROR_STOP=1", `${dsn} dbname=${name}`], query);
	}
	const container = `aidr-waitlist-${randomUUID().slice(0, 8)}`;
	const started = await run("docker", ["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=waitlist-fixture-only", "postgres:17-alpine"]);
	assert.equal(started.code, 0, started.stderr);
	t.after(() => run("docker", ["rm", "-f", container]));
	for (let i = 0; i < 100; i++) {
		if ((await run("docker", ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0) break;
		await new Promise((done) => setTimeout(done, 100));
	}
	return (query) => run("docker", ["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"], query);
}

async function fixture(t) {
	const raw = await database(t);
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
	create extension if not exists pgcrypto;
	create schema auth;
	create table auth.users(id uuid primary key, email text);
	create table public.tenants(id uuid primary key, status text not null);
	create table public.tenant_legal_holds(tenant_id uuid not null, released_at timestamptz);
	create table public.pilot_applications(user_id uuid not null, tenant_id uuid not null, status text not null default 'pending',
		cohort text, notes text, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
		primary key(user_id, tenant_id));
	create table public.admin_audit_logs(id bigint generated always as identity primary key, actor_user_id uuid not null,
		tenant_id uuid not null, action text not null, target_user_id uuid, detail jsonb not null default '{}');
	create table public.waitlist_signups(id bigint generated always as identity primary key, email text not null,
		email_lower text generated always as (lower(email)) stored, name text, company text, message text,
		created_at timestamptz not null default now(), tenant_id uuid, unique (email_lower));`);
	await sql(readFileSync(resolve(root, MIGRATION), "utf8"));
	// The migration is re-runnable (create or replace / if not exists).
	await sql(readFileSync(resolve(root, MIGRATION), "utf8"));
	return { sql, raw };
}

test("public waitlist rows are purged after 365 days, bounded, dry-run first and service-role only", { timeout: 120_000 }, async (t) => {
	const { sql, raw } = await fixture(t);
	const tenant = randomUUID();
	await sql(`insert into public.waitlist_signups(email, name, message, created_at, tenant_id) values
		('old-1@example.test', 'Old One', 'free text', now() - interval '400 days', null),
		('old-2@example.test', 'Old Two', null, now() - interval '366 days', null),
		('fresh@example.test', 'Fresh', 'hi', now() - interval '10 days', null),
		('tenant-row@example.test', 'Tenant', null, now() - interval '900 days', '${tenant}');`);
	const purge = async (limit, apply) => JSON.parse(await sql(`set role service_role; select public.purge_expired_waitlist_signups(${limit}, ${apply});`));

	const dry = await purge(100, false);
	assert.deepEqual([dry.eligible, dry.deleted, dry.remaining, dry.applied, dry.retention_days], [2, 0, 2, false, 365]);
	assert.equal(await sql("select count(*) from public.waitlist_signups;"), "4");

	const first = await purge(1, true);
	assert.deepEqual([first.deleted, first.remaining], [1, 1]);
	const second = await purge(1, true);
	assert.deepEqual([second.deleted, second.remaining], [1, 0]);
	assert.equal(await sql("select string_agg(email, ',' order by email) from public.waitlist_signups;"), "fresh@example.test,tenant-row@example.test",
		"recent rows and tenant-attributed rows (tenant offboarding) are kept");

	for (const role of ["anon", "authenticated"]) {
		const denied = await raw(`set role ${role}; select public.purge_expired_waitlist_signups(1, true);`);
		assert.notEqual(denied.code, 0, `${role} must not purge`);
		assert.match(denied.stderr, /permission denied/);
	}
	const invalid = await raw("set role service_role; select public.purge_expired_waitlist_signups(0, true);");
	assert.match(invalid.stderr, /invalid_waitlist_purge/);
});

test("a DSAR by e-mail exports, then erases waitlist PII and unheld pilot notes, with a hashed receipt", { timeout: 120_000 }, async (t) => {
	const { sql, raw } = await fixture(t);
	const user = randomUUID(), other = randomUUID(), free = randomUUID(), held = randomUUID(), admin = randomUUID();
	await sql(`insert into auth.users values ('${user}', 'Person@Example.test'), ('${other}', 'other@example.test');
		insert into public.tenants values ('${free}', 'active'), ('${held}', 'active');
		insert into public.tenant_legal_holds(tenant_id) values ('${held}');
		insert into public.waitlist_signups(email, name, company, message) values
			('PERSON@example.test', 'Person', 'Acme', 'please call me'), ('other@example.test', 'Other', null, null);
		insert into public.pilot_applications(user_id, tenant_id, status, notes) values
			('${user}', '${free}', 'approved', 'free-text use case'),
			('${user}', '${held}', 'pending', 'held use case'),
			('${other}', '${free}', 'pending', 'other notes');
		insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail) values
			('${admin}', '${free}', 'pilot.approve', '${user}', '{"notes":"free-text use case"}'),
			('${user}', '${free}', 'pilot.apply', '${user}', '{"has_use_case":true}');`);
	const call = async (email, apply, reference = "DSAR-2026-001") =>
		JSON.parse(await sql(`set role service_role; select public.erase_waitlist_pilot_subject('${email}', ${apply}, '${reference}');`));

	const exported = await call("  person@EXAMPLE.test ", false);
	assert.equal(exported.applied, false);
	assert.equal(exported.waitlist.length, 1);
	assert.equal(exported.waitlist[0].message, "please call me");
	assert.equal(exported.pilot_applications.length, 2);
	assert.deepEqual(exported.pilot_applications.map((row) => row.legal_hold).sort(), [false, true]);
	assert.deepEqual([exported.waitlist_rows_deleted, exported.pilot_notes_cleared, exported.held_pilot_notes_retained, exported.audit_note_copies_retained, exported.auth_users_matched], [0, 0, 1, 1, 1]);
	assert.equal(await sql("select count(*) from public.waitlist_signups;"), "2", "an access request changes nothing");

	const erased = await call("person@example.test", true);
	assert.deepEqual([erased.waitlist_rows_deleted, erased.pilot_notes_cleared, erased.held_pilot_notes_retained, erased.audit_note_copies_retained], [1, 1, 1, 1]);
	assert.deepEqual(erased.waitlist, []);
	assert.deepEqual(erased.pilot_applications, [], "an erasure response does not echo the erased text");
	assert.equal(await sql("select string_agg(email, ',') from public.waitlist_signups;"), "other@example.test");
	assert.equal(await sql(`select notes is null from public.pilot_applications where user_id='${user}' and tenant_id='${free}';`), "t");
	assert.equal(await sql(`select notes from public.pilot_applications where user_id='${user}' and tenant_id='${held}';`), "held use case", "legal hold wins");
	assert.equal(await sql(`select notes from public.pilot_applications where user_id='${other}';`), "other notes", "other subjects are untouched");
	assert.equal(await sql(`select status from public.pilot_applications where user_id='${user}' and tenant_id='${free}';`), "approved");

	const digest = createHash("sha256").update("person@example.test").digest("hex");
	assert.equal(await sql(`select count(*) from public.privacy_subject_requests where subject_email_sha256='${digest}';`), "2");
	assert.equal(await sql("select count(*) from public.privacy_subject_requests where subject_email_sha256 like '%@%' or request_reference like '%@%';"), "0");

	const again = await call("person@example.test", true);
	assert.deepEqual([again.waitlist_rows_deleted, again.pilot_notes_cleared], [0, 0], "erasure is idempotent");

	for (const [args, pattern] of [["'not-an-email', false, 'ref'", /invalid_subject_request/], ["'a@example.test', null, 'ref'", /invalid_subject_request/], ["'a@example.test', true, ' '", /invalid_subject_request/]]) {
		const rejected = await raw(`set role service_role; select public.erase_waitlist_pilot_subject(${args});`);
		assert.match(rejected.stderr, pattern);
	}
	const denied = await raw("set role anon; select public.erase_waitlist_pilot_subject('person@example.test', false, 'ref');");
	assert.match(denied.stderr, /permission denied/);
	const receipts = await raw("set role authenticated; select count(*) from public.privacy_subject_requests;");
	assert.match(receipts.stderr, /permission denied/);
});
