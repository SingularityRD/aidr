// Isolated PostgreSQL regression for the in-database retention schedule used on
// Supabase Cloud (CP-3, migration 20261013000200).
//
// pg_cron is not part of a plain PostgreSQL server, so the scheduling path runs
// against a stand-in `cron` schema that records cron.schedule calls with
// pg_cron's upsert-by-name semantics; the guard path runs without it.
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
const SCHEDULE = readFileSync(resolve(root, "supabase/migrations/20261013000200_scheduled_retention_pg_cron.sql"), "utf8");
const WAITLIST = readFileSync(resolve(root, "supabase/migrations/20261013000100_waitlist_pilot_retention_erasure.sql"), "utf8");
const JOBS = ["telemetry", "billing", "trial_subjects", "waitlist", "team_invitations", "approval_requests", "ai_governance", "rate_limits", "governance_digest"];

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
		const name = `aidr_cron_${randomUUID().slice(0, 8)}`;
		const admin = (query) => run("psql", ["-X", "-qAt", "-v", "ON_ERROR_STOP=1", dsn], query);
		const created = await admin(`create database ${name};`);
		assert.equal(created.code, 0, created.stderr);
		t.after(() => admin(`drop database if exists ${name} with (force);`));
		raw = (query) => run("psql", ["-X", "-qAt", "-v", "ON_ERROR_STOP=1", `${dsn} dbname=${name}`], query);
	} else {
		const container = `aidr-cron-${randomUUID().slice(0, 8)}`;
		const started = await run("docker", ["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
			"-e", "POSTGRES_PASSWORD=cron-fixture-only", "postgres:17-alpine"]);
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
		alter role service_role bypassrls; -- as on Supabase
		if not exists (select 1 from pg_roles where rolname='anon') then create role anon; end if;
		if not exists (select 1 from pg_roles where rolname='authenticated') then create role authenticated; end if;
	end $$;
	create extension if not exists pgcrypto;
	create schema auth;
	create table auth.users(id uuid primary key, email text);
	create table public.tenant_legal_holds(tenant_id uuid not null, released_at timestamptz);
	create table public.pilot_applications(user_id uuid not null, tenant_id uuid not null, status text not null default 'pending',
		cohort text, notes text, created_at timestamptz not null default now(), updated_at timestamptz not null default now());
	create table public.admin_audit_logs(id bigint generated always as identity, actor_user_id uuid, tenant_id uuid, action text,
		target_user_id uuid, detail jsonb not null default '{}');
	create table public.waitlist_signups(id bigint generated always as identity primary key, email text not null,
		email_lower text generated always as (lower(email)) stored, name text, company text, message text,
		created_at timestamptz not null default now(), tenant_id uuid, unique (email_lower));`);
	await sql(WAITLIST);
	return { sql, raw };
}

const CRON_STUB = `create schema cron;
	create table cron.job(jobid bigint generated always as identity primary key, jobname text unique, schedule text, command text, username text);
	create function cron.schedule(job_name text, schedule text, command text) returns bigint language sql as $$
		insert into cron.job(jobname, schedule, command, username) values (job_name, schedule, command, current_user)
		on conflict (jobname) do update set schedule = excluded.schedule, command = excluded.command
		returning jobid $$;
	create function cron.unschedule(job_id bigint) returns boolean language sql as $$
		delete from cron.job where jobid = job_id returning true $$;`;

test("without pg_cron the migration applies, schedules nothing and says why", { timeout: 120_000 }, async (t) => {
	const { sql } = await database(t);
	await sql(SCHEDULE);
	await sql(SCHEDULE);
	assert.deepEqual(JSON.parse(await sql("select app.schedule_retention_maintenance();")), { scheduled: false, reason: "pg_cron is not installed" });
	assert.equal(await sql("select app.unschedule_retention_maintenance();"), "0");
});

test("with pg_cron every retention job is scheduled once, idempotently, as its own statement", { timeout: 120_000 }, async (t) => {
	const { sql, raw } = await database(t);
	await sql(CRON_STUB);
	await sql(SCHEDULE);
	await sql(SCHEDULE); // re-running the migration (or the operator call) must not duplicate jobs
	assert.equal(JSON.parse(await sql("select app.schedule_retention_maintenance();")).scheduled, true);
	const jobs = (await sql("select jobname || '|' || schedule || '|' || command from cron.job order by jobname;")).split("\n").map((line) => line.split("|"));
	assert.equal(jobs.length, JOBS.length);
	assert.deepEqual(jobs.map(([, , command]) => command.match(/^select app\.run_retention_job\('([a-z_]+)'\)$/)?.[1]).sort(), [...JOBS].sort());
	for (const [name, schedule] of jobs) {
		assert.match(name, /^aidr-(retention-[a-z-]+|governance-digest)$/);
		assert.equal(schedule.split(" ").length, 5, `${name}: five-field cron`);
	}
	// Only operators (the job owner) may run or (re)schedule jobs.
	for (const role of ["service_role", "authenticated", "anon"]) {
		for (const call of ["app.run_retention_job('waitlist')", "app.schedule_retention_maintenance()"]) {
			const denied = await raw(`set role ${role}; select ${call};`);
			assert.notEqual(denied.code, 0, `${role}: ${call}`);
		}
	}
	assert.equal(await sql("select app.unschedule_retention_maintenance();"), String(JOBS.length));
	assert.equal(await sql("select count(*) from cron.job;"), "0");
});

test("a scheduled run deletes due rows, records a receipt, and records failures instead of hiding them", { timeout: 120_000 }, async (t) => {
	const { sql, raw } = await database(t);
	await sql(SCHEDULE);
	await sql(`insert into public.waitlist_signups(email, created_at) values
		('old@example.test', now() - interval '400 days'), ('new@example.test', now());`);
	const waitlist = JSON.parse(await sql("select app.run_retention_job('waitlist');"));
	assert.equal(waitlist.ok, true);
	assert.equal(waitlist.result.deleted, 1);
	assert.equal(await sql("select string_agg(email, ',') from public.waitlist_signups;"), "new@example.test");

	const digest = JSON.parse(await sql("select app.run_retention_job('governance_digest');"));
	assert.equal(digest.ok, false, "an unconfigured digest is not a success");
	assert.equal(digest.result.status, "not_configured");

	const unknown = JSON.parse(await sql("select app.run_retention_job('nope');"));
	assert.equal(unknown.ok, false);
	assert.equal(unknown.result.error, "22023");

	const status = Object.fromEntries((await sql("select job || '|' || last_ok || '|' || (last_success_at is not null) from public.retention_job_status;"))
		.split("\n").map((line) => { const [job, ok, succeeded] = line.split("|"); return [job, { ok, succeeded }]; }));
	assert.deepEqual(status.waitlist, { ok: "true", succeeded: "true" });
	assert.deepEqual(status.governance_digest, { ok: "false", succeeded: "false" });
	assert.equal(await sql("set role service_role; select count(*) from public.retention_job_status;"), "3");
	const hidden = await raw("set role authenticated; select count(*) from public.retention_job_runs;");
	assert.match(hidden.stderr, /permission denied/);
});
