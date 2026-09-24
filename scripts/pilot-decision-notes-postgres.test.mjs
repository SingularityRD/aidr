// Isolated PostgreSQL regression for the database-enforced audit-note limit.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-pilot-notes-${randomUUID().slice(0, 8)}`;

function docker(args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 30_000 });
		let stdout = "", stderr = "";
		child.stdout.on("data", chunk => { stdout += chunk; });
		child.stderr.on("data", chunk => { stderr += chunk; });
		child.on("error", reject);
		child.on("close", code => done({ code, stdout: stdout.trim(), stderr }));
		child.stdin.on("error", () => {});
		child.stdin.end(input);
	});
}

const pgArgs = ["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
async function sql(query) {
	const result = await docker(pgArgs, query);
	assert.equal(result.code, 0, result.stderr);
	return result.stdout;
}

test("pilot decision notes accept 4000 characters and reject 4001 before audit or mutation", { timeout: 120_000 }, async () => {
	const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=pilot-notes-fixture-only", "postgres:17-alpine"]);
	assert.equal(started.code, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 100; i++) {
			if ((await docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0) { ready = true; break; }
			await new Promise(done => setTimeout(done, 100));
		}
		assert.ok(ready, "isolated PostgreSQL must start");

		await sql(`do $$ begin
			if not exists (select 1 from pg_roles where rolname='service_role') then create role service_role; end if;
			if not exists (select 1 from pg_roles where rolname='anon') then create role anon; end if;
			if not exists (select 1 from pg_roles where rolname='authenticated') then create role authenticated; end if;
		end $$;
			create schema auth;
			create table auth.users(id uuid primary key);
			create table public.tenants(id uuid primary key, status text not null);
			create table public.tenant_members(user_id uuid not null, tenant_id uuid not null, role text not null, expires_at timestamptz);
			create table public.pilot_admins(user_id uuid primary key);
			create table public.pilot_applications(
				user_id uuid not null, tenant_id uuid not null, status text not null, cohort text, notes text,
				primary key(user_id,tenant_id));
			create table public.admin_audit_logs(
				id bigint generated always as identity primary key, actor_user_id uuid not null,
				tenant_id uuid not null, action text not null, target_user_id uuid not null, detail jsonb not null);
		`);
		await sql(readFileSync(resolve(root, "supabase/migrations/20260923000017_pilot_application_atomic_audit.sql"), "utf8"));
		await sql(readFileSync(resolve(root, "supabase/migrations/20260924000009_bound_pilot_decision_notes.sql"), "utf8"));

		const target = randomUUID(), admin = randomUUID();
		await sql(`insert into auth.users values ('${target}'),('${admin}');
			insert into public.tenants values ('${target}','active');
			insert into public.tenant_members values ('${target}','${target}','owner',null);
			insert into public.pilot_admins values ('${admin}');`);
		const accepted = await sql(`set role service_role;
			select public.decide_pilot_application('${admin}','${target}','${target}',
				'approve','cohort-4000',repeat('x',4000));
			reset role;`);
		assert.match(accepted, /"status": "approved"|"status":"approved"/);
		assert.equal(await sql(`select length(notes) from public.pilot_applications where user_id='${target}' and tenant_id='${target}';`), "4000");
		assert.equal(await sql(`select length(detail->>'notes') from public.admin_audit_logs where action='pilot.approve' and target_user_id='${target}';`), "4000",
			"accepted boundary value is audited without truncation");

		const rejected = await docker(pgArgs, `set role service_role;
			do $$ begin
				begin
					perform public.decide_pilot_application('${admin}','${target}','${target}',
						'deny','must-not-commit',repeat('x',4001));
					raise exception '4001-character decision unexpectedly succeeded';
				exception when sqlstate '22023' then
					if sqlerrm <> 'invalid_pilot_decision' then raise; end if;
				end;
			end $$;
			reset role;`);
		assert.equal(rejected.code, 0, rejected.stderr);
		assert.equal(await sql(`select status || '|' || cohort || '|' || length(notes) from public.pilot_applications where user_id='${target}' and tenant_id='${target}';`),
			"approved|cohort-4000|4000", "rejected decision must not mutate the application");
		assert.equal(await sql(`select count(*) from public.admin_audit_logs where action like 'pilot.%' and target_user_id='${target}';`), "1",
			"rejected 4001-character decision must not write durable audit detail");
	} finally {
		const removed = await docker(["rm", "--force", container]);
		assert.equal(removed.code, 0, removed.stderr);
	}
});
