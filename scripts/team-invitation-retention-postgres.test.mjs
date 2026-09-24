// Real PostgreSQL regression for policy-driven stale invitation cleanup.
// Creates its own network-isolated container and never connects to a deployment.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-invite-retention-${randomUUID().slice(0, 8)}`;

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
async function denied(query, pattern) {
	const result = await docker(pgArgs, query);
	assert.notEqual(result.code, 0, "statement must be denied");
	assert.match(result.stderr, pattern);
}
const rpc = async (limit = 100, apply = true) => JSON.parse(await sql(
	`set role service_role; select public.prune_expired_team_invitations(${limit},${apply});`,
));
const delay = ms => new Promise(done => setTimeout(done, ms));

function lockedTenant(tenantId) {
	const child = spawn("docker", pgArgs, { stdio: ["pipe", "pipe", "pipe"], timeout: 15_000 });
	let output = "", stderr = "";
	child.stdout.on("data", chunk => { output += chunk; });
	child.stderr.on("data", chunk => { stderr += chunk; });
	child.stdin.write(`begin; select pg_advisory_xact_lock(hashtextextended('${tenantId}'::text,2606));\n\\echo LOCKED\n`);
	return (async () => {
		for (let i = 0; i < 100 && !output.includes("LOCKED"); i++) await delay(20);
		assert.ok(output.includes("LOCKED"), `tenant lock unavailable: ${stderr}`);
		return async () => {
			child.stdin.end("commit;\n\\q\n");
			await new Promise(done => child.on("close", done));
		};
	})();
}

test("team-invitation retention is policy-driven, bounded, held, tenant-scoped, and service-only", { timeout: 120_000 }, async () => {
	const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=invite-retention-fixture-only", "postgres:17-alpine"]);
	assert.equal(started.code, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 100; i++) {
			if ((await docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0) { ready = true; break; }
			await delay(100);
		}
		assert.ok(ready, "isolated PostgreSQL must start");

		await sql(`do $$ begin
			if not exists (select 1 from pg_roles where rolname='service_role') then create role service_role; end if;
			if not exists (select 1 from pg_roles where rolname='anon') then create role anon; end if;
			if not exists (select 1 from pg_roles where rolname='authenticated') then create role authenticated; end if;
		end $$;
			create table public.tenants (id uuid primary key, status text not null);
			create table public.tenant_data_retention_policies (
				tenant_id uuid not null, data_class text not null, retention_days integer not null,
				primary key (tenant_id,data_class));
			create table public.tenant_legal_holds (tenant_id uuid not null, released_at timestamptz);
			create table public.team_invitations (
				id uuid primary key, tenant_id uuid not null, email text not null, token_hash text not null unique,
				role text not null, created_by uuid not null, created_at timestamptz not null,
				expires_at timestamptz not null, accepted_at timestamptz);
		`);
		await sql(readFileSync(resolve(root, "supabase/migrations/20260924000007_expired_invitation_retention.sql"), "utf8"));

		const active = randomUUID(), held = randomUUID(), closing = randomUUID(), noPolicy = randomUUID(), strict = randomUUID();
		const ids = {
			oldest: randomUUID(), newer: randomUUID(), young: randomUUID(), live: randomUUID(), accepted: randomUUID(),
			held: randomUUID(), inactive: randomUUID(), missingPolicy: randomUUID(), strict: randomUUID(), locked: randomUUID(),
		};
		await sql(`insert into public.tenants(id,status) values
			('${active}','active'),('${held}','active'),('${closing}','closing'),('${noPolicy}','active'),('${strict}','active');
			insert into public.tenant_data_retention_policies(tenant_id,data_class,retention_days) values
				('${active}','identity_membership',2),('${held}','identity_membership',2),
				('${closing}','identity_membership',2),('${strict}','identity_membership',5);
			insert into public.tenant_legal_holds(tenant_id,released_at) values ('${held}',null);`);

		function invitation(id, tenantId, email, createdAt, expiresAt, acceptedAt = "null") {
			return `('${id}','${tenantId}','${email}','${randomUUID().replaceAll("-", "").padEnd(64, "0")}','member','${randomUUID()}',${createdAt},${expiresAt},${acceptedAt})`;
		}
		await sql(`insert into public.team_invitations(id,tenant_id,email,token_hash,role,created_by,created_at,expires_at,accepted_at) values
			${invitation(ids.oldest, active, "oldest@example.invalid", "now()-interval '10 days'", "now()-interval '3 days'")},
			${invitation(ids.newer, active, "newer@example.invalid", "now()-interval '8 days'", "now()-interval '2 days'")},
			${invitation(ids.young, active, "young@example.invalid", "now()-interval '1 day'", "now()-interval '1 hour'")},
			${invitation(ids.live, active, "live@example.invalid", "now()-interval '10 days'", "now()+interval '1 day'")},
			${invitation(ids.accepted, active, "accepted@example.invalid", "now()-interval '10 days'", "now()-interval '3 days'", "now()-interval '2 days'")},
			${invitation(ids.held, held, "held@example.invalid", "now()-interval '10 days'", "now()-interval '3 days'")},
			${invitation(ids.inactive, closing, "inactive@example.invalid", "now()-interval '10 days'", "now()-interval '3 days'")},
			${invitation(ids.missingPolicy, noPolicy, "policyless@example.invalid", "now()-interval '10 days'", "now()-interval '3 days'")},
			${invitation(ids.strict, strict, "strict@example.invalid", "now()-interval '3 days'", "now()-interval '2 days'")};`);

		const dry = await rpc(1, false);
		assert.equal(dry.applied, false);
		assert.equal(dry.eligible, 1, "dry run obeys the global row limit");
		assert.equal(dry.deleted, 0);
		assert.equal(dry.remaining, 1);
		assert.equal(dry.held_tenants_present, 1);
		assert.equal(dry.inactive_tenant_rows_present, 1);
		assert.equal(dry.active_tenants_missing_policy, 1);
		assert.equal(await sql("select count(*) from public.team_invitations;"), "9", "dry run is non-destructive");

		const first = await rpc(1, true);
		assert.equal(first.deleted, 1);
		assert.equal(first.remaining, 1);
		assert.equal(await sql(`select count(*) from public.team_invitations where id='${ids.oldest}';`), "0",
			"oldest due invitation is removed first");
		assert.equal(await sql(`select count(*) from public.team_invitations where id='${ids.newer}';`), "1");
		const second = await rpc(1, true);
		assert.equal(second.deleted, 1);
		assert.equal(second.remaining, 0);
		assert.equal((await rpc()).deleted, 0, "repeat is idempotent");
		for (const id of [ids.young, ids.live, ids.accepted, ids.held, ids.inactive, ids.missingPolicy, ids.strict]) {
			assert.equal(await sql(`select count(*) from public.team_invitations where id='${id}';`), "1", `${id} must be retained`);
		}

		// Retention follows each tenant's configured period, not a hard-coded age.
		await sql(`update public.team_invitations set created_at=now()-interval '6 days' where id='${ids.strict}';`);
		assert.equal((await rpc(100, false)).eligible, 1);
		assert.equal((await rpc(100, false)).deleted, 0);
		assert.equal((await rpc(100,true)).deleted, 1);

		// Active legal hold and non-active status stop deletion; after release/reactivation
		// the same expired rows become eligible without changing their evidence.
		await sql(`update public.tenant_legal_holds set released_at=now() where tenant_id='${held}';
			update public.tenants set status='active' where id='${closing}';
			insert into public.tenant_data_retention_policies(tenant_id,data_class,retention_days)
				values ('${noPolicy}','identity_membership',0);`);
		assert.equal((await rpc(100,true)).deleted, 3);
		for (const id of [ids.held, ids.inactive, ids.missingPolicy]) {
			assert.equal(await sql(`select count(*) from public.team_invitations where id='${id}';`), "0");
		}

		// The same advisory lock used by hold placement/offboarding prevents a
		// competing cleanup worker from treating contention as a completion receipt.
		const lockRowTenant = active;
		await sql(`insert into public.team_invitations(id,tenant_id,email,token_hash,role,created_by,created_at,expires_at,accepted_at)
			values ${invitation(ids.locked, lockRowTenant, "locked@example.invalid", "now()-interval '10 days'", "now()-interval '3 days'")};`);
		const unlock = await lockedTenant(lockRowTenant);
		try {
			const contended = await rpc(100,true);
			assert.equal(contended.deleted, 0);
			assert.equal(contended.contended_tenants, 1);
			assert.equal(contended.remaining, 1);
		} finally { await unlock(); }
		assert.equal((await rpc(100,true)).deleted, 1, "cleanup resumes after the tenant lock is released");

		for (const role of ["anon", "authenticated"]) {
			await denied(`set role ${role}; select public.prune_expired_team_invitations();`, /permission denied/);
		}
		await denied("begin isolation level repeatable read; select public.prune_expired_team_invitations();",
			/invitation_retention_requires_read_committed/);
		await denied("select public.prune_expired_team_invitations(0);", /invalid_invitation_retention_batch/);
		await denied("select public.prune_expired_team_invitations(1001);", /invalid_invitation_retention_batch/);
	} finally {
		const removed = await docker(["rm", "--force", container]);
		assert.equal(removed.code, 0, removed.stderr);
	}
});
