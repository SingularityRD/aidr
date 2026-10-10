// Real PostgreSQL regression: full canonical migration chain, then the rollback
// SQL checks and two-session races for owner-only bounded workspace retention
// and the atomic OIDC provider save (production gaps 2 and 15).
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";
import { authIdentityFixtureSql } from "./lib/postgres-auth-fixture.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-retention-oidc-${randomUUID().slice(0, 8)}`;
const psql = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=20000 -c lock_timeout=15000", container,
	"psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];

function command(args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 120_000 });
		let stdout = ""; let stderr = "";
		child.stdout.on("data", (c) => { stdout += c; });
		child.stderr.on("data", (c) => { stderr += c; });
		child.on("error", reject);
		child.on("close", (code) => done({ code, stdout: stdout.trim(), stderr }));
		child.stdin.on("error", () => {});
		child.stdin.end(input);
	});
}
async function sql(text) { const r = await command(psql, text); assert.equal(r.code, 0, r.stderr); return r.stdout; }
function session(name) {
	const child = spawn("docker", psql, { stdio: ["pipe", "pipe", "pipe"], timeout: 30_000 });
	const state = { child, stdout: "", stderr: "" };
	child.stdout.setEncoding("utf8").on("data", (c) => { state.stdout += c; });
	child.stderr.setEncoding("utf8").on("data", (c) => { state.stderr += c; });
	child.stdin.on("error", () => {});
	state.closed = new Promise((done) => child.on("close", (code) => done({ code, stdout: state.stdout, stderr: state.stderr })));
	child.stdin.write(`set application_name='${name}'; begin;\n`);
	return state;
}
async function marker(state, text) {
	for (let i = 0; i < 200; i++) { if (state.stdout.includes(text)) return; await delay(25); }
	assert.fail(`missing ${text}: ${state.stdout}\n${state.stderr}`);
}
async function lockWait(name) {
	for (let i = 0; i < 200; i++) {
		if (await sql(`select exists(select 1 from pg_stat_activity where application_name='${name}' and wait_event_type='Lock');`) === "t") return;
		await delay(25);
	}
	assert.fail(`${name} never waited for a lock`);
}

test("workspace retention + OIDC provider save on full-chain PostgreSQL", { timeout: 900_000 }, async (t) => {
	const started = await command(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=test-only", "supabase/postgres:17.6.1.136"]);
	assert.equal(started.code, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 150 && !ready; i++) {
			ready = (await command(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0;
			if (!ready) await delay(200);
		}
		assert.ok(ready);
		await delay(1500);
		const storage = await command(["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"],
			`grant create on schema storage to postgres;
			 ${authIdentityFixtureSql}
			 create function auth.jwt() returns jsonb language sql stable as $$
			   select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb $$;`);
		assert.equal(storage.code, 0, storage.stderr);
		await sql(`create table storage.buckets(id text primary key, name text, public boolean);
			create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, metadata jsonb);
			create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;`);
		const only = process.env.SCRATCH_SKIP ? new Set(process.env.SCRATCH_SKIP.split(",")) : new Set();
		const migrations = readdirSync(resolve(root, "supabase/migrations")).filter((n) => n.endsWith(".sql") && !only.has(n)).sort();
		for (const name of migrations) {
			const r = await command(psql, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
			assert.equal(r.code, 0, `${name}: ${r.stderr}`);
		}
		t.diagnostic(`Applied ${migrations.length} migrations through ${migrations.at(-1)}`);

		for (const file of (process.env.SCRATCH_SQL ?? "workspace-settings-retention.rollback.sql,oidc-provider-save.rollback.sql").split(",")) {
			await t.test(file, async () => {
				const r = await command(["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"],
					readFileSync(resolve(root, "supabase/functions/__tests__", file), "utf8"));
				t.diagnostic(`${file}: code=${r.code} ${r.stderr.trim()}`);
				assert.equal(r.code, 0, r.stderr);
				assert.match(r.stderr, /: ok/);
			});
		}
		if (process.env.SCRATCH_SQL) return;

		async function tenantFixture(kind) {
			const tenant = randomUUID(); const owner = randomUUID(); const admin = randomUUID(); const backup = randomUUID();
			await sql(`insert into auth.users(id,email) values ('${owner}','o-${owner}@x.invalid'),('${admin}','a-${admin}@x.invalid'),('${backup}','b-${backup}@x.invalid');
				insert into public.tenant_members(tenant_id,user_id,role) select '${tenant}','${backup}','owner' where false;
				insert into public.tenants(id,name,kind,created_by) values ('${tenant}','Race fixture','${kind}','${owner}');
				insert into public.teams(id,tenant_id,name,plan) values ('${tenant}','${tenant}','Race fixture','free');
				insert into public.tenant_members(tenant_id,user_id,role) values ('${tenant}','${owner}','owner'),('${tenant}','${admin}','admin'),('${tenant}','${backup}','owner');`);
			return { tenant, owner, admin };
		}

		await t.test("workspace retention: owner demoted while waiting on the tenant lock is refused", async () => {
			const f = await tenantFixture("team");
			const before = await sql(`select string_agg(data_class||'='||retention_days, ',' order by data_class) from public.tenant_data_retention_policies where tenant_id='${f.tenant}';`);
			const holder = session("ws-holder");
			holder.child.stdin.write(`select pg_advisory_xact_lock(hashtextextended('${f.tenant}',2606)); select 'HELD';\n`);
			await marker(holder, "HELD");
			const waiter = session("ws-waiter");
			waiter.child.stdin.end(`set local role service_role; select public.update_tenant_workspace_settings('${f.tenant}','${f.owner}',null,7); commit;\n`);
			await lockWait("ws-waiter");
			holder.child.stdin.end(`update public.tenant_members set role='admin' where tenant_id='${f.tenant}' and user_id='${f.owner}'; commit;\n`);
			const [a, b] = await Promise.all([holder.closed, waiter.closed]);
			assert.equal(a.code, 0, a.stderr);
			assert.notEqual(b.code, 0, "demoted owner changed retention");
			assert.match(b.stderr, /retention_admin_owner_required/);
			assert.doesNotMatch(b.stderr, /deadlock/);
			assert.equal(await sql(`select string_agg(data_class||'='||retention_days, ',' order by data_class) from public.tenant_data_retention_policies where tenant_id='${f.tenant}';`), before);
		});

		await t.test("workspace retention: concurrent admin rename and owner retention change both commit without deadlock", async () => {
			const f = await tenantFixture("team");
			const owner = session("ws-owner");
			owner.child.stdin.write(`set local role service_role; select public.update_tenant_workspace_settings('${f.tenant}','${f.owner}',null,7); select 'OWNER_DONE';\n`);
			await marker(owner, "OWNER_DONE");
			const admin = session("ws-admin");
			admin.child.stdin.end(`set local role service_role; select public.update_tenant_workspace_settings('${f.tenant}','${f.admin}','Renamed',null); commit;\n`);
			await lockWait("ws-admin");
			owner.child.stdin.end("commit;\n");
			const [a, b] = await Promise.all([owner.closed, admin.closed]);
			assert.equal(a.code, 0, a.stderr);
			assert.equal(b.code, 0, b.stderr);
			assert.equal(await sql(`select name||'/'||retention_days from public.tenants where id='${f.tenant}';`), "Renamed/7");
		});

		await t.test("oidc_save_provider: owner demoted while waiting is refused and nothing is written", async () => {
			const f = await tenantFixture("enterprise");
			const provider = randomUUID();
			const doc = JSON.stringify({ id: provider, tenant_id: f.tenant, kind: "generic", display_name: "Race IdP",
				issuer: "https://idp.example.invalid", client_id: "race-client", client_secret_ref: null, token_auth_method: "none",
				allowed_algs: ["RS256"], subject_claim: "sub", groups_claim: null, groups_mode: "ignore",
				session_max_seconds: 43200, clock_skew_seconds: 60, discovery: { issuer: "https://idp.example.invalid" }, enabled: true });
			const holder = session("oidc-holder");
			holder.child.stdin.write(`select pg_advisory_xact_lock(hashtextextended('${f.tenant}',2606)); select 'HELD';\n`);
			await marker(holder, "HELD");
			const waiter = session("oidc-waiter");
			waiter.child.stdin.end(`set local role service_role; select public.oidc_save_provider('${f.owner}','${doc}'::jsonb,'identity.oidc.provider_updated','{}'); commit;\n`);
			await lockWait("oidc-waiter");
			holder.child.stdin.end(`update public.tenant_members set role='admin' where tenant_id='${f.tenant}' and user_id='${f.owner}'; commit;\n`);
			const [a, b] = await Promise.all([holder.closed, waiter.closed]);
			assert.equal(a.code, 0, a.stderr);
			assert.notEqual(b.code, 0, "demoted owner saved the provider");
			assert.match(b.stderr, /oidc_provider_forbidden/);
			assert.equal(await sql(`select count(*) from public.oidc_providers where tenant_id='${f.tenant}';`), "0");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id='${f.tenant}' and action like 'identity.oidc.%';`), "0");
		});

		await t.test("oidc_save_provider: a demotion attempted mid-save waits for the save to commit", async () => {
			const f = await tenantFixture("enterprise");
			const provider = randomUUID();
			const doc = JSON.stringify({ id: provider, tenant_id: f.tenant, kind: "generic", display_name: "Race IdP",
				issuer: "https://idp.example.invalid", client_id: "race-client", token_auth_method: "none",
				allowed_algs: ["RS256"], subject_claim: "sub", groups_mode: "ignore",
				session_max_seconds: 43200, clock_skew_seconds: 60, enabled: false });
			const saver = session("oidc-saver");
			saver.child.stdin.write(`set local role service_role; select public.oidc_save_provider('${f.owner}','${doc}'::jsonb,'identity.oidc.provider_updated','{}'); select 'SAVED';\n`);
			await marker(saver, "SAVED");
			const demoter = session("oidc-demoter");
			demoter.child.stdin.end(`update public.tenant_members set role='admin' where tenant_id='${f.tenant}' and user_id='${f.owner}'; commit;\n`);
			await lockWait("oidc-demoter");
			saver.child.stdin.end("commit;\n");
			const [a, b] = await Promise.all([saver.closed, demoter.closed]);
			assert.equal(a.code, 0, a.stderr);
			assert.equal(b.code, 0, b.stderr);
			assert.equal(await sql(`select count(*) from public.oidc_providers where tenant_id='${f.tenant}';`), "1");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id='${f.tenant}' and action='identity.oidc.provider_updated';`), "1");
		});
	} finally {
		await command(["rm", "-f", container]);
	}
});
