// Real PostgreSQL regression for the dashboard-pushed Browser Guard setting
// (supabase/migrations/20261010000200_browser_guard_native_ner_setting.sql):
// the full canonical migration chain in an isolated supabase/postgres container,
// then public.update_browser_guard_settings — owner/admin only on an active
// tenant, audited, no direct client write, four-eyes refuses relaxing it, and a
// concurrent demotion waits for an in-flight change instead of racing it.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { authIdentityFixtureSql } from "./lib/postgres-auth-fixture.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-bg-settings-${randomUUID().slice(0, 8)}`;
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
async function fails(text, pattern) {
	const r = await command(psql, text);
	assert.notEqual(r.code, 0, `expected failure: ${text}`);
	assert.match(r.stderr, pattern);
}
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

const rpc = (tenant, actor, value) =>
	`set local role service_role; select public.update_browser_guard_settings(${tenant === null ? "null" : `'${tenant}'`},${actor === null ? "null" : `'${actor}'`},${value});`;
const asService = (body) => `begin; ${body} commit;`;

test("Browser Guard require-native-NER setting on full-chain PostgreSQL", { timeout: 900_000 }, async (t) => {
	// No silent skip: this is a CI gate (docker + supabase/postgres:17.6.1.136 required).
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
		const migrations = readdirSync(resolve(root, "supabase/migrations")).filter((n) => n.endsWith(".sql")).sort();
		for (const name of migrations) {
			const r = await command(psql, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
			assert.equal(r.code, 0, `${name}: ${r.stderr}`);
		}
		assert.ok(migrations.includes("20261010000200_browser_guard_native_ner_setting.sql"));
		t.diagnostic(`Applied ${migrations.length} migrations through ${migrations.at(-1)}`);

		async function tenantFixture() {
			const tenant = randomUUID(); const owner = randomUUID(); const admin = randomUUID();
			const member = randomUUID(); const viewer = randomUUID();
			const users = [owner, admin, member, viewer];
			await sql(`insert into auth.users(id,email) values ${users.map((u) => `('${u}','u-${u}@x.invalid')`).join(",")};
				insert into public.tenants(id,name,kind,created_by) values ('${tenant}','BG fixture','team','${owner}');
				insert into public.teams(id,tenant_id,name,plan) values ('${tenant}','${tenant}','BG fixture','team');
				insert into public.tenant_members(tenant_id,user_id,role) values ('${tenant}','${owner}','owner'),
				  ('${tenant}','${admin}','admin'),('${tenant}','${member}','member'),('${tenant}','${viewer}','viewer');`);
			return { tenant, owner, admin, member, viewer };
		}
		const value = (tenant) => sql(`select coalesce((select browser_guard_require_native_ner::text from public.tenant_ai_governance_settings where tenant_id='${tenant}'),'none');`);
		const audits = (tenant) => sql(`select coalesce(string_agg(detail::text, '|' order by created_at), '') from public.admin_audit_logs where tenant_id='${tenant}' and action='browser_guard.settings_updated';`);

		await t.test("schema: defaulted column, service-role-only RPC, no client write path", async () => {
			assert.equal(await sql(`select data_type||':'||is_nullable||':'||column_default from information_schema.columns
				where table_schema='public' and table_name='tenant_ai_governance_settings' and column_name='browser_guard_require_native_ner';`),
			"boolean:NO:false");
			const fn = "public.update_browser_guard_settings(uuid,uuid,boolean)";
			assert.equal(await sql(`select prosecdef from pg_proc where oid='${fn}'::regprocedure;`), "t");
			assert.equal(await sql(`select string_agg(r||'='||has_function_privilege(r,'${fn}','execute')::text, ',' order by r)
				from unnest(array['anon','authenticated','service_role']) r;`), "anon=false,authenticated=false,service_role=true");
			assert.equal(await sql(`select has_column_privilege('authenticated','public.tenant_ai_governance_settings','browser_guard_require_native_ner','update')::text;`), "false");
		});

		await t.test("owner/admin change it with one audit row per change; others are refused", async () => {
			const f = await tenantFixture();
			assert.equal(await value(f.tenant), "none");
			for (const actor of [f.member, f.viewer, randomUUID()]) {
				await fails(asService(rpc(f.tenant, actor, true)), /ai_governance_forbidden/);
			}
			await fails(asService(rpc(f.tenant, f.owner, "null")), /invalid_browser_guard_settings/);
			await fails(asService(rpc(null, f.owner, true)), /invalid_browser_guard_settings/);
			// Another tenant's owner cannot change this tenant.
			const other = await tenantFixture();
			await fails(asService(rpc(f.tenant, other.owner, true)), /ai_governance_forbidden/);
			assert.equal(await value(f.tenant), "none");
			assert.equal(await audits(f.tenant), "");

			const on = JSON.parse((await sql(asService(rpc(f.tenant, f.admin, true)))).split("\n").at(-1));
			assert.deepEqual(on, { require_native_ner: true, changed: true });
			assert.equal(await value(f.tenant), "true");
			const again = JSON.parse((await sql(asService(rpc(f.tenant, f.owner, true)))).split("\n").at(-1));
			assert.deepEqual(again, { require_native_ner: true, changed: false });
			const off = JSON.parse((await sql(asService(rpc(f.tenant, f.owner, false)))).split("\n").at(-1));
			assert.deepEqual(off, { require_native_ner: false, changed: true });
			assert.equal(await value(f.tenant), "false");
			assert.equal(await audits(f.tenant),
				'{"require_native_ner_to": true, "require_native_ner_from": false}|{"require_native_ner_to": false, "require_native_ner_from": true}');
			assert.equal(await sql(`select string_agg(user_id::text, ',' order by created_at) from public.audit_logs where tenant_id='${f.tenant}' and action='browser_guard.settings_updated';`),
				`${f.admin},${f.owner}`);
			assert.equal(await sql(`select updated_by::text from public.tenant_ai_governance_settings where tenant_id='${f.tenant}';`), f.owner);
		});

		await t.test("an inactive tenant cannot be changed", async () => {
			const f = await tenantFixture();
			await sql(`update public.tenants set status='suspended' where id='${f.tenant}';`);
			await fails(asService(rpc(f.tenant, f.owner, true)), /ai_governance_forbidden/);
			assert.equal(await value(f.tenant), "none");
		});

		await t.test("four-eyes: switching it on stays immediate, switching it off is refused", async () => {
			const f = await tenantFixture();
			await sql(asService(rpc(f.tenant, f.owner, true)));
			await sql(asService(`set local role service_role; select public.update_ai_governance_settings('${f.tenant}','${f.owner}',true,null);`));
			await fails(asService(rpc(f.tenant, f.admin, false)), /browser_guard_four_eyes_required/);
			assert.equal(await value(f.tenant), "true");
			assert.equal((await audits(f.tenant)).split("|").length, 1);
			// Confirming the stricter value is not a relaxation.
			await sql(asService(rpc(f.tenant, f.admin, true)));
		});

		await t.test("members read the setting under RLS but cannot write it directly", async () => {
			const f = await tenantFixture();
			await sql(asService(rpc(f.tenant, f.owner, true)));
			const claims = (user) => `select set_config('request.jwt.claims', '{"sub":"${user}","role":"authenticated","aal":"aal1"}', true),
				set_config('request.jwt.claim.sub', '${user}', true);`;
			const read = await sql(`begin; set local role authenticated; ${claims(f.viewer)}
				select coalesce(string_agg(browser_guard_require_native_ner::text, ','), 'none') from public.tenant_ai_governance_settings; commit;`);
			assert.equal(read.split("\n").at(-1), "true");
			await fails(`begin; set local role authenticated; ${claims(f.owner)}
				update public.tenant_ai_governance_settings set browser_guard_require_native_ner=false where tenant_id='${f.tenant}'; commit;`,
			/permission denied/);
			const outsider = await tenantFixture();
			const foreign = await sql(`begin; set local role authenticated; ${claims(outsider.owner)}
				select count(*) from public.tenant_ai_governance_settings where tenant_id='${f.tenant}'; commit;`);
			assert.equal(foreign.split("\n").at(-1), "0");
			assert.equal(await value(f.tenant), "true");
		});

		await t.test("a demotion attempted mid-change waits for the change to commit", async () => {
			const f = await tenantFixture();
			const setter = session("bg-setter");
			setter.child.stdin.write(`${rpc(f.tenant, f.admin, true)} select 'SET';\n`);
			await marker(setter, "SET");
			const demoter = session("bg-demoter");
			demoter.child.stdin.end(`update public.tenant_members set role='member' where tenant_id='${f.tenant}' and user_id='${f.admin}'; commit;\n`);
			await lockWait("bg-demoter");
			setter.child.stdin.end("commit;\n");
			const [a, b] = await Promise.all([setter.closed, demoter.closed]);
			assert.equal(a.code, 0, a.stderr);
			assert.equal(b.code, 0, b.stderr);
			assert.equal(await value(f.tenant), "true");
			assert.equal((await audits(f.tenant)).split("|").length, 1);
			// Demoted now: refused.
			await fails(asService(rpc(f.tenant, f.admin, false)), /ai_governance_forbidden/);
		});
	} finally {
		await command(["rm", "-f", container]);
	}
});
