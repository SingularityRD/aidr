// Real PostgreSQL regression: full canonical migration chain, then the rollback
// SQL checks and two-session races for owner-only bounded workspace retention
// and the atomic OIDC provider save (production gaps 2 and 15), plus the
// follow-ups: a workspace change never silently shortens a retention class
// (20261011000200) and a discovery refresh never writes back a stale provider
// row (20261011000300).
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
		"-e", "POSTGRES_PASSWORD=test-only", "supabase/postgres:17.11.0.004"]);
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
			owner.child.stdin.write(`set local role service_role; select public.update_tenant_workspace_settings('${f.tenant}','${f.owner}',null,7,true); select 'OWNER_DONE';\n`);
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

		const classes = (tenant) => sql(`select string_agg(data_class||'='||retention_days, ',' order by data_class) from public.tenant_data_retention_policies where tenant_id='${tenant}';`);

		await t.test("workspace retention: raising the workspace value never shortens a longer per-class value", async () => {
			const f = await tenantFixture("team");
			// The free plan caps telemetry at 7 days; lift it in this disposable database.
			await sql("update public.plans set retention_days = 3650 where id = 'free';");
			await sql(`set role service_role;
				select public.admin_set_tenant_retention('${f.tenant}','${f.owner}',d,3650,'Long-term evidence')
				  from unnest(array['security_audit','commercial_records','identity_membership']) d;`);
			const before = await classes(f.tenant);
			assert.match(before, /commercial_records=3650/);
			assert.match(before, /identity_membership=3650/);
			assert.match(before, /security_audit=3650/);
			// The reported repro: 30 -> 31, no confirmation (it is an increase).
			const result = JSON.parse(await sql(`set role service_role; select public.update_tenant_workspace_settings('${f.tenant}','${f.owner}',null,31);`));
			assert.equal(result.retention_days, 31);
			const after = await classes(f.tenant);
			for (const pair of before.split(",")) {
				const [cls, days] = pair.split("=");
				if (cls === "operational_ephemera") continue;
				const now = Number(new RegExp(`${cls}=(\\d+)`).exec(after)?.[1]);
				assert.ok(now >= Number(days), `${cls} shortened ${days} -> ${now} (${after})`);
			}
			assert.match(after, /commercial_records=3650/);
			assert.match(after, /identity_membership=3650/);
			assert.match(after, /security_audit=3650/);
			assert.match(after, /telemetry=31/);

			// Telemetry raised per class above the workspace value: a workspace
			// "increase" (31 -> 40) that lowers stored telemetry (90) is refused.
			await sql(`set role service_role; select public.admin_set_tenant_retention('${f.tenant}','${f.owner}','telemetry',90,'Longer telemetry');`);
			const refused = await command(psql, `set role service_role; select public.update_tenant_workspace_settings('${f.tenant}','${f.owner}',null,40);`);
			assert.notEqual(refused.code, 0, "unconfirmed telemetry reduction was applied");
			assert.match(refused.stderr, /retention_reduction_unconfirmed/);
			assert.match(await classes(f.tenant), /telemetry=90/);
			assert.equal(await sql(`select retention_days from public.tenants where id='${f.tenant}';`), "31");
			// Confirmed, telemetry follows; nothing else goes down.
			await sql(`set role service_role; select public.update_tenant_workspace_settings('${f.tenant}','${f.owner}',null,40,true);`);
			const confirmed = await classes(f.tenant);
			assert.match(confirmed, /telemetry=40/);
			assert.match(confirmed, /security_audit=3650/);
			assert.match(confirmed, /identity_membership=3650/);
			assert.equal(await sql(`select detail->>'retention_reduction_confirmed' from public.admin_audit_logs where tenant_id='${f.tenant}' and action='tenant.settings_updated' order by created_at desc limit 1;`), "true");
			await sql("update public.plans set retention_days = 7 where id = 'free';");
		});

		const enabledProvider = (f, id) => JSON.stringify({ id, tenant_id: f.tenant, kind: "generic", display_name: "Race IdP",
			issuer: "https://idp.example.invalid", client_id: "race-client", client_secret_ref: null, token_auth_method: "none",
			allowed_algs: ["RS256"], subject_claim: "sub", groups_claim: null, groups_mode: "ignore",
			session_max_seconds: 43200, clock_skew_seconds: 60,
			discovery: { issuer: "https://idp.example.invalid", jwks_uri: "https://idp.example.invalid/old-keys" }, enabled: true });
		const freshDiscovery = JSON.stringify({ issuer: "https://idp.example.invalid", authorization_endpoint: "https://idp.example.invalid/authorize",
			token_endpoint: "https://idp.example.invalid/token", jwks_uri: "https://idp.example.invalid/new-keys" });
		const refreshSql = (f, id, issuer = "https://idp.example.invalid") =>
			`set local role service_role; select public.oidc_update_provider_discovery('${f.owner}','${f.tenant}','${id}','${issuer}',array['RS256'],'${freshDiscovery}'::jsonb,'{"jwks_changed":true}'::jsonb);`;
		const providerState = (id) => sql(`select enabled||'/'||display_name||'/'||(discovery->>'jwks_uri') from public.oidc_providers where id='${id}';`);

		await t.test("oidc discovery refresh: a disable committed during the refresh stays disabled", async () => {
			const f = await tenantFixture("enterprise");
			const provider = randomUUID();
			const doc = enabledProvider(f, provider);
			await sql(`set role service_role; select public.oidc_save_provider('${f.owner}','${doc}'::jsonb,'identity.oidc.provider_updated','{}');`);
			// Edge function reads the (enabled) row, then starts the slow discovery fetch.
			// Meanwhile another owner disables the provider; their transaction is still open.
			const disabler = session("oidc-disabler");
			const disabled = JSON.stringify({ ...JSON.parse(doc), enabled: false, display_name: "Disabled" });
			disabler.child.stdin.write(`set local role service_role; select public.oidc_save_provider('${f.owner}','${disabled}'::jsonb,'identity.oidc.provider_updated','{}'); select 'DISABLED';\n`);
			await marker(disabler, "DISABLED");
			// The refresh lands while the disable is in flight: it waits on the tenant lock.
			const refresher = session("oidc-refresher");
			refresher.child.stdin.end(`${refreshSql(f, provider)} commit;\n`);
			await lockWait("oidc-refresher");
			disabler.child.stdin.end("commit;\n");
			const [a, b] = await Promise.all([disabler.closed, refresher.closed]);
			assert.equal(a.code, 0, a.stderr);
			assert.equal(b.code, 0, b.stderr);
			assert.equal(await providerState(provider), "false/Disabled/https://idp.example.invalid/new-keys");
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id='${f.tenant}' and action='identity.oidc.discovery_refreshed' and detail->>'provider_id'='${provider}';`), "1");

			// A refresh committed after the disable, sequentially, likewise keeps it disabled.
			await sql(`begin; ${refreshSql(f, provider)} commit;`);
			assert.equal(await providerState(provider), "false/Disabled/https://idp.example.invalid/new-keys");
		});

		await t.test("oidc discovery refresh: refused when the issuer changed since the read, or for a non-owner", async () => {
			const f = await tenantFixture("enterprise");
			const provider = randomUUID();
			await sql(`set role service_role; select public.oidc_save_provider('${f.owner}','${enabledProvider(f, provider)}'::jsonb,'identity.oidc.provider_updated','{}');`);
			const before = await providerState(provider);
			const stale = await command(psql, `begin; ${refreshSql(f, provider, "https://old-idp.example.invalid")} commit;`);
			assert.notEqual(stale.code, 0, "stale-issuer refresh committed");
			assert.match(stale.stderr, /oidc_provider_changed/);
			const admin = await command(psql, `begin; ${refreshSql({ ...f, owner: f.admin }, provider)} commit;`);
			assert.notEqual(admin.code, 0, "admin refreshed discovery");
			assert.match(admin.stderr, /oidc_provider_forbidden/);
			assert.equal(await providerState(provider), before);
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id='${f.tenant}' and action='identity.oidc.discovery_refreshed';`), "0");
			// Grants: service_role only.
			assert.equal(await sql(`select has_function_privilege('anon','public.oidc_update_provider_discovery(uuid,uuid,uuid,text,text[],jsonb,jsonb)','execute')
				or has_function_privilege('authenticated','public.oidc_update_provider_discovery(uuid,uuid,uuid,text,text[],jsonb,jsonb)','execute')
				or has_function_privilege('anon','public.update_tenant_workspace_settings(uuid,uuid,text,integer,boolean)','execute')
				or has_function_privilege('authenticated','public.update_tenant_workspace_settings(uuid,uuid,text,integer,boolean)','execute');`), "f");
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
