import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";

const container = `aidr-discovery-cloud-${randomUUID()}`;
const literal = value => `'${String(value).replaceAll("'", "''")}'`;
function docker(args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 120000 });
		let stdout = "", stderr = "";
		child.stdout.on("data", value => { stdout += value; }); child.stderr.on("data", value => { stderr += value; });
		child.once("error", reject); child.once("close", code => done({ code, stdout: stdout.trim(), stderr }));
		child.stdin.on("error", () => {}); child.stdin.end(input);
	});
}
const args = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=10000 -c lock_timeout=5000", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
async function sql(text) { const r = await docker(args, text); assert.equal(r.code, 0, r.stderr); return r.stdout; }
async function denied(text, pattern) { const r = await docker(args, text); assert.notEqual(r.code, 0); assert.match(r.stderr, pattern); }

test("typed provider discovery preserves authorization, reconciliation and offboarding", { timeout: 600000 }, async t => {
	const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container, "-e", "POSTGRES_PASSWORD=discovery-fixture-only", "supabase/postgres:17.6.1.136"]);
	assert.equal(started.code, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 150 && !ready; i++) { ready = (await docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0; if (!ready) await delay(100); }
		assert.ok(ready);
		const bootstrap = await docker(["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"], `grant create on schema storage to postgres;
create table auth.identities(id uuid primary key default gen_random_uuid(),user_id uuid,provider text,provider_id text,identity_data jsonb);
grant select,insert,update,delete on auth.identities to postgres;
create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb $$;`);
		assert.equal(bootstrap.code, 0, bootstrap.stderr);
		await sql(`create table storage.buckets(id text primary key,name text,public boolean);
create table storage.objects(id uuid primary key default gen_random_uuid(),bucket_id text,name text,metadata jsonb);
create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name,'/') $$;`);
		for (const name of readdirSync("supabase/migrations").filter(name => /^\d+_.+\.sql$/.test(name)).sort()) {
			const r = await docker(args, `begin;\n${readFileSync(resolve("supabase/migrations", name), "utf8")}\ncommit;`); assert.equal(r.code, 0, `${name}: ${r.stderr}`);
		}
		const owner = randomUUID(), outsider = randomUUID(), tenant = randomUUID(), scopeHash = "a".repeat(64), tokenHash = "b".repeat(64);
		await sql(`insert into auth.users(id,email,raw_app_meta_data) values (${literal(owner)},'owner@example.invalid','{"aidr_scim_provisioned":true}'),(${literal(outsider)},'outsider@example.invalid','{"aidr_scim_provisioned":true}');
insert into public.tenants(id,name,kind,created_by) values(${literal(tenant)},'Discovery fixture','team',${literal(owner)});
insert into public.teams(id,tenant_id,name) values(${literal(tenant)},${literal(tenant)},'Discovery fixture');
insert into public.team_members(team_id,tenant_id,user_id,role) values(${literal(tenant)},${literal(tenant)},${literal(owner)},'owner');
update public.tenant_data_retention_policies set retention_days=0 where tenant_id=${literal(tenant)};`);
		const evidence = (items, complete = true, hash = scopeHash) => ({ provider: "aws", scope_hash: hash, coverage: "tagged_resources", complete, observed_at: new Date().toISOString(), items });
		const item = id => ({ resource_id: `arn:aws:s3:::${id}`, resource_type: "s3:bucket", scope_id: "aws:123456789012:eu-central-1", region: "eu-central-1", observed_at: new Date(Date.now() - 1000).toISOString() });
		const ingest = (sequence, payload, actor = owner) => `public.ingest_tenant_discovery_cycle(${literal(tenant)},${literal(actor)},'cloud',${literal(randomUUID())},${sequence},60000,${payload.complete},0,'[]'::jsonb,${literal(JSON.stringify(payload))}::jsonb)`;
		const machine = (sequence, payload) => `public.ingest_tenant_discovery_cycle_machine(${literal(tenant)},'cloud',${literal(tokenHash)},${literal(randomUUID())},${sequence},60000,${payload.complete},0,'[]'::jsonb,${literal(JSON.stringify(payload))}::jsonb)`;
		await t.test("cloud-only cycle stores real identifiers without URL coercion and rejects replay or foreign actors", async () => {
			await sql(`set role service_role;select ${ingest(1, evidence([item("first")]))};`);
			assert.equal(await sql(`select resource_id from public.tenant_discovery_provider_resources where tenant_id=${literal(tenant)};`), "arn:aws:s3:::first");
			await denied(`set role service_role;select ${ingest(1, evidence([]))};`, /discovery_cycle_replayed/);
			await denied(`set role service_role;select ${ingest(2, evidence([]), outsider)};`, /discovery_forbidden/);
			await denied(`set role authenticated;select * from public.tenant_discovery_provider_resources;`, /permission denied/);
		});
		await t.test("partial omissions retain evidence; complete cycles reconcile; invalid inventory cannot advance cursor", async () => {
			await sql(`set role service_role;select ${ingest(2, evidence([], false))};`);
			assert.equal(await sql(`select count(*) from public.tenant_discovery_provider_resources where tenant_id=${literal(tenant)};`), "1");
			assert.equal(await sql(`select complete from public.tenant_discovery_collectors where tenant_id=${literal(tenant)};`), "f");
			await denied(`set role service_role;select ${ingest(3, evidence([item("dup"), item("dup")]))};`, /duplicate_discovery_resource/);
			assert.equal(await sql(`select sequence from public.tenant_discovery_collectors where tenant_id=${literal(tenant)};`), "2");
			await sql(`set role service_role;select ${ingest(3, evidence([item("second")]))};`);
			assert.equal(await sql(`select resource_id from public.tenant_discovery_provider_resources where tenant_id=${literal(tenant)};`), "arn:aws:s3:::second");
		});
		await t.test("machine upload requires the reviewed provider scope and legacy rotation removes that grant", async () => {
			const issue = scope => `public.issue_tenant_discovery_credential(${literal(tenant)},${literal(owner)},'cloud',${literal(tokenHash)},30,${scope ? literal(JSON.stringify(scope)) + "::jsonb" : "null"})`;
			await sql(`set role service_role;select ${issue(null)};`);
			await denied(`set role service_role;select ${machine(4, evidence([]))};`, /invalid_collector_provider_scope/);
			await sql(`set role service_role;select ${issue({ provider: "aws", scope_hash: scopeHash })};`);
			assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(tenant)} and action='discovery.credential.issued' and detail->'allowed_provider_scope'= ${literal(JSON.stringify({ provider: "aws", scope_hash: scopeHash }))}::jsonb;`), "1");
			await denied(`set role service_role;select ${machine(4, evidence([], true, "c".repeat(64)))};`, /invalid_collector_provider_scope/);
			await sql(`set role service_role;select ${machine(4, evidence([item("machine")]))};`);
			assert.equal(await sql(`select detail->>'provider_resource_count' from public.admin_audit_logs where tenant_id=${literal(tenant)} and action='discovery.cycle.ingested' and detail->>'sequence'='4' and detail->'provider_scope'=${literal(JSON.stringify({ provider: "aws", scope_hash: scopeHash }))}::jsonb;`), "1");
			await sql(`set role service_role;select public.issue_tenant_discovery_credential(${literal(tenant)},${literal(owner)},'cloud',${literal(tokenHash)},30);`);
			await denied(`set role service_role;select ${machine(5, evidence([]))};`, /invalid_collector_provider_scope/);
			const legacyCycle = randomUUID(), legacyTokenHash = "d".repeat(64);
			await sql(`set role service_role;
select public.ingest_tenant_discovery_cycle(${literal(tenant)},${literal(owner)},'legacy-http',${literal(randomUUID())},1,60000,true,0,'[]'::jsonb,${literal(JSON.stringify(evidence([item("legacy")])))}::jsonb);
select public.issue_tenant_discovery_credential(${literal(tenant)},${literal(owner)},'legacy-http',${literal(legacyTokenHash)},30,${literal(JSON.stringify({ provider: "aws", scope_hash: scopeHash }))}::jsonb);
select public.ingest_tenant_discovery_cycle_machine(${literal(tenant)},'legacy-http',${literal(legacyTokenHash)},${literal(legacyCycle)},2,60000,true,1,'[{"target":"https://example.invalid/","reachable":true,"attempts":1,"error_code":null}]'::jsonb);`);
			assert.equal(await sql(`select provider_evidence is null from public.tenant_discovery_collectors where tenant_id=${literal(tenant)} and collector_id='legacy-http';`), "t");
			assert.equal(await sql(`select count(*) from public.tenant_discovery_provider_resources where tenant_id=${literal(tenant)} and collector_id='legacy-http';`), "0");
			assert.equal(await sql(`select target from public.tenant_discovery_items where tenant_id=${literal(tenant)} and collector_id='legacy-http';`), "https://example.invalid/");
			await denied(`set role service_role;select public.ingest_tenant_discovery_cycle_machine(${literal(tenant)},'legacy-http',${literal(legacyTokenHash)},${literal(randomUUID())},3,60000,true,0,'[]'::jsonb);`, /invalid_discovery_cycle/);
		});
		await t.test("legal hold preserves completed omissions and actual endpoint phase erases dependent cloud rows", async () => {
			const hold = await sql(`select public.admin_place_tenant_legal_hold(${literal(tenant)},${literal(owner)},'CASE-CLOUD','Fixture owner','Preserve discovered resource evidence');`);
			await sql(`set role service_role;select ${ingest(5, evidence([]))};`);
			assert.equal(await sql(`select count(*) from public.tenant_discovery_provider_resources where tenant_id=${literal(tenant)};`), "1");
			const run = JSON.parse(await sql(`set role service_role;select public.request_tenant_offboarding(${literal(tenant)},${literal(owner)});`)).run_id;
			assert.equal(JSON.parse(await sql(`set role service_role;select public.run_tenant_offboarding_batch(${literal(run)},100);`)).status, "blocked_legal_hold");
			await sql(`update public.tenant_legal_holds set released_at=now(),released_by=${literal(owner)},release_reason='Fixture release after hold assertion' where id=${literal(hold)};
update public.tenant_offboarding_phase_receipts set eligible_at=now() where run_id=${literal(run)} and status<>'completed';`);
			for (let i = 0; i < 100; i++) { const state = JSON.parse(await sql(`set role service_role;select public.run_tenant_offboarding_batch(${literal(run)},100);`)); if (state.action === "invalidate_cache") await sql(`set role service_role;select public.ack_tenant_offboarding_cache(${literal(run)},array['fixture-cache'],0);`); if (state.status === "completed") break; }
			assert.equal(await sql(`select count(*) from public.tenant_discovery_provider_resources where tenant_id=${literal(tenant)};`), "0");
			assert.equal(await sql(`select status from public.tenant_offboarding_phase_receipts where run_id=${literal(run)} and phase='agents';`), "completed");
			await denied(`set role service_role;select ${ingest(6, evidence([]))};`, /discovery_forbidden/);
		});
	} finally { const removed = await docker(["rm", "--force", container]); assert.equal(removed.code, 0, removed.stderr); }
});
