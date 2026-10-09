// Real PostgreSQL test for the legal-hold management and per-tenant retention RPCs.
// Creates and removes its OWN offline container (cached supabase/postgres image,
// --pull never), applies the COMPLETE canonical migration chain, and never targets
// an existing deployment. Storage's schema is a minimal fixture.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { authIdentityFixtureSql } from "./lib/postgres-auth-fixture.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-hold-admin-${randomUUID().slice(0, 8)}`;

function docker(args, input = "") {
	return new Promise((done, reject) => {
		const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 120_000 });
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
const psql = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=10000 -c lock_timeout=5000", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
async function sql(text) {
	const result = await docker(psql, text);
	assert.equal(result.code, 0, result.stderr);
	return result.stdout;
}
async function denied(text, pattern) {
	const result = await docker(psql, text);
	assert.notEqual(result.code, 0, "statement must be refused");
	assert.match(result.stderr, pattern);
}
const service = (text) => sql(`set role service_role; ${text}`);

test("legal-hold management and tenant retention RPCs on real PostgreSQL", { timeout: 900_000 }, async (t) => {
	const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=hold-admin-fixture-only", "supabase/postgres:17.6.1.136"]);
	assert.equal(started.code, 0, started.stderr);
	try {
		let ready = false;
		for (let i = 0; i < 150 && !ready; i++) {
			ready = (await docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0;
			if (!ready) await new Promise((done) => setTimeout(done, 200));
		}
		assert.ok(ready, "isolated PostgreSQL must start");
		const fixture = await docker(["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"],
			`grant create on schema storage to postgres;
			 ${authIdentityFixtureSql}
			 create function auth.jwt() returns jsonb language sql stable as $$
			   select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb $$;`);
		assert.equal(fixture.code, 0, fixture.stderr);
		await sql(`create table storage.buckets(id text primary key, name text, public boolean);
			create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, metadata jsonb);
			create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;`);
		for (const name of readdirSync(resolve(root, "supabase/migrations")).filter((file) => file.endsWith(".sql")).sort()) {
			const result = await docker(psql, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${name}: ${result.stderr}`);
		}

		const owner = randomUUID();
		const admin = randomUUID();
		const outsider = randomUUID();
		for (const id of [owner, admin, outsider]) {
			await sql(`insert into auth.users(id,email) values ('${id}','hold-${id}@example.invalid');`);
		}
		async function tenant() {
			const id = randomUUID();
			await sql(`insert into public.tenants(id,name,kind,created_by) values ('${id}','Hold fixture','enterprise','${owner}');
				insert into public.tenant_members(tenant_id,user_id,role) values ('${id}','${owner}','owner'), ('${id}','${admin}','admin')
				on conflict (tenant_id,user_id) do update set role = excluded.role;
				-- Retention is bounded by the plan (Free: 7 days). The fixture tenant is an
				-- actively licensed Enterprise tenant so the RPC bounds, not the plan, decide.
				insert into public.teams(id,tenant_id,name,plan) values ('${id}','${id}','Hold fixture','enterprise')
				on conflict (id) do update set plan = 'enterprise';
				insert into public.tenant_admissions(tenant_id,owner_user_id,kind,seats,starts_at,expires_at,grant_reference)
				values ('${id}','${owner}','licensed',25,now() - interval '1 day',now() + interval '365 days','test:licensed-fixture')
				on conflict (tenant_id) do nothing;`);
			return id;
		}
		const place = (id, actor = owner, caseId = "CASE-2026-001", who = "Counsel A. Example", reason = "Preserve evidence for litigation", ref = "null") =>
			service(`select public.admin_place_tenant_legal_hold('${id}','${actor}','${caseId}','${who}','${reason}',${ref});`);
		const release = (id, hold, actor = owner, reason = "Matter closed") =>
			service(`select public.admin_release_tenant_legal_hold('${id}','${actor}','${hold}','${reason}');`);
		const audit = (id, action) => sql(`select count(*) from public.admin_audit_logs where tenant_id='${id}' and action='${action}';`);

		await t.test("only an active owner can place or release; other roles and tenants are refused", async () => {
			const id = await tenant();
			const other = await tenant();
			await denied(`set role service_role; select public.admin_place_tenant_legal_hold('${id}','${admin}','CASE-1','Owner','reason',null);`, /retention_admin_owner_required/);
			await denied(`set role service_role; select public.admin_place_tenant_legal_hold('${id}','${outsider}','CASE-1','Owner','reason',null);`, /retention_admin_owner_required/);
			// An owner of another tenant has no authority here.
			await sql(`insert into public.tenant_members(tenant_id,user_id,role) values ('${other}','${outsider}','owner');`);
			await denied(`set role service_role; select public.admin_place_tenant_legal_hold('${id}','${outsider}','CASE-1','Owner','reason',null);`, /retention_admin_owner_required/);
			assert.equal(await sql(`select count(*) from public.tenant_legal_holds where tenant_id='${id}';`), "0");
			for (const role of ["anon", "authenticated"]) {
				await denied(`set role ${role}; select public.admin_place_tenant_legal_hold('${id}','${owner}','CASE-1','Owner','reason',null);`, /permission denied/);
				await denied(`set role ${role}; select public.admin_release_tenant_legal_hold('${id}','${owner}','${randomUUID()}','done');`, /permission denied/);
				await denied(`set role ${role}; select public.admin_set_tenant_retention('${id}','${owner}','telemetry',60,'x');`, /permission denied/);
			}
		});

		await t.test("placement validates input, records case/owner/reason, audits, and allows one active hold", async () => {
			const id = await tenant();
			await denied(`set role service_role; select public.admin_place_tenant_legal_hold('${id}','${owner}','','Owner','reason',null);`, /legal_hold_invalid_request/);
			await denied(`set role service_role; select public.admin_place_tenant_legal_hold('${id}','${owner}','bad;case','Owner','reason',null);`, /legal_hold_invalid_request/);
			await denied(`set role service_role; select public.admin_place_tenant_legal_hold('${id}','${owner}','CASE-1',' padded ','reason',null);`, /legal_hold_invalid_request/);
			await denied(`set role service_role; select public.admin_place_tenant_legal_hold('${id}','${owner}','CASE-1','Owner','',null);`, /legal_hold_invalid_request/);
			const hold = await place(id);
			assert.match(hold, /^[0-9a-f-]{36}$/);
			assert.equal(await sql(`select case_id||'|'||hold_owner||'|'||hold_reference||'|'||placed_by from public.tenant_legal_holds where id='${hold}';`),
				`CASE-2026-001|Counsel A. Example|CASE-2026-001|${owner}`);
			assert.equal(await audit(id, "legal_hold.placed"), "1");
			assert.equal(await sql(`select detail->>'case_id' from public.admin_audit_logs where tenant_id='${id}' and action='legal_hold.placed';`), "CASE-2026-001");
			await denied(`set role service_role; select public.admin_place_tenant_legal_hold('${id}','${owner}','CASE-2','Owner','again',null);`, /legal_hold_already_active/);
			assert.equal(await audit(id, "legal_hold.placed"), "1", "a refused placement writes no audit row");
		});

		await t.test("release is single-shot, audited, tenant-scoped and history stays immutable", async () => {
			const id = await tenant();
			const other = await tenant();
			const hold = await place(id);
			assert.equal(await release(other, hold), "f", "a hold id cannot be released through another tenant");
			await denied(`set role service_role; select public.admin_release_tenant_legal_hold('${id}','${admin}','${hold}','x');`, /retention_admin_owner_required/);
			await denied(`set role service_role; select public.admin_release_tenant_legal_hold('${id}','${owner}','${hold}','');`, /legal_hold_invalid_request/);
			assert.equal(await release(id, hold), "t");
			assert.equal(await release(id, hold), "f");
			assert.equal(await audit(id, "legal_hold.released"), "1");
			assert.equal(await sql(`select released_by::text||'|'||release_reason from public.tenant_legal_holds where id='${hold}';`), `${owner}|Matter closed`);
			// Immutable history, including the new columns, and no delete.
			await denied(`update public.tenant_legal_holds set case_id='TAMPER' where id='${hold}';`, /legal_hold_update_must_be_a_single_release/);
			await denied(`delete from public.tenant_legal_holds where id='${hold}';`, /legal_hold_history_is_immutable/);
			// A new hold can follow a released one; history keeps both rows.
			await place(id, owner, "CASE-2026-002");
			assert.equal(await sql(`select count(*) from public.tenant_legal_holds where tenant_id='${id}';`), "2");
		});

		await t.test("a hold frozen columns cannot change even on the release update", async () => {
			const id = await tenant();
			const hold = await place(id);
			await denied(`update public.tenant_legal_holds set released_at=now(),released_by='${owner}',release_reason='r',hold_owner='someone else' where id='${hold}';`,
				/legal_hold_update_must_be_a_single_release/);
			await denied(`update public.tenant_legal_holds set released_at=now(),released_by='${owner}',release_reason='r',case_id='CASE-9' where id='${hold}';`,
				/legal_hold_update_must_be_a_single_release/);
		});

		await t.test("placement is refused while an export deletion authorization is pending", async () => {
			const id = await tenant();
			const path = `${id}/${randomUUID()}.json`;
			await sql(`insert into public.audit_export_objects(path,tenant_id,created_by,expires_at) values ('${path}','${id}','${owner}',now()-interval '1 day');
				insert into public.audit_export_deletion_authorizations(path,tenant_id) values ('${path}','${id}');`);
			await denied(`set role service_role; select public.admin_place_tenant_legal_hold('${id}','${owner}','CASE-1','Owner','reason',null);`, /legal_hold_refused_pending_export_deletion/);
			assert.equal(await sql(`select count(*) from public.tenant_legal_holds where tenant_id='${id}' and released_at is null;`), "0");
			assert.equal(await audit(id, "legal_hold.placed"), "0");
		});

		await t.test("retention: bounds, non-configurable classes, defaults unchanged, audited old/new values", async () => {
			const id = await tenant();
			const defaults = await sql(`select string_agg(data_class||'='||retention_days, ',' order by data_class) from public.tenant_data_retention_policies where tenant_id='${id}';`);
			assert.match(defaults, /telemetry=30/, "the seeded default (tenants.retention_days) is unchanged by the migration");
			const set = (cls, days, actor = owner, reason = "Contract requires it") =>
				service(`select public.admin_set_tenant_retention('${id}','${actor}','${cls}',${days},'${reason}');`);
			await denied(`set role service_role; select public.admin_set_tenant_retention('${id}','${admin}','telemetry',60,'x');`, /retention_admin_owner_required/);
			await denied(`set role service_role; select public.admin_set_tenant_retention('${id}','${owner}','telemetry',6,'x');`, /retention_days_out_of_bounds/);
			await denied(`set role service_role; select public.admin_set_tenant_retention('${id}','${owner}','telemetry',3651,'x');`, /retention_days_out_of_bounds/);
			await denied(`set role service_role; select public.admin_set_tenant_retention('${id}','${owner}','security_audit',30,'x');`, /retention_days_out_of_bounds/);
			await denied(`set role service_role; select public.admin_set_tenant_retention('${id}','${owner}','commercial_records',365,'x');`, /retention_days_out_of_bounds/);
			await denied(`set role service_role; select public.admin_set_tenant_retention('${id}','${owner}','access_credentials',5,'x');`, /retention_class_not_configurable/);
			await denied(`set role service_role; select public.admin_set_tenant_retention('${id}','${owner}','unknown_class',5,'x');`, /retention_class_not_configurable/);
			await denied(`set role service_role; select public.admin_set_tenant_retention('${id}','${owner}','telemetry',60,'');`, /retention_invalid_request/);
			assert.equal(await sql(`select retention_days from public.tenant_data_retention_policies where tenant_id='${id}' and data_class='telemetry';`), "30");
			assert.equal(await audit(id, "retention.policy.changed"), "0");

			const changed = JSON.parse(await set("telemetry", 90));
			assert.deepEqual(changed, { data_class: "telemetry", retention_days: 90, previous_retention_days: 30, changed: true });
			assert.equal(await sql(`select retention_days||'|'||updated_by from public.tenant_data_retention_policies where tenant_id='${id}' and data_class='telemetry';`), `90|${owner}`);
			assert.equal(await sql(`select detail->>'previous_days'||'>'||(detail->>'new_days')||':'||(detail->>'reason') from public.admin_audit_logs where tenant_id='${id}' and action='retention.policy.changed';`),
				"30>90:Contract requires it");
			assert.equal(JSON.parse(await set("telemetry", 90)).changed, false);
			assert.equal(await audit(id, "retention.policy.changed"), "1", "an unchanged value writes no audit row");
			// Other classes and other tenants are untouched.
			assert.equal(await sql(`select string_agg(data_class||'='||retention_days, ',' order by data_class) from public.tenant_data_retention_policies where tenant_id='${id}' and data_class <> 'telemetry';`),
				defaults.split(",").filter((entry) => !entry.startsWith("telemetry=")).join(","));
			const other = await tenant();
			assert.equal(await sql(`select retention_days from public.tenant_data_retention_policies where tenant_id='${other}' and data_class='telemetry';`), "30");
		});

		await t.test("retention changes are refused during offboarding", async () => {
			const id = await tenant();
			await sql(`insert into public.tenant_offboarding_runs(tenant_id,requested_by) values ('${id}','${owner}');`);
			await denied(`set role service_role; select public.admin_set_tenant_retention('${id}','${owner}','telemetry',60,'x');`, /retention_change_refused_offboarding|retention_admin_owner_required/);
		});

		await t.test("the telemetry reaper honours the configured period and a hold placed through the RPC", async () => {
			const id = await tenant();
			const agent = randomUUID();
			// Fixture-only pilot admission so the telemetry rows can be created.
			await service("select public.configure_tenant_admission_mode('pilot');");
			await sql(`insert into public.pilot_applications(user_id,tenant_id,status,cohort) values ('${owner}','${id}','approved','hold_admin') on conflict (user_id,tenant_id) do nothing;
				insert into public.agents(id,tenant_id,user_id,iid) values ('${agent}','${id}','${owner}','hold-admin-agent');
				insert into public.events(user_id,tenant_id,agent_id,event_id,type,payload,created_at)
				  values ('${owner}','${id}','${agent}','old-event','hold_admin','{}',now()-interval '20 days');`);
			const events = () => sql(`select count(*) from public.events where tenant_id='${id}';`);
			const reap = async () => JSON.parse(await service("select public.prune_expired_telemetry_events(100,true,now());"));
			// Default 30 days: a 20-day-old event is retained.
			assert.equal((await reap()).events_deleted, 0);
			assert.equal(await events(), "1");
			// Shorten to 7 days and place a hold: still retained, reported as held.
			await service(`select public.admin_set_tenant_retention('${id}','${owner}','telemetry',7,'shorter period');`);
			const hold = await place(id);
			const held = await reap();
			assert.equal(held.events_deleted, 0);
			assert.ok(held.held_tenants >= 1);
			assert.equal(await events(), "1");
			// Release: eligible under the shorter period on the next run.
			assert.equal(await release(id, hold), "t");
			assert.equal((await reap()).events_deleted >= 1, true);
			assert.equal(await events(), "0");
		});

		await t.test("bounds table is service-read-only and deny-by-default for other roles", async () => {
			for (const role of ["anon", "authenticated"]) {
				await denied(`set role ${role}; select * from public.retention_policy_bounds;`, /permission denied/);
			}
			assert.equal(await service("select count(*) from public.retention_policy_bounds;"), "10");
			await denied("set role service_role; update public.retention_policy_bounds set min_days = 0;", /permission denied/);
		});
	} finally {
		await docker(["rm", "-f", container]);
	}
});
