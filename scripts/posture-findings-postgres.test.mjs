// Real-PostgreSQL contract for supabase/migrations/20260925000050_posture_findings.sql.
//
// Runs against either
//   AIDR_POSTGRES_TEST_URL=postgres://user@host:port/db  (a disposable database
//     is created next to it and dropped afterwards), or
//   an isolated `supabase/postgres` container (docker, no network),
// and is skipped, visibly, when neither is available.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const migration = readFileSync(
	resolve(root, "supabase/migrations/20260925000050_posture_findings.sql"),
	"utf8",
);

function run(command, args, input = "") {
	const result = spawnSync(command, args, { input, encoding: "utf8", timeout: 60_000 });
	return { code: result.status ?? 1, stdout: (result.stdout ?? "").trim(), stderr: result.stderr ?? "" };
}

function connectionFor(database) {
	const url = new URL(process.env.AIDR_POSTGRES_TEST_URL);
	url.pathname = `/${database}`;
	return url.toString();
}

async function startDatabase() {
	if (process.env.AIDR_POSTGRES_TEST_URL) {
		const database = `aidr_posture_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
		const admin = process.env.AIDR_POSTGRES_TEST_URL;
		const created = run("psql", [admin, "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-c", `create database ${database}`]);
		if (created.code !== 0) throw new Error(created.stderr);
		const url = connectionFor(database);
		return {
			exec: (sql) => run("psql", [url, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], sql),
			stop: () => run("psql", [admin, "-X", "-qAt", "-c", `drop database if exists ${database} with (force)`]),
		};
	}
	if (run("docker", ["info"]).code !== 0) return null;
	const container = `aidr-posture-${randomUUID().slice(0, 8)}`;
	const started = run("docker", ["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=posture-fixture-only", "supabase/postgres:17.6.1.136"]);
	if (started.code !== 0) return null;
	for (let i = 0; i < 100; i++) {
		if (run("docker", ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"]).code === 0) break;
		await new Promise((done) => setTimeout(done, 100));
	}
	return {
		exec: (sql) => run("docker", ["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"], sql),
		stop: () => run("docker", ["rm", "--force", container]),
	};
}

// The smallest schema the migration depends on, shaped like the canonical
// tables it references (events, tenants, offboarding runs, membership helper).
const FIXTURE = `
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end $$;
create schema if not exists auth;
create schema if not exists app;
do $$ begin
  if to_regprocedure('auth.uid()') is null then
    execute $f$create function auth.uid() returns uuid language sql stable as
      'select nullif(current_setting(''request.jwt.claim.sub'', true), '''')::uuid'$f$;
  end if;
end $$;
create table public.tenants (id uuid primary key, status text not null default 'active');
create table public.tenant_members (tenant_id uuid not null, user_id uuid not null);
create table public.tenant_offboarding_runs (id uuid primary key, tenant_id uuid not null, status text not null);
create table public.events (
  id bigint generated always as identity primary key,
  user_id uuid,
  agent_id uuid not null,
  tenant_id uuid not null,
  type text not null,
  event_id text,
  created_at timestamptz not null default now(),
  payload jsonb not null
);
create function app.is_tenant_member(p_tenant uuid) returns boolean
  language sql stable security definer set search_path = public as
  'select exists (select 1 from public.tenant_members where tenant_id = p_tenant and user_id = auth.uid())';
grant usage on schema app, public, auth to authenticated, service_role;
grant execute on function app.is_tenant_member(uuid) to authenticated;
grant execute on function auth.uid() to authenticated;
`;

const TENANT_A = "11111111-1111-4111-8111-111111111111";
const TENANT_B = "22222222-2222-4222-8222-222222222222";
const MEMBER_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const AGENT = "33333333-3333-4333-8333-333333333333";
const DIGEST = `sha256:${"a".repeat(64)}`;

function insertEvent(tenant, type, payload) {
	const json = JSON.stringify(payload).replaceAll("'", "''");
	return `insert into public.events (tenant_id, agent_id, type, event_id, payload)
		values ('${tenant}', '${AGENT}', '${type}', '${randomUUID()}', '${json}'::jsonb);`;
}

test("posture findings projection, RLS, cascade retention and offboarding guard", { timeout: 180_000 }, async (t) => {
	const database = await startDatabase();
	if (!database) {
		t.skip("no PostgreSQL available (set AIDR_POSTGRES_TEST_URL or run docker with supabase/postgres)");
		return;
	}
	const sql = (query) => {
		const result = database.exec(query);
		assert.equal(result.code, 0, result.stderr);
		return result.stdout;
	};
	const sqlFails = (query) => {
		const result = database.exec(query);
		assert.notEqual(result.code, 0, `expected failure: ${query}`);
		return result.stderr;
	};
	try {
		sql(FIXTURE);
		sql(`insert into public.tenants (id) values ('${TENANT_A}'), ('${TENANT_B}');
			insert into public.tenant_members values ('${TENANT_A}', '${MEMBER_A}');`);
		// A pre-existing event is backfilled by the migration.
		sql(insertEvent(TENANT_A, "plugin_scan_finding", {
			severity: "warning", plugin_key: "legacy-plugin", matched_threat_id: "CLT-SUPPLY-001",
		}));
		sql(migration);
		// Idempotent: re-applying neither fails nor duplicates the backfill.
		sql(migration);
		assert.equal(sql("select count(*) from public.posture_findings;"), "1");
		assert.equal(
			sql("select source || '|' || finding_kind || '|' || severity || '|' || rule_id from public.posture_findings;"),
			"skill_scan|skill_rule|medium|CLT-SUPPLY-001",
		);

		sql(insertEvent(TENANT_A, "infra_scan_finding", {
			timestamp: "2999-01-01T00:00:00.000Z", scan_id: "scan-1", finding_kind: "cve",
			finding_severity: "critical", vuln_id: "CVE-2024-37032", cvss: 9.14, component: "ollama",
			component_version: "0.1.30", applicability: "confirmed", target_digest: DIGEST,
		}));
		sql(insertEvent(TENANT_A, "infra_scan_finding", {
			finding_kind: "mcp_server", finding_severity: "bogus", severity: "high",
			vuln_id: "CVE-1; drop", cvss: "9.8", component: "ollama\nhttp://10.0.0.1", target_digest: "http://10.0.0.1",
			timestamp: "not a time",
		}));
		sql(insertEvent(TENANT_B, "mcp_inventory_finding", {
			finding_severity: "high", mcp_server_name: "shell-runner", mcp_transport: "stdio",
			risk_categories: ["shell_wrapper_command", "mcp-05", "--allow-all /", 7, "shell_wrapper_command"],
			attestation_status: "unverifiable", server_digest: DIGEST,
		}));
		sql(insertEvent(TENANT_A, "runtime_verdict", { verdict: "deny", severity: "high" }));

		assert.equal(sql("select count(*) from public.posture_findings;"), "4", "runtime verdicts are not posture findings");
		assert.equal(
			sql(`select concat_ws('|', finding_kind, severity, cvss, vuln_id, component, component_version, applicability,
				target_digest = '${DIGEST}', observed_at <= created_at)
				from public.posture_findings where vuln_id is not null;`),
			"cve|critical|9.1|CVE-2024-37032|ollama|0.1.30|confirmed|t|t",
			"a future client timestamp is clamped to receipt",
		);
		assert.equal(
			sql(`select concat_ws('|', finding_kind, severity, coalesce(cvss::text, 'null'), coalesce(vuln_id, 'null'),
				coalesce(component, 'null'), coalesce(target_digest, 'null'))
				from public.posture_findings where source = 'infra_scan' and vuln_id is null;`),
			"advisory|high|null|null|null|null",
			"malformed optional fields become NULL instead of dropping the event",
		);
		assert.equal(
			sql(`select concat_ws('|', mcp_server_name, mcp_transport, array_to_string(risk_categories, ','), attestation_status,
				subject_digest = '${DIGEST}') from public.posture_findings where source = 'mcp_inventory';`),
			"shell-runner|stdio|mcp-05,shell_wrapper_command|unverifiable|t",
		);

		// RLS: a member reads only their tenant; nobody writes through the API roles.
		const asMember = (query) => `begin; set local role authenticated;
			select set_config('request.jwt.claim.sub', '${MEMBER_A}', true); ${query} commit;`;
		assert.equal(sql(asMember("select count(*) from public.posture_findings;")).split("\n").at(-1), "3");
		assert.equal(sql(asMember(`select count(*) from public.posture_findings where tenant_id = '${TENANT_B}';`)).split("\n").at(-1), "0");
		assert.match(
			sqlFails(asMember(`insert into public.posture_findings (tenant_id, event_row_id, agent_id, source, finding_kind, severity, observed_at)
				values ('${TENANT_A}', 999, '${AGENT}', 'infra_scan', 'cve', 'critical', now());`)),
			/permission denied/,
		);
		assert.match(sqlFails(asMember("delete from public.posture_findings;")), /permission denied/);
		assert.equal(sql("select has_table_privilege('anon', 'public.posture_findings', 'SELECT');"), "f");
		assert.equal(sql("select has_table_privilege('authenticated', 'public.posture_findings', 'INSERT');"), "f");
		assert.equal(sql("select has_function_privilege('authenticated', 'app.insert_posture_finding(public.events)', 'EXECUTE');"), "f");

		// Offboarding: closing a tenant with posture residue is refused; deleting
		// its events (the retention/offboarding path) cascades and unblocks it.
		const blocked = sqlFails(`update public.tenants set status = 'closed' where id = '${TENANT_B}';`);
		assert.match(blocked, /posture_findings_offboarding_residue/);
		sql(`insert into public.tenant_offboarding_runs values ('${randomUUID()}', '${TENANT_B}', 'running');`);
		assert.match(
			sqlFails(`update public.tenant_offboarding_runs set status = 'completed' where tenant_id = '${TENANT_B}';`),
			/posture_findings_offboarding_residue/,
		);
		sql(`delete from public.events where tenant_id = '${TENANT_B}';`);
		assert.equal(sql(`select count(*) from public.posture_findings where tenant_id = '${TENANT_B}';`), "0");
		sql(`update public.tenant_offboarding_runs set status = 'completed' where tenant_id = '${TENANT_B}';
			update public.tenants set status = 'closed' where id = '${TENANT_B}';`);

		// Retention deletes events in batches; posture rows follow each deleted event.
		sql(`delete from public.events where tenant_id = '${TENANT_A}' and type = 'infra_scan_finding';`);
		assert.equal(sql(`select count(*) from public.posture_findings where tenant_id = '${TENANT_A}';`), "1");
	} finally {
		database.stop();
	}
});
