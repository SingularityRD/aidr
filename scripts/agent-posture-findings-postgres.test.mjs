// Real-PostgreSQL contract for supabase/migrations/20260927004000_agent_environment_posture.sql
// (applied on top of 20260925000050_posture_findings.sql).
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
const baseMigration = readFileSync(
	resolve(root, "supabase/migrations/20260925000050_posture_findings.sql"),
	"utf8",
);
const migration = readFileSync(
	resolve(root, "supabase/migrations/20260927004000_agent_environment_posture.sql"),
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
		const database = `aidr_agent_posture_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
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
	const container = `aidr-agent-posture-${randomUUID().slice(0, 8)}`;
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

test("agent environment posture rows: projection, validation, RLS and retention", { timeout: 180_000 }, async (t) => {
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
		sql(baseMigration);
		// Stored before this migration: ignored by the old trigger, backfilled by the new one.
		sql(insertEvent(TENANT_A, "agent_posture_finding", {
			finding_severity: "critical", agent_host: "codex", check_id: "sandbox_full_access", finding_count: 1,
		}));
		assert.equal(sql("select count(*) from public.posture_findings;"), "0");
		sql(migration);
		// Idempotent: re-applying neither fails nor duplicates the backfill.
		sql(migration);
		assert.equal(
			sql("select concat_ws('|', source, finding_kind, severity, agent_host, check_id, finding_count) from public.posture_findings;"),
			"agent_environment|agent_config|critical|codex|sandbox_full_access|1",
		);

		sql(insertEvent(TENANT_A, "agent_posture_finding", {
			finding_severity: "medium", agent_host: "environment", check_id: "cloud_credentials_in_env",
			finding_count: 3, timestamp: "2999-01-01T00:00:00.000Z",
		}));
		// A modified client: unknown host/check, oversized count and smuggled fields become NULL.
		sql(insertEvent(TENANT_A, "agent_posture_finding", {
			severity: "warning", agent_host: "/home/user", check_id: "AWS_SECRET_ACCESS_KEY",
			finding_count: 1e9, names: ["AWS_SECRET_ACCESS_KEY"],
		}));
		// Agent fields on other sources are never stored.
		sql(insertEvent(TENANT_B, "mcp_inventory_finding", {
			finding_severity: "high", mcp_server_name: "shell-runner", mcp_transport: "stdio",
			server_digest: DIGEST, agent_host: "codex", check_id: "sandbox_full_access", finding_count: 5,
		}));

		assert.equal(
			sql(`select concat_ws('|', severity, agent_host, check_id, finding_count, observed_at <= created_at)
				from public.posture_findings where check_id = 'cloud_credentials_in_env';`),
			"medium|environment|cloud_credentials_in_env|3|t",
			"a future client timestamp is clamped to receipt",
		);
		assert.equal(
			sql(`select concat_ws('|', finding_kind, severity, coalesce(agent_host, 'null'), coalesce(check_id, 'null'),
				coalesce(finding_count::text, 'null')) from public.posture_findings
				where source = 'agent_environment' and agent_host is null;`),
			"agent_config|medium|null|null|null",
		);
		assert.equal(
			sql(`select concat_ws('|', source, coalesce(agent_host, 'null'), coalesce(check_id, 'null'), coalesce(finding_count::text, 'null'))
				from public.posture_findings where tenant_id = '${TENANT_B}';`),
			"mcp_inventory|null|null|null",
		);
		assert.match(
			sqlFails(`update public.posture_findings set check_id = 'rm -rf' where source = 'agent_environment';`),
			/posture_findings_check_id_check/,
		);

		const asMember = (query) => `begin; set local role authenticated;
			select set_config('request.jwt.claim.sub', '${MEMBER_A}', true); ${query} commit;`;
		assert.equal(
			sql(asMember("select count(*) from public.posture_findings where source = 'agent_environment';")).split("\n").at(-1),
			"3",
		);
		assert.equal(sql(asMember(`select count(*) from public.posture_findings where tenant_id = '${TENANT_B}';`)).split("\n").at(-1), "0");
		assert.match(sqlFails(asMember("delete from public.posture_findings;")), /permission denied/);

		// Retention: deleting the source events removes the agent rows.
		sql(`delete from public.events where type = 'agent_posture_finding';`);
		assert.equal(sql("select count(*) from public.posture_findings where source = 'agent_environment';"), "0");
	} finally {
		database.stop();
	}
});
