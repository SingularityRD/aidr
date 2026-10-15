// Isolated PostgreSQL regression for C10: per-connector heartbeats and the
// `agent.unprotected` alert (migration 20261014000200).
//
// Fixture tables carry the columns the migration touches; the alert helper is
// the production app.enqueue_channel_notification (20260928000001), copied
// verbatim so the dedupe and flood-cap behaviour is the real one.
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
const MIGRATION = readFileSync(resolve(root, "supabase/migrations/20261014000200_connector_heartbeats.sql"), "utf8");
const ALERTS = readFileSync(resolve(root, "supabase/migrations/20260928000001_agent_offline_governance_alerts.sql"), "utf8");
const ENQUEUE = ALERTS.slice(
	ALERTS.indexOf("create or replace function app.enqueue_channel_notification("),
	ALERTS.indexOf("-- ── Governance request events"),
);

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
		const name = `aidr_hb_${randomUUID().slice(0, 8)}`;
		const admin = (query) => run("psql", ["-X", "-qAt", "-v", "ON_ERROR_STOP=1", dsn], query);
		const created = await admin(`create database ${name};`);
		assert.equal(created.code, 0, created.stderr);
		t.after(() => admin(`drop database if exists ${name} with (force);`));
		raw = (query) => run("psql", ["-X", "-qAt", "-v", "ON_ERROR_STOP=1", `${dsn} dbname=${name}`], query);
	} else {
		const container = `aidr-hb-${randomUUID().slice(0, 8)}`;
		const started = await run("docker", ["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
			"-e", "POSTGRES_PASSWORD=heartbeat-fixture-only", "postgres:17-alpine"]);
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
	const refused = async (query, pattern) => {
		const result = await raw(query);
		assert.notEqual(result.code, 0, "statement must be refused");
		assert.match(result.stderr, pattern);
	};
	await sql(`do $$ begin
		if not exists (select 1 from pg_roles where rolname='service_role') then create role service_role; end if;
		if not exists (select 1 from pg_roles where rolname='anon') then create role anon; end if;
		if not exists (select 1 from pg_roles where rolname='authenticated') then create role authenticated; end if;
	end $$;
	create schema app;
	create function app.is_tenant_member(p_tenant_id uuid) returns boolean language sql stable as 'select true';
	create function public.tenant_identity_access_allowed(p_tenant_id uuid) returns boolean language sql stable as 'select true';
	create table public.tenants(id uuid primary key, status text not null default 'active');
	create table public.agents(id uuid primary key, tenant_id uuid not null references public.tenants(id),
		iid text not null, last_seen timestamptz not null default now() - interval '1 day', unique (tenant_id, id));
	create table public.notification_channels(id uuid primary key, tenant_id uuid not null,
		enabled boolean not null default true, on_agent_offline boolean not null default false);
	create table public.notification_deliveries(id uuid primary key default gen_random_uuid(), tenant_id uuid not null,
		channel_id uuid not null, event_type text not null, dedupe_key text not null, payload jsonb not null,
		created_at timestamptz not null default clock_timestamp(), unique (channel_id, dedupe_key),
		constraint notification_deliveries_event_type_check check (event_type in ('agent.offline')));`);
	await sql(ENQUEUE);
	await sql(MIGRATION);
	return { sql, refused };
}

const TENANT = "11111111-1111-4111-8111-111111111111";
const AGENT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const WATCHING = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const NOT_WATCHING = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

async function seed(sql) {
	await sql(`insert into public.tenants(id) values ('${TENANT}');
		insert into public.agents(id, tenant_id, iid) values ('${AGENT}', '${TENANT}', 'iid-1');
		insert into public.notification_channels(id, tenant_id, on_agent_offline) values
			('${WATCHING}', '${TENANT}', true), ('${NOT_WATCHING}', '${TENANT}', false);`);
}

const report = (reports) =>
	`select public.record_connector_heartbeat('${TENANT}', '${AGENT}', '${JSON.stringify(reports)}'::jsonb);`;

test("a protected connector that loses its hook raises one agent.unprotected alert", async (t) => {
	const { sql } = await database(t);
	await seed(sql);
	const first = JSON.parse(await sql(report([
		{ connector: "claude-code", state: "protected", enforcement: "machine_policy", host_version: "2.1.250" },
		{ connector: "codex", state: "hook_untrusted" },
	])));
	assert.deepEqual(first, { recorded: 2, alerts: 0 }, "a first report never alerts (coverage gap, not a regression)");
	assert.ok(await sql(`select last_seen > now() - interval '1 minute' from public.agents where id = '${AGENT}';`) === "t",
		"a heartbeat refreshes agents.last_seen, so a stopped heartbeat raises agent.offline");

	const second = JSON.parse(await sql(report([{ connector: "claude-code", state: "hook_missing" }])));
	assert.deepEqual(second, { recorded: 1, alerts: 1 });
	const payload = JSON.parse(await sql(
		`select payload from public.notification_deliveries where channel_id = '${WATCHING}' and event_type = 'agent.unprotected';`,
	));
	assert.equal(payload.agent_id, AGENT);
	assert.equal(payload.category, "claude-code");
	assert.equal(payload.connector_state, "hook_missing");
	assert.equal(payload.severity, "high");
	assert.equal(await sql(`select count(*) from public.notification_deliveries where channel_id = '${NOT_WATCHING}';`), "0");

	// The same episode reported again does not alert again.
	const third = JSON.parse(await sql(report([{ connector: "claude-code", state: "hook_missing" }])));
	assert.equal(third.alerts, 0);
	assert.equal(await sql("select count(*) from public.notification_deliveries;"), "1");
	assert.equal(await sql(`select state from public.connector_heartbeats where connector = 'codex';`), "hook_untrusted");
});

test("blocked disable attempts on a locked editor alert when the counter rises", async (t) => {
	const { sql } = await database(t);
	await seed(sql);
	await sql(report([{ connector: "cursor", state: "protected", protection_locked: true, disable_attempts: 0 }]));
	const rose = JSON.parse(await sql(report([{ connector: "cursor", state: "protected", protection_locked: true, disable_attempts: 2 }])));
	assert.equal(rose.alerts, 1);
	assert.equal(
		await sql("select payload->>'connector_state' from public.notification_deliveries;"),
		"disable_attempted",
	);
	const same = JSON.parse(await sql(report([{ connector: "cursor", state: "protected", protection_locked: true, disable_attempts: 2 }])));
	assert.equal(same.alerts, 0);
});

test("invalid reports, unknown agents and inactive tenants are refused", async (t) => {
	const { sql, refused } = await database(t);
	await seed(sql);
	await refused(report([{ connector: "notepad", state: "protected" }]), /invalid_connector_heartbeat/);
	await refused(report([{ connector: "codex", state: "fine" }]), /invalid_connector_heartbeat/);
	await refused(report([{ connector: "codex", state: "protected" }, { connector: "codex", state: "protected" }]), /invalid_connector_heartbeat/);
	await refused(report([{ connector: "codex", state: "protected", host_version: "1.0; drop" }]), /invalid_connector_heartbeat/);
	await refused(report([]), /invalid_connector_heartbeat/);
	await refused(
		`select public.record_connector_heartbeat('${TENANT}', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', '[{"connector":"codex","state":"protected"}]'::jsonb);`,
		/connector_heartbeat_agent_unknown/,
	);
	await sql(`update public.tenants set status = 'suspended' where id = '${TENANT}';`);
	await refused(report([{ connector: "codex", state: "protected" }]), /connector_heartbeat_tenant_inactive/);
	for (const role of ["anon", "authenticated"]) {
		assert.equal(
			await sql(`select has_function_privilege('${role}', 'public.record_connector_heartbeat(uuid, uuid, jsonb)', 'execute');`),
			"f",
		);
	}
});
