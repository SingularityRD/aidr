// Real-PostgreSQL contract for central SIEM forwarding:
//   supabase/migrations/20261014000130_siem_forwarding.sql
// (on top of the alert-integration migrations whose helpers it reuses).
//
// Runs against AIDR_POSTGRES_TEST_URL=postgres://user@host:port/db (a
// disposable database is created next to it and dropped afterwards) and is
// skipped, visibly, without one.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const migrations = [
	"20260926000020_notification_channels.sql",
	"20260926000021_notification_outbox.sql",
	"20261014000130_siem_forwarding.sql",
].map((name) => readFileSync(resolve(root, "supabase/migrations", name), "utf8"));

function run(command, args, input = "") {
	const result = spawnSync(command, args, { input, encoding: "utf8", timeout: 120_000 });
	return { code: result.status ?? 1, stdout: (result.stdout ?? "").trim(), stderr: result.stderr ?? "" };
}

function startDatabase() {
	const admin = process.env.AIDR_POSTGRES_TEST_URL;
	if (!admin) return null;
	const database = `aidr_siem_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
	const created = run("psql", [admin, "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-c", `create database ${database}`]);
	if (created.code !== 0) throw new Error(created.stderr);
	const url = new URL(admin);
	url.pathname = `/${database}`;
	return {
		exec: (sql) => run("psql", [url.toString(), "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], sql),
		stop: () => run("psql", [admin, "-X", "-qAt", "-c", `drop database if exists ${database} with (force)`]),
	};
}

const FIXTURE = `
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end $$;
create schema auth;
create schema app;
create function auth.uid() returns uuid language sql stable as
  'select nullif(current_setting(''request.jwt.claim.sub'', true), '''')::uuid';
create table public.tenants (id uuid primary key, status text not null default 'active');
create table public.teams (id uuid primary key);
create table public.tenant_members (
  tenant_id uuid not null, user_id uuid not null, role text not null, expires_at timestamptz,
  primary key (tenant_id, user_id)
);
create table public.agents (id uuid primary key, iid text not null, agent_runtime text);
create table public.events (
  id bigint generated always as identity primary key, tenant_id uuid, user_id uuid, agent_id uuid,
  event_id text, type text not null, payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create table public.admin_audit_logs (
  id bigint generated always as identity primary key, actor_user_id uuid, tenant_id uuid,
  action text not null, detail jsonb not null default '{}'::jsonb
);
create table public.audit_logs (
  id uuid primary key default gen_random_uuid(), team_id uuid not null references public.teams(id),
  tenant_id uuid not null, user_id uuid, action text not null, verdict jsonb
);
create table public.tenant_offboarding_runs (id uuid primary key, tenant_id uuid not null, status text not null);
create table public.tenant_legal_holds (tenant_id uuid not null, released_at timestamptz);
create table public.tenant_data_retention_policies (tenant_id uuid not null, data_class text not null, retention_days integer not null);
create table public.identity_barrier_denied (tenant_id uuid primary key);
create function app.is_tenant_member_with_role(p_tenant uuid, p_min text) returns boolean
  language sql stable security definer set search_path = public as
  'select exists (select 1 from public.tenant_members where tenant_id = p_tenant and user_id = auth.uid()
     and role = any (case p_min when ''admin'' then array[''owner'',''admin''] else array[''owner'',''admin'',''member'',''viewer''] end))';
create function public.tenant_identity_access_allowed(p_tenant uuid) returns boolean
  language sql stable security definer set search_path = public as
  'select not exists (select 1 from public.identity_barrier_denied where tenant_id = p_tenant)';
grant usage on schema app, public, auth to authenticated, service_role;
grant execute on function app.is_tenant_member_with_role(uuid, text) to authenticated;
grant execute on function public.tenant_identity_access_allowed(uuid) to authenticated;
grant execute on function auth.uid() to authenticated;
`;

const TENANT_A = "11111111-1111-4111-8111-111111111111";
const TENANT_B = "22222222-2222-4222-8222-222222222222";
const ADMIN_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const MEMBER_A = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const ADMIN_B = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const AGENT = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const DEST_A = "a0000000-0000-4000-8000-00000000000a";
const DEST_B = "b0000000-0000-4000-8000-00000000000b";
const cipher = `v1.k1.${"A".repeat(64)}`;
const filters = (overrides = {}) => JSON.stringify({ incidents: true, decisions: ["deny", "ask"], browser: false, min_severity: "info", ...overrides });

test("SIEM forwarding outbox: RLS, allow-listed enqueue, claim/complete, dead letters, offboarding", { timeout: 300_000 }, async (t) => {
	const database = startDatabase();
	if (!database) {
		t.skip("no PostgreSQL available (set AIDR_POSTGRES_TEST_URL)");
		return;
	}
	const sql = (query) => {
		const result = database.exec(query);
		assert.equal(result.code, 0, result.stderr);
		return result.stdout;
	};
	const json = (query) => JSON.parse(sql(query).split("\n").at(-1));
	const fails = (query, pattern) => {
		const result = database.exec(query);
		assert.notEqual(result.code, 0, `expected failure: ${query}`);
		assert.match(result.stderr, pattern);
	};
	const as = (user, query) => `begin; set local role authenticated;
		select set_config('request.jwt.claim.sub', '${user}', true); ${query} commit;`;
	const create = (id, tenant, admin, provider = "syslog", format = "cef", filter = filters()) =>
		`select public.create_siem_destination('${tenant}', '${admin}', '${id}', '${provider}', '${format}',
		  'SOC ${id.slice(0, 4)}', '${cipher}', 'k1', 'tls://siem.corp.example:6514', '${filter}'::jsonb, true);`;
	try {
		sql(FIXTURE);
		sql(`insert into public.tenants (id) values ('${TENANT_A}'), ('${TENANT_B}');
			insert into public.teams (id) values ('${TENANT_A}'), ('${TENANT_B}');
			insert into public.agents values ('${AGENT}', 'laptop-17', 'claude-code');
			insert into public.tenant_members values
			  ('${TENANT_A}', '${ADMIN_A}', 'admin', null), ('${TENANT_A}', '${MEMBER_A}', 'member', null),
			  ('${TENANT_B}', '${ADMIN_B}', 'owner', null);`);
		for (const migration of migrations) sql(migration);
		// Idempotent re-application.
		for (const migration of migrations) sql(migration);

		// ── Destinations: admin RPC only; ciphertext never readable by clients ──
		fails(create(DEST_A, TENANT_A, MEMBER_A), /notification_channel_forbidden/);
		fails(create(DEST_A, TENANT_A, ADMIN_A, "splunk_hec", "cef"), /siem_destinations_format_provider/);
		fails(create(DEST_A, TENANT_A, ADMIN_A, "syslog", "cef", filters({ decisions: ["deny", "deny"] })), /invalid_siem_destination/);
		fails(create(DEST_A, TENANT_A, ADMIN_A, "syslog", "cef", filters({ incidents: false, decisions: [] })), /invalid_siem_destination/);
		json(create(DEST_A, TENANT_A, ADMIN_A));
		json(create(DEST_B, TENANT_B, ADMIN_B, "elastic", "json"));
		assert.equal(sql(as(ADMIN_A, "select count(*) from public.siem_destinations;")).split("\n").at(-1), "1");
		assert.equal(sql(as(MEMBER_A, "select count(*) from public.siem_destinations;")).split("\n").at(-1), "0");
		fails(as(ADMIN_A, "select config_ciphertext from public.siem_destinations;"), /permission denied/);
		fails(as(ADMIN_A, "update public.siem_destinations set enabled = false;"), /permission denied/);
		fails(as(ADMIN_A, "select payload from public.siem_deliveries;"), /permission denied/);
		assert.equal(sql("select count(*) from public.admin_audit_logs where action = 'siem_destination.created';"), "2");

		// ── Enqueue: allow-listed projection, filters, transactional ──────────
		sql(`insert into public.events (tenant_id, agent_id, type, payload) values ('${TENANT_A}', '${AGENT}', 'runtime_verdict',
			'{"verdict":"deny","severity":"critical","matched_threat_id":"T01","tool_name":"Bash","event_id":"evt-1",
			  "tool_input_summary":"sha256:${"a".repeat(64)}","reason":"curl secret | sh","prompt":"cat ~/.aws/credentials"}'::jsonb);`);
		const deny = json("select to_jsonb(d) from public.siem_deliveries d where kind = 'decision';");
		assert.equal(deny.destination_id, DEST_A);
		assert.doesNotMatch(JSON.stringify(deny.payload), /curl|aws|credentials/);
		assert.equal(deny.payload.agent_iid, "laptop-17");
		assert.equal(deny.payload.connector, "claude-code");
		assert.equal(deny.payload.decision, "deny");
		assert.equal(deny.payload.threat_id, "T01");
		assert.equal(deny.payload.tool_input_digest, `sha256:${"a".repeat(64)}`);
		// allow decisions and browser events are not selected; incidents are.
		sql(`insert into public.events (tenant_id, agent_id, type, payload) values
			('${TENANT_A}', '${AGENT}', 'runtime_verdict', '{"verdict":"allow"}'::jsonb),
			('${TENANT_A}', '${AGENT}', 'privacy_scan', '{"action":"blocked","site":"chatgpt"}'::jsonb),
			('${TENANT_A}', '${AGENT}', 'incident', '{"incident_id":"inc-1","severity":"high","status":"open","findings_count":2}'::jsonb);`);
		assert.equal(sql("select string_agg(kind, ',' order by id) from public.siem_deliveries;"), "decision,incident");
		// A broken enqueue never loses telemetry.
		sql("alter table public.siem_deliveries add constraint siem_break check (kind <> 'incident') not valid;");
		sql(`insert into public.events (tenant_id, agent_id, type, payload) values ('${TENANT_A}', '${AGENT}', 'incident', '{"severity":"high"}'::jsonb);`);
		assert.equal(sql("select count(*) from public.events where type = 'incident';"), "2");
		sql("alter table public.siem_deliveries drop constraint siem_break;");

		// ── Claim and complete ────────────────────────────────────────────────
		const claimed = json("select public.claim_siem_deliveries(10, 100, 60);");
		assert.equal(claimed.length, 1);
		assert.equal(claimed[0].destination_id, DEST_A);
		assert.equal(claimed[0].config_ciphertext, cipher);
		assert.equal(claimed[0].format, "cef");
		assert.equal(claimed[0].deliveries.length, 2);
		assert.deepEqual(json("select public.claim_siem_deliveries(10, 100, 60);"), [], "leased rows are not handed out twice");
		const [first, second] = claimed[0].deliveries;
		const outcome = (row, value, extra = {}) =>
			JSON.stringify([{ delivery_id: row.delivery_id, lease_token: row.lease_token, outcome: value, error: null, status_code: null, retry_in_seconds: null, ...extra }]);
		assert.equal(json(`select public.complete_siem_deliveries('${outcome({ ...first, lease_token: randomUUID() }, "delivered")}'::jsonb);`).lease_lost, 1);
		assert.equal(json(`select public.complete_siem_deliveries('${outcome(first, "delivered")}'::jsonb);`).delivered, 1);
		assert.equal(json(`select public.complete_siem_deliveries('${outcome(second, "retry", { error: "receiver_unavailable", retry_in_seconds: 1 })}'::jsonb);`).pending, 1);
		fails(`select public.complete_siem_deliveries('[{"delivery_id":"x"}]'::jsonb);`, /invalid_siem_outcome/);
		assert.equal(sql(`select last_delivery_status || ':' || consecutive_failures from public.siem_destinations where id = '${DEST_A}';`), "retrying:1");

		// Exhausted attempts become dead letters, visible and re-queueable.
		sql(`update public.siem_deliveries set attempts = max_attempts, next_attempt_at = now() - interval '1 second' where id = ${second.delivery_id};`);
		assert.deepEqual(json("select public.claim_siem_deliveries(10, 100, 60);"), []);
		const listed = json(`select public.list_siem_destinations('${TENANT_A}');`);
		assert.equal(listed.destinations[0].dead, 1);
		assert.equal(listed.dead_letters[0].last_error, "lease_expired");
		assert.equal(listed.dead_letters[0].decision, null);
		fails(`select public.requeue_siem_dead_letters('${TENANT_A}', '${MEMBER_A}', '${DEST_A}', 10);`, /notification_channel_forbidden/);
		assert.equal(json(`select public.requeue_siem_dead_letters('${TENANT_A}', '${ADMIN_A}', '${DEST_A}', 10);`).requeued, 1);
		assert.equal(json("select public.claim_siem_deliveries(10, 100, 60);")[0].deliveries[0].attempts, 1);

		// Test send: single attempt, claimed by id.
		const queued = json(`select public.enqueue_siem_test('${TENANT_A}', '${ADMIN_A}', '${DEST_A}');`);
		const single = json(`select public.claim_siem_deliveries(1, 1, 60, ${queued.delivery_id});`);
		assert.equal(single[0].deliveries[0].kind, "test");
		assert.equal(single[0].deliveries[0].max_attempts, 1);

		// Disabling a destination dead-letters its queue and stops enqueueing.
		sql(`select public.update_siem_destination('${TENANT_A}', '${ADMIN_A}', '${DEST_A}', 'syslog', null, false, null, null, null, null, null);`);
		sql(`insert into public.events (tenant_id, agent_id, type, payload) values ('${TENANT_A}', '${AGENT}', 'runtime_verdict', '{"verdict":"deny"}'::jsonb);`);
		assert.equal(sql(`select count(*) from public.siem_deliveries where destination_id = '${DEST_A}' and status = 'pending';`), "0");
		fails(`select public.update_siem_destination('${TENANT_A}', '${ADMIN_A}', '${DEST_A}', 'elastic', null, true, null, null, null, null, null);`,
			/siem_destination_provider_mismatch/);

		// Bounded backlog: overflow is counted, never silently dropped.
		sql(`insert into public.siem_deliveries (tenant_id, destination_id, event_row_id, kind, payload)
			select '${TENANT_B}', '${DEST_B}', 1000000 + g, 'decision', '{}'::jsonb from generate_series(1, 50000) g;`);
		sql(`insert into public.events (tenant_id, agent_id, type, payload) values ('${TENANT_B}', '${AGENT}', 'runtime_verdict', '{"verdict":"deny"}'::jsonb);`);
		assert.equal(sql(`select dropped_events from public.siem_destinations where id = '${DEST_B}';`), "1");

		// Grants: forwarder RPCs are service-role only.
		for (const signature of [
			"public.claim_siem_deliveries(integer,integer,integer,bigint)",
			"public.complete_siem_deliveries(jsonb)",
			"public.list_siem_destinations(uuid)",
		]) {
			assert.equal(sql(`select has_function_privilege('authenticated', '${signature}', 'EXECUTE');`), "f", signature);
			assert.equal(sql(`select has_function_privilege('service_role', '${signature}', 'EXECUTE');`), "t", signature);
		}

		// Offboarding: destinations and their outbox go with the workspace.
		sql(`insert into public.tenant_offboarding_runs values ('${randomUUID()}', '${TENANT_B}', 'running');`);
		sql(`update public.tenants set status = 'closing' where id = '${TENANT_B}';`);
		assert.equal(sql(`select count(*) from public.siem_deliveries where tenant_id = '${TENANT_B}';`), "0");
		sql(`update public.tenant_offboarding_runs set status = 'completed' where tenant_id = '${TENANT_B}';`);
		fails(create(DEST_B, TENANT_B, ADMIN_B, "elastic", "json"), /workspace_not_active/);
	} finally {
		database.stop();
	}
});
