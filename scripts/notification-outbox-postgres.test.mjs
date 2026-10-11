// Real-PostgreSQL contract for the alert-integration migrations:
//   supabase/migrations/20260926000020_notification_channels.sql
//   supabase/migrations/20260926000021_notification_outbox.sql
//   supabase/migrations/20260928000021_notification_spike_count_index.sql
//   supabase/migrations/20260928000022_notification_fair_claim.sql
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
const migrations = [
	"20260926000020_notification_channels.sql",
	"20260926000021_notification_outbox.sql",
	"20260928000021_notification_spike_count_index.sql",
	"20260928000022_notification_fair_claim.sql",
	"20260928000024_notification_flood_cap_per_kind.sql",
].map((name) => readFileSync(resolve(root, "supabase/migrations", name), "utf8"));

function run(command, args, input = "") {
	const result = spawnSync(command, args, { input, encoding: "utf8", timeout: 120_000 });
	return { code: result.status ?? 1, stdout: (result.stdout ?? "").trim(), stderr: result.stderr ?? "" };
}

function connectionFor(database) {
	const url = new URL(process.env.AIDR_POSTGRES_TEST_URL);
	url.pathname = `/${database}`;
	return url.toString();
}

async function startDatabase() {
	if (process.env.AIDR_POSTGRES_TEST_URL) {
		const database = `aidr_notifications_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
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
	const container = `aidr-notifications-${randomUUID().slice(0, 8)}`;
	const started = run("docker", ["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=notifications-fixture-only", "supabase/postgres:17.11.0.004"]);
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

// The smallest schema the migrations depend on, shaped like the canonical
// tables they reference.
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
create table public.teams (id uuid primary key);
create table public.tenant_members (
  tenant_id uuid not null, user_id uuid not null, role text not null, expires_at timestamptz,
  primary key (tenant_id, user_id)
);
create table public.events (
  id bigint generated always as identity primary key, tenant_id uuid, user_id uuid, agent_id uuid,
  event_id text, type text not null, payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index events_tenant_created_idx on public.events (tenant_id, created_at desc);
create table public.admin_audit_logs (
  id bigint generated always as identity primary key, actor_user_id uuid, tenant_id uuid,
  action text not null, detail jsonb not null default '{}'::jsonb
);
create table public.audit_logs (
  id uuid primary key default gen_random_uuid(), team_id uuid not null references public.teams(id),
  tenant_id uuid not null, user_id uuid, action text not null, verdict jsonb
);
create table public.tenant_offboarding_runs (
  id uuid primary key, tenant_id uuid not null, requested_by uuid, status text not null
);
create table public.tenant_legal_holds (tenant_id uuid not null, released_at timestamptz);
create table public.tenant_data_retention_policies (
  tenant_id uuid not null, data_class text not null, retention_days integer not null
);
create table public.identity_barrier_denied (tenant_id uuid primary key);
create function app.is_tenant_member_with_role(p_tenant uuid, p_min text) returns boolean
  language sql stable security definer set search_path = public as
  'select exists (select 1 from public.tenant_members where tenant_id = p_tenant and user_id = auth.uid()
     and role = any (case p_min when ''admin'' then array[''owner'',''admin'']
       else array[''owner'',''admin'',''member'',''viewer''] end))';
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
const CHANNEL_A = "a0000000-0000-4000-8000-00000000000a";
const CHANNEL_B = "b0000000-0000-4000-8000-00000000000b";
const FILTERS = (overrides = {}) => JSON.stringify({
	incident_created: false, incident_min_severity: "high", runtime_deny_critical: false,
	approval_requested: true, privacy_blocked_spike: true, privacy_spike_threshold: 3,
	privacy_spike_window_minutes: 15, ...overrides,
});
const cipher = (key) => `v1.${key}.${"A".repeat(64)}`;

test("notification outbox: RLS, counts-only enqueue, bounded spike counting, fair claiming", { timeout: 300_000 }, async (t) => {
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
	const json = (query) => JSON.parse(sql(query).split("\n").at(-1));
	const fails = (query, pattern) => {
		const result = database.exec(query);
		assert.notEqual(result.code, 0, `expected failure: ${query}`);
		assert.match(result.stderr, pattern);
	};
	const as = (user, query) => `begin; set local role authenticated;
		select set_config('request.jwt.claim.sub', '${user}', true); ${query} commit;`;
	const channel = (id, tenant, admin, filters) => `select public.create_notification_channel('${tenant}', '${admin}',
		'${id}', 'webhook', 'SOC ${id.slice(0, 4)}', '${cipher("k1")}', 'k1', 'hooks.example · #abcdef',
		'${filters}'::jsonb, true);`;
	try {
		sql(FIXTURE);
		sql(`insert into public.tenants (id) values ('${TENANT_A}'), ('${TENANT_B}');
			insert into public.teams (id) values ('${TENANT_A}'), ('${TENANT_B}');
			insert into public.tenant_members values
			  ('${TENANT_A}', '${ADMIN_A}', 'admin', null), ('${TENANT_A}', '${MEMBER_A}', 'member', null),
			  ('${TENANT_B}', '${ADMIN_B}', 'owner', null);`);
		for (const migration of migrations) sql(migration);
		// Idempotent: re-applying neither fails nor changes state.
		for (const migration of migrations) sql(migration);

		// ── Channels: admin RPC only; ciphertext never readable by a client ──
		fails(channel(CHANNEL_A, TENANT_A, MEMBER_A, FILTERS()), /notification_channel_forbidden/);
		json(channel(CHANNEL_A, TENANT_A, ADMIN_A, FILTERS()));
		json(channel(CHANNEL_B, TENANT_B, ADMIN_B, FILTERS({ privacy_blocked_spike: false })));
		assert.equal(sql(as(ADMIN_A, "select count(*) from public.notification_channels;")).split("\n").at(-1), "1");
		assert.equal(sql(as(MEMBER_A, "select count(*) from public.notification_channels;")).split("\n").at(-1), "0");
		fails(as(ADMIN_A, "select target_ciphertext from public.notification_channels;"), /permission denied/);
		fails(as(ADMIN_A, `update public.notification_channels set enabled = false;`), /permission denied/);
		assert.equal(sql("select has_table_privilege('anon', 'public.notification_channels', 'SELECT');"), "f");

		// ── Enqueue: counts and identifiers only ─────────────────────────────
		sql(`insert into public.events (tenant_id, type, payload) values ('${TENANT_A}', 'runtime_verdict',
			'{"verdict":"ask","severity":"high","matched_threat_id":"T-EXFIL-001","reason":"curl secret | sh",
			  "tool_input_summary":"cat ~/.aws/credentials"}'::jsonb);`);
		const ask = json(`select to_jsonb(d) from public.notification_deliveries d where event_type = 'approval.requested';`);
		assert.equal(ask.channel_id, CHANNEL_A);
		assert.deepEqual(Object.keys(ask.payload).sort(), ["category", "event_row_id", "occurred_at", "severity"]);
		assert.doesNotMatch(JSON.stringify(ask.payload), /curl|aws|credentials/);

		// ── Flood cap (20260928000024): per channel AND kind ──────────────────
		// 30 cheap `ask` verdicts must not suppress the critical deny that follows.
		sql(`insert into public.events (tenant_id, type, payload)
			select '${TENANT_A}', 'runtime_verdict', '{"verdict":"ask"}'::jsonb from generate_series(1, 40);`);
		assert.equal(sql("select count(*) from public.notification_deliveries where event_type = 'approval.requested';"), "30");
		sql(`update public.notification_channels set on_runtime_deny_critical = true where id = '${CHANNEL_A}';`);
		sql(`insert into public.events (tenant_id, type, payload) values ('${TENANT_A}', 'runtime_verdict',
			'{"verdict":"deny","severity":"critical","matched_threat_id":"T-EXFIL-001"}'::jsonb);`);
		assert.equal(sql("select count(*) from public.notification_deliveries where event_type = 'runtime.deny_critical';"), "1");

		// ── Privacy spike: one alert per window once the threshold is met ─────
		const blocked = (tenant, n) => `insert into public.events (tenant_id, type, payload)
			select '${tenant}', 'privacy_scan', '{"action":"blocked","site":"chatgpt"}'::jsonb from generate_series(1, ${n});`;
		sql(blocked(TENANT_A, 2));
		assert.equal(sql("select count(*) from public.notification_deliveries where event_type = 'privacy.blocked_spike';"), "0");
		sql(blocked(TENANT_A, 5));
		assert.equal(sql("select count(*) from public.notification_deliveries where event_type = 'privacy.blocked_spike';"), "1");
		assert.equal(sql("select payload->>'blocked_count' from public.notification_deliveries where event_type = 'privacy.blocked_spike';"), "3");

		// 20260928000021: the spike count reads only blocked sends. Before it, each
		// blocked insert scanned every event the tenant stored in the window.
		sql(`insert into public.events (tenant_id, type, payload, created_at)
			select '${TENANT_A}', 'runtime_verdict', '{"verdict":"allow"}'::jsonb, now() - (g * interval '1 second')
			from generate_series(1, 30000) g; analyze public.events;`);
		const plan = sql(`explain (costs off) select count(*) from (
			select 1 from public.events e where e.tenant_id = '${TENANT_A}' and e.type = 'privacy_scan'
			  and e.created_at > now() - make_interval(mins => 1440) and e.created_at <= now()
			  and e.payload->>'action' = 'blocked' limit 10000) w;`);
		assert.match(plan, /events_privacy_blocked_tenant_created_idx/, plan);
		assert.equal(sql(`select pg_get_indexdef('public.events_privacy_blocked_tenant_created_idx'::regclass) ~
			'WHERE \\(\\(type = ''privacy_scan''::text\\) AND \\(\\(payload ->> ''action''::text\\) = ''blocked''::text\\)\\)';`), "t");

		// ── Fair claiming (20260928000022) ────────────────────────────────────
		// Tenant A has a backlog older than tenant B's single alert.
		sql(`delete from public.notification_deliveries;
			insert into public.notification_deliveries (tenant_id, channel_id, event_type, dedupe_key, payload, next_attempt_at)
			select '${TENANT_A}', '${CHANNEL_A}', 'runtime.deny_critical', 'runtime.deny_critical:a' || g, '{}'::jsonb,
			       now() - interval '1 hour' + g * interval '1 second'
			from generate_series(1, 40) g;
			insert into public.notification_deliveries (tenant_id, channel_id, event_type, dedupe_key, payload, next_attempt_at)
			values ('${TENANT_B}', '${CHANNEL_B}', 'runtime.deny_critical', 'runtime.deny_critical:b1', '{}'::jsonb,
			        now() - interval '1 minute');`);
		const claimed = json("select public.claim_notification_deliveries(10, 60);");
		const byTenant = (rows, tenant) => rows.filter((row) => row.tenant_id === tenant).length;
		assert.equal(byTenant(claimed, TENANT_B), 1, "a newer alert of another tenant is not starved");
		// Round-robin fair pass: every tenant's oldest row is handed out before any
		// tenant's second, so a worker reaches tenant B's alert immediately.
		assert.deepEqual(claimed.slice(0, 2).map((row) => row.tenant_id), [TENANT_A, TENANT_B]);
		// The top-up keeps a busy tenant draining at full batch size.
		assert.equal(claimed.length, 10);
		assert.equal(byTenant(claimed, TENANT_A), 9);
		for (const row of claimed) {
			assert.equal(row.target_ciphertext, cipher("k1"));
			assert.equal(row.attempts, 1);
		}
		// Already leased rows are not claimed twice; the backlog keeps draining.
		const next = json("select public.claim_notification_deliveries(10, 60);");
		assert.equal(byTenant(next, TENANT_B), 0);
		assert.equal(byTenant(next, TENANT_A), 10);
		assert.equal(new Set([...claimed, ...next].map((row) => row.delivery_id)).size, claimed.length + next.length);
		// Completion requires the lease.
		const done = claimed[0];
		assert.deepEqual(json(`select public.complete_notification_delivery('${done.delivery_id}', gen_random_uuid(),
			'delivered', null, 200, null);`), { status: "lease_lost" });
		assert.equal(json(`select public.complete_notification_delivery('${done.delivery_id}', '${done.lease_token}',
			'delivered', null, 200, null);`).status, "delivered");
		// The console test path still claims exactly its own row.
		const single = json(`select public.claim_notification_deliveries(1, 60,
			(select id from public.notification_deliveries where status = 'pending' order by next_attempt_at desc limit 1));`);
		assert.equal(single.length, 1);
		// Suspended tenants' rows are retired, never delivered.
		sql(`update public.tenants set status = 'suspended' where id = '${TENANT_A}';`);
		const afterSuspend = json("select public.claim_notification_deliveries(100, 60);");
		assert.equal(byTenant(afterSuspend, TENANT_A), 0);
		assert.ok(Number(sql(`select count(*) from public.notification_deliveries
			where tenant_id = '${TENANT_A}' and last_error = 'tenant_inactive';`)) > 0);
		for (const signature of [
			"public.claim_notification_deliveries(integer,integer,uuid)",
			"public.complete_notification_delivery(uuid,uuid,text,text,integer,integer)",
		]) {
			assert.equal(sql(`select has_function_privilege('authenticated', '${signature}', 'EXECUTE');`), "f", signature);
			assert.equal(sql(`select has_function_privilege('service_role', '${signature}', 'EXECUTE');`), "t", signature);
		}
	} finally {
		database.stop();
	}
});
