// Real-PostgreSQL contract for
//   supabase/migrations/20261014000100_incident_triage.sql
//   supabase/migrations/20261014000200_executive_reports.sql
// replayed on top of the COMPLETE canonical migration chain.
//
// Runs against AIDR_POSTGRES_TEST_URL=postgres://user@host:port/db (a
// disposable database is created next to it and dropped afterwards) and is
// skipped, visibly, when it is not set. The only fixture is the part of the
// Supabase platform the migrations reference (roles, auth.*, storage.*,
// pgcrypto in `extensions`), the same as control-plane-gaps-postgres.test.mjs.
//
// It proves: only owners/admins triage, through the service-role RPC only;
// the owner must be an active non-viewer member; closing needs a note; snooze
// is bounded and only on active incidents; optimistic concurrency; the history
// is append-only and kept after the event expires while the triage state
// follows the event; the admin audit row carries no note text; the summary
// counts untriaged incidents as open; report options are owner/admin only and
// audited; the team list holds only workspaces the user administers; and
// offboarding seeds and dispatches both new tables.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const admin = process.env.AIDR_POSTGRES_TEST_URL;

const PLATFORM = `
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
  if not exists (select 1 from pg_roles where rolname = 'supabase_auth_admin') then create role supabase_auth_admin nologin; end if;
end $$;
create schema if not exists auth;
create schema if not exists extensions;
create schema if not exists storage;
create extension if not exists pgcrypto with schema extensions;
create table auth.users (id uuid primary key, email text, raw_user_meta_data jsonb default '{}'::jsonb,
  raw_app_meta_data jsonb default '{}'::jsonb, created_at timestamptz default now(), updated_at timestamptz default now(),
  email_confirmed_at timestamptz, last_sign_in_at timestamptz, is_sso_user boolean default false,
  deleted_at timestamptz, banned_until timestamptz, phone text, is_anonymous boolean default false);
create table auth.sessions (id uuid primary key default gen_random_uuid(), user_id uuid, created_at timestamptz default now(),
  updated_at timestamptz, aal text, not_after timestamptz);
create table auth.identities (id uuid primary key default gen_random_uuid(), user_id uuid, provider text, provider_id text,
  identity_data jsonb, created_at timestamptz default now());
create table auth.mfa_factors (id uuid primary key default gen_random_uuid(), user_id uuid, status text, factor_type text,
  created_at timestamptz default now());
create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
create function auth.role() returns text language sql stable as $$ select nullif(current_setting('request.jwt.claim.role', true), '') $$;
create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
create table storage.buckets(id text primary key, name text, public boolean, file_size_limit bigint, allowed_mime_types text[]);
create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, owner uuid,
  metadata jsonb, created_at timestamptz default now());
create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;
alter table storage.objects enable row level security;
grant usage on schema auth, extensions, storage to anon, authenticated, service_role;
`;

function psql(url, sql) {
	const result = spawnSync("psql", [url, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], {
		input: sql, encoding: "utf8", timeout: 120_000,
	});
	return { code: result.status ?? 1, stdout: (result.stdout ?? "").trim(), stderr: result.stderr ?? "" };
}

test("incident triage and executive report SQL on real PostgreSQL", {
	skip: admin ? false : "AIDR_POSTGRES_TEST_URL is not set",
}, async () => {
	const name = `aidr_triage_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
	assert.equal(psql(admin, `create database ${name}`).code, 0);
	const url = new URL(admin);
	url.pathname = `/${name}`;
	const db = url.toString();
	const sql = (text) => {
		const result = psql(db, text);
		assert.equal(result.code, 0, result.stderr);
		return result.stdout;
	};
	const fails = (text, pattern) => {
		const result = psql(db, text);
		assert.notEqual(result.code, 0, `must be refused: ${text.slice(0, 160)}`);
		assert.match(result.stderr, pattern);
	};
	const service = (text) => sql(`set role service_role; ${text}`);
	const json = (text) => JSON.parse(service(`select (${text})::text;`));

	try {
		sql(PLATFORM);
		for (const file of readdirSync(resolve(root, "supabase/migrations")).filter((f) => f.endsWith(".sql")).sort()) {
			const result = psql(db, `begin;\n${readFileSync(resolve(root, "supabase/migrations", file), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${file}: ${result.stderr}`);
		}

		const [TENANT_A, TENANT_B, OWNER, ADMIN, MEMBER, VIEWER, OUTSIDER, AGENT_A, AGENT_B] =
			Array.from({ length: 9 }, () => randomUUID());
		sql(`
			insert into auth.users(id, email) values
			  ('${OWNER}', 'owner@example.invalid'), ('${ADMIN}', 'admin@example.invalid'),
			  ('${MEMBER}', 'member@example.invalid'), ('${VIEWER}', 'viewer@example.invalid'),
			  ('${OUTSIDER}', 'outsider@example.invalid');
			insert into public.tenants(id, name, kind, created_by) values
			  ('${TENANT_A}', 'Alpha', 'enterprise', '${OWNER}'), ('${TENANT_B}', 'Beta', 'enterprise', '${OUTSIDER}');
			insert into public.teams(id, tenant_id, name, plan) values
			  ('${TENANT_A}', '${TENANT_A}', 'Alpha', 'enterprise'), ('${TENANT_B}', '${TENANT_B}', 'Beta', 'enterprise')
			  on conflict (id) do update set plan = excluded.plan;
			insert into public.tenant_members(tenant_id, user_id, role) values
			  ('${TENANT_A}', '${OWNER}', 'owner'), ('${TENANT_A}', '${ADMIN}', 'admin'),
			  ('${TENANT_A}', '${MEMBER}', 'member'), ('${TENANT_A}', '${VIEWER}', 'viewer'),
			  ('${TENANT_B}', '${OUTSIDER}', 'owner'), ('${TENANT_B}', '${MEMBER}', 'member')
			  on conflict (tenant_id, user_id) do update set role = excluded.role;
			-- Telemetry rows come from the ingest path in production; the seat
			-- admission triggers are not under test here.
			set session_replication_role = replica;
			insert into public.agents(id, tenant_id, user_id, iid) values
			  ('${AGENT_A}', '${TENANT_A}', '${OWNER}', 'iid-a'), ('${AGENT_B}', '${TENANT_B}', '${OUTSIDER}', 'iid-b');
			insert into public.events(user_id, agent_id, tenant_id, event_id, type, payload, created_at) values
			  ('${OWNER}', '${AGENT_A}', '${TENANT_A}', 'deny-1', 'runtime_verdict', '{"verdict":"deny","severity":"critical"}', now() - interval '1 hour'),
			  ('${MEMBER}', '${AGENT_A}', '${TENANT_A}', 'ask-1', 'runtime_verdict', '{"verdict":"ask","severity":"high"}', now() - interval '1 hour'),
			  ('${OWNER}', '${AGENT_A}', '${TENANT_A}', 'allow-1', 'runtime_verdict', '{"verdict":"allow"}', now() - interval '1 hour'),
			  ('${OWNER}', '${AGENT_A}', '${TENANT_A}', 'scan-1', 'plugin_scan', '{"findings_count":2}', now() - interval '1 hour'),
			  ('${OUTSIDER}', '${AGENT_B}', '${TENANT_B}', 'deny-b', 'runtime_verdict', '{"verdict":"deny"}', now() - interval '1 hour');
			set session_replication_role = origin;`);
		const eventId = (key) => sql(`select id from public.events where event_id = '${key}';`);
		const DENY = eventId("deny-1");
		const ASK = eventId("ask-1");
		const ALLOW = eventId("allow-1");
		const SCAN = eventId("scan-1");
		const DENY_B = eventId("deny-b");
		const fields = (status, extra = {}) =>
			`'${JSON.stringify({ status, owner_user_id: null, resolution_note: null, snoozed_until: null, ...extra })}'::jsonb`;
		const update = (actor, event, version, status, extra = {}, tenant = TENANT_A) =>
			`select public.update_incident_triage('${tenant}', '${actor}', ${event}, ${version}, ${fields(status, extra)})`;

		// ── No browser path at all ────────────────────────────────────────
		fails(`set role authenticated; select * from public.incident_triage;`, /permission denied/);
		fails(`set role authenticated; select * from public.incident_triage_history;`, /permission denied/);
		fails(`set role authenticated; ${update(OWNER, DENY, 0, "acknowledged")};`, /permission denied/);
		fails(`set role anon; select public.set_governance_report_options('${TENANT_A}', '${OWNER}', 'tr', true);`, /permission denied/);

		// ── Role, tenant and event checks ─────────────────────────────────
		for (const actor of [MEMBER, VIEWER, OUTSIDER]) {
			fails(`set role service_role; ${update(actor, DENY, 0, "acknowledged")};`, /incident_triage_forbidden/);
		}
		fails(`set role service_role; ${update(OWNER, DENY_B, 0, "acknowledged")};`, /incident_not_found/);
		fails(`set role service_role; ${update(OWNER, ALLOW, 0, "acknowledged")};`, /incident_not_found/);
		fails(`set role service_role; ${update(OWNER, DENY, 0, "acknowledged", { owner_user_id: VIEWER })};`, /incident_owner_not_member/);
		fails(`set role service_role; ${update(OWNER, DENY, 0, "acknowledged", { owner_user_id: OUTSIDER })};`, /incident_owner_not_member/);
		fails(`set role service_role; ${update(OWNER, DENY, 0, "resolved")};`, /incident_resolution_note_required/);
		fails(`set role service_role; ${update(OWNER, DENY, 0, "open", { snoozed_until: new Date(Date.now() + 40 * 86_400_000).toISOString() })};`,
			/invalid_incident_triage:snoozed_until/);
		fails(`set role service_role; ${update(OWNER, DENY, 0, "resolved", { resolution_note: "done", snoozed_until: new Date(Date.now() + 86_400_000).toISOString() })};`,
			/incident_snooze_closed/);
		fails(`set role service_role; select public.update_incident_triage('${TENANT_A}', '${OWNER}', ${DENY}, 0, '{"status":"open","extra":"x"}'::jsonb);`,
			/invalid_incident_triage:extra/);

		// ── Lifecycle: acknowledge + assign, conflict, false positive ─────
		const first = json(update(ADMIN, DENY, 0, "acknowledged", { owner_user_id: MEMBER }));
		assert.equal(first.version, 1);
		assert.equal(first.owner_user_id, MEMBER);
		fails(`set role service_role; ${update(OWNER, DENY, 0, "open")};`, /incident_triage_conflict/);
		fails(`set role service_role; ${update(OWNER, DENY, 1, "acknowledged", { owner_user_id: MEMBER })};`, /incident_triage_unchanged/);
		const snoozed = json(update(OWNER, ASK, 0, "open", { snoozed_until: new Date(Date.now() + 2 * 86_400_000).toISOString() }));
		assert.ok(snoozed.snoozed_until);
		const closed = json(update(OWNER, DENY, 1, "false_positive", { owner_user_id: MEMBER, resolution_note: "Release script; secret-scan note 123" }));
		assert.equal(closed.version, 2);
		// The event was raised by the owner's own agent: allowed, but recorded.
		assert.equal(closed.self_closure, true);
		assert.equal(json(update(ADMIN, SCAN, 0, "resolved", { resolution_note: "Plugin removed" })).self_closure, false);

		const history = sql(`select to_status || ':' || coalesce(from_status, '-') || ':' || self_closure
			from public.incident_triage_history where event_id = ${DENY} order by id;`).split("\n");
		assert.deepEqual(history, ["acknowledged:-:false", "false_positive:acknowledged:true"]);
		const audit = sql(`select detail::text from public.admin_audit_logs where action = 'incident.triaged' and tenant_id = '${TENANT_A}';`);
		assert.match(audit, /"to_status": "false_positive"/);
		assert.doesNotMatch(audit, /Release script|secret-scan/);
		// The team-visible audit row is written too.
		assert.equal(sql(`select count(*) from public.audit_logs where team_id = '${TENANT_A}' and action = 'incident.triaged';`), "4");
		// History is append-only for the service role.
		fails(`set role service_role; update public.incident_triage_history set note = 'x';`, /permission denied/);
		fails(`set role service_role; delete from public.incident_triage_history;`, /permission denied/);

		// ── Counts: untriaged incidents are open ──────────────────────────
		const summary = json(`public.incident_triage_summary('${TENANT_A}', now() - interval '1 day', now())`);
		assert.deepEqual(
			{ total: summary.total, open: summary.open, resolved: summary.resolved, false_positive: summary.false_positive,
				snoozed: summary.snoozed, unassigned_active: summary.unassigned_active, active_high: summary.active_high,
				active_critical: summary.active_critical },
			{ total: 3, open: 1, resolved: 1, false_positive: 1, snoozed: 1, unassigned_active: 1, active_high: 1, active_critical: 0 },
		);
		assert.equal(json(`public.incident_triage_summary('${TENANT_B}', now() - interval '1 day', now())`).open, 1);

		// ── Retention: triage follows the event, history stays ────────────
		sql(`delete from public.events where id = ${DENY};`);
		assert.equal(sql(`select count(*) from public.incident_triage where event_id = ${DENY};`), "0");
		assert.equal(sql(`select count(*) from public.incident_triage_history where event_id = ${DENY};`), "2");

		// ── Report options and team list ──────────────────────────────────
		const defaults = json(`public.governance_report_context('${TENANT_A}', now() - interval '7 days', now())`);
		assert.equal(defaults.language, "en");
		assert.equal(defaults.attachment, true);
		assert.equal(typeof defaults.triage.total, "number");
		fails(`set role service_role; select public.set_governance_report_options('${TENANT_A}', '${MEMBER}', 'tr', true);`, /report_options_forbidden/);
		fails(`set role service_role; select public.set_governance_report_options('${TENANT_A}', '${OWNER}', 'de', true);`, /invalid_report_options/);
		assert.equal(json(`public.set_governance_report_options('${TENANT_A}', '${ADMIN}', 'tr', false)`).digest_language, "tr");
		const context = json(`public.governance_report_context('${TENANT_A}', now() - interval '7 days', now())`);
		assert.deepEqual([context.language, context.attachment], ["tr", false]);
		assert.match(sql(`select detail::text from public.admin_audit_logs where action = 'governance_report_options.updated';`),
			/"digest_language": "tr"/);
		// The digest schedule is untouched by an options change.
		assert.equal(sql(`select digest_enabled from public.tenant_governance_settings where tenant_id = '${TENANT_A}';`), "f");

		const teams = (user) => json(`public.executive_report_teams('${user}')`).map((team) => team.tenant_id).sort();
		assert.ok(teams(OWNER).includes(TENANT_A));
		assert.ok(!teams(OWNER).includes(TENANT_B));
		assert.ok(!teams(MEMBER).includes(TENANT_A) && !teams(MEMBER).includes(TENANT_B));
		assert.ok(!teams(VIEWER).includes(TENANT_A));
		sql(`update public.tenant_members set expires_at = now() - interval '1 minute' where tenant_id = '${TENANT_A}' and user_id = '${ADMIN}';`);
		assert.ok(!teams(ADMIN).includes(TENANT_A));

		// ── Offboarding seeds and dispatches both tables ──────────────────
		sql(`insert into public.tenant_offboarding_runs (tenant_id, requested_by) values ('${TENANT_A}', '${OWNER}');`);
		assert.equal(
			sql(`select string_agg(phase_order || ':' || phase || ':' || data_class, ',' order by phase_order)
				from public.tenant_offboarding_phase_receipts r join public.tenant_offboarding_runs o on o.id = r.run_id
				where o.tenant_id = '${TENANT_A}' and r.phase like 'incident_triage%';`),
			"60:incident_triage:telemetry,61:incident_triage_history:security_audit",
		);
		const dispatcher = sql(`select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure);`);
		assert.match(dispatcher, /when 'incident_triage' then 'public\.incident_triage'/);
		assert.match(dispatcher, /when 'incident_triage_history' then 'public\.incident_triage_history'/);
	} finally {
		psql(admin, `drop database if exists ${name} with (force)`);
	}
});
