// Real-PostgreSQL contract for
//   supabase/migrations/20260928000001_agent_offline_governance_alerts.sql
//   supabase/migrations/20260928000002_agent_profile_staging.sql
// replayed on top of the COMPLETE canonical migration chain.
//
// Runs against AIDR_POSTGRES_TEST_URL=postgres://user@host:port/db (a
// disposable database is created next to it and dropped afterwards) and is
// skipped, visibly, when it is not set. The only fixture is the part of the
// Supabase platform the migrations reference (roles, auth.*, storage.*,
// pgcrypto in `extensions`).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { agentProfileTemplateDocument } from "../packages/core/dist/index.js";
import { stagedProfileDigest } from "./provision-agent-profiles.mjs";

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

test("agent offline, governance alerts and agent profile staging on real PostgreSQL", {
	skip: admin ? false : "AIDR_POSTGRES_TEST_URL is not set",
}, async () => {
	const name = `aidr_f2_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
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
		assert.notEqual(result.code, 0, `must be refused: ${text.slice(0, 120)}`);
		assert.match(result.stderr, pattern);
	};
	const json = (text) => JSON.parse(sql(text));
	try {
		sql(`alter database ${name} set search_path = public, extensions`);
		sql(PLATFORM);
		for (const file of readdirSync(resolve(root, "supabase/migrations")).filter((f) => f.endsWith(".sql")).sort()) {
			const result = psql(db, `begin;\n${readFileSync(resolve(root, "supabase/migrations", file), "utf8")}\ncommit;`);
			assert.equal(result.code, 0, `${file}: ${result.stderr}`);
		}

		// Workspace: owner (creates the team tenant), an admin and a member.
		const owner = randomUUID();
		const adminUser = randomUUID();
		const member = randomUUID();
		sql(`insert into auth.users(id, email) values ('${owner}', 'owner@example.test');`);
		const tenant = sql(`select t.id from public.teams t join public.tenant_members m on m.tenant_id = t.id
			where m.user_id = '${owner}' limit 1;`);
		sql(`insert into auth.users(id, email) values ('${adminUser}', 'admin@example.test'), ('${member}', 'member@example.test');
			insert into public.tenant_members(tenant_id, user_id, role) values ('${tenant}', '${adminUser}', 'admin'), ('${tenant}', '${member}', 'member');
			-- Enrollment admission has its own suites; agents are fixtures here.
			alter table public.agents disable trigger agents_enrollment_admission;`);
		const agent = (iid, minutesAgo) => sql(`insert into public.agents(user_id, tenant_id, iid, agent_runtime, display_name, last_seen)
			values ('${owner}', '${tenant}', '${iid}', 'claude-code', 'alice-laptop', now() - interval '${minutesAgo} minutes') returning id;`);
		const longDead = agent("iid-dead", 180);
		const flaky = agent("iid-flaky", 90);
		agent("iid-live", 10);

		// ── Channel with the extended filters ─────────────────────────────────
		const channel = randomUUID();
		const legacy = { incident_created: false, incident_min_severity: "high", runtime_deny_critical: false,
			approval_requested: false, privacy_blocked_spike: false, privacy_spike_threshold: 10, privacy_spike_window_minutes: 15 };
		const filters = { ...legacy, agent_offline: true, agent_offline_minutes: 60, governance_review_overdue: true,
			governance_intake_requested: true, governance_change_pending: true, governance_exception_expiring: true,
			governance_exception_days: 30, governance_digest: true };
		const ciphertext = `v1.k1.${"A".repeat(60)}`;
		const created = json(`set role service_role; select public.create_notification_channel('${tenant}', '${adminUser}',
			'${channel}', 'slack', 'Fleet', '${ciphertext}', 'k1', 'hooks.slack.com', '${JSON.stringify(filters)}'::jsonb, true);`);
		assert.deepEqual(created.filters, filters);
		// Older consoles (original keys only) still work; unknown keys and bounds are refused.
		fails(`set role service_role; select public.create_notification_channel('${tenant}', '${adminUser}', gen_random_uuid(),
			'slack', 'Bad', '${ciphertext}', 'k1', 'h', '${JSON.stringify({ ...legacy, governance_everything: true })}'::jsonb, true);`,
		/invalid_notification_channel/);
		fails(`set role service_role; select public.create_notification_channel('${tenant}', '${adminUser}', gen_random_uuid(),
			'slack', 'Bad', '${ciphertext}', 'k1', 'h', '${JSON.stringify({ ...legacy, agent_offline: true, agent_offline_minutes: 4 })}'::jsonb, true);`,
		/invalid_notification_channel/);
		fails(`set role service_role; select public.create_notification_channel('${tenant}', '${member}', gen_random_uuid(),
			'slack', 'Member', '${ciphertext}', 'k1', 'h', '${JSON.stringify(filters)}'::jsonb, true);`, /notification_channel_forbidden/);
		assert.equal(sql(`select agent_offline_armed_at is not null from public.notification_channels where id = '${channel}';`), "t");
		// Pretend the channel was armed two hours ago (fixture only).
		sql(`set session_replication_role = replica;
			update public.notification_channels set agent_offline_armed_at = now() - interval '2 hours' where id = '${channel}';`);

		const scan = () => json("set role service_role; select public.enqueue_scheduled_notifications(500);");
		const deliveries = (type) => sql(`select coalesce(json_agg(payload order by created_at, id), '[]') from public.notification_deliveries
			where channel_id = '${channel}' and event_type = '${type}';`);

		// Governance fixtures: an overdue asset and an approved exception expiring in 5 days.
		const asset = sql(`insert into public.ai_assets(tenant_id, asset_type, identifier, name, business_purpose, status, review_due_at)
			values ('${tenant}', 'mcp_server', 'github', 'GitHub MCP', 'secret purpose text', 'approved', current_date - 3) returning id;`);
		sql(`insert into public.ai_governance_exceptions(tenant_id, asset_id, scope_kind, justification, status, requested_by,
			created_at, expires_at, starts_at, decided_by, decided_at, decision_reason, waived_status)
			values ('${tenant}', '${asset}', 'tenant', 'private justification', 'approved', '${member}', now() - interval '1 day',
			now() + interval '5 days', now() - interval '1 day', '${adminUser}', now(), 'ok', 'restricted');`);

		const first = scan();
		assert.deepEqual(first, { skipped: false, agent_offline: 1, agent_recovered: 0, governance_review_overdue: 1,
			governance_exception_expiring: 1, capped: 0 });
		const offline = JSON.parse(deliveries("agent.offline"));
		assert.equal(offline.length, 1, "only the agent that went offline after arming alerts");
		assert.equal(offline[0].agent_id, flaky);
		assert.equal(offline[0].offline_minutes, 60);
		assert.equal(offline[0].category, "claude-code");
		assert.notEqual(offline[0].agent_id, longDead);
		assert.deepEqual(JSON.parse(deliveries("governance.review_overdue"))[0].items_count, 1);
		assert.deepEqual(JSON.parse(deliveries("governance.exception_expiring"))[0].window_days, 30);
		for (const payload of [deliveries("agent.offline"), deliveries("governance.review_overdue"), deliveries("governance.exception_expiring")]) {
			assert.doesNotMatch(payload, /alice-laptop|secret purpose|private justification|GitHub MCP|github/);
		}

		// Same outage, same day: nothing new.
		assert.deepEqual(scan(), { skipped: false, agent_offline: 0, agent_recovered: 0, governance_review_overdue: 0,
			governance_exception_expiring: 0, capped: 0 });
		// The agent reports again: one recovery notice, the outage closes.
		sql(`update public.agents set last_seen = now() where id = '${flaky}';`);
		assert.equal(scan().agent_recovered, 1);
		assert.equal(sql(`select count(*) from public.notification_agent_outages where agent_id = '${flaky}';`), "0");
		assert.ok(JSON.parse(deliveries("agent.recovered"))[0].offline_minutes >= 89);
		// A new outage alerts again.
		sql(`update public.agents set last_seen = now() - interval '61 minutes' where id = '${flaky}';`);
		assert.equal(scan().agent_offline, 1);
		assert.equal(JSON.parse(deliveries("agent.offline")).length, 2);
		// Switching the filter off forgets open outages.
		json(`set role service_role; select public.update_notification_channel('${tenant}', '${adminUser}', '${channel}', 'slack',
			null, null, '${JSON.stringify({ ...filters, agent_offline: false })}'::jsonb, null, null, null);`);
		assert.equal(sql(`select count(*) from public.notification_agent_outages where channel_id = '${channel}';`), "0");

		// Request events are enqueued in the same transaction, identifiers only.
		const intake = sql(`insert into public.ai_intake_requests(tenant_id, asset_type, identifier, name, business_purpose,
			requested_by, expires_at) values ('${tenant}', 'ai_site', 'chat.example.test', 'Chat', 'secret purpose text',
			'${member}', now() + interval '30 days') returning id;`);
		const intakeAlert = JSON.parse(deliveries("governance.intake_requested"));
		assert.deepEqual([intakeAlert[0].request_id, intakeAlert[0].category], [intake, "ai_site"]);
		assert.doesNotMatch(JSON.stringify(intakeAlert), /secret purpose|chat\.example/);

		// ── Agent profile staging ────────────────────────────────────────────
		const v1 = agentProfileTemplateDocument("read-only-reviewer");
		const v2 = agentProfileTemplateDocument("ci-agent");
		const stage = (actor, expected, doc, restored = "null") =>
			`set role service_role; select to_jsonb(public.stage_agent_profiles('${tenant}', '${actor}', ${expected},
				'${JSON.stringify(doc).replaceAll("'", "''")}'::jsonb, ${restored}));`;
		const staged = json(stage(owner, 0, v1));
		assert.equal(staged.version, 1);
		// The control plane's digest is the one the operator CLI verifies.
		assert.equal(staged.policy_sha256, stagedProfileDigest(v1));
		fails(stage(owner, 0, v2), /policy_version_conflict/);
		fails(stage(member, 1, v2), /policy_forbidden/);
		fails(stage(owner, 1, { ...v2, version: 2 }), /invalid_agent_profiles/);
		fails(stage(owner, 1, { ...v2, unknown: true }), /invalid_agent_profiles/);
		assert.equal(json(stage(adminUser, 1, v2)).version, 2);
		fails(stage(owner, 2, v2, "1"), /invalid_agent_profiles/);
		const restored = json(stage(owner, 2, v1, "1"));
		assert.equal(restored.version, 3);
		assert.equal(sql(`select restored_from from public.agent_profile_revisions where tenant_id = '${tenant}' and version = 3;`), "1");
		fails(`update public.agent_profile_revisions set profile_count = 2 where tenant_id = '${tenant}';`, /agent_profile_revision_immutable/);
		fails(`delete from public.agent_profile_revisions where tenant_id = '${tenant}';`, /agent_profile_revision_immutable/);
		fails(`set role authenticated; select * from public.tenant_agent_profiles;`, /permission denied/);
		assert.match(sql(`select detail::text from public.admin_audit_logs where action = 'agent_profiles.staged' order by id desc limit 1;`),
			/"version": 3/);

		// Four-eyes: direct staging is refused; an approved change request applies it.
		sql(`insert into public.tenant_ai_governance_settings(tenant_id, policy_four_eyes) values ('${tenant}', true);`);
		fails(stage(owner, 3, v2), /policy_four_eyes_required/);
		const request = json(`set role service_role; select public.submit_policy_change_request('${tenant}', '${owner}',
			'agent_profiles_stage', 3, null, null, '${JSON.stringify({ policy: v2 })}'::jsonb);`);
		assert.equal(request.status, "pending");
		const pending = JSON.parse(deliveries("governance.change_pending"));
		assert.deepEqual([pending[0].request_id, pending[0].category], [request.request_id, "agent_profiles_stage"]);
		fails(`set role service_role; select public.decide_policy_change_request('${tenant}', '${owner}',
			'${request.request_id}', 'approve', 'self');`, /four_eyes_self_approval/);
		const decided = json(`set role service_role; select public.decide_policy_change_request('${tenant}', '${adminUser}',
			'${request.request_id}', 'approve', 'reviewed');`);
		assert.deepEqual([decided.status, decided.applied_version], ["approved", 4]);
		assert.equal(sql(`select version from public.tenant_agent_profiles where tenant_id = '${tenant}';`), "4");

		// ── Governance digest to channels, once per period ───────────────────
		sql(`insert into public.tenant_governance_settings(tenant_id, digest_enabled, digest_next_at)
			values ('${tenant}', true, now() - interval '1 minute');`);
		const claims = json(`set role service_role; select public.claim_due_governance_digests(10, true);`).claims;
		const claim = claims.find((entry) => entry.tenant_id === tenant);
		const completed = json(`set role service_role; select public.complete_governance_digest('${tenant}', '${claim.claim_id}',
			'no_transport', 0, 0);`);
		assert.equal(completed.channels_queued, 1);
		const digest = JSON.parse(deliveries("governance.digest"));
		assert.equal(digest.length, 1);
		assert.equal(digest[0].category, "weekly");
		assert.equal(digest[0].digest.agents_enrolled, 3);
		assert.equal(digest[0].digest.reviews_overdue, 1);
		assert.ok(Object.values(digest[0].digest).every((value) => Number.isInteger(value) && value >= 0));
		assert.doesNotMatch(JSON.stringify(digest), /@example\.test|alice-laptop|Chat|GitHub/);
		assert.equal(sql(`select app.enqueue_governance_digest_notifications('${tenant}', 'weekly',
			'${digest[0].period_from}', '${digest[0].period_to}');`), "0", "one digest per channel per period");

		// Offboarding purges channels, their deliveries and open outages together.
		sql(`update public.tenants set status = 'closing' where id = '${tenant}';`);
		assert.equal(sql(`select (select count(*) from public.notification_channels where tenant_id = '${tenant}')
			+ (select count(*) from public.notification_deliveries where tenant_id = '${tenant}')
			+ (select count(*) from public.notification_agent_outages where tenant_id = '${tenant}');`), "0");
	} finally {
		psql(admin, `drop database if exists ${name} with (force)`);
	}
});
