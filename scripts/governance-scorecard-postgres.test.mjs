// Real-PostgreSQL contract for the governance scorecard and scheduled summary
// migrations (supabase/migrations/20260927000060_governance_scorecard.sql and
// 20260927000061_governance_digest_schedule.sql).
//
// Runs against AIDR_POSTGRES_TEST_URL=postgres://user@host:port/db (a disposable
// database is created next to it and dropped afterwards) or an isolated
// plain `postgres:17` container (docker, no network; the fixture builds its own auth schema and roles), and is skipped, visibly,
// when neither is available.
//
// It proves: owner/admin-only access behind the tenant identity barrier, tenant
// scoping, counts-only output, the human-oversight review prompt thresholds,
// acceptable-use acknowledgement counting, the settings RPC and its audit
// receipt, the digest claim/lease/complete/retry cycle, service-role-only
// grants, and offboarding disable + purge.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const scorecardMigration = readFileSync(resolve(root, "supabase/migrations/20260927000060_governance_scorecard.sql"), "utf8");
const scheduleMigration = readFileSync(resolve(root, "supabase/migrations/20260927000061_governance_digest_schedule.sql"), "utf8");

function run(command, args, input = "") {
	const result = spawnSync(command, args, { input, encoding: "utf8", timeout: 60_000 });
	return { code: result.status ?? 1, stdout: (result.stdout ?? "").trim(), stderr: result.stderr ?? "" };
}

async function startDatabase() {
	if (process.env.AIDR_POSTGRES_TEST_URL) {
		const database = `aidr_governance_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
		const admin = process.env.AIDR_POSTGRES_TEST_URL;
		const created = run("psql", [admin, "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-c", `create database ${database}`]);
		if (created.code !== 0) throw new Error(created.stderr);
		const url = new URL(admin);
		url.pathname = `/${database}`;
		return {
			exec: (sql) => run("psql", [url.toString(), "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], sql),
			stop: () => run("psql", [admin, "-X", "-qAt", "-c", `drop database if exists ${database} with (force)`]),
		};
	}
	if (run("docker", ["info"]).code !== 0) return null;
	const container = `aidr-governance-${randomUUID().slice(0, 8)}`;
	const started = run("docker", ["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=governance-fixture-only", "postgres:17-bookworm"]);
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

// The smallest schema the migrations read, shaped like the canonical tables,
// with the canonical membership helper and tenant identity barrier.
const FIXTURE = `
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end $$;
create schema if not exists auth;
create schema if not exists app;
create table if not exists auth.users (id uuid primary key, email text);
create table if not exists auth.mfa_factors (id uuid primary key default gen_random_uuid(), user_id uuid not null, status text not null);
create or replace function auth.uid() returns uuid language sql stable as
  $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
create or replace function auth.jwt() returns jsonb language sql stable as
  $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
create table public.tenants (id uuid primary key, name text not null, status text not null default 'active');
create table public.tenant_members (
  tenant_id uuid not null, user_id uuid not null, role text not null,
  joined_at timestamptz not null default now(), expires_at timestamptz, primary key (tenant_id, user_id)
);
create table public.agents (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, agent_runtime text,
  first_seen timestamptz not null default now(), last_seen timestamptz not null default now()
);
create table public.events (
  id bigint generated always as identity primary key, tenant_id uuid not null, agent_id uuid,
  type text not null, created_at timestamptz not null default now(), payload jsonb not null
);
create table public.approval_requests (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, status text not null,
  decided_by uuid, decided_at timestamptz, created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '30 minutes'
);
create table public.posture_findings (id bigint generated always as identity primary key, tenant_id uuid not null,
  source text not null, finding_kind text not null, severity text not null, applicability text,
  mcp_server_name text, attestation_status text, subject_digest text, observed_at timestamptz not null default now());
create table public.tenant_dlp_policies (tenant_id uuid primary key, version bigint not null, updated_at timestamptz not null default now());
create table public.dlp_policy_revisions (tenant_id uuid not null, version bigint not null, created_at timestamptz not null default now());
create table public.tenant_runtime_policies (tenant_id uuid primary key, version bigint not null, updated_at timestamptz not null default now());
create table public.runtime_policy_revisions (tenant_id uuid not null, version bigint not null, created_at timestamptz not null default now());
create table public.team_policies (id uuid primary key default gen_random_uuid(), tenant_id uuid not null, content text not null, updated_at timestamptz not null default now());
create table public.tenant_identity_policies (tenant_id uuid primary key, require_mfa boolean not null default false, required_saml_provider_id uuid);
create table public.identity_user_session_state (user_id uuid primary key, revoked_before timestamptz, global_revoke_pending_session_id uuid);
create table public.scim_tokens (id uuid primary key default gen_random_uuid(), tenant_id uuid not null, revoked_at timestamptz, expires_at timestamptz);
create table public.admin_audit_logs (id bigint generated always as identity primary key, actor_user_id uuid, tenant_id uuid,
  action text not null, detail jsonb not null default '{}'::jsonb, created_at timestamptz not null default now());
create table public.tenant_data_retention_policies (tenant_id uuid not null, data_class text not null, retention_days integer not null);
create table public.tenant_legal_holds (id uuid primary key default gen_random_uuid(), tenant_id uuid not null, placed_at timestamptz not null default now(), released_at timestamptz);
create table public.tenant_offboarding_runs (id uuid primary key default gen_random_uuid(), tenant_id uuid not null, status text not null default 'running', requested_by uuid);
create table public.tenant_offboarding_phase_receipts (run_id uuid not null, phase text not null, status text not null default 'pending',
  eligible_at timestamptz not null default now() - interval '1 minute', rows_deleted bigint not null default 0);

create or replace function app.is_tenant_member_with_role(p_tenant_id uuid, p_min_role text)
returns boolean language sql stable security definer set search_path = public, pg_catalog as $$
  select exists (
    select 1 from public.tenant_members tm join public.tenants t on t.id = tm.tenant_id
    where tm.tenant_id = p_tenant_id and tm.user_id = auth.uid()
      and (tm.expires_at is null or tm.expires_at > now()) and t.status = 'active'
      and tm.role = any (case p_min_role when 'owner' then array['owner'] when 'admin' then array['owner', 'admin']
        when 'member' then array['owner', 'admin', 'member'] else array[]::text[] end))
$$;
create or replace function public.tenant_identity_access_allowed(p_tenant_id uuid)
returns boolean language sql stable security definer set search_path = public, pg_temp as $$
  select auth.uid() is not null
    and not exists (select 1 from public.identity_user_session_state s
      where s.user_id = auth.uid() and s.global_revoke_pending_session_id is not null)
    and not exists (select 1 from public.tenant_identity_policies p
      where p.tenant_id = p_tenant_id and p.require_mfa and coalesce(auth.jwt()->>'aal', 'aal1') <> 'aal2')
$$;
grant usage on schema public, auth, app to authenticated, service_role, anon;
grant execute on function app.is_tenant_member_with_role(uuid, text) to authenticated;
grant execute on function public.tenant_identity_access_allowed(uuid) to authenticated, service_role;
grant execute on function auth.uid(), auth.jwt() to authenticated, service_role;
`;

const TENANT_A = "11111111-1111-4111-8111-111111111111";
const TENANT_B = "22222222-2222-4222-8222-222222222222";
const OWNER_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ADMIN_A = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const MEMBER_A = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const OWNER_B = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const BROWSER_1 = "e1111111-1111-4111-8111-111111111111";
const BROWSER_2 = "e2222222-2222-4222-8222-222222222222";

function event(tenant, type, payload, when = "now() - interval '1 day'", agent = null) {
	const json = JSON.stringify(payload).replaceAll("'", "''");
	return `insert into public.events (tenant_id, agent_id, type, created_at, payload) values ('${tenant}', ${agent ? `'${agent}'` : "null"}, '${type}', ${when}, '${json}'::jsonb);`;
}

// ADMIN_A approves 10 requests within 5 seconds each (a review prompt at the
// default thresholds); OWNER_A decides 4 requests slowly.
const approvals = [
	...Array.from({ length: 10 }, () => `('${TENANT_A}', 'approved', '${ADMIN_A}', now() - interval '2 days' + interval '5 seconds', now() - interval '2 days')`),
	`('${TENANT_A}', 'approved', '${OWNER_A}', now() - interval '3 days' + interval '600 seconds', now() - interval '3 days')`,
	`('${TENANT_A}', 'denied', '${OWNER_A}', now() - interval '3 days' + interval '120 seconds', now() - interval '3 days')`,
	`('${TENANT_A}', 'denied', '${OWNER_A}', now() - interval '3 days' + interval '240 seconds', now() - interval '3 days')`,
	`('${TENANT_B}', 'approved', '${OWNER_B}', now() - interval '1 day' + interval '1 second', now() - interval '1 day')`,
].join(",\n  ");

const SEED = `
insert into public.tenants (id, name) values ('${TENANT_A}', 'Acme Security'), ('${TENANT_B}', 'Other Corp');
insert into auth.users values ('${OWNER_A}', 'owner@acme.example'), ('${ADMIN_A}', 'Admin@Acme.example'),
  ('${MEMBER_A}', 'member@acme.example'), ('${OWNER_B}', 'owner@other.example');
insert into auth.mfa_factors (user_id, status) values ('${OWNER_A}', 'verified'), ('${ADMIN_A}', 'unverified');
insert into public.tenant_members (tenant_id, user_id, role) values
  ('${TENANT_A}', '${OWNER_A}', 'owner'), ('${TENANT_A}', '${ADMIN_A}', 'admin'),
  ('${TENANT_A}', '${MEMBER_A}', 'member'), ('${TENANT_B}', '${OWNER_B}', 'owner');
insert into public.agents (id, tenant_id, agent_runtime, last_seen) values
  ('${BROWSER_1}', '${TENANT_A}', 'browser_guard', now() - interval '2 days'),
  ('${BROWSER_2}', '${TENANT_A}', 'browser_guard', now() - interval '3 days'),
  (gen_random_uuid(), '${TENANT_A}', 'browser_guard', now() - interval '200 days'),
  (gen_random_uuid(), '${TENANT_A}', 'claude-code', now()),
  (gen_random_uuid(), '${TENANT_A}', 'Bad Runtime!', now() - interval '100 days'),
  (gen_random_uuid(), '${TENANT_B}', 'claude-code', now());
${event(TENANT_A, "privacy_scan", { site: "chatgpt", action: "masked", channel: "prompt", entity_counts: { EMAIL: 2 }, findings_count: 3, prompt: "TCKN 10000000146" })}
${event(TENANT_A, "privacy_scan", { site: "gemini", action: "blocked", channel: "paste", findings_count: 1, url: "https://chat.example/c/1" })}
${event(TENANT_A, "privacy_scan", { site: "chatgpt", action: "masked", channel: "prompt", findings_count: 50 }, "now() - interval '60 days'")}
${event(TENANT_B, "privacy_scan", { site: "claude", action: "masked", channel: "prompt", findings_count: 1000 })}
${event(TENANT_A, "runtime_verdict", { decision: "deny", source: "dlp" })}
${event(TENANT_A, "runtime_verdict", { verdict: "ask", source: "heuristic" })}
${event(TENANT_A, "runtime_verdict", { decision: "allow", source: "operator_approval", user_override: true })}
${event(TENANT_A, "runtime_verdict", { decision: "allow", source: "dashboard_approval", user_override: true })}
${event(TENANT_B, "runtime_verdict", { decision: "deny", source: "dlp" })}
${event(TENANT_A, "incident", { incident_id: "inc-1", severity: "critical", status: "open" }, "now() - interval '2 days'")}
${event(TENANT_A, "incident", { incident_id: "inc-1", severity: "critical", status: "resolved" }, "now() - interval '1 day'")}
${event(TENANT_A, "incident", { incident_id: "inc-2", severity: "high", status: "acknowledged" })}
${event(TENANT_A, "incident", { severity: "extreme" })}
${event(TENANT_A, "aup_acknowledgement", { site: "chatgpt", notice_id: "acme-aup", notice_version: 3 }, "now() - interval '100 days'", BROWSER_1)}
${event(TENANT_A, "aup_acknowledgement", { site: "gemini", notice_id: "acme-aup", notice_version: 3 }, "now() - interval '1 day'", BROWSER_2)}
${event(TENANT_A, "aup_acknowledgement", { site: "gemini", notice_id: "acme-aup", notice_version: 3 }, "now() - interval '1 day'", BROWSER_2)}
${event(TENANT_A, "aup_acknowledgement", { site: "chatgpt", notice_id: "acme-aup", notice_version: 2 }, "now() - interval '120 days'", BROWSER_1)}
${event(TENANT_A, "aup_acknowledgement", { site: "chatgpt", notice_id: "bad id!", notice_version: 1 }, "now() - interval '1 day'", BROWSER_1)}
insert into public.approval_requests (tenant_id, status, decided_by, decided_at, created_at) values
  ${approvals};
insert into public.approval_requests (tenant_id, status, created_at, expires_at) values
  ('${TENANT_A}', 'expired', now() - interval '4 days', now() - interval '4 days' + interval '30 minutes'),
  ('${TENANT_A}', 'pending', now() - interval '2 hours', now() - interval '1 hour'),
  ('${TENANT_A}', 'pending', now() - interval '1 minute', now() + interval '29 minutes');
insert into public.posture_findings (tenant_id, source, finding_kind, severity, mcp_server_name, attestation_status) values
  ('${TENANT_A}', 'mcp_inventory', 'mcp_server', 'high', 'shell-runner', 'unverifiable'),
  ('${TENANT_A}', 'mcp_inventory', 'mcp_server', 'info', 'docs', 'approved'),
  ('${TENANT_B}', 'mcp_inventory', 'mcp_server', 'high', 'tenant-b-secret', 'approved');
insert into public.posture_findings (tenant_id, source, finding_kind, severity, applicability) values
  ('${TENANT_A}', 'infra_scan', 'cve', 'critical', 'confirmed');
insert into public.tenant_runtime_policies values ('${TENANT_A}', 5, now() - interval '120 days');
insert into public.runtime_policy_revisions values ('${TENANT_A}', 5, now() - interval '120 days');
insert into public.tenant_identity_policies (tenant_id, require_mfa) values ('${TENANT_A}', true);
insert into public.tenant_data_retention_policies values ('${TENANT_A}', 'telemetry', 90);
insert into public.admin_audit_logs (tenant_id, action) values ('${TENANT_A}', 'compliance_report.generated');
`;

const claims = (user, aal = "aal2") => `set local role authenticated;
set local "request.jwt.claim.sub" = '${user}';
set local "request.jwt.claims" = '${JSON.stringify({ sub: user, aal })}';`;
const asUser = (user, query, aal) => `begin;\n${claims(user, aal)}\n${query}\ncommit;`;
const scorecard = (user, days = 30, tenant = TENANT_A, aal = "aal2") =>
	asUser(user, `select public.governance_scorecard('${tenant}', ${days});`, aal);
const settings = (user, values) => asUser(user, `select public.set_governance_settings('${TENANT_A}', ${values});`);

test("governance scorecard and scheduled summary against real PostgreSQL", { timeout: 180_000 }, async (t) => {
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
		for (let pass = 0; pass < 2; pass++) {
			sql(scorecardMigration); // idempotent re-apply
			sql(scheduleMigration);
		}
		sql(SEED);

		const card = JSON.parse(sql(scorecard(OWNER_A)));
		assert.equal(card.window_days, 30);
		assert.equal(card.period.days, 30);
		assert.equal(card.trend.length, 30);

		// AI usage: tenant A only; browser installs separate from agents.
		assert.deepEqual(card.usage.agents, { enrolled: 2, active: 1 });
		assert.deepEqual(card.usage.browser_installs, { enrolled: 3, active: 2 });
		assert.deepEqual(card.usage.by_runtime.map((row) => row.runtime).sort(), ["browser_guard", "claude-code", "unknown"]);
		assert.deepEqual(card.usage.ai_sites, {
			distinct: 2,
			by_site: [{ site: "chatgpt", scans: 1, blocked: 0 }, { site: "gemini", scans: 1, blocked: 1 }],
		});
		assert.deepEqual(card.usage.mcp_servers, { distinct: 2, not_approved: 1 });

		// Decisions, releases and the daily trend.
		assert.deepEqual(card.decisions, {
			allow: 2, ask: 1, deny: 1, released_by_operator: 1, released_by_dashboard: 1, released_other: 0,
		});
		const totals = card.trend.reduce((sum, day) => ({
			allow: sum.allow + day.allow, deny: sum.deny + day.deny, masked: sum.masked + day.masked,
		}), { allow: 0, deny: 0, masked: 0 });
		assert.deepEqual(totals, { allow: 2, deny: 1, masked: 1 });
		assert.deepEqual(card.browser_guard, { scans: 2, masked: 1, warned: 0, blocked: 1, allowed: 0, items_masked: 3 });

		// Approvals and the human-oversight panel.
		assert.equal(card.approvals.requested, 16);
		assert.equal(card.approvals.approved, 11);
		assert.equal(card.approvals.denied, 2);
		assert.equal(card.approvals.expired_without_decision, 2, "expired and pending-past-expiry both count");
		assert.equal(card.approvals.pending, 1);
		assert.equal(card.approvals.median_decision_seconds, 5);
		assert.equal(card.oversight.thresholds.fast_seconds, 30);
		assert.equal(card.oversight.approvers, 2);
		assert.equal(card.oversight.review_prompts, 1);
		const [first, second] = card.oversight.by_approver;
		assert.deepEqual(
			[first.user_id, first.email, first.decisions, first.fast_approvals, first.review],
			[ADMIN_A, "Admin@Acme.example", 10, 10, true],
		);
		assert.deepEqual([second.user_id, second.decisions, second.denied, second.review], [OWNER_A, 3, 2, false]);

		// Incidents by latest status; posture; policy freshness; identity.
		assert.deepEqual(
			[card.incidents.reported, card.incidents.open, card.incidents.status_unknown],
			[3, 1, 1],
		);
		assert.equal(card.incidents.open_by_severity.high, 1);
		assert.equal(card.incidents.open_by_severity.critical, 0, "resolved later in the period");
		assert.deepEqual(card.posture, { findings: 3, critical: 1, high: 1, cve_confirmed: 1 });
		assert.equal(card.policies.runtime.version, 5);
		assert.ok(card.policies.runtime.age_days >= 119);
		assert.equal(card.policies.dlp, null);
		assert.equal(card.identity.require_mfa, true);
		assert.equal(card.identity.owners_admins, 2);
		assert.equal(card.identity.owners_admins_without_mfa, 1);
		assert.equal(card.identity.telemetry_retention_days, 90);

		// Acceptable use: distinct installs per notice version, malformed ids dropped.
		assert.deepEqual(
			card.acceptable_use.versions.map((row) => [row.notice_id, row.notice_version, row.installs]),
			[["acme-aup", 3, 2], ["acme-aup", 2, 1]],
		);

		assert.deepEqual(card.signals, {
			agents_reporting: true,
			browser_guard_reporting: true,
			dlp_policy_configured: false,
			runtime_policy_configured: true,
			human_approval_in_use: true,
			acceptable_use_acknowledged: true,
			mcp_inventory_reported: true,
			posture_reported: true,
			mfa_required: true,
			retention_configured: true,
			compliance_report_generated: true,
			governance_digest_enabled: false,
		});
		assert.equal(card.settings.digest_enabled, false);
		assert.deepEqual(card.recent_deliveries, []);

		// Counts only: no event content and nothing from tenant B.
		const text = JSON.stringify(card);
		for (const needle of ["10000000146", "chat.example", "Other Corp", "owner@other.example", "tenant-b-secret", "member@acme.example"]) {
			assert.equal(text.includes(needle), false, `scorecard leaked ${needle}`);
		}

		// Authorization: admins yes; members, other tenants, AAL1 under an MFA policy and bad windows no.
		assert.equal(JSON.parse(sql(scorecard(ADMIN_A, 7))).window_days, 7);
		assert.match(sqlFails(scorecard(MEMBER_A)), /governance_forbidden/);
		assert.match(sqlFails(scorecard(OWNER_B)), /governance_forbidden/);
		assert.match(sqlFails(scorecard(OWNER_A, 30, TENANT_A, "aal1")), /governance_identity_barrier/);
		assert.match(sqlFails(scorecard(OWNER_A, 14)), /invalid_governance_window/);
		assert.equal(JSON.parse(sql(scorecard(OWNER_B, 90, TENANT_B))).usage.agents.enrolled, 1);

		// Settings: validated, audited, owner/admin only; clients cannot write the table.
		const saved = JSON.parse(sql(settings(OWNER_A, "true, 'weekly', 'owners_admins', 60, 5, 0.8")));
		assert.equal(saved.digest_enabled, true);
		assert.ok(Date.parse(saved.digest_next_at) > Date.now());
		assert.equal(new Date(saved.digest_next_at).getUTCDay(), 1, "weekly summaries go out on Monday");
		assert.equal(new Date(saved.digest_next_at).getUTCHours(), 6);
		assert.equal(sql(`select count(*) from public.admin_audit_logs where action = 'governance_settings.updated' and actor_user_id = '${OWNER_A}';`), "1");
		const reviewed = JSON.parse(sql(scorecard(OWNER_A)));
		assert.equal(reviewed.oversight.thresholds.fast_seconds, 60);
		assert.equal(reviewed.oversight.review_prompts, 1, "min_decisions 5 and share 0.8 still flag only the fast approver");
		assert.equal(reviewed.signals.governance_digest_enabled, true);
		for (const values of [
			"true, 'daily', 'owners_admins', 30, 10, 0.9",
			"true, 'weekly', 'everyone', 30, 10, 0.9",
			"true, 'weekly', 'owners', 0, 10, 0.9",
			"true, 'weekly', 'owners', 30, 10, 0.4",
			"true, 'weekly', 'owners', 30, 10, 0.9001",
		]) {
			assert.match(sqlFails(settings(OWNER_A, values)), /invalid_governance_settings/);
		}
		assert.match(sqlFails(settings(MEMBER_A, "false, 'weekly', 'owners', 30, 10, 0.9")), /governance_forbidden/);
		assert.match(
			sqlFails(asUser(OWNER_A, `update public.tenant_governance_settings set digest_enabled = false where tenant_id = '${TENANT_A}';`)),
			/permission denied/,
		);
		assert.equal(
			sql(asUser(OWNER_A, `select count(*) from public.tenant_governance_settings;`)),
			"1",
			"owners read their own settings through RLS",
		);
		assert.equal(sql(asUser(MEMBER_A, `select count(*) from public.tenant_governance_settings;`)), "0");

		// Schedule: dry run, claim with lease, complete, retry on failure.
		sql(`update public.tenant_governance_settings set digest_next_at = now() - interval '15 days' where tenant_id = '${TENANT_A}';`);
		const dry = JSON.parse(sql(`select public.claim_due_governance_digests(10, false);`));
		assert.deepEqual([dry.applied, dry.due, dry.claims.length], [false, 1, 0]);
		const claimed = JSON.parse(sql(`select public.claim_due_governance_digests(10, true);`));
		assert.equal(claimed.claims.length, 1);
		const [claim] = claimed.claims;
		assert.equal(claim.tenant_id, TENANT_A);
		assert.deepEqual(claim.recipients, ["admin@acme.example", "owner@acme.example"]);
		assert.equal(Date.parse(claim.period_to) - Date.parse(claim.period_from), 7 * 86_400_000);
		assert.ok(Date.now() - Date.parse(claim.period_to) < 8 * 86_400_000, "a stale schedule summarises the latest week only");
		assert.equal(JSON.parse(sql(`select public.claim_due_governance_digests(10, true);`)).claims.length, 0, "lease held");
		assert.match(sqlFails(`select public.complete_governance_digest('${TENANT_A}', '${randomUUID()}', 'sent', 2, 2);`), /governance_digest_claim_lost/);
		assert.match(sqlFails(`select public.complete_governance_digest('${TENANT_A}', '${claim.claim_id}', 'sent', 2, 3);`), /invalid_governance_digest_result/);

		const retry = JSON.parse(sql(`select public.complete_governance_digest('${TENANT_A}', '${claim.claim_id}', 'failed', 2, 0);`));
		assert.deepEqual([retry.retry, retry.attempts], [true, 1]);
		assert.equal(JSON.parse(sql(`select public.claim_due_governance_digests(10, true);`)).claims.length, 0, "back-off after a failed send");
		sql(`update public.tenant_governance_settings set digest_claim_expires_at = now() - interval '1 second' where tenant_id = '${TENANT_A}';`);
		const again = JSON.parse(sql(`select public.claim_due_governance_digests(10, true);`)).claims[0];
		assert.equal(again.period_from, claim.period_from, "the retry covers the same period");
		const done = JSON.parse(sql(`select public.complete_governance_digest('${TENANT_A}', '${again.claim_id}', 'sent', 2, 2);`));
		assert.equal(done.retry, false);
		assert.ok(Date.parse(done.next_at) > Date.now());
		assert.equal(
			sql(`select string_agg(status || ':' || recipients || ':' || delivered, ',' order by id) from public.governance_digest_deliveries where tenant_id = '${TENANT_A}';`),
			"failed:2:0,sent:2:2",
		);
		const after = JSON.parse(sql(scorecard(OWNER_A)));
		assert.equal(after.settings.digest_last_status, "sent");
		assert.equal(after.recent_deliveries.length, 2);
		assert.equal(after.recent_deliveries[0].status, "sent");

		// The e-mailed summary carries no identities.
		const summary = JSON.parse(sql(`select public.governance_digest_summary('${TENANT_A}', now() - interval '7 days', now());`));
		assert.deepEqual(summary.oversight.by_approver, []);
		assert.equal(summary.oversight.review_prompts, 1);
		assert.equal(JSON.stringify(summary).includes("@"), false);

		// Test sends: owner/admin context and receipt.
		const context = JSON.parse(sql(`select public.governance_digest_test_context('${TENANT_A}', '${ADMIN_A}');`));
		assert.deepEqual(context.recipients, ["admin@acme.example", "owner@acme.example"]);
		assert.match(sqlFails(`select public.governance_digest_test_context('${TENANT_A}', '${MEMBER_A}');`), /governance_forbidden/);
		sql(`select public.record_governance_digest_test('${TENANT_A}', '${ADMIN_A}', 'weekly', now() - interval '7 days', now(), 'no_transport', 2, 0);`);
		assert.equal(sql(`select count(*) from public.admin_audit_logs where action = 'governance_digest.test_sent';`), "1");
		assert.match(
			sqlFails(`select public.record_governance_digest_test('${TENANT_A}', '${ADMIN_A}', 'weekly', now() - interval '7 days', now(), 'sent', 0, 0);`),
			/violates check constraint/,
		);

		// Grants: service role only for the dispatcher functions.
		for (const signature of [
			"public.claim_due_governance_digests(integer, boolean)",
			"public.complete_governance_digest(uuid, uuid, text, integer, integer)",
			"public.governance_digest_summary(uuid, timestamptz, timestamptz)",
			"public.governance_digest_test_context(uuid, uuid)",
			"public.record_governance_digest_test(uuid, uuid, text, timestamptz, timestamptz, text, integer, integer)",
		]) {
			for (const [role, expected] of [["anon", "f"], ["authenticated", "f"], ["service_role", "t"]]) {
				assert.equal(sql(`select has_function_privilege('${role}', '${signature}', 'EXECUTE');`), expected, `${role} ${signature}`);
			}
		}
		assert.equal(sql(`select has_function_privilege('anon', 'public.governance_scorecard(uuid, integer)', 'EXECUTE');`), "f");
		assert.equal(sql(`select has_function_privilege('authenticated', 'app.governance_scorecard_data(uuid, timestamptz, timestamptz, boolean)', 'EXECUTE');`), "f");

		// Offboarding: the request disables the summary; the events phase purges both tables.
		const run = sql(`insert into public.tenant_offboarding_runs (tenant_id, requested_by) values ('${TENANT_A}', '${OWNER_A}') returning id;`);
		assert.equal(sql(`select digest_enabled::text || ':' || coalesce(digest_next_at::text, 'null') from public.tenant_governance_settings where tenant_id = '${TENANT_A}';`), "false:null");
		sql(`insert into public.tenant_offboarding_phase_receipts (run_id, phase) values ('${run}', 'events');`);
		sql(`insert into public.tenant_legal_holds (tenant_id) values ('${TENANT_A}');`);
		assert.match(sqlFails(`update public.tenant_offboarding_phase_receipts set status = 'completed' where run_id = '${run}';`), /governance_offboarding_legal_hold/);
		sql(`update public.tenant_legal_holds set released_at = now() where tenant_id = '${TENANT_A}';`);
		sql(`update public.tenant_offboarding_phase_receipts set status = 'completed' where run_id = '${run}';`);
		assert.equal(sql(`select count(*) from public.tenant_governance_settings where tenant_id = '${TENANT_A}';`), "0");
		assert.equal(sql(`select count(*) from public.governance_digest_deliveries where tenant_id = '${TENANT_A}';`), "0");
		assert.equal(sql(`select rows_deleted from public.tenant_offboarding_phase_receipts where run_id = '${run}';`), "4");
	} finally {
		database.stop();
	}
});
