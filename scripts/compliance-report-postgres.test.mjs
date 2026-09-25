// Real-PostgreSQL contract for supabase/migrations/20260926000030_compliance_report.sql.
//
// Runs against either
//   AIDR_POSTGRES_TEST_URL=postgres://user@host:port/db  (a disposable database
//     is created next to it and dropped afterwards), or
//   an isolated `supabase/postgres` container (docker, no network),
// and is skipped, visibly, when neither is available.
//
// It proves that the evidence function aggregates one tenant only, refuses
// non-admins and out-of-range periods, emits no raw content (prompt text, DLP
// keywords, policy bodies, hold reasons, member emails), and that its output is
// accepted by the Edge Function's schema projection unchanged.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const migration = readFileSync(resolve(root, "supabase/migrations/20260926000030_compliance_report.sql"), "utf8");

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
		const database = `aidr_compliance_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
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
	const container = `aidr-compliance-${randomUUID().slice(0, 8)}`;
	const started = run("docker", ["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=compliance-fixture-only", "supabase/postgres:17.6.1.136"]);
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

// The smallest schema the migration reads, shaped like the canonical tables.
const FIXTURE = `
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end $$;
create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists auth;
create table if not exists auth.users (id uuid primary key, email text);
create table if not exists auth.mfa_factors (id uuid primary key default gen_random_uuid(), user_id uuid not null, status text not null);
create table public.tenants (
  id uuid primary key, name text not null, kind text not null default 'team', status text not null default 'active',
  region text, retention_days integer not null default 30, created_at timestamptz not null default now()
);
create table public.tenant_members (
  tenant_id uuid not null, user_id uuid not null, role text not null,
  joined_at timestamptz not null default now(), expires_at timestamptz, primary key (tenant_id, user_id)
);
create table public.agents (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, iid text not null default 'iid',
  display_name text, agent_runtime text, first_seen timestamptz not null default now(), last_seen timestamptz not null default now()
);
create table public.events (
  id bigint generated always as identity primary key, tenant_id uuid not null, agent_id uuid,
  type text not null, created_at timestamptz not null default now(), payload jsonb not null
);
create table public.tenant_dlp_policies (tenant_id uuid primary key, version bigint not null, policy jsonb not null, updated_at timestamptz not null default now());
create table public.dlp_policy_revisions (tenant_id uuid not null, version bigint not null, policy jsonb not null, created_at timestamptz not null default now());
create table public.tenant_runtime_policies (tenant_id uuid primary key, version bigint not null, policy jsonb not null, updated_at timestamptz not null default now());
create table public.runtime_policy_revisions (tenant_id uuid not null, version bigint not null, policy jsonb not null, created_at timestamptz not null default now());
create table public.team_policies (id uuid primary key default gen_random_uuid(), tenant_id uuid not null, content text not null, updated_at timestamptz not null default now());
create table public.tenant_identity_policies (tenant_id uuid primary key, require_mfa boolean not null default false,
  break_glass_enabled boolean not null default false, required_saml_provider_id uuid, updated_at timestamptz not null default now());
create table public.scim_tokens (id uuid primary key default gen_random_uuid(), tenant_id uuid not null, revoked_at timestamptz, expires_at timestamptz, last_used_at timestamptz);
create table public.scim_users (id uuid primary key default gen_random_uuid(), tenant_id uuid not null, active boolean not null default true);
create table public.scim_group_role_mappings (tenant_id uuid not null, external_group_id text not null, role text not null);
create table public.admin_audit_logs (id bigint generated always as identity primary key, actor_user_id uuid, tenant_id uuid,
  action text not null, detail jsonb not null default '{}'::jsonb, created_at timestamptz not null default now());
create table public.posture_findings (id bigint generated always as identity primary key, tenant_id uuid not null,
  source text not null, finding_kind text not null, severity text not null, cvss numeric(3, 1), vuln_id text,
  applicability text, mcp_server_name text, mcp_transport text, risk_categories text[] not null default '{}',
  attestation_status text, subject_digest text, skill_risk_type text, observed_at timestamptz not null default now());
create table public.tenant_data_retention_policies (tenant_id uuid not null, data_class text not null, retention_days integer not null,
  description text not null default 'x', covers_backups boolean not null default false, updated_at timestamptz not null default now());
create table public.tenant_legal_holds (id uuid primary key default gen_random_uuid(), tenant_id uuid not null, hold_reference text not null,
  reason text not null, placed_at timestamptz not null default now(), released_at timestamptz);
create table public.tenant_offboarding_runs (id uuid primary key default gen_random_uuid(), tenant_id uuid not null, status text not null,
  requested_at timestamptz not null default now(), completed_at timestamptz, backup_scope text not null default 'excluded_external_retention');
create table public.tenant_offboarding_phase_receipts (run_id uuid not null, phase text not null, status text not null, rows_deleted bigint not null default 0);
create table public.audit_export_objects (path text primary key, tenant_id uuid not null, created_at timestamptz not null default now(), expires_at timestamptz not null);
grant usage on schema public, auth, extensions to authenticated, service_role, anon;
`;

const TENANT_A = "11111111-1111-4111-8111-111111111111";
const TENANT_B = "22222222-2222-4222-8222-222222222222";
const OWNER_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ADMIN_A = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const MEMBER_A = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const OWNER_B = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const SECRET_TEXT = ["10000000146", "Project Falcon", "Litigation LIT-2026-7", "member@acme.example", "tenant-b-secret", "https://chat.example"];

function event(tenant, type, payload, when = "now() - interval '1 day'") {
	const json = JSON.stringify(payload).replaceAll("'", "''");
	return `insert into public.events (tenant_id, type, created_at, payload) values ('${tenant}', '${type}', ${when}, '${json}'::jsonb);`;
}

const SEED = `
insert into public.tenants (id, name, region, retention_days) values
  ('${TENANT_A}', 'Acme Security', 'eu-central-1', 90), ('${TENANT_B}', 'Other Corp', 'http://not-a-region', 30);
insert into auth.users values ('${OWNER_A}', 'owner@acme.example'), ('${ADMIN_A}', 'admin@acme.example'),
  ('${MEMBER_A}', 'member@acme.example'), ('${OWNER_B}', 'owner@other.example');
insert into auth.mfa_factors (user_id, status) values ('${OWNER_A}', 'verified'), ('${ADMIN_A}', 'unverified');
insert into public.tenant_members (tenant_id, user_id, role) values
  ('${TENANT_A}', '${OWNER_A}', 'owner'), ('${TENANT_A}', '${ADMIN_A}', 'admin'),
  ('${TENANT_A}', '${MEMBER_A}', 'member'), ('${TENANT_B}', '${OWNER_B}', 'owner');
insert into public.agents (tenant_id, agent_runtime, display_name, last_seen) values
  ('${TENANT_A}', 'browser_guard', 'Finance laptop', now() - interval '2 days'),
  ('${TENANT_A}', 'browser_guard', 'Old laptop', now() - interval '400 days'),
  ('${TENANT_A}', 'claude-code', 'dev box', now()),
  ('${TENANT_A}', 'Bad Runtime!', 'x', now()),
  ('${TENANT_B}', 'claude-code', 'tenant-b-secret', now());
${event(TENANT_A, "privacy_scan", { site: "chatgpt", action: "masked", channel: "prompt", entity_counts: { EMAIL: 2, TC_KIMLIK: 1 }, policy_id: "acme-policy-v3", prompt: "TCKN 10000000146" })}
${event(TENANT_A, "privacy_scan", { site: "gemini", action: "blocked", channel: "paste", entity_counts: { SECRET: 1 }, url: "https://chat.example/c/1" })}
${event(TENANT_A, "privacy_scan", { site: "https://chat.example", action: "warned", channel: "file", entity_counts: { "lower-case": 5, EMAIL: "7" } })}
${event(TENANT_A, "privacy_scan", { site: "chatgpt", action: "masked", channel: "prompt", entity_counts: { EMAIL: 50 } }, "now() - interval '200 days'")}
${event(TENANT_B, "privacy_scan", { site: "claude", action: "masked", channel: "prompt", entity_counts: { EMAIL: 1000 } })}
${event(TENANT_A, "runtime_verdict", { decision: "deny", source: "dlp", tool_input_summary: "Project Falcon" })}
${event(TENANT_A, "runtime_verdict", { verdict: "ask", source: "heuristic" })}
${event(TENANT_A, "runtime_verdict", { decision: "allow", source: "DLP" })}
${event(TENANT_A, "runtime_verdict", { decision: "allow", source: "has spaces / bad" })}
${event(TENANT_B, "runtime_verdict", { decision: "deny", source: "dlp" })}
${event(TENANT_A, "incident", { severity: "high", status: "open" })}
${event(TENANT_A, "incident", { severity: "extreme", status: "resolved" })}
${event(TENANT_A, "plugin_scan", { findings_count: 2 })}
${event(TENANT_A, "plugin_scan", { findings_count: 0 })}
${event(TENANT_A, "runtime_verdict", { decision: "deny" }, "now() - interval '95 days'")}
insert into public.tenant_dlp_policies values ('${TENANT_A}', 2,
  '{"tenantId":"${TENANT_A}","version":"2","labels":[{"id":"l1"}],"rules":[{"id":"r1","keyword":"Project Falcon"},{"id":"r2"}],"exceptions":[]}', now() - interval '3 days');
insert into public.dlp_policy_revisions values
  ('${TENANT_A}', 1, '{"rules":[{"keyword":"Project Falcon"}]}', now() - interval '300 days'),
  ('${TENANT_A}', 2, '{"rules":[{"keyword":"Project Falcon"}]}', now() - interval '3 days');
insert into public.tenant_runtime_policies values ('${TENANT_A}', 5,
  '{"command_default":"ask","mcp_unknown":"deny","url_default":"bogus","mcp_require_approval_servers":["a","b"],"mcp_deny_tools":[],"note":"tenant-b-secret"}', now());
insert into public.runtime_policy_revisions values ('${TENANT_A}', 5, '{}', now() - interval '1 day');
insert into public.team_policies (tenant_id, content) values ('${TENANT_A}', 'Project Falcon rules');
insert into public.tenant_identity_policies (tenant_id, require_mfa, required_saml_provider_id) values ('${TENANT_A}', true, gen_random_uuid());
insert into public.scim_tokens (tenant_id, last_used_at) values ('${TENANT_A}', now() - interval '1 hour');
insert into public.scim_tokens (tenant_id, revoked_at) values ('${TENANT_A}', now());
insert into public.scim_users (tenant_id, active) values ('${TENANT_A}', true), ('${TENANT_A}', false), ('${TENANT_B}', true);
insert into public.admin_audit_logs (tenant_id, action, detail) values
  ('${TENANT_A}', 'dlp_policy.save', '{"keyword":"Project Falcon"}'),
  ('${TENANT_A}', 'tenant.settings_updated', '{}'), ('${TENANT_B}', 'tenant.settings_updated', '{}');
insert into public.posture_findings (tenant_id, source, finding_kind, severity, cvss, vuln_id, applicability) values
  ('${TENANT_A}', 'infra_scan', 'cve', 'critical', 9.8, 'CVE-2024-37032', 'confirmed');
insert into public.posture_findings (tenant_id, source, finding_kind, severity, mcp_server_name, mcp_transport, risk_categories, attestation_status) values
  ('${TENANT_A}', 'mcp_inventory', 'mcp_server', 'high', 'shell-runner', 'stdio', '{shell_wrapper_command,mcp-05}', 'unverifiable'),
  ('${TENANT_B}', 'mcp_inventory', 'mcp_server', 'high', 'tenant-b-secret', 'remote', '{}', 'approved');
insert into public.posture_findings (tenant_id, source, finding_kind, severity, skill_risk_type) values
  ('${TENANT_A}', 'skill_scan', 'skill_rule', 'medium', 'T03');
insert into public.tenant_data_retention_policies (tenant_id, data_class, retention_days) values
  ('${TENANT_A}', 'telemetry', 90), ('${TENANT_A}', 'security_audit', 365);
insert into public.tenant_legal_holds (tenant_id, hold_reference, reason) values ('${TENANT_A}', 'LIT-2026-7', 'Litigation LIT-2026-7');
insert into public.audit_export_objects values
  ('${TENANT_A}/a.json', '${TENANT_A}', now() - interval '2 days', now() - interval '1 day'),
  ('${TENANT_A}/b.json', '${TENANT_A}', now(), now() + interval '1 day');
`;

const PERIOD = "now() - interval '90 days', now()";
const evidence = (actor, period = PERIOD, tenant = TENANT_A) =>
	`select public.compliance_report_evidence('${tenant}', '${actor}', ${period});`;

test("compliance report evidence: tenant scope, authorization, bounds and content minimisation", { timeout: 180_000 }, async (t) => {
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
		sql(migration);
		sql(migration); // idempotent re-apply
		sql(SEED);

		const report = JSON.parse(sql(evidence(OWNER_A)));
		assert.equal(report.actor_role, "owner");
		assert.equal(report.tenant_profile.tenant_id, TENANT_A);
		assert.equal(report.tenant_profile.region, "eu-central-1");

		// Coverage: runtime slugs only; unknown runtimes are grouped, other tenants excluded.
		const runtimes = Object.fromEntries(report.protection_coverage.by_runtime.map((row) => [row.runtime, row]));
		assert.deepEqual(Object.keys(runtimes).sort(), ["browser_guard", "claude-code", "unknown"]);
		assert.equal(runtimes.browser_guard.enrolled, 2);
		assert.equal(runtimes.browser_guard.active_in_period, 1);
		assert.equal(report.protection_coverage.totals.enrolled, 4);
		assert.equal(report.protection_coverage.totals.browser_installs_active_in_period, 1);

		// Browser Guard: only in-period tenant-A scans; malformed keys and sites are neutralised.
		assert.deepEqual(report.browser_guard.totals, { scans: 3, masked: 1, warned: 1, blocked: 1, allowed: 0 });
		const entities = Object.fromEntries(report.browser_guard.by_entity_type.map((row) => [row.entity_type, row]));
		assert.deepEqual(Object.keys(entities).sort(), ["EMAIL", "SECRET", "TC_KIMLIK"]);
		assert.equal(entities.EMAIL.items, 2);
		assert.equal(entities.EMAIL.masked_items, 2);
		assert.equal(entities.SECRET.blocked_items, 1);
		assert.deepEqual(report.browser_guard.by_site.map((row) => row.site).sort(), ["chatgpt", "gemini", "other"]);
		assert.deepEqual(report.browser_guard.managed_policy_ids.map((row) => row.policy_id), ["acme-policy-v3"]);

		// Agent decisions and the DLP subset.
		assert.deepEqual(report.agent_decisions.totals, { decisions: 4, allow: 2, ask: 1, deny: 1 });
		assert.deepEqual(report.agent_decisions.data_protection, { decisions: 2, allow: 1, ask: 0, deny: 1 });
		assert.ok(report.agent_decisions.by_source.some((row) => row.source === "unspecified"));

		// Policies: versions, digests and counts; never bodies.
		assert.equal(report.policy_inventory.dlp.current.version, 2);
		assert.equal(report.policy_inventory.dlp.current.rules, 2);
		assert.match(report.policy_inventory.dlp.current.sha256, /^[a-f0-9]{64}$/);
		assert.deepEqual(report.policy_inventory.dlp.revisions_in_period.map((row) => row.version), [2]);
		assert.equal(report.policy_inventory.dlp.revisions_total, 2);
		assert.deepEqual(report.policy_inventory.runtime.current.actions, { command_default: "ask", mcp_unknown: "deny" });
		assert.deepEqual(report.policy_inventory.runtime.current.list_sizes, { mcp_deny_tools: 0, mcp_require_approval_servers: 2 });
		assert.match(report.policy_inventory.team_policy.sha256, /^[a-f0-9]{64}$/);

		// Access: owner/admin only, with MFA state; members are counted, not listed.
		assert.deepEqual(report.access_identity.identity_policy.require_mfa, true);
		assert.equal(report.access_identity.identity_policy.sso_required, true);
		assert.deepEqual(report.access_identity.scim, {
			active_tokens: 1, last_token_use_at: report.access_identity.scim.last_token_use_at,
			provisioned_users_active: 1, group_role_mappings: 0,
		});
		assert.deepEqual(
			report.access_identity.admins.map((row) => [row.role, row.email, row.mfa_verified]),
			[["owner", "owner@acme.example", true], ["admin", "admin@acme.example", false]],
		);
		assert.deepEqual(report.access_identity.admin_activity.map((row) => row.action).sort(), ["dlp_policy.save", "tenant.settings_updated"]);

		// Incidents and posture.
		assert.equal(report.incidents.incidents.total, 2);
		assert.deepEqual(report.incidents.incidents.by_severity, { high: 1, unknown: 1 });
		assert.equal(report.incidents.plugin_scans_with_findings, 1);
		assert.equal(report.ai_security_posture.cve.max_cvss, 9.8);
		assert.deepEqual(report.ai_security_posture.mcp.by_risk_category, { "mcp-05": 1, shell_wrapper_command: 1 });
		assert.deepEqual(report.ai_security_posture.skills.by_risk_type, { T03: 1 });

		// Retention and deletion evidence.
		assert.equal(report.retention_deletion.telemetry.retention_days, 90);
		assert.equal(report.retention_deletion.telemetry.within_policy, false, "a 200-day-old event exceeds a 90-day window");
		assert.equal(report.retention_deletion.legal_holds.active, true);
		assert.deepEqual(report.retention_deletion.audit_exports, { created_in_period: 2, stored_now: 2, expired_pending_cleanup: 1 });

		// No raw content and nothing from tenant B.
		const text = JSON.stringify(report);
		for (const needle of [...SECRET_TEXT, "Other Corp", "owner@other.example", "Finance laptop", "keyword"]) {
			assert.equal(text.includes(needle), false, `report leaked ${needle}`);
		}

		// The Edge Function's schema projection accepts the real SQL output unchanged.
		const shared = await import(pathToFileURL(resolve(root, "supabase/functions/_shared/compliance-report.ts")).href);
		const body = shared.buildComplianceReportBody({
			evidence: report,
			reportId: randomUUID(),
			actorUserId: OWNER_A,
			from: new Date(Date.now() - 90 * 86_400_000),
			to: new Date(),
		});
		assert.equal(body.sections.tenant_profile.tenant_id, TENANT_A);

		// Tenant B's invalid region is dropped, not echoed.
		assert.equal(JSON.parse(sql(evidence(OWNER_B, PERIOD, TENANT_B))).tenant_profile.region, null);

		// Authorization: admins yes; members, other tenants' owners and expired admins no.
		assert.equal(JSON.parse(sql(evidence(ADMIN_A))).actor_role, "admin");
		for (const actor of [MEMBER_A, OWNER_B, randomUUID()]) {
			assert.match(sqlFails(evidence(actor)), /compliance_report_forbidden/);
		}
		sql(`update public.tenant_members set expires_at = now() - interval '1 minute' where user_id = '${ADMIN_A}';`);
		assert.match(sqlFails(evidence(ADMIN_A)), /compliance_report_forbidden/);
		sql(`update public.tenants set status = 'suspended' where id = '${TENANT_A}';`);
		assert.match(sqlFails(evidence(OWNER_A)), /compliance_report_forbidden/);
		sql(`update public.tenants set status = 'active' where id = '${TENANT_A}';`);

		// Period bounds mirror the Edge Function.
		for (const period of [
			"now() - interval '367 days', now()",
			"now(), now() - interval '1 day'",
			"now() - interval '1 day', now() + interval '1 hour'",
			"timestamptz '2019-06-01', timestamptz '2019-12-31'",
			"null, now()",
		]) {
			assert.match(sqlFails(evidence(OWNER_A, period)), /invalid_compliance_period/);
		}
		assert.equal(JSON.parse(sql(evidence(OWNER_A, "now() - interval '366 days', now()"))).actor_role, "owner");

		// Receipt: appended for admins only, validated.
		const receipt = (actor, sha = "a".repeat(64), key = "'compliance-2026-09'") =>
			`select public.record_compliance_report('${TENANT_A}', '${actor}', '${randomUUID()}', ${PERIOD}, '${sha}', ${key});`;
		sql(receipt(OWNER_A));
		sql(receipt(OWNER_A, "b".repeat(64), "null"));
		assert.equal(
			sql(`select string_agg((detail->>'signed') || ':' || coalesce(detail->>'signature_key_id', '-'), ',' order by id)
				from public.admin_audit_logs where action = 'compliance_report.generated' and tenant_id = '${TENANT_A}' and actor_user_id = '${OWNER_A}';`),
			"true:compliance-2026-09,false:-",
		);
		assert.match(sqlFails(receipt(MEMBER_A)), /compliance_report_forbidden/);
		assert.match(sqlFails(receipt(OWNER_A, "not-a-digest")), /invalid_compliance_receipt/);
		assert.match(sqlFails(receipt(OWNER_A, "a".repeat(64), "'bad key id'")), /invalid_compliance_receipt/);

		// Only the service role may execute either function.
		for (const signature of [
			"public.compliance_report_evidence(uuid, uuid, timestamptz, timestamptz)",
			"public.record_compliance_report(uuid, uuid, uuid, timestamptz, timestamptz, text, text)",
		]) {
			for (const [role, expected] of [["anon", "f"], ["authenticated", "f"], ["service_role", "t"]]) {
				assert.equal(sql(`select has_function_privilege('${role}', '${signature}', 'EXECUTE');`), expected, `${role} ${signature}`);
			}
		}
	} finally {
		database.stop();
	}
});
