// Real-PostgreSQL contract for the AI governance migrations:
//   supabase/migrations/20260927000040_ai_governance_register.sql
//   supabase/migrations/20260927000041_policy_change_control.sql
//   supabase/migrations/20260927000042_ai_governance_retention_offboarding.sql
//
// Runs against either
//   AIDR_POSTGRES_TEST_URL=postgres://user@host:port/db  (a disposable database
//     is created next to it and dropped afterwards), or
//   an isolated `supabase/postgres` container (docker, no network),
// and is skipped, visibly, when neither is available.
//
// The fixture is the smallest schema the migrations touch, shaped like the
// canonical tables; the publication functions are reduced to what the
// four-eyes guard observes (they write a revision row).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const migrations = [
	"20260927000040_ai_governance_register.sql",
	"20260927000041_policy_change_control.sql",
	"20260927000042_ai_governance_retention_offboarding.sql",
].map((name) => readFileSync(resolve(root, "supabase/migrations", name), "utf8"));

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
		const database = `aidr_governance_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
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
	const container = `aidr-governance-${randomUUID().slice(0, 8)}`;
	const started = run("docker", ["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=governance-fixture-only", "supabase/postgres:17.6.1.136"]);
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
create table public.agents (
  id uuid primary key, tenant_id uuid not null, agent_runtime text,
  first_seen timestamptz default now(), last_seen timestamptz default now()
);
create table public.events (
  id bigint generated always as identity primary key, tenant_id uuid not null, type text not null,
  created_at timestamptz not null default now(), payload jsonb not null default '{}'::jsonb
);
create table public.posture_findings (
  id bigint generated always as identity primary key, tenant_id uuid not null, source text not null,
  severity text not null, vuln_id text, mcp_server_name text, rule_id text, component text,
  observed_at timestamptz not null default now()
);
create table public.approval_requests (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, tool text not null,
  status text not null, created_at timestamptz not null default now()
);
create table public.tenant_discovery_items (
  tenant_id uuid not null, target text not null,
  first_reported_at timestamptz not null default now(), last_reported_at timestamptz not null default now()
);
create table public.admin_audit_logs (
  id bigint generated always as identity primary key, actor_user_id uuid, tenant_id uuid,
  action text not null, detail jsonb not null default '{}'::jsonb
);
create table public.audit_logs (
  id uuid primary key default gen_random_uuid(), team_id uuid not null references public.teams(id),
  tenant_id uuid not null, user_id uuid, action text not null, verdict jsonb
);
create table public.tenant_runtime_policies (tenant_id uuid primary key, version bigint not null, policy jsonb not null,
  updated_by uuid not null, updated_at timestamptz not null default now());
create table public.runtime_policy_revisions (tenant_id uuid not null, version bigint not null, policy jsonb not null,
  updated_by uuid not null, created_at timestamptz not null default now(), primary key (tenant_id, version));
create table public.tenant_dlp_policies (tenant_id uuid primary key, version bigint not null, policy jsonb not null,
  updated_by uuid not null, updated_at timestamptz not null default now());
create table public.dlp_policy_revisions (tenant_id uuid not null, version bigint not null, policy jsonb not null,
  updated_by uuid not null, created_at timestamptz not null default now(), primary key (tenant_id, version));
create table public.tenant_offboarding_runs (
  id uuid primary key, tenant_id uuid not null, requested_by uuid not null, status text not null
);
create table public.tenant_offboarding_phase_receipts (
  run_id uuid not null, phase text not null, status text not null, eligible_at timestamptz not null,
  rows_deleted bigint not null default 0, completed_at timestamptz, primary key (run_id, phase)
);
create table public.tenant_legal_holds (tenant_id uuid not null, released_at timestamptz);
create table public.tenant_data_retention_policies (
  tenant_id uuid not null, data_class text not null, retention_days integer not null
);
create table public.identity_barrier_denied (tenant_id uuid primary key);
create function app.is_tenant_member(p_tenant uuid) returns boolean
  language sql stable security definer set search_path = public as
  'select exists (select 1 from public.tenant_members where tenant_id = p_tenant and user_id = auth.uid())';
create function public.tenant_identity_access_allowed(p_tenant uuid) returns boolean
  language sql stable security definer set search_path = public as
  'select not exists (select 1 from public.identity_barrier_denied where tenant_id = p_tenant)';
-- Canonical key-sorted JSON (20260916000000_policy_rollout_rings.sql).
create function app.policy_rollout_canonical_json(value jsonb) returns text
language sql immutable strict set search_path = public, pg_temp as $$
  select case jsonb_typeof(value)
    when 'object' then '{' || coalesce((select string_agg(to_jsonb(key)::text || ':' || app.policy_rollout_canonical_json(val), ',' order by key collate "C") from jsonb_each(value) e(key, val)), '') || '}'
    when 'array' then '[' || coalesce((select string_agg(app.policy_rollout_canonical_json(val), ',' order by ord) from jsonb_array_elements(value) with ordinality e(val, ord)), '') || ']'
    else value::text end;
$$;
-- Publication paths reduced to the owner/admin check, CAS and the revision write.
create function public.publish_runtime_policy(p_tenant_id uuid, p_user_id uuid, p_expected_version bigint, p_policy jsonb)
returns public.tenant_runtime_policies language plpgsql security definer set search_path = public, pg_temp as $$
declare result public.tenant_runtime_policies; current_version bigint;
begin
  if not exists (select 1 from public.tenant_members m where m.tenant_id = p_tenant_id and m.user_id = p_user_id
      and m.role in ('owner', 'admin')) then raise exception 'policy_forbidden' using errcode = '42501'; end if;
  select version into current_version from public.tenant_runtime_policies where tenant_id = p_tenant_id;
  if coalesce(current_version, 0) <> p_expected_version then raise exception 'policy_version_conflict' using errcode = '40001'; end if;
  insert into public.runtime_policy_revisions(tenant_id, version, policy, updated_by)
    values (p_tenant_id, p_expected_version + 1, p_policy, p_user_id);
  insert into public.tenant_runtime_policies(tenant_id, version, policy, updated_by)
    values (p_tenant_id, p_expected_version + 1, p_policy, p_user_id)
    on conflict (tenant_id) do update set version = excluded.version, policy = excluded.policy
    returning * into result;
  return result;
end $$;
create function public.publish_dlp_policy(p_tenant_id uuid, p_user_id uuid, p_expected_version bigint, p_policy jsonb)
returns public.tenant_dlp_policies language plpgsql security definer set search_path = public, pg_temp as $$
declare result public.tenant_dlp_policies; current_version bigint;
begin
  if not exists (select 1 from public.tenant_members m where m.tenant_id = p_tenant_id and m.user_id = p_user_id
      and m.role in ('owner', 'admin')) then raise exception 'policy_forbidden' using errcode = '42501'; end if;
  select version into current_version from public.tenant_dlp_policies where tenant_id = p_tenant_id;
  if coalesce(current_version, 0) <> p_expected_version then raise exception 'policy_version_conflict' using errcode = 'PT409'; end if;
  insert into public.dlp_policy_revisions(tenant_id, version, policy, updated_by)
    values (p_tenant_id, p_expected_version + 1, p_policy, p_user_id);
  insert into public.tenant_dlp_policies(tenant_id, version, policy, updated_by)
    values (p_tenant_id, p_expected_version + 1, p_policy, p_user_id)
    on conflict (tenant_id) do update set version = excluded.version, policy = excluded.policy
    returning * into result;
  return result;
end $$;
grant usage on schema app, public, auth to authenticated, service_role;
grant execute on function app.is_tenant_member(uuid) to authenticated;
grant execute on function public.tenant_identity_access_allowed(uuid) to authenticated;
grant execute on function auth.uid() to authenticated;
`;

const TENANT_A = "11111111-1111-4111-8111-111111111111";
const TENANT_B = "22222222-2222-4222-8222-222222222222";
const TENANT_SOLO = "33333333-3333-4333-8333-333333333333";
const OWNER_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ADMIN_A = "a2a2a2a2-a2a2-4a2a-8a2a-a2a2a2a2a2a2";
const MEMBER_A = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const REVIEWER_A = "b2b2b2b2-b2b2-4b2b-8b2b-b2b2b2b2b2b2";
const VIEWER_A = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const OWNER_B = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const OWNER_SOLO = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const AGENT_A = "44444444-4444-4444-8444-444444444444";

const lit = (value) => (value === null ? "null" : `'${String(value).replaceAll("'", "''")}'`);
const js = (value) => `${lit(JSON.stringify(value))}::jsonb`;

test("AI governance: register, intake, exceptions, four-eyes change control, retention and offboarding", { timeout: 180_000 }, async (t) => {
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
	const last = (output) => output.split("\n").at(-1);
	const upsert = (actor, assetId, version, fields, tenant = TENANT_A) =>
		`select public.upsert_ai_asset('${tenant}', '${actor}', ${lit(assetId)}, ${version ?? "null"}, ${js(fields)});`;
	const assetId = (identifier) => sql(`select id from public.ai_assets where identifier = '${identifier}';`);
	const overlay = (user, agent) => json(`select public.ai_governance_policy_overlay('${TENANT_A}', ${lit(user)}, ${lit(agent)});`);

	try {
		sql(FIXTURE);
		sql(`insert into public.tenants (id) values ('${TENANT_A}'), ('${TENANT_B}'), ('${TENANT_SOLO}');
			insert into public.teams (id) values ('${TENANT_A}'), ('${TENANT_B}'), ('${TENANT_SOLO}');
			insert into public.tenant_members values
			  ('${TENANT_A}', '${OWNER_A}', 'owner', null), ('${TENANT_A}', '${ADMIN_A}', 'admin', null),
			  ('${TENANT_A}', '${MEMBER_A}', 'member', null), ('${TENANT_A}', '${REVIEWER_A}', 'member', null),
			  ('${TENANT_A}', '${VIEWER_A}', 'viewer', null), ('${TENANT_B}', '${OWNER_B}', 'owner', null),
			  ('${TENANT_SOLO}', '${OWNER_SOLO}', 'owner', null);
			insert into public.agents (id, tenant_id, agent_runtime) values
			  ('${AGENT_A}', '${TENANT_A}', 'claude-code'), (gen_random_uuid(), '${TENANT_A}', 'browser_guard'),
			  (gen_random_uuid(), '${TENANT_B}', 'codex');
			insert into public.events (tenant_id, type, payload) values
			  ('${TENANT_A}', 'privacy_scan', '{"site":"deepseek","action":"masked"}'),
			  ('${TENANT_A}', 'privacy_scan', '{"site":"other","action":"masked"}'),
			  ('${TENANT_A}', 'incident', '{"severity":"high"}'),
			  ('${TENANT_B}', 'privacy_scan', '{"site":"grok","action":"masked"}');
			insert into public.posture_findings (tenant_id, source, severity, mcp_server_name) values
			  ('${TENANT_A}', 'mcp_inventory', 'high', 'shell-runner'), ('${TENANT_B}', 'mcp_inventory', 'high', 'tenant-b-only');
			insert into public.tenant_discovery_items (tenant_id, target) values ('${TENANT_A}', 'https://llm.internal:8443/');
			insert into public.tenant_data_retention_policies values
			  ('${TENANT_A}', 'security_audit', 365), ('${TENANT_B}', 'security_audit', 365);`);
		for (const migration of migrations) sql(migration);
		// Idempotent re-apply.
		for (const migration of migrations) sql(migration);

		// ── Grants and RLS ──────────────────────────────────────────────────
		for (const table of ["ai_assets", "ai_intake_requests", "ai_governance_exceptions", "policy_change_requests",
			"ai_asset_evidence", "ai_governance_reviewers", "tenant_ai_governance_settings"]) {
			assert.equal(sql(`select has_table_privilege('anon', 'public.${table}', 'SELECT');`), "f", table);
			assert.equal(sql(`select has_table_privilege('authenticated', 'public.${table}', 'INSERT');`), "f", table);
			assert.equal(sql(`select has_table_privilege('service_role', 'public.${table}', 'UPDATE');`), "f", table);
		}
		for (const fn of ["public.upsert_ai_asset(uuid,uuid,uuid,integer,jsonb)", "public.decide_policy_change_request(uuid,uuid,uuid,text,text)",
			"public.ai_governance_policy_overlay(uuid,uuid,uuid)", "public.run_ai_governance_maintenance(integer,boolean)"]) {
			assert.equal(sql(`select has_function_privilege('authenticated', '${fn}', 'EXECUTE');`), "f", fn);
			assert.equal(sql(`select has_function_privilege('service_role', '${fn}', 'EXECUTE');`), "t", fn);
		}

		// ── Register: import from observed data, roles, identity immutability ──
		assert.deepEqual(json(`select public.import_ai_asset_candidates('${TENANT_A}', '${OWNER_A}', 100);`), {
			created: 4, refreshed: 0, skipped: 0,
			created_by_source: { fleet: 1, posture: 1, browser_telemetry: 1, discovery: 1 },
		});
		assert.equal(sql(`select string_agg(asset_type || ':' || identifier, ',' order by asset_type, identifier) from public.ai_assets;`),
			"ai_site:deepseek,coding_agent:claude-code,mcp_server:shell-runner,model_service:llm.internal:8443");
		assert.equal(json(`select public.import_ai_asset_candidates('${TENANT_A}', '${OWNER_A}', 100);`).created, 0, "import is idempotent");
		fails(`select public.import_ai_asset_candidates('${TENANT_A}', '${MEMBER_A}', 100);`, /ai_governance_forbidden/);
		fails(upsert(MEMBER_A, null, null, { asset_type: "mcp_server", identifier: "x", name: "X" }), /ai_governance_forbidden/);
		fails(upsert(OWNER_B, null, null, { asset_type: "mcp_server", identifier: "x", name: "X" }), /ai_governance_forbidden/);
		fails(upsert(OWNER_A, null, null, { asset_type: "mcp_server", identifier: "bad@id", name: "X" }), /ai_assets_mcp_identifier/);
		fails(upsert(OWNER_A, null, null, { asset_type: "mcp_server", identifier: "x", name: "X", owner_user_id: OWNER_B }), /ai_asset_owner_not_member/);
		fails(upsert(OWNER_A, null, null, { asset_type: "mcp_server", identifier: "x", name: "X", created_by: OWNER_A }), /invalid_ai_governance_field/);
		fails(upsert(OWNER_A, null, null, { asset_type: "ai_site", identifier: "x", name: "X", risk_tier: "prohibited", status: "approved" }),
			/ai_assets_prohibited_status/);
		const shell = assetId("shell-runner");
		assert.equal(json(upsert(OWNER_A, shell, 1, { status: "banned", risk_tier: "high", data_categories: ["secrets", "source_code"] })).version, 2);
		fails(upsert(OWNER_A, shell, 1, { name: "stale" }), /ai_asset_version_conflict/);
		fails(`update public.ai_assets set identifier = 'renamed' where id = '${shell}';`, /ai_asset_identity_immutable/);
		sql(upsert(ADMIN_A, assetId("deepseek"), 1, { status: "banned" }));
		sql(upsert(ADMIN_A, null, null, { asset_type: "mcp_server", identifier: "github", name: "GitHub", status: "restricted" }));

		assert.equal(last(sql(as(VIEWER_A, "select count(*) from public.ai_assets;"))), "5");
		assert.equal(last(sql(as(OWNER_B, "select count(*) from public.ai_assets;"))), "0");
		fails(as(OWNER_A, `update public.ai_assets set status = 'approved';`), /permission denied/);
		sql(`insert into public.identity_barrier_denied values ('${TENANT_A}');`);
		assert.equal(last(sql(as(OWNER_A, "select count(*) from public.ai_assets;"))), "0", "identity barrier hides rows");
		sql(`delete from public.identity_barrier_denied;`);

		// ── Evidence ───────────────────────────────────────────────────────────
		const finding = sql(`select id from public.posture_findings where mcp_server_name = 'shell-runner';`);
		const foreignFinding = sql(`select id from public.posture_findings where mcp_server_name = 'tenant-b-only';`);
		assert.equal(json(`select public.link_ai_asset_evidence('${TENANT_A}', '${OWNER_A}', '${shell}', 'posture_finding', '${finding}', true);`).created, true);
		fails(`select public.link_ai_asset_evidence('${TENANT_A}', '${OWNER_A}', '${shell}', 'posture_finding', '${foreignFinding}', true);`,
			/ai_asset_evidence_source_not_found/);
		assert.equal(sql("select label from public.ai_asset_evidence;"), "mcp_inventory · high · shell-runner");

		// ── Enforcement feed ───────────────────────────────────────────────────
		assert.deepEqual(overlay(null, null), {
			mcp_deny_servers: ["shell-runner"], mcp_require_approval_servers: ["github"], browser_guard_blocked_sites: ["deepseek"],
		});

		// ── Exceptions: four-eyes, scope, expiry ──────────────────────────────
		const requested = json(`select public.request_ai_governance_exception('${TENANT_A}', '${MEMBER_A}', ${js({
			asset_id: shell, scope_kind: "members", scope_user_ids: [MEMBER_A], justification: "Migration week",
			expires_at: new Date(Date.now() + 5 * 86_400_000).toISOString(),
		})});`);
		fails(`select public.decide_ai_governance_exception('${TENANT_A}', '${MEMBER_A}', '${requested.exception_id}', 'approve', 'mine');`,
			/ai_governance_forbidden/);
		const selfRequested = json(`select public.request_ai_governance_exception('${TENANT_A}', '${ADMIN_A}', ${js({
			asset_id: shell, scope_kind: "tenant", justification: "Admin waiver",
			expires_at: new Date(Date.now() + 5 * 86_400_000).toISOString(),
		})});`);
		fails(`select public.decide_ai_governance_exception('${TENANT_A}', '${ADMIN_A}', '${selfRequested.exception_id}', 'approve', 'mine');`,
			/four_eyes_self_approval/);
		fails(`update public.ai_governance_exceptions set status = 'approved', decided_by = requested_by, decided_at = now(),
			decision_reason = 'x', starts_at = now() where id = '${selfRequested.exception_id}';`, /ai_governance_exceptions_four_eyes/);
		sql(`select public.cancel_ai_governance_request('${TENANT_A}', '${ADMIN_A}', 'exception', '${selfRequested.exception_id}');`);
		assert.equal(json(`select public.decide_ai_governance_exception('${TENANT_A}', '${ADMIN_A}', '${requested.exception_id}', 'approve', 'Five days');`).status, "approved");
		assert.deepEqual(overlay(MEMBER_A, null).mcp_deny_servers, [], "waived for the named member");
		assert.deepEqual(overlay(OWNER_A, AGENT_A).mcp_deny_servers, ["shell-runner"], "others stay blocked");
		// Move the window into the past: the overlay stops honouring it at once.
		sql(`update public.ai_governance_exceptions set created_at = now() - interval '3 days', starts_at = now() - interval '2 days',
			expires_at = now() - interval '1 minute' where id = '${requested.exception_id}';`);
		assert.deepEqual(overlay(MEMBER_A, null).mcp_deny_servers, ["shell-runner"], "expired exception stops applying without a sweep");
		const agentScoped = json(`select public.request_ai_governance_exception('${TENANT_A}', '${MEMBER_A}', ${js({
			asset_id: assetId("github"), scope_kind: "agents", scope_agent_ids: [AGENT_A], justification: "CI agent",
			expires_at: new Date(Date.now() + 2 * 86_400_000).toISOString(),
		})});`);
		sql(`select public.decide_ai_governance_exception('${TENANT_A}', '${OWNER_A}', '${agentScoped.exception_id}', 'approve', 'CI only');`);
		assert.deepEqual(overlay(MEMBER_A, AGENT_A).mcp_require_approval_servers, []);
		assert.deepEqual(overlay(MEMBER_A, null).mcp_require_approval_servers, ["github"]);

		// ── Intake: four-eyes and designated reviewers ────────────────────────
		const intake = json(`select public.submit_ai_intake_request('${TENANT_A}', '${MEMBER_A}', ${js({
			asset_type: "ai_site", identifier: "claude", name: "Claude", business_purpose: "Drafting docs", data_categories: ["customer_data"],
		})});`);
		fails(`select public.submit_ai_intake_request('${TENANT_A}', '${VIEWER_A}', ${js({
			asset_type: "ai_site", identifier: "gemini", name: "Gemini", business_purpose: "x" })});`, /ai_governance_forbidden/);
		fails(`select public.submit_ai_intake_request('${TENANT_A}', '${OWNER_A}', ${js({
			asset_type: "ai_site", identifier: "claude", name: "Claude", business_purpose: "dup" })});`, /ai_intake_request_pending/);
		fails(`select public.decide_ai_intake_request('${TENANT_A}', '${MEMBER_A}', '${intake.request_id}', 'approve', 'mine');`, /ai_governance_forbidden/);
		fails(`select public.set_ai_governance_reviewer('${TENANT_A}', '${OWNER_A}', '${VIEWER_A}', true);`, /ai_governance_reviewer_not_member/);
		sql(`select public.set_ai_governance_reviewer('${TENANT_A}', '${OWNER_A}', '${REVIEWER_A}', true);`);
		sql(`select public.set_ai_governance_reviewer('${TENANT_A}', '${OWNER_A}', '${MEMBER_A}', true);`);
		fails(`select public.decide_ai_intake_request('${TENANT_A}', '${MEMBER_A}', '${intake.request_id}', 'approve', 'mine');`, /four_eyes_self_approval/);
		assert.equal(json(`select public.decide_ai_intake_request('${TENANT_A}', '${REVIEWER_A}', '${intake.request_id}', 'approve', 'Fine for docs');`).status, "approved");
		assert.equal(sql(`select status || ':' || (owner_user_id = '${MEMBER_A}') from public.ai_assets where identifier = 'claude';`), "approved:true");
		// A reviewer may not lift an enforced ban.
		const lift = json(`select public.submit_ai_intake_request('${TENANT_A}', '${MEMBER_A}', ${js({ asset_id: assetId("deepseek"), business_purpose: "Research" })});`);
		fails(`select public.decide_ai_intake_request('${TENANT_A}', '${REVIEWER_A}', '${lift.request_id}', 'approve', 'ok');`, /governance_reviewer_scope/);
		sql(`select public.decide_ai_intake_request('${TENANT_A}', '${OWNER_A}', '${lift.request_id}', 'reject', 'Not allowed');`);
		assert.equal(json(`select public.review_ai_asset('${TENANT_A}', '${REVIEWER_A}', '${shell}', null);`).asset_id, shell);
		fails(`select public.review_ai_asset('${TENANT_A}', '${VIEWER_A}', '${shell}', null);`, /ai_governance_forbidden/);

		// ── Four-eyes policy change control ───────────────────────────────────
		fails(`select public.update_ai_governance_settings('${TENANT_SOLO}', '${OWNER_SOLO}', true, null);`, /four_eyes_requires_two_approvers/);
		sql(`select public.publish_runtime_policy('${TENANT_A}', '${OWNER_A}', 0, '{"command_default":"ask"}');`);
		sql(`select public.update_ai_governance_settings('${TENANT_A}', '${OWNER_A}', true, 90);`);
		fails(`select public.publish_runtime_policy('${TENANT_A}', '${OWNER_A}', 1, '{"command_default":"deny"}');`, /policy_four_eyes_required/);
		fails(`select public.publish_dlp_policy('${TENANT_A}', '${OWNER_A}', 0, '{"tenantId":"${TENANT_A}","version":"1"}');`, /policy_four_eyes_required/);
		sql(`select public.publish_runtime_policy('${TENANT_B}', '${OWNER_B}', 0, '{"command_default":"ask"}');`); // other tenants unaffected
		fails(upsert(OWNER_A, assetId("deepseek"), 2, { status: "approved" }), /governance_four_eyes_required/);
		sql(upsert(OWNER_A, assetId("claude"), 1, { status: "restricted" })); // tightening stays immediate

		const change = json(`select public.submit_policy_change_request('${TENANT_A}', '${OWNER_A}', 'runtime_publish', 1, null, null, '{"policy":{"command_default":"deny"}}');`);
		fails(`select public.submit_policy_change_request('${TENANT_A}', '${MEMBER_A}', 'runtime_publish', 1, null, null, '{"policy":{}}');`, /policy_forbidden/);
		fails(`select public.submit_policy_change_request('${TENANT_A}', '${OWNER_A}', 'runtime_publish', 1, null, null, '{"policy":{},"extra":1}');`, /invalid_policy_change_request/);
		fails(as(OWNER_A, "select payload from public.policy_change_requests;"), /permission denied/);
		assert.equal(last(sql(as(MEMBER_A, "select count(*) from public.policy_change_requests;"))), "1");
		fails(`select public.decide_policy_change_request('${TENANT_A}', '${OWNER_A}', '${change.request_id}', 'approve', 'mine');`, /four_eyes_self_approval/);
		fails(`select public.decide_policy_change_request('${TENANT_A}', '${MEMBER_A}', '${change.request_id}', 'approve', 'x');`, /policy_forbidden/);
		assert.deepEqual(json(`select public.decide_policy_change_request('${TENANT_A}', '${ADMIN_A}', '${change.request_id}', 'approve', 'Diff reviewed');`), {
			outcome: "decided", request_id: change.request_id, status: "approved", change_kind: "runtime_publish", applied_version: 2,
		});
		assert.equal(sql(`select version || ':' || (policy->>'command_default') || ':' || (updated_by = '${OWNER_A}') from public.tenant_runtime_policies where tenant_id = '${TENANT_A}';`),
			"2:deny:true", "published with the author as publisher");
		fails(`update public.policy_change_requests set status = 'rejected' where id = '${change.request_id}';`, /policy_change_request_already_final/);
		const stale = json(`select public.submit_policy_change_request('${TENANT_A}', '${ADMIN_A}', 'runtime_publish', 1, null, null, '{"policy":{"command_default":"allow"}}');`);
		assert.equal(json(`select public.decide_policy_change_request('${TENANT_A}', '${OWNER_A}', '${stale.request_id}', 'approve', 'ok');`).outcome, "superseded");
		assert.equal(sql(`select version from public.tenant_runtime_policies where tenant_id = '${TENANT_A}';`), "2", "a stale change applies nothing");
		const dlp = json(`select public.submit_policy_change_request('${TENANT_A}', '${ADMIN_A}', 'dlp_publish', 0, null, null, '{"policy":{"tenantId":"${TENANT_A}","version":"1","labels":[],"rules":[],"exceptions":[]}}');`);
		assert.equal(json(`select public.decide_policy_change_request('${TENANT_A}', '${OWNER_A}', '${dlp.request_id}', 'approve', 'DLP ok');`).applied_version, 1);
		const disable = json(`select public.update_ai_governance_settings('${TENANT_A}', '${OWNER_A}', false, null);`);
		assert.equal(disable.policy_four_eyes, true, "turning four-eyes off needs a second approver");
		fails(`select public.decide_policy_change_request('${TENANT_A}', '${OWNER_A}', '${disable.pending_disable_request_id}', 'approve', 'mine');`, /four_eyes_self_approval/);
		sql(`select public.decide_policy_change_request('${TENANT_A}', '${ADMIN_A}', '${disable.pending_disable_request_id}', 'approve', 'Agreed');`);
		assert.equal(sql(`select policy_four_eyes from public.tenant_ai_governance_settings where tenant_id = '${TENANT_A}';`), "f");
		sql(`select public.publish_runtime_policy('${TENANT_A}', '${OWNER_A}', 2, '{"command_default":"ask"}');`);
		const actions = sql(`select string_agg(distinct action, ',' order by action) from public.admin_audit_logs where tenant_id = '${TENANT_A}';`);
		for (const action of ["ai_asset.created", "ai_asset.status_changed", "ai_exception.approved", "ai_intake.approved",
			"policy_change.approved", "policy_change.superseded", "ai_governance.settings_updated"]) assert.ok(actions.includes(action), action);
		assert.ok(Number(sql(`select count(*) from public.audit_logs where tenant_id = '${TENANT_A}';`)) > 10, "team audit rows written");

		// ── Maintenance: expiry sweep and retention with legal hold ───────────
		sql(`update public.ai_intake_requests set created_at = now() - interval '2 days', expires_at = now() - interval '1 day'
			where status = 'pending';`);
		const pendingIntake = json(`select public.submit_ai_intake_request('${TENANT_A}', '${MEMBER_A}', ${js({
			asset_type: "mcp_server", identifier: "jira", name: "Jira", business_purpose: "Tickets" })});`);
		sql(`update public.ai_intake_requests set created_at = now() - interval '2 days', expires_at = now() - interval '1 day' where id = '${pendingIntake.request_id}';`);
		const dry = json("select public.run_ai_governance_maintenance(100, false);");
		assert.equal(dry.expired, 2, "lapsed intake and the past-window exception");
		assert.equal(json("select public.run_ai_governance_maintenance(100, true);").expired, 2);
		assert.equal(sql(`select status from public.ai_intake_requests where id = '${pendingIntake.request_id}';`), "expired");
		assert.equal(sql(`select status from public.ai_governance_exceptions where id = '${requested.exception_id}';`), "expired");
		sql(`update public.ai_intake_requests set closed_at = now() - interval '400 days', created_at = now() - interval '401 days',
			expires_at = now() - interval '400 days', decided_at = case when decided_at is null then null else now() - interval '400 days' end
			where tenant_id = '${TENANT_A}';`);
		sql(`insert into public.tenant_legal_holds values ('${TENANT_A}', null);`);
		const held = json("select public.run_ai_governance_maintenance(100, true);");
		assert.equal(held.deleted, 0);
		assert.equal(held.held_tenants_present, 1);
		sql("update public.tenant_legal_holds set released_at = now();");
		const pruned = json("select public.run_ai_governance_maintenance(100, true);");
		assert.equal(pruned.deleted, 3, "closed intake decisions older than security_audit retention");
		assert.equal(sql(`select count(*) from public.ai_intake_requests where tenant_id = '${TENANT_A}';`), "0");
		assert.equal(sql("select count(*) from public.ai_assets;"), "6", "register entries are configuration, never pruned");

		// ── Offboarding ───────────────────────────────────────────────────────
		const openException = json(`select public.request_ai_governance_exception('${TENANT_A}', '${MEMBER_A}', ${js({
			asset_id: shell, scope_kind: "tenant", justification: "Pending at closure",
			expires_at: new Date(Date.now() + 5 * 86_400_000).toISOString() })});`);
		const run = randomUUID();
		sql(`insert into public.tenant_offboarding_runs values ('${run}', '${TENANT_A}', '${OWNER_A}', 'requested');`);
		assert.equal(sql(`select status from public.ai_governance_exceptions where id = '${openException.exception_id}';`), "cancelled");
		assert.equal(sql(`select status from public.ai_governance_exceptions where id = '${agentScoped.exception_id}';`), "revoked");
		assert.deepEqual(overlay(MEMBER_A, AGENT_A).mcp_require_approval_servers, ["github"], "revoked at request time");
		fails(`update public.tenant_offboarding_runs set status = 'completed' where id = '${run}';`, /ai_governance_offboarding_residue/);
		sql(`update public.tenant_offboarding_runs set status = 'running' where id = '${run}';
			insert into public.tenant_offboarding_phase_receipts (run_id, phase, status, eligible_at)
			values ('${run}', 'tenant_runtime_policies', 'running', now() - interval '1 minute');
			update public.tenant_offboarding_phase_receipts set status = 'completed', completed_at = now() where run_id = '${run}';`);
		for (const table of ["ai_assets", "ai_asset_evidence", "ai_intake_requests", "ai_governance_exceptions",
			"policy_change_requests", "ai_governance_reviewers", "tenant_ai_governance_settings"]) {
			assert.equal(sql(`select count(*) from public.${table} where tenant_id = '${TENANT_A}';`), "0", table);
		}
		assert.ok(Number(sql(`select rows_deleted from public.tenant_offboarding_phase_receipts where run_id = '${run}';`)) > 0);
		sql(`update public.tenant_offboarding_runs set status = 'completed' where id = '${run}';
			update public.tenants set status = 'closed' where id = '${TENANT_A}';`);
		assert.equal(sql(`select count(*) from public.runtime_policy_revisions where tenant_id = '${TENANT_B}';`), "1", "other tenant untouched");
	} finally {
		database.stop();
	}
});
