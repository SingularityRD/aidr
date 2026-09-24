import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const migration = await readFile(
	new URL("../supabase/migrations/20260922000005_rls_audit_owner_hardening.sql", import.meta.url),
	"utf8",
);
const revocationMigration = await readFile(
	new URL(
		"../supabase/migrations/20260922000001_tenant_owner_and_device_revocation_hardening.sql",
		import.meta.url,
	),
	"utf8",
);
const atomicDeviceMigration = await readFile(
	new URL("../supabase/migrations/20260923000013_device_authorization_atomic_audit.sql", import.meta.url),
	"utf8",
);

function functionBody(name, sql = migration) {
	const match = sql.match(
		new RegExp(`create or replace function ${name.replaceAll(".", "\\.")}\\([^]*?\\n\\$\\$;`, "i"),
	);
	assert.ok(match, `missing function ${name}`);
	return match[0];
}

test("device bind shares the revocation lock and checks the verified JWT issuance time before mutation", () => {
	const body = functionBody("public.authorize_device_session");
	assert.match(migration, /drop function if exists public\.authorize_device_session\(text, uuid, uuid\)/i);
	assert.match(
		migration,
		/create or replace function public\.authorize_device_session\([\s\S]*p_access_token_issued_at timestamptz/i,
	);
	assert.match(
		migration,
		/revoke all on function public\.authorize_device_session\(text, uuid, uuid, timestamptz\)[\s\S]*from public, anon, authenticated;[\s\S]*grant execute[\s\S]*to service_role;/i,
	);
	const lock = body.indexOf("pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611))");
	const barrier = body.indexOf("p_access_token_issued_at <= v_revoked_before");
	const bind = body.indexOf("update public.device_sessions");
	assert.ok(lock >= 0 && barrier > lock && bind > barrier);
});

test("device authorization and revocation share a deterministic per-user linearization point", () => {
	const revoke = functionBody("public.mark_identity_session_revoked", revocationMigration);
	const lock = revoke.indexOf("pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611))");
	const barrier = revoke.indexOf("v_barrier := clock_timestamp()");
	const publish = revoke.indexOf("insert into public.identity_user_session_state");
	assert.ok(lock >= 0 && barrier > lock && publish > barrier);
});

test("device binding and its audit receipt commit in the same RPC transaction", () => {
	const body = functionBody("public.authorize_device_session", atomicDeviceMigration);
	const lock = body.indexOf("pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611))");
	const bind = body.indexOf("update public.device_sessions");
	const audit = body.indexOf("insert into public.admin_audit_logs");
	const result = body.indexOf("return next;");
	assert.ok(lock >= 0 && bind > lock && audit > bind && result > audit);
	assert.match(body, /if not found then return; end if;/i);
	assert.match(body, /jsonb_build_object\('device_session_id', id\)/i);
	assert.doesNotMatch(body, /'user_code'/i);
	assert.match(atomicDeviceMigration, /revoke all on function public\.authorize_device_session\(text, uuid, uuid, timestamptz\)[\s\S]*grant execute[\s\S]*to service_role;/i);
});

test("active tenants retain an owner even for trusted cascades", () => {
	const body = functionBody("app.preserve_active_tenant_owner");
	const activation = functionBody("app.require_owner_for_active_tenant");
	assert.match(body, /pg_advisory_xact_lock\(hashtextextended\(v_old_tenant_id::text, 2612\)\)/i);
	assert.match(body, /v_old_tenant_id < v_new_tenant_id[\s\S]*v_new_tenant_id::text, 2612/i);
	assert.match(body, /t\.status = 'active'/i);
	assert.match(body, /m\.user_id <> v_old_user_id[\s\S]*m\.role = 'owner'/i);
	assert.doesNotMatch(body, /current_user/i);
	assert.match(activation, /new\.status = 'active' and old\.status is distinct from 'active'/i);
	assert.match(activation, /hashtextextended\(new\.id::text, 2612\)/i);
	assert.match(activation, /member\.role = 'owner'/i);
	assert.match(migration, /before update or delete on public\.team_members/i);
	assert.match(migration, /before update or delete on public\.tenant_members/i);
	assert.match(migration, /before update of status on public\.tenants/i);
});

test("only the unambiguous legacy creator-admin shape is promoted and ambiguity aborts", () => {
	assert.match(migration, /tm\.user_id = tenant\.created_by/i);
	assert.match(migration, /tm\.role = 'admin'/i);
	assert.match(migration, /canonical\.role = 'admin'/i);
	assert.match(migration, /action, detail[\s\S]*'tenant\.owner\.reconciled'/i);
	assert.match(migration, /raise exception 'team_owner_reconciliation_ambiguous'/i);
});

test("unentitled historical paid labels fail the upgrade", () => {
	assert.match(migration, /team\.plan in \('pro', 'enterprise'\)/i);
	assert.match(migration, /entitlement\.included_agents > 1/i);
	assert.match(migration, /entitlement\.extra_agents > 0/i);
	assert.match(migration, /raise exception 'unentitled_paid_team_plan_requires_reconciliation'/i);
});

test("audit provenance distinguishes the pre-boundary rows", () => {
	assert.match(migration, /add column write_provenance text not null default 'pre_boundary_unverified'/i);
	assert.match(migration, /alter column write_provenance set default 'service_boundary_v1'/i);
});

test("audit mutation guards use caller identity and permit only nested FK anonymization", () => {
	const audit = functionBody("public.reject_audit_mutation");
	const admin = functionBody("app.reject_admin_audit_mutation");
	assert.doesNotMatch(audit, /current_user/i);
	assert.doesNotMatch(admin, /current_user/i);
	assert.match(audit, /pg_trigger_depth\(\) > 1/i);
	assert.match(audit, /old\.user_id is not null[\s\S]*new\.user_id is null/i);
	assert.match(audit, /to_jsonb\(new\) - 'user_id'/i);
	assert.match(audit, /session_user in \('postgres', 'supabase_admin', 'supabase_auth_admin'\)/i);
	assert.match(admin, /receipt\.phase = 'admin_audit_logs'[\s\S]*receipt\.status = 'running'/i);
});

test("audit tables deny direct mutation and statement-level truncation", () => {
	assert.match(
		migration,
		/revoke update, delete, truncate on public\.audit_logs, public\.admin_audit_logs[\s\S]*from public, anon, authenticated, service_role/i,
	);
	assert.match(migration, /before update or delete on public\.admin_audit_logs/i);
	assert.match(migration, /before truncate on public\.audit_logs/i);
	assert.match(migration, /before truncate on public\.admin_audit_logs/i);
});
