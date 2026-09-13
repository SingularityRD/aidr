import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const migrationPath = "supabase/migrations/20260912140000_tenant_offboarding_retention.sql";
const sql = await readFile(migrationPath, "utf8");

test("retention policy covers ten explicit data classes and excludes backups", () => {
	const classes = [
		"temporary_exports", "access_credentials", "telemetry", "endpoint_identity",
		"security_intelligence", "policy_configuration", "identity_membership",
		"commercial_records", "security_audit", "operational_ephemera",
	];
	for (const dataClass of classes) assert.match(sql, new RegExp(`'${dataClass}'`));
	assert.match(sql, /covers_backups boolean not null default false check \(covers_backups = false\)/);
	assert.match(sql, /backup_scope text not null default 'excluded_external_retention'/);
	assert.match(sql, /Backup copies are excluded from this live-data receipt/);
});

test("legal holds and deletion batches serialize on the same tenant lock", () => {
	assert.ok((sql.match(/hashtextextended\([^\n]+2606\)/g) ?? []).length >= 3);
	assert.match(sql, /legal_hold_history_is_immutable/);
	assert.match(sql, /legal_hold_update_must_be_a_single_release/);
	assert.match(sql, /blocked_legal_hold/);
	assert.match(sql, /not exists\(select 1 from public\.tenant_legal_holds h[\s\S]+h\.released_at is null\)/);
});

test("all mutating functions are service-only and batches are bounded", () => {
	for (const signature of [
		"request_tenant_offboarding\\(uuid, uuid\\)",
		"run_tenant_offboarding_batch\\(uuid, integer\\)",
		"ack_tenant_offboarding_objects\\(uuid, text\\[\\]\\)",
	]) {
		assert.match(sql, new RegExp(`revoke all on function public\\.${signature} from public, anon, authenticated`));
		assert.match(sql, new RegExp(`grant execute on function public\\.${signature} to service_role`));
	}
	assert.match(sql, /p_batch_size not between 1 and 1000/);
	assert.match(sql, /order by eligible_at, phase_order limit 1/);
	assert.match(sql, /limit \$2/);
});

test("offboarding includes SCIM, delegated credentials and core tenant data", () => {
	for (const phase of [
		"audit_export_objects", "events", "agents", "api_keys", "audit_logs",
		"admin_audit_logs", "tenant_members", "team_members", "scim_tokens",
		"scim_group_memberships", "scim_managed_memberships", "scim_groups",
		"scim_users", "delegated_credential_receipts", "delegated_credential_grants",
		"identity_recovery_codes", "identity_password_recovery_grants", "tenant_identity_policies",
	]) assert.match(sql, new RegExp(`'${phase}'`));
	assert.match(sql, /update public\.api_keys set revoked = true/);
	assert.match(sql, /update public\.scim_tokens set revoked_at/);
	assert.match(sql, /update public\.delegated_credential_receipts[\s\S]+set state='revoked'/);
});

test("long-lived entitlement snapshots survive shorter endpoint identity deletion", () => {
	assert.match(sql, /foreign key \(tenant_id, agent_id\) references public\.agents\(tenant_id, id\)[\s\S]+on delete set null \(agent_id\)/);
	assert.match(sql, /if v_phase\.phase='delegated_credential_receipts' then v_order_by := 'delegation_depth desc, ctid'/);
});
