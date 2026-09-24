import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const migrationPath = "supabase/migrations/20260912140000_tenant_offboarding_retention.sql";
const sql = await readFile(migrationPath, "utf8");

// The cache-invalidation extension is a separate, append-only migration. Keeping
// it out of `sql` is what lets the assertions below distinguish "the shipped
// phase list was extended" from "the shipped migration was edited".
const cacheMigrationPath = "supabase/migrations/20260913000006_tenant_cache_invalidation_offboarding.sql";
const cacheSql = await readFile(cacheMigrationPath, "utf8");
const playbookOffboardingMigrationPath = "supabase/migrations/20260923000012_fleet_response_playbook_offboarding.sql";
const playbookOffboardingSql = await readFile(playbookOffboardingMigrationPath, "utf8");

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

test("a cache invalidation phase exists and records a receipt", () => {
	// Append-only: the shipped phase list is extended by a new migration, so the
	// cache phase (and its receipt column) must not appear in the old bytes.
	assert.doesNotMatch(sql, /tenant_cache/);
	assert.doesNotMatch(sql, /cache_invalidation_receipt/);

	// The cache step is a real, ordered phase of the same shape as the others:
	// phase order 41 follows the fleet-command phase 40, maps to one of the ten
	// explicit data classes, and is seeded for new runs and backfilled for
	// in-flight runs alike.
	assert.match(cacheSql, /values \(new\.id, 41, 'tenant_cache', 'operational_ephemera', 'invalidate_cache'/);
	assert.match(cacheSql, /select r\.id, 41, 'tenant_cache', 'operational_ephemera', 'invalidate_cache'/);
	assert.match(cacheSql, /create trigger tenant_offboarding_cache_phase[\s\S]+after insert on public\.tenant_offboarding_runs/);
	assert.match(cacheSql, /where r\.status <> 'completed'/);
	assert.match(cacheSql, /on conflict \(run_id, phase\) do nothing/);

	// The phase records its own receipt: a dedicated column, mandatory for a
	// completed cache phase, written by an acknowledgement RPC that is blocked by
	// an active legal hold and granted to service_role only.
	assert.match(cacheSql, /add column cache_invalidation_receipt jsonb/);
	assert.match(cacheSql, /operation <> 'invalidate_cache'[\s\S]+status <> 'completed'[\s\S]+cache_invalidation_receipt is not null/);
	assert.match(cacheSql, /check \(operation in \('delete_records', 'delete_storage_objects', 'invalidate_cache'\)\)/);
	assert.match(cacheSql, /tenant_legal_holds where tenant_id = v_run\.tenant_id and released_at is null/);
	assert.match(cacheSql, /cache_invalidation_receipt = jsonb_build_object\([\s\S]+'invalidated', v_invalidated/);
	assert.match(cacheSql, /revoke all on function public\.ack_tenant_offboarding_cache\(uuid, text\[\], bigint\) from public, anon, authenticated/);
	assert.match(cacheSql, /grant execute on function public\.ack_tenant_offboarding_cache\(uuid, text\[\], bigint\) to service_role/);

	// The batch RPC hands the cache phase out as its own action, and the
	// extension refuses to apply against an unexpected definition.
	assert.match(cacheSql, /''phase'',v_phase\.phase,''action'',''invalidate_cache'',''cache_scope'',v_run\.tenant_id/);
	assert.match(cacheSql, /unexpected_offboarding_batch_definition/);

	// The ten explicit data classes and the backup exclusion are untouched: no
	// policy row is written, no class is added, and backups are never claimed.
	assert.doesNotMatch(cacheSql, /insert into public\.tenant_data_retention_policies/);
	assert.doesNotMatch(cacheSql, /data_class in \(/);
	assert.doesNotMatch(cacheSql, /covers_backups\s*=\s*true/);
});

test("playbook deletion is receipted before fleet commands without rewriting shipped migrations", () => {
	assert.doesNotMatch(sql, /fleet_response_playbook/);
	assert.match(playbookOffboardingSql, /values\s*\(new\.id,40,'fleet_response_playbook_steps','security_audit','delete_records'/);
	assert.match(playbookOffboardingSql, /\(new\.id,41,'fleet_response_playbook_runs','security_audit','delete_records'/);
	assert.match(playbookOffboardingSql, /\(40,'fleet_response_playbook_steps'\)[\s\S]+\(41,'fleet_response_playbook_runs'\)/);
	assert.match(playbookOffboardingSql, /\(new\.id,42,'fleet_response_commands'/);
	assert.match(playbookOffboardingSql, /values \(new\.id, 43, 'tenant_cache'/);
	assert.match(playbookOffboardingSql, /\(new\.id, 44, 'dlp_policy_revisions'/);
	assert.match(playbookOffboardingSql, /\(new\.id, 45, 'tenant_dlp_policies'/);
	assert.match(playbookOffboardingSql, /where r\.status<>'completed'/);
	assert.match(playbookOffboardingSql, /order by p\.run_id, p\.phase_order desc[\s\S]+set phase_order = phase_order \+ 2/);
	assert.match(playbookOffboardingSql, /completed_offboarding_has_fleet_response_playbook_data/);
	assert.match(playbookOffboardingSql, /completed_fleet_phase_has_playbook_data/);
	assert.match(playbookOffboardingSql, /unexpected_inflight_offboarding_phase_order/);
	assert.match(playbookOffboardingSql, /when ''fleet_response_playbook_steps'' then ''public\.fleet_response_playbook_steps''/);
	assert.match(playbookOffboardingSql, /app\.aidr_playbook_offboarding_run_id/);
	assert.match(playbookOffboardingSql, /fleet_response_playbook_offboarding_residue/);
});
