import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const sql = readFileSync(new URL("../supabase/migrations/20260923000011_active_telemetry_retention.sql", import.meta.url), "utf8");

test("active telemetry retention is policy-driven, bounded, held, serialized, and service-only", () => {
	assert.match(sql, /public\.tenant_data_retention_policies[\s\S]+p\.data_class = 'telemetry'[\s\S]+make_interval\(days => p\.retention_days\)/);
	assert.match(sql, /t\.status = 'active'/);
	assert.match(sql, /p_limit not between 1 and 1000/);
	assert.match(sql, /pg_try_advisory_xact_lock\(hashtextextended\(v_tenant::text, 2606\)\)/);
	assert.match(sql, /tenant_legal_holds[\s\S]+released_at is null/);
	assert.match(sql, /active_tenants_missing_policy/);
	assert.match(sql, /not exists \([\s\S]+tenant_data_retention_policies p[\s\S]+p\.data_class = 'telemetry'/);
	assert.match(sql, /for share of p/);
	assert.match(sql, /revoke all on function public\.prune_expired_telemetry_events[\s\S]+from public, anon, authenticated/);
	assert.match(sql, /grant execute on function public\.prune_expired_telemetry_events[\s\S]+to service_role/);
	assert.doesNotMatch(sql, /interval\s+'\d+\s+days'/i, "retention days must come from the tenant policy, not a new hard-coded duration");
});
