import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (name) =>
	readFileSync(new URL(`../supabase/migrations/${name}`, import.meta.url), "utf8");
const sql = read("20260925000001_browser_privacy_telemetry.sql");
const retention = read("20260923000011_active_telemetry_retention.sql");
const offboarding = read("20260912140000_tenant_offboarding_retention.sql");
const teamRead = read("20260923000014_team_read_rls.sql");

test("browser privacy scans stay in public.events so existing tenant controls cover them", () => {
	// A new table would need its own RLS, retention class and offboarding phase.
	assert.doesNotMatch(sql, /create\s+table/i);
	assert.match(sql, /on public\.events \(tenant_id, created_at desc\)\s+where type = 'privacy_scan'/);
	// Members read through RLS; there is still no browser write policy on events.
	assert.match(teamRead, /create policy tenant_events_select on public\.events for select to authenticated\s+using \(app\.is_tenant_member\(tenant_id\)\)/);
	// Active retention prunes every events row of the tenant, whatever its type.
	assert.match(retention, /delete from public\.events e using \(\s+select id from public\.events\s+where tenant_id = v_tenant\s+and created_at <=/);
	assert.doesNotMatch(retention, /type\s*=\s*'runtime_verdict'/);
	// Offboarding deletes the whole events phase for the tenant.
	assert.match(offboarding, /\(4, 'events', 'telemetry', 'delete_records'\)/);
	assert.match(offboarding, /when 'events' then 'public\.events'/);
});

test("the dashboard summary keeps RLS and is not callable anonymously", () => {
	assert.match(sql, /function public\.privacy_guard_summary\(\s+p_tenant_id uuid,\s+p_days integer default 30\s+\)/);
	assert.match(sql, /security invoker/);
	assert.doesNotMatch(sql, /security definer/);
	assert.match(sql, /set search_path = pg_catalog, public, app, pg_temp/);
	assert.match(sql, /p_days not in \(7, 30\)/);
	assert.match(sql, /if not app\.is_tenant_member\(p_tenant_id\) then\s+raise exception 'tenant_forbidden' using errcode = '42501'/);
	assert.match(sql, /revoke all on function public\.privacy_guard_summary\(uuid, integer\) from public, anon;/);
	assert.match(sql, /grant execute on function public\.privacy_guard_summary\(uuid, integer\) to authenticated, service_role;/);
	// Aggregates read counts and enums only; stored payloads carry nothing else.
	for (const field of sql.matchAll(/payload->>?'([a-z_]+)'/g)) {
		assert.ok(["action", "site", "findings_count", "entity_counts"].includes(field[1]), field[1]);
	}
});
