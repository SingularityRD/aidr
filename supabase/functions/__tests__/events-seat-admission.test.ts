import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";

const sql = readFileSync(join(process.cwd(), "supabase/migrations/20260923000032_events_seat_admission_guard.sql"), "utf8");

it("rechecks each stored event against current tenant seats and exact agent binding", () => {
	const lock = sql.indexOf("pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 0))");
	const entitlement = sql.indexOf("where e.tenant_id = new.tenant_id\n   for update");
	const agent = sql.indexOf("a.id = new.agent_id and a.tenant_id = new.tenant_id\n     and a.user_id = new.user_id\n   for key share");
	const duplicate = sql.indexOf("ev.tenant_id = new.tenant_id and ev.event_id = new.event_id\n   for share");
	const effective = sql.indexOf("public.effective_tenant_seats(new.tenant_id)");
	const rank = sql.indexOf("(a.first_seen, a.id) < (v_first_seen, new.agent_id)");
	expect(sql).toContain("on public.agents (tenant_id, first_seen, id)");
	expect(lock).toBeGreaterThan(0);
	expect(entitlement).toBeGreaterThan(lock);
	expect(agent).toBeGreaterThan(entitlement);
	expect(duplicate).toBeGreaterThan(agent);
	expect(effective).toBeGreaterThan(duplicate);
	expect(rank).toBeGreaterThan(effective);
	expect(sql).toMatch(/v_existing_agent = new\.agent_id and v_existing_user = new\.user_id/);
	expect(sql).toMatch(/if v_prior >= v_allowed then\s+raise exception 'agent_seat_not_authorized' using errcode = '42501'/);
	expect(sql).toMatch(/create trigger events_seat_admission\s+before insert on public\.events\s+for each row/);
	expect(sql).toMatch(/revoke all on function app\.enforce_event_seat_admission\(\)\s+from public, anon, authenticated, service_role/);
});
