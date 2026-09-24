import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const sql = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
	"../../migrations/20260923000036_effective_seat_usage_view.sql"), "utf8");
const executableSql = sql.split(/\r?\n/).filter((line) => !line.trimStart().startsWith("--")).join("\n");

describe("browser-visible admitted seats", () => {
	it("keeps the view invoker-RLS and checks authenticated tenant membership", () => {
		expect(sql).toMatch(/create or replace view public\.seat_usage\s+with \(security_invoker = true\)/i);
		expect(sql).toContain("auth.role() is distinct from 'authenticated'");
		expect(sql).toContain("auth.uid() is null");
		expect(sql).toContain("not app.is_tenant_member(p_tenant_id)");
		expect(sql).toContain("not public.tenant_identity_access_allowed(p_tenant_id)");
		expect(sql).not.toContain("p_tenant_id is distinct from app.current_tenant_id()");
		expect(sql).toContain("grant execute on function app.visible_tenant_admission_capacity(uuid) to authenticated");
	});

	it("uses a read-only admission/entitlement projection for all displayed seat fields", () => {
		expect(sql).toContain("public.effective_tenant_seats(p_tenant_id)");
		expect(executableSql).not.toMatch(/\bfor (?:update|share)\b|pg_advisory/i);
		expect(sql).toContain("admitted.allowed_agents - least(greatest(e.included_agents, 0), admitted.allowed_agents) as extra_agents");
		expect(sql).toContain("admitted.allowed_agents,");
	});
});
