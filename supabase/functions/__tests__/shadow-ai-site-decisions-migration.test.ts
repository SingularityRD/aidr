// Static contract for supabase/migrations/20261007140000_shadow_ai_site_decisions.sql
// (Docker/Postgres is not available to this suite; scripts/ai-governance-postgres.test.mjs
// covers the register against a live database).
//
// Shadow AI allow/block decisions reuse the AI governance register: no new table, no new
// write path. The migration only widens what is enforceable and adds the Browser Guard
// list to the overlay that the signed browser-guard-policy document is built from.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { SHADOW_AI_SERVICE_ID } from "../_shared/browser-guard-policy.ts";
import { AI_SERVICE_ID_PATTERN, AI_SERVICES } from "../../../packages/browser-guard/src/sites/catalog.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const MIGRATIONS = join(ROOT, "supabase", "migrations");
const NAME = "20261007140000_shadow_ai_site_decisions.sql";
const SQL = readFileSync(join(MIGRATIONS, NAME), "utf8");
const code = SQL.split("\n").filter((line) => !line.trim().startsWith("--")).join("\n");

/** Body of the last CREATE OR REPLACE FUNCTION <name> in `sql`, up to its closing `$$;`. */
function functionBody(sql: string, name: string): string {
	const start = sql.lastIndexOf(`create or replace function ${name}(`);
	expect(start, `${name} is defined`).toBeGreaterThanOrEqual(0);
	const open = sql.indexOf("$$", start);
	return sql.slice(start, sql.indexOf("$$;", open + 2) + 3);
}

/** Migrations (in apply order) that define `name`. */
function definers(name: string): string[] {
	return readdirSync(MIGRATIONS).filter((f) => f.endsWith(".sql")).sort()
		.filter((f) => readFileSync(join(MIGRATIONS, f), "utf8").includes(`create or replace function ${name}(`));
}

describe(NAME, () => {
	it("is the authoritative (last) definition of every function it replaces", () => {
		for (const name of ["app.ai_shadow_ai_service", "app.ai_asset_enforceable", "public.ai_governance_policy_overlay"]) {
			expect(definers(name).at(-1), name).toBe(NAME);
		}
	});

	it("adds no table, policy, grant to clients or transaction control", () => {
		expect(code).not.toMatch(/create table|alter table|create policy|drop policy|drop function/i);
		expect(code).not.toMatch(/grant [^;]* to (anon|authenticated|public)/i);
		expect(code).not.toMatch(/^\s*(begin|commit|rollback)\s*;/im);
	});

	it("uses the same catalog id shape as Browser Guard and the Edge Function", () => {
		const body = functionBody(code, "app.ai_shadow_ai_service");
		expect(body).toContain("'^[a-z0-9][a-z0-9-]{0,31}$'");
		expect(SHADOW_AI_SERVICE_ID.source).toBe("^[a-z0-9][a-z0-9-]{0,31}$");
		expect(AI_SERVICE_ID_PATTERN.source).toBe(SHADOW_AI_SERVICE_ID.source);
		for (const service of AI_SERVICES) expect(SHADOW_AI_SERVICE_ID.test(service.id), service.id).toBe(true);
		// Register hostnames are not catalog ids and never reach the browser list.
		expect(SHADOW_AI_SERVICE_ID.test("chat.corp.example")).toBe(false);
		expect(body).toMatch(/immutable\s+set search_path = pg_catalog, pg_temp/);
		expect(code).toContain("revoke all on function app.ai_shadow_ai_service(text) from public, anon, authenticated;");
	});

	it("puts Shadow AI bans under the same four-eyes and reviewer rules as MCP bans", () => {
		const body = functionBody(code, "app.ai_asset_enforceable");
		expect(body).toContain("p_type = 'mcp_server'");
		expect(body).toContain("app.ai_browser_guard_site(p_identifier) or app.ai_shadow_ai_service(p_identifier)");
		expect(code).toContain("revoke all on function app.ai_asset_enforceable(text, text) from public, anon, authenticated;");
	});

	it("delivers waived-aware bans and approvals as browser_guard_shadow_ai, service role only", () => {
		const body = functionBody(code, "public.ai_governance_policy_overlay");
		expect(body).toMatch(/security definer\s+set search_path = pg_catalog, public, app, pg_temp/);
		// Bans come from `effective` (enforced minus approved, unexpired exceptions).
		expect(body).toContain("select * from enforced where id not in (select asset_id from waived)");
		expect(body).toContain("app.ai_status_rank(x.status) <= app.ai_status_rank(e.waived_status)");
		const shadow = body.slice(body.indexOf("'browser_guard_shadow_ai'"));
		expect(shadow).toMatch(/'blocked', coalesce\(\(\s+select jsonb_agg\(identifier order by identifier collate "C"\) from effective\s+where asset_type = 'ai_site' and status = 'banned'\s+and app\.ai_shadow_ai_service\(identifier\)/);
		expect(shadow).toMatch(/'sanctioned', coalesce\(\(\s+select jsonb_agg\(identifier order by identifier collate "C"\) from sanctioned\)/);
		const sanctioned = body.slice(body.indexOf("sanctioned as ("), body.indexOf("select jsonb_build_object("));
		expect(sanctioned).toContain("a.tenant_id = p_tenant_id");
		expect(sanctioned).toContain("a.status = 'approved'");
		expect(sanctioned).toContain("app.ai_shadow_ai_service(a.identifier)");
		// The managed blockedSites list keeps only built-in site ids (Chrome refuses others).
		const sites = body.slice(body.indexOf("'browser_guard_blocked_sites'"), body.indexOf("'browser_guard_shadow_ai'"));
		expect(sites).toContain("app.ai_browser_guard_site(identifier)");
		// Every pre-existing overlay key is still produced.
		for (const key of ["mcp_deny_servers", "mcp_require_approval_servers", "browser_guard_blocked_sites"]) {
			expect(body).toContain(`'${key}'`);
		}
		expect(code).toContain("revoke all on function public.ai_governance_policy_overlay(uuid, uuid, uuid) from public, anon, authenticated;");
		expect(code).toContain("grant execute on function public.ai_governance_policy_overlay(uuid, uuid, uuid) to service_role;");
	});
});
