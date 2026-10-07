// Static contract for 20261007130000_plan_retention_and_feature_gating.sql.
//
// The migration needs a Supabase Postgres to execute (Docker is not available
// in every gate), so this suite pins its security-relevant shape: which
// sources may grant a plan, that every entry point fails closed, the grants,
// that the reaper and the retention admin path use the plan cap, and that the
// admin audit read is owner/admin-only, tenant-scoped and paginated. It also
// pins the shared Edge resolver to the catalog seed so the tier table cannot
// drift.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
	decideFeature,
	effectiveRetentionDays,
	FEATURE_MINIMUM_PLAN,
	GATED_FEATURES,
	parseTenantPlanEntitlement,
	PLAN_IDS,
	requireFeature,
} from "../_shared/plan-entitlements.ts";

const read = (name: string) => readFileSync(new URL(`../../migrations/${name}`, import.meta.url), "utf8");
const sql = read("20261007130000_plan_retention_and_feature_gating.sql");
const catalog = read("20260925000010_plan_catalog.sql");

function body(signature: string): string {
	const start = sql.indexOf(signature);
	expect(start, signature).toBeGreaterThanOrEqual(0);
	return sql.slice(start, sql.indexOf("\n$$;", start));
}

const resolver = body("create or replace function app.tenant_plan_entitlements(");
const reaper = body("create or replace function public.prune_expired_telemetry_events(");
const adminSet = body("create or replace function public.admin_set_tenant_retention(");
const effective = body("create or replace function app.tenant_effective_retention_days(");
const adminAudit = body("create or replace function public.list_tenant_admin_audit_logs(");
const memberPlan = body("create or replace function public.get_tenant_plan_entitlements(");
const hasFeature = body("create or replace function app.tenant_has_plan_feature(");

/** Catalog seed rows: id -> features. */
function seedFeatures(): Map<string, string[]> {
	const seed = catalog.split("-- catalog-seed:begin")[1]?.split("-- catalog-seed:end")[0] ?? "";
	const rows = new Map<string, string[]>();
	for (const match of seed.matchAll(/\('(\w+)', '[^']+', \d+, \d+, [^']*'USD', '(\[[^\]]*\])'::jsonb/g)) {
		rows.set(match[1] as string, JSON.parse(match[2] as string) as string[]);
	}
	return rows;
}

describe("plan resolver SQL", () => {
	it("uses the catalog tier names and resolves features from public.plans", () => {
		expect(catalog).toContain("check (id in ('free', 'team', 'business', 'enterprise'))");
		expect([...PLAN_IDS]).toEqual(["free", "team", "business", "enterprise"]);
		expect(resolver).toContain("select * into v_plan from public.plans where id = v_plan_id;");
		expect(resolver).toContain("'features', v_plan.features");
		expect(resolver).toContain("'retention_days_max', v_plan.retention_days");
		expect(resolver).toContain("raise exception 'tenant_plan_unavailable'");
	});

	it("honours a Stripe plan only when bound to the active licensed admission", () => {
		expect(resolver).toMatch(/v_sub\.admission_state = 'granted' and v_licensed_active\s+and v_admission\.grant_reference = 'stripe:' \|\| v_sub\.provider_subscription_id/);
	});

	it("honours a paid team label only with an active licence or approved pilot; otherwise Free", () => {
		expect(resolver).toContain("if v_licensed_active or v_pilot_approved then");
		expect(resolver).toContain("v_source := 'admission_inactive';");
		expect(resolver).toMatch(/v_admission\.revoked_at is null\s+and v_admission\.starts_at <= v_now\s+and v_admission\.expires_at > v_now/);
		expect(resolver).toMatch(/if not v_tenant_active then\s+v_source := 'admission_inactive';/);
	});

	it("lets an active verified trial evaluate Team, never a higher edition", () => {
		expect(resolver).toMatch(/if v_trial_active and v_plan_id = 'free' then\s+v_plan_id := 'team';\s+v_source := 'trial';/);
	});

	it("is service-role only for Edge Functions and membership-checked for the dashboard", () => {
		expect(sql).toMatch(/revoke all on function app\.tenant_plan_entitlements\(uuid\) from public, anon, authenticated, service_role;/);
		expect(sql).toMatch(/revoke all on function public\.tenant_plan_entitlements\(uuid\) from public, anon, authenticated;\s+grant execute on function public\.tenant_plan_entitlements\(uuid\) to service_role;/);
		expect(memberPlan).toContain("app.is_tenant_member(p_tenant_id)");
		expect(memberPlan).toContain("public.tenant_identity_access_allowed(p_tenant_id)");
		expect(memberPlan).toContain("raise exception 'tenant_plan_access_denied'");
		for (const fn of [resolver, memberPlan, hasFeature, effective, adminAudit]) {
			expect(fn).toContain("security definer");
			expect(fn).toMatch(/set search_path = [^\n]*pg_temp/);
		}
	});

	it("gates posture views with a restrictive RLS policy that fails closed", () => {
		expect(hasFeature).toMatch(/exception when others then\s+return false;/);
		expect(sql).toMatch(/create policy posture_findings_plan_feature on public\.posture_findings\s+as restrictive for select to authenticated\s+using \(app\.tenant_has_plan_feature\(tenant_id, 'ai_security_posture'\)\);/);
	});
});

describe("plan-bound retention SQL", () => {
	it("caps only the telemetry class: min(setting, plan max), plan term when never configured", () => {
		expect(effective).toContain("if p_data_class is distinct from 'telemetry'");
		expect(effective).toContain("return least(p_configured_days, v_max);");
		expect(effective).toMatch(/if v_max is null then return p_configured_days; end if;/);
		expect(effective).toMatch(/end if;\s+return v_max;\s+end;$/);
	});

	it("drives every reaper eligibility check and the delete from the effective period", () => {
		expect(reaper).not.toMatch(/make_interval\(days => p\.retention_days\)/);
		expect(reaper.match(/app\.tenant_effective_retention_days\(p\.tenant_id, p\.data_class, p\.retention_days, p\.updated_by is not null\)/g)).toHaveLength(2);
		expect(reaper).toContain("v_retention_days := app.tenant_effective_retention_days(v_tenant, 'telemetry', v_retention_days, v_explicit);");
		// Unchanged safety properties of the original reaper.
		expect(reaper).toContain("pg_try_advisory_xact_lock(hashtextextended(v_tenant::text, 2606))");
		expect(reaper).toContain("for share of p;");
		expect(reaper).toMatch(/tenant_legal_holds[\s\S]+released_at is null/);
		expect(sql).toMatch(/grant execute on function public\.prune_expired_telemetry_events\(integer, boolean, timestamptz\)\s+to service_role;/);
	});

	it("refuses a telemetry setting above the plan term before any write", () => {
		const guard = adminSet.indexOf("raise exception 'retention_days_exceeds_plan'");
		expect(guard).toBeGreaterThan(0);
		expect(guard).toBeLessThan(adminSet.indexOf("update public.tenant_data_retention_policies"));
		expect(adminSet).toContain("perform app.retention_assert_tenant_owner(p_tenant_id, p_actor_user_id);");
		expect(adminSet).toContain("'retention.policy.changed'");
	});
});

describe("admin audit trail SQL", () => {
	it("is owner/admin-only, tenant-scoped, keyset-paginated and bounded", () => {
		expect(adminAudit).toContain("m.role in ('owner', 'admin')");
		expect(adminAudit).toContain("public.tenant_identity_access_allowed(p_tenant_id)");
		expect(adminAudit).toContain("where a.tenant_id = p_tenant_id");
		expect(adminAudit).toContain("(a.created_at, a.id) < (p_before_created_at, p_before_id)");
		expect(adminAudit).toContain("order by a.created_at desc, a.id desc");
		expect(adminAudit).toContain("p_limit not between 1 and 200");
		expect(sql).toMatch(/revoke all on function public\.list_tenant_admin_audit_logs\([^)]*\)\s+from public, anon;/);
		expect(sql).not.toMatch(/grant execute on function public\.list_tenant_admin_audit_logs[^;]*anon/);
	});
});

describe("shared Edge resolver", () => {
	it("names the cheapest catalog edition for every gated feature", () => {
		const rows = seedFeatures();
		expect([...rows.keys()]).toEqual(["free", "team", "business", "enterprise"]);
		for (const feature of GATED_FEATURES) {
			const cheapest = [...rows.entries()].find(([, features]) => features.includes(feature))?.[0];
			expect(FEATURE_MINIMUM_PLAN[feature], feature).toBe(cheapest);
		}
		expect(FEATURE_MINIMUM_PLAN).toMatchObject({
			browser_privacy_guard: "team",
			entra_sso: "team",
			siem_export: "business",
			scim: "business",
			ai_security_posture: "business",
			air_gapped_deployment: "enterprise",
		});
	});

	const TENANT = "11111111-1111-4111-8111-111111111111";
	const row = (overrides: Record<string, unknown> = {}) => ({
		tenant_id: TENANT,
		plan_id: "team",
		plan_source: "stripe_subscription",
		trial_active: false,
		features: ["local_detection", "dashboard", "browser_privacy_guard", "entra_sso"],
		retention_days_max: 90,
		...overrides,
	});

	it("parses strictly and fails closed on anything unexpected", () => {
		expect(parseTenantPlanEntitlement(row(), TENANT)?.planId).toBe("team");
		expect(parseTenantPlanEntitlement([row()], TENANT)?.retentionDaysMax).toBe(90);
		for (const bad of [
			null,
			row({ tenant_id: "22222222-2222-4222-8222-222222222222" }),
			row({ plan_id: "pro" }),
			row({ plan_source: "browser" }),
			row({ features: "scim" }),
			row({ features: ["SCIM!"] }),
			row({ retention_days_max: 0 }),
			row({ trial_active: "yes" }),
			[row(), row()],
		]) {
			expect(parseTenantPlanEntitlement(bad, TENANT)).toBeNull();
		}
	});

	it("answers 402 plan_feature_required, 503 when unavailable, and allows only an entitled plan", async () => {
		const db = (data: unknown, error: unknown = null) => ({
			calls: [] as Array<[string, Record<string, unknown>]>,
			rpc(name: string, args: Record<string, unknown>) {
				this.calls.push([name, args]);
				return Promise.resolve({ data, error });
			},
		});
		const team = db(row());
		expect((await requireFeature(team, TENANT, "entra_sso")).ok).toBe(true);
		expect(team.calls).toEqual([["tenant_plan_entitlements", { p_tenant_id: TENANT }]]);
		expect(await requireFeature(team, TENANT, "scim")).toEqual({
			ok: false,
			status: 402,
			body: { error: "plan_feature_required", feature: "scim", plan_id: "team", required_plan: "business" },
		});
		expect(await requireFeature(db(null, { message: "down" }), TENANT, "scim")).toEqual({
			ok: false,
			status: 503,
			body: { error: "plan_entitlement_unavailable" },
		});
		const throwing = { rpc: () => Promise.reject(new Error("network")) };
		expect((await requireFeature(throwing, TENANT, "scim")).ok).toBe(false);
		expect(decideFeature(null, "siem_export")).toMatchObject({ status: 503 });
	});

	it("computes effective retention exactly like the SQL", () => {
		expect(effectiveRetentionDays(30, false, 90)).toBe(90);
		expect(effectiveRetentionDays(365, true, 90)).toBe(90);
		expect(effectiveRetentionDays(30, true, 90)).toBe(30);
		expect(effectiveRetentionDays(400, true, null)).toBe(400);
		expect(effectiveRetentionDays(30, false, 7)).toBe(7);
	});
});
