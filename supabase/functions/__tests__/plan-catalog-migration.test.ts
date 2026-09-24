// Static contract for the plan catalog and the audited Stripe plan admission
// path. These migrations need a Supabase Postgres to execute; this suite pins
// the security-relevant shape (RLS, grants, lock, binding, audit, terminal
// state) so a later edit cannot silently weaken it.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const read = (name: string) => readFileSync(new URL(`../../migrations/${name}`, import.meta.url), "utf8");
const catalog = read("20260925000010_plan_catalog.sql");
const admission = read("20260925000011_stripe_plan_admission.sql");
const projection = read("20260925000012_get_tenant_plan.sql");
const applyBody = admission.split("create or replace function public.apply_stripe_plan_subscription(")[1]?.split("\n$$;")[0] ?? "";
const projectionBody = projection.split("create or replace function public.get_tenant_plan(")[1]?.split("\n$$;")[0] ?? "";

describe("plan catalog migration", () => {
	it("is reference data readable only by signed-in users and never writable by them", () => {
		expect(catalog).toContain("alter table public.plans enable row level security;");
		expect(catalog).toContain("revoke all on public.plans from public, anon, authenticated;");
		expect(catalog).toContain("grant select on public.plans to authenticated;");
		expect(catalog).toMatch(/create policy plans_select_authenticated on public\.plans\s+for select to authenticated/);
		expect(catalog).not.toMatch(/grant\s+(insert|update|delete|all)[^;]*public\.plans[^;]*to\s+(anon|authenticated)/i);
		expect(catalog).not.toMatch(/to anon/);
	});

	it("labels list prices as awaiting COM-001 approval", () => {
		expect(catalog).toContain("LIST PRICES ONLY");
		expect(catalog).toContain("COM-001");
		expect(catalog).toMatch(/currency text not null default 'USD' check \(currency = 'USD'\)/);
	});

	it("is re-runnable", () => {
		expect(catalog).toContain("create table if not exists public.plans");
		expect(catalog).toContain("on conflict (id) do update set");
		expect(catalog).toContain("drop policy if exists plans_select_authenticated on public.plans;");
		expect(catalog).toContain("drop constraint if exists teams_plan_check");
		expect(admission).toContain("create table if not exists public.billing_plan_subscriptions");
	});

	it("keeps legacy team labels valid and maps them to catalog ids", () => {
		expect(catalog).toContain("check (plan in ('free', 'pro', 'team', 'business', 'enterprise'))");
		expect(catalog).toContain("when 'pro' then 'team'");
	});
});

describe("stripe plan admission RPC", () => {
	it("is service-role only and holds the shared admission lock", () => {
		expect(admission).toMatch(/revoke all on function public\.apply_stripe_plan_subscription\([^)]*\)\s+from public, anon, authenticated;/);
		expect(admission).toMatch(/grant execute on function public\.apply_stripe_plan_subscription\([^)]*\)\s+to service_role;/);
		expect(applyBody).toContain("security definer");
		expect(applyBody).toContain("perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));");
		expect(admission).toContain("alter table public.billing_plan_subscriptions enable row level security;");
		expect(admission).toContain("revoke all on public.billing_plan_subscriptions from public, anon, authenticated;");
	});

	it("rejects replays, stale events, cross-tenant reuse and closed subscriptions before any write", () => {
		const firstWrite = applyBody.indexOf("update public.entitlements");
		for (const guard of ["'subscription_tenant_conflict'", "'duplicate_event'", "'stale_event'", "'subscription_closed'"]) {
			const index = applyBody.indexOf(guard);
			expect(index, guard).toBeGreaterThan(0);
			expect(index, guard).toBeLessThan(firstWrite);
		}
		expect(applyBody).toContain("v_row.last_event_created_at > p_event_created_at");
	});

	it("binds grants to stripe:<subscription> and never replaces another licence", () => {
		expect(applyBody).toContain("v_reference := 'stripe:' || p_subscription_id;");
		expect(applyBody).toContain("v_admission.grant_reference is distinct from v_reference");
		expect(applyBody).toContain("'licensed_admission_exists'");
		expect(applyBody).toMatch(/v_mode is distinct from 'cloud'/);
		expect(applyBody).toContain("p_seats < v_plan.min_seats");
		expect(applyBody).toContain("p_current_period_end <= v_now");
		expect(applyBody).toContain("m.role in ('owner', 'admin')");
		expect(applyBody).toContain("v_plan_id not in ('team', 'business')");
	});

	it("never lets a payment undo an operator revocation", () => {
		const guard = applyBody.indexOf("'admission_revoked_requires_operator'");
		const admissionWrite = applyBody.indexOf("insert into public.tenant_admissions");
		expect(guard).toBeGreaterThan(0);
		expect(guard).toBeLessThan(admissionWrite);
		expect(applyBody).toContain("v_admission.revoked_at is not null");
		expect(applyBody).toContain("s.admission_reason = 'subscription_ended'");
	});

	it("revokes only the admission its own subscription granted", () => {
		const revoke = applyBody.split("if p_action = 'revoke' then")[1]?.split("elsif p_action = 'hold' then")[0] ?? "";
		expect(revoke).toContain("v_admission.grant_reference = v_reference");
		expect(revoke).toContain("revocation_epoch = revocation_epoch + 1");
		expect(revoke).toContain("where tenant_id = p_tenant_id and grant_reference = v_reference and revoked_at is null");
		expect(revoke).toContain("'no_bound_admission'");
	});

	it("never grants on hold and audits every applied decision", () => {
		const hold = applyBody.split("elsif p_action = 'hold' then")[1]?.split("\n  else\n")[0] ?? "";
		expect(hold).not.toContain("insert into public.tenant_admissions");
		expect(hold).not.toContain("update public.entitlements");
		expect(applyBody).toMatch(/insert into public\.admin_audit_logs\(actor_user_id, tenant_id, target_user_id, action, detail\)\s+values \(null, p_tenant_id, p_user_id, v_audit_action,/);
		for (const action of [
			"admission.stripe_plan_granted",
			"admission.stripe_plan_revoked",
			"billing.stripe_plan_conflict",
			"billing.stripe_plan_rejected",
			"billing.stripe_plan_status_recorded",
		]) expect(applyBody).toContain(`'${action}'`);
	});
});

describe("get_tenant_plan projection", () => {
	it("is member-only behind the identity barrier and never granted to anon", () => {
		expect(projectionBody).toContain("not app.is_tenant_member(p_tenant_id)");
		expect(projectionBody).toContain("not public.tenant_identity_access_allowed(p_tenant_id)");
		expect(projectionBody).toContain("raise exception 'tenant_plan_access_denied' using errcode = '42501'");
		expect(projection).toContain("revoke all on function public.get_tenant_plan(uuid) from public, anon;");
		expect(projection).toContain("grant execute on function public.get_tenant_plan(uuid) to authenticated;");
	});

	it("reports a Stripe plan only while its bound admission is active", () => {
		expect(projectionBody).toContain("v_admission.grant_reference = 'stripe:' || v_sub.provider_subscription_id");
		expect(projectionBody).toContain("v_admission_status = 'active'");
		expect(projectionBody).toContain("app.visible_tenant_admission_capacity(p_tenant_id)");
		expect(projectionBody).not.toMatch(/\b(insert|update|delete)\b/i);
	});
});
