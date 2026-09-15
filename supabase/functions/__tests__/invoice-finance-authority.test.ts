import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const migration = readFileSync(new URL("../../migrations/20260916000001_invoice_finance_authority.sql", import.meta.url), "utf8");
const rpc = migration.split("create function public.record_invoice_approval(")[1]?.split("\n$$;")[0] ?? "";
const authority = migration.split("create function public.assert_invoice_finance_operator(")[1]?.split("\n$$;")[0] ?? "";

describe("invoice finance authority replacement migration", () => {
	it("starts empty and cannot be self-provisioned by customers or the Edge role", () => {
		expect(migration).toContain("create table public.invoice_finance_operators");
		expect(migration).toContain("primary key (tenant_id, user_id)");
		expect(migration).toContain("alter table public.invoice_finance_operators enable row level security");
		expect(migration).toContain("revoke all on public.invoice_finance_operators from public, anon, authenticated, service_role");
		expect(migration).toContain("grant select on public.invoice_finance_operators to service_role");
		expect(migration).not.toMatch(/insert into public\.invoice_finance_operators/);
		expect(migration).toContain("revoke all on public.enterprise_invoice_approvals from service_role");
		expect(migration).toContain("grant select on public.enterprise_invoice_approvals to service_role");
	});

	it("removes the actor-less bypass and grants only the actor-bound transition", () => {
		expect(migration).toContain("drop function public.record_invoice_approval(uuid, text, bigint, text, text)");
		expect(rpc).toContain("p_tenant_id uuid");
		expect(rpc).toContain("p_actor_user_id uuid");
		expect(rpc).not.toContain("p_approver");
		expect(migration).toContain("revoke all on function public.record_invoice_approval(uuid, uuid, uuid, bigint, text, text)\n  from public, anon, authenticated");
		expect(migration).toContain("grant execute on function public.record_invoice_approval(uuid, uuid, uuid, bigint, text, text)\n  to service_role");
	});

	it("locks and checks the authenticated grant and active tenant inside the paid transaction", () => {
		for (const check of ["f.user_id = p_actor_user_id", "f.tenant_id = p_tenant_id", "f.revoked_at is null", "f.expires_at > now()", "t.status = 'active'", "for share of f, t", "using errcode = '42501'"]) {
			expect(authority).toContain(check);
		}
		expect(authority).not.toContain("tenant_members");
		const check = rpc.indexOf("perform public.assert_invoice_finance_operator(p_tenant_id, p_actor_user_id)");
		const insert = rpc.indexOf("insert into public.enterprise_invoice_approvals");
		expect(check).toBeGreaterThan(-1);
		expect(insert).toBeGreaterThan(check);
		expect(rpc).toContain("where id = p_order_id and tenant_id = p_tenant_id for update");
		expect(rpc).toContain("p_actor_user_id::text, p_actor_user_id");
		expect(rpc).toContain("p_actor_user_id, p_tenant_id, 'invoice_approval.recorded'");
	});

	it("serializes all orders of a tenant before insertion and subtotal calculation", () => {
		const lock = rpc.indexOf("pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2617))");
		const insert = rpc.indexOf("insert into public.enterprise_invoice_approvals");
		const sum = rpc.indexOf("sum(a.agents_granted)");
		const update = rpc.indexOf("on conflict (tenant_id) do update");
		expect(lock).toBeGreaterThan(-1);
		expect(insert).toBeGreaterThan(lock);
		expect(sum).toBeGreaterThan(insert);
		expect(update).toBeGreaterThan(sum);
		expect(rpc).toContain("invoice_approval_conflict");
		expect(rpc).toContain("using errcode = '23505'");
	});
});
