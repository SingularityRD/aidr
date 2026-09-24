import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const migration = readFileSync(
	join(
		ROOT,
		"supabase",
		"migrations",
		"20260922000001_tenant_owner_and_device_revocation_hardening.sql",
	),
	"utf8",
);

function functionBody(name: string): string {
	const start = migration.indexOf(`create or replace function public.${name}(`);
	expect(start).toBeGreaterThanOrEqual(0);
	const end = migration.indexOf("\n$$;", start);
	expect(end).toBeGreaterThan(start);
	return migration.slice(start, end);
}

describe("owner-role mutation boundary", () => {
	const guard = functionBody("guard_team_owner");

	it("protects both legacy and canonical memberships without a definer current_user bypass", () => {
		expect(guard).not.toContain("current_user");
		expect(guard).toContain("auth.role() = 'service_role'");
		expect(guard).toContain("session_user in ('postgres', 'service_role', 'supabase_admin', 'supabase_auth_admin')");
		expect(migration).toContain("before insert or update or delete on public.team_members");
		expect(migration).toContain("before insert or update or delete on public.tenant_members");
	});

	it("requires an active owner for owner changes and preserves only creator bootstrap", () => {
		expect(guard).toContain("m.user_id = v_actor_id");
		expect(guard).toContain("m.role = 'owner'");
		expect(guard).toContain("t.status = 'active'");
		expect(guard).toContain("v_actor_id = v_new_user_id");
		expect(guard).toContain("t.created_by = v_new_user_id");
		expect(guard).toContain("not exists (\n        select 1 from public.tenant_members m");
		expect(guard).toContain("raise exception 'owner role change requires an owner'");
	});

	it("keeps a last-active-owner invariant for authenticated DML", () => {
		const lockAt = guard.indexOf("pg_advisory_xact_lock");
		const nowAt = guard.indexOf("v_now := clock_timestamp()");
		const ownerCheckAt = guard.indexOf("if v_old_role = 'owner' and not exists");
		expect(lockAt).toBeGreaterThanOrEqual(0);
		expect(nowAt).toBeGreaterThan(lockAt);
		expect(nowAt).toBeLessThan(ownerCheckAt);
		expect(lockAt).toBeLessThan(ownerCheckAt);
		expect(guard).toContain("hashtextextended(v_old_tenant_id::text, 2612)");
		expect(guard).toContain("hashtextextended(v_new_tenant_id::text, 2612)");
		expect(guard).toContain("m.user_id <> v_old_user_id");
		expect(guard).toContain("m.expires_at is null or m.expires_at > v_now");
		expect(guard).toContain("raise exception 'tenant must retain at least one owner'");
	});
});

describe("device enrollment revocation boundary", () => {
	const revoke = functionBody("mark_identity_session_revoked");
	const issue = functionBody("issue_device_enrollment_token");

	it("revokes device grants and unconsumed device tokens in the barrier transaction", () => {
		expect(revoke).toContain("pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611))");
		expect(revoke).toContain("update public.device_sessions");
		expect(revoke).toContain("exchanged_at is null");
		expect(revoke).toContain("update public.enrollment_tokens");
		expect(revoke).toContain("label like 'device:%'");
		expect(revoke).toContain("consumed_at is null");
		expect(revoke.indexOf("identity_user_session_state")).toBeLessThan(
			revoke.indexOf("update public.device_sessions"),
		);
		expect(revoke.indexOf("update public.enrollment_tokens")).toBeLessThan(
			revoke.indexOf("identity.sessions.revoked"),
		);
	});

	it("serializes issue with revoke and rejects authorizations at or before the barrier", () => {
		expect(issue).toContain("pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611))");
		expect(issue).toContain("v_session.authorized_at <= v_revoked_before");
		expect(issue.indexOf("v_session.authorized_at <= v_revoked_before")).toBeLessThan(
			issue.indexOf("insert into public.enrollment_tokens"),
		);
		expect(issue.indexOf("pg_advisory_xact_lock")).toBeLessThan(issue.indexOf("for update;"));
	});

	it("keeps both mutation RPCs service-only", () => {
		for (const signature of [
			"mark_identity_session_revoked(uuid, uuid, uuid, text)",
			"issue_device_enrollment_token(text, text, timestamptz)",
		]) {
			expect(migration).toContain(`grant execute on function public.${signature}\n  to service_role`);
			expect(migration).toContain(`revoke all on function public.${signature}\n  from public, anon, authenticated`);
		}
	});
});
