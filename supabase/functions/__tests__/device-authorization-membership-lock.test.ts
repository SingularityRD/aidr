import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const migration = readFileSync(
	join(ROOT, "supabase", "migrations", "20260924000003_device_authorization_membership_lock.sql"),
	"utf8",
);

describe("atomic device authorization membership boundary", () => {
	it("locks and rechecks active tenant membership before binding the device code", () => {
		const body = migration.split("create or replace function public.authorize_device_session(")[1]?.split("\n$$;")[0] ?? "";
		expect(body).toContain("for share of m, t");
		expect(body).toContain("m.role in ('owner', 'admin', 'member')");
		expect(body).toContain("m.expires_at > clock_timestamp()");
		expect(body).toContain("t.status = 'active'");
		expect(body.indexOf("if not found then return; end if;\n\n  update public.device_sessions"))
			.toBeGreaterThanOrEqual(0);
		expect(body).toContain("and (d.tenant_id is null or d.tenant_id = v_tenant_id)");
	});

	it("keeps device binding and its audit receipt in the same restricted RPC", () => {
		expect(migration).toContain("insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)");
		expect(migration).toContain("revoke all on function public.authorize_device_session(text, uuid, uuid, timestamptz)");
		expect(migration).toContain("from public, anon, authenticated");
		expect(migration).toContain("grant execute on function public.authorize_device_session(text, uuid, uuid, timestamptz)");
		expect(migration).toContain("to service_role");
	});
});
