import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	dashboardRecoveryUrl,
	formatRecoveryCode,
	generateRecoveryCodes,
	jwtHasAuthenticationMethod,
	jwtIssuedAtMs,
	normalizeEmail,
	normalizeRecoveryCode,
	policyAllowsAssurance,
	sessionPassesRevocationBarrier,
	validateNewPassword,
} from "../identity-security/logic.ts";

const FUNCTIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = resolve(FUNCTIONS_DIR, "..", "..");

function token(payload: Record<string, unknown>): string {
	const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
	return `header.${encoded}.signature`;
}

describe("identity recovery input boundaries", () => {
	it("keeps recovery tokens on a credential-free HTTPS dashboard origin", () => {
		expect(dashboardRecoveryUrl("https://dashboard.example.test/app?next=elsewhere", "grant-1").toString())
			.toBe("https://dashboard.example.test/auth/recover?grant=grant-1");
		expect(dashboardRecoveryUrl("http://localhost:5173").toString())
			.toBe("http://localhost:5173/auth/recover");
		for (const base of [
			"http://dashboard.example.test",
			"http://localhost.example.test",
			"https://user:secret@dashboard.example.test",
			"javascript:alert(1)",
		]) {
			expect(() => dashboardRecoveryUrl(base)).toThrow();
		}
	});

	it("normalizes email and rejects account-enumeration payload tricks", () => {
		expect(normalizeEmail(" Owner@Example.Test ")).toBe("owner@example.test");
		for (const value of [null, "", "owner", "a@b", `${"a".repeat(250)}@x.test`]) {
			expect(normalizeEmail(value)).toBeNull();
		}
	});

	it("formats 160-bit recovery codes and accepts the human-readable form", () => {
		const raw = "00112233445566778899aabbccddeeff00112233";
		const formatted = formatRecoveryCode(raw);
		expect(formatted).toBe("00112-23344-55667-78899-AABBC-CDDEE-FF001-12233");
		expect(normalizeRecoveryCode(formatted)).toBe(raw);
		expect(normalizeRecoveryCode("0011")).toBeNull();
	});

	it("generates a unique, bounded set without storing plaintext", () => {
		let counter = 0;
		const codes = generateRecoveryCodes(8, (bytes) => {
			bytes.fill(counter++);
			return bytes;
		});
		expect(codes).toHaveLength(8);
		expect(new Set(codes).size).toBe(8);
		for (const code of codes) expect(normalizeRecoveryCode(code)).toMatch(/^[0-9a-f]{40}$/);
	});

	it("enforces a meaningful server-side password floor", () => {
		for (const value of ["short", "passwordpassword", " leading-password-1", "trailing-password-1 "]) {
			expect(validateNewPassword(value)).toBeNull();
		}
		expect(validateNewPassword("correct horse battery staple 42")).toBe(
			"correct horse battery staple 42",
		);
	});
});

describe("session and MFA policy", () => {
	it("requires an Auth-issued aal2 session only when the tenant policy enables MFA", () => {
		expect(policyAllowsAssurance(false, "aal1")).toBe(true);
		expect(policyAllowsAssurance(true, "aal1")).toBe(false);
		expect(policyAllowsAssurance(true, null)).toBe(false);
		expect(policyAllowsAssurance(true, "aal2")).toBe(true);
	});

	it("rejects tokens issued at or before a global revocation barrier", () => {
		const jwt = token({ iat: 1_800_000_000 });
		expect(jwtIssuedAtMs(jwt)).toBe(1_800_000_000_000);
		expect(sessionPassesRevocationBarrier(jwt, "2026-01-15T08:00:00.000Z")).toBe(true);
		expect(sessionPassesRevocationBarrier(jwt, "2030-01-01T00:00:00.000Z")).toBe(false);
		expect(sessionPassesRevocationBarrier("malformed", "2026-01-01T00:00:00.000Z")).toBe(
			false,
		);
	});

	it("distinguishes an Auth recovery session from an ordinary password session", () => {
		expect(
			jwtHasAuthenticationMethod(
				token({ amr: [{ method: "recovery", timestamp: 1 }] }),
				"recovery",
			),
		).toBe(true);
		expect(jwtHasAuthenticationMethod(token({ amr: ["recovery"] }), "recovery")).toBe(true);
		expect(
			jwtHasAuthenticationMethod(
				token({ amr: [{ method: "password", timestamp: 1 }] }),
				"recovery",
			),
		).toBe(false);
		expect(jwtHasAuthenticationMethod("invalid", "recovery")).toBe(false);
	});
});

describe("identity-security server wiring", () => {
	const source = readFileSync(join(FUNCTIONS_DIR, "identity-security", "index.ts"), "utf8");
	const migration = readFileSync(
		join(REPO_ROOT, "supabase", "migrations", "20260912000013_identity_security.sql"),
		"utf8",
	);

	it("validates configuration before creating the service client", () => {
		const handler = source.slice(source.indexOf("Deno.serve("));
		expect(handler.indexOf("loadConfig(runtimeEnv,")).toBeGreaterThanOrEqual(0);
		expect(handler.indexOf("loadConfig(runtimeEnv,")).toBeLessThan(handler.indexOf("createClient("));
		expect(source).toContain('from "../_shared/cors.ts"');
		expect(source).toContain("handleCors(req)");
	});

	it("keeps reset responses generic and break-glass delivery explicitly manual", () => {
		expect(source).toContain("auth_provider_if_configured");
		expect(source).not.toMatch(/user_not_found|email_not_found|account_exists/);
		expect(source).toContain('delivery: "manual"');
		expect(source).toContain("consume_identity_recovery_code");
		expect(source).toContain("auth.admin.mfa.deleteFactor");
		expect(source).toContain("auth.admin.generateLink");
	});

	it("revokes refresh sessions and creates an immediate RLS barrier for global recovery", () => {
		expect(source).toContain("auth.admin.signOut(identity.token, scope)");
		expect(source).toContain('auth.admin.signOut(identity.token, "global")');
		expect(source).toContain("mark_identity_session_revoked");
		expect(source).toContain('jwtHasAuthenticationMethod(identity.token, "recovery")');
		const recovery = source.slice(
			source.indexOf('if (body.action === "complete_password_recovery")'),
			source.indexOf('const requestedTenant ='),
		);
		const barrierAt = recovery.indexOf('db.rpc("mark_identity_session_revoked"');
		const signOutAt = recovery.indexOf('db.auth.admin.signOut(identity.token, "global")');
		const passwordAt = recovery.indexOf("db.auth.admin.updateUserById");
		expect(barrierAt).toBeGreaterThanOrEqual(0);
		expect(signOutAt).toBeGreaterThan(barrierAt);
		expect(passwordAt).toBeGreaterThan(signOutAt);
		expect(migration).toContain("tenant_identity_access_allowed");
		expect(migration).toContain("as restrictive for all to authenticated");
		expect(migration).toContain("auth.jwt()->>'aal'");
		expect(migration).toContain("auth.jwt()->>'iat'");
	});

	it("stores only recovery-code hashes and consumes each code and grant atomically", () => {
		expect(migration).toContain("code_hash text not null unique");
		expect(migration).not.toMatch(/code_plain|plaintext_code|recovery_code text/);
		expect(migration).toContain("pg_advisory_xact_lock");
		expect(migration).toContain("used_at is null and c.expires_at > now()");
		expect(migration).toContain("consume_identity_password_recovery_grant");
		expect(migration).toContain("used_at is null and expires_at > now()");
	});

	it("keeps identity tables and mutation RPCs service-only", () => {
		expect(migration).toContain("from public, anon, authenticated");
		for (const name of [
			"set_tenant_identity_policy",
			"issue_identity_recovery_codes",
			"consume_identity_recovery_code",
			"consume_identity_password_recovery_grant",
			"mark_identity_session_revoked",
		]) {
			expect(migration).toMatch(new RegExp(`grant execute on function public\\.${name}\\([\\s\\S]*?to service_role`));
		}
	});
});
