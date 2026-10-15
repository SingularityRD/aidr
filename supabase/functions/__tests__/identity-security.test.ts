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
	jwtHasSamlProvider,
	jwtSamlProviderId,
	jwtIssuedAtMs,
	jwtSessionId,
	normalizeEmail,
	normalizeRecoveryCode,
	normalizeRecoveryTokenHash,
	policyAllowsAssurance,
	recoveryCodeIssueError,
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
		expect(dashboardRecoveryUrl("https://dashboard.example.test/app?next=elsewhere").toString())
			.toBe("https://dashboard.example.test/auth/recover");
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

	it("accepts only the provider's fixed-size recovery token hash", () => {
		expect(normalizeRecoveryTokenHash("A".repeat(64))).toBe("a".repeat(64));
		for (const value of [null, "", "a".repeat(63), "g".repeat(64), `${"a".repeat(64)}?next=x`]) {
			expect(normalizeRecoveryTokenHash(value)).toBeNull();
		}
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

	it("allows recovery-code issuance only to the same Auth identity at AAL2", () => {
		const adminA = "11111111-1111-4111-8111-111111111111";
		const sharedMember = "22222222-2222-4222-8222-222222222222";
		expect(recoveryCodeIssueError(adminA, sharedMember)).toBe("recovery_code_issue_forbidden");
		expect(policyAllowsAssurance(true, "aal1")).toBe(false);
		expect(policyAllowsAssurance(true, "aal2")).toBe(true);
		expect(recoveryCodeIssueError(sharedMember, sharedMember)).toBeNull();
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

	it("keeps the fractional barrier while identifying the new OTP session", () => {
		const sessionId = "22222222-2222-4222-8222-222222222222";
		const jwt = token({ iat: 1_800_000_000, session_id: sessionId, amr: [{ method: "otp" }] });
		expect(jwtSessionId(jwt)).toBe(sessionId);
		expect(sessionPassesRevocationBarrier(jwt, "2027-01-15T08:00:00.500Z")).toBe(false);
		expect(jwtHasAuthenticationMethod(jwt, "otp")).toBe(true);
	});

	it("accepts the pinned GoTrue OTP AMR but not a fabricated recovery AMR", () => {
		expect(
			jwtHasAuthenticationMethod(token({ amr: [{ method: "otp", timestamp: 1 }] }), "otp"),
		).toBe(true);
		expect(jwtHasAuthenticationMethod(token({ amr: ["otp"] }), "otp")).toBe(true);
		expect(
			jwtHasAuthenticationMethod(token({ amr: [{ method: "recovery", timestamp: 1 }] }), "otp"),
		).toBe(false);
		expect(jwtHasAuthenticationMethod("invalid", "otp")).toBe(false);
	});

	it("matches method and provider in one SAML AMR entry regardless of MFA order", () => {
		const provider = "33333333-3333-4333-8333-333333333333";
		expect(jwtHasSamlProvider(token({ amr: [{ method: "totp" }, { method: "sso/saml", provider }] }), provider)).toBe(true);
		expect(jwtSamlProviderId(token({ amr: [{ method: "totp" }, { method: "sso/saml", provider }] }))).toBe(provider);
		for (const amr of [
			undefined,
			"not-an-array",
			[{ method: "sso/saml", provider: "other" }],
			[{ method: "sso/saml" }, { method: "totp", provider }],
		]) expect(jwtHasSamlProvider(token({ amr }), provider)).toBe(false);
		for (const amr of [
			undefined,
			[{ method: "password" }],
			[{ method: "sso/saml", provider: "bad" }],
			[{ method: "sso/saml", provider }, { method: "sso/saml", provider }],
		]) expect(jwtSamlProviderId(token({ amr }))).toBeNull();
	});

});

describe("identity-security server wiring", () => {
	const source = readFileSync(join(FUNCTIONS_DIR, "identity-security", "index.ts"), "utf8");
	it("binds only verified SAML subjects before discovering tenant memberships", () => {
		const bootstrap = source.slice(source.indexOf('if (body.action === "bootstrap")'));
		expect(bootstrap.indexOf('jwtSamlProviderId(identity.token)')).toBeLessThan(bootstrap.indexOf('db.rpc("scim_bind_saml_identity"'));
		expect(bootstrap.indexOf('db.rpc("scim_bind_saml_identity"')).toBeLessThan(bootstrap.indexOf('.from("tenant_members")'));
	});
	const config = readFileSync(join(REPO_ROOT, "supabase", "config.toml"), "utf8");
	const recoveryTemplate = readFileSync(
		join(REPO_ROOT, "supabase", "templates", "recovery.html"),
		"utf8",
	);
	const migration = readFileSync(
		join(REPO_ROOT, "supabase", "migrations", "20260912000013_identity_security.sql"),
		"utf8",
	);
	const recoveryGrantMigration = readFileSync(
		join(REPO_ROOT, "supabase", "migrations", "20260922000004_recovery_grant_session_binding.sql"),
		"utf8",
	);
	const recoveryProofMigration = readFileSync(
		join(
			REPO_ROOT,
			"supabase",
			"migrations",
			"20260922000007_identity_recovery_and_team_barrier_hardening.sql",
		),
		"utf8",
	);
	const recoverySagaMigration = readFileSync(
		join(
			REPO_ROOT,
			"supabase",
			"migrations",
			"20260922000008_identity_recovery_completion_saga.sql",
		),
		"utf8",
	);
	const recoverySelfMigration = readFileSync(
		join(REPO_ROOT, "supabase", "migrations", "20260924000001_recovery_code_self_only.sql"),
		"utf8",
	);

	it("allows recovery codes only for the authenticated member's own account", () => {
		const rotate = source.slice(
			source.indexOf('if (body.action === "rotate_recovery_codes")'),
			source.indexOf('if (body.action === "revoke_sessions")'),
		);
		expect(rotate).toContain('identity.currentLevel !== "aal2"');
		expect(rotate).toContain("recoveryCodeIssueError(identity.user.id, targetUserId)");
		expect(rotate).not.toMatch(/member\.role.*owner.*admin/);
		expect(rotate.indexOf('identity.currentLevel !== "aal2"')).toBeLessThan(rotate.indexOf("generateRecoveryCodes()"));
		expect(rotate.indexOf("recoveryCodeIssueError(identity.user.id, targetUserId)")).toBeLessThan(rotate.indexOf("generateRecoveryCodes()"));
		expect(recoverySelfMigration).toContain("p_actor_user_id <> p_target_user_id");
		expect(recoverySelfMigration).toContain("m.user_id = p_actor_user_id");
		expect(recoverySelfMigration).toContain("created_by <> user_id and used_at is null");
		expect(recoverySelfMigration).toMatch(/revoke all on function public\.issue_identity_recovery_codes[\s\S]*from public, anon, authenticated/);
		expect(recoverySelfMigration).toMatch(/grant execute on function public\.issue_identity_recovery_codes[\s\S]*to service_role/);
	});

	it("validates configuration before creating the service client", () => {
		const handler = source.slice(source.indexOf("Deno.serve("));
		expect(handler.indexOf("loadConfig(runtimeEnv,")).toBeGreaterThanOrEqual(0);
		expect(handler.indexOf("loadConfig(runtimeEnv,")).toBeLessThan(handler.search(/createClient(?:<[^>]+>)?\(/));
		expect(source).toContain('from "../_shared/cors.ts"');
		expect(source).toContain("handleCors(req)");
	});

	it("audits a break-glass MFA reset before any factor is deleted (SEC-5)", () => {
		const breakGlass = source.slice(source.indexOf('if (body.action === "break_glass_recover")'));
		const auditAt = breakGlass.indexOf('action: "identity.break_glass.token_issued"');
		const failClosedAt = breakGlass.indexOf('if (!logged) return corsJson(req, 503, { error: "recovery_unavailable" });');
		const listAt = breakGlass.indexOf("auth.admin.mfa.listFactors");
		const deleteAt = breakGlass.indexOf("auth.admin.mfa.deleteFactor");
		expect(auditAt).toBeGreaterThan(0);
		expect(failClosedAt).toBeGreaterThan(auditAt);
		expect(listAt).toBeGreaterThan(failClosedAt);
		expect(deleteAt).toBeGreaterThan(listAt);
	});

	it("keeps reset responses generic and break-glass secrets out of links", () => {
		expect(source).toContain("auth_provider_if_configured");
		expect(source).not.toMatch(/user_not_found|email_not_found|account_exists/);
		expect(source).toContain('delivery: "in_app"');
		expect(source).toContain("begin_identity_break_glass_recovery");
		expect(source).toContain("complete_identity_break_glass_recovery");
		expect(source).toContain("auth.admin.mfa.deleteFactor");
		expect(source).toContain("auth.admin.generateLink");
		expect(source).toContain("properties?.hashed_token");
		expect(source).toContain("recovery_token_hash: tokenHash");
		expect(source).toContain("dashboardRecoveryUrl(config.values.AIDR_DASHBOARD_URL).toString()");
		expect(source).not.toContain("dashboardRecoveryUrl(config.values.AIDR_DASHBOARD_URL, grantId)");
		expect(source).not.toContain("properties?.action_link");
		expect(source).not.toContain("recovery_link:");
		expect(source.indexOf("auth.resetPasswordForEmail")).toBeLessThan(
			source.indexOf('db.rpc("issue_identity_password_recovery_grant"'),
		);
		expect(source.indexOf("auth.admin.generateLink")).toBeLessThan(
			source.indexOf('"issue_identity_break_glass_password_recovery_grant"'),
		);
		expect(source).toContain("p_proof_challenge_hash: recoveryChallenge");
		expect(source).toContain("p_proof_verifier: recoveryVerifier");
		const publicResetResponse = source.slice(
			source.indexOf("return corsJson(req, 202"),
			source.indexOf("if (body.action === \"break_glass_recover\")"),
		);
		expect(publicResetResponse).not.toContain("grant_id");
	});

	it("ships an OTP recovery template without putting a credential in its URL", () => {
		expect(config).toContain("[auth.email.template.recovery]");
		expect(config).toContain('content_path = "./supabase/templates/recovery.html"');
		expect(config).toContain('"http://localhost:5173/auth/recover"');
		expect(recoveryTemplate).toContain("{{ .Token }}");
		expect(recoveryTemplate).toContain('href="{{ .RedirectTo }}"');
		expect(recoveryTemplate).toContain("same browser");
		expect(recoveryTemplate).toContain("within 2 minutes");
		expect(recoveryTemplate).not.toMatch(/TokenHash|ConfirmationURL|token_hash|access_token/);
	});

	it("revokes refresh sessions and creates an immediate RLS barrier for global recovery", () => {
		expect(source).toContain('auth.admin.signOut(identity.token, "others")');
		expect(source).toContain('auth.admin.signOut(identity.token, "global")');
		expect(source).toContain('auth.admin.signOut(recoveryIdentity.token, "global")');
		expect(source).toContain("mark_identity_session_revoked");
		expect(source.indexOf('body.action === "revoke_sessions" && body.scope === "global"')).toBeLessThan(
			source.indexOf("const requestedTenant ="),
		);
		expect(source).toContain('jwtHasAuthenticationMethod(recoveryIdentity.token, "otp")');
		expect(source).toContain("bind_identity_password_recovery_grant");
		const recovery = source.slice(
			source.indexOf('body.action === "bind_password_recovery_grant"'),
			source.indexOf('if (body.action === "revoke_sessions" && body.scope === "global")'),
		);
		const beginAt = recovery.indexOf('db.rpc("begin_identity_password_recovery_completion"');
		const barrierAt = recovery.indexOf('db.rpc("mark_identity_session_revoked"');
		const signOutAt = recovery.indexOf('db.auth.admin.signOut(recoveryIdentity.token, "global")');
		const passwordAt = recovery.indexOf("db.auth.admin.updateUserById");
		const completeAt = recovery.indexOf('"complete_identity_password_recovery_completion"');
		expect(beginAt).toBeGreaterThanOrEqual(0);
		expect(barrierAt).toBeGreaterThan(beginAt);
		expect(signOutAt).toBeGreaterThan(barrierAt);
		expect(passwordAt).toBeGreaterThan(signOutAt);
		expect(completeAt).toBeGreaterThan(passwordAt);
		const globalRevoke = source.slice(
			source.indexOf('if (body.action === "revoke_sessions" && body.scope === "global")'),
			source.indexOf("const identity = await authenticate(db, req);"),
		);
		expect(globalRevoke.indexOf('"begin_identity_global_revocation"')).toBeGreaterThanOrEqual(0);
		expect(globalRevoke.indexOf('db.auth.admin.signOut(identity.token, "global")')).toBeGreaterThan(
			globalRevoke.indexOf('"begin_identity_global_revocation"'),
		);
		expect(globalRevoke.indexOf('"complete_identity_global_revocation"')).toBeGreaterThan(
			globalRevoke.indexOf('db.auth.admin.signOut(identity.token, "global")'),
		);
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
		expect(recoveryGrantMigration).toContain("p_session_id uuid");
		expect(recoveryGrantMigration).toContain("session_id = p_session_id");
		expect(recoveryGrantMigration).toContain("bound_at is not null");
		expect(recoveryProofMigration).toContain("proof_challenge_hash text");
		expect(recoveryProofMigration).toContain("from auth.sessions s");
		expect(recoveryProofMigration).toContain("u.recovery_sent_at = g.auth_recovery_sent_at");
		expect(recoveryProofMigration).toContain("v_session_created_at <= v_state.revoked_before");
		expect(recoverySagaMigration).toContain("begin_identity_break_glass_recovery");
		expect(recoverySagaMigration).toContain("complete_identity_break_glass_recovery");
		expect(recoverySagaMigration).toContain("begin_identity_password_recovery_completion");
		expect(recoverySagaMigration).toContain("complete_identity_password_recovery_completion");
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
		for (const name of [
			"issue_identity_password_recovery_grant",
			"issue_identity_break_glass_password_recovery_grant",
			"bind_identity_password_recovery_grant",
			"consume_identity_password_recovery_grant",
		]) {
			expect(`${recoveryGrantMigration}\n${recoveryProofMigration}`).toMatch(
				new RegExp(`grant execute on function public\\.${name}\\([\\s\\S]*?to service_role`),
			);
		}
		for (const name of [
			"begin_identity_break_glass_recovery",
			"complete_identity_break_glass_recovery",
			"begin_identity_password_recovery_completion",
			"complete_identity_password_recovery_completion",
		]) {
			expect(recoverySagaMigration).toMatch(
				new RegExp(`grant execute on function public\\.${name}\\([\\s\\S]*?to service_role`),
			);
		}
	});
});
