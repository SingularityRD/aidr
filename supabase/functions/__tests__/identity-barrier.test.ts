import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";

const FUNCTIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function jwt(issuedAt: number, amr?: unknown): string {
	return `header.${Buffer.from(JSON.stringify({ iat: issuedAt, amr })).toString("base64url")}.signature`;
}

function database(options: {
	revokedBefore?: string | null;
	pendingSessionId?: string | null;
	stateError?: boolean;
	requireMfa?: boolean;
	requiredSamlProviderId?: string | null;
	policyError?: boolean;
	level?: "aal1" | "aal2";
	assuranceError?: boolean;
} = {}) {
	const requests: Array<{ table: string; column: string; value: string }> = [];
	const assurance = vi.fn(async () => ({
		data: options.assuranceError ? null : { currentLevel: options.level ?? "aal1" },
		error: options.assuranceError ? new Error("auth_down") : null,
	}));
	const db = {
		from(table: string) {
			return {
				select(_columns: string) {
					return {
						eq(column: string, value: string) {
							requests.push({ table, column, value });
							return {
								async maybeSingle() {
									if (table === "identity_user_session_state") return {
										data: {
											revoked_before: options.revokedBefore ?? null,
											global_revoke_pending_session_id: options.pendingSessionId ?? null,
										},
										error: options.stateError ? new Error("db_down") : null,
									};
									return {
										data: {
											require_mfa: options.requireMfa ?? false,
											required_saml_provider_id: options.requiredSamlProviderId ?? null,
										},
										error: options.policyError ? new Error("db_down") : null,
									};
								},
							};
						},
					};
				},
			};
		},
		auth: { mfa: { getAuthenticatorAssuranceLevel: assurance } },
	} as unknown as Parameters<typeof checkIdentityBarrier>[0];
	return { db, requests, assurance };
}

describe("service-role identity barrier", () => {
	const token = jwt(1_800_000_000);
	const user = "11111111-1111-4111-8111-111111111111";
	const tenant = "22222222-2222-4222-8222-222222222222";
	const provider = "33333333-3333-4333-8333-333333333333";

	it("rejects revoked or unverifiable sessions before tenant reads", async () => {
		for (const accessToken of [token, "malformed"]) {
			const { db, requests } = database({ revokedBefore: "2030-01-01T00:00:00.000Z" });
			expect(await checkIdentityBarrier(db, accessToken, user, tenant)).toEqual({ ok: false, status: 401, error: "session_revoked" });
			expect(requests).toEqual([{ table: "identity_user_session_state", column: "user_id", value: user }]);
		}
	});

	it("rejects every session while global Auth revocation is pending", async () => {
		const pending = database({
			pendingSessionId: "33333333-3333-4333-8333-333333333333",
		});
		expect(await checkIdentityBarrier(pending.db, token, user, tenant)).toEqual({
			ok: false,
			status: 401,
			error: "session_revoked",
		});
		expect(pending.assurance).not.toHaveBeenCalled();
	});

	it("fails closed when either security table or Auth assurance is unavailable", async () => {
		expect(await checkIdentityBarrier(database({ stateError: true }).db, token, user, tenant)).toEqual({ ok: false, status: 503, error: "identity_state_unavailable" });
		expect(await checkIdentityBarrier(database({ policyError: true }).db, token, user, tenant)).toEqual({ ok: false, status: 503, error: "identity_policy_unavailable" });
		expect(await checkIdentityBarrier(database({ requireMfa: true, assuranceError: true }).db, token, user, tenant)).toEqual({ ok: false, status: 503, error: "assurance_unavailable" });
	});

	it("requires Auth-confirmed aal2 only for tenants that enable MFA", async () => {
		const optional = database();
		expect(await checkIdentityBarrier(optional.db, token, user, tenant)).toEqual({ ok: true });
		expect(optional.assurance).not.toHaveBeenCalled();
		expect(await checkIdentityBarrier(database({ requireMfa: true }).db, token, user, tenant)).toEqual({ ok: false, status: 403, error: "mfa_required" });
		expect(await checkIdentityBarrier(database({ requireMfa: true, level: "aal2" }).db, token, user, tenant)).toEqual({ ok: true });
	});

	it("requires the configured SAML provider on the same AMR entry after MFA", async () => {
		const configured = { requiredSamlProviderId: provider };
		for (const amr of [
			undefined,
			"not-an-array",
			[{ method: "sso/saml", provider: tenant }],
			[{ method: "sso/saml" }, { method: "totp", provider }],
		]) {
			expect(await checkIdentityBarrier(database(configured).db, jwt(1_800_000_000, amr), user, tenant))
				.toEqual({ ok: false, status: 403, error: "sso_required" });
		}
		const samlAfterMfa = jwt(1_800_000_000, [
			{ method: "totp" }, { method: "sso/saml", provider },
		]);
		expect(await checkIdentityBarrier(database(configured).db, samlAfterMfa, user, tenant))
			.toEqual({ ok: true });
		expect(await checkIdentityBarrier(database({ ...configured, requireMfa: true }).db, samlAfterMfa, user, tenant))
			.toEqual({ ok: false, status: 403, error: "mfa_required" });
		expect(await checkIdentityBarrier(database({ ...configured, requireMfa: true, level: "aal2" }).db, samlAfterMfa, user, tenant))
			.toEqual({ ok: true });
	});

	it("checks global revocation without inventing a tenant for pre-enrollment requests", async () => {
		const { db, requests } = database();
		expect(await checkIdentityBarrier(db, token, user)).toEqual({ ok: true });
		expect(requests).toHaveLength(1);
	});
});

describe("canonical service-role user routes", () => {
	it("calls the barrier in the enumerated JWT-authenticated routes", () => {
		for (const route of [
			"api-keys", "audit-export", "autosecops-runtime", "billing-checkout",
			"device-verify", "enrollment-tokens", "fleet-keys", "oauth-callback", "operator-admin", "pilot-admin",
			"pilot-apply", "pilot-status", "policy-management", "team-invite",
			"tenant-settings", "approval-requests", "compliance-report", "governance-digest", "ai-governance",
		]) {
			const source = readFileSync(join(FUNCTIONS_DIR, route, "index.ts"), "utf8");
			expect(source, route).toContain("checkIdentityBarrier(");
		}
	});
});
