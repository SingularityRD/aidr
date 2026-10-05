import { Buffer } from "node:buffer";
import { describe, expect, it, vi } from "vitest";
import { checkIdentityBarrier, sessionHasOidcProvider } from "../_shared/identity-barrier.ts";

const USER = "11111111-1111-4111-8111-111111111111";
const TENANT = "22222222-2222-4222-8222-222222222222";
const OTHER_TENANT = "22222222-2222-4222-8222-999999999999";
const PROVIDER = "33333333-3333-4333-8333-333333333333";
const OTHER_PROVIDER = "33333333-3333-4333-8333-444444444444";
const SESSION = "44444444-4444-4444-8444-444444444444";
const NOW = Date.now();

function jwt(claims: Record<string, unknown>): string {
	return `header.${Buffer.from(JSON.stringify({ iat: 1_800_000_000, ...claims })).toString("base64url")}.signature`;
}
const OIDC_TOKEN = jwt({ session_id: SESSION });

type SessionRow = { session_id: string; user_id: string; provider_id: string; tenant_id: string; expires_at: string; revoked_at: string | null };

function database(options: {
	requiredOidcProviderId?: string | null;
	requiredSamlProviderId?: string | null;
	requireMfa?: boolean;
	sessions?: SessionRow[];
	sessionError?: boolean;
	level?: "aal1" | "aal2";
}) {
	const queries: string[] = [];
	const db = {
		from(table: string) {
			const filters: Array<[string, unknown]> = [];
			const builder = {
				select: () => builder,
				eq(column: string, value: unknown) {
					filters.push([column, value]);
					return builder;
				},
				async maybeSingle() {
					queries.push(table);
					if (table === "identity_user_session_state")
						return { data: { revoked_before: null, global_revoke_pending_session_id: null }, error: null };
					if (table === "tenant_identity_policies")
						return {
							data: {
								require_mfa: options.requireMfa ?? false,
								required_saml_provider_id: options.requiredSamlProviderId ?? null,
								required_oidc_provider_id: options.requiredOidcProviderId ?? null,
							},
							error: null,
						};
					if (options.sessionError) return { data: null, error: new Error("db_down") };
					const row = (options.sessions ?? []).find((candidate) =>
						filters.every(([column, value]) => (candidate as Record<string, unknown>)[column] === value),
					);
					return { data: row ?? null, error: null };
				},
			};
			return builder;
		},
		auth: { mfa: { getAuthenticatorAssuranceLevel: vi.fn(async () => ({ data: { currentLevel: options.level ?? "aal1" }, error: null })) } },
	} as unknown as Parameters<typeof checkIdentityBarrier>[0];
	return { db, queries };
}

const liveSession: SessionRow = {
	session_id: SESSION,
	user_id: USER,
	provider_id: PROVIDER,
	tenant_id: TENANT,
	expires_at: new Date(NOW + 3_600_000).toISOString(),
	revoked_at: null,
};

describe("OIDC enforcement in the shared identity barrier", () => {
	it("does not consult oidc_sso_sessions for tenants that do not enforce OIDC", async () => {
		const { db, queries } = database({});
		expect(await checkIdentityBarrier(db, OIDC_TOKEN, USER, TENANT)).toEqual({ ok: true });
		expect(queries).not.toContain("oidc_sso_sessions");
	});

	it("allows a session with a live binding for the enforced provider", async () => {
		const { db } = database({ requiredOidcProviderId: PROVIDER, sessions: [liveSession] });
		expect(await checkIdentityBarrier(db, OIDC_TOKEN, USER, TENANT)).toEqual({ ok: true });
	});

	it("denies a session that never completed the OIDC flow (password, email link or SAML session)", async () => {
		const { db } = database({ requiredOidcProviderId: PROVIDER, sessions: [] });
		expect(await checkIdentityBarrier(db, OIDC_TOKEN, USER, TENANT)).toEqual({ ok: false, status: 403, error: "sso_required" });
		const samlOnly = jwt({ session_id: SESSION, amr: [{ method: "sso/saml", provider: PROVIDER }] });
		expect(await checkIdentityBarrier(db, samlOnly, USER, TENANT)).toEqual({ ok: false, status: 403, error: "sso_required" });
	});

	it("denies tokens without a session id and sessions bound to another provider, tenant or user", async () => {
		const { db } = database({ requiredOidcProviderId: PROVIDER, sessions: [{ ...liveSession, provider_id: OTHER_PROVIDER }] });
		expect(await checkIdentityBarrier(db, OIDC_TOKEN, USER, TENANT)).toMatchObject({ ok: false, error: "sso_required" });
		expect(await checkIdentityBarrier(database({ requiredOidcProviderId: PROVIDER, sessions: [liveSession] }).db, jwt({}), USER, TENANT)).toMatchObject({ ok: false, error: "sso_required" });
		const crossTenant = database({ requiredOidcProviderId: PROVIDER, sessions: [{ ...liveSession, tenant_id: OTHER_TENANT }] });
		expect(await checkIdentityBarrier(crossTenant.db, OIDC_TOKEN, USER, TENANT)).toMatchObject({ ok: false, error: "sso_required" });
		const otherUser = database({ requiredOidcProviderId: PROVIDER, sessions: [{ ...liveSession, user_id: "55555555-5555-4555-8555-555555555555" }] });
		expect(await checkIdentityBarrier(otherUser.db, OIDC_TOKEN, USER, TENANT)).toMatchObject({ ok: false, error: "sso_required" });
	});

	it("denies a revoked binding and an expired binding", async () => {
		const revoked = database({ requiredOidcProviderId: PROVIDER, sessions: [{ ...liveSession, revoked_at: new Date(NOW).toISOString() }] });
		expect(await checkIdentityBarrier(revoked.db, OIDC_TOKEN, USER, TENANT)).toMatchObject({ ok: false, error: "sso_required" });
		const expired = database({ requiredOidcProviderId: PROVIDER, sessions: [{ ...liveSession, expires_at: new Date(Date.now() - 1_000).toISOString() }] });
		expect(await checkIdentityBarrier(expired.db, OIDC_TOKEN, USER, TENANT)).toMatchObject({ ok: false, error: "sso_required" });
	});

	it("fails closed when the binding table cannot be read", async () => {
		const { db } = database({ requiredOidcProviderId: PROVIDER, sessionError: true });
		expect(await checkIdentityBarrier(db, OIDC_TOKEN, USER, TENANT)).toEqual({ ok: false, status: 503, error: "identity_policy_unavailable" });
	});

	it("still applies the MFA requirement after SSO", async () => {
		const required = { requiredOidcProviderId: PROVIDER, sessions: [liveSession], requireMfa: true };
		expect(await checkIdentityBarrier(database(required).db, OIDC_TOKEN, USER, TENANT)).toMatchObject({ ok: false, error: "mfa_required" });
		expect(await checkIdentityBarrier(database({ ...required, level: "aal2" }).db, OIDC_TOKEN, USER, TENANT)).toEqual({ ok: true });
	});

	it("reports the binding through the exported helper with an injectable clock", async () => {
		const { db } = database({ sessions: [liveSession] });
		expect(await sessionHasOidcProvider(db, OIDC_TOKEN, USER, PROVIDER, TENANT, NOW)).toBe(true);
		expect(await sessionHasOidcProvider(db, OIDC_TOKEN, USER, PROVIDER, TENANT, NOW + 7_200_000)).toBe(false);
		expect(await sessionHasOidcProvider(db, OIDC_TOKEN, USER, OTHER_PROVIDER, TENANT, NOW)).toBe(false);
	});
});
