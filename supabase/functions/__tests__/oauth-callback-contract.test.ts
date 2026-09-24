// Contract suite for the `oauth-callback` Edge Function (AIDR-019 / TEN-03).
//
// The route keeps its historical name: it accepts a team invitation for an
// ALREADY authenticated session. There is no provider code/state exchange in
// this function. The browser call site is
// `packages/dashboard/src/enterprise/auth.tsx`, which posts `{ invite_token }`
// and refuses to report an accepted invitation unless the function answers
// `{"ok":true}`. The invite token is therefore the single-use credential, the
// stored invitation row is its "state", and `accept_team_invitation` is the
// privileged redemption of it.
//
// This file is named in `docs/production-readiness/edge-function-contract-manifest.json`,
// so the browser-invoked function cannot ship without an executable contract.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	createClientCalls: [] as unknown[][],
	db: null as unknown,
}));

// The Edge Function imports Supabase through Deno's `npm:` specifier, which a
// Node test runner cannot resolve. The factory only exists to prove that the
// handler builds its client from validated configuration; the suite drives the
// handler with an injected database.
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: (...args: unknown[]) => {
		mocks.createClientCalls.push(args);
		if (!mocks.db) {
			throw new Error("createClient must be injected through OAuthCallbackDeps.db");
		}
		return mocks.db;
	},
}));

// The Edge runtime provides `Deno.env` and `Deno.serve`; the test process does
// not. The env stub delegates to `process.env` so `vi.stubEnv` drives the same
// values the production `runtimeEnv` reader would see. `serve` records the
// handler so the suite can prove the runtime entry point is wired to the
// exported factory.
const serveCalls: unknown[] = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: {
		get: (name: string) => process.env[name],
	},
	serve: (handler: unknown) => {
		serveCalls.push(handler);
	},
};

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const oauthSource = readFileSync(
	join(ROOT, "supabase", "functions", "oauth-callback", "index.ts"),
	"utf8",
);

const DASHBOARD_ORIGIN = "https://app.aidr.example";
const EVIL_ORIGIN = "https://evil.example";
const FUNCTION_URL = "https://project.supabase.co/functions/v1/oauth-callback";
const PROJECT_URL = "https://project.supabase.co";
const SERVICE_ROLE_SECRET = "service-role-secret-value-not-for-callers";
const BEARER_TOKEN = "valid-token";
const USER = "11111111-1111-4111-8111-111111111111";
const TENANT = "22222222-2222-4222-8222-222222222222";
const OTHER_TENANT = "33333333-3333-4333-8333-333333333333";
const INVITE_TOKEN = ["01234567", "89abcdef"].join("").repeat(4);
const OTHER_INVITE_TOKEN = ["fedcba98", "76543210"].join("").repeat(4);

const environment: Record<string, string> = {
	SUPABASE_URL: PROJECT_URL,
	SUPABASE_SERVICE_ROLE_KEY: SERVICE_ROLE_SECRET,
	AIDR_ALLOWED_ORIGINS: `${DASHBOARD_ORIGIN},https://staging.aidr.example`,
};

/** Independent SHA-256 of the credential, so the handler cannot agree with itself. */
function hashOf(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

interface InvitationRow {
	tenant_id: string;
	accepted_at: string | null;
	expires_at: string;
}

function invitationRow(tenantId: string, overrides: Partial<InvitationRow> = {}): InvitationRow {
	return {
		tenant_id: tenantId,
		accepted_at: null,
		expires_at: "2099-01-01T00:00:00.000Z",
		...overrides,
	};
}

type SupabaseResult = { data: unknown; error: unknown };

interface RpcCall {
	name: string;
	args: Record<string, unknown>;
}

interface DbCalls {
	from: string[];
	tokenHashes: string[];
	policyTenants: string[];
	rpc: RpcCall[];
	redemptions: number;
}

interface DbOptions {
	/** Stored invitations, keyed by token hash: the single-use "state" store. */
	invitations?: Record<string, InvitationRow>;
	invitationError?: unknown;
	requireMfa?: boolean;
	policyError?: unknown;
	stateError?: unknown;
	revokedBefore?: string | null;
	user?: { id: string } | null;
	userThrows?: boolean;
	mfaLevel?: string;
	rpc?: (name: string, args: Record<string, unknown>) => SupabaseResult;
	rpcThrows?: boolean;
	rpcError?: { code?: string } | null;
	rpcData?: unknown;
}

/**
 * Minimal PostgREST-shaped double: chainable, `.maybeSingle()`-terminated, and
 * recording every credential-bearing argument so a test can assert on what the
 * handler actually sent. The `accept_team_invitation` double mirrors the SQL
 * contract in `supabase/migrations/20260911000001_team_invitations.sql`: the
 * row must exist, must not be expired, and is consumed (replay refused) once.
 */
function database(options: DbOptions = {}) {
	const invitations = options.invitations ?? {};
	const calls: DbCalls = { from: [], tokenHashes: [], policyTenants: [], rpc: [], redemptions: 0 };
	const user = options.user === undefined ? { id: USER } : options.user;

	const builder = (table: string) => {
		let tokenHash: string | null = null;
		const query = {
			select: () => query,
			eq: (column: string, value: string) => {
				if (table === "team_invitations" && column === "token_hash") {
					tokenHash = value;
					calls.tokenHashes.push(value);
				}
				if (table === "tenant_identity_policies" && column === "tenant_id") {
					calls.policyTenants.push(value);
				}
				return query;
			},
			limit: () => query,
			maybeSingle: async (): Promise<SupabaseResult> => {
				if (table === "identity_user_session_state") {
					return { data: { revoked_before: options.revokedBefore ?? null }, error: options.stateError ?? null };
				}
				if (table === "tenant_identity_policies") {
					return { data: { require_mfa: options.requireMfa === true }, error: options.policyError ?? null };
				}
				if (table === "team_invitations") {
					if (options.invitationError !== undefined) return { data: null, error: options.invitationError };
					const row = tokenHash ? invitations[tokenHash] : undefined;
					return { data: row ? { tenant_id: row.tenant_id } : null, error: null };
				}
				return { data: null, error: null };
			},
		};
		return query;
	};

	const db = {
		auth: {
			getUser: vi.fn(async (token: string): Promise<SupabaseResult> => {
				if (options.userThrows) throw new Error("auth_transport_down");
				if (token !== BEARER_TOKEN || !user) {
					return { data: { user: null }, error: new Error("invalid_jwt") };
				}
				return { data: { user }, error: null };
			}),
			mfa: {
				getAuthenticatorAssuranceLevel: vi.fn(async () => ({
					data: { currentLevel: options.mfaLevel ?? "aal1" },
					error: null,
				})),
			},
		},
		from: vi.fn((table: string) => {
			calls.from.push(table);
			return builder(table);
		}),
		rpc: vi.fn(async (name: string, args: Record<string, unknown>): Promise<SupabaseResult> => {
			calls.rpc.push({ name, args });
			if (options.rpc) return options.rpc(name, args);
			if (options.rpcThrows) throw new Error("redemption_transport_timeout");
			if (options.rpcError !== undefined) return { data: null, error: options.rpcError };
			if (options.rpcData !== undefined) return { data: options.rpcData, error: null };
			const row = invitations[String(args.p_hash)];
			if (!row || row.accepted_at !== null || Date.parse(row.expires_at) <= Date.now()) {
				return { data: null, error: { code: "42501" } };
			}
			row.accepted_at = "2026-01-01T00:00:00.000Z";
			calls.redemptions += 1;
			return { data: row.tenant_id, error: null };
		}),
	};
	return { db, calls };
}

type Handle = (request: Request) => Promise<Response>;

/**
 * `AIDR_ALLOWED_ORIGINS` is read once at module scope by the shared CORS helper,
 * so every case re-imports the handler after its environment is stubbed.
 */
async function handlerWith(
	options: DbOptions = {},
	env: Record<string, string | undefined> = {},
	deps: Record<string, unknown> = {},
): Promise<{ handle: Handle; db: ReturnType<typeof database>["db"]; calls: DbCalls }> {
	for (const [key, value] of Object.entries(environment)) vi.stubEnv(key, value);
	for (const [key, value] of Object.entries(env)) vi.stubEnv(key, value);
	vi.resetModules();
	const { db, calls } = database(options);
	const mod = await import("../oauth-callback/index.ts");
	const handle = mod.createOAuthCallbackHandler({ db: db as never, ...deps }) as Handle;
	return { handle, db, calls };
}

function post(
	body: unknown,
	headers: Record<string, string> = {},
): Request {
	return new Request(FUNCTION_URL, {
		method: "POST",
		headers: {
			Origin: DASHBOARD_ORIGIN,
			Authorization: `Bearer ${BEARER_TOKEN}`,
			"Content-Type": "application/json",
			...headers,
		},
		body: JSON.stringify(body),
	});
}

function rawPost(body: string, headers: Record<string, string> = {}): Request {
	return new Request(FUNCTION_URL, {
		method: "POST",
		headers: {
			Origin: DASHBOARD_ORIGIN,
			Authorization: `Bearer ${BEARER_TOKEN}`,
			"Content-Type": "application/json",
			...headers,
		},
		body,
	});
}

async function readJson(response: Response): Promise<{ status: number; raw: string; body: Record<string, unknown> }> {
	const raw = await response.text();
	return { status: response.status, raw, body: JSON.parse(raw) as Record<string, unknown> };
}

const RESPONSE_FIELDS = new Set(["ok", "team_id", "error", "missing", "invalid"]);
// A credential would have to appear as a field or assignment. The fixed error
// codes `missing_access_token` / `invalid_access_token` are not assignments.
const CREDENTIAL_ASSIGNMENT =
	/["']?(?:access_token|refresh_token|provider_token|provider_refresh_token|id_token|client_secret)["']?\s*[:=]/i;

/**
 * The response must carry an outcome and nothing else: no bearer token, no
 * service-role secret, and no credential supplied by the caller.
 */
function expectNoCredentialLeak(raw: string, body: Record<string, unknown>): void {
	expect(raw).not.toContain(BEARER_TOKEN);
	expect(raw).not.toContain(SERVICE_ROLE_SECRET);
	expect(raw).not.toContain(INVITE_TOKEN);
	expect(raw).not.toContain(OTHER_INVITE_TOKEN);
	expect(raw).not.toMatch(CREDENTIAL_ASSIGNMENT);
	for (const key of Object.keys(body)) {
		expect(RESPONSE_FIELDS.has(key), `unexpected response field: ${key}`).toBe(true);
	}
}

function liveHandle(tenantId: string, options: DbOptions = {}) {
	return handlerWith({ invitations: { [hashOf(INVITE_TOKEN)]: invitationRow(tenantId) }, ...options });
}

beforeEach(() => {
	mocks.createClientCalls.length = 0;
	mocks.db = null;
	for (const [key, value] of Object.entries(environment)) vi.stubEnv(key, value);
});

afterEach(() => {
	vi.unstubAllEnvs();
	vi.restoreAllMocks();
	vi.resetModules();
	mocks.db = null;
});

describe("oauth-callback Edge contract: origin and preflight", () => {
	it("answers an OPTIONS preflight from an allowlisted origin without touching the database", async () => {
		const { handle, db } = await handlerWith();
		const response = await handle(
			new Request(FUNCTION_URL, { method: "OPTIONS", headers: { Origin: DASHBOARD_ORIGIN } }),
		);

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true });
		expect(response.headers.get("Access-Control-Allow-Origin")).toBe(DASHBOARD_ORIGIN);
		expect(response.headers.get("Access-Control-Allow-Methods")).toContain("OPTIONS");
		expect(response.headers.get("Vary")).toContain("Origin");
		expect(db.from).not.toHaveBeenCalled();
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(db.rpc).not.toHaveBeenCalled();
	});

	it("refuses an origin that is not in AIDR_ALLOWED_ORIGINS before any provider or database work", async () => {
		const { handle, db, calls } = await liveHandle(TENANT, {});
		const response = await handle(post({ invite_token: INVITE_TOKEN }, { Origin: EVIL_ORIGIN }));
		const { status, raw, body } = await readJson(response);

		expect(status).toBe(403);
		expect(body).toEqual({ error: "origin_not_allowed" });
		expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
		// A valid session and a valid invitation are still refused: the origin
		// check is the first guard, so no credential is ever inspected.
		expect(db.from).not.toHaveBeenCalled();
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(calls.tokenHashes).toEqual([]);
		expect(calls.rpc).toEqual([]);
		expectNoCredentialLeak(raw, body);
	});

	it("fails closed for every browser origin when no allowlist is configured", async () => {
		for (const origin of [DASHBOARD_ORIGIN, EVIL_ORIGIN]) {
			const { handle, db } = await handlerWith({}, { AIDR_ALLOWED_ORIGINS: undefined });
			const response = await handle(post({ invite_token: INVITE_TOKEN }, { Origin: origin }));
			expect(response.status, origin).toBe(403);
			expect(await response.json()).toMatchObject({ error: "origin_not_allowed" });
			expect(db.from).not.toHaveBeenCalled();
		}

		// A non-browser caller (no Origin header) is not a CORS decision and is
		// still served, so an unconfigured allowlist cannot break server-to-server use.
		const { handle } = await liveHandle(TENANT);
		const response = await handle(
			new Request(FUNCTION_URL, {
				method: "POST",
				headers: { Authorization: `Bearer ${BEARER_TOKEN}` },
				body: JSON.stringify({ invite_token: INVITE_TOKEN }),
			}),
		);
		expect(response.status).toBe(200);
	});
});

describe("oauth-callback Edge contract: method and configuration guards", () => {
	it("refuses every non-POST method with 405 and performs no database work", async () => {
		const { handle, db } = await handlerWith();
		for (const method of ["GET", "PUT", "PATCH", "DELETE", "HEAD"]) {
			const response = await handle(
				new Request(FUNCTION_URL, { method, headers: { Origin: DASHBOARD_ORIGIN } }),
			);
			expect(response.status, method).toBe(405);
			expect(await response.json(), method).toEqual({ error: "method_not_allowed" });
		}
		expect(db.from).not.toHaveBeenCalled();
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(db.rpc).not.toHaveBeenCalled();
	});

	it("answers a missing platform variable with 500 server_misconfigured and never echoes a configured value", async () => {
		const logged: string[] = [];
		vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
			logged.push(args.map(String).join(" "));
		});

		for (const [variable, expectedMissing] of [
			["SUPABASE_URL", "SUPABASE_URL"],
			["SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SERVICE_ROLE_KEY"],
		] as const) {
			const { handle, db } = await handlerWith({}, { [variable]: undefined });
			const { status, raw, body } = await readJson(await handle(post({ invite_token: INVITE_TOKEN })));

			expect(status, variable).toBe(500);
			expect(body.error, variable).toBe("server_misconfigured");
			expect(body.missing, variable).toEqual([expectedMissing]);
			// The variable NAME is reported; neither configured value is.
			expect(raw, variable).not.toContain(SERVICE_ROLE_SECRET);
			expect(raw, variable).not.toContain(PROJECT_URL);
			expectNoCredentialLeak(raw, body);
			// No client, no authentication and no invitation read happened.
			expect(db.from, variable).not.toHaveBeenCalled();
			expect(db.auth.getUser, variable).not.toHaveBeenCalled();
		}

		expect(logged.join("\n")).toContain("server_misconfigured");
		for (const line of logged) {
			expect(line).not.toContain(SERVICE_ROLE_SECRET);
			expect(line).not.toContain(BEARER_TOKEN);
			expect(line).not.toContain(INVITE_TOKEN);
		}
	});
});

describe("oauth-callback Edge contract: invitation credential and single-use redemption", () => {
	it("refuses an unauthenticated or unverifiable access token before reading any invitation", async () => {
		const { handle, db, calls } = await liveHandle(TENANT);
		const missing = await readJson(
			await handle(new Request(FUNCTION_URL, { method: "POST", headers: { Origin: DASHBOARD_ORIGIN } })),
		);
		expect(missing.status).toBe(401);
		expect(missing.body).toEqual({ error: "missing_access_token" });

		const invalid = await readJson(
			await handle(post({ invite_token: INVITE_TOKEN }, { Authorization: "Bearer some-other-token" })),
		);
		expect(invalid.status).toBe(401);
		expect(invalid.body).toEqual({ error: "invalid_access_token" });

		expect(calls.tokenHashes).toEqual([]);
		expect(calls.rpc).toEqual([]);
		expect(db.rpc).not.toHaveBeenCalled();
	});

	it("refuses a revoked or unreadable session state before any invitation read", async () => {
		const revoked = await handlerWith(
			{ revokedBefore: "2099-01-01T00:00:00.000Z" },
			{},
		);
		const revokedResponse = await readJson(await revoked.handle(post({ invite_token: INVITE_TOKEN })));
		expect(revokedResponse.status).toBe(401);
		expect(revokedResponse.body).toEqual({ error: "session_revoked" });
		expect(revoked.calls.tokenHashes).toEqual([]);

		const unreadable = await handlerWith({ stateError: { code: "HY000" } });
		const unreadableResponse = await readJson(await unreadable.handle(post({ invite_token: INVITE_TOKEN })));
		expect(unreadableResponse.status).toBe(503);
		expect(unreadableResponse.body).toEqual({ error: "identity_state_unavailable" });
		expect(unreadable.calls.tokenHashes).toEqual([]);
		expect(unreadable.calls.rpc).toEqual([]);
	});

	it("rejects a missing or malformed invite token with 400 before hashing or any lookup", async () => {
		const { handle, db, calls } = await liveHandle(TENANT);
		const bodies: unknown[] = [
			{},
			{ invite_token: "" },
			{ invite_token: "   " },
			{ invite_token: "0123" },
			{ invite_token: "0".repeat(63) },
			{ invite_token: "0".repeat(65) },
			// Uppercase hex and non-hex characters are not the stored credential form.
			{ invite_token: "A".repeat(64) },
			{ invite_token: "z".repeat(64) },
			{ invite_token: 42 },
			{ invite_token: { token: INVITE_TOKEN } },
			{ token: INVITE_TOKEN },
			{ invite_token: null },
			null,
			[],
		];

		for (const body of bodies) {
			const { status, raw, body: response } = await readJson(await handle(post(body)));
			expect(status, JSON.stringify(body)).toBe(400);
			expect(response, JSON.stringify(body)).toEqual({ error: "invalid_invitation" });
			expectNoCredentialLeak(raw, response);
		}

		// Nothing was hashed, nothing was looked up, nothing was redeemed.
		expect(calls.tokenHashes).toEqual([]);
		expect(db.rpc).not.toHaveBeenCalled();
	});

	it("rejects a malformed JSON body with 400 without hashing or redeeming anything", async () => {
		const { handle, db, calls } = await liveHandle(TENANT);
		const { status, body } = await readJson(await handle(rawPost("{not json")));
		expect(status).toBe(400);
		expect(body).toEqual({ error: "invalid_json" });
		expect(calls.tokenHashes).toEqual([]);
		expect(db.rpc).not.toHaveBeenCalled();
	});

	it("hashes the invite token and never sends the raw credential to the database", async () => {
		const { handle, calls } = await liveHandle(TENANT);
		const { status, raw, body } = await readJson(await handle(post({ invite_token: INVITE_TOKEN })));

		expect(status).toBe(200);
		expect(body).toEqual({ ok: true, team_id: TENANT });
		expect(calls.tokenHashes).toEqual([hashOf(INVITE_TOKEN)]);
		expect(calls.tokenHashes).not.toContain(INVITE_TOKEN);
		expect(JSON.stringify(calls.rpc)).not.toContain(INVITE_TOKEN);
		expect(JSON.stringify(calls.from)).not.toContain(INVITE_TOKEN);
		expectNoCredentialLeak(raw, body);
		// The privileged redemption receives the digest and the verified user only:
		// no tenant, no role and no raw token can be supplied by the caller.
		expect(calls.rpc).toHaveLength(1);
		const [redemption] = calls.rpc;
		expect(redemption?.name).toBe("accept_team_invitation");
		expect(Object.keys(redemption?.args ?? {}).sort()).toEqual(["p_hash", "p_user_id"]);
		expect(redemption?.args.p_hash).toBe(hashOf(INVITE_TOKEN));
		expect(redemption?.args.p_user_id).toBe(USER);
		expect(mocks.createClientCalls).toEqual([]);
	});

	it("binds the redemption to the stored tenant and ignores a client-supplied tenant", async () => {
		const { handle, calls } = await liveHandle(TENANT, {});
		const { status, body } = await readJson(
			await handle(
				post(
					{ invite_token: INVITE_TOKEN, tenant_id: OTHER_TENANT, team_id: OTHER_TENANT },
					{ "X-AIDR-Tenant-ID": OTHER_TENANT },
				),
			),
		);

		expect(status).toBe(200);
		expect(body).toEqual({ ok: true, team_id: TENANT });
		// The tenant used for the post-acceptance identity barrier is the one the
		// invitation row names, not the one the caller asked for.
		expect(calls.policyTenants).toEqual([TENANT]);
		expect(JSON.stringify(calls.policyTenants)).not.toContain(OTHER_TENANT);
	});

	it("refuses an unknown, expired or already-redeemed invitation and consumes the state at most once", async () => {
		// Unknown credential: the stored, unexpired, single-use value does not exist.
		const unknown = await liveHandle(TENANT);
		const unknownResponse = await readJson(await unknown.handle(post({ invite_token: OTHER_INVITE_TOKEN })));
		expect(unknownResponse.status).toBe(403);
		expect(unknownResponse.body).toEqual({ error: "invitation_not_accepted" });
		expect(unknown.calls.tokenHashes).toEqual([hashOf(OTHER_INVITE_TOKEN)]);
		expect(unknown.calls.rpc).toEqual([]);

		// Expired stored value.
		const expired = await handlerWith({
			invitations: {
				[hashOf(INVITE_TOKEN)]: invitationRow(TENANT, { expires_at: "2000-01-01T00:00:00.000Z" }),
			},
		});
		const expiredResponse = await readJson(await expired.handle(post({ invite_token: INVITE_TOKEN })));
		expect(expiredResponse.status).toBe(403);
		expect(expiredResponse.body).toEqual({ error: "invitation_not_accepted" });
		expect(expired.calls.redemptions).toBe(0);

		// Replay: the same stored value cannot be redeemed twice.
		const { handle, calls } = await liveHandle(TENANT);
		const first = await readJson(await handle(post({ invite_token: INVITE_TOKEN })));
		const replay = await readJson(await handle(post({ invite_token: INVITE_TOKEN })));
		expect([first.status, replay.status]).toEqual([200, 403]);
		expect(first.body).toEqual({ ok: true, team_id: TENANT });
		expect(replay.body).toEqual({ error: "invitation_not_accepted" });
		expect(calls.redemptions).toBe(1);
		expect(calls.tokenHashes).toEqual([hashOf(INVITE_TOKEN), hashOf(INVITE_TOKEN)]);
		expectNoCredentialLeak(replay.raw, replay.body);
	});

	it("refuses an invitation whose tenant fails the identity barrier and never falls back to the caller's tenant", async () => {
		const otherTenantInvite = {
			invitations: { [hashOf(OTHER_INVITE_TOKEN)]: invitationRow(OTHER_TENANT) },
			requireMfa: true,
			mfaLevel: "aal1",
		};
		const refused = await handlerWith(otherTenantInvite);
		const refusedResponse = await readJson(
			await refused.handle(
				post(
					{ invite_token: OTHER_INVITE_TOKEN, tenant_id: TENANT },
					{ "X-AIDR-Tenant-ID": TENANT },
				),
			),
		);

		expect(refusedResponse.status).toBe(403);
		expect(refusedResponse.body).toEqual({ error: "mfa_required" });
		// The barrier was evaluated against the invitation's tenant, so a caller
		// cannot redeem a credential by claiming a tenant they do hold.
		expect(refused.calls.policyTenants).toEqual([OTHER_TENANT]);
		expect(refused.calls.rpc).toEqual([]);
		expect(refused.calls.redemptions).toBe(0);

		// With the assurance the policy demands, the same credential is redeemed
		// for its own tenant and not for the claimed one.
		const admitted = await handlerWith({ ...otherTenantInvite, mfaLevel: "aal2" });
		const admittedResponse = await readJson(
			await admitted.handle(
				post({ invite_token: OTHER_INVITE_TOKEN, tenant_id: TENANT }, { "X-AIDR-Tenant-ID": TENANT }),
			),
		);
		expect(admittedResponse.status).toBe(200);
		expect(admittedResponse.body).toEqual({ ok: true, team_id: OTHER_TENANT });
		expect(admitted.calls.policyTenants).toEqual([OTHER_TENANT]);
	});
});

describe("oauth-callback Edge contract: redemption failures are fail-closed", () => {
	it("maps a privileged redemption error to 403 or 503 and never to a success or a session", async () => {
		const cases: Array<{ error: { code?: string }; status: number }> = [
			// 42501 is the SQL contract's "unknown, expired, already accepted or
			// revoked" signal.
			{ error: { code: "42501" }, status: 403 },
			{ error: { code: "XX000" }, status: 503 },
			{ error: {}, status: 503 },
		];

		for (const { error, status } of cases) {
			const { handle, calls } = await liveHandle(TENANT, { rpcError: error });
			const { status: actual, raw, body } = await readJson(await handle(post({ invite_token: INVITE_TOKEN })));
			expect(actual, JSON.stringify(error)).toBe(status);
			expect(body, JSON.stringify(error)).toEqual({ error: "invitation_not_accepted" });
			expect(body.ok, JSON.stringify(error)).toBeUndefined();
			expect(raw).not.toMatch(/session|"ok":true/i);
			expectNoCredentialLeak(raw, body);
			expect(calls.redemptions).toBe(0);
		}
	});

	it("fails closed when the redemption result is missing, malformed or foreign", async () => {
		const results: Array<{ data: unknown; label: string }> = [
			{ data: null, label: "missing" },
			{ data: {}, label: "object" },
			{ data: 42, label: "number" },
			{ data: "", label: "empty" },
			{ data: [TENANT], label: "array" },
			// A foreign tenant is not this invitation's tenant: accepting it would
			// grant membership in a tenant the invitation never named.
			{ data: OTHER_TENANT, label: "foreign_tenant" },
		];

		for (const { data, label } of results) {
			const { handle } = await liveHandle(TENANT, { rpcData: data });
			const { status, raw, body } = await readJson(await handle(post({ invite_token: INVITE_TOKEN })));
			expect(status, label).not.toBe(200);
			expect(status, label).toBe(503);
			expect(body, label).toEqual({ error: "invitation_unavailable" });
			expect(raw, label).not.toContain(OTHER_TENANT);
			expect(raw, label).not.toContain("true");
			expectNoCredentialLeak(raw, body);
		}
	});

	it("fails closed on a transport error during authentication, lookup or redemption", async () => {
		const transports: Array<{ options: DbOptions; status: number; error: string; label: string }> = [
			{ options: { userThrows: true }, status: 503, error: "invitation_unavailable", label: "auth" },
			{
				options: { invitationError: { code: "HY000" } },
				status: 503,
				error: "invitation_unavailable",
				label: "lookup",
			},
			{ options: { policyError: { code: "HY000" } }, status: 503, error: "identity_policy_unavailable", label: "policy" },
			{ options: { rpcThrows: true }, status: 503, error: "invitation_unavailable", label: "redemption" },
		];

		for (const { options, status, error, label } of transports) {
			const { handle, calls } = await liveHandle(TENANT, options);
			const { status: actual, raw, body } = await readJson(await handle(post({ invite_token: INVITE_TOKEN })));
			expect(actual, label).toBe(status);
			expect(body, label).toEqual({ error });
			expect(raw, label).not.toContain('"ok":true');
			expectNoCredentialLeak(raw, body);
			expect(calls.redemptions, label).toBe(0);
		}
	});
});

describe("oauth-callback Edge contract: credential containment", () => {
	it("builds the service-role client from validated configuration and an injectable transport", async () => {
		const injectedTransport = (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
		const { db } = database();
		mocks.db = db;

		vi.resetModules();
		const mod = await import("../oauth-callback/index.ts");
		const handle = mod.createOAuthCallbackHandler({ fetch: injectedTransport }) as Handle;
		expect(mocks.createClientCalls).toHaveLength(0);
		await handle(post({ invite_token: INVITE_TOKEN }));
		expect(mocks.createClientCalls).toHaveLength(1);

		const [url, key, clientOptions] = mocks.createClientCalls[0] ?? [];
		expect(url).toBe(PROJECT_URL);
		// Positive control for the containment assertions: the secret really does
		// reach the service-role client, and still never reaches a response body.
		expect(key).toBe(SERVICE_ROLE_SECRET);
		expect(clientOptions).toEqual({
			auth: { persistSession: false },
			global: { fetch: injectedTransport },
		});
	});

	it("never returns an access token, a refresh token or a configured secret in a response body", async () => {
		// The misconfiguration case logs through the shared helper; the dedicated
		// log test below asserts on that line.
		vi.spyOn(console, "error").mockImplementation(() => undefined);

		async function check(label: string, expected: number, response: Response) {
			const { status, raw, body } = await readJson(response);
			expect(status, label).toBe(expected);
			expectNoCredentialLeak(raw, body);
			expect(Object.keys(body), label).not.toContain("session");
			return { raw, body };
		}

		{
			const { handle } = await handlerWith();
			await check(
				"preflight",
				200,
				await handle(new Request(FUNCTION_URL, { method: "OPTIONS", headers: { Origin: DASHBOARD_ORIGIN } })),
			);
			await check(
				"method",
				405,
				await handle(new Request(FUNCTION_URL, { method: "GET", headers: { Origin: DASHBOARD_ORIGIN } })),
			);
			await check("origin", 403, await handle(post({ invite_token: INVITE_TOKEN }, { Origin: EVIL_ORIGIN })));
		}

		{
			const { handle } = await liveHandle(TENANT);
			const accepted = await check("accepted", 200, await handle(post({ invite_token: INVITE_TOKEN })));
			// A confirmed acceptance carries the invitation outcome and nothing else.
			expect(Object.keys(accepted.body).sort()).toEqual(["ok", "team_id"]);
			expect(accepted.raw).not.toContain(OTHER_TENANT);
			await check("malformed_credential", 400, await handle(post({ invite_token: "A".repeat(64) })));
			await check("unknown_credential", 403, await handle(post({ invite_token: OTHER_INVITE_TOKEN })));
		}

		{
			const { handle } = await liveHandle(TENANT, { rpcThrows: true });
			await check("redemption_transport", 503, await handle(post({ invite_token: INVITE_TOKEN })));
		}

		// Last, because it unsets a platform variable for the rest of the test.
		{
			const { handle } = await handlerWith({}, { SUPABASE_SERVICE_ROLE_KEY: undefined });
			const misconfigured = await check("misconfigured", 500, await handle(post({ invite_token: INVITE_TOKEN })));
			expect(misconfigured.raw).not.toContain(PROJECT_URL);
			expect(misconfigured.body.missing).toEqual(["SUPABASE_SERVICE_ROLE_KEY"]);
		}
	});

	it("never writes a request credential to the server log", async () => {
		const logged: string[] = [];
		vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
			logged.push(args.map(String).join(" "));
		});
		vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
			logged.push(args.map(String).join(" "));
		});
		vi.spyOn(console, "warn").mockImplementation((...args: unknown[]) => {
			logged.push(args.map(String).join(" "));
		});

		// The only logging path in the handler is the shared configuration helper.
		const { handle, calls } = await liveHandle(TENANT, { rpcThrows: true });
		await handle(post({ invite_token: INVITE_TOKEN }));
		expect(calls.rpc).toHaveLength(1);
		expect(logged).toEqual([]);

		const misconfigured = await handlerWith({}, { SUPABASE_URL: undefined });
		await misconfigured.handle(post({ invite_token: INVITE_TOKEN }));
		expect(logged.join("\n")).toContain("[oauth-callback] configuration error");
		for (const line of logged) {
			expect(line).not.toContain(SERVICE_ROLE_SECRET);
			expect(line).not.toContain(BEARER_TOKEN);
			expect(line).not.toContain(INVITE_TOKEN);
			expect(line).not.toMatch(CREDENTIAL_ASSIGNMENT);
		}
	});
});

describe("oauth-callback handler source and wiring contract", () => {
	it("validates configuration through the shared helper before any client or database work", () => {
		expect(oauthSource).toContain('from "../_shared/config.ts"');
		expect(oauthSource).toContain("const config = loadConfig(runtimeEnv,");
		expect(oauthSource).toContain("configFailure(");
		expect(oauthSource).toContain('"SUPABASE_URL"');
		expect(oauthSource).toContain('"SUPABASE_SERVICE_ROLE_KEY"');

		for (const variable of ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]) {
			expect(oauthSource, variable).not.toMatch(
				new RegExp(`Deno\\.env\\.get\\(\\s*"${variable}"\\s*\\)`),
			);
			expect(oauthSource, variable).not.toMatch(
				new RegExp(`Deno\\.env\\.get\\(\\s*"${variable}"\\s*\\)\\s*\\?\\?\\s*""`),
			);
		}

		const guard = oauthSource.indexOf("const config = loadConfig(runtimeEnv,");
		expect(guard).toBeGreaterThan(-1);
		expect(guard).toBeLessThan(oauthSource.indexOf("createClient("));
		expect(guard).toBeLessThan(oauthSource.indexOf("db.auth.getUser"));
		expect(guard).toBeLessThan(oauthSource.indexOf("db.from("));
	});

	it("answers every response through the request-scoped CORS helpers", () => {
		expect(oauthSource).toContain('from "../_shared/cors.ts"');
		const preflight = oauthSource.indexOf("handleCors(req)");
		expect(preflight).toBeGreaterThan(-1);
		expect(preflight).toBeLessThan(oauthSource.indexOf('req.method !== "POST"'));
		expect(preflight).toBeLessThan(oauthSource.indexOf("const config = loadConfig(runtimeEnv,"));
		expect(oauthSource).toContain("corsJson(req");
		expect(oauthSource.match(/corsJson\(req/g)?.length ?? 0).toBeGreaterThanOrEqual(12);
	});

	it("constructs only fixed response bodies, so no credential can be serialised", () => {
		const shapes = [
			/^\{ error: "[a-z_]+" \}$/,
			/^\{ error: (?:identity|tenantIdentity)\.error \}$/,
			/^\{ ok: true, team_id: data \}$/,
		];
		const bodies = [...oauthSource.matchAll(/corsJson\(req,[^,]*,\s*(\{[^{}]*\})/g)].map(
			(match) => match[1] ?? "",
		);

		expect(bodies.length).toBeGreaterThanOrEqual(12);
		for (const body of bodies) {
			expect(
				shapes.some((shape) => shape.test(body)),
				`unexpected response body: ${body}`,
			).toBe(true);
		}
		expect(oauthSource).not.toMatch(CREDENTIAL_ASSIGNMENT);
		// The handler must not log anything itself; the shared config helper is the
		// only log line, and it prints variable names rather than values.
		expect(oauthSource).not.toMatch(/console\.(?:log|error|warn|info|debug)/);
	});

	it("wires the exported factory into Deno.serve", () => {
		expect(oauthSource).toContain("export function createOAuthCallbackHandler(deps: OAuthCallbackDeps = {})");
		expect(oauthSource).toContain("export interface OAuthCallbackDeps");
		expect(oauthSource).toContain("Deno.serve(createOAuthCallbackHandler())");
	});

	it("serves the factory-built handler through the runtime entry point", async () => {
		const { db, calls } = database({ invitations: { [hashOf(INVITE_TOKEN)]: invitationRow(TENANT) } });
		mocks.db = db;

		vi.resetModules();
		const mod = await import("../oauth-callback/index.ts");
		const served = serveCalls[serveCalls.length - 1];
		expect(typeof served).toBe("function");
		expect(typeof mod.createOAuthCallbackHandler).toBe("function");

		const { status, body } = await readJson(
			await (served as (request: Request) => Promise<Response>)(post({ invite_token: INVITE_TOKEN })),
		);
		expect(status).toBe(200);
		expect(body).toEqual({ ok: true, team_id: TENANT });
		expect(calls.redemptions).toBe(1);
		expect(mocks.createClientCalls).toHaveLength(1);
	});
});
