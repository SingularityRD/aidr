import { Buffer } from "node:buffer";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const FUNCTIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const USER = "11111111-1111-4111-8111-111111111111";
const TEAM = "22222222-2222-4222-8222-222222222222";
const OTHER = "33333333-3333-4333-8333-333333333333";
const SESSION = "44444444-4444-4444-8444-444444444444";
const NOW = "2026-09-16T12:00:00.000Z";
const JWT = `header.${Buffer.from(JSON.stringify({ iat: Date.parse(NOW) / 1000 - 60, session_id: SESSION })).toString("base64url")}.signature`;
const OTP_JWT = `header.${Buffer.from(JSON.stringify({ iat: Date.parse(NOW) / 1000 - 60, session_id: SESSION, amr: [{ method: "otp", timestamp: Date.parse(NOW) / 1000 - 60 }] })).toString("base64url")}.signature`;
const SAML_JWT = `header.${Buffer.from(JSON.stringify({ iat: Date.parse(NOW) / 1000 - 60, session_id: SESSION, amr: [{ method: "totp" }, { method: "sso/saml", provider: OTHER }] })).toString("base64url")}.signature`;
const SAML_CHANGE = {
	request_id: "55555555-5555-4555-8555-555555555555", tenant_id: TEAM, requested_by: USER,
	old_provider_id: null, new_provider_id: OTHER, reason: "Enable the verified SAML provider", change_ref: "SEC-42",
	created_at: NOW, expires_at: "2026-09-16T12:15:00.000Z", approved_by: null, approved_at: null,
};
function samlPolicyToken(overrides: Row = {}) {
	return `header.${Buffer.from(JSON.stringify({
		iat: Date.parse(NOW) / 1000 - 60, exp: Date.parse(NOW) / 1000 + 3600, session_id: SESSION,
		aal: "aal2", amr: [{ method: "sso/saml", provider: OTHER }], ...overrides,
	})).toString("base64url")}.signature`;
}
type Handler = (request: Request) => Promise<Response>;
type Row = Record<string, unknown>;
type Query = { table: string; columns?: string; filters: [string, string, unknown][]; order?: { field: string; ascending: boolean } };
const compiled = new Map<string, string>();

function harness(options: {
	invalidToken?: boolean;
	assuranceError?: boolean;
	current?: "aal1" | "aal2" | null;
	next?: "aal1" | "aal2" | null;
	failTable?: string;
	rpcError?: boolean;
	signOutError?: boolean;
	signOutFailures?: number;
	failOnceAt?: "generate-link" | "grant" | "factor-delete" | "audit" | "break-glass-complete" | "barrier" | "auth-signout" | "password-update" | "password-complete";
	samlError?: string;
	samlThrows?: boolean;
	samlData?: unknown;
	plan?: { data: unknown; error: unknown };
} = {}) {
	const tables: Record<string, Row[]> = {
		identity_user_session_state: [],
		rate_limits: [],
		admin_audit_logs: [],
		tenant_members: [{ user_id: USER, tenant_id: TEAM, expires_at: null, role: "owner" }],
		tenants: [{ id: TEAM, status: "active", name: "Protected tenant", region: "secret" }],
		team_members: [{ user_id: USER, team_id: TEAM, tenant_id: TEAM, role: "owner" }],
		teams: [{ id: TEAM, tenant_id: TEAM, name: "Protected team", plan: "enterprise" }],
		tenant_identity_policies: [{ tenant_id: TEAM, require_mfa: true, break_glass_enabled: true }],
	};
	const queries: Query[] = [];
	const events: string[] = [];
	let remainingInjectedFailures = options.failOnceAt ? 1 : 0;
	const injectedFailure = (step: typeof options.failOnceAt) =>
		options.failOnceAt === step && remainingInjectedFailures-- > 0;
	let breakGlassChallenge: unknown = null;
	let breakGlassCompleted = false;
	let passwordCompletionStarted = false;
	let passwordCompletionCompleted = false;
	let factors = [{ id: OTHER }];
	const getUser = vi.fn(async (_token: string) => {
		events.push("authenticate");
		return options.invalidToken
			? { data: { user: null }, error: { message: "invalid or expired" } }
			: { data: { user: { id: USER, email: "private@example.test" } }, error: null };
	});
	const getAssurance = vi.fn(async (_token: string) => {
		events.push("assurance");
		return {
			data: { currentLevel: options.current === undefined ? "aal1" : options.current, nextLevel: options.next === undefined ? "aal2" : options.next },
			error: options.assuranceError ? { message: "unavailable" } : null,
		};
	});
	const rpc = vi.fn(async (name: string, parameters: Record<string, unknown>) => {
		if (options.rpcError) return { data: null, error: { message: "private database error" } };
		if (name === "tenant_plan_entitlements") {
			// Entitled Team plan unless a test overrides the RPC answer.
			return options.plan ?? { data: {
				tenant_id: parameters.p_tenant_id, plan_id: "team", plan_source: "team_record", trial_active: false,
				features: ["local_detection", "dashboard", "browser_privacy_guard", "entra_sso"], retention_days_max: 90,
			}, error: null };
		}
		if (["request_tenant_saml_policy_change", "approve_tenant_saml_policy_change", "get_tenant_saml_policy_change"].includes(name)) {
			if (options.samlThrows) throw new Error("private database credential");
			return { data: options.samlData === undefined ? SAML_CHANGE : options.samlData,
				error: options.samlError ? { message: options.samlError, details: "private session proof" } : null };
		}
		if (name === "increment_rate_limit") {
			const existing = tables.rate_limits.find((row) =>
				row.key === parameters.p_key && row.window_start === parameters.p_window_start
			);
			if (existing) existing.count = Number(existing.count) + 1;
			else tables.rate_limits.push({
				key: parameters.p_key,
				window_start: parameters.p_window_start,
				count: 1,
			});
			return { data: true, error: null };
		}
		if (name === "begin_identity_break_glass_recovery") {
			events.push("break-glass-begin");
			if (breakGlassChallenge !== null && breakGlassChallenge !== parameters.p_proof_challenge_hash) {
				return { data: null, error: null };
			}
			breakGlassChallenge = parameters.p_proof_challenge_hash;
			return {
				data: {
					status: breakGlassCompleted ? "completed" : "pending",
					user_id: USER,
					tenant_id: TEAM,
				},
				error: null,
			};
		}
		if (name === "issue_identity_break_glass_password_recovery_grant") {
			events.push("break-glass-grant");
			return injectedFailure("grant")
				? { data: null, error: { message: "injected grant failure" } }
				: { data: true, error: null };
		}
		if (name === "complete_identity_break_glass_recovery") {
			events.push("break-glass-complete");
			if (injectedFailure("break-glass-complete")) {
				return { data: null, error: { message: "injected completion failure" } };
			}
			breakGlassCompleted = true;
			return { data: true, error: null };
		}
		if (name === "bind_identity_password_recovery_grant") {
			return { data: true, error: null };
		}
		if (name === "begin_identity_password_recovery_completion") {
			events.push("password-begin");
			passwordCompletionStarted = true;
			return {
				data: {
					status: passwordCompletionCompleted ? "completed" : "pending",
					source: "email",
					tenant_id: null,
				},
				error: null,
			};
		}
		if (name === "complete_identity_password_recovery_completion") {
			events.push("password-complete");
			if (injectedFailure("password-complete")) {
				return { data: null, error: { message: "injected completion failure" } };
			}
			passwordCompletionCompleted = true;
			return { data: true, error: null };
		}
		if (name === "begin_identity_global_revocation") {
			const state = tables.identity_user_session_state[0];
			const pendingSession = state?.global_revoke_pending_session_id;
			const sessionId = parameters.p_session_id;
			const issuedAt = Date.parse(String(parameters.p_access_token_issued_at));
			const barrier = state?.revoked_before ? Date.parse(String(state.revoked_before)) : -Infinity;
			if (pendingSession !== sessionId && issuedAt <= barrier) {
				return { data: false, error: null };
			}
			events.push("revocation-begin");
			tables.identity_user_session_state = [
				{
					user_id: parameters.p_user_id,
					revoked_before: NOW,
					global_revoke_pending_session_id: sessionId,
				},
			];
			return { data: true, error: null };
		}
		if (name === "complete_identity_global_revocation") {
			const state = tables.identity_user_session_state[0];
			if (state?.global_revoke_pending_session_id !== parameters.p_session_id) {
				return { data: false, error: null };
			}
			events.push("revocation-complete");
			tables.identity_user_session_state = [
				{ user_id: parameters.p_user_id, revoked_before: NOW },
			];
			return { data: true, error: null };
		}
		if (name === "mark_identity_session_revoked") {
			events.push("barrier-write");
			if (passwordCompletionStarted && injectedFailure("barrier")) {
				return { data: null, error: { message: "injected barrier failure" } };
			}
			tables.identity_user_session_state = [
				{ user_id: parameters.p_user_id, revoked_before: NOW },
			];
		}
		return { data: true, error: null };
	});
	let remainingSignOutFailures = options.signOutFailures ?? (options.signOutError ? Infinity : 0);
	const signOut = vi.fn(async (_token: string, _scope: string) => {
		events.push("auth-signout");
		return {
			error: injectedFailure("auth-signout") || remainingSignOutFailures-- > 0
				? { message: "private auth error" }
				: null,
		};
	});
	const generateLink = vi.fn(async ({ email }: { email: string }) => {
		events.push("generate-link");
		if (injectedFailure("generate-link")) {
			return { data: null, error: { message: "injected link failure" } };
		}
		return {
			data: {
				user: { id: USER },
				properties: {
					hashed_token: "a".repeat(64),
					verification_type: "recovery",
					redirect_to: "https://dashboard.example.test/auth/recover",
				},
			},
			error: null,
		};
	});
	const listFactors = vi.fn(async () => {
		events.push("factor-list");
		return { data: { factors: [...factors] }, error: null };
	});
	const deleteFactor = vi.fn(async ({ id }: { id: string }) => {
		events.push("factor-delete");
		if (injectedFailure("factor-delete")) {
			return { error: { message: "injected factor failure" } };
		}
		factors = factors.filter((factor) => factor.id !== id);
		return { error: null };
	});
	const updateUserById = vi.fn(async () => {
		events.push("password-update");
		return { error: injectedFailure("password-update") ? { message: "injected password failure" } : null };
	});
	const db = {
		auth: {
			getUser,
			resetPasswordForEmail: vi.fn(async () => ({ error: null })),
			mfa: { getAuthenticatorAssuranceLevel: getAssurance },
			admin: {
				signOut,
				generateLink,
				updateUserById,
				mfa: { listFactors, deleteFactor },
			},
		},
		rpc,
		from(table: string) {
			events.push(table);
			const call: Query = { table, filters: [] };
			queries.push(call);
			const execute = () => {
				if (options.failTable === table) return { data: null, error: { message: "private database error" } };
				if (!tables[table]) throw new Error(`Unexpected table: ${table}`);
				const rows = tables[table].filter((row) => call.filters.every(([kind, field, value]) => {
					if (kind === "eq") return row[field] === value;
					if (kind === "in") return (value as unknown[]).includes(row[field]);
					if (kind === "or") {
						expect(field).toBe(`expires_at.is.null,expires_at.gt.${NOW}`);
						return row.expires_at === null || Date.parse(String(row.expires_at)) > Date.parse(NOW);
					}
					throw new Error(`Unexpected filter: ${kind}`);
				}));
				if (call.order) {
					const { field, ascending } = call.order;
					rows.sort((left, right) => String(left[field]).localeCompare(String(right[field])) * (ascending ? 1 : -1));
				}
				const columns = call.columns?.split(",") ?? [];
				return { data: rows.map((row) => Object.fromEntries(columns.map((column) => [column, row[column]]))), error: null };
			};
			const query = {
				async insert(values: Row) {
					events.push("audit");
					if (table !== "admin_audit_logs") throw new Error(`Unexpected insert: ${table}`);
					if (injectedFailure("audit")) return { error: { message: "injected audit failure" } };
					tables.admin_audit_logs.push(values);
					return { error: null };
				},
				select(columns: string) { call.columns = columns; return query; },
				eq(field: string, value: unknown) { call.filters.push(["eq", field, value]); return query; },
				in(field: string, values: unknown[]) { call.filters.push(["in", field, values]); return query; },
				or(filter: string) { call.filters.push(["or", filter, null]); return query; },
				order(field: string, options?: { ascending?: boolean }) {
					expect(field).toBe(table === "team_members" ? "joined_at" : "id");
					expect(options).toEqual(table === "team_members" ? { ascending: false } : undefined);
					call.order = { field, ascending: options?.ascending ?? true };
					return query;
				},
				async maybeSingle() { const result = execute(); return { ...result, data: result.data?.[0] ?? null }; },
				then(onFulfilled: (value: ReturnType<typeof execute>) => unknown) { return Promise.resolve(execute()).then(onFulfilled); },
			};
			return query;
		},
	};
	const env: Record<string, string> = {
		SUPABASE_URL: "https://test.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
		AIDR_DASHBOARD_URL: "https://dashboard.example.test",
	};
	let handler: Handler | undefined;
	const modules = new Map<string, { exports: unknown }>();
	// Execute the production entrypoint and real shared authentication/barrier
	// modules. Only the remote Supabase SDK is replaced, never the security logic.
	function load(path: string): unknown {
		if (modules.has(path)) return modules.get(path)?.exports;
		let javascript = compiled.get(path);
		if (!javascript) {
			javascript = ts.transpileModule(readFileSync(path, "utf8"), {
				compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
			}).outputText;
			compiled.set(path, javascript);
		}
		const module = { exports: {} };
		modules.set(path, module);
		runInNewContext(javascript, {
			module, exports: module.exports,
			require: (name: string) => {
				if (name === "npm:@supabase/supabase-js@2.116.0") return { createClient: () => db };
				if (!name.startsWith(".")) throw new Error(`Unexpected import: ${name}`);
				return load(resolve(dirname(path), name));
			},
			Deno: { env: { get: (name: string) => env[name] }, serve: (value: Handler) => { handler = value; } },
			crypto: webcrypto, URL, Request, Response, TextDecoder, TextEncoder, Uint8Array, Date, atob, console,
		});
		return module.exports;
	}
	load(resolve(FUNCTIONS_DIR, "identity-security", "index.ts"));
	if (!handler) throw new Error("identity-security did not register its handler");
	return {
		handler,
		tables,
		queries,
		events,
		getUser,
		getAssurance,
		rpc,
		signOut,
		generateLink,
		listFactors,
		deleteFactor,
		updateUserById,
	};
}

function request(token: string | null = JWT, body: Row = {}, extraHeaders: Record<string, string> = {}) {
	return new Request("https://test.supabase.co/functions/v1/identity-security", {
		method: "POST",
		headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}), ...extraHeaders },
		body: JSON.stringify({ action: "bootstrap", ...body }),
	});
}

beforeEach(() => { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date(NOW)); });
afterEach(() => vi.useRealTimers());

describe("SAML policy change administration", () => {
	const enable = {
		action: "request_saml_policy_change", tenant_id: TEAM, new_provider_id: OTHER,
		reason: " Enable the verified SAML provider ", change_ref: " SEC-42 ",
	};
	const approve = { action: "approve_saml_policy_change", tenant_id: TEAM, request_id: SAML_CHANGE.request_id };
	const get = { action: "get_saml_policy_change", tenant_id: TEAM, request_id: SAML_CHANGE.request_id };
	const samlCalls = (runtime: ReturnType<typeof harness>) => runtime.rpc.mock.calls.filter(([name]) => name.endsWith("_tenant_saml_policy_change"));

	it("derives actor and session proof only from verified Auth and signed JWT claims", async () => {
		const runtime = harness({ current: "aal2", samlData: { ...SAML_CHANGE, validated_session: "secret", audit_id: 99, access_token: "secret" } });
		const token = samlPolicyToken({ user_id: OTHER });
		const response = await runtime.handler(request(token, enable));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, request: SAML_CHANGE });
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(runtime.getUser).toHaveBeenCalledWith(token);
		expect(samlCalls(runtime)).toEqual([["request_tenant_saml_policy_change", {
			p_tenant_id: TEAM, p_actor_user_id: USER, p_new_provider_id: OTHER,
			p_reason: enable.reason.trim(), p_change_ref: enable.change_ref.trim(), p_validated_session: {
				session_id: SESSION, issued_at: "2026-09-16T11:59:00.000Z", expires_at: "2026-09-16T13:00:00.000Z",
				aal: "aal2", saml_provider_id: OTHER,
			},
		}]]);
	});

	it("approves with the caller's verified proof and permits owner reads under the tenant barrier", async () => {
		const runtime = harness({ current: "aal2" });
		expect((await runtime.handler(request(samlPolicyToken(), approve))).status).toBe(200);
		expect(samlCalls(runtime)[0]).toMatchObject(["approve_tenant_saml_policy_change", {
			p_actor_user_id: USER, p_request_id: SAML_CHANGE.request_id,
			p_validated_session: { session_id: SESSION, saml_provider_id: OTHER },
		}]);
		const reader = harness({ current: "aal1" });
		reader.tables.tenant_identity_policies[0].require_mfa = false;
		const result = await reader.handler(request(samlPolicyToken({ aal: "aal1", amr: [] }), get));
		expect(result.status).toBe(200);
		expect(samlCalls(reader)).toEqual([["get_tenant_saml_policy_change", { p_tenant_id: TEAM, p_actor_user_id: USER, p_request_id: SAML_CHANGE.request_id }]]);
	});

	it("allows disabling only through the currently enforced provider session", async () => {
		const runtime = harness({ current: "aal2", samlData: { ...SAML_CHANGE, old_provider_id: OTHER, new_provider_id: null } });
		runtime.tables.tenant_identity_policies[0].required_saml_provider_id = OTHER;
		const response = await runtime.handler(request(samlPolicyToken(), { ...enable, new_provider_id: null }));
		expect(response.status).toBe(200);
		expect(samlCalls(runtime)[0]?.[1]).toMatchObject({ p_new_provider_id: null, p_validated_session: { saml_provider_id: OTHER } });
	});

	it.each([
		{ ...enable, actor_user_id: OTHER },
		{ ...enable, validated_session: { session_id: OTHER } },
		{ ...approve, session_id: OTHER },
		{ ...get, request_id: "not-a-uuid" },
		{ ...enable, tenant_id: "bad" },
		{ ...enable, new_provider_id: "bad" },
		{ ...enable, new_provider_id: undefined },
		{ ...enable, reason: "too short" },
		{ ...enable, reason: "a".repeat(501) },
		{ ...enable, reason: "contains\ncontrol characters" },
		{ ...enable, change_ref: " " },
		{ ...enable, change_ref: "a".repeat(201) },
		{ ...enable, change_ref: "SEC\u0000-42" },
	])("rejects caller proof/actor fields and malformed exact bodies %#", async (body) => {
		const runtime = harness({ current: "aal2" });
		const response = await runtime.handler(request(samlPolicyToken(), body));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "saml_policy_invalid_request" });
		expect(samlCalls(runtime)).toEqual([]);
	});

	it.each([OTHER, "invalid"])("rejects a conflicting or invalid tenant header (%s)", async (header) => {
		const runtime = harness({ current: "aal2" });
		const response = await runtime.handler(request(samlPolicyToken(), enable, { "X-AIDR-Tenant-ID": header }));
		expect(response.status).toBe(400);
		expect(samlCalls(runtime)).toEqual([]);
	});

	it.each([enable, approve, get])("requires an active owner for $action", async (body) => {
		for (const role of ["admin", "member", "viewer"]) {
			const runtime = harness({ current: "aal2" });
			runtime.tables.tenant_members[0].role = role;
			const response = await runtime.handler(request(samlPolicyToken(), body));
			expect(response.status).toBe(403);
			expect(await response.json()).toEqual({ error: "saml_policy_owner_required" });
			expect(samlCalls(runtime)).toEqual([]);
		}
	});

	it("rejects expired owners and inactive tenants before request RPCs", async () => {
		for (const state of ["expired", "suspended", "closing", "closed"]) {
			const runtime = harness({ current: "aal2" });
			if (state === "expired") runtime.tables.tenant_members[0].expires_at = NOW;
			else runtime.tables.tenants[0].status = state;
			expect((await runtime.handler(request(samlPolicyToken(), enable))).status).toBe(403);
			expect(samlCalls(runtime)).toEqual([]);
		}
	});

	it.each([enable, approve])("requires AAL2 for $action even without a tenant MFA policy", async (body) => {
		const runtime = harness({ current: "aal1" });
		runtime.tables.tenant_identity_policies[0].require_mfa = false;
		const response = await runtime.handler(request(samlPolicyToken({ aal: "aal1" }), body));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "saml_policy_aal2_required" });
		expect(samlCalls(runtime)).toEqual([]);
	});

	it.each([
		{ exp: undefined }, { exp: "1800000000" }, { exp: Date.parse(NOW) / 1000 }, { exp: Number.MAX_SAFE_INTEGER },
		{ iat: Date.parse(NOW) / 1000 + 7200 }, { iat: 1.5 }, { session_id: "invalid" },
	])("rejects malformed, expired or inconsistent JWT proof %#", async (claims) => {
		const runtime = harness({ current: "aal2" });
		const response = await runtime.handler(request(samlPolicyToken(claims), enable));
		expect(response.status).toBe(401);
		expect(samlCalls(runtime)).toEqual([]);
	});

	it.each([[], [{ method: "sso/saml", provider: TEAM }], [{ method: "sso/saml", provider: OTHER }, { method: "sso/saml", provider: TEAM }]])("requires a unique target SAML provider proof %#", async (amr) => {
		const runtime = harness({ current: "aal2" });
		const response = await runtime.handler(request(samlPolicyToken({ amr }), enable));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "saml_policy_provider_session_required" });
		expect(samlCalls(runtime)).toEqual([]);
	});

	it.each([enable, approve, get])("preserves revocation, current-provider and tenant MFA barriers for $action", async (body) => {
		const wrongProvider = harness({ current: "aal2" });
		wrongProvider.tables.tenant_identity_policies[0].required_saml_provider_id = TEAM;
		expect((await wrongProvider.handler(request(samlPolicyToken(), body))).status).toBe(403);
		expect(samlCalls(wrongProvider)).toEqual([]);
		const revoked = harness({ current: "aal2" });
		revoked.tables.identity_user_session_state.push({ user_id: USER, revoked_before: NOW });
		expect((await revoked.handler(request(samlPolicyToken(), body))).status).toBe(401);
		expect(samlCalls(revoked)).toEqual([]);
		const reader = harness({ current: "aal1" });
		expect((await reader.handler(request(samlPolicyToken({ aal: "aal1" }), body))).status).toBe(403);
		expect(samlCalls(reader)).toEqual([]);
	});

	it.each([
		["invalid_request", 400], ["owner_required", 403], ["aal2_required", 403], ["session_invalid", 401],
		["session_revoked", 401], ["provider_session_required", 403], ["provider_unavailable", 409],
		["owners_not_verified", 409], ["scim_identity_conflict", 409], ["unsupported_transition", 409],
		["policy_conflict", 409], ["request_expired", 409], ["request_consumed", 409],
		["distinct_owner_required", 403], ["request_not_found", 404], ["request_pending_limit", 429],
	] as const)("maps only the safe SQL reason %s", async (reason, status) => {
		const runtime = harness({ current: "aal2", samlError: `saml_policy_${reason}` });
		const response = await runtime.handler(request(samlPolicyToken(), approve));
		expect(response.status).toBe(status);
		expect(await response.json()).toEqual({ error: `saml_policy_${reason}` });
	});

	it("returns a safe unavailable response for unknown SQL errors or thrown RPC failures", async () => {
		for (const options of [{ samlError: "database credential is private" }, { samlThrows: true }]) {
			const runtime = harness({ current: "aal2", ...options });
			const response = await runtime.handler(request(samlPolicyToken(), approve));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "saml_policy_unavailable" });
		}
	});

	it("maps a missing request to 404 and refuses malformed or cross-tenant metadata", async () => {
		for (const data of [null, true, {}, { ...SAML_CHANGE, tenant_id: OTHER }]) {
			const runtime = harness({ current: "aal2", samlData: data });
			const response = await runtime.handler(request(samlPolicyToken(), get));
			expect(response.status).toBe(data === null ? 404 : 503);
		}
	});

	it("reports an unreadable identity barrier and null mutation outcomes as unavailable", async () => {
		const runtime = harness({ current: "aal2", failTable: "identity_user_session_state" });
		expect((await runtime.handler(request(samlPolicyToken(), enable))).status).toBe(503);
		expect(samlCalls(runtime)).toEqual([]);
		const empty = harness({ current: "aal2", samlData: null });
		const response = await empty.handler(request(samlPolicyToken(), enable));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "saml_policy_unavailable" });
	});

	it("exposes the current enforced provider IDs without dropping existing status fields", async () => {
		const runtime = harness({ current: "aal2" });
		runtime.tables.tenant_identity_policies[0].required_saml_provider_id = OTHER;
		const response = await runtime.handler(request(samlPolicyToken(), { action: "status", tenant_id: TEAM }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, tenant_id: TEAM, role: "owner", require_mfa: true,
			required_saml_provider_id: OTHER, required_oidc_provider_id: null, break_glass_enabled: true, current_assurance: "aal2", access_allowed: true });
	});

	it("rejects Auth-unverified tokens before any SAML request RPC", async () => {
		const runtime = harness({ current: "aal2", invalidToken: true });
		const response = await runtime.handler(request(samlPolicyToken(), enable));
		expect(response.status).toBe(401);
		expect(runtime.rpc).not.toHaveBeenCalled();
	});

	describe("plan gating (entra_sso)", () => {
		const FREE = { data: {
			tenant_id: TEAM, plan_id: "free", plan_source: "default", trial_active: false,
			features: ["local_detection", "dashboard"], retention_days_max: 7,
		}, error: null };
		const planCalls = (runtime: ReturnType<typeof harness>) => runtime.rpc.mock.calls.filter(([name]) => name === "tenant_plan_entitlements");

		it.each([enable, approve, get])("answers 402 for $action on a free plan before any SAML policy RPC", async (body) => {
			const runtime = harness({ current: "aal2", plan: FREE });
			const response = await runtime.handler(request(samlPolicyToken(), body));
			expect(response.status).toBe(402);
			expect(await response.json()).toEqual({ error: "plan_feature_required", feature: "entra_sso", plan_id: "free", required_plan: "team" });
			expect(planCalls(runtime)).toEqual([["tenant_plan_entitlements", { p_tenant_id: TEAM }]]);
			expect(samlCalls(runtime)).toEqual([]);
			expect(runtime.tables.admin_audit_logs).toEqual([]);
		});

		it.each([
			["an RPC error", { data: null, error: { message: "private database error" } }],
			["a malformed row", { data: { tenant_id: TEAM, plan_id: "platinum" }, error: null }],
			["another tenant's row", { data: { ...FREE.data, tenant_id: OTHER, plan_id: "team", features: ["entra_sso"] }, error: null }],
		])("fails closed with 503 on %s", async (_label, plan) => {
			const runtime = harness({ current: "aal2", plan });
			const response = await runtime.handler(request(samlPolicyToken(), enable));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "plan_entitlement_unavailable" });
			expect(samlCalls(runtime)).toEqual([]);
		});

		it("checks the plan only for a confirmed owner, and never for other identity actions", async () => {
			const member = harness({ current: "aal2", plan: FREE });
			member.tables.tenant_members[0].role = "admin";
			expect((await member.handler(request(samlPolicyToken(), enable))).status).toBe(403);
			expect(planCalls(member)).toEqual([]);
			const status = harness({ current: "aal2", plan: FREE });
			expect((await status.handler(request(samlPolicyToken(), { action: "status", tenant_id: TEAM }))).status).toBe(200);
			expect(planCalls(status)).toEqual([]);
		});
	});
});

describe("identity-security bootstrap handler", () => {
	it.each([
		["request_password_reset", "identity-reset:aggregate", 1000, 202],
		["break_glass_recover", "identity-break-glass:aggregate", 300, 401],
	] as const)("bounds anonymous %s work across distinct emails", async (action, key, maximum, allowedStatus) => {
		const runtime = harness();
		runtime.tables.rate_limits.push({ key, window_start: Math.floor(Date.parse(NOW) / 600_000), count: maximum - 1 });
		const body = { action, recovery_challenge: "b".repeat(64), recovery_code: "invalid" };
		const first = await runtime.handler(request(null, { ...body, email: "first@example.test" }));
		expect(first.status).toBe(allowedStatus);
		const auditRows = runtime.tables.admin_audit_logs.length;
		const callCount = runtime.rpc.mock.calls.length;
		for (const email of ["second@example.test", "third@example.test"]) {
			const denied = await runtime.handler(request(null, { ...body, email }));
			expect(denied.status).toBe(429);
			expect(await denied.json()).toEqual({ error: "rate_limited" });
		}
		// Only the fixed aggregate is touched after saturation; no new email buckets or audits.
		expect(runtime.tables.rate_limits).toHaveLength(2);
		expect(runtime.tables.admin_audit_logs).toHaveLength(auditRows);
		expect(runtime.rpc.mock.calls.slice(callCount)).toEqual([
			["increment_rate_limit", { p_key: key, p_window_start: Math.floor(Date.parse(NOW) / 600_000), p_delta: 1 }],
			["increment_rate_limit", { p_key: key, p_window_start: Math.floor(Date.parse(NOW) / 600_000), p_delta: 1 }],
		]);
	});

	it.each(["request_password_reset", "break_glass_recover"])("fails closed before anonymous %s subject work when aggregate storage fails", async (action) => {
		const runtime = harness({ rpcError: true });
		const response = await runtime.handler(request(null, { action, email: "first@example.test", recovery_challenge: "b".repeat(64) }));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "recovery_unavailable" });
		expect(runtime.rpc).toHaveBeenCalledTimes(1);
		expect(runtime.tables.admin_audit_logs).toEqual([]);
	});

	it("rejects an understated chunked body before authentication", async () => {
		const runtime = harness();
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new Uint8Array(8193));
				controller.close();
			},
		});
		const response = await runtime.handler(new Request(
			"https://test.supabase.co/functions/v1/identity-security",
			{
				method: "POST",
				headers: { Authorization: `Bearer ${JWT}`, "content-length": "2" },
				body,
				duplex: "half",
			} as RequestInit,
		));
		expect(response.status).toBe(413);
		expect(await response.json()).toEqual({ error: "request_too_large" });
		expect(runtime.getUser).not.toHaveBeenCalled();
		expect(runtime.queries).toEqual([]);
	});

	it("lets an AAL1 caller globally revoke their own sessions without tenant membership", async () => {
		const runtime = harness({ current: "aal1" });
		runtime.tables.tenant_members = [];
		const response = await runtime.handler(request(JWT, { action: "revoke_sessions", scope: "global" }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			ok: true,
			scope: "global",
			reauthentication_required: true,
		});
		expect(runtime.rpc).toHaveBeenCalledWith("begin_identity_global_revocation", {
			p_user_id: USER,
			p_actor_user_id: USER,
			p_session_id: SESSION,
			p_access_token_issued_at: new Date(Date.parse(NOW) - 60_000).toISOString(),
		});
		expect(runtime.rpc).toHaveBeenCalledWith("complete_identity_global_revocation", {
			p_user_id: USER,
			p_actor_user_id: USER,
			p_session_id: SESSION,
		});
		expect(runtime.signOut).toHaveBeenCalledWith(JWT, "global");
		expect(runtime.rpc).toHaveBeenCalledTimes(2);
		expect(runtime.events).toEqual([
			"authenticate",
			"revocation-begin",
			"auth-signout",
			"revocation-complete",
		]);
		expect(runtime.queries).toEqual([]);
	});

	it.each([
		["revocation barrier", { rpcError: true }, false],
		["auth sign-out", { signOutError: true }, true],
	] as const)("fails closed when global %s fails", async (_name, options, reachesSignOut) => {
		const runtime = harness(options);
		const response = await runtime.handler(request(JWT, { action: "revoke_sessions", scope: "global" }));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "session_revoke_failed" });
		expect(runtime.signOut).toHaveBeenCalledTimes(reachesSignOut ? 1 : 0);
	});

	it("rejects a completed old-token replay without revoking newer sessions", async () => {
		const runtime = harness();
		const body = { action: "revoke_sessions", scope: "global" };

		expect((await runtime.handler(request(JWT, body))).status).toBe(200);
		const replay = await runtime.handler(request(JWT, body));

		expect(replay.status).toBe(401);
		expect(await replay.json()).toEqual({ error: "session_revoked" });
		expect(runtime.signOut).toHaveBeenCalledTimes(1);
		expect(runtime.rpc).toHaveBeenCalledTimes(3);
		expect(
			runtime.rpc.mock.calls.filter(([name]) => name === "complete_identity_global_revocation"),
		).toHaveLength(1);
		expect(runtime.tables.identity_user_session_state).toEqual([
			{ user_id: USER, revoked_before: NOW },
		]);
	});

	it("retries Auth sign-out with the same JWT after the revocation barrier committed", async () => {
		const runtime = harness({ signOutFailures: 1 });
		const body = { action: "revoke_sessions", scope: "global" };

		const first = await runtime.handler(request(JWT, body));
		expect(first.status).toBe(503);
		expect(await first.json()).toEqual({ error: "session_revoke_failed" });
		expect(runtime.tables.identity_user_session_state).toEqual([
			{
				user_id: USER,
				revoked_before: NOW,
				global_revoke_pending_session_id: SESSION,
			},
		]);

		const retry = await runtime.handler(request(JWT, body));
		expect(retry.status).toBe(200);
		expect(await retry.json()).toMatchObject({ ok: true, scope: "global" });
		expect(runtime.getUser).toHaveBeenCalledTimes(2);
		expect(runtime.rpc).toHaveBeenCalledTimes(3);
		expect(runtime.signOut).toHaveBeenCalledTimes(2);
		expect(runtime.events).toEqual([
			"authenticate",
			"revocation-begin",
			"auth-signout",
			"authenticate",
			"revocation-begin",
			"auth-signout",
			"revocation-complete",
		]);
		expect(runtime.queries).toEqual([]);
	});

	it.each(["barrier", "auth-signout", "password-update", "password-complete"] as const)(
		"resumes password recovery after a one-time %s failure and short-circuits completed replay",
		async (failOnceAt) => {
			const runtime = harness({ failOnceAt });
			const body = {
				action: "complete_password_recovery",
				recovery_verifier: "a".repeat(43),
				new_password: "correct horse battery staple 42",
			};

			const first = await runtime.handler(request(OTP_JWT, body));
			expect(first.status).toBe(503);
			const retry = await runtime.handler(request(OTP_JWT, body));
			expect(retry.status).toBe(200);
			expect(await retry.json()).toMatchObject({ ok: true, reauthentication_required: true });

			const updatesAfterCompletion = runtime.updateUserById.mock.calls.length;
			const signOutsAfterCompletion = runtime.signOut.mock.calls.length;
			const replay = await runtime.handler(request(OTP_JWT, body));
			expect(replay.status).toBe(200);
			expect(runtime.updateUserById).toHaveBeenCalledTimes(updatesAfterCompletion);
			expect(runtime.signOut).toHaveBeenCalledTimes(signOutsAfterCompletion);
			expect(
				runtime.rpc.mock.calls.filter(([name]) =>
					name === "complete_identity_password_recovery_completion"
				),
			).toHaveLength(failOnceAt === "password-complete" ? 2 : 1);
		},
	);

	it.each([
		"generate-link",
		"grant",
		"factor-delete",
		"audit",
		"break-glass-complete",
	] as const)(
		"resumes the same proof after a one-time break-glass %s failure and denies a different proof",
		async (failOnceAt) => {
			const runtime = harness({ failOnceAt });
			const recoveryCode = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-00000-11111";
			const body = {
				action: "break_glass_recover",
				email: "private@example.test",
				recovery_code: recoveryCode,
				recovery_challenge: "b".repeat(64),
			};

			const first = await runtime.handler(request(null, body));
			expect(first.status).toBe(503);
			if (failOnceAt === "generate-link" || failOnceAt === "grant") {
				expect(runtime.deleteFactor).not.toHaveBeenCalled();
			}

			const retry = await runtime.handler(request(null, body));
			expect(retry.status).toBe(200);
			expect(await retry.json()).toMatchObject({
				ok: true,
				recovery_token_hash: "a".repeat(64),
				recovery_type: "recovery",
			});
			const externalCalls = runtime.generateLink.mock.calls.length;

			const stolenProof = await runtime.handler(request(null, {
				...body,
				recovery_challenge: "c".repeat(64),
			}));
			expect(stolenProof.status).toBe(401);
			expect(await stolenProof.json()).toEqual({ error: "invalid_or_expired_recovery_code" });
			expect(runtime.generateLink).toHaveBeenCalledTimes(externalCalls);
		},
	);

	it("authenticates and checks revocation before exposing minimal AAL1 membership requirements", async () => {
		const runtime = harness();
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, memberships: [{
			team_id: TEAM, tenant_id: TEAM, require_mfa: true,
			current_assurance: "aal1", next_assurance: "aal2", access_allowed: false,
		}] });
		expect(runtime.getUser).toHaveBeenCalledWith(JWT);
		expect(runtime.getAssurance).toHaveBeenCalledWith(JWT);
		expect(runtime.events.slice(0, 4)).toEqual(["authenticate", "identity_user_session_state", "assurance", "tenant_members"]);
		expect(runtime.queries).toEqual([
			{ table: "identity_user_session_state", columns: "revoked_before,global_revoke_pending_session_id", filters: [["eq", "user_id", USER]] },
			{ table: "tenant_members", columns: "tenant_id,expires_at", filters: [["eq", "user_id", USER], ["or", `expires_at.is.null,expires_at.gt.${NOW}`, null]] },
			{ table: "tenants", columns: "id", filters: [["in", "id", [TEAM]], ["eq", "status", "active"]], order: { field: "id", ascending: true } },
			{ table: "team_members", columns: "team_id,tenant_id", filters: [["eq", "user_id", USER], ["in", "tenant_id", [TEAM]]], order: { field: "joined_at", ascending: false } },
			{ table: "teams", columns: "id,tenant_id", filters: [["in", "id", [TEAM]], ["in", "tenant_id", [TEAM]]] },
			{ table: "tenant_identity_policies", columns: "tenant_id,require_mfa,required_saml_provider_id,required_oidc_provider_id", filters: [["in", "tenant_id", [TEAM]]] },
		]);
	});

	it("keeps SSO-required tenant actions closed to email sessions and accepts matching SAML after MFA", async () => {
		const runtime = harness({ current: "aal2" });
		runtime.tables.tenant_identity_policies[0].required_saml_provider_id = OTHER;
		const bootstrap = await runtime.handler(request());
		expect((await bootstrap.json()).memberships[0].access_allowed).toBe(false);
		const denied = await runtime.handler(request(JWT, { action: "status", tenant_id: TEAM }));
		expect(denied.status).toBe(403);
		expect(await denied.json()).toEqual({ error: "sso_required" });
		const permitted = await runtime.handler(request(SAML_JWT, { action: "status", tenant_id: TEAM }));
		expect(permitted.status).toBe(200);
		expect(await permitted.json()).toMatchObject({ access_allowed: true });
	});

	it("returns newest canonical team memberships first, then tenant-only identifiers", async () => {
		const runtime = harness();
		const unmatched = "44444444-4444-4444-8444-444444444444";
		runtime.tables.tenant_members = [USER, TEAM, OTHER, unmatched].map((tenantId) => ({
			user_id: USER, tenant_id: tenantId, expires_at: null,
		}));
		runtime.tables.tenants = [USER, TEAM, OTHER, unmatched].map((id) => ({ id, status: "active" }));
		// Intentionally neither UUID nor source row order matches recency. The
		// newest unmatched team relation must never become the default either.
		runtime.tables.team_members = [
			{ user_id: USER, team_id: TEAM, tenant_id: TEAM, joined_at: "2026-01-01T00:00:00Z" },
			{ user_id: USER, team_id: unmatched, tenant_id: unmatched, joined_at: "2026-09-01T00:00:00Z" },
			{ user_id: USER, team_id: OTHER, tenant_id: OTHER, joined_at: "2026-06-01T00:00:00Z" },
		];
		runtime.tables.teams = [
			{ id: TEAM, tenant_id: TEAM },
			{ id: unmatched, tenant_id: USER },
			{ id: OTHER, tenant_id: OTHER },
		];
		runtime.tables.tenant_identity_policies = [{ tenant_id: OTHER, require_mfa: true }];
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		const result = await response.json();
		expect(result.memberships).toEqual([
			{ team_id: OTHER, tenant_id: OTHER, require_mfa: true, current_assurance: "aal1", next_assurance: "aal2", access_allowed: false },
			{ team_id: TEAM, tenant_id: TEAM, require_mfa: false, current_assurance: "aal1", next_assurance: "aal2", access_allowed: true },
			{ team_id: null, tenant_id: USER, require_mfa: false, current_assurance: "aal1", next_assurance: "aal2", access_allowed: true },
			{ team_id: null, tenant_id: unmatched, require_mfa: false, current_assurance: "aal1", next_assurance: "aal2", access_allowed: true },
		]);
		expect(runtime.queries.find((query) => query.table === "team_members")).toMatchObject({
			columns: "team_id,tenant_id", order: { field: "joined_at", ascending: false },
		});
	});

	it.each([null, "invalid", "expired"])("rejects a missing, invalid, or Auth-expired token (%s) before membership reads", async (token) => {
		const runtime = harness({ invalidToken: true });
		const response = await runtime.handler(request(token));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: token ? "invalid_access_token" : "missing_access_token" });
		expect(runtime.queries).toEqual([]);
		expect(runtime.getAssurance).not.toHaveBeenCalled();
		if (!token) expect(runtime.getUser).not.toHaveBeenCalled();
	});

	it.each(["2026-09-16T11:59:00.000Z", NOW])("rejects a revoked token at/before the barrier (%s)", async (revokedBefore) => {
		const runtime = harness();
		runtime.tables.identity_user_session_state.push({ user_id: USER, revoked_before: revokedBefore });
		const response = await runtime.handler(request());
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "session_revoked" });
		expect(runtime.queries.map((query) => query.table)).toEqual(["identity_user_session_state"]);
		expect(runtime.getAssurance).not.toHaveBeenCalled();
	});

	it("ignores client-selected tenant/user/team identifiers and excludes other users' memberships", async () => {
		const runtime = harness();
		runtime.tables.tenant_members.push({ user_id: OTHER, tenant_id: OTHER, expires_at: null });
		runtime.tables.tenants.push({ id: OTHER, status: "active" });
		runtime.tables.team_members.push({ user_id: OTHER, team_id: OTHER, tenant_id: OTHER });
		runtime.tables.teams.push({ id: OTHER, tenant_id: OTHER });
		const response = await runtime.handler(request(JWT, { tenant_id: OTHER, team_id: OTHER, user_id: OTHER }));
		expect(response.status).toBe(200);
		const result = await response.json();
		expect(result.memberships).toHaveLength(1);
		expect(result.memberships[0].tenant_id).toBe(TEAM);
		expect(JSON.stringify(result)).not.toContain(OTHER);
	});

	it.each(["2026-09-15T12:00:00.000Z", NOW, "invalid"])("excludes expired or invalid memberships (%s) before tenant reads", async (expiresAt) => {
		const runtime = harness();
		runtime.tables.tenant_members[0].expires_at = expiresAt;
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, memberships: [] });
		expect(runtime.queries.map((query) => query.table)).toEqual(["identity_user_session_state", "tenant_members"]);
	});

	it("accepts a still-active expiring membership", async () => {
		const runtime = harness();
		runtime.tables.tenant_members[0].expires_at = "2026-09-17T12:00:00.000Z";
		const response = await runtime.handler(request());
		expect((await response.json()).memberships).toHaveLength(1);
	});

	it.each(["suspended", "closing", "closed"])("excludes %s tenants before policy/team reads", async (status) => {
		const runtime = harness();
		runtime.tables.tenants[0].status = status;
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, memberships: [] });
		expect(runtime.queries.map((query) => query.table)).toEqual(["identity_user_session_state", "tenant_members", "tenants"]);
	});

	it("returns an empty list for callers without tenant membership", async () => {
		const runtime = harness();
		runtime.tables.tenant_members = [];
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, memberships: [] });
	});

	it("does not expose a team identifier without the caller's team membership", async () => {
		const runtime = harness();
		runtime.tables.team_members[0].user_id = OTHER;
		const response = await runtime.handler(request());
		expect((await response.json()).memberships[0]).toMatchObject({ tenant_id: TEAM, team_id: null });
		expect(runtime.queries.some((query) => query.table === "teams")).toBe(false);
	});

	it("checks the team's canonical tenant relation, not merely its identifier", async () => {
		const runtime = harness();
		runtime.tables.teams[0].tenant_id = OTHER;
		const response = await runtime.handler(request());
		expect((await response.json()).memberships[0]).toMatchObject({ tenant_id: TEAM, team_id: null });
	});

	it("supports personal tenant membership without inventing a team", async () => {
		const runtime = harness();
		runtime.tables.tenant_members = [{ user_id: USER, tenant_id: USER, expires_at: null }];
		runtime.tables.tenants = [{ id: USER, status: "active" }];
		const response = await runtime.handler(request());
		expect(await response.json()).toEqual({ ok: true, memberships: [{
			team_id: null, tenant_id: USER, require_mfa: false,
			current_assurance: "aal1", next_assurance: "aal2", access_allowed: true,
		}] });
	});

	it.each(["aal1", "aal2", null] as const)("reports assurance %s without granting required-MFA access prematurely", async (current) => {
		const runtime = harness({ current });
		const response = await runtime.handler(request());
		expect((await response.json()).memberships[0]).toMatchObject({ current_assurance: current, access_allowed: current === "aal2" });
	});

	it("reports enrollment is needed when MFA is required but the next level is aal1", async () => {
		const runtime = harness({ next: "aal1" });
		const response = await runtime.handler(request());
		expect((await response.json()).memberships[0]).toMatchObject({ require_mfa: true, current_assurance: "aal1", next_assurance: "aal1", access_allowed: false });
	});

	it("defaults only a missing policy row to optional MFA", async () => {
		const runtime = harness();
		runtime.tables.tenant_identity_policies = [];
		const response = await runtime.handler(request());
		expect((await response.json()).memberships[0]).toMatchObject({ require_mfa: false, access_allowed: true });
	});

	it.each(["identity_user_session_state", "tenant_members", "tenants", "team_members", "teams", "tenant_identity_policies"])("fails closed when %s cannot be read", async (failTable) => {
		const runtime = harness({ failTable });
		const response = await runtime.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: failTable === "identity_user_session_state" ? "identity_state_unavailable" : "identity_bootstrap_unavailable" });
		expect(runtime.queries.at(-1)?.table).toBe(failTable);
	});

	it("fails closed on assurance lookup failure before membership reads", async () => {
		const runtime = harness({ assuranceError: true });
		const response = await runtime.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "assurance_unavailable" });
		expect(runtime.queries.map((query) => query.table)).toEqual(["identity_user_session_state"]);
	});
});
