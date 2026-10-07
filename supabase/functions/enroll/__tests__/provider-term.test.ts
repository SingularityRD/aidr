import { generateKeyPairSync, randomUUID, verify, webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const USER_ID = "11111111-1111-4111-8111-111111111111";
const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const AGENT_ID = "33333333-3333-4333-8333-333333333333";
const RUNTIME_CAPS = ["runtime_detectors", "behavioral_learning_v1"];
const signer = generateKeyPairSync("ed25519");

function configureSigning() {
	vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_KEY_ID", "runtime-test-key");
	vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64", signer.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"));
}

type RateFailure = "update" | "read" | "missing" | "over-limit";

async function enroll(
	effectiveRows: unknown,
	allowedAgents = 2,
	admissionResult?: Record<string, unknown>,
	rateFailure?: RateFailure,
	exchangeOverrides: Record<string, unknown> = {},
) {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role");
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => process.env[name] },
		serve: (value: typeof handler) => { handler = value; },
	});
	const upsert = vi.fn(async (_row: Record<string, unknown>) => ({ error: null }));
	const rpc = vi.fn(async (name: string) => {
		if (name === "resolve_enrollment_token") return {
			data: { user_id: USER_ID, tenant_id: TENANT_ID }, error: null,
		};
		if (name === "increment_rate_limit") return {
			data: null, error: rateFailure === "update" ? { message: "rate store unavailable" } : null,
		};
		if (name === "exchange_enrollment_token") return {
			data: { status: "enrolled", user_id: USER_ID, tenant_id: TENANT_ID,
				agent_id: AGENT_ID, included_agents: 1, extra_agents: 1,
				allowed_agents: allowedAgents, revocation_epoch: 1,
				premium_intel: false, premium_correlation: false, premium_pkg_plugin: false, ...exchangeOverrides },
			error: null,
		};
		if (name === "effective_tenant_seats") return { data: effectiveRows, error: null };
		if (name === "get_tenant_admission") return { data: admissionResult ?? {
			mode: "cloud", status: "active", access_kind: "licensed",
			allowed_agents: allowedAgents,
			expires_at: new Date(Date.now() + 30 * 86_400_000).toISOString(),
			trial_available: false,
		}, error: null };
		throw new Error(`unexpected RPC: ${name}`);
	});
	sdk.createClient.mockReturnValue({
		rpc,
		from(table: string) {
			if (table === "rate_limits") {
				const query = { select: () => query, eq: () => query,
					// Unresolved-token budget (read before resolution): empty window.
					maybeSingle: async () => ({ data: null, error: null }),
					single: async () => ({
						data: rateFailure === "missing" ? null : { count: rateFailure === "over-limit" ? 999 : 1 },
						error: rateFailure === "read" ? { message: "rate store unavailable" } : null,
					}) };
				return query;
			}
			if (table === "entitlement_snapshots") return { upsert };
			if (table === "admin_audit_logs") return { insert: async () => ({ error: null }) };
			throw new Error(`unexpected table: ${table}`);
		},
	});
	vi.resetModules();
	await import("../index.ts");
	if (!handler) throw new Error("enroll did not register a handler");
	return { handler, rpc, upsert };
}

function request(fields: Record<string, unknown> = {}) {
	return new Request("https://project.supabase.co/functions/v1/enroll", {
		method: "POST",
		headers: { Authorization: "Bearer aidr_enroll_test-token", "Content-Type": "application/json" },
		body: JSON.stringify({ iid: "host-1", ...fields }),
	});
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
});

describe("enrollment provider term", () => {
	it.each(["update", "read", "missing"] as const)("fails closed when rate-limit %s is unavailable", async (failure) => {
		const runtime = await enroll([], 2, undefined, failure);
		const response = await runtime.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({
			error: "enrollment_rate_limit_unavailable", enrollment_outcome: "not_committed",
		});
		expect(runtime.rpc).not.toHaveBeenCalledWith("exchange_enrollment_token", expect.anything());
		expect(runtime.upsert).not.toHaveBeenCalled();
	});

	it("returns a real rate-limit response for an over-limit counter", async () => {
		const runtime = await enroll([], 2, undefined, "over-limit");
		const response = await runtime.handler(request());
		expect(response.status).toBe(429);
		expect(await response.json()).toEqual({ error: "rate_limited", enrollment_outcome: "not_committed" });
		expect(runtime.rpc).not.toHaveBeenCalledWith("exchange_enrollment_token", expect.anything());
	});

	it("caps the persisted signed-snapshot inputs at the verified period end", async () => {
		const term = new Date(Date.now() + 2 * 3_600_000).toISOString();
		const runtime = await enroll([{ extra_agents: 1, provider_valid_until: term }]);
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		const snapshot = runtime.upsert.mock.calls[0]?.[0]?.entitlement as Record<string, unknown>;
		expect(snapshot).toMatchObject({ extra_agents: 1, allowed_agents: 2 });
		expect(Date.parse(snapshot.expires_at as string)).toBeLessThanOrEqual(Date.parse(term));
		expect(Date.parse(snapshot.grace_until as string)).toBeLessThanOrEqual(Date.parse(term));
	});

	it("does not issue a stale paid snapshot after a committed exchange", async () => {
		const runtime = await enroll([{ extra_agents: 0, provider_valid_until: null }]);
		const response = await runtime.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({
			error: "enrollment_committed_entitlement_unavailable", enrollment_outcome: "committed",
		});
		expect(runtime.upsert).not.toHaveBeenCalled();
	});

	it("caps trial expiry and offline grace without applying that cap to paid mode", async () => {
		const trialEnd = new Date(Date.now() + 2 * 3_600_000).toISOString();
		const runtime = await enroll([{ extra_agents: 0, provider_valid_until: null }], 1, {
			mode: "cloud", status: "active", access_kind: "trial", allowed_agents: 1,
			expires_at: trialEnd, trial_available: false,
		});
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		const snapshot = runtime.upsert.mock.calls[0]?.[0]?.entitlement as Record<string, unknown>;
		expect(snapshot).toMatchObject({ extra_agents: 0, allowed_agents: 1 });
		expect(Date.parse(snapshot.expires_at as string)).toBeLessThanOrEqual(Date.parse(trialEnd));
		expect(Date.parse(snapshot.grace_until as string)).toBeLessThanOrEqual(Date.parse(trialEnd));
	});

	it("returns a cryptographically signed operator grant bound to the licensed tenant and provider term", async () => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const term = new Date(Date.now() + 2 * 3_600_000).toISOString();
		const runtime = await enroll([{ extra_agents: 1, provider_valid_until: term }]);
		const response = await runtime.handler(request());
		const body = await response.json();
		expect(response.status).toBe(200);
		const signed = body.entitlement_signed;
		expect(signed).toMatchObject({ alg: "ed25519", key_id: "runtime-test-key", snapshot: {
			tenant_id: TENANT_ID, subscription_tier: "pro", premium_modules: RUNTIME_CAPS,
			allowed_agents: 2, revocation_epoch: 1, expires_at: term, grace_until: term,
		} });
		expect(verify(null, Buffer.from(JSON.stringify(signed.snapshot)), signer.publicKey, Buffer.from(signed.sig_b64, "base64"))).toBe(true);
		expect(verify(null, Buffer.from(JSON.stringify({ ...signed.snapshot, premium_modules: [] })), signer.publicKey, Buffer.from(signed.sig_b64, "base64"))).toBe(false);
		expect(runtime.upsert).toHaveBeenCalledWith(expect.objectContaining({
			tenant_id: TENANT_ID, entitlement: signed.snapshot, sig_b64: signed.sig_b64,
		}), { onConflict: "tenant_id,iid" });
		expect(runtime.rpc).toHaveBeenCalledWith("get_tenant_admission", { p_tenant_id: TENANT_ID, p_user_id: USER_ID });
	});

	it.each([
		["disabled", ""],
		["foreign tenant", JSON.stringify({ foreign: RUNTIME_CAPS })],
		["malformed", "{"],
		["wildcard", JSON.stringify({ "*": RUNTIME_CAPS })],
		["unknown", JSON.stringify({ [TENANT_ID]: ["premium_intel"] })],
		["learning without detector", JSON.stringify({ [TENANT_ID]: ["behavioral_learning_v1"] })],
	] as const)("does not convert %s configuration or client claims into a signed runtime grant", async (_name, config) => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", config);
		const runtime = await enroll([{ extra_agents: 0, provider_valid_until: null }], 1);
		const response = await runtime.handler(request({
			tenant_id: "foreign", subscription_tier: "enterprise", premium_modules: RUNTIME_CAPS,
			runtime_detectors: true, behavioral_learning_v1: true,
			entitlement: { premium_modules: RUNTIME_CAPS },
		}));
		const body = await response.json();
		expect(response.status).toBe(200);
		expect(body.entitlement_signed.snapshot).toMatchObject({ tenant_id: TENANT_ID, subscription_tier: "free", premium_modules: [] });
		expect(runtime.rpc).toHaveBeenCalledWith("exchange_enrollment_token", expect.objectContaining({
			p_iid: "host-1", p_agent_runtime: null, p_agent_runtime_version: null,
		}));
	});

	it.each(["trial", "pilot"])("does not grant runtime capabilities for %s admission", async (kind) => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const runtime = await enroll([{ extra_agents: 0, provider_valid_until: null }], 1, {
			mode: kind === "pilot" ? "pilot" : "cloud", status: "active", access_kind: kind,
			allowed_agents: 1, expires_at: kind === "pilot" ? null : new Date(Date.now() + 3_600_000).toISOString(),
		});
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		expect((await response.json()).entitlement_signed.snapshot.premium_modules).toEqual([]);
	});

	it.each([
		["free", { access_kind: "free" }],
		["expired", { expires_at: "2000-01-01T00:00:00.000Z" }],
		["unbounded", { expires_at: null }],
	] as const)("cannot issue a runtime grant after %s admission is rejected", async (_name, patch) => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const runtime = await enroll([{ extra_agents: 0, provider_valid_until: null }], 1, {
			mode: "cloud", status: "active", access_kind: "licensed", allowed_agents: 1,
			expires_at: new Date(Date.now() + 3_600_000).toISOString(), ...patch,
		});
		const response = await runtime.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "enrollment_committed_admission_unavailable", enrollment_outcome: "committed" });
		expect(runtime.upsert).not.toHaveBeenCalled();
	});

	it("keeps premium intelligence distinct from an explicit runtime capability grant", async () => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", "");
		const runtime = await enroll([{ extra_agents: 0, provider_valid_until: null }], 1, undefined, undefined, { premium_intel: true });
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		expect((await response.json()).entitlement_signed.snapshot.premium_modules).toEqual(["premium_intel"]);
	});

	it("does not persist runtime capabilities when entitlement signing is unconfigured", async () => {
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_KEY_ID", "");
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64", "");
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const runtime = await enroll([{ extra_agents: 0, provider_valid_until: null }], 1);
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		expect((await response.json()).entitlement_signed).toBeNull();
		expect(runtime.upsert.mock.calls[0]?.[0]?.entitlement).toMatchObject({ premium_modules: [] });
	});

	it("does not exchange a one-use enrollment token when a configured runtime grant signer is invalid", async () => {
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_KEY_ID", "runtime-test-key");
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64", `invalid-${randomUUID()}`);
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const runtime = await enroll([{ extra_agents: 0, provider_valid_until: null }], 1);
		const response = await runtime.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "entitlement_signing_unavailable", enrollment_outcome: "not_committed" });
		expect(runtime.rpc).not.toHaveBeenCalled();
		expect(runtime.upsert).not.toHaveBeenCalled();
	});
});
