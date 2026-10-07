import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const TENANT = "11111111-1111-4111-8111-111111111111";
const CYCLE = "22222222-2222-4222-8222-222222222222";
const CREDENTIAL = "33333333-3333-4333-8333-333333333333";
const USER = "44444444-4444-4444-8444-444444444444";
const state = vi.hoisted(() => ({
	rpcs: vi.fn(), getUser: vi.fn(), from: vi.fn(), ingestError: null as null | { code: string },
	cursor: null as null | Record<string, unknown>,
	membership: null as null | Record<string, unknown>,
	credential: null as null | Record<string, unknown>,
	credentialError: null as null | { code: string },
}));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => ({
		auth: { getUser: state.getUser },
		from: state.from,
		rpc: state.rpcs,
	}),
}));

vi.mock("../discovery/credential.ts", () => ({
	hasCollectorCredentialPrefix: (token: string) => token.startsWith("aidr_collector_"),
	validCollectorCredential: (token: string) => token === "aidr_collector_valid",
	collectorCredentialHash: async () => "test-token-hash",
	createCollectorCredential: () => "unused",
}));

let handle: ((request: Request) => Promise<Response>) | undefined;
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: typeof handle) => { handle = handler; },
};
await import("../discovery/index.ts");

function request(token = "aidr_collector_valid", body: Record<string, unknown> = {
	action: "ingest", tenant_id: TENANT, collector_id: "collector-1", cycle_id: CYCLE,
	sequence: 1, stale_after_ms: 60_000, complete: true, expected_targets: 1,
	items: [{ target: "https://example.test/", reachable: true, attempts: 1, error_code: null }],
}): Request {
	return new Request("https://project.supabase.co/functions/v1/discovery", {
		method: "POST",
		headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

describe("discovery machine handler", () => {
	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
		state.ingestError = null;
		state.cursor = { credential_id: CREDENTIAL, collector_id: "collector-1", last_sequence: 0, next_sequence: 1 };
		state.membership = { role: "member", expires_at: null };
		state.credential = { tenant_id: TENANT, collector_id: "collector-1", revoked_at: null, expires_at: new Date(Date.now() + 86_400_000).toISOString() };
		state.credentialError = null;
		state.getUser.mockReset();
		state.from.mockReset().mockImplementation((table: string) => {
			const query = {
				select: () => query,
				eq: () => query,
				maybeSingle: async () => ({
					data: table === "tenant_members"
						? state.membership
						: table === "tenants"
							? { status: "active" }
							: table === "tenant_discovery_credentials"
								? state.credential
								: null,
					error: table === "tenant_discovery_credentials" ? state.credentialError : null,
				}),
			};
			return query;
		});
		state.rpcs.mockReset().mockImplementation(async (name: string) => {
			if (name === "read_tenant_discovery_collector_cursor") return { data: state.cursor, error: null };
			if (name === "consume_tenant_rate_limit") return { data: [{ allowed: true, remaining: 599 }], error: null };
			if (name === "read_tenant_discovery_summary") return { data: { collectors: 0 }, error: null };
			if (name === "ingest_tenant_discovery_cycle_machine") return {
				data: { cycle_id: CYCLE, sequence: 1 }, error: state.ingestError,
			};
			throw new Error(`unexpected RPC: ${name}`);
		});
	});
	afterEach(() => vi.unstubAllEnvs());

	it("binds a complete collector cycle to its credential and tenant", async () => {
		const response = await handle?.(request());
		expect(response?.status).toBe(201);
		expect(await response?.json()).toMatchObject({ ok: true, cycle: { cycle_id: CYCLE, sequence: 1 } });
		expect(state.rpcs).toHaveBeenCalledWith("read_tenant_discovery_collector_cursor", {
			p_tenant_id: TENANT, p_collector_id: "collector-1", p_token_hash: "test-token-hash",
		});
		expect(state.rpcs).toHaveBeenCalledWith("ingest_tenant_discovery_cycle_machine", expect.objectContaining({
			p_tenant_id: TENANT, p_collector_id: "collector-1", p_token_hash: "test-token-hash",
			p_cycle_id: CYCLE, p_sequence: 1, p_complete: true, p_expected_targets: 1,
		}));
		expect(state.getUser).not.toHaveBeenCalled();
	});

	it("rejects replayed cycles and invalid collector credentials", async () => {
		state.ingestError = { code: "PT409" };
		const replay = await handle?.(request());
		expect(replay?.status).toBe(409);
		expect(await replay?.json()).toMatchObject({ error: "discovery_cycle_replayed" });

		state.rpcs.mockClear();
		const invalid = await handle?.(request("aidr_collector_invalid"));
		expect(invalid?.status).toBe(401);
		expect(state.rpcs).not.toHaveBeenCalled();
	});

	it("authenticates both credential kinds before reading the request body", async () => {
		const large = { action: "summary", tenant_id: TENANT, padding: "x".repeat(400_000) };
		state.credential = null;
		const unknownCollector = request("aidr_collector_valid", large);
		const collectorResponse = await handle?.(unknownCollector);
		expect(collectorResponse?.status).toBe(401);
		expect(await collectorResponse?.json()).toEqual({ error: "invalid_collector_credential" });
		expect(unknownCollector.bodyUsed).toBe(false);
		expect(state.rpcs).not.toHaveBeenCalled();

		state.getUser.mockResolvedValueOnce({ data: { user: null }, error: new Error("invalid token") });
		const invalidSession = request("invalid-user-session", large);
		const sessionResponse = await handle?.(invalidSession);
		expect(sessionResponse?.status).toBe(401);
		expect(await sessionResponse?.json()).toEqual({ error: "invalid_access_token" });
		expect(invalidSession.bodyUsed).toBe(false);
	});

	it.each([
		["revoked", { revoked_at: new Date().toISOString() }],
		["expired", { expires_at: new Date(Date.now() - 1_000).toISOString() }],
		["bound to another tenant", { tenant_id: CREDENTIAL }],
		["bound to another collector", { collector_id: "collector-2" }],
	])("rejects a %s collector credential without any RPC", async (_name, patch) => {
		state.credential = { ...state.credential, ...patch };
		const response = await handle?.(request());
		expect(response?.status).toBe(401);
		expect(await response?.json()).toEqual({ error: "invalid_collector_credential" });
		expect(state.rpcs).not.toHaveBeenCalled();
	});

	it("fails closed when the collector credential lookup is unavailable", async () => {
		state.credentialError = { code: "08006" };
		const response = await handle?.(request());
		expect(response?.status).toBe(503);
		expect(state.rpcs).not.toHaveBeenCalled();
	});

	it("requires the advertised next sequence and a well-formed cursor bound to this collector", async () => {
		state.cursor = { credential_id: CREDENTIAL, collector_id: "collector-1", last_sequence: 4, next_sequence: 5 };
		const skipped = await handle?.(request());
		expect(skipped?.status).toBe(409);
		expect(await skipped?.json()).toMatchObject({ error: "discovery_sequence_conflict" });
		expect(state.rpcs).not.toHaveBeenCalledWith("ingest_tenant_discovery_cycle_machine", expect.anything());

		state.rpcs.mockClear();
		state.cursor = { credential_id: CREDENTIAL, collector_id: "another-collector", last_sequence: 0, next_sequence: 1 };
		const mismatched = await handle?.(request());
		expect(mismatched?.status).toBe(503);
		expect(state.rpcs).not.toHaveBeenCalledWith("ingest_tenant_discovery_cycle_machine", expect.anything());
	});

	it("rejects malformed sequence cursors instead of forwarding them", async () => {
		state.cursor = { credential_id: CREDENTIAL, collector_id: "collector-1", last_sequence: 0, next_sequence: 3 };
		const response = await handle?.(request());
		expect(response?.status).toBe(503);
		expect(state.rpcs).not.toHaveBeenCalledWith("ingest_tenant_discovery_cycle_machine", expect.anything());
	});

	it("rejects invalid user sessions before tenant reads and rejects nonmembers before summary RPCs", async () => {
		state.getUser.mockResolvedValueOnce({ data: { user: null }, error: new Error("invalid token") });
		const invalid = await handle?.(request("invalid-user-session", { action: "summary", tenant_id: TENANT }));
		expect(invalid?.status).toBe(401);
		expect(await invalid?.json()).toEqual({ error: "invalid_access_token" });
		expect(state.from).not.toHaveBeenCalled();
		expect(state.rpcs).not.toHaveBeenCalled();

		state.getUser.mockResolvedValueOnce({ data: { user: { id: USER } }, error: null });
		state.membership = null;
		const nonmember = await handle?.(request("valid-user-session", { action: "summary", tenant_id: TENANT }));
		expect(nonmember?.status).toBe(403);
		expect(await nonmember?.json()).toEqual({ error: "tenant_access_denied" });
		expect(state.rpcs).not.toHaveBeenCalledWith("read_tenant_discovery_summary", expect.anything());
	});

	it("serves the user-session summary only after tenant and identity checks", async () => {
		state.getUser.mockResolvedValueOnce({ data: { user: { id: USER } }, error: null });
		const response = await handle?.(request("valid-user-session", { action: "summary", tenant_id: TENANT }));
		expect(response?.status).toBe(200);
		expect(await response?.json()).toMatchObject({ ok: true, summary: { collectors: 0 } });
		expect(state.from.mock.calls.map(([table]) => table)).toEqual([
			"tenant_members", "tenants", "identity_user_session_state", "tenant_identity_policies",
		]);
		expect(state.rpcs).toHaveBeenCalledWith("read_tenant_discovery_summary", {
			p_tenant_id: TENANT, p_actor_user_id: USER,
		});
	});
});
