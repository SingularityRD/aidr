import { createHash, generateKeyPairSync, randomUUID, verify, webcrypto } from "node:crypto";
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

async function ingest(
	failEventInsert: boolean | { code: string; message: string } = false,
	registration: Record<string, unknown> = { agent_id: AGENT_ID, seat_exceeded: false, allowed_agents: 1 },
	entitlementResult?: { data: Record<string, unknown> | null; error: Record<string, unknown> | null },
	registrationError?: { code: string; message: string },
	effectiveResult: { data: unknown; error: Record<string, unknown> | null } = {
		data: [{ extra_agents: 0, provider_valid_until: null }], error: null,
	},
	admissionResult?: Record<string, unknown>,
) {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role");
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => process.env[name] },
		serve: (value: typeof handler) => { handler = value; },
	});
	const reads: Array<{ table: string; filters: Array<[string, unknown]> }> = [];
	const insertedEvents = vi.fn(async () => ({
		error: failEventInsert
			? typeof failEventInsert === "boolean" ? { message: "private database detail" } : failEventInsert
			: null,
	}));
	const insertedSnapshot = vi.fn(async () => ({ error: null }));
	const rows: Record<string, Record<string, unknown>> = {
		api_keys: { user_id: USER_ID, tenant_id: TENANT_ID, revoked: false, agent_id: null, scope: "tenant" },
		tenant_members: { role: "member", expires_at: null },
		tenants: { status: "active" },
		entitlements: { included_agents: 1, extra_agents: 0, premium_intel: false, premium_correlation: false, premium_pkg_plugin: false, revocation_epoch: 1 },
	};
	const rpc = vi.fn(async (name: string) => {
		const admitted = admissionResult ?? {
			mode: "cloud", status: "active", access_kind: "licensed",
			allowed_agents: Number(registration.allowed_agents ?? 1),
			expires_at: new Date(Date.now() + 30 * 86_400_000).toISOString(),
			trial_available: false,
		};
		if (name === "tenant_admission_capacity") return { data: admitted.allowed_agents, error: null };
		if (name === "get_tenant_admission") return { data: admitted, error: null };
		if (name === "consume_tenant_rate_limit") return { data: [{ allowed: true, remaining: 1199 }], error: null };
		if (name === "register_agent_for_ingest") return registrationError
			? { data: null, error: registrationError }
			: { data: [registration], error: null };
		if (name === "effective_tenant_seats") return effectiveResult;
		if (name === "increment_rate_limit") return { data: null, error: null };
		throw new Error(`Unexpected RPC: ${name}`);
	});
	const db = {
		rpc,
		from(table: string) {
			if (!(table in rows) && table !== "events" && table !== "entitlement_snapshots" && table !== "rate_limits") {
				throw new Error(`Unexpected table: ${table}`);
			}
			const filters: Array<[string, unknown]> = [];
			reads.push({ table, filters });
			return {
				select() { return this; },
				eq(column: string, value: unknown) { filters.push([column, value]); return this; },
				async maybeSingle() {
					return table === "entitlements" && entitlementResult
						? entitlementResult
						: { data: rows[table] ?? null, error: null };
				},
				upsert: table === "events" ? insertedEvents : insertedSnapshot,
			};
		},
	};
	sdk.createClient.mockReturnValue(db);
	vi.resetModules();
	await import("../ingest/index.ts");
	if (!handler) throw new Error("ingest did not register a handler");
	return { handler, rpc, reads, insertedEvents, insertedSnapshot };
}

function request(fields: Record<string, unknown> = {}) {
	return new Request("https://project.supabase.co/functions/v1/ingest", {
		method: "POST",
		headers: { Authorization: "Bearer test-api-key", "Content-Type": "application/json" },
		body: JSON.stringify({ iid: "host-1", events: [{ event_id: "evt-1", type: "runtime_verdict", verdict: "deny" }], ...fields }),
	});
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
});

describe("ingest delivery handler", () => {
	it("acknowledges only an event inserted under the authenticated tenant", async () => {
		const runtime = await ingest();
		const response = await runtime.handler(request());
		const body = await response.json();
		expect(response.status).toBe(200);
		expect(body).toMatchObject({ ok: true, acknowledged_event_ids: ["evt-1"], agent_id: AGENT_ID });
		expect(runtime.insertedEvents).toHaveBeenCalledWith([expect.objectContaining({
			user_id: USER_ID, tenant_id: TENANT_ID, agent_id: AGENT_ID, event_id: "evt-1",
		})], { onConflict: "tenant_id,event_id", ignoreDuplicates: true });
		expect(runtime.reads.find(({ table }) => table === "api_keys")?.filters).toEqual([
			["key_hash", createHash("sha256").update("test-api-key").digest("hex")],
		]);
		expect(runtime.reads.find(({ table }) => table === "tenant_members")?.filters).toEqual([
			["tenant_id", TENANT_ID], ["user_id", USER_ID],
		]);
		expect(runtime.insertedSnapshot).toHaveBeenCalledOnce();
	});

	it("returns retryable 503 without acknowledging events when insertion fails", async () => {
		const runtime = await ingest(true);
		const response = await runtime.handler(request());
		const text = await response.text();
		expect(response.status).toBe(503);
		expect(JSON.parse(text)).toEqual({ error: "events_insert_failed", retryable: true });
		expect(text).not.toContain("private database detail");
		expect(runtime.insertedEvents).toHaveBeenCalledOnce();
		expect(runtime.insertedSnapshot).not.toHaveBeenCalled();
	});

	it("does not endlessly retry an event denied at the final authorization boundary", async () => {
		const runtime = await ingest({ code: "42501", message: "private database detail" });
		const response = await runtime.handler(request());
		const text = await response.text();
		expect(response.status).toBe(403);
		expect(JSON.parse(text)).toEqual({ error: "agent_not_authorized" });
		expect(text).not.toContain("private database detail");
		expect(runtime.insertedEvents).toHaveBeenCalledOnce();
		expect(runtime.insertedSnapshot).not.toHaveBeenCalled();
	});

	it("returns seat-limit 402 when the registration RPC has no agent ID", async () => {
		const runtime = await ingest(false, {
			agent_id: null,
			seat_exceeded: true,
			current_agents: 1,
			allowed_agents: 1,
		});
		const response = await runtime.handler(request());
		const body = await response.json();
		expect(response.status).toBe(402);
		expect(body).toMatchObject({
			error: "agent_limit_exceeded",
			current_agents: 1,
			allowed_agents: 1,
		});
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
		expect(runtime.insertedSnapshot).not.toHaveBeenCalled();
	});

	it("returns only seat counts on seat_exceeded: no signed snapshot and no pack key", async () => {
		configureSigning();
		vi.stubEnv("AIDR_PACK_MASTER_KEY_B64", Buffer.alloc(32, 7).toString("base64"));
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const runtime = await ingest(false,
			{ agent_id: null, seat_exceeded: true, current_agents: 3, allowed_agents: 2 },
			{ data: { included_agents: 1, extra_agents: 1, premium_intel: true, premium_correlation: true, premium_pkg_plugin: true, revocation_epoch: 1 }, error: null },
			undefined,
			{ data: [{ extra_agents: 1, provider_valid_until: null }], error: null });
		const response = await runtime.handler(request());
		const text = await response.text();
		expect(response.status).toBe(402);
		expect(JSON.parse(text)).toEqual({ error: "agent_limit_exceeded", allowed_agents: 2, current_agents: 3 });
		expect(text).not.toMatch(/entitlement_sig|pack_keys|key_b64|snapshot/);
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
		expect(runtime.insertedSnapshot).not.toHaveBeenCalled();
	});

	it("caches a healthy signer per isolate instead of importing the key for every request", async () => {
		configureSigning();
		const importKey = vi.spyOn(webcrypto.subtle, "importKey");
		try {
			const runtime = await ingest();
			for (let i = 0; i < 3; i++) expect((await runtime.handler(request({ events: [] }))).status).toBe(200);
			const pkcs8Imports = importKey.mock.calls.filter(([format]) => format === "pkcs8").length;
			// One healthcheck probe, then one real signature per response.
			expect(pkcs8Imports).toBe(4);
		} finally {
			importKey.mockRestore();
		}
	});

	it("does not mint free seats or insert events for a tenant without an entitlement row", async () => {
		const runtime = await ingest(false, { agent_id: AGENT_ID, seat_exceeded: false, allowed_agents: 1 }, { data: null, error: null });
		const response = await runtime.handler(request());
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "entitlement_not_provisioned" });
		expect(runtime.rpc.mock.calls.map(([name]) => name)).not.toContain("register_agent_for_ingest");
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
		expect(runtime.insertedSnapshot).not.toHaveBeenCalled();
	});

	it("keeps entitlement lookup failures retryable without signing a free entitlement", async () => {
		const runtime = await ingest(false, { agent_id: AGENT_ID, seat_exceeded: false, allowed_agents: 1 }, {
			data: null, error: { message: "private database detail" },
		});
		const response = await runtime.handler(request());
		const body = await response.text();
		expect(response.status).toBe(503);
		expect(JSON.parse(body)).toEqual({ error: "entitlements_unavailable", retryable: true });
		expect(body).not.toContain("private database detail");
		expect(runtime.rpc.mock.calls.map(([name]) => name)).not.toContain("register_agent_for_ingest");
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
		expect(runtime.insertedSnapshot).not.toHaveBeenCalled();
	});

	it("denies enrollment admission failures without acknowledging or signing events", async () => {
		const runtime = await ingest(false, { agent_id: AGENT_ID, seat_exceeded: false, allowed_agents: 1 }, undefined, {
			code: "42501", message: "private admission detail",
		});
		const response = await runtime.handler(request());
		const body = await response.text();
		expect(response.status).toBe(403);
		expect(JSON.parse(body)).toEqual({ error: "tenant_not_admitted" });
		expect(body).not.toContain("private admission detail");
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
		expect(runtime.insertedSnapshot).not.toHaveBeenCalled();
	});

	it("keeps an unexpected missing agent ID distinct from a seat-limit response", async () => {
		const runtime = await ingest(false, { agent_id: null, seat_exceeded: false, allowed_agents: 1 });
		const response = await runtime.handler(request());
		expect(response.status).toBe(500);
		expect(await response.json()).toEqual({ error: "agent_registration_failed" });
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
	});

	it("refuses a stale paid registration before acknowledging any event", async () => {
		const runtime = await ingest(false,
			{ agent_id: AGENT_ID, seat_exceeded: false, allowed_agents: 2 },
			{ data: { included_agents: 1, extra_agents: 1, premium_intel: false, premium_correlation: false, premium_pkg_plugin: false, revocation_epoch: 1 }, error: null },
			undefined,
			{ data: [{ extra_agents: 0, provider_valid_until: null }], error: null });
		const response = await runtime.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "entitlements_changed", retryable: true });
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
	});

	it("never signs offline grace beyond a paid provider term", async () => {
		const term = new Date(Date.now() + 2 * 3_600_000).toISOString();
		const runtime = await ingest(false,
			{ agent_id: AGENT_ID, seat_exceeded: false, allowed_agents: 2 },
			{ data: { included_agents: 1, extra_agents: 1, premium_intel: false, premium_correlation: false, premium_pkg_plugin: false, revocation_epoch: 1 }, error: null },
			undefined,
			{ data: [{ extra_agents: 1, provider_valid_until: term }], error: null });
		const response = await runtime.handler(request());
		const body = await response.json();
		expect(response.status).toBe(200);
		expect(body.entitlement).toMatchObject({ extra_agents: 1, allowed_agents: 2 });
		expect(Date.parse(body.entitlement.expires_at)).toBeLessThanOrEqual(Date.parse(term));
		expect(Date.parse(body.entitlement.grace_until)).toBeLessThanOrEqual(Date.parse(term));
	});

	it("caps trial expiry and grace without needing a provider period", async () => {
		const trialEnd = new Date(Date.now() + 2 * 3_600_000).toISOString();
		const runtime = await ingest(false,
			{ agent_id: AGENT_ID, seat_exceeded: false, allowed_agents: 1 },
			undefined, undefined,
			{ data: [{ extra_agents: 0, provider_valid_until: null }], error: null },
			{ mode: "cloud", status: "active", access_kind: "trial",
				allowed_agents: 1, expires_at: trialEnd, trial_available: false });
		const response = await runtime.handler(request());
		const body = await response.json();
		expect(response.status).toBe(200);
		expect(body.entitlement).toMatchObject({ extra_agents: 0, allowed_agents: 1 });
		expect(Date.parse(body.entitlement.expires_at)).toBeLessThanOrEqual(Date.parse(trialEnd));
		expect(Date.parse(body.entitlement.grace_until)).toBeLessThanOrEqual(Date.parse(trialEnd));
	});

	it("signs explicit runtime capabilities for the authenticated licensed tenant without extending its term", async () => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const term = new Date(Date.now() + 2 * 3_600_000).toISOString();
		const runtime = await ingest(false,
			{ agent_id: AGENT_ID, seat_exceeded: false, allowed_agents: 2 },
			{ data: { included_agents: 1, extra_agents: 1, premium_intel: false, premium_correlation: false, premium_pkg_plugin: false, revocation_epoch: 1 }, error: null },
			undefined, { data: [{ extra_agents: 1, provider_valid_until: term }], error: null });
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
		expect(body.entitlement).toEqual(signed.snapshot);
		expect(runtime.insertedSnapshot).toHaveBeenCalledWith(expect.objectContaining({
			tenant_id: TENANT_ID, entitlement: signed.snapshot, sig_b64: signed.sig_b64,
		}), { onConflict: "tenant_id,iid" });
		expect(runtime.rpc).toHaveBeenCalledWith("get_tenant_admission", { p_tenant_id: TENANT_ID, p_user_id: USER_ID });
	});

	it("uses licensed on-prem admission authority without changing the existing zero-extra-seat tier label", async () => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const term = new Date(Date.now() + 3_600_000).toISOString();
		const runtime = await ingest(false, undefined, undefined, undefined, undefined, {
			mode: "onprem", status: "active", access_kind: "licensed", allowed_agents: 1, expires_at: term,
		});
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		expect((await response.json()).entitlement_signed.snapshot).toMatchObject({
			subscription_tier: "free", premium_modules: RUNTIME_CAPS, expires_at: term, grace_until: term,
		});
	});

	it.each([
		["disabled", ""],
		["foreign tenant", JSON.stringify({ foreign: RUNTIME_CAPS })],
		["malformed", "{"],
		["wildcard", JSON.stringify({ "*": RUNTIME_CAPS })],
		["unknown", JSON.stringify({ [TENANT_ID]: ["premium_intel"] })],
		["learning without detector", JSON.stringify({ [TENANT_ID]: ["behavioral_learning_v1"] })],
	] as const)("does not let %s operator configuration or client entitlement claims mint runtime capabilities", async (_name, config) => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", config);
		const runtime = await ingest();
		const response = await runtime.handler(request({
			tenant_id: "foreign", subscription_tier: "enterprise", premium_modules: RUNTIME_CAPS,
			runtime_detectors: true, behavioral_learning_v1: true,
			entitlement: { premium_modules: RUNTIME_CAPS },
			entitlement_signed: { snapshot: { tenant_id: "foreign", premium_modules: RUNTIME_CAPS } },
		}));
		expect(response.status).toBe(200);
		expect((await response.json()).entitlement_signed.snapshot).toMatchObject({
			tenant_id: TENANT_ID, subscription_tier: "free", premium_modules: [],
		});
		expect(runtime.rpc).toHaveBeenCalledWith("register_agent_for_ingest", {
			p_user_id: USER_ID, p_tenant_id: TENANT_ID, p_iid: "host-1", p_agent_runtime: null, p_agent_runtime_version: null,
		});
	});

	it.each(["trial", "pilot"])("does not grant runtime capabilities for %s admission", async (kind) => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const runtime = await ingest(false, undefined, undefined, undefined, undefined, {
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
	] as const)("does not acknowledge events or issue a grant for %s admission", async (_name, patch) => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const runtime = await ingest(false, undefined, undefined, undefined, undefined, {
			mode: "cloud", status: "active", access_kind: "licensed", allowed_agents: 1,
			expires_at: new Date(Date.now() + 3_600_000).toISOString(), ...patch,
		});
		const response = await runtime.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "admission_unavailable", retryable: true });
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
		expect(runtime.insertedSnapshot).not.toHaveBeenCalled();
	});

	it("does not derive runtime capabilities from premium intelligence", async () => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", "");
		const runtime = await ingest(false, undefined, {
			data: { included_agents: 1, extra_agents: 0, premium_intel: true, premium_correlation: false, premium_pkg_plugin: false, revocation_epoch: 1 }, error: null,
		});
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		expect((await response.json()).entitlement_signed.snapshot.premium_modules).toEqual(["premium_intel"]);
	});

	it("does not publish runtime capabilities when signing is unconfigured", async () => {
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_KEY_ID", "");
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64", "");
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const runtime = await ingest();
		const response = await runtime.handler(request());
		const body = await response.json();
		expect(response.status).toBe(200);
		expect(body.entitlement_signed).toBeNull();
		expect(body.entitlement.premium_modules).toEqual([]);
	});

	it("fails closed before event insertion when a configured runtime grant signer cannot sign", async () => {
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_KEY_ID", "runtime-test-key");
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64", `invalid-${randomUUID()}`);
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const runtime = await ingest();
		const response = await runtime.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "entitlement_signing_unavailable", retryable: true });
		expect(runtime.rpc).not.toHaveBeenCalled();
		expect(runtime.reads).toEqual([]);
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
		expect(runtime.insertedSnapshot).not.toHaveBeenCalled();
	});

	it("removes an operator grant on the next heartbeat without a function reload", async () => {
		configureSigning();
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", JSON.stringify({ [TENANT_ID]: RUNTIME_CAPS }));
		const runtime = await ingest();
		const first = await runtime.handler(request({ events: [] }));
		expect(first.status).toBe(200);
		expect((await first.json()).entitlement_signed.snapshot.premium_modules).toEqual(RUNTIME_CAPS);
		vi.stubEnv("AIDR_RUNTIME_CAPABILITIES_BY_TENANT", undefined);
		const next = await runtime.handler(request({ events: [], premium_modules: RUNTIME_CAPS }));
		const body = await next.json();
		expect(next.status).toBe(200);
		expect(body.entitlement_signed.snapshot.premium_modules).toEqual([]);
		expect(verify(null, Buffer.from(JSON.stringify(body.entitlement_signed.snapshot)), signer.publicKey, Buffer.from(body.entitlement_signed.sig_b64, "base64"))).toBe(true);
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
		expect(runtime.insertedSnapshot).toHaveBeenCalledTimes(2);
	});
});
