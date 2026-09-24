import { createHash, webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const USER_ID = "11111111-1111-4111-8111-111111111111";
const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const AGENT_ID = "33333333-3333-4333-8333-333333333333";

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
		api_keys: { user_id: USER_ID, tenant_id: TENANT_ID, revoked: false, agent_id: null },
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
		throw new Error(`Unexpected RPC: ${name}`);
	});
	const db = {
		rpc,
		from(table: string) {
			if (!(table in rows) && table !== "events" && table !== "entitlement_snapshots") {
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

function request() {
	return new Request("https://project.supabase.co/functions/v1/ingest", {
		method: "POST",
		headers: { Authorization: "Bearer test-api-key", "Content-Type": "application/json" },
		body: JSON.stringify({ iid: "host-1", events: [{ event_id: "evt-1", type: "runtime_verdict", verdict: "deny" }] }),
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
});
