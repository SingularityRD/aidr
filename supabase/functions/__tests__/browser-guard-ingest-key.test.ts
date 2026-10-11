// Contract suite for `ingest:browser_guard` API keys
// (supabase/migrations/20260925000061_browser_guard_ingest_keys.sql).
//
// Browser Guard's telemetry key is readable at chrome://policy by anyone using
// the managed profile, so the key must only be able to deliver counts-only
// privacy_scan and shadow_ai_usage events, within a per-key rate budget and installation cap, and
// must never receive the tenant entitlement (which can carry the pack key).
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { leaseAware } from "./lease-rpc-fake.ts";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));
vi.mock("../_shared/identity-barrier.ts", () => ({
	checkIdentityBarrier: async () => ({ ok: true }),
}));

const USER_ID = "11111111-1111-4111-8111-111111111111";
const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const AGENT_ID = "33333333-3333-4333-8333-333333333333";
const KEY_ID = "44444444-4444-4444-8444-444444444444";
const IID = "5b7f3f0e-4a8e-4d59-9c1a-5a3e0b1d2c44";

const BROWSER_KEY_ROW = {
	id: KEY_ID,
	user_id: USER_ID,
	tenant_id: TENANT_ID,
	revoked: false,
	agent_id: null,
	scope: "ingest:browser_guard",
	install_limit: 25,
};

function scan(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		event_id: "bg:0b0c6c1e-7c7e-4b39-9d55-7a1d9d1f8e21",
		event_type: "privacy_scan",
		timestamp: "2026-09-24T10:15:00Z",
		site: "chatgpt",
		action: "masked",
		channel: "prompt",
		entity_counts: { EMAIL: 2 },
		findings_count: 2,
		...overrides,
	};
}

type RpcResult = { data: unknown; error: Record<string, unknown> | null };

// tenant_plan_entitlements answer (catalog features of each plan).
function planRow(planId: "free" | "team" | "business"): RpcResult {
	const features = {
		free: ["local_detection", "dashboard"],
		team: ["local_detection", "dashboard", "browser_privacy_guard", "entra_sso"],
		business: ["local_detection", "dashboard", "browser_privacy_guard", "entra_sso", "siem_export", "scim", "ai_security_posture"],
	}[planId];
	return {
		data: { tenant_id: TENANT_ID, plan_id: planId, plan_source: "stripe_subscription", trial_active: false, features, retention_days_max: null },
		error: null,
	};
}

async function ingestHandler(options: {
	key?: Record<string, unknown>;
	registration?: Record<string, unknown>;
	registrationError?: Record<string, unknown>;
	rate?: RpcResult;
	premium?: boolean;
	plan?: RpcResult;
} = {}) {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role");
	vi.stubEnv("AIDR_PACK_MASTER_KEY_B64", Buffer.alloc(32, 7).toString("base64"));
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => process.env[name] },
		serve: (value: typeof handler) => {
			handler = value;
		},
	});
	const insertedEvents = vi.fn(async () => ({ error: null }));
	const insertedSnapshot = vi.fn(async () => ({ error: null }));
	const rows: Record<string, Record<string, unknown>> = {
		api_keys: options.key ?? BROWSER_KEY_ROW,
		tenant_members: { role: "admin", expires_at: null },
		tenants: { status: "active" },
		entitlements: {
			included_agents: 5,
			extra_agents: 0,
			premium_intel: options.premium ?? false,
			premium_correlation: false,
			premium_pkg_plugin: false,
			revocation_epoch: 1,
		},
	};
	const rpc = vi.fn(async (name: string, _args?: Record<string, unknown>): Promise<RpcResult> => {
		if (name === "tenant_admission_capacity") return { data: 5, error: null };
		if (name === "get_tenant_admission")
			return {
				data: {
					mode: "cloud",
					status: "active",
					access_kind: "licensed",
					allowed_agents: 5,
					expires_at: new Date(Date.now() + 30 * 86_400_000).toISOString(),
					trial_available: false,
				},
				error: null,
			};
		if (name === "consume_tenant_rate_limit")
			return options.rate ?? { data: [{ allowed: true, remaining: 5999 }], error: null };
		if (name === "register_browser_guard_agent_for_ingest" || name === "register_agent_for_ingest") {
			if (options.registrationError) return { data: null, error: options.registrationError };
			return {
				data: [
					options.registration ?? {
						agent_id: AGENT_ID,
						tenant_id: TENANT_ID,
						created: true,
						current_agents: 1,
						allowed_agents: 5,
						seat_exceeded: false,
						install_limit_exceeded: false,
					},
				],
				error: null,
			};
		}
		if (name === "effective_tenant_seats")
			return { data: [{ extra_agents: 0, provider_valid_until: null }], error: null };
		if (name === "tenant_plan_entitlements") return options.plan ?? planRow("business");
		throw new Error(`Unexpected RPC: ${name}`);
	});
	const reads: string[] = [];
	sdk.createClient.mockReturnValue({
		rpc: leaseAware(rpc),
		from(table: string) {
			reads.push(table);
			return {
				select() {
					return this;
				},
				eq() {
					return this;
				},
				async maybeSingle() {
					return { data: rows[table] ?? null, error: null };
				},
				upsert: table === "events" ? insertedEvents : insertedSnapshot,
			};
		},
	});
	vi.resetModules();
	await import("../ingest/index.ts");
	if (!handler) throw new Error("ingest did not register a handler");
	return { handler, rpc, reads, insertedEvents, insertedSnapshot };
}

function ingestRequest(body: Record<string, unknown>) {
	return new Request("https://project.supabase.co/functions/v1/ingest", {
		method: "POST",
		headers: { Authorization: "Bearer aidr_ingest_test-key", "Content-Type": "application/json" },
		body: JSON.stringify({
			iid: IID,
			agent_runtime: "browser_guard",
			agent_runtime_version: "chrome-126",
			aidr_version: "1.0.0",
			events: [scan()],
			...body,
		}),
	});
}

const rpcNames = (rpc: ReturnType<typeof vi.fn>) => rpc.mock.calls.map(([name]) => name);

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
});

describe("ingest with an ingest:browser_guard key", () => {
	it("delivers privacy_scan events through the key-bound registration and per-key budget", async () => {
		const runtime = await ingestHandler({ premium: true });
		const response = await runtime.handler(ingestRequest({}));
		const body = await response.json();
		expect(response.status).toBe(200);
		expect(body).toEqual({
			ok: true,
			acknowledged_event_ids: ["bg:0b0c6c1e-7c7e-4b39-9d55-7a1d9d1f8e21"],
			agent_id: AGENT_ID,
		});
		// No entitlement, signature or pack key ever reaches the browser credential.
		expect(JSON.stringify(body)).not.toMatch(/entitlement|pack_keys|key_b64/);
		expect(runtime.insertedSnapshot).not.toHaveBeenCalled();
		expect(runtime.rpc).toHaveBeenCalledWith("consume_tenant_rate_limit", expect.objectContaining({
			p_tenant_id: TENANT_ID,
			p_subject: `api_key:${KEY_ID}`,
			p_endpoint: "ingest:browser_guard",
			p_subject_limit: 6000,
			p_tenant_limit: 50_000,
			p_cost: 1,
		}));
		expect(runtime.rpc).toHaveBeenCalledWith("register_browser_guard_agent_for_ingest", {
			p_api_key_id: KEY_ID,
			p_iid: IID,
			p_agent_runtime_version: "chrome-126",
		});
		expect(rpcNames(runtime.rpc)).not.toContain("register_agent_for_ingest");
		expect(runtime.insertedEvents).toHaveBeenCalledWith(
			[expect.objectContaining({ tenant_id: TENANT_ID, agent_id: AGENT_ID, type: "privacy_scan" })],
			{ onConflict: "tenant_id,event_id", ignoreDuplicates: true },
		);
	});

	it("honours a configured per-key budget and fails closed on a malformed one", async () => {
		vi.stubEnv("AIDR_BROWSER_KEY_INGEST_RL_PER_MIN", "120");
		let runtime = await ingestHandler();
		expect((await runtime.handler(ingestRequest({}))).status).toBe(200);
		expect(runtime.rpc).toHaveBeenCalledWith(
			"consume_tenant_rate_limit",
			expect.objectContaining({ p_subject_limit: 120 }),
		);
		for (const value of ["0", "abc", "60000", "-1"]) {
			vi.stubEnv("AIDR_BROWSER_KEY_INGEST_RL_PER_MIN", value);
			runtime = await ingestHandler();
			const response = await runtime.handler(ingestRequest({}));
			expect(response.status).toBe(503);
			expect(await response.json()).toMatchObject({ error: "rate_limit_unavailable" });
			expect(rpcNames(runtime.rpc)).not.toContain("register_browser_guard_agent_for_ingest");
		}
	});

	it("refuses a runtime other than browser_guard before spending budget or seats", async () => {
		for (const agentRuntime of ["claude-code", undefined, "Browser_Guard"]) {
			const runtime = await ingestHandler();
			const response = await runtime.handler(ingestRequest({ agent_runtime: agentRuntime }));
			expect(response.status).toBe(403);
			expect(await response.json()).toEqual({ error: "api_key_scope_denied" });
			expect(rpcNames(runtime.rpc)).not.toContain("consume_tenant_rate_limit");
			expect(runtime.insertedEvents).not.toHaveBeenCalled();
		}
	});

	it("delivers acceptable-use acknowledgements (notice id and version only) with the same key", async () => {
		const runtime = await ingestHandler();
		const ack = {
			event_id: "bg:6f2c1d9a-3b4e-4c5d-8e7f-0a1b2c3d4e5f",
			event_type: "aup_acknowledgement",
			timestamp: "2026-09-24T10:16:00Z",
			site: "gemini",
			notice_id: "acme-aup",
			notice_version: 3,
			notice_text: "Do not paste customer data",
		};
		const response = await runtime.handler(ingestRequest({ events: [scan(), ack] }));
		expect(response.status).toBe(200);
		const [rows] = runtime.insertedEvents.mock.calls[0] as unknown as [Array<Record<string, unknown>>];
		const stored = rows.find((row) => row.type === "aup_acknowledgement");
		expect(stored?.payload).toEqual({
			event_id: "bg:6f2c1d9a-3b4e-4c5d-8e7f-0a1b2c3d4e5f",
			type: "aup_acknowledgement",
			timestamp: "2026-09-24T10:16:00.000Z",
			site: "gemini",
			notice_id: "acme-aup",
			notice_version: 3,
		});
		expect(JSON.stringify(rows)).not.toContain("customer data");
	});

	it("also delivers counts-only shadow_ai_usage events", async () => {
		const runtime = await ingestHandler();
		const usage = {
			event_id: "bg:6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b",
			event_type: "shadow_ai_usage",
			timestamp: "2026-09-24T10:16:00Z",
			service_id: "poe",
			action: "blocked",
			count: 3,
			sanctioned: false,
			url: "https://poe.com/chat/secret-conversation",
		};
		const response = await runtime.handler(ingestRequest({ events: [scan(), usage] }));
		expect(response.status).toBe(200);
		const rows = (runtime.insertedEvents.mock.calls[0] as unknown as [Array<Record<string, unknown>>])[0];
		expect(rows.map((row) => row.type)).toEqual(["privacy_scan", "shadow_ai_usage"]);
		expect(rows[1]?.payload).toEqual({
			event_id: usage.event_id,
			type: "shadow_ai_usage",
			timestamp: "2026-09-24T10:16:00.000Z",
			service_id: "poe",
			category: "chat",
			action: "blocked",
			decision: "deny",
			count: 3,
			sanctioned: false,
		});
		expect(JSON.stringify(rows)).not.toContain("poe.com");
	});

	it("refuses any event type other than privacy_scan and shadow_ai_usage", async () => {
		for (const event of [
			{ event_id: "evt-1", type: "runtime_verdict", verdict: "deny" },
			{ event_id: "evt-2", type: "incident", severity: "high", title: "forged" },
			{ event_id: "evt-3" },
		]) {
			const runtime = await ingestHandler();
			const response = await runtime.handler(ingestRequest({ events: [scan(), event] }));
			expect(response.status).toBe(403);
			expect(await response.json()).toEqual({ error: "event_type_not_permitted" });
			expect(rpcNames(runtime.rpc)).not.toContain("register_browser_guard_agent_for_ingest");
			expect(runtime.insertedEvents).not.toHaveBeenCalled();
		}
	});

	it("stops at the key's installation limit without storing events", async () => {
		const runtime = await ingestHandler({
			registration: {
				agent_id: null,
				tenant_id: TENANT_ID,
				created: false,
				current_agents: 25,
				allowed_agents: 25,
				seat_exceeded: false,
				install_limit_exceeded: true,
			},
		});
		const response = await runtime.handler(ingestRequest({}));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "install_limit_exceeded", install_limit: 25 });
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
	});

	it("answers a seat-limit refusal without the entitlement", async () => {
		const runtime = await ingestHandler({
			registration: {
				agent_id: null,
				tenant_id: TENANT_ID,
				created: false,
				current_agents: 5,
				allowed_agents: 5,
				seat_exceeded: true,
				install_limit_exceeded: false,
			},
		});
		const response = await runtime.handler(ingestRequest({}));
		expect(response.status).toBe(402);
		expect(await response.json()).toEqual({
			error: "agent_limit_exceeded",
			allowed_agents: 5,
			current_agents: 5,
		});
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
	});

	it.each([
		["agent_runtime_mismatch", "agent_runtime_mismatch"],
		["api_key_scope_denied", "api_key_scope_denied"],
		["agent_seat_not_authorized", "tenant_not_admitted"],
	])("maps a %s refusal from the database to %s", async (message, error) => {
		const runtime = await ingestHandler({ registrationError: { code: "42501", message } });
		const response = await runtime.handler(ingestRequest({}));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error });
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
	});

	it("requires the Team plan's Browser Guard feature before spending budget, seats or rows", async () => {
		const runtime = await ingestHandler({ plan: planRow("free") });
		const response = await runtime.handler(ingestRequest({}));
		expect(response.status).toBe(402);
		expect(await response.json()).toEqual({
			error: "plan_feature_required",
			feature: "browser_privacy_guard",
			plan_id: "free",
			required_plan: "team",
		});
		expect(runtime.rpc).toHaveBeenCalledWith("tenant_plan_entitlements", { p_tenant_id: TENANT_ID });
		expect(rpcNames(runtime.rpc)).not.toContain("consume_tenant_rate_limit");
		expect(rpcNames(runtime.rpc)).not.toContain("register_browser_guard_agent_for_ingest");
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
		expect(runtime.insertedSnapshot).not.toHaveBeenCalled();
		// A heartbeat from the same key is gated too.
		const heartbeat = await runtime.handler(ingestRequest({ events: [] }));
		expect(heartbeat.status).toBe(402);
	});

	it("accepts Browser Guard telemetry on the Team plan", async () => {
		const runtime = await ingestHandler({ plan: planRow("team") });
		expect((await runtime.handler(ingestRequest({}))).status).toBe(200);
		expect(runtime.insertedEvents).toHaveBeenCalledOnce();
	});

	it.each([
		["an RPC error", { data: null, error: { message: "private database detail" } }],
		["a malformed row", { data: { tenant_id: TENANT_ID, plan_id: "platinum" }, error: null }],
		["another tenant's row", { ...planRow("business"), data: { ...(planRow("business").data as object), tenant_id: USER_ID } }],
	])("fails a browser key closed (503) on %s", async (_label, plan) => {
		const runtime = await ingestHandler({ plan: plan as RpcResult });
		const response = await runtime.handler(ingestRequest({}));
		const text = await response.text();
		expect(response.status).toBe(503);
		expect(JSON.parse(text)).toEqual({ error: "plan_entitlement_unavailable", retryable: true });
		expect(text).not.toContain("private database detail");
		expect(rpcNames(runtime.rpc)).not.toContain("register_browser_guard_agent_for_ingest");
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
	});

	it("keeps a tenant key on the unchanged ingest path", async () => {
		const runtime = await ingestHandler({
			key: { ...BROWSER_KEY_ROW, scope: "tenant", install_limit: null },
		});
		const response = await runtime.handler(
			ingestRequest({ agent_runtime: "claude-code", events: [{ event_id: "e", type: "runtime_verdict" }] }),
		);
		expect(response.status).toBe(200);
		expect(await response.json()).toHaveProperty("entitlement");
		expect(runtime.rpc).toHaveBeenCalledWith("consume_tenant_rate_limit", expect.objectContaining({
			p_subject: USER_ID,
			p_endpoint: "ingest",
			p_subject_limit: 1200,
		}));
		expect(rpcNames(runtime.rpc)).toContain("register_agent_for_ingest");
		// Verdict ingest with a tenant key never resolves a plan.
		expect(rpcNames(runtime.rpc)).not.toContain("tenant_plan_entitlements");
	});
});

// ── Dashboard issuance (/v1/api-keys) ──────────────────────────────────────
const issuance = vi.hoisted(() => ({ role: "owner", rpc: vi.fn() }));

async function apiKeysHandler() {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role");
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => process.env[name] },
		serve: (value: typeof handler) => {
			handler = value;
		},
	});
	sdk.createClient.mockReturnValue({
		auth: { getUser: async () => ({ data: { user: { id: USER_ID } }, error: null }) },
		rpc: issuance.rpc,
		from(table: string) {
			const query = {
				select: () => query,
				eq: () => query,
				maybeSingle: async () => ({
					data:
						table === "tenant_members"
							? { tenant_id: TENANT_ID, role: issuance.role, expires_at: null }
							: table === "tenants"
								? { status: "active" }
								: table === "rate_limits"
									? { count: 1 }
									: null,
					error: null,
				}),
			};
			return query;
		},
	});
	vi.resetModules();
	await import("../api-keys/index.ts");
	if (!handler) throw new Error("api-keys did not register a handler");
	return handler;
}

function createRequest(body: Record<string, unknown>) {
	return new Request("https://project.supabase.co/functions/v1/api-keys", {
		method: "POST",
		headers: {
			Authorization: "Bearer synthetic-access-token",
			"Content-Type": "application/json",
			"X-AIDR-Tenant-ID": TENANT_ID,
		},
		body: JSON.stringify({ action: "create", ...body }),
	});
}

describe("issuing an ingest:browser_guard key", () => {
	beforeEach(() => {
		issuance.role = "owner";
		issuance.rpc.mockReset();
		issuance.rpc.mockImplementation(async (name: string) =>
			name === "increment_rate_limit"
				? { data: null, error: null }
				: { data: { status: "issued", id: KEY_ID }, error: null },
		);
	});

	it.each(["owner", "admin"])("lets an %s issue one with an explicit installation limit", async (role) => {
		issuance.role = role;
		const handler = await apiKeysHandler();
		const response = await handler(
			createRequest({ label: " browsers ", scope: "ingest:browser_guard", install_limit: 500 }),
		);
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body).toMatchObject({ ok: true, scope: "ingest:browser_guard", install_limit: 500 });
		expect(body.api_key).toMatch(/^aidr_ingest_[A-Za-z0-9_-]{43}$/);
		const issue = issuance.rpc.mock.calls.find(([name]) => name === "issue_scoped_api_key_with_audit");
		expect(issue?.[1]).toEqual({
			p_actor_user_id: USER_ID,
			p_tenant_id: TENANT_ID,
			p_label: "browsers",
			p_key_hash: createHash("sha256").update(body.api_key).digest("hex"),
			p_scope: "ingest:browser_guard",
			p_install_limit: 500,
		});
		expect(issuance.rpc.mock.calls.map(([name]) => name)).not.toContain("issue_api_key_with_audit");
	});

	it("does not let a member issue an ingest key", async () => {
		issuance.role = "member";
		const handler = await apiKeysHandler();
		const response = await handler(
			createRequest({ scope: "ingest:browser_guard", install_limit: 10 }),
		);
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "tenant_role_insufficient" });
		expect(issuance.rpc).not.toHaveBeenCalled();
	});

	it.each([
		[{ scope: "ingest:browser_guard" }, "invalid_install_limit"],
		[{ scope: "ingest:browser_guard", install_limit: 0 }, "invalid_install_limit"],
		[{ scope: "ingest:browser_guard", install_limit: 100_001 }, "invalid_install_limit"],
		[{ scope: "ingest:browser_guard", install_limit: 2.5 }, "invalid_install_limit"],
		[{ scope: "ingest:browser_guard", install_limit: "50" }, "invalid_install_limit"],
		[{ scope: "tenant", install_limit: 50 }, "invalid_install_limit"],
		[{ scope: "admin" }, "invalid_scope"],
		[{ scope: "ingest:*" }, "invalid_scope"],
	])("refuses an incoherent request %j", async (body, error) => {
		const handler = await apiKeysHandler();
		const response = await handler(createRequest(body));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error });
		expect(issuance.rpc).not.toHaveBeenCalled();
	});

	it("keeps the default create path issuing a tenant key", async () => {
		const handler = await apiKeysHandler();
		const response = await handler(createRequest({ label: "server" }));
		const body = await response.json();
		expect(body).toMatchObject({ ok: true, scope: "tenant" });
		expect(body.api_key).toMatch(/^aidr_live_/);
		expect(issuance.rpc.mock.calls.map(([name]) => name)).toContain("issue_api_key_with_audit");
	});
});

describe("ingest key database contract", () => {
	const migration = readFileSync(
		new URL("../../migrations/20260925000061_browser_guard_ingest_keys.sql", import.meta.url),
		"utf8",
	);

	it("constrains the type, the limit and their immutability", () => {
		expect(migration).toMatch(/scope = 'tenant' and install_limit is null/);
		expect(migration).toMatch(
			/scope = 'ingest:browser_guard' and agent_id is null\s+and install_limit is not null and install_limit between 1 and 100000/,
		);
		expect(migration).toMatch(/before update of scope, install_limit on public\.api_keys/);
	});

	it("registers under the tenant seat lock and never adopts another runtime's agent", () => {
		const body = migration.slice(migration.indexOf("register_browser_guard_agent_for_ingest("));
		const lock = body.indexOf("pg_advisory_xact_lock(hashtextextended(v_key.tenant_id::text, 0))");
		const mismatch = body.indexOf("agent_runtime_mismatch");
		const cap = body.indexOf("v_installs >= v_key.install_limit");
		const register = body.indexOf("public.register_agent_for_ingest(");
		expect(lock).toBeGreaterThan(0);
		expect(mismatch).toBeGreaterThan(lock);
		expect(cap).toBeGreaterThan(mismatch);
		expect(register).toBeGreaterThan(cap);
		expect(body).toMatch(/v_key\.scope <> 'ingest:browser_guard'/);
		expect(body).toMatch(/'browser_guard', p_agent_runtime_version, v_key\.tenant_id/);
	});

	it("keeps issuance and registration service-only and owner/admin gated", () => {
		expect(migration).toMatch(/m\.role in \('owner', 'admin'\)/);
		for (const signature of [
			"issue_scoped_api_key_with_audit(uuid, uuid, text, text, text, integer)",
			"register_browser_guard_agent_for_ingest(uuid, text, text)",
		]) {
			expect(migration).toContain(`revoke all on function public.${signature}\n  from public, anon, authenticated;`);
			expect(migration).toContain(`grant execute on function public.${signature}\n  to service_role;`);
		}
		expect(migration).toMatch(
			/create policy tenant_identity_access_restrict on public\.api_key_ingest_installations\s+as restrictive/,
		);
	});
});
