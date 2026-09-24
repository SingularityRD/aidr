// Contract suite for Browser Guard privacy telemetry
// (docs/contracts/privacy-telemetry.md): the ingest projection must keep
// counts, enums and the optional policy identifier only.
import { webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ENTITY_TYPES as BROWSER_GUARD_ENTITY_TYPES } from "../../../packages/browser-guard/src/types.ts";
import { ENTITY_TYPES as PRIVACY_ENTITY_TYPES_SOURCE } from "../../../packages/privacy/src/types.ts";
import {
	MAX_INGEST_EVENTS,
	MAX_PRIVACY_ENTITY_KEYS,
	normalizeIngestEvents,
	PRIVACY_ACTION_DECISIONS,
	PRIVACY_ENTITY_TYPES,
	PRIVACY_SITES,
} from "../ingest/events.ts";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const USER_ID = "11111111-1111-4111-8111-111111111111";
const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const AGENT_ID = "33333333-3333-4333-8333-333333333333";
const IID = "5b7f3f0e-4a8e-4d59-9c1a-5a3e0b1d2c44";

function scan(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		event_id: "bg:0b0c6c1e-7c7e-4b39-9d55-7a1d9d1f8e21",
		event_type: "privacy_scan",
		timestamp: "2026-09-24T10:15:00Z",
		site: "chatgpt",
		action: "masked",
		channel: "prompt",
		entity_counts: { EMAIL: 2, TC_KIMLIK: 1 },
		findings_count: 3,
		policy_id: "managed.default:v4",
		...overrides,
	};
}

function projectOne(event: Record<string, unknown>) {
	const result = normalizeIngestEvents([event]);
	if (!result.ok) throw new Error(`rejected: ${result.error} ${result.detail ?? ""}`);
	return result.events[0];
}

describe("privacy_scan ingest projection", () => {
	it("stores the contract example as counts, enums and the policy identifier only", () => {
		expect(projectOne(scan())).toEqual({
			event_id: "bg:0b0c6c1e-7c7e-4b39-9d55-7a1d9d1f8e21",
			type: "privacy_scan",
			timestamp: "2026-09-24T10:15:00.000Z",
			site: "chatgpt",
			action: "masked",
			channel: "prompt",
			decision: "allow",
			entity_counts: { EMAIL: 2, TC_KIMLIK: 1 },
			findings_count: 3,
			policy_id: "managed.default:v4",
		});
	});

	it("maps every guard action to the generic decision named by the contract", () => {
		expect(PRIVACY_ACTION_DECISIONS).toEqual({
			masked: "allow",
			warned: "ask",
			blocked: "deny",
			allowed: "allow",
		});
		for (const [action, decision] of Object.entries(PRIVACY_ACTION_DECISIONS)) {
			expect(projectOne(scan({ action }))).toMatchObject({ action, decision });
		}
	});

	it("never stores raw, masked or matched text or page URLs, even when a client sends them", () => {
		const email = "ayse.yilmaz@example.test";
		const tckn = "10000000146";
		const stored = projectOne(
			scan({
				prompt: `Please email ${email} about ${tckn}`,
				masked_text: "Please email [EMAIL_1] about [TC_KIMLIK_1]",
				text: email,
				values: [email, tckn],
				url: `https://chatgpt.com/c/123?q=${email}`,
				page_url: "https://chatgpt.com/c/123",
				findings: [{ type: "EMAIL", value: email, start: 13, end: 37 }],
				verdict: "deny",
				tool_name: "chatgpt",
				session_id: "session-1",
				tenant_id: "forged-tenant",
				user_id: "forged-user",
			}),
		);
		const serialized = JSON.stringify(stored);
		for (const leaked of [email, tckn, "[EMAIL_1]", "chatgpt.com", "forged-"]) {
			expect(serialized).not.toContain(leaked);
		}
		expect(Object.keys(stored).sort()).toEqual(
			[
				"action",
				"channel",
				"decision",
				"entity_counts",
				"event_id",
				"findings_count",
				"policy_id",
				"site",
				"timestamp",
				"type",
			].sort(),
		);
	});

	it("keeps only privacy entity types with integer counts from 1 to 100000", () => {
		// JSON.parse keeps "__proto__" as an own key, as a real request body would.
		const entity_counts = JSON.parse(
			'{"EMAIL":1,"PHONE":100000,"IBAN":100001,"PERSON":0,"ADDRESS":-2,"SECRET":1.5,' +
				'"PASSPORT":"4","LOCATION":null,"ayse@example.test":1,"email":3,"__proto__":5}',
		);
		const stored = projectOne(scan({ entity_counts }));
		expect(stored.entity_counts).toEqual({ EMAIL: 1, PHONE: 100_000 });
	});

	it("rejects oversized or malformed entity_counts instead of guessing", () => {
		const tooMany = Object.fromEntries(
			Array.from({ length: MAX_PRIVACY_ENTITY_KEYS + 1 }, (_, index) => [`K${index}`, 1]),
		);
		for (const entity_counts of [tooMany, [1, 2], "EMAIL=2", null]) {
			expect(normalizeIngestEvents([scan({ entity_counts })])).toEqual({
				ok: false,
				status: 400,
				error: "invalid_event",
				detail: "events[0].entity_counts",
			});
		}
		expect(projectOne(scan({ entity_counts: undefined })).entity_counts).toEqual({});
	});

	it("requires a known action and channel, and files unknown sites under other", () => {
		expect(normalizeIngestEvents([scan({ action: "redacted" })])).toMatchObject({
			ok: false,
			status: 400,
			detail: "events[0].action",
		});
		expect(normalizeIngestEvents([scan({ action: undefined })])).toMatchObject({
			ok: false,
			detail: "events[0].action",
		});
		expect(normalizeIngestEvents([scan({ channel: "voice" })])).toMatchObject({
			ok: false,
			detail: "events[0].channel",
		});
		for (const site of PRIVACY_SITES) expect(projectOne(scan({ site })).site).toBe(site);
		expect(projectOne(scan({ site: "https://evil.example/?q=secret" })).site).toBe("other");
		expect(projectOne(scan({ site: undefined })).site).toBe("other");
	});

	it("bounds findings_count and drops credential-shaped policy identifiers", () => {
		expect(projectOne(scan({ findings_count: 1_000_000 })).findings_count).toBe(1_000_000);
		for (const findings_count of [1_000_001, -1, 2.5, "3"]) {
			expect(projectOne(scan({ findings_count }))).not.toHaveProperty("findings_count");
		}
		for (const policy_id of ["has spaces", "sk_live_abcdefghijklmnop", "x".repeat(129), 7]) {
			expect(projectOne(scan({ policy_id }))).not.toHaveProperty("policy_id");
		}
	});

	it("treats event_type as an alias of type and refuses a conflicting pair", () => {
		expect(projectOne(scan({ event_type: undefined, type: "privacy_scan" })).type).toBe(
			"privacy_scan",
		);
		expect(projectOne(scan({ type: "privacy_scan" })).type).toBe("privacy_scan");
		expect(normalizeIngestEvents([scan({ type: "runtime_verdict" })])).toMatchObject({
			ok: false,
			status: 400,
			detail: "events[0].type",
		});
		expect(normalizeIngestEvents([scan({ event_type: "dlp_payload" })])).toMatchObject({
			ok: false,
			status: 400,
			detail: "events[0].type",
		});
		expect(
			projectOne({ event_id: "evt-legacy", event_type: "runtime_verdict", verdict: "deny" }),
		).toEqual({ event_id: "evt-legacy", type: "runtime_verdict", verdict: "deny" });
	});

	it("accepts the contract's 200-event batch limit and refuses anything larger", () => {
		const batch = (size: number) =>
			Array.from({ length: size }, (_, index) => scan({ event_id: `bg:${index}` }));
		expect(MAX_INGEST_EVENTS).toBe(200);
		const accepted = normalizeIngestEvents(batch(200));
		expect(accepted.ok && accepted.events.length).toBe(200);
		expect(normalizeIngestEvents(batch(201))).toMatchObject({
			ok: false,
			status: 413,
			error: "events_limit_exceeded",
		});
	});

	it("pins the entity vocabulary to the privacy engine and Browser Guard", () => {
		expect([...PRIVACY_ENTITY_TYPES]).toEqual([...PRIVACY_ENTITY_TYPES_SOURCE]);
		expect([...PRIVACY_ENTITY_TYPES]).toEqual([...BROWSER_GUARD_ENTITY_TYPES]);
		expect(PRIVACY_ENTITY_TYPES.length).toBeLessThanOrEqual(MAX_PRIVACY_ENTITY_KEYS);
	});
});

async function ingestHandler(registration: Record<string, unknown>) {
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
	const insertedEvents = vi.fn(async () => ({ error: null }));
	const rows: Record<string, Record<string, unknown>> = {
		api_keys: { user_id: USER_ID, tenant_id: TENANT_ID, revoked: false, agent_id: null },
		tenant_members: { role: "member", expires_at: null },
		tenants: { status: "active" },
		entitlements: {
			included_agents: 2,
			extra_agents: 0,
			premium_intel: false,
			premium_correlation: false,
			premium_pkg_plugin: false,
			revocation_epoch: 1,
		},
	};
	const rpc = vi.fn(async (name: string, _args?: Record<string, unknown>) => {
		if (name === "tenant_admission_capacity") return { data: 2, error: null };
		if (name === "get_tenant_admission")
			return {
				data: {
					mode: "cloud",
					status: "active",
					access_kind: "licensed",
					allowed_agents: 2,
					expires_at: new Date(Date.now() + 30 * 86_400_000).toISOString(),
					trial_available: false,
				},
				error: null,
			};
		if (name === "consume_tenant_rate_limit")
			return { data: [{ allowed: true, remaining: 1199 }], error: null };
		if (name === "register_agent_for_ingest") return { data: [registration], error: null };
		if (name === "effective_tenant_seats")
			return { data: [{ extra_agents: 0, provider_valid_until: null }], error: null };
		throw new Error(`Unexpected RPC: ${name}`);
	});
	sdk.createClient.mockReturnValue({
		rpc,
		from(table: string) {
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
				upsert: table === "events" ? insertedEvents : vi.fn(async () => ({ error: null })),
			};
		},
	});
	vi.resetModules();
	await import("../ingest/index.ts");
	if (!handler) throw new Error("ingest did not register a handler");
	return { handler, rpc, insertedEvents };
}

function browserGuardRequest(events: unknown[]) {
	return new Request("https://project.supabase.co/functions/v1/ingest", {
		method: "POST",
		headers: { Authorization: "Bearer aidr_test-api-key", "Content-Type": "application/json" },
		body: JSON.stringify({
			iid: IID,
			agent_runtime: "browser_guard",
			agent_runtime_version: "chrome-126",
			aidr_version: "1.0.0",
			events,
		}),
	});
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
});

describe("privacy_scan ingest delivery", () => {
	it("registers the browser install as a protected agent seat and stores counts only", async () => {
		const runtime = await ingestHandler({
			agent_id: AGENT_ID,
			seat_exceeded: false,
			allowed_agents: 2,
		});
		const response = await runtime.handler(
			browserGuardRequest([scan({ prompt: "raw prompt with ayse@example.test" })]),
		);
		const body = await response.json();
		expect(response.status).toBe(200);
		expect(body).toMatchObject({
			ok: true,
			acknowledged_event_ids: ["bg:0b0c6c1e-7c7e-4b39-9d55-7a1d9d1f8e21"],
		});
		expect(runtime.rpc).toHaveBeenCalledWith("register_agent_for_ingest", {
			p_user_id: USER_ID,
			p_tenant_id: TENANT_ID,
			p_iid: IID,
			p_agent_runtime: "browser_guard",
			p_agent_runtime_version: "chrome-126",
		});
		expect(runtime.insertedEvents).toHaveBeenCalledWith(
			[
				{
					user_id: USER_ID,
					tenant_id: TENANT_ID,
					agent_id: AGENT_ID,
					event_id: "bg:0b0c6c1e-7c7e-4b39-9d55-7a1d9d1f8e21",
					type: "privacy_scan",
					payload: {
						event_id: "bg:0b0c6c1e-7c7e-4b39-9d55-7a1d9d1f8e21",
						type: "privacy_scan",
						timestamp: "2026-09-24T10:15:00.000Z",
						site: "chatgpt",
						action: "masked",
						channel: "prompt",
						decision: "allow",
						entity_counts: { EMAIL: 2, TC_KIMLIK: 1 },
						findings_count: 3,
						policy_id: "managed.default:v4",
					},
				},
			],
			{ onConflict: "tenant_id,event_id", ignoreDuplicates: true },
		);
		expect(JSON.stringify(runtime.insertedEvents.mock.calls)).not.toContain("ayse@example.test");
	});

	it("refuses a browser install beyond the seat limit without storing its scans", async () => {
		const runtime = await ingestHandler({
			agent_id: null,
			seat_exceeded: true,
			current_agents: 2,
			allowed_agents: 2,
		});
		const response = await runtime.handler(browserGuardRequest([scan()]));
		expect(response.status).toBe(402);
		expect(await response.json()).toMatchObject({
			error: "agent_limit_exceeded",
			current_agents: 2,
			allowed_agents: 2,
		});
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
	});

	it("rejects a contract violation before registering the install", async () => {
		const runtime = await ingestHandler({
			agent_id: AGENT_ID,
			seat_exceeded: false,
			allowed_agents: 2,
		});
		const response = await runtime.handler(browserGuardRequest([scan({ action: "leaked" })]));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({
			error: "invalid_event",
			detail: "events[0].action",
		});
		expect(runtime.rpc.mock.calls.map(([name]) => name)).not.toContain(
			"register_agent_for_ingest",
		);
		expect(runtime.insertedEvents).not.toHaveBeenCalled();
	});
});
