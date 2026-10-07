// Contract suite for GET /browser-guard-policy: the signed Shadow AI decisions that
// enrolled Browser Guard installs apply (docs/ai-governance.md). The responses are
// verified with the extension's own verifier, so the wire contract cannot drift.
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { verifyDashboardPolicy } from "../../../packages/browser-guard/src/background/dashboard-policy.ts";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => { throw new Error("browser-guard-policy test requires an injected database"); },
}));

const served: unknown[] = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: unknown) => served.push(handler),
};

const { createBrowserGuardPolicyHandler } = await import("../browser-guard-policy/index.ts");
const { browserGuardPolicyFromOverlay } = await import("../_shared/browser-guard-policy.ts");

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const URL = "https://project.supabase.co/functions/v1/browser-guard-policy";
const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const AGENT = "44444444-4444-4444-8444-444444444444";
const KEY_ID = "55555555-5555-4555-8555-555555555555";
const NOW = new Date("2026-10-07T12:00:00.000Z");

function keypair() {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	return {
		pkcs8B64: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
		publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
	};
}
const SIGNING = keypair();
const OTHER = keypair();

type Options = {
	scope?: "tenant" | "ingest:browser_guard";
	agentId?: string | null;
	revoked?: boolean;
	tenantStatus?: string;
	rate?: "deny" | "unavailable";
	overlay?: unknown;
	overlayError?: boolean;
	/** tenant_plan_entitlements row; null = RPC error. Defaults to Team (browser_privacy_guard). */
	plan?: Record<string, unknown> | null;
};

const teamPlan = (overrides: Record<string, unknown> = {}) => ({
	tenant_id: TENANT, plan_id: "team", plan_source: "stripe_subscription", trial_active: false,
	features: ["local_detection", "dashboard", "browser_privacy_guard", "entra_sso"], retention_days_max: 90, ...overrides,
});

const OVERLAY = {
	mcp_deny_servers: ["shell-runner"],
	mcp_require_approval_servers: [],
	browser_guard_blocked_sites: ["deepseek"],
	browser_guard_shadow_ai: { blocked: ["poe", "deepseek"], sanctioned: ["claude", "chatgpt"] },
};

function database(options: Options = {}) {
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const rateSubjects: unknown[] = [];
	function from(table: string) {
		const query = {
			select: (_columns: string) => query,
			eq: (_column: string, _value: unknown) => query,
			maybeSingle: async () => {
				switch (table) {
					case "api_keys": {
						const scope = options.scope ?? "ingest:browser_guard";
						return { data: {
							id: KEY_ID, user_id: USER, tenant_id: TENANT, revoked: options.revoked ?? false, scope,
							agent_id: options.agentId ?? null, install_limit: scope === "tenant" ? null : 25,
						}, error: null };
					}
					case "tenant_members": return { data: { role: "admin", expires_at: null }, error: null };
					case "tenants": return { data: { status: options.tenantStatus ?? "active" }, error: null };
					case "rate_limits": return { data: null, error: null };
					default: throw new Error(`unexpected relation ${table}`);
				}
			},
		};
		return query;
	}
	const db = {
		from,
		rpc: async (name: string, args: Record<string, unknown> = {}) => {
			rpcCalls.push({ name, args });
			if (name === "tenant_admission_capacity") return { data: 1, error: null };
			if (name === "tenant_plan_entitlements") {
				return options.plan === null ? { data: null, error: new Error("db_down") } : { data: options.plan ?? teamPlan(), error: null };
			}
			if (name === "increment_rate_limit") return { data: null, error: null };
			if (name === "consume_tenant_rate_limit") {
				rateSubjects.push(args.p_subject ?? args);
				return options.rate === "unavailable" ? { data: null, error: new Error("db_down") }
					: { data: { allowed: options.rate !== "deny", remaining: options.rate === "deny" ? 0 : 59 }, error: null };
			}
			if (name === "ai_governance_policy_overlay") {
				return options.overlayError ? { data: null, error: new Error("db_down") }
					: { data: "overlay" in options ? options.overlay : OVERLAY, error: null };
			}
			throw new Error(`unexpected RPC ${name}`);
		},
	};
	return { db, rpcCalls, rateSubjects };
}

const get = (token = "aidr_bg_contract_key") => new Request(URL, { headers: { Authorization: `Bearer ${token}` } });
const handler = (fake: ReturnType<typeof database>) =>
	createBrowserGuardPolicyHandler({ db: fake.db as never, now: () => NOW });
const trust = (pem = SIGNING.publicPem, tenantId: string | null = TENANT) => ({ publicKeysPem: [pem], tenantId });

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
	vi.stubEnv("AIDR_POLICY_SIGNING_KEY_ID", "policy-key-1");
	vi.stubEnv("AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64", SIGNING.pkcs8B64);
	vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_KEY_ID", "");
	vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64", "");
	vi.stubEnv("AIDR_POLICY_SIGNATURE_TTL_HOURS", "");
});
afterEach(() => vi.unstubAllEnvs());

describe("browser-guard-policy", () => {
	it("serves the same handler in Edge and tests and is declared without gateway JWT checks", () => {
		expect(served).toHaveLength(1);
		expect(readFileSync(join(ROOT, "supabase", "config.toml"), "utf8"))
			.toMatch(/^\[functions\.browser-guard-policy\]\n(?:#.*\n)*verify_jwt = false$/m);
	});

	it("signs the tenant's Shadow AI decisions so the extension verifies and applies them", async () => {
		const fake = database();
		const response = await handler(fake)(get());
		expect(response.status).toBe(200);
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		const body = await response.json();
		expect(body).toMatchObject({
			policy_version: "browser-guard/v1",
			browser_guard: { shadow_ai: { blocked: ["deepseek", "poe"], sanctioned: ["chatgpt", "claude"] } },
			cache_seconds: 900,
			policy_signed: { alg: "ed25519", key_id: "policy-key-1", envelope: { tenant_id: TENANT, sequence: NOW.getTime() } },
		});
		// No MCP lists or other tenant data leave through a browser key.
		expect(JSON.stringify(body)).not.toContain("shell-runner");
		const verified = await verifyDashboardPolicy(body, { trust: trust(), now: NOW.getTime() + 1000 });
		expect(verified).toMatchObject({ ok: true, policy: { shadowAi: { blocked: ["deepseek", "poe"] } } });
		expect(await verifyDashboardPolicy(body, { trust: trust(OTHER.publicPem), now: NOW.getTime() }))
			.toEqual({ ok: false, reason: "bad_signature" });
		const tampered = structuredClone(body);
		tampered.browser_guard.shadow_ai.blocked = [];
		expect(await verifyDashboardPolicy(tampered, { trust: trust(), now: NOW.getTime() }))
			.toEqual({ ok: false, reason: "digest_mismatch" });
	});

	it("applies only tenant-wide exceptions for a shared Browser Guard key", async () => {
		const fake = database({ scope: "ingest:browser_guard", agentId: null });
		expect((await handler(fake)(get())).status).toBe(200);
		expect(fake.rpcCalls.find((c) => c.name === "ai_governance_policy_overlay")?.args)
			.toEqual({ p_tenant_id: TENANT, p_user_id: null, p_agent_id: null });
		expect(fake.rateSubjects).toEqual([`api_key:${KEY_ID}`]);

		const bound = database({ scope: "tenant", agentId: AGENT });
		expect((await handler(bound)(get())).status).toBe(200);
		expect(bound.rpcCalls.find((c) => c.name === "ai_governance_policy_overlay")?.args)
			.toEqual({ p_tenant_id: TENANT, p_user_id: null, p_agent_id: AGENT });
	});

	it("never serves an unsigned document", async () => {
		vi.stubEnv("AIDR_POLICY_SIGNING_KEY_ID", "");
		vi.stubEnv("AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64", "");
		const fake = database();
		const response = await handler(fake)(get());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "policy_signing_unavailable" });
		expect(fake.rpcCalls).toEqual([]);

		vi.stubEnv("AIDR_POLICY_SIGNING_KEY_ID", "policy-key-1");
		vi.stubEnv("AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64", Buffer.from("not a key").toString("base64"));
		expect((await handler(database())(get())).status).toBe(503);
	});

	it("rejects bad methods, credentials, tenants and quotas before reading decisions", async () => {
		const fake = database();
		expect((await handler(fake)(new Request(URL, { method: "POST" }))).status).toBe(405);
		expect((await handler(fake)(new Request(URL))).status).toBe(401);
		for (const [options, status] of [
			[{ revoked: true }, 401], [{ tenantStatus: "suspended" }, 403],
			[{ rate: "deny" }, 429], [{ rate: "unavailable" }, 503],
		] as const) {
			const denied = database(options);
			expect((await handler(denied)(get())).status).toBe(status);
			expect(denied.rpcCalls.some((c) => c.name === "ai_governance_policy_overlay")).toBe(false);
		}
	});

	it("fails closed on an unreadable or malformed overlay instead of serving a partial block list", async () => {
		for (const options of [
			{ overlayError: true },
			{ overlay: null },
			{ overlay: { ...OVERLAY, browser_guard_shadow_ai: undefined } },
			{ overlay: { ...OVERLAY, browser_guard_shadow_ai: { blocked: ["https://poe.com"], sanctioned: [] } } },
			{ overlay: { ...OVERLAY, browser_guard_shadow_ai: { blocked: Array.from({ length: 501 }, (_, i) => `s${i}`), sanctioned: [] } } },
		]) {
			const response = await handler(database(options))(get());
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "policy_unavailable" });
		}
	});

	it("requires the Browser Guard plan feature (Team) before any budget or decision read", async () => {
		const free = database({ plan: teamPlan({ plan_id: "free", features: ["local_detection", "dashboard"], retention_days_max: 7 }) });
		const refused = await handler(free)(get());
		expect(refused.status).toBe(402);
		expect(await refused.json()).toEqual({
			error: "plan_feature_required", feature: "browser_privacy_guard", plan_id: "free", required_plan: "team",
		});
		expect(free.rpcCalls.map((c) => c.name)).not.toContain("consume_tenant_rate_limit");
		expect(free.rpcCalls.map((c) => c.name)).not.toContain("ai_governance_policy_overlay");
		expect(free.rpcCalls.find((c) => c.name === "tenant_plan_entitlements")?.args).toEqual({ p_tenant_id: TENANT });

		const unreadable = database({ plan: null });
		const failed = await handler(unreadable)(get());
		expect(failed.status).toBe(503);
		expect(await failed.json()).toEqual({ error: "plan_entitlement_unavailable" });
		expect(unreadable.rpcCalls.map((c) => c.name)).not.toContain("ai_governance_policy_overlay");
	});

	it("keeps deny over allow when a service is listed twice", () => {
		expect(browserGuardPolicyFromOverlay({ browser_guard_shadow_ai: { blocked: ["poe"], sanctioned: ["poe", "claude"] } }))
			.toEqual({ shadow_ai: { blocked: ["poe"], sanctioned: ["claude"] } });
	});
});
