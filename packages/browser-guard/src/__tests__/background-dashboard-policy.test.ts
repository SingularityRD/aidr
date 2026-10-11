import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
	canonicalJson,
	DASHBOARD_POLICY_ALARM,
	DASHBOARD_POLICY_VERSION,
	DASHBOARD_STORAGE_KEYS,
	mergeDashboardShadowAi,
	type VerifiedDashboardPolicy,
	verifyDashboardPolicy,
	withDashboardPolicy,
} from "../background/dashboard-policy.js";
import { startBackground } from "../background/index.js";
import { evaluatePolicy, validateUserSettings } from "../background/policy.js";
import { SHADOW_DNR_RULE_IDS } from "../background/shadow-ai.js";
import { AI_SERVICES } from "../sites/catalog.js";
import type { DashboardPolicyTrust, ShadowAiPolicy } from "../types.js";
import { createChromeFake } from "./helpers/chrome-fake.js";

const TENANT = "22222222-2222-4222-8222-222222222222";
const NOW = Date.parse("2026-10-07T12:00:00Z");
const TELEMETRY = {
	controlPlaneUrl: "https://cp.example.com",
	apiKey: `aidr_test_${randomBytes(8).toString("hex")}`,
};
const POLICY_URL = "https://cp.example.com/functions/v1/browser-guard-policy";

function keypair() {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	return { privateKey, publicPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
}
const SIGNER = keypair();
const OTHER = keypair();
const TRUST: DashboardPolicyTrust = { publicKeysPem: [SIGNER.publicPem], tenantId: TENANT };

type Doc = {
	shadow_ai: { blocked: string[]; sanctioned: string[] };
	require_native_ner?: unknown;
};

/** Builds a body exactly as the browser-guard-policy Edge Function does. */
function signedBody(
	doc: Doc,
	options: {
		key?: ReturnType<typeof keypair>;
		sequence?: number;
		issuedAt?: number;
		ttlMs?: number;
		tenantId?: string;
	} = {},
) {
	const issuedAt = options.issuedAt ?? NOW - 60_000;
	const policySha256 = createHash("sha256").update(canonicalJson(doc)).digest("hex");
	const envelope = {
		schema_version: 1,
		key_id: "policy-key-1",
		policy_version: DASHBOARD_POLICY_VERSION,
		policy_sha256: policySha256,
		sequence: options.sequence ?? issuedAt,
		issued_at: new Date(issuedAt).toISOString(),
		expires_at: new Date(issuedAt + (options.ttlMs ?? 24 * 3_600_000)).toISOString(),
		tenant_id: options.tenantId ?? TENANT,
	};
	const sig = sign(
		null,
		Buffer.from(canonicalJson(envelope)),
		(options.key ?? SIGNER).privateKey,
	).toString("base64");
	return {
		policy_version: DASHBOARD_POLICY_VERSION,
		policy_sha256: policySha256,
		browser_guard: doc,
		policy_signed: { alg: "ed25519", key_id: "policy-key-1", sig_b64: sig, envelope },
		cache_seconds: 900,
	};
}

const BLOCK_POE: Doc = { shadow_ai: { blocked: ["poe"], sanctioned: ["claude"] } };

describe("verifyDashboardPolicy", () => {
	const verify = (body: unknown, extra: Record<string, unknown> = {}) =>
		verifyDashboardPolicy(body, { trust: TRUST, now: NOW, ...extra });

	it("accepts a document signed by a pinned key for the pinned tenant", async () => {
		const result = await verify(signedBody(BLOCK_POE));
		expect(result).toMatchObject({
			ok: true,
			policy: { shadowAi: { blocked: ["poe"], sanctioned: ["claude"] }, tenantId: TENANT },
		});
	});

	it("ignores unsigned, tampered, foreign and replayed documents", async () => {
		const good = signedBody(BLOCK_POE);
		const { policy_signed: _omit, ...unsigned } = good;
		expect(await verify(unsigned)).toEqual({ ok: false, reason: "malformed" });

		// The block list was edited in transit: the digest no longer matches.
		const edited = structuredClone(good);
		edited.browser_guard.shadow_ai.blocked = [];
		expect(await verify(edited)).toEqual({ ok: false, reason: "digest_mismatch" });

		// Edited and re-digested: the signed envelope still names the original digest.
		const redigested = structuredClone(edited);
		redigested.policy_sha256 = createHash("sha256")
			.update(canonicalJson(edited.browser_guard))
			.digest("hex");
		expect(await verify(redigested)).toEqual({ ok: false, reason: "binding_mismatch" });

		// Envelope edited to match: the signature breaks.
		const forged = structuredClone(redigested);
		forged.policy_signed.envelope.policy_sha256 = redigested.policy_sha256;
		expect(await verify(forged)).toEqual({ ok: false, reason: "bad_signature" });

		expect(await verify(signedBody(BLOCK_POE, { key: OTHER }))).toEqual({
			ok: false,
			reason: "bad_signature",
		});
		expect(
			await verify(signedBody(BLOCK_POE, { tenantId: "33333333-3333-4333-8333-333333333333" })),
		).toEqual({ ok: false, reason: "tenant_mismatch" });
		expect(await verify(signedBody(BLOCK_POE, { issuedAt: NOW - 2 * 86_400_000 }))).toEqual({
			ok: false,
			reason: "expired",
		});
		expect(
			await verify(good, {
				highWater: {
					sequence: good.policy_signed.envelope.sequence + 1,
					policySha256: "0".repeat(64),
				},
			}),
		).toEqual({ ok: false, reason: "rollback" });
		expect(
			await verifyDashboardPolicy(good, { trust: { ...TRUST, publicKeysPem: [] }, now: NOW }),
		).toEqual({ ok: false, reason: "no_trusted_keys" });
		const extraField = structuredClone(good) as Record<string, unknown>;
		(extraField.browser_guard as Record<string, unknown>).mode = "off";
		expect(await verify(extraField)).toEqual({ ok: false, reason: "malformed" });
	});
});

describe("verifyDashboardPolicy: require_native_ner", () => {
	const verify = (body: unknown) => verifyDashboardPolicy(body, { trust: TRUST, now: NOW });

	it("reads the optional flag; absent means false", async () => {
		expect(await verify(signedBody(BLOCK_POE))).toMatchObject({
			ok: true,
			policy: { requireNativeNer: false },
		});
		for (const flag of [true, false]) {
			expect(await verify(signedBody({ ...BLOCK_POE, require_native_ner: flag }))).toMatchObject({
				ok: true,
				policy: { requireNativeNer: flag, shadowAi: { blocked: ["poe"] } },
			});
		}
	});

	it("refuses a non-boolean flag and a flag edited in transit", async () => {
		for (const flag of ["true", 1, null, { on: true }]) {
			expect(await verify(signedBody({ ...BLOCK_POE, require_native_ner: flag }))).toEqual({
				ok: false,
				reason: "malformed",
			});
		}
		// The digest covers the flag: switching it off (or dropping it) breaks the binding.
		const on = signedBody({ ...BLOCK_POE, require_native_ner: true });
		const off = structuredClone(on);
		off.browser_guard.require_native_ner = false;
		expect(await verify(off)).toEqual({ ok: false, reason: "digest_mismatch" });
		const dropped = structuredClone(on);
		delete dropped.browser_guard.require_native_ner;
		expect(await verify(dropped)).toEqual({ ok: false, reason: "digest_mismatch" });
	});
});

describe("canonicalJson: the control plane's one canonical JSON", () => {
	const vectors = (
		JSON.parse(
			readFileSync(
				join(
					dirname(fileURLToPath(import.meta.url)),
					"../../../../docs/contracts/policy-canonical-json-vectors.json",
				),
				"utf8",
			),
		) as { vectors: { name: string; input_json: string; canonical: string; sha256: string }[] }
	).vectors;

	it.each(vectors.map((v) => [v.name, v] as const))("%s", (_name, vector) => {
		const canonical = canonicalJson(JSON.parse(vector.input_json));
		expect(canonical).toBe(vector.canonical);
		expect(createHash("sha256").update(canonical, "utf8").digest("hex")).toBe(vector.sha256);
	});
});

describe("withDashboardPolicy: require_native_ner, true wins", () => {
	const verified = (requireNativeNer: boolean): VerifiedDashboardPolicy => ({
		shadowAi: { blocked: [], sanctioned: [] },
		requireNativeNer,
		sequence: 1,
		policySha256: "0".repeat(64),
		expiresAt: NOW + 3_600_000,
		tenantId: TENANT,
		keyId: "policy-key-1",
	});

	it("switches the requirement on, forces the native bridge and locks both keys", () => {
		const base = evaluatePolicy(undefined, { useNativeHost: false }).policy;
		expect(base.requireNativeNer).toBe(false);
		for (const expired of [false, true]) {
			const applied = withDashboardPolicy(base, { policy: verified(true), expired });
			expect(applied.requireNativeNer).toBe(true);
			expect(applied.useNativeHost).toBe(true);
			expect(applied.managedKeys).toEqual(
				expect.arrayContaining(["requireNativeNer", "useNativeHost"]),
			);
			expect(Object.isFrozen(applied)).toBe(true);
		}
	});

	it("never switches off a managed requirement and leaves an unset one unchanged", () => {
		const managed = evaluatePolicy({ requireNativeNer: true }, undefined).policy;
		const applied = withDashboardPolicy(managed, { policy: verified(false), expired: false });
		expect(applied.requireNativeNer).toBe(true);
		expect(applied.useNativeHost).toBe(true);
		expect(applied.managedKeys.filter((k) => k === "useNativeHost")).toHaveLength(1);

		const plain = evaluatePolicy(undefined, { useNativeHost: false }).policy;
		const untouched = withDashboardPolicy(plain, { policy: verified(false), expired: false });
		expect(untouched.requireNativeNer).toBe(false);
		expect(untouched.useNativeHost).toBe(false);
		expect(untouched.managedKeys).toEqual(plain.managedKeys);
	});
});

describe("mergeDashboardShadowAi: most restrictive wins", () => {
	const local = (p: Partial<ShadowAiPolicy>): ShadowAiPolicy => ({
		mode: "off",
		sanctioned: [],
		blocked: [],
		...p,
	});

	it("adds dashboard blocks in every mode and sanctions only what the enterprise policy allows", () => {
		expect(mergeDashboardShadowAi(local({ mode: "monitor" }), BLOCK_POE.shadow_ai, false)).toEqual({
			mode: "monitor",
			sanctioned: ["claude"],
			blocked: ["poe"],
		});
		// An MDM block-unsanctioned mode blocks claude; a dashboard allow cannot lift it.
		const strict = local({ mode: "block-unsanctioned", sanctioned: ["chatgpt"] });
		expect(
			mergeDashboardShadowAi(strict, { blocked: ["chatgpt"], sanctioned: ["claude"] }, false),
		).toEqual({ mode: "block-unsanctioned", sanctioned: ["chatgpt"], blocked: ["chatgpt"] });
		// An MDM explicit block cannot be sanctioned either.
		expect(
			mergeDashboardShadowAi(local({ blocked: ["claude"] }), BLOCK_POE.shadow_ai, false),
		).toEqual({ mode: "off", sanctioned: [], blocked: ["claude", "poe"] });
	});

	it("keeps blocks and drops sanctions once the signed document expired", () => {
		expect(mergeDashboardShadowAi(local({ mode: "monitor" }), BLOCK_POE.shadow_ai, true)).toEqual({
			mode: "monitor",
			sanctioned: [],
			blocked: ["poe"],
		});
	});
});

describe("policy: dashboardPolicy trust anchor", () => {
	it("is managed-only and accepts only Ed25519 SPKI keys", () => {
		const ok = evaluatePolicy(
			{ dashboardPolicy: { publicKeysPem: [SIGNER.publicPem] } },
			undefined,
		);
		expect(ok.policy.dashboardPolicy).toEqual({
			publicKeysPem: [SIGNER.publicPem.trim()],
			tenantId: null,
		});
		expect(ok.policy.managedKeys).toContain("dashboardPolicy");
		const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 })
			.publicKey.export({ type: "spki", format: "pem" })
			.toString();
		for (const bad of [
			{ publicKeysPem: [rsa] },
			{ publicKeysPem: [] },
			{ publicKeysPem: [SIGNER.publicPem], tenantId: "not-a-uuid" },
			{ publicKeysPem: [SIGNER.publicPem], extra: true },
		]) {
			const { policy, warnings } = evaluatePolicy({ dashboardPolicy: bad }, undefined);
			expect(policy.dashboardPolicy).toBeNull();
			expect(warnings).toContain('managed: invalid value for "dashboardPolicy" ignored');
		}
		expect(
			validateUserSettings({ dashboardPolicy: { publicKeysPem: [OTHER.publicPem] } }),
		).toMatchObject({
			unknownKeys: ["dashboardPolicy"],
		});
	});
});

const ruleIdFor = (serviceId: string) =>
	SHADOW_DNR_RULE_IDS[AI_SERVICES.findIndex((s) => s.id === serviceId)] as number;

async function worker(options: {
	managed: Record<string, unknown>;
	respond: () => unknown;
	local?: Record<string, unknown>;
	now?: number;
}) {
	const fake = createChromeFake({ version: "1.0.0" });
	for (const [k, v] of Object.entries(options.managed)) fake.managed.data.set(k, v);
	for (const [k, v] of Object.entries(options.local ?? {})) fake.local.data.set(k, v);
	const fetchMock = vi.fn(async (url: string) =>
		url === POLICY_URL
			? new Response(JSON.stringify(options.respond()), { status: 200 })
			: new Response("{}", { status: 202 }),
	);
	const bg = startBackground({
		chrome: fake.chrome,
		fetch: fetchMock as unknown as typeof fetch,
		now: () => options.now ?? NOW,
		random: () => 0.5,
		navigator: { userAgent: "Mozilla/5.0 Chrome/126.0.0.0" },
		createNativeBridge: () => ({ status: () => "disabled", scanText: async () => null }),
		log: () => {},
	});
	await bg.ready;
	const policyFetches = () => fetchMock.mock.calls.filter(([url]) => url === POLICY_URL);
	await vi.waitFor(() => expect(policyFetches().length).toBeGreaterThanOrEqual(1));
	return { fake, bg, fetchMock, policyFetches };
}

const MANAGED = {
	telemetry: TELEMETRY,
	dashboardPolicy: { publicKeysPem: [SIGNER.publicPem], tenantId: TENANT },
	shadowAi: { mode: "monitor" },
};

describe("worker: signed dashboard Shadow AI decisions", () => {
	it("enforces a signed dashboard block on the next refresh, sent with the telemetry key", async () => {
		const t = await worker({ managed: MANAGED, respond: () => signedBody(BLOCK_POE) });
		await vi.waitFor(() => expect(t.fake.dnrRules.has(ruleIdFor("poe"))).toBe(true));
		expect(t.fake.dnrRules.get(ruleIdFor("poe"))?.condition.requestDomains).toContain("poe.com");
		expect(t.bg.policy().shadowAi).toEqual({
			mode: "monitor",
			sanctioned: ["claude"],
			blocked: ["poe"],
		});
		const [, init] = t.policyFetches()[0] as unknown as [string, RequestInit];
		expect(init.method).toBe("GET");
		expect((init.headers as Record<string, string>).Authorization).toBe(
			`Bearer ${TELEMETRY.apiKey}`,
		);
		expect(t.fake.alarms.get(DASHBOARD_POLICY_ALARM)).toEqual({ periodInMinutes: 15 });
	});

	it("ignores an unsigned or tampered document and keeps the last verified one", async () => {
		const unsigned = (() => {
			const { policy_signed: _omit, ...body } = signedBody(BLOCK_POE);
			return body;
		})();
		const u = await worker({ managed: MANAGED, respond: () => unsigned });
		await new Promise((r) => setTimeout(r, 10));
		expect(u.fake.dnrRules.has(ruleIdFor("poe"))).toBe(false);
		expect(u.bg.policy().shadowAi.blocked).toEqual([]);
		expect(u.fake.local.data.has(DASHBOARD_STORAGE_KEYS.document)).toBe(false);

		// A verified block is in force; a later tampered answer that drops it is ignored.
		let answer: unknown = signedBody(BLOCK_POE);
		const t = await worker({ managed: MANAGED, respond: () => answer });
		await vi.waitFor(() => expect(t.fake.dnrRules.has(ruleIdFor("poe"))).toBe(true));
		const tampered = structuredClone(signedBody(BLOCK_POE, { sequence: NOW + 1 }));
		tampered.browser_guard.shadow_ai.blocked = [];
		answer = tampered;
		t.fake.fireAlarm(DASHBOARD_POLICY_ALARM);
		await vi.waitFor(() => expect(t.policyFetches().length).toBe(2));
		await new Promise((r) => setTimeout(r, 10));
		expect(t.fake.dnrRules.has(ruleIdFor("poe"))).toBe(true);

		// A document signed by a key the administrator did not pin is ignored as well.
		answer = signedBody(
			{ shadow_ai: { blocked: [], sanctioned: [] } },
			{ key: OTHER, sequence: NOW + 2 },
		);
		t.fake.fireAlarm(DASHBOARD_POLICY_ALARM);
		await vi.waitFor(() => expect(t.policyFetches().length).toBe(3));
		await new Promise((r) => setTimeout(r, 10));
		expect(t.fake.dnrRules.has(ruleIdFor("poe"))).toBe(true);

		// A newer signed document that lifts the block applies.
		answer = signedBody({ shadow_ai: { blocked: [], sanctioned: [] } }, { sequence: NOW + 3 });
		t.fake.fireAlarm(DASHBOARD_POLICY_ALARM);
		await vi.waitFor(() => expect(t.fake.dnrRules.has(ruleIdFor("poe"))).toBe(false));
	});

	it("never relaxes an MDM-locked Shadow AI block", async () => {
		const t = await worker({
			managed: { ...MANAGED, shadowAi: { mode: "block-unsanctioned", sanctioned: ["chatgpt"] } },
			respond: () => signedBody({ shadow_ai: { blocked: ["chatgpt"], sanctioned: ["claude"] } }),
		});
		await vi.waitFor(() => expect(t.fake.dnrRules.has(ruleIdFor("chatgpt"))).toBe(true));
		expect(t.fake.dnrRules.has(ruleIdFor("claude"))).toBe(true);
		expect(t.bg.policy().shadowAi.sanctioned).toEqual(["chatgpt"]);
	});

	it("applies a signed require_native_ner and recreates the native bridge enabled", async () => {
		const fake = createChromeFake({ version: "1.0.0" });
		for (const [k, v] of Object.entries(MANAGED)) fake.managed.data.set(k, v);
		const bridgeFlags: boolean[] = [];
		const body = signedBody({ ...BLOCK_POE, require_native_ner: true });
		const fetchMock = vi.fn(async (url: string) =>
			url === POLICY_URL
				? new Response(JSON.stringify(body), { status: 200 })
				: new Response("{}", { status: 202 }),
		);
		const bg = startBackground({
			chrome: fake.chrome,
			fetch: fetchMock as unknown as typeof fetch,
			now: () => NOW,
			random: () => 0.5,
			navigator: { userAgent: "Mozilla/5.0 Chrome/126.0.0.0" },
			createNativeBridge: (enabled: boolean) => {
				bridgeFlags.push(enabled);
				return { status: () => (enabled ? "unavailable" : "disabled"), scanText: async () => null };
			},
			log: () => {},
		});
		await bg.ready;
		expect(bg.policy().requireNativeNer).toBe(false);
		await vi.waitFor(() => expect(bg.policy().requireNativeNer).toBe(true));
		expect(bg.policy().useNativeHost).toBe(true);
		expect(bg.policy().managedKeys).toEqual(
			expect.arrayContaining(["requireNativeNer", "useNativeHost"]),
		);
		expect(bridgeFlags.at(-1)).toBe(true);
		expect(bg.warnings()).toContain('dashboard: "requireNativeNer" on; "useNativeHost" forced on');
	});

	it("does nothing without the managed trust anchor", async () => {
		const fake = createChromeFake({ version: "1.0.0" });
		fake.managed.data.set("telemetry", TELEMETRY);
		const fetchMock = vi.fn(async () => new Response("{}", { status: 202 }));
		const bg = startBackground({
			chrome: fake.chrome,
			fetch: fetchMock as unknown as typeof fetch,
			now: () => NOW,
			log: () => {},
			createNativeBridge: () => ({ status: () => "disabled", scanText: async () => null }),
		});
		await bg.ready;
		await new Promise((r) => setTimeout(r, 10));
		expect(fetchMock.mock.calls.some(([url]) => url === POLICY_URL)).toBe(false);
	});

	it("keeps an expired document's blocks when the control plane is unreachable", async () => {
		const stale = signedBody(BLOCK_POE, { issuedAt: NOW - 3 * 86_400_000 });
		const t = await worker({
			managed: MANAGED,
			local: { [DASHBOARD_STORAGE_KEYS.document]: stale },
			respond: () => {
				throw new Error("offline");
			},
		});
		expect(t.fake.dnrRules.has(ruleIdFor("poe"))).toBe(true);
		expect(t.bg.policy().shadowAi).toMatchObject({ blocked: ["poe"], sanctioned: [] });
		expect(t.bg.warnings()).toContain(
			"dashboard: Shadow AI decisions expired; blocks kept, sanctions dropped",
		);
	});
});
