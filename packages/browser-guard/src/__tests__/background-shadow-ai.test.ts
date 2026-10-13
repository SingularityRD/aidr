import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import {
	CUSTOM_MAIN_SCRIPT_ID,
	CUSTOM_SCRIPT_ID,
	customSiteForUrl,
} from "../background/custom-sites.js";
import { DNR_RULE_IDS } from "../background/dnr.js";
import { startBackground } from "../background/index.js";
import {
	DEFAULT_POLICY,
	evaluatePolicy,
	normalizeCustomHost,
	validateUserSettings,
} from "../background/policy.js";
import {
	blockedServices,
	buildShadowRules,
	SHADOW_DNR_RULE_IDS,
	ShadowAiUsageStore,
	shadowAiOrigins,
} from "../background/shadow-ai.js";
import { GuardStorage, STORAGE_KEYS } from "../background/storage.js";
import {
	buildShadowEvent,
	sanitizeQueuedEvent,
	sanitizeShadowEvent,
	TELEMETRY_ALARM,
} from "../background/telemetry.js";
import { AI_SERVICES, serviceOrigins } from "../sites/catalog.js";
import type { GuardPolicy, ShadowAiPolicy, SiteAccessStatus } from "../types.js";
import { createChromeFake, EXTENSION_BASE } from "./helpers/chrome-fake.js";

const INTERNAL = {
	id: "corp-gpt",
	label: "Corp GPT",
	hosts: ["ai.internal.example"],
	editorSelectors: ["#composer"],
	sendButtonSelectors: [".corp-send"],
	responseSelectors: [".corp-answer"],
};
const INTERNAL_ORIGIN = "https://ai.internal.example/*";
// Generated per run: the telemetry key is opaque to the code under test.
const TELEMETRY = {
	controlPlaneUrl: "https://cp.example.com",
	apiKey: `aidr_test_${randomBytes(8).toString("hex")}`,
};

const managedPolicy = (managed: Record<string, unknown>) => evaluatePolicy(managed, undefined);

describe("policy: customSites", () => {
	it("defaults to no custom sites and Shadow AI off", () => {
		expect(DEFAULT_POLICY.customSites).toEqual([]);
		expect(DEFAULT_POLICY.shadowAi).toEqual({ mode: "off", sanctioned: [], blocked: [] });
	});

	it("accepts a valid site, normalises hosts and locks the key", () => {
		const { policy, warnings } = managedPolicy({
			customSites: [
				{
					...INTERNAL,
					label: "  Corp GPT  ",
					hosts: ["https://AI.Internal.Example/", "chat.corp.example", "chat.corp.example"],
				},
			],
		});
		expect(warnings).toEqual([]);
		expect(policy.customSites).toEqual([
			{ ...INTERNAL, hosts: ["ai.internal.example", "chat.corp.example"] },
		]);
		expect(policy.managedKeys).toContain("customSites");
	});

	it("defaults the selector lists to empty", () => {
		const { policy } = managedPolicy({
			customSites: [{ id: "x", label: "X", hosts: ["x.corp.example"] }],
		});
		expect(policy.customSites[0]).toMatchObject({
			editorSelectors: [],
			sendButtonSelectors: [],
			responseSelectors: [],
		});
	});

	const bad: Array<[string, unknown]> = [
		["http host", [{ ...INTERNAL, hosts: ["http://ai.internal.example"] }]],
		["port", [{ ...INTERNAL, hosts: ["https://ai.internal.example:8443"] }]],
		["path", [{ ...INTERNAL, hosts: ["https://ai.internal.example/chat"] }]],
		["wildcard", [{ ...INTERNAL, hosts: ["*.internal.example"] }]],
		["single label", [{ ...INTERNAL, hosts: ["intranet"] }]],
		["IP address", [{ ...INTERNAL, hosts: ["10.0.0.5"] }]],
		["built-in host", [{ ...INTERNAL, hosts: ["chatgpt.com"] }]],
		["no hosts", [{ ...INTERNAL, hosts: [] }]],
		[
			"too many hosts",
			[{ ...INTERNAL, hosts: Array.from({ length: 11 }, (_, i) => `h${i}.corp.example`) }],
		],
		["bad id", [{ ...INTERNAL, id: "Corp GPT" }]],
		["empty label", [{ ...INTERNAL, label: "   " }]],
		["control char label", [{ ...INTERNAL, label: "a\u0007b" }]],
		["long label", [{ ...INTERNAL, label: "x".repeat(65) }]],
		["rule syntax selector", [{ ...INTERNAL, editorSelectors: ["a{color:red}"] }]],
		["markup selector", [{ ...INTERNAL, responseSelectors: ["<script>"] }]],
		["unknown key", [{ ...INTERNAL, script: "alert(1)" }]],
		["duplicate id", [INTERNAL, { ...INTERNAL, hosts: ["b.corp.example"] }]],
		["duplicate host", [INTERNAL, { ...INTERNAL, id: "other-site" }]],
		[
			"more than 20 sites",
			Array.from({ length: 21 }, (_, i) => ({
				...INTERNAL,
				id: `s${i}`,
				hosts: [`s${i}.corp.example`],
			})),
		],
		["not an array", INTERNAL],
	];
	for (const [name, value] of bad) {
		it(`rejects the whole key for ${name}`, () => {
			const { policy, warnings } = managedPolicy({ customSites: value });
			expect(policy.customSites).toEqual([]);
			expect(warnings).toContain('managed: invalid value for "customSites" ignored');
		});
	}

	it("is not a user setting", () => {
		const result = validateUserSettings({ customSites: [INTERNAL], shadowAi: { mode: "off" } });
		expect(result.unknownKeys).toEqual(["customSites", "shadowAi"]);
	});

	it("normalizeCustomHost accepts bare hosts and https origins only", () => {
		expect(normalizeCustomHost("ai.internal.example")).toBe("ai.internal.example");
		expect(normalizeCustomHost("https://ai.internal.example")).toBe("ai.internal.example");
		for (const raw of [
			"https://u:p@a.example/",
			"https://a.example/?q",
			"ftp://a.example",
			"a..b",
			"",
		])
			expect(normalizeCustomHost(raw)).toBeNull();
	});
});

describe("static/managed_schema.json: customSites and shadowAi", () => {
	const schema = JSON.parse(
		readFileSync(new URL("../../static/managed_schema.json", import.meta.url), "utf8"),
	) as { properties: Record<string, Record<string, unknown>> };
	type Props = Record<string, { pattern?: string; items?: { pattern?: string }; enum?: string[] }>;
	const site = (schema.properties.customSites?.items as { properties: Props; required: string[] })
		.properties;
	const shadow = schema.properties.shadowAi as { properties: Props; required: string[] };
	const re = (p: string | undefined) => new RegExp(p as string);

	it("declares the site fields and agrees with the validator's shapes", () => {
		expect(Object.keys(site).sort()).toEqual(
			[
				"editorSelectors",
				"hosts",
				"id",
				"label",
				"responseSelectors",
				"sendButtonSelectors",
			].sort(),
		);
		expect(re(site.id?.pattern).test("corp-gpt")).toBe(true);
		expect(re(site.id?.pattern).test("Corp GPT")).toBe(false);
		const host = re(site.hosts?.items?.pattern);
		for (const ok of ["ai.internal.example", "https://ai.internal.example/"]) {
			expect(host.test(ok)).toBe(true);
			expect(normalizeCustomHost(ok)).not.toBeNull();
		}
		for (const bad of ["http://ai.internal.example", "https://ai.internal.example:8443"]) {
			expect(host.test(bad)).toBe(false);
			expect(normalizeCustomHost(bad)).toBeNull();
		}
		const selector = re(site.editorSelectors?.items?.pattern);
		expect(selector.test("div.answer > p")).toBe(true);
		expect(selector.test("a{color:red}")).toBe(false);
	});

	it("uses the validator's Shadow AI modes and id syntax", () => {
		expect(shadow.required).toEqual(["mode"]);
		expect(shadow.properties.mode?.enum).toEqual(["off", "monitor", "block-unsanctioned"]);
		for (const key of ["sanctioned", "blocked"]) {
			const pattern = re(shadow.properties[key]?.items?.pattern);
			for (const id of AI_SERVICES.map((s) => s.id)) expect(pattern.test(id)).toBe(true);
			expect(pattern.test("https://poe.com")).toBe(false);
		}
	});
});

describe("policy: shadowAi", () => {
	it("accepts the modes and keeps well-formed ids unknown to this catalog", () => {
		const { policy, warnings } = managedPolicy({
			shadowAi: {
				mode: "block-unsanctioned",
				sanctioned: ["chatgpt", "future-ai", "chatgpt"],
				blocked: ["poe"],
			},
		});
		expect(warnings).toEqual([]);
		expect(policy.shadowAi).toEqual({
			mode: "block-unsanctioned",
			sanctioned: ["chatgpt", "future-ai"],
			blocked: ["poe"],
		});
		expect(policy.managedKeys).toContain("shadowAi");
	});

	for (const value of [
		{ mode: "audit" },
		{ sanctioned: [] },
		{ mode: "monitor", sanctioned: ["Bad Id"] },
		{ mode: "monitor", blocked: "poe" },
		{ mode: "monitor", extra: true },
		"monitor",
	]) {
		it(`rejects ${JSON.stringify(value)}`, () => {
			const { policy, warnings } = managedPolicy({ shadowAi: value });
			expect(policy.shadowAi).toEqual(DEFAULT_POLICY.shadowAi);
			expect(warnings).toContain('managed: invalid value for "shadowAi" ignored');
		});
	}
});

describe("Shadow AI rules", () => {
	const policy = (p: Partial<ShadowAiPolicy>): ShadowAiPolicy => ({
		mode: "off",
		sanctioned: [],
		blocked: [],
		...p,
	});

	it("blocks every unsanctioned service in block-unsanctioned mode", () => {
		const ids = blockedServices(
			policy({ mode: "block-unsanctioned", sanctioned: ["chatgpt", "claude"] }),
		).map((s) => s.id);
		expect(ids).toHaveLength(AI_SERVICES.length - 2);
		expect(ids).not.toContain("chatgpt");
		expect(ids).toContain("poe");
	});

	it("blocks listed services in every mode, and deny wins over sanctioned", () => {
		expect(blockedServices(policy({ blocked: ["poe"] })).map((s) => s.id)).toEqual(["poe"]);
		expect(
			blockedServices(policy({ mode: "monitor", sanctioned: ["poe"], blocked: ["poe"] })).map(
				(s) => s.id,
			),
		).toEqual(["poe"]);
		expect(blockedServices(policy({ mode: "monitor" }))).toEqual([]);
	});

	it("needs every catalog origin for visibility, only blocked ones otherwise", () => {
		expect(shadowAiOrigins(policy({}))).toEqual([]);
		expect(shadowAiOrigins(policy({ blocked: ["poe"] }))).toEqual(["https://poe.com/*"]);
		expect(shadowAiOrigins(policy({ mode: "monitor" }))).toEqual(serviceOrigins(AI_SERVICES));
	});

	it("builds one main_frame + sub_frame rule per blocked service in its own id range", () => {
		const rules = buildShadowRules(policy({ blocked: ["poe", "midjourney"] }));
		expect(rules).toHaveLength(2);
		for (const rule of rules) {
			expect(SHADOW_DNR_RULE_IDS).toContain(rule.id);
			expect(DNR_RULE_IDS).not.toContain(rule.id);
			expect(rule.action).toEqual({ type: "block" });
			expect(rule.condition.resourceTypes).toEqual(["main_frame", "sub_frame"]);
		}
		expect(rules[0]?.condition.requestDomains).toEqual(["poe.com"]);
		expect(new Set(SHADOW_DNR_RULE_IDS).size).toBe(AI_SERVICES.length);
	});

	it("blocks Microsoft 365 Copilot Chat on its host and /chat path, not the rest of Microsoft 365 (BG-10)", () => {
		const [rule] = buildShadowRules(policy({ blocked: ["m365-copilot"] }));
		expect(rule?.condition.requestDomains).toBeUndefined();
		expect(rule?.condition.resourceTypes).toEqual(["main_frame", "sub_frame"]);
		const filter = new RegExp(rule?.condition.regexFilter ?? "^$");
		for (const url of [
			"https://m365.cloud.microsoft/chat",
			"https://m365.cloud.microsoft/chat/",
			"https://m365.cloud.microsoft/chat?auth=2",
			"https://copilot.cloud.microsoft/",
			"https://eu.copilot.cloud.microsoft/x",
		])
			expect(filter.test(url), url).toBe(true);
		for (const url of [
			"https://m365.cloud.microsoft/",
			"https://m365.cloud.microsoft/apps",
			"https://m365.cloud.microsoft/chatter",
			"https://evil.test/m365.cloud.microsoft/chat",
			"https://copilot.cloud.microsoft.evil.test/",
			"https://notcopilot.cloud.microsoft/",
		])
			expect(filter.test(url), url).toBe(false);
	});
});

describe("ShadowAiUsageStore", () => {
	it("keeps 30 UTC days of counts and drains telemetry deltas once", async () => {
		const fake = createChromeFake();
		let clock = Date.parse("2026-09-01T12:00:00Z");
		const store = new ShadowAiUsageStore(new GuardStorage(fake.chrome), () => clock);
		await store.record("poe", "visited", true);
		await store.record("poe", "visited", true);
		await store.record("poe", "blocked", false);
		await store.record("not-in-catalog", "visited", true);
		expect(await store.usage()).toEqual([
			{ day: "2026-09-01", serviceId: "poe", visited: 2, blocked: 1 },
		]);
		expect(await store.drainPending()).toEqual([{ serviceId: "poe", visited: 2, blocked: 0 }]);
		expect(await store.drainPending()).toEqual([]);
		clock += 30 * 86_400_000;
		await store.record("claude", "visited", false);
		expect(await store.usage()).toEqual([
			{ day: "2026-10-01", serviceId: "claude", visited: 1, blocked: 0 },
		]);
		const raw = JSON.stringify(fake.local.data.get(STORAGE_KEYS.shadowAiUsage));
		expect(raw).not.toMatch(/https?:|\.com|\//);
	});
});

describe("shadow_ai_usage telemetry events", () => {
	it("builds contract events and rejects anything beyond the contract", () => {
		const event = buildShadowEvent(
			{ serviceId: "poe", action: "visited", count: 3, sanctioned: false, policyId: "acme-1" },
			Date.parse("2026-09-24T10:00:00Z"),
		);
		expect(event).toMatchObject({
			event_type: "shadow_ai_usage",
			timestamp: "2026-09-24T10:00:00.000Z",
			service_id: "poe",
			action: "visited",
			count: 3,
			sanctioned: false,
			policy_id: "acme-1",
		});
		expect(event?.event_id).toMatch(/^bg:[0-9a-f-]{36}$/);
		expect(sanitizeShadowEvent(event)).toEqual(event);
		expect(sanitizeQueuedEvent(event)).toEqual(event);
		expect(sanitizeShadowEvent({ ...event, url: "https://poe.com/chat/1" })).toBeNull();
		expect(sanitizeShadowEvent({ ...event, service_id: "unknown-ai" })).toBeNull();
		expect(sanitizeShadowEvent({ ...event, action: "used" })).toBeNull();
		expect(sanitizeShadowEvent({ ...event, count: 0 })).toBeNull();
		expect(sanitizeShadowEvent({ ...event, count: 100_001 })).toBeNull();
		expect(sanitizeShadowEvent({ ...event, sanctioned: "no" })).toBeNull();
		expect(
			buildShadowEvent({ serviceId: "poe", action: "blocked", count: 10 ** 9, sanctioned: true }, 0)
				?.count,
		).toBe(100_000);
	});
});

interface Setup {
	managed?: Record<string, unknown>;
}

async function setup(options: Setup = {}) {
	const fake = createChromeFake({ version: "1.0.0" });
	for (const [k, v] of Object.entries(options.managed ?? {})) fake.managed.data.set(k, v);
	const clock = Date.parse("2026-09-24T10:00:00Z");
	const fetchMock = vi.fn(async () => new Response("{}", { status: 202 }));
	const bg = startBackground({
		chrome: fake.chrome,
		fetch: fetchMock as unknown as typeof fetch,
		now: () => clock,
		random: () => 0.5,
		navigator: { userAgent: "Mozilla/5.0 Chrome/126.0.0.0" },
		createNativeBridge: () => ({ status: () => "disabled", scanText: async () => null }),
		log: () => {},
	});
	await bg.ready;
	const send = (message: unknown, sender = fake.extensionSender("options.html")) =>
		fake.sendRuntimeMessage(message, sender) as Promise<Record<string, unknown>>;
	const navigate = (tabId: number, url: string) =>
		fake.events.onUpdated.dispatch(tabId, { url, status: "loading" }, { id: tabId, url });
	const access = async () =>
		((await send({ type: "GET_SITE_ACCESS" })) as { access: SiteAccessStatus }).access;
	return { fake, bg, fetchMock, send, navigate, access };
}

describe("worker: Shadow AI", () => {
	it("blocks unsanctioned services, shows blocked.html and counts the attempt", async () => {
		const t = await setup({
			managed: { shadowAi: { mode: "block-unsanctioned", sanctioned: ["chatgpt"] } },
		});
		const installed = [...t.fake.dnrRules.values()].filter((r) =>
			SHADOW_DNR_RULE_IDS.includes(r.id),
		);
		expect(installed).toHaveLength(AI_SERVICES.length - 1);
		expect(installed.some((r) => r.condition.requestDomains?.includes("chatgpt.com"))).toBe(false);

		t.navigate(7, "https://poe.com/chat/abc?x=1");
		await vi.waitFor(() =>
			expect(t.fake.tabUpdates).toEqual([
				{ tabId: 7, url: `${EXTENSION_BASE}blocked.html?service=poe` },
			]),
		);
		await vi.waitFor(async () =>
			expect((await t.access()).shadowAi.usage).toEqual([
				{ day: "2026-09-24", serviceId: "poe", visited: 0, blocked: 1 },
			]),
		);
	});

	it("counts entering a service once per visit, never storing URLs", async () => {
		const t = await setup({ managed: { shadowAi: { mode: "monitor" } } });
		expect([...t.fake.dnrRules.keys()].some((id) => SHADOW_DNR_RULE_IDS.includes(id))).toBe(false);
		t.navigate(4, "https://claude.ai/new");
		t.navigate(4, "https://claude.ai/chat/1");
		t.navigate(4, "https://claude.ai/chat/2");
		t.navigate(4, "https://example.com/");
		t.navigate(4, "https://claude.ai/chat/3");
		t.navigate(5, "https://sub.midjourney.com/imagine");
		await vi.waitFor(async () =>
			expect((await t.access()).shadowAi.usage).toEqual([
				{ day: "2026-09-24", serviceId: "claude", visited: 2, blocked: 0 },
				{ day: "2026-09-24", serviceId: "midjourney", visited: 1, blocked: 0 },
			]),
		);
		expect(t.fake.tabUpdates).toEqual([]);
		const stored = JSON.stringify([...t.fake.local.data.entries()]);
		expect(stored).not.toContain("claude.ai");
		expect(stored).not.toContain("/chat/");
	});

	it("counts nothing while discovery is off", async () => {
		const t = await setup();
		t.navigate(4, "https://claude.ai/new");
		await new Promise((r) => setTimeout(r, 10));
		expect((await t.access()).shadowAi.usage).toEqual([]);
		expect(t.fake.local.data.has(STORAGE_KEYS.shadowAiUsage)).toBe(false);
	});

	it("reports aggregated shadow_ai_usage events at the telemetry flush", async () => {
		const t = await setup({
			managed: {
				telemetry: TELEMETRY,
				policyId: "acme-7",
				shadowAi: { mode: "monitor", sanctioned: ["claude"] },
			},
		});
		t.navigate(4, "https://claude.ai/new");
		t.navigate(5, "https://poe.com/");
		t.navigate(6, "https://claude.ai/new");
		await vi.waitFor(async () => expect((await t.access()).shadowAi.usage).toHaveLength(2));
		t.fake.fireAlarm(TELEMETRY_ALARM);
		await vi.waitFor(() => expect(t.fetchMock).toHaveBeenCalledTimes(1));
		const [, init] = t.fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		const body = JSON.parse(String(init.body)) as { events: Record<string, unknown>[] };
		const events = body.events
			.map(({ event_id: _id, timestamp: _ts, ...rest }) => rest)
			.sort((a, b) => String(a.service_id).localeCompare(String(b.service_id)));
		expect(events).toEqual([
			{
				event_type: "shadow_ai_usage",
				service_id: "claude",
				action: "visited",
				count: 2,
				sanctioned: true,
				policy_id: "acme-7",
			},
			{
				event_type: "shadow_ai_usage",
				service_id: "poe",
				action: "visited",
				count: 1,
				sanctioned: false,
				policy_id: "acme-7",
			},
		]);
		expect(String(init.body)).not.toContain("claude.ai");
	});

	it("GET_SITE_ACCESS is for extension pages and tracks the host-access grant", async () => {
		const t = await setup({ managed: { shadowAi: { mode: "off", blocked: ["poe"] } } });
		const denied = await t.send(
			{ type: "GET_SITE_ACCESS" },
			t.fake.contentSender(1, "https://chatgpt.com/"),
		);
		expect(denied).toEqual({ ok: false, error: "NOT_ALLOWED" });
		expect((await t.access()).shadowAi).toMatchObject({
			mode: "off",
			blocked: ["poe"],
			origins: ["https://poe.com/*"],
			missingOrigins: ["https://poe.com/*"],
		});
		t.fake.setOriginsGranted(["https://poe.com/*"], true);
		expect((await t.access()).shadowAi.missingOrigins).toEqual([]);
	});
});

describe("worker: custom sites", () => {
	const PAGE = "https://ai.internal.example/chat";

	it("registers content.js only for granted hosts and follows grants and revocations", async () => {
		const t = await setup({ managed: { customSites: [INTERNAL] } });
		expect(t.fake.contentScripts.size).toBe(0);
		expect((await t.access()).customSites).toEqual([
			{
				id: "corp-gpt",
				label: "Corp GPT",
				hosts: ["ai.internal.example"],
				origins: [INTERNAL_ORIGIN],
				granted: false,
				active: false,
			},
		]);

		t.fake.setOriginsGranted([INTERNAL_ORIGIN], true);
		await vi.waitFor(() =>
			expect(t.fake.contentScripts.get(CUSTOM_SCRIPT_ID)).toEqual({
				id: CUSTOM_SCRIPT_ID,
				matches: [INTERNAL_ORIGIN],
				js: ["content.js"],
				runAt: "document_start",
				allFrames: false,
				persistAcrossSessions: true,
			}),
		);
		expect(t.fake.contentScripts.get(CUSTOM_MAIN_SCRIPT_ID)).toEqual({
			id: CUSTOM_MAIN_SCRIPT_ID,
			matches: [INTERNAL_ORIGIN],
			js: ["content-main.js"],
			runAt: "document_start",
			allFrames: false,
			persistAcrossSessions: true,
			world: "MAIN",
		});
		expect((await t.access()).customSites[0]).toMatchObject({ granted: true, active: true });

		t.fake.setOriginsGranted([INTERNAL_ORIGIN], false);
		await vi.waitFor(() => expect(t.fake.contentScripts.size).toBe(0));
	});

	it("drops the registration when the policy no longer lists the site", async () => {
		const t = await setup({ managed: { customSites: [INTERNAL] } });
		t.fake.setOriginsGranted([INTERNAL_ORIGIN], true);
		await vi.waitFor(() => expect(t.fake.contentScripts.size).toBe(2));
		await t.fake.managed.adminReplace({});
		await vi.waitFor(() => expect(t.fake.contentScripts.size).toBe(0));
	});

	it("accepts the content script on a configured host as site 'custom' only", async () => {
		const t = await setup({ managed: { customSites: [INTERNAL] } });
		const content = t.fake.contentSender(9, PAGE);
		const reply = (await t.send({ type: "GET_POLICY" }, content)) as {
			ok: boolean;
			policy: GuardPolicy;
		};
		expect(reply.ok).toBe(true);
		expect(reply.policy.customSites).toEqual([INTERNAL]);
		expect(reply.policy.telemetry).toBeNull();
		await t.send(
			{
				type: "RECORD",
				site: "chatgpt",
				action: "masked",
				channel: "prompt",
				counts: { EMAIL: 1 },
			},
			content,
		);
		const stats = (await t.send({ type: "GET_STATS", tabId: 9 })) as {
			stats: { site: string; maskedItems: number };
		};
		expect(stats.stats).toMatchObject({ site: "custom", maskedItems: 1 });

		for (const url of [
			"https://evil.example/",
			"https://ai.internal.example:8443/",
			"http://ai.internal.example/",
			"https://sub.ai.internal.example/",
		]) {
			expect(await t.send({ type: "GET_POLICY" }, t.fake.contentSender(9, url))).toEqual({
				ok: false,
				error: "SENDER_DENIED",
			});
		}
	});

	it("broadcasts policy changes to custom-site tabs", async () => {
		const t = await setup({ managed: { customSites: [INTERNAL] } });
		t.fake.tabs.push({ id: 11, url: PAGE });
		await t.fake.managed.adminSet({ mode: "block" });
		await vi.waitFor(() =>
			expect(
				t.fake.tabMessages.some(
					(m) => m.tabId === 11 && (m.message as { type: string }).type === "POLICY_CHANGED",
				),
			).toBe(true),
		);
	});

	it("customSiteForUrl matches exact https hosts only", () => {
		const sites = [{ ...INTERNAL }];
		expect(customSiteForUrl(PAGE, sites)?.id).toBe("corp-gpt");
		expect(customSiteForUrl("https://AI.INTERNAL.EXAMPLE/", sites)?.id).toBe("corp-gpt");
		expect(customSiteForUrl("https://x.ai.internal.example/", sites)).toBeNull();
		expect(customSiteForUrl("https://ai.internal.example.evil.test/", sites)).toBeNull();
		expect(customSiteForUrl(42, sites)).toBeNull();
	});
});
