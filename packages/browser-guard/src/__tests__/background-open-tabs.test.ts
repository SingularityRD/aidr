/**
 * Already-open tabs (GA audit BG-7, BG-13) and pause / policy-error reporting (BG-6, BG-4):
 * the worker injects into AI tabs open before it started, reports which tabs run a live
 * content script, applies blocks to open tabs, and marks telemetry sent while paused or
 * under an invalid managed policy.
 */
import { describe, expect, it, vi } from "vitest";
import { type BackgroundController, startBackground } from "../background/index.js";
import { ContentTabs, injectOpenTabs } from "../background/open-tabs.js";
import { SHADOW_API_DNR_RULE_IDS } from "../background/shadow-ai.js";
import { GuardStorage, STORAGE_KEYS } from "../background/storage.js";
import type { GuardStats } from "../types.js";
import { type ChromeFake, createChromeFake } from "./helpers/chrome-fake.js";

const CHATGPT = "https://chatgpt.com/c/123";
const GEMINI = "https://gemini.google.com/app";
const POE = "https://poe.com/chat/1";
const OTHER = "https://example.com/";
const TELEMETRY = { controlPlaneUrl: "https://cp.example.com", apiKey: ["aidr_test", "key_123456"].join("_") };
const BASE = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";

interface Setup {
	readonly fake?: ChromeFake;
	readonly managed?: Record<string, unknown>;
	readonly tabs?: { id: number; url: string; discarded?: boolean }[];
}

async function setup(options: Setup = {}) {
	const fake = options.fake ?? createChromeFake();
	if (!options.fake) {
		for (const [k, v] of Object.entries(options.managed ?? {})) fake.managed.data.set(k, v);
		fake.tabs.push(
			...(options.tabs ?? [
				{ id: 1, url: CHATGPT },
				{ id: 2, url: GEMINI },
				{ id: 3, url: OTHER },
			]),
		);
	}
	const bg: BackgroundController = startBackground({
		chrome: fake.chrome,
		fetch: vi.fn(async () => new Response("{}", { status: 202 })) as unknown as typeof fetch,
		now: () => Date.parse("2026-10-13T10:00:00Z"),
		random: () => 0.5,
		navigator: { userAgent: "Mozilla/5.0 Chrome/126.0.0.0" },
		log: () => {},
	});
	await bg.ready;
	const send = (message: unknown, sender = fake.extensionSender("popup.html")) =>
		fake.sendRuntimeMessage(message, sender) as Promise<Record<string, unknown>>;
	const content = (tabId: number, url: string) => fake.contentSender(tabId, url);
	const stats = async (tabId: number) =>
		(await send({ type: "GET_STATS", tabId })).stats as GuardStats;
	return { fake, bg, send, content, stats };
}

describe("open AI tabs at install / update / enable (BG-7)", () => {
	it("injects content.js and the page-world hook into open protected tabs only", async () => {
		const t = await setup();
		expect(await t.bg.openTabsInjected).toEqual([1, 2]);
		expect(t.fake.executedScripts).toEqual([
			{ target: { tabId: 1 }, files: ["content.js"] },
			{ target: { tabId: 1 }, files: ["content-main.js"], world: "MAIN" },
			{ target: { tabId: 2 }, files: ["content.js"] },
			{ target: { tabId: 2 }, files: ["content-main.js"], world: "MAIN" },
		]);
	});

	it("runs once per extension start and skips tabs that already run a live script", async () => {
		const t = await setup();
		await t.bg.openTabsInjected;
		// A worker restart in the same extension start (storage.session kept): no new sweep.
		const again = await setup({ fake: t.fake });
		expect(await again.bg.openTabsInjected).toEqual([]);
		// The next extension start (update/enable: storage.session cleared) sweeps again,
		// except for a tab whose content script already fetched its policy.
		t.fake.session.data.clear();
		await t.send({ type: "GET_POLICY" }, t.content(1, CHATGPT));
		t.fake.session.data.delete(STORAGE_KEYS.openTabsInjected);
		const next = await setup({ fake: t.fake });
		expect(await next.bg.openTabsInjected).toEqual([2]);
	});

	it("skips discarded tabs (they reload with the manifest scripts)", async () => {
		const t = await setup({ tabs: [{ id: 4, url: CHATGPT, discarded: true }] });
		expect(await t.bg.openTabsInjected).toEqual([]);
	});

	it("never rejects when injection fails or the API is missing", async () => {
		const storage = new GuardStorage(createChromeFake().chrome, () => {});
		const contentTabs = new ContentTabs(storage);
		const failing = {
			scripting: {
				...createChromeFake().chrome.scripting,
				executeScript: async () => {
					throw new Error("Cannot access contents of the page");
				},
			},
			tabs: { ...createChromeFake().chrome.tabs, query: async () => [{ id: 7, url: CHATGPT }] },
		} as never;
		const protectedUrl = () => true;
		expect(await injectOpenTabs({ chrome: failing, contentTabs, protectedUrl })).toEqual([]);
		const noApi = { tabs: { query: async () => [{ id: 7, url: CHATGPT }] } } as never;
		expect(await injectOpenTabs({ chrome: noApi, contentTabs, protectedUrl })).toEqual([]);
	});

	it("reports a tab as active only once its content script fetched the policy for that origin", async () => {
		const t = await setup();
		// The auditor's case: a ChatGPT tab with no live script must not read as protected.
		expect((await t.stats(1)).contentActive).toBe(false);
		await t.send({ type: "GET_POLICY" }, t.content(1, CHATGPT));
		expect((await t.stats(1)).contentActive).toBe(true);
		// Sub-frames do not count; another origin in the same tab is not covered.
		await t.send({ type: "GET_POLICY" }, { ...t.content(2, GEMINI), frameId: 3 });
		expect((await t.stats(2)).contentActive).toBe(false);
		const tab = t.fake.tabs.find((x) => x.id === 1);
		if (tab) tab.url = "https://chat.openai.com/";
		expect((await t.stats(1)).contentActive).toBe(false);
		// A closed tab is forgotten; global stats carry no tab state.
		if (tab) tab.url = CHATGPT;
		t.fake.events.onRemoved.dispatch(1);
		await vi.waitFor(async () => expect((await t.stats(1)).contentActive).toBe(false));
		expect((await t.send({ type: "GET_STATS" })).stats).not.toHaveProperty("contentActive");
	});

	it("injects into an open custom-site tab once its host is granted", async () => {
		const fake = createChromeFake();
		fake.managed.data.set("customSites", [
			{ id: "acme", label: "ACME GPT", hosts: ["gpt.acme.example"] },
		]);
		fake.tabs.push({ id: 5, url: "https://gpt.acme.example/chat" });
		// As in the browser: no injection without host access to the page.
		const scripting = fake.chrome.scripting;
		const execute = scripting?.executeScript?.bind(scripting);
		if (scripting && execute)
			scripting.executeScript = async (injection) => {
				if (!fake.grantedOrigins.has("https://gpt.acme.example/*"))
					throw new Error("Cannot access contents of the page");
				return execute(injection);
			};
		const t = await setup({ fake });
		expect(await t.bg.openTabsInjected).toEqual([]);
		t.fake.setOriginsGranted(["https://gpt.acme.example/*"], true);
		await vi.waitFor(() =>
			expect(t.fake.executedScripts.map((s) => s.target.tabId)).toEqual([5, 5]),
		);
	});
});

describe("blocks reach tabs that are already open (BG-13)", () => {
	it("a newly blocked built-in site sends its open tabs to blocked.html", async () => {
		const t = await setup();
		await t.fake.managed.adminReplace({ blockedSites: ["gemini"] });
		await t.bg.reload(true);
		await vi.waitFor(() =>
			expect(t.fake.tabUpdates).toEqual([{ tabId: 2, url: `${BASE}blocked.html?site=gemini` }]),
		);
	});

	it("a newly blocked Shadow AI service sends its visible open tabs to blocked.html", async () => {
		const t = await setup({
			tabs: [
				{ id: 6, url: POE },
				{ id: 1, url: CHATGPT },
			],
		});
		await t.fake.managed.adminReplace({ shadowAi: { mode: "monitor", blocked: ["poe"] } });
		await t.bg.reload(true);
		await vi.waitFor(() =>
			expect(t.fake.tabUpdates).toEqual([{ tabId: 6, url: `${BASE}blocked.html?service=poe` }]),
		);
	});

	it("cuts off the API traffic of open pages of a blocked service, whatever the host grant", async () => {
		const t = await setup({ managed: { shadowAi: { mode: "off", blocked: ["poe"] } } });
		const apiRules = [...t.fake.dnrRules.values()].filter((r) =>
			SHADOW_API_DNR_RULE_IDS.includes(r.id),
		);
		expect(apiRules).toEqual([
			expect.objectContaining({
				action: { type: "block" },
				condition: {
					initiatorDomains: ["poe.com"],
					resourceTypes: ["xmlhttprequest", "websocket"],
				},
			}),
		]);
		await t.fake.managed.adminReplace({});
		await t.bg.reload(false);
		expect([...t.fake.dnrRules.keys()].some((id) => SHADOW_API_DNR_RULE_IDS.includes(id))).toBe(
			false,
		);
	});
});

describe("telemetry marks pauses and policy errors (BG-6, BG-4)", () => {
	const record = { type: "RECORD", action: "allowed", channel: "prompt", counts: { EMAIL: 1 } };

	it("a send during an allowed pause is reported with reason paused", async () => {
		const t = await setup({ managed: { telemetry: TELEMETRY, allowUserPause: true } });
		await t.send(record, t.content(1, CHATGPT));
		expect(await t.send({ type: "PAUSE", minutes: 10 })).toMatchObject({ ok: true });
		await t.send(record, t.content(1, CHATGPT));
		await vi.waitFor(async () => expect(await t.bg.telemetry.pending()).toHaveLength(2));
		const [before, during] = await t.bg.telemetry.pending();
		expect(before).not.toHaveProperty("reason");
		expect(during).toMatchObject({ action: "allowed", reason: "paused" });
	});

	it("a managed policy without allowUserPause refuses the pause", async () => {
		const t = await setup({ managed: { telemetry: TELEMETRY } });
		expect(t.bg.policy().allowUserPause).toBe(false);
		expect(await t.send({ type: "PAUSE", minutes: 10 })).toEqual({
			ok: false,
			error: "PAUSE_DISABLED",
		});
	});

	it("every event carries the number of invalid managed keys", async () => {
		const t = await setup({
			managed: { telemetry: TELEMETRY, mode: "Block", blockedSites: ["deepseek", "chatgtp"] },
		});
		expect(t.bg.policy().policyErrors).toEqual(["mode", "blockedSites"]);
		await t.send(record, t.content(1, CHATGPT));
		await vi.waitFor(async () => expect(await t.bg.telemetry.pending()).toHaveLength(1));
		expect((await t.bg.telemetry.pending())[0]).toMatchObject({ policy_errors: 2 });
	});
});
