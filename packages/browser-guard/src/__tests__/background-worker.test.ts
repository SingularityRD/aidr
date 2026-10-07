import { describe, expect, it, vi } from "vitest";
import {
	applyBlockedSites,
	buildBlockRules,
	DNR_RULE_IDS,
	navigationBlocked,
	redirectBlockedTab,
	SITE_HOSTS,
	siteForNavigation,
	siteForUrl,
	updatedTabUrl,
} from "../background/dnr.js";
import { startBackground } from "../background/index.js";
import { badgeText } from "../background/stats.js";
import { STORAGE_KEYS } from "../background/storage.js";
import { TELEMETRY_ALARM } from "../background/telemetry.js";
import type { Finding, GuardPolicy, GuardStats, NativeBridge } from "../types.js";
import { createChromeFake, EXTENSION_BASE } from "./helpers/chrome-fake.js";

const CHATGPT = "https://chatgpt.com/c/123";
const GEMINI = "https://gemini.google.com/app";
const TELEMETRY = { controlPlaneUrl: "https://cp.example.com", apiKey: "aidr_test_key_123456" };

interface Setup {
	managed?: Record<string, unknown>;
	user?: Record<string, unknown>;
	managedError?: Error;
	bridge?: NativeBridge;
}

async function setup(options: Setup = {}) {
	const fake = createChromeFake({ version: "1.0.0" });
	if (options.managed)
		for (const [k, v] of Object.entries(options.managed)) fake.managed.data.set(k, v);
	if (options.user) fake.local.data.set(STORAGE_KEYS.userSettings, options.user);
	if (options.managedError) fake.managed.failWith = options.managedError;
	fake.tabs.push(
		{ id: 1, url: CHATGPT, active: true },
		{ id: 2, url: GEMINI },
		{ id: 3, url: "https://example.com/" },
	);
	let clock = Date.parse("2026-09-24T10:00:00Z");
	const fetchMock = vi.fn(async () => new Response("{}", { status: 202 }));
	const bridgeFactory = vi.fn(
		(enabled: boolean): NativeBridge =>
			options.bridge && enabled
				? options.bridge
				: { status: () => (enabled ? "unavailable" : "disabled"), scanText: async () => null },
	);
	const logs: string[] = [];
	const bg = startBackground({
		chrome: fake.chrome,
		fetch: fetchMock as unknown as typeof fetch,
		now: () => clock,
		random: () => 0.5,
		navigator: { userAgent: "Mozilla/5.0 Chrome/126.0.0.0" },
		createNativeBridge: bridgeFactory,
		log: (m) => logs.push(m),
	});
	await bg.ready;
	const content = (tabId = 1, url = CHATGPT) => fake.contentSender(tabId, url);
	const popup = () => fake.extensionSender("popup.html");
	const send = (message: unknown, sender = popup()) =>
		fake.sendRuntimeMessage(message, sender) as Promise<Record<string, unknown>>;
	return {
		fake,
		bg,
		fetchMock,
		bridgeFactory,
		logs,
		content,
		popup,
		send,
		advance: (ms: number) => {
			clock += ms;
		},
		now: () => clock,
		policyMessages: () =>
			fake.tabMessages.filter((m) => (m.message as { type: string }).type === "POLICY_CHANGED"),
	};
}

describe("background: sender validation", () => {
	it("rejects messages from other extensions, other hosts and spoofed URLs", async () => {
		const t = await setup();
		const denied = { ok: false, error: "SENDER_DENIED" };
		const get = { type: "GET_POLICY" };
		expect(await t.send(get, { ...t.content(), id: "someotherextensionid" })).toEqual(denied);
		expect(await t.send(get, t.fake.contentSender(3, "https://example.com/"))).toEqual(denied);
		expect(await t.send(get, t.fake.contentSender(1, "http://chatgpt.com/"))).toEqual(denied);
		expect(await t.send(get, t.fake.contentSender(1, "https://chatgpt.com.evil.test/"))).toEqual(
			denied,
		);
		expect(await t.send(get, t.fake.contentSender(1, "https://chatgpt.com:8443/"))).toEqual(denied);
		expect(await t.send(get, { id: t.fake.chrome.runtime.id, url: CHATGPT })).toEqual(denied);
		expect(
			await t.send(get, {
				id: t.fake.chrome.runtime.id,
				url: `${EXTENSION_BASE}popup.html`,
				origin: "https://evil.test",
			}),
		).toEqual(denied);
		expect(await t.fake.sendRuntimeMessage(get, undefined as never)).toEqual(denied);
		expect(await t.bg.handleMessage(get, {})).toEqual(denied);
	});

	it("rejects malformed messages", async () => {
		const t = await setup();
		expect(await t.send(null)).toEqual({ ok: false, error: "BAD_MESSAGE" });
		expect(await t.send({ type: "NOPE" })).toEqual({ ok: false, error: "BAD_MESSAGE" });
		expect(await t.send({ type: 5 })).toEqual({ ok: false, error: "BAD_MESSAGE" });
	});

	it("content scripts never receive the telemetry API key", async () => {
		const t = await setup({ managed: { telemetry: TELEMETRY } });
		const fromContent = (await t.send({ type: "GET_POLICY" }, t.content())).policy as GuardPolicy;
		expect(fromContent.telemetry).toBeNull();
		const fromPopup = (await t.send({ type: "GET_POLICY" })).policy as GuardPolicy;
		expect(fromPopup.telemetry).toEqual(TELEMETRY);
		expect(JSON.stringify(t.policyMessages())).not.toContain(TELEMETRY.apiKey);
	});

	it("content scripts may not change settings or pause", async () => {
		const t = await setup();
		expect(
			await t.send({ type: "SET_USER_SETTINGS", settings: { mode: "monitor" } }, t.content()),
		).toEqual({ ok: false, error: "NOT_ALLOWED" });
		expect(await t.send({ type: "PAUSE", minutes: 10 }, t.content())).toEqual({
			ok: false,
			error: "NOT_ALLOWED",
		});
	});
});

describe("background: policy", () => {
	it("merges managed over user settings and reports managed keys", async () => {
		const t = await setup({
			managed: { mode: "block" },
			user: { mode: "monitor", language: "tr" },
		});
		const policy = t.bg.policy();
		expect(policy.mode).toBe("block");
		expect(policy.language).toBe("tr");
		expect(policy.managedKeys).toContain("mode");
	});

	it("suspends user settings when managed storage cannot be read", async () => {
		const t = await setup({ managedError: new Error("boom"), user: { mode: "monitor" } });
		expect(t.bg.policy().mode).toBe("auto");
		expect(t.bg.warnings().join("\n")).toContain("user settings suspended");
	});

	it("treats a missing managed manifest (Firefox) as no policy", async () => {
		const t = await setup({
			managedError: new Error("Managed storage manifest not found"),
			user: { mode: "confirm" },
		});
		expect(t.bg.policy().mode).toBe("confirm");
	});

	it("reloads and broadcasts POLICY_CHANGED to supported-site tabs on a managed change", async () => {
		const t = await setup();
		await t.fake.managed.adminSet({ mode: "confirm" });
		await t.bg.reload(false);
		await vi.waitFor(() => expect(t.policyMessages().length).toBeGreaterThanOrEqual(2));
		const tabs = new Set(t.policyMessages().map((m) => m.tabId));
		expect(tabs).toEqual(new Set([1, 2]));
		const last = t.policyMessages().at(-1)?.message as { policy: GuardPolicy };
		expect(last.policy.mode).toBe("confirm");
		expect(last.policy.telemetry).toBeNull();
	});

	it("applies per-site disable as monitor mode for that site only", async () => {
		const t = await setup({ user: { disabledSites: ["gemini"] } });
		const gem = (await t.send({ type: "GET_POLICY" }, t.content(2, GEMINI))).policy as GuardPolicy;
		const gpt = (await t.send({ type: "GET_POLICY" }, t.content())).policy as GuardPolicy;
		expect(gem.mode).toBe("monitor");
		expect(gpt.mode).toBe("auto");
	});
});

describe("background: SET_USER_SETTINGS", () => {
	it("stores valid settings, reloads and broadcasts", async () => {
		const t = await setup();
		const reply = await t.send({
			type: "SET_USER_SETTINGS",
			settings: { mode: "confirm", maskPaste: false },
		});
		expect(reply.ok).toBe(true);
		expect((reply.policy as GuardPolicy).mode).toBe("confirm");
		expect(t.fake.local.data.get(STORAGE_KEYS.userSettings)).toEqual({
			mode: "confirm",
			maskPaste: false,
		});
		await t.send({ type: "SET_USER_SETTINGS", settings: { language: "en" } });
		expect(t.fake.local.data.get(STORAGE_KEYS.userSettings)).toEqual({
			mode: "confirm",
			maskPaste: false,
			language: "en",
		});
		expect(t.policyMessages().some((m) => m.tabId === 1)).toBe(true);
	});

	it("rejects keys locked by managed policy without writing anything", async () => {
		const t = await setup({ managed: { mode: "block", maskPaste: true } });
		const reply = await t.send({
			type: "SET_USER_SETTINGS",
			settings: { mode: "monitor", maskPaste: false, language: "en" },
		});
		expect(reply).toEqual({ ok: false, error: "LOCKED_KEYS", keys: ["mode", "maskPaste"] });
		expect(t.fake.local.data.has(STORAGE_KEYS.userSettings)).toBe(false);
		expect(t.bg.policy().mode).toBe("block");
	});

	it("any managed policy rejects protection-reducing user settings (L2)", async () => {
		const t = await setup({ managed: { policyId: "acme-2026" } });
		const attempts: Record<string, unknown>[] = [
			{ enabledEntities: ["EMAIL"] },
			{ enabledEntities: [] },
			{ literals: [] },
			{ maskPaste: false },
			{ restoreResponses: false },
			{ disabledSites: ["chatgpt"] },
			{ mode: "monitor" },
		];
		for (const settings of attempts) {
			const reply = await t.send({ type: "SET_USER_SETTINGS", settings });
			expect(reply).toEqual({ ok: false, error: "LOCKED_KEYS", keys: Object.keys(settings) });
		}
		expect(t.fake.local.data.has(STORAGE_KEYS.userSettings)).toBe(false);
		// Settings that cannot weaken protection stay editable.
		expect((await t.send({ type: "SET_USER_SETTINGS", settings: { language: "tr" } })).ok).toBe(
			true,
		);
		expect(t.bg.policy()).toMatchObject({ mode: "auto", maskPaste: true, language: "tr" });
	});

	it("user settings stored before the managed policy arrived are not applied", async () => {
		const t = await setup({
			managed: { policyId: "acme-2026" },
			user: { mode: "monitor", enabledEntities: [], maskPaste: false },
		});
		expect(t.bg.policy()).toMatchObject({ mode: "auto", maskPaste: true });
		expect(t.bg.policy().enabledEntities.length).toBeGreaterThan(0);
	});

	it("allowUserOverrides: true accepts user changes to keys the policy does not set", async () => {
		const t = await setup({ managed: { policyId: "acme-2026", allowUserOverrides: true } });
		const reply = await t.send({
			type: "SET_USER_SETTINGS",
			settings: { enabledEntities: ["EMAIL"], maskPaste: false },
		});
		expect(reply.ok).toBe(true);
		expect(t.bg.policy()).toMatchObject({ enabledEntities: ["EMAIL"], maskPaste: false });
	});

	it("a managed mode also locks disabledSites", async () => {
		const t = await setup({ managed: { mode: "auto" } });
		const reply = await t.send({
			type: "SET_USER_SETTINGS",
			settings: { disabledSites: ["chatgpt"] },
		});
		expect(reply).toEqual({ ok: false, error: "LOCKED_KEYS", keys: ["disabledSites"] });
	});

	it("rejects unknown, admin-only and invalid keys", async () => {
		const t = await setup();
		expect(
			await t.send({
				type: "SET_USER_SETTINGS",
				settings: { allowUserPause: false, mode: "yolo", blockedSites: ["chatgpt"] },
			}),
		).toEqual({
			ok: false,
			error: "INVALID_SETTINGS",
			keys: ["allowUserPause", "blockedSites", "mode"],
		});
		expect(await t.send({ type: "SET_USER_SETTINGS", settings: "mode=monitor" })).toEqual({
			ok: false,
			error: "BAD_MESSAGE",
		});
		expect(
			await t.send({
				type: "SET_USER_SETTINGS",
				settings: {
					telemetry: { controlPlaneUrl: "http://cp.example.com", apiKey: "aidr_12345678" },
				},
			}),
		).toEqual({ ok: false, error: "INVALID_SETTINGS", keys: ["telemetry"] });
		expect(t.fake.local.data.has(STORAGE_KEYS.userSettings)).toBe(false);
	});
});

describe("background: PAUSE", () => {
	it("pauses for 1..60 minutes: content scripts get monitor mode until it expires", async () => {
		const t = await setup();
		const reply = await t.send({ type: "PAUSE", minutes: 15 });
		expect(reply).toEqual({ ok: true, pausedUntil: t.now() + 15 * 60_000 });
		expect(t.fake.alarms.get("aidr-pause-end")).toEqual({ when: t.now() + 15 * 60_000 });
		const paused = (await t.send({ type: "GET_POLICY" }, t.content())).policy as GuardPolicy;
		expect(paused.mode).toBe("monitor");
		const last = t.policyMessages().at(-1)?.message as { policy: GuardPolicy };
		expect(last.policy.mode).toBe("monitor");
		const stats = (await t.send({ type: "GET_STATS" })).stats as GuardStats;
		expect(stats.pausedUntil).toBe(t.now() + 15 * 60_000);

		t.advance(15 * 60_000 + 1);
		t.fake.fireAlarm("aidr-pause-end");
		const resumed = (await t.send({ type: "GET_POLICY" }, t.content())).policy as GuardPolicy;
		expect(resumed.mode).toBe("auto");
		await vi.waitFor(() =>
			expect((t.policyMessages().at(-1)?.message as { policy: GuardPolicy }).policy.mode).toBe(
				"auto",
			),
		);
	});

	it("resumes immediately with minutes 0", async () => {
		const t = await setup();
		await t.send({ type: "PAUSE", minutes: 60 });
		expect(await t.send({ type: "PAUSE", minutes: 0 })).toEqual({ ok: true, pausedUntil: null });
		expect(t.fake.alarms.has("aidr-pause-end")).toBe(false);
		const p = (await t.send({ type: "GET_POLICY" }, t.content())).policy as GuardPolicy;
		expect(p.mode).toBe("auto");
	});

	it("rejects out-of-range durations", async () => {
		const t = await setup();
		for (const minutes of [61, -1, 1.5, "10", null])
			expect(await t.send({ type: "PAUSE", minutes })).toEqual({ ok: false, error: "BAD_MESSAGE" });
	});

	it("is refused when the administrator disallows pausing, and a stale pause is ignored", async () => {
		const t = await setup();
		await t.send({ type: "PAUSE", minutes: 30 });
		await t.fake.managed.adminSet({ allowUserPause: false });
		await t.bg.reload(false);
		expect(await t.send({ type: "PAUSE", minutes: 5 })).toEqual({
			ok: false,
			error: "PAUSE_DISABLED",
		});
		const p = (await t.send({ type: "GET_POLICY" }, t.content())).policy as GuardPolicy;
		expect(p.mode).toBe("auto");
		const stats = (await t.send({ type: "GET_STATS" })).stats as GuardStats;
		expect(stats.pausedUntil).toBeNull();
	});
});

describe("background: RECORD and GET_STATS", () => {
	it("counts per tab and globally, derives the site from the sender and sets the badge", async () => {
		const t = await setup({ managed: { telemetry: TELEMETRY, policyId: "acme-2026" } });
		expect(
			await t.send(
				{
					type: "RECORD",
					site: "claude",
					action: "masked",
					channel: "prompt",
					counts: { EMAIL: 2, PHONE: 1 },
				},
				t.content(),
			),
		).toEqual({ ok: true });
		await t.send(
			{ type: "RECORD", site: "chatgpt", action: "blocked", channel: "file", counts: { IBAN: 1 } },
			t.content(),
		);
		await t.send(
			{ type: "RECORD", site: "gemini", action: "masked", channel: "paste", counts: { EMAIL: 1 } },
			t.content(2, GEMINI),
		);

		const tab1 = (await t.send({ type: "GET_STATS", tabId: 1 })).stats as GuardStats;
		expect(tab1).toMatchObject({
			site: "chatgpt",
			protectedPrompts: 2,
			maskedItems: 3,
			blockedSends: 1,
			byType: { EMAIL: 2, PHONE: 1, IBAN: 1 },
			nativeHost: "disabled",
		});
		const global = (await t.send({ type: "GET_STATS" })).stats as GuardStats;
		expect(global).toMatchObject({ site: null, maskedItems: 4, protectedPrompts: 3 });
		// A content script only ever sees its own tab.
		const own = (await t.send({ type: "GET_STATS", tabId: 1 }, t.content(2, GEMINI)))
			.stats as GuardStats;
		expect(own.site).toBe("gemini");
		expect(t.fake.badges.get(1)).toBe("3");
		expect(t.fake.badges.get(2)).toBe("1");

		await vi.waitFor(async () => expect(await t.bg.telemetry.pending()).toHaveLength(3));
		const events = await t.bg.telemetry.pending();
		expect(events.map((e) => e.site)).toEqual(["chatgpt", "chatgpt", "gemini"]);
		expect(events[0]).toMatchObject({ policy_id: "acme-2026", findings_count: 3 });
	});

	it("rejects RECORD from extension pages and with bad enums", async () => {
		const t = await setup();
		expect(
			await t.send({
				type: "RECORD",
				site: "chatgpt",
				action: "masked",
				channel: "prompt",
				counts: {},
			}),
		).toEqual({ ok: false, error: "NOT_ALLOWED" });
		expect(
			await t.send(
				{ type: "RECORD", site: "chatgpt", action: "leak", channel: "prompt", counts: {} },
				t.content(),
			),
		).toEqual({ ok: false, error: "BAD_MESSAGE" });
		expect(
			await t.send(
				{ type: "RECORD", site: "chatgpt", action: "masked", channel: "voice", counts: {} },
				t.content(),
			),
		).toEqual({ ok: false, error: "BAD_MESSAGE" });
		expect(await t.send({ type: "GET_STATS", tabId: -4 })).toEqual({
			ok: false,
			error: "BAD_MESSAGE",
		});
	});

	it("queues no telemetry when telemetry is not configured", async () => {
		const t = await setup();
		await t.send(
			{
				type: "RECORD",
				site: "chatgpt",
				action: "masked",
				channel: "prompt",
				counts: { EMAIL: 1 },
			},
			t.content(),
		);
		expect(await t.bg.telemetry.pending()).toHaveLength(0);
		expect(t.fake.local.data.has(STORAGE_KEYS.telemetryQueue)).toBe(false);
	});

	it("flushes telemetry on the periodic alarm", async () => {
		const t = await setup({ managed: { telemetry: TELEMETRY } });
		expect(t.fake.alarms.get(TELEMETRY_ALARM)).toEqual({ periodInMinutes: 1 });
		await t.send(
			{ type: "RECORD", site: "chatgpt", action: "warned", channel: "prompt", counts: {} },
			t.content(),
		);
		await vi.waitFor(async () => expect(await t.bg.telemetry.pending()).toHaveLength(1));
		t.fake.fireAlarm(TELEMETRY_ALARM);
		await vi.waitFor(() => expect(t.fetchMock).toHaveBeenCalledTimes(1));
		const [url, init] = t.fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("https://cp.example.com/functions/v1/ingest");
		expect(JSON.parse(String(init.body))).toMatchObject({
			agent_runtime: "browser_guard",
			agent_runtime_version: "chrome-126",
			aidr_version: "1.0.0",
		});
	});

	it("forgets a tab's counters when the tab closes", async () => {
		const t = await setup();
		await t.send(
			{
				type: "RECORD",
				site: "chatgpt",
				action: "masked",
				channel: "prompt",
				counts: { EMAIL: 1 },
			},
			t.content(),
		);
		t.fake.events.onRemoved.dispatch(1);
		const tab1 = (await t.send({ type: "GET_STATS", tabId: 1 })).stats as GuardStats;
		expect(tab1).toMatchObject({ site: null, maskedItems: 0 });
		const global = (await t.send({ type: "GET_STATS" })).stats as GuardStats;
		expect(global.maskedItems).toBe(1);
	});

	it("keeps counters in session storage only", async () => {
		const t = await setup();
		await t.send(
			{
				type: "RECORD",
				site: "chatgpt",
				action: "masked",
				channel: "prompt",
				counts: { EMAIL: 1 },
			},
			t.content(),
		);
		expect(t.fake.session.data.has(STORAGE_KEYS.stats)).toBe(true);
		expect(t.fake.local.data.has(STORAGE_KEYS.stats)).toBe(false);
		expect(t.fake.session.accessLevel).toBe("TRUSTED_CONTEXTS");
	});
});

describe("background: NATIVE_SCAN and SET_RESTORE_VISIBLE", () => {
	it("returns null findings when the native host is disabled", async () => {
		const t = await setup();
		expect(await t.send({ type: "NATIVE_SCAN", text: "Ada Lovelace" }, t.content())).toEqual({
			ok: true,
			findings: null,
			status: "disabled",
		});
		expect(await t.send({ type: "NATIVE_SCAN", text: 42 }, t.content())).toEqual({
			ok: false,
			error: "BAD_MESSAGE",
		});
	});

	it("proxies to the native bridge when managed policy enables it", async () => {
		const findings: Finding[] = [
			{ type: "PERSON", start: 0, end: 12, score: 0.9, source: "native-ner" },
		];
		const scanText = vi.fn(async () => findings);
		const t = await setup({
			managed: { useNativeHost: true },
			bridge: { status: () => "connected", scanText },
		});
		expect(await t.send({ type: "NATIVE_SCAN", text: "Ada Lovelace" }, t.content())).toEqual({
			ok: true,
			findings,
			status: "connected",
		});
		expect(scanText).toHaveBeenCalledWith("Ada Lovelace");
		const stats = (await t.send({ type: "GET_STATS" })).stats as GuardStats;
		expect(stats.nativeHost).toBe("connected");
		scanText.mockRejectedValueOnce(new Error("host crashed"));
		expect(await t.send({ type: "NATIVE_SCAN", text: "x" }, t.content())).toEqual({
			ok: true,
			findings: null,
			status: "connected",
		});
	});

	it("proxies NATIVE_IMAGE_SCAN to the bridge's OCR and zeroes the decoded image", async () => {
		const seen: Uint8Array[] = [];
		const scanImage = vi.fn(async (bytes: Uint8Array) => {
			seen.push(bytes);
			return {
				result: "sensitive" as const,
				counts: { EMAIL: 1 },
				reasons: ["IMAGE_SENSITIVE_TEXT"],
			};
		});
		const t = await setup({
			managed: { useNativeHost: true },
			bridge: { status: () => "connected", scanText: async () => null, scanImage },
		});
		const data = Buffer.from([1, 2, 3, 4]).toString("base64");
		expect(await t.send({ type: "NATIVE_IMAGE_SCAN", data }, t.content())).toEqual({
			ok: true,
			inspection: { result: "sensitive", counts: { EMAIL: 1 }, reasons: ["IMAGE_SENSITIVE_TEXT"] },
			status: "connected",
		});
		expect([...(seen[0] ?? [])]).toEqual([0, 0, 0, 0]);
		scanImage.mockRejectedValueOnce(new Error("host crashed"));
		expect(await t.send({ type: "NATIVE_IMAGE_SCAN", data }, t.content())).toEqual({
			ok: true,
			inspection: null,
			status: "connected",
		});
		for (const bad of [42, "not base64!", "QQ"]) {
			expect(await t.send({ type: "NATIVE_IMAGE_SCAN", data: bad }, t.content())).toEqual({
				ok: false,
				error: "BAD_MESSAGE",
			});
		}
	});

	it("answers NATIVE_IMAGE_SCAN with no inspection when the native host is off", async () => {
		const t = await setup();
		const data = Buffer.from([1, 2, 3]).toString("base64");
		expect(await t.send({ type: "NATIVE_IMAGE_SCAN", data }, t.content())).toEqual({
			ok: true,
			inspection: null,
			status: "disabled",
		});
	});

	it("honours a user opt-in and recreates the bridge when nativeMessaging is granted", async () => {
		const fake = createChromeFake();
		fake.local.data.set(STORAGE_KEYS.userSettings, { useNativeHost: true });
		const onAdded: ((p: { permissions?: string[] }) => void)[] = [];
		fake.chrome.permissions = {
			onAdded: { addListener: (l) => onAdded.push(l), removeListener: () => {} },
		};
		const factory = vi.fn(
			(_enabled: boolean): NativeBridge => ({
				status: () => "unavailable",
				scanText: async () => null,
			}),
		);
		const bg = startBackground({ chrome: fake.chrome, createNativeBridge: factory, log: () => {} });
		await bg.ready;
		expect(factory.mock.calls).toEqual([[true]]);
		onAdded[0]?.({ permissions: ["tabs"] });
		await bg.ready;
		expect(factory).toHaveBeenCalledTimes(1);
		onAdded[0]?.({ permissions: ["nativeMessaging"] });
		await expect.poll(() => factory.mock.calls).toEqual([[true], [true]]);
	});
});

describe("background: per-tab vault persistence (VAULT_SAVE / VAULT_LOAD)", () => {
	const EMAIL_ENTRY = { placeholder: "[EMAIL_1]", value: "ayse@example.com", type: "EMAIL" };
	const PHONE_ENTRY = { placeholder: "[PHONE_1]", value: "+90 532 000 00 00", type: "PHONE" };
	const snapshot = (createdAt: number, entries: unknown[] = [EMAIL_ENTRY]) => ({
		version: 1,
		createdAt,
		entries,
	});

	it("stores the vault in session storage only, keyed by the sender's tab and origin", async () => {
		const t = await setup();
		const save = {
			type: "VAULT_SAVE",
			snapshot: snapshot(t.now(), [EMAIL_ENTRY, PHONE_ENTRY]),
			sent: ["[EMAIL_1]", "[NOT_OURS_1]", "[EMAIL_1]"],
		};
		expect(await t.send(save, t.content(1, CHATGPT))).toEqual({ ok: true });
		expect([...t.fake.session.data.keys()]).toContain("vault:1:https://chatgpt.com");
		expect(JSON.stringify([...t.fake.local.data.values()])).not.toContain("ayse@example.com");
		expect(t.fake.session.accessLevel).toBe("TRUSTED_CONTEXTS");

		const loaded = await t.send({ type: "VAULT_LOAD" }, t.content(1, "https://chatgpt.com/c/9"));
		expect(loaded.ok).toBe(true);
		expect((loaded.snapshot as { entries: unknown[] }).entries).toEqual([EMAIL_ENTRY, PHONE_ENTRY]);
		expect(loaded.sent).toEqual(["[EMAIL_1]"]); // unknown and duplicate placeholders dropped

		// Another tab, or another site in the same tab, sees nothing.
		expect(await t.send({ type: "VAULT_LOAD" }, t.content(2, GEMINI))).toEqual({
			ok: true,
			snapshot: null,
			sent: [],
		});
		expect(await t.send({ type: "VAULT_LOAD" }, t.content(1, "https://chat.openai.com/"))).toEqual({
			ok: true,
			snapshot: null,
			sent: [],
		});
	});

	it("refuses extension pages, sub-frames and malformed or oversized snapshots", async () => {
		const t = await setup();
		const save = { type: "VAULT_SAVE", snapshot: snapshot(t.now()), sent: [] };
		expect(await t.send(save)).toEqual({ ok: false, error: "NOT_ALLOWED" });
		expect(await t.send({ type: "VAULT_LOAD" })).toEqual({ ok: false, error: "NOT_ALLOWED" });
		expect(await t.send(save, { ...t.content(), frameId: 3 })).toEqual({
			ok: false,
			error: "NOT_ALLOWED",
		});
		const bad = (s: unknown, sent: unknown = []) =>
			t.send({ type: "VAULT_SAVE", snapshot: s, sent }, t.content());
		expect(await bad({ ...snapshot(t.now()), extra: 1 })).toEqual({
			ok: false,
			error: "BAD_MESSAGE",
		});
		expect(
			await bad(snapshot(t.now(), [{ placeholder: "[PHONE_1]", value: "x@y.z", type: "EMAIL" }])),
		).toEqual({ ok: false, error: "BAD_MESSAGE" });
		expect(await bad(snapshot(t.now()), "[EMAIL_1]")).toEqual({ ok: false, error: "BAD_MESSAGE" });
		const huge = Array.from({ length: 40 }, (_, i) => ({
			placeholder: `[SECRET_${i + 1}]`,
			value: `${i}`.padEnd(60_000, "x"),
			type: "SECRET",
		}));
		expect(await bad(snapshot(t.now(), huge))).toEqual({ ok: false, error: "TOO_LARGE" });
		expect([...t.fake.session.data.keys()].some((k) => k.startsWith("vault:"))).toBe(false);
	});

	it("forgets a tab's vault when the tab closes, and every vault after the TTL", async () => {
		const t = await setup();
		const save = { type: "VAULT_SAVE", snapshot: snapshot(t.now()), sent: ["[EMAIL_1]"] };
		await t.send(save, t.content(1, CHATGPT));
		await t.send(save, t.content(2, GEMINI));
		t.fake.events.onRemoved.dispatch(1);
		await expect
			.poll(() => [...t.fake.session.data.keys()].filter((k) => k.startsWith("vault:")))
			.toEqual(["vault:2:https://gemini.google.com"]);

		t.advance(4 * 60 * 60 * 1000 + 1);
		expect(await t.send({ type: "VAULT_LOAD" }, t.content(2, GEMINI))).toEqual({
			ok: true,
			snapshot: null,
			sent: [],
		});
		expect(t.fake.session.data.has("vault:2:https://gemini.google.com")).toBe(false);

		await t.send({ ...save, snapshot: snapshot(t.now()) }, t.content(1, CHATGPT));
		t.advance(4 * 60 * 60 * 1000 + 1);
		t.fake.fireAlarm(TELEMETRY_ALARM);
		await expect
			.poll(() => [...t.fake.session.data.keys()].some((k) => k.startsWith("vault:")))
			.toBe(false);
	});

	it("an empty snapshot removes the stored vault", async () => {
		const t = await setup();
		await t.send(
			{ type: "VAULT_SAVE", snapshot: snapshot(t.now()), sent: [] },
			t.content(1, CHATGPT),
		);
		expect(t.fake.session.data.has("vault:1:https://chatgpt.com")).toBe(true);
		expect(
			await t.send(
				{ type: "VAULT_SAVE", snapshot: snapshot(t.now(), []), sent: [] },
				t.content(1, CHATGPT),
			),
		).toEqual({ ok: true });
		expect(t.fake.session.data.has("vault:1:https://chatgpt.com")).toBe(false);
	});

	it("routes SET_RESTORE_VISIBLE to the sender's tab or the active site tab", async () => {
		const t = await setup();
		expect(
			await t.send({ type: "SET_RESTORE_VISIBLE", visible: false }, t.content(2, GEMINI)),
		).toEqual({ ok: true });
		expect(await t.send({ type: "SET_RESTORE_VISIBLE", visible: true })).toEqual({ ok: true });
		const restore = t.fake.tabMessages.filter(
			(m) => (m.message as { type: string }).type === "SET_RESTORE_VISIBLE",
		);
		expect(restore).toEqual([
			{ tabId: 2, message: { type: "SET_RESTORE_VISIBLE", visible: false } },
			{ tabId: 1, message: { type: "SET_RESTORE_VISIBLE", visible: true } },
		]);
		expect(await t.send({ type: "SET_RESTORE_VISIBLE", visible: "yes" })).toEqual({
			ok: false,
			error: "BAD_MESSAGE",
		});
	});
});

describe("background: blocked sites (declarativeNetRequest)", () => {
	it("blocks top-level navigations and frames (no web-accessible redirect target)", () => {
		const rules = buildBlockRules(["chatgpt", "other"]);
		expect(rules).toHaveLength(2);
		const [navigation, frame] = rules;
		expect(navigation).toMatchObject({
			action: { type: "block" },
			condition: {
				requestDomains: ["chatgpt.com", "chat.openai.com"],
				resourceTypes: ["main_frame"],
			},
		});
		expect(frame).toMatchObject({
			action: { type: "block" },
			condition: {
				requestDomains: ["chatgpt.com", "chat.openai.com"],
				resourceTypes: ["sub_frame"],
			},
		});
		for (const rule of rules) expect(DNR_RULE_IDS).toContain(rule.id);
		expect(buildBlockRules([])).toEqual([]);
	});

	it("covers all eight supported sites with unique rule ids", () => {
		expect(Object.keys(SITE_HOSTS)).toHaveLength(8);
		const rules = buildBlockRules(Object.keys(SITE_HOSTS) as never);
		expect(rules).toHaveLength(16);
		expect(new Set(rules.map((r) => r.id)).size).toBe(16);
	});

	it("applies managed blockedSites and replaces rules on change", async () => {
		const t = await setup({ managed: { blockedSites: ["chatgpt", "grok"] } });
		expect(t.fake.dnrRules.size).toBe(4);
		await t.fake.managed.adminReplace({ blockedSites: ["gemini"] });
		await t.bg.reload(false);
		const domains = [...t.fake.dnrRules.values()].flatMap((r) => r.condition.requestDomains);
		expect(new Set(domains)).toEqual(new Set(["gemini.google.com"]));
		await t.fake.managed.adminReplace({});
		await t.bg.reload(false);
		expect(t.fake.dnrRules.size).toBe(0);
	});

	it("reports DNR failures without throwing", async () => {
		const ok = await applyBlockedSites(
			{
				declarativeNetRequest: {
					updateDynamicRules: async () => {
						throw new Error("quota");
					},
				},
			},
			["chatgpt"],
		);
		expect(ok).toBe(false);
	});

	it("shows blocked.html in a tab whose navigation the installed rule refused", async () => {
		const t = await setup({ managed: { blockedSites: ["gemini"] } });
		t.fake.events.onUpdated.dispatch(2, { status: "loading", url: GEMINI }, { id: 2, url: GEMINI });
		await vi.waitFor(() =>
			expect(t.fake.tabUpdates).toEqual([
				{ tabId: 2, url: `${EXTENSION_BASE}blocked.html?site=gemini` },
			]),
		);
		// A site that is not blocked, a non-web URL and our own page are left alone.
		t.fake.events.onUpdated.dispatch(1, { url: CHATGPT }, { id: 1, url: CHATGPT });
		t.fake.events.onUpdated.dispatch(3, { url: "chrome://newtab/" }, { id: 3 });
		t.fake.events.onUpdated.dispatch(
			2,
			{ url: `${EXTENSION_BASE}blocked.html?site=gemini` },
			{ id: 2 },
		);
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(t.fake.tabUpdates).toHaveLength(1);
	});

	it("keys the redirect off the installed rules, subdomains included", async () => {
		const t = await setup();
		const tabs = { update: vi.fn(async () => undefined) };
		const chrome = {
			...t.fake.chrome,
			tabs: { ...t.fake.chrome.tabs, update: tabs.update },
		};
		expect(await redirectBlockedTab(chrome, 5, "https://gemini.google.com/app")).toBeNull();
		await applyBlockedSites(t.fake.chrome, ["gemini"]);
		expect(await redirectBlockedTab(chrome, 5, "https://sub.gemini.google.com/x")).toBe("gemini");
		expect(await redirectBlockedTab(chrome, 5, "https://gemini.google.com.evil.test/")).toBeNull();
		expect(tabs.update).toHaveBeenCalledTimes(1);
		expect(tabs.update).toHaveBeenCalledWith(5, {
			url: `${EXTENSION_BASE}blocked.html?site=gemini`,
		});
		const rules = [...t.fake.dnrRules.values()];
		expect(navigationBlocked(rules, "gemini")).toBe(true);
		expect(navigationBlocked(rules, "chatgpt")).toBe(false);
		expect(siteForNavigation("http://chat.openai.com/")).toBe("chatgpt");
		expect(siteForNavigation("file:///etc/passwd")).toBeNull();
		expect(updatedTabUrl({ url: "https://a.test/" }, undefined)).toBe("https://a.test/");
		expect(updatedTabUrl({ status: "loading" }, { url: "https://b.test/" })).toBe(
			"https://b.test/",
		);
		expect(updatedTabUrl({ status: "complete" }, { url: "https://b.test/" })).toBeUndefined();
	});

	it("maps only exact HTTPS hosts of supported sites", () => {
		expect(siteForUrl("https://chatgpt.com/")).toBe("chatgpt");
		expect(siteForUrl("https://chat.openai.com/c/1")).toBe("chatgpt");
		expect(siteForUrl("https://www.perplexity.ai/")).toBe("perplexity");
		expect(siteForUrl("https://sub.claude.ai/")).toBeNull();
		expect(siteForUrl("https://user:pw@claude.ai/")).toBeNull();
		expect(siteForUrl("not a url")).toBeNull();
		expect(siteForUrl(undefined)).toBeNull();
	});
});

describe("badgeText", () => {
	it("hides zero and caps large counts", () => {
		expect(badgeText(0)).toBe("");
		expect(badgeText(7)).toBe("7");
		expect(badgeText(1000)).toBe("999+");
	});
});
