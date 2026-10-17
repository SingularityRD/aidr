/**
 * Frame coverage for the Microsoft 365 Copilot pane inside the Office web apps: the pane is
 * a cross-origin iframe, so the content script also runs in subframes of the Microsoft 365
 * Copilot hosts (src/sites/frames.ts). The worker must accept those frames (and only those),
 * tag their counts with the `copilot` site from the frame's own URL, keep their vault apart
 * from the top frame's, push policy changes to them although the tab's page is not a
 * protected site, and never block or redirect the Office app itself.
 */
import { describe, expect, it, vi } from "vitest";
import { ContentFrames } from "../background/content-frames.js";
import { buildBlockRules, redirectBlockedTab, siteForNavigation } from "../background/dnr.js";
import { startBackground } from "../background/index.js";
import { GuardStorage, STORAGE_KEYS } from "../background/storage.js";
import { serviceForUrl } from "../sites/catalog.js";
import { FRAME_GUARD_HOSTS, isFrameGuardUrl } from "../sites/frames.js";
import { adapterForUrl, FRAME_MATCH_PATTERNS, MATCH_PATTERNS } from "../sites/index.js";
import type { GuardPolicy, GuardStats } from "../types.js";
import { createChromeFake } from "./helpers/chrome-fake.js";

/** Office web app pages that embed the Copilot pane (never protected sites themselves). */
const WORD = "https://word-edit.officeapps.live.com/we/wordeditorframe.aspx?ui=en-US";
const OUTLOOK = "https://outlook.office.com/mail/";
const PANE = "https://copilot.cloud.microsoft/pane?hostApp=Word";
const M365_PANE = "https://m365.cloud.microsoft/chat/?hostApp=Excel";
const CHATGPT = "https://chatgpt.com/c/1";
const TELEMETRY = { controlPlaneUrl: "https://cp.example.com", apiKey: ["aidr_test", "key_123456"].join("_") };

const EMAIL_ENTRY = { placeholder: "[EMAIL_1]", value: "ayse@example.com", type: "EMAIL" };

async function setup(managed: Record<string, unknown> = {}) {
	const fake = createChromeFake({ version: "1.0.0" });
	for (const [k, v] of Object.entries(managed)) fake.managed.data.set(k, v);
	fake.tabs.push(
		{ id: 1, url: WORD, active: true },
		{ id: 2, url: CHATGPT },
		{ id: 3, url: "https://m365.cloud.microsoft/" },
	);
	const now = Date.parse("2026-10-13T10:00:00Z");
	const bg = startBackground({
		chrome: fake.chrome,
		fetch: vi.fn(async () => new Response("{}", { status: 202 })) as unknown as typeof fetch,
		now: () => now,
		random: () => 0.5,
		navigator: { userAgent: "Mozilla/5.0 Chrome/126.0.0.0" },
		log: () => {},
	});
	await bg.ready;
	/** A content script in frame `frameId` of `tabId` (whose top-level page is `topUrl`). */
	const frame = (tabId: number, url: string, frameId: number, topUrl = WORD) => ({
		...fake.contentSender(tabId, url),
		frameId,
		tab: { id: tabId, url: topUrl },
	});
	const send = (message: unknown, sender: unknown = fake.extensionSender("popup.html")) =>
		fake.sendRuntimeMessage(message, sender as never) as Promise<Record<string, unknown>>;
	const policyPushes = () =>
		fake.tabMessages.filter((m) => (m.message as { type: string }).type === "POLICY_CHANGED");
	return { fake, bg, frame, send, policyPushes, now };
}

describe("frame-guarded hosts (src/sites/frames.ts)", () => {
	it("are the Microsoft 365 Copilot hosts of the copilot adapter, and nothing else", () => {
		expect(FRAME_GUARD_HOSTS).toEqual(["m365.cloud.microsoft", "copilot.cloud.microsoft"]);
		for (const pattern of FRAME_MATCH_PATTERNS) expect(MATCH_PATTERNS).toContain(pattern);
		for (const host of FRAME_GUARD_HOSTS)
			expect(adapterForUrl(`https://${host}/pane`).id).toBe("copilot");
		// Consumer Copilot and every other site stay top-frame only.
		expect(FRAME_MATCH_PATTERNS).not.toContain("https://copilot.microsoft.com/*");
		expect(FRAME_MATCH_PATTERNS).toHaveLength(2);
	});

	it("isFrameGuardUrl matches exact https hosts only", () => {
		expect(isFrameGuardUrl(PANE)).toBe(true);
		expect(isFrameGuardUrl(M365_PANE)).toBe(true);
		for (const url of [
			WORD,
			OUTLOOK,
			CHATGPT,
			"https://copilot.microsoft.com/",
			"http://copilot.cloud.microsoft/",
			"https://copilot.cloud.microsoft:8443/",
			"https://user:pw@copilot.cloud.microsoft/",
			"https://evil.copilot.cloud.microsoft/",
			"https://copilot.cloud.microsoft.evil.example/",
			"not a url",
			42,
		])
			expect(isFrameGuardUrl(url)).toBe(false);
	});

	it("Office host pages are neither protected sites nor Shadow AI services (no Office block)", () => {
		for (const url of [
			WORD,
			OUTLOOK,
			"https://excel.officeapps.live.com/x/_layouts/xlviewerinternal.aspx",
		]) {
			expect(adapterForUrl(url).id).toBe("other");
			expect(siteForNavigation(url)).toBeNull();
			expect(serviceForUrl(url)).toBeNull();
		}
		// blockedSites: ["copilot"] blocks the Copilot hosts (top level and as a frame: the pane
		// itself), never an Office host.
		const rules = JSON.stringify(buildBlockRules(["copilot"]));
		for (const office of ["officeapps", "office.com", "sharepoint", "outlook"])
			expect(rules).not.toContain(office);
	});
});

describe("background: Copilot pane subframes", () => {
	it("accepts a subframe content script only on the frame-guarded hosts", async () => {
		const t = await setup();
		const pane = await t.send({ type: "GET_POLICY" }, t.frame(1, PANE, 5));
		expect(pane.ok).toBe(true);
		// A subframe of any other protected site never runs a content script: refused.
		expect(await t.send({ type: "GET_POLICY" }, t.frame(2, CHATGPT, 4, CHATGPT))).toEqual({
			ok: false,
			error: "SENDER_DENIED",
		});
		// An Office frame (no adapter) is refused at top level and as a frame.
		expect(await t.send({ type: "GET_POLICY" }, t.frame(1, WORD, 0))).toEqual({
			ok: false,
			error: "SENDER_DENIED",
		});
		expect(await t.send({ type: "GET_POLICY" }, t.frame(1, OUTLOOK, 6))).toEqual({
			ok: false,
			error: "SENDER_DENIED",
		});
	});

	it("tags stats and telemetry with the frame's site (copilot), not the Office page", async () => {
		const t = await setup({ telemetry: TELEMETRY });
		const record = (sender: unknown, counts: Record<string, number>) =>
			t.send(
				{ type: "RECORD", site: "chatgpt", action: "masked", channel: "prompt", counts },
				sender,
			);
		expect(await record(t.frame(1, PANE, 5), { EMAIL: 2 })).toEqual({ ok: true });
		const stats = (await t.send({ type: "GET_STATS", tabId: 1 })).stats as GuardStats;
		expect(stats).toMatchObject({ site: "copilot", protectedPrompts: 1, maskedItems: 2 });
		expect(t.fake.badges.get(1)).toBe("2");
		await vi.waitFor(async () => expect(await t.bg.telemetry.pending()).toHaveLength(1));
		expect((await t.bg.telemetry.pending()).map((e) => e.site)).toEqual(["copilot"]);
	});

	it("counts each send once when a top-frame guard and a pane guard share a tab", async () => {
		const t = await setup({ telemetry: TELEMETRY });
		const top = t.fake.contentSender(3, "https://m365.cloud.microsoft/");
		const pane = t.frame(3, PANE, 7, "https://m365.cloud.microsoft/");
		const record = (sender: unknown) =>
			t.send({ type: "RECORD", action: "masked", channel: "prompt", counts: { EMAIL: 1 } }, sender);
		await record(top);
		await record(pane);
		const stats = (await t.send({ type: "GET_STATS", tabId: 3 })).stats as GuardStats;
		expect(stats).toMatchObject({ site: "copilot", protectedPrompts: 2, maskedItems: 2 });
		await vi.waitFor(async () => expect(await t.bg.telemetry.pending()).toHaveLength(2));
	});

	it("keeps the pane's vault apart from the top frame's, even on the same origin", async () => {
		const t = await setup();
		const snapshot = { version: 1, createdAt: t.now, entries: [EMAIL_ENTRY] };
		const top = t.fake.contentSender(3, "https://m365.cloud.microsoft/");
		const pane = t.frame(3, M365_PANE, 9, "https://m365.cloud.microsoft/");
		expect(await t.send({ type: "VAULT_SAVE", snapshot, sent: ["[EMAIL_1]"] }, pane)).toEqual({
			ok: true,
		});
		const keys = [...t.fake.session.data.keys()].filter((k) => k.startsWith("vault:"));
		expect(keys).toEqual(["vault:3:frame:https://m365.cloud.microsoft"]);
		// The pane reloads (same tab, possibly a new frame id) and gets its vault back.
		const loaded = await t.send({ type: "VAULT_LOAD" }, { ...pane, frameId: 12 });
		expect((loaded.snapshot as { entries: unknown[] }).entries).toHaveLength(1);
		expect(loaded.sent).toEqual(["[EMAIL_1]"]);
		// The top frame of the same origin does not see (or overwrite) it.
		expect(await t.send({ type: "VAULT_LOAD" }, top)).toEqual({
			ok: true,
			snapshot: null,
			sent: [],
		});
		// Closing the tab forgets both.
		t.fake.events.onRemoved.dispatch(3);
		await vi.waitFor(() =>
			expect([...t.fake.session.data.keys()].some((k) => k.startsWith("vault:3:"))).toBe(false),
		);
	});

	it("pushes policy changes to registered pane frames with their own site's policy", async () => {
		const t = await setup();
		await t.send({ type: "GET_POLICY" }, t.frame(1, PANE, 5));
		const before = t.policyPushes().length;
		t.fake.local.data.set(STORAGE_KEYS.userSettings, { disabledSites: ["copilot"] });
		await t.bg.reload(true);
		const pushes = t.policyPushes().slice(before);
		// Tab 1 (Word) is reached through its registered pane frame only, never its top frame.
		const toWord = pushes.filter((m) => m.tabId === 1);
		expect(toWord.map((m) => m.frameId)).toEqual([5]);
		expect((toWord[0].message as { policy: GuardPolicy }).policy.mode).toBe("monitor");
		// Protected top frames are addressed as frame 0 with their own site's policy.
		const toChatgpt = pushes.find((m) => m.tabId === 2);
		expect(toChatgpt?.frameId).toBe(0);
		expect((toChatgpt?.message as { policy: GuardPolicy }).policy.mode).toBe("auto");
		// Content scripts never receive the telemetry key.
		expect(JSON.stringify(pushes)).not.toContain("apiKey");
	});

	it("forgets a tab's pane frames when the tab closes", async () => {
		const t = await setup();
		await t.send({ type: "GET_POLICY" }, t.frame(1, PANE, 5));
		expect(t.fake.session.data.get(STORAGE_KEYS.contentFrames)).toEqual({ 1: { 5: "copilot" } });
		t.fake.events.onRemoved.dispatch(1);
		await vi.waitFor(() => expect(t.fake.session.data.get(STORAGE_KEYS.contentFrames)).toEqual({}));
	});

	it("lets the popup toggle restore visibility on an Office tab with a guarded pane", async () => {
		const t = await setup();
		expect(await t.send({ type: "SET_RESTORE_VISIBLE", visible: false })).toEqual({
			ok: false,
			error: "NOT_ALLOWED",
		});
		await t.send({ type: "GET_POLICY" }, t.frame(1, PANE, 5));
		expect(await t.send({ type: "SET_RESTORE_VISIBLE", visible: false })).toEqual({ ok: true });
	});

	it("accepts the acceptable-use acknowledgement from the pane", async () => {
		const t = await setup({
			acceptableUse: { id: "acme-aup", version: 2, title: "AI use", text: "Be careful." },
		});
		expect(
			await t.send(
				{ type: "AUP_ACKNOWLEDGE", noticeId: "acme-aup", version: 2 },
				t.frame(1, PANE, 5),
			),
		).toEqual({ ok: true });
	});

	it("never redirects the Office tab when copilot is blocked (only the pane's own request is)", async () => {
		const t = await setup({ blockedSites: ["copilot"] });
		expect(await redirectBlockedTab(t.fake.chrome, 1, WORD)).toBeNull();
		expect(t.fake.tabUpdates).toEqual([]);
		// The frame block rule covers the Copilot hosts, so the pane itself does not load.
		const rules = [...t.fake.dnrRules.values()];
		expect(
			rules.some(
				(r) =>
					r.condition.resourceTypes?.includes("sub_frame") &&
					r.condition.requestDomains?.includes("copilot.cloud.microsoft"),
			),
		).toBe(true);
	});
});

describe("ContentFrames", () => {
	it("records subframes only, bounded per tab, and validates what it reads back", async () => {
		const fake = createChromeFake();
		const frames = new ContentFrames(new GuardStorage(fake.chrome, () => {}));
		await frames.mark(1, 0, "copilot"); // the top frame is never a frame record
		await frames.mark(-1, 3, "copilot");
		expect(await frames.list()).toEqual([]);
		for (let id = 1; id <= 12; id++) await frames.mark(1, id, "copilot");
		const list = await frames.list();
		expect(list).toHaveLength(8);
		expect(list.map((f) => f.frameId)).toEqual([5, 6, 7, 8, 9, 10, 11, 12]);
		expect(await frames.has(1)).toBe(true);
		expect(await frames.has(2)).toBe(false);
		fake.session.data.set(STORAGE_KEYS.contentFrames, {
			x: { 1: "copilot" },
			4: { 0: "copilot", 2: 7 },
		});
		expect(await frames.list()).toEqual([]);
	});
});
