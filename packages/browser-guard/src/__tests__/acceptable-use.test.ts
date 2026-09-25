// @vitest-environment jsdom
/**
 * AI acceptable-use notice: managed policy validation, the background worker's
 * AUP_STATUS / AUP_ACKNOWLEDGE handling and counts-only telemetry, and the in-page
 * dialog (closed shadow root, accessible, plain-text rendering, once per version).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { startBackground } from "../background/index.js";
import {
	DEFAULT_POLICY,
	evaluatePolicy,
	MANAGED_POLICY_KEYS,
	validateAcceptableUseNotice,
} from "../background/policy.js";
import { STORAGE_KEYS } from "../background/storage.js";
import {
	buildAupAckEvent,
	sanitizeAupAckEvent,
	sanitizeQueuedEvent,
} from "../background/telemetry.js";
import {
	createAcceptableUseNotice,
	extractNotice,
	noticeParagraphs,
} from "../content/acceptable-use.js";
import { STRINGS } from "../content/strings.js";
import { createGuardUi, type GuardUi } from "../content/ui.js";
import type { AcceptableUseNotice, GuardMessage, GuardPolicy } from "../types.js";
import { createChromeFake } from "./helpers/chrome-fake.js";

const NOTICE: AcceptableUseNotice = {
	id: "acme-aup",
	version: 3,
	title: "Using AI at Acme",
	text: "Do not paste customer records.\n\nCheck AI answers before you rely on them.",
	url: "https://intranet.acme.example/ai-policy",
};
const TELEMETRY = { controlPlaneUrl: "https://cp.example.com", apiKey: "aidr_ingest_test_123456" };
const CHATGPT = "https://chatgpt.com/c/1";

describe("acceptableUse managed policy", () => {
	it("accepts a complete notice, trims text and normalises the link", () => {
		expect(validateAcceptableUseNotice({ ...NOTICE, title: "  Using AI at Acme  " })).toEqual(
			NOTICE,
		);
		const { url: _url, ...withoutUrl } = NOTICE;
		expect(validateAcceptableUseNotice(withoutUrl)).toEqual(withoutUrl);
	});

	it("rejects the whole notice when any field is out of contract", () => {
		for (const bad of [
			{ ...NOTICE, id: "has space" },
			{ ...NOTICE, id: "x".repeat(65) },
			{ ...NOTICE, version: 0 },
			{ ...NOTICE, version: 1.5 },
			{ ...NOTICE, version: 1_000_000 },
			{ ...NOTICE, title: "" },
			{ ...NOTICE, title: "t".repeat(121) },
			{ ...NOTICE, text: "   " },
			{ ...NOTICE, text: "x".repeat(4001) },
			{ ...NOTICE, text: "bell\u0007" },
			{ ...NOTICE, url: "http://intranet.acme.example" },
			{ ...NOTICE, url: "https://user:pass@acme.example" },
			{ ...NOTICE, url: "javascript:alert(1)" },
			{ ...NOTICE, html: "<b>x</b>" },
			"notice",
			null,
		])
			expect(validateAcceptableUseNotice(bad)).toBeNull();
	});

	it("is a managed-only key: administrators set it, users cannot", () => {
		expect(MANAGED_POLICY_KEYS).toContain("acceptableUse");
		expect(DEFAULT_POLICY.acceptableUse).toBeNull();
		const managed = evaluatePolicy({ acceptableUse: NOTICE }, undefined);
		expect(managed.policy.acceptableUse).toEqual(NOTICE);
		expect(managed.policy.managedKeys).toContain("acceptableUse");
		const invalid = evaluatePolicy({ acceptableUse: { ...NOTICE, version: -1 } }, undefined);
		expect(invalid.policy.acceptableUse).toBeNull();
		expect(invalid.warnings).toContain('managed: invalid value for "acceptableUse" ignored');
		const user = evaluatePolicy(undefined, { acceptableUse: NOTICE });
		expect(user.policy.acceptableUse).toBeNull();
		expect(user.warnings).toContain('user: unknown key "acceptableUse" ignored');
	});
});

describe("acknowledgement telemetry event", () => {
	it("carries the site, notice id and version only", () => {
		const event = buildAupAckEvent({ site: "gemini", noticeId: "acme-aup", noticeVersion: 3 }, 0);
		expect(event).toMatchObject({
			event_type: "aup_acknowledgement",
			timestamp: "1970-01-01T00:00:00.000Z",
			site: "gemini",
			notice_id: "acme-aup",
			notice_version: 3,
		});
		expect(Object.keys(event ?? {})).toHaveLength(6);
		expect(sanitizeAupAckEvent({ ...event, notice_text: NOTICE.text })).toBeNull();
		expect(sanitizeAupAckEvent({ ...event, notice_version: 0 })).toBeNull();
		expect(sanitizeAupAckEvent({ ...event, site: "https://chatgpt.com" })).toBeNull();
		expect(sanitizeQueuedEvent(event)).toEqual(event);
		expect(
			buildAupAckEvent({ site: "chatgpt", noticeId: "bad id", noticeVersion: 1 }, 0),
		).toBeNull();
	});
});

async function worker(
	managed: Record<string, unknown> = { acceptableUse: NOTICE, telemetry: TELEMETRY },
) {
	const fake = createChromeFake({ version: "1.0.0" });
	for (const [key, value] of Object.entries(managed)) fake.managed.data.set(key, value);
	fake.tabs.push({ id: 1, url: CHATGPT, active: true });
	const fetchMock = vi.fn(async () => new Response("{}", { status: 202 }));
	const bg = startBackground({
		chrome: fake.chrome,
		fetch: fetchMock as unknown as typeof fetch,
		now: () => Date.parse("2026-09-24T10:00:00Z"),
		random: () => 0.5,
		navigator: { userAgent: "Mozilla/5.0 Chrome/126.0.0.0" },
		createNativeBridge: () => ({ status: () => "disabled", scanText: async () => null }),
		log: () => {},
	});
	await bg.ready;
	const content = (tabId = 1, url = CHATGPT) => fake.contentSender(tabId, url);
	const send = (message: unknown, sender = content()) =>
		fake.sendRuntimeMessage(message, sender) as Promise<Record<string, unknown>>;
	return { fake, bg, send, fetchMock, content };
}

describe("background worker: AUP_STATUS and AUP_ACKNOWLEDGE", () => {
	it("reports the notice until this version is acknowledged, then queues one counts-only event", async () => {
		const w = await worker();
		expect(await w.send({ type: "AUP_STATUS" })).toEqual({
			ok: true,
			notice: NOTICE,
			acknowledged: false,
		});
		expect(await w.send({ type: "AUP_ACKNOWLEDGE", noticeId: "acme-aup", version: 3 })).toEqual({
			ok: true,
		});
		expect(await w.send({ type: "AUP_ACKNOWLEDGE", noticeId: "acme-aup", version: 3 })).toEqual({
			ok: true,
		});
		expect(await w.send({ type: "AUP_STATUS" })).toMatchObject({ acknowledged: true });
		expect(w.fake.local.data.get(STORAGE_KEYS.aupAcknowledged)).toEqual({ "acme-aup": 3 });
		await vi.waitFor(async () => expect(await w.bg.telemetry.pending()).toHaveLength(1));
		const [event] = await w.bg.telemetry.pending();
		expect(event).toMatchObject({
			event_type: "aup_acknowledgement",
			site: "chatgpt",
			notice_id: "acme-aup",
			notice_version: 3,
		});
		expect(JSON.stringify(await w.bg.telemetry.pending())).not.toContain("customer records");

		expect(await w.bg.telemetry.flush()).toBe("sent");
		const body = JSON.parse(
			String((w.fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body),
		);
		expect(body.events).toEqual([event]);
		expect(body.agent_runtime).toBe("browser_guard");
	});

	it("shows a raised version again and refuses stale or foreign acknowledgements", async () => {
		const w = await worker();
		await w.send({ type: "AUP_ACKNOWLEDGE", noticeId: "acme-aup", version: 3 });
		w.fake.managed.data.set("acceptableUse", { ...NOTICE, version: 4 });
		await w.bg.reload(false);
		expect(await w.send({ type: "AUP_STATUS" })).toMatchObject({
			acknowledged: false,
			notice: { version: 4 },
		});
		for (const message of [
			{ type: "AUP_ACKNOWLEDGE", noticeId: "acme-aup", version: 3 },
			{ type: "AUP_ACKNOWLEDGE", noticeId: "other", version: 4 },
			{ type: "AUP_ACKNOWLEDGE", noticeId: "acme-aup", version: "4" },
		])
			expect(await w.send(message)).toEqual({ ok: false, error: "BAD_MESSAGE" });
		// Only a protected site's content script can acknowledge.
		expect(
			await w.send(
				{ type: "AUP_ACKNOWLEDGE", noticeId: "acme-aup", version: 4 },
				w.fake.extensionSender("options.html"),
			),
		).toEqual({ ok: false, error: "NOT_ALLOWED" });
		expect(await w.send({ type: "AUP_STATUS" }, w.content(9, "https://evil.example/"))).toEqual({
			ok: false,
			error: "SENDER_DENIED",
		});
	});

	it("has nothing to show without a managed notice and records nothing without telemetry", async () => {
		const none = await worker({ telemetry: TELEMETRY });
		expect(await none.send({ type: "AUP_STATUS" })).toEqual({
			ok: true,
			notice: null,
			acknowledged: true,
		});
		expect(await none.send({ type: "AUP_ACKNOWLEDGE", noticeId: "acme-aup", version: 3 })).toEqual({
			ok: false,
			error: "BAD_MESSAGE",
		});
		const offline = await worker({ acceptableUse: NOTICE });
		expect(
			await offline.send({ type: "AUP_ACKNOWLEDGE", noticeId: "acme-aup", version: 3 }),
		).toEqual({ ok: true });
		expect(await offline.bg.telemetry.pending()).toEqual([]);
		expect(await offline.send({ type: "AUP_STATUS" })).toMatchObject({ acknowledged: true });
	});
});

describe("in-page notice", () => {
	let ui: GuardUi | null = null;
	afterEach(() => {
		ui?.destroy();
		ui = null;
		document.body.innerHTML = "";
	});

	function setup(status: Record<string, unknown>, ackReply: unknown = { ok: true }) {
		ui = createGuardUi({ document, window, strings: () => STRINGS.en, toastMs: 1_000 });
		const messages: GuardMessage[] = [];
		const send = vi.fn(async (message: GuardMessage) => {
			messages.push(message);
			return message.type === "AUP_STATUS" ? status : ackReply;
		});
		const notice = createAcceptableUseNotice({ ui, send, strings: () => STRINGS.en });
		return { notice, messages, ui };
	}

	const dialog = (current: GuardUi) =>
		current.root.querySelector('[role="alertdialog"]') as HTMLElement;
	const button = (current: GuardUi, label: string) =>
		[...current.root.querySelectorAll("button")].find(
			(b) => b.textContent === label,
		) as HTMLButtonElement;

	it("shows the notice in a closed shadow root as an accessible dialog and records I understand", async () => {
		const s = setup({ ok: true, notice: NOTICE, acknowledged: false });
		const outcome = s.notice.check();
		await vi.waitFor(() => expect(dialog(s.ui).hidden).toBe(false));
		expect(s.ui.host.shadowRoot).toBeNull();
		const box = dialog(s.ui);
		const title = s.ui.root.getElementById(box.getAttribute("aria-labelledby") ?? "");
		expect(title?.textContent).toContain("Using AI at Acme");
		expect(
			s.ui.root.getElementById(box.getAttribute("aria-describedby") ?? "")?.textContent,
		).toContain("Do not paste customer records.");
		expect([...box.querySelectorAll(".line")].map((p) => p.textContent)).toEqual([
			"Do not paste customer records.",
			"Check AI answers before you rely on them.",
			"Read the full policy",
		]);
		expect(box.querySelector(".caption")?.textContent).toBe("Acceptable-use notice, version 3");
		const link = box.querySelector("a") as HTMLAnchorElement;
		expect([link.href, link.target, link.rel]).toEqual([
			"https://intranet.acme.example/ai-policy",
			"_blank",
			"noopener noreferrer",
		]);
		expect(s.ui.root.activeElement).toBe(button(s.ui, "I understand"));
		// Tab cycles through the link and both buttons inside the dialog.
		box.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", bubbles: true }));
		expect(s.ui.root.activeElement).toBe(link);

		button(s.ui, "I understand").click();
		expect(await outcome).toBe("recorded");
		expect(s.messages).toEqual([
			{ type: "AUP_STATUS" },
			{ type: "AUP_ACKNOWLEDGE", noticeId: "acme-aup", version: 3 },
		]);
		expect(s.ui.root.querySelector('[role="status"]')?.textContent).toContain(
			"Your acknowledgement was recorded",
		);
	});

	it("renders administrator text as text, never as markup", async () => {
		const s = setup({
			ok: true,
			notice: {
				...NOTICE,
				title: "<img src=x onerror=alert(1)>",
				text: "<script>alert(1)</script>",
				url: undefined,
			},
			acknowledged: false,
		});
		void s.notice.check();
		await vi.waitFor(() => expect(dialog(s.ui).hidden).toBe(false));
		expect(s.ui.root.querySelector("img, script")).toBeNull();
		expect(dialog(s.ui).textContent).toContain("<script>alert(1)</script>");
		expect(dialog(s.ui).querySelector("a")).toBeNull();
		s.ui.closeBubble();
	});

	it("does not interrupt when already acknowledged, and Escape defers it without recording", async () => {
		const done = setup({ ok: true, notice: NOTICE, acknowledged: true });
		expect(await done.notice.check()).toBe("acknowledged");
		expect(dialog(done.ui).hidden).toBe(true);
		done.ui.destroy();

		const later = setup({ ok: true, notice: NOTICE, acknowledged: false });
		const outcome = later.notice.check();
		await vi.waitFor(() => expect(dialog(later.ui).hidden).toBe(false));
		dialog(later.ui).dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
		expect(await outcome).toBe("dismissed");
		expect(later.messages.map((m) => m.type)).toEqual(["AUP_STATUS"]);
	});

	it("re-checks only when the notice id or version changes and survives a failed worker", async () => {
		const s = setup({ ok: true, notice: NOTICE, acknowledged: true });
		const policy = (acceptableUse: AcceptableUseNotice | null) =>
			({ acceptableUse }) as unknown as GuardPolicy;
		s.notice.policyChanged(policy(NOTICE));
		await vi.waitFor(() => expect(s.messages).toHaveLength(1));
		s.notice.policyChanged(policy(NOTICE));
		await Promise.resolve();
		expect(s.messages).toHaveLength(1);
		s.notice.policyChanged(policy({ ...NOTICE, version: 4 }));
		await vi.waitFor(() => expect(s.messages).toHaveLength(2));

		const broken = setup({ ok: false, error: "INTERNAL" });
		expect(await broken.notice.check()).toBe("failed");
		const failedAck = setup(
			{ ok: true, notice: NOTICE, acknowledged: false },
			{ ok: false, error: "INTERNAL" },
		);
		const outcome = failedAck.notice.check();
		await vi.waitFor(() => expect(dialog(failedAck.ui).hidden).toBe(false));
		button(failedAck.ui, "I understand").click();
		expect(await outcome).toBe("failed");
	});

	it("parses worker replies defensively", () => {
		expect(extractNotice(NOTICE)).toEqual(NOTICE);
		expect(extractNotice({ ...NOTICE, url: "javascript:alert(1)" })).toEqual({
			...NOTICE,
			url: undefined,
		});
		expect(extractNotice({ ...NOTICE, id: "bad id" })).toBeNull();
		expect(extractNotice({ ...NOTICE, version: 0 })).toBeNull();
		expect(noticeParagraphs("a\n\n\n b \n\nc")).toEqual(["a", "b", "c"]);
		expect(STRINGS.tr.aupAcknowledge).toBe("Anladım");
	});
});
