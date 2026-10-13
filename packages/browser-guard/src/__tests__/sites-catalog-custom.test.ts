// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { bootContentGuard, type RuntimeLike } from "../content/boot";
import { editorAccess, findSendButton, isSyntheticEditorEvent } from "../dom/editor";
import { createVault } from "../engine/vault";
import {
	AI_SERVICE_CATEGORIES,
	AI_SERVICE_ID_PATTERN,
	AI_SERVICE_IDS,
	AI_SERVICES,
	type AiService,
	isAiServiceId,
	serviceById,
	serviceForHost,
	serviceForUrl,
	serviceOrigins,
} from "../sites/catalog";
import { customAdapter, isUsableSelector } from "../sites/custom";
import { ADAPTERS, adapterForUrl, GENERIC_ADAPTER } from "../sites/index";
import type { CustomSiteConfig, GuardMessage, GuardPolicy } from "../types";
import { BASE_POLICY, EMAIL, fakeEngine } from "./content-helpers";

const HOSTNAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

const INTERNAL: CustomSiteConfig = {
	id: "corp-gpt",
	label: "Corp GPT",
	hosts: ["ai.internal.example"],
	editorSelectors: ["#composer"],
	sendButtonSelectors: [".corp-send"],
	responseSelectors: [".corp-answer"],
};

describe("Shadow AI catalog", () => {
	it("lists about sixty services with unique, well-formed ids and hosts", () => {
		expect(AI_SERVICES.length).toBeGreaterThanOrEqual(60);
		expect(new Set(AI_SERVICE_IDS).size).toBe(AI_SERVICE_IDS.length);
		const hosts = AI_SERVICES.flatMap((s) => s.hosts);
		expect(new Set(hosts).size).toBe(hosts.length);
		for (const service of AI_SERVICES) {
			expect(service.id).toMatch(AI_SERVICE_ID_PATTERN);
			expect(AI_SERVICE_CATEGORIES).toContain(service.category);
			expect(service.name.trim().length).toBeGreaterThan(0);
			expect(service.hosts.length).toBeGreaterThan(0);
			for (const host of service.hosts) expect(host).toMatch(HOSTNAME);
			expect(Object.isFrozen(service)).toBe(true);
		}
		for (const category of AI_SERVICE_CATEGORIES)
			expect(AI_SERVICES.some((s) => s.category === category)).toBe(true);
	});

	it("uses the built-in site ids and hosts for the protected sites", () => {
		for (const adapter of ADAPTERS) {
			if (adapter.id === "copilot") continue;
			expect(serviceById(adapter.id)?.hosts).toEqual(adapter.hosts);
		}
		// Copilot is one protected site but two Shadow AI services (consumer + Microsoft 365).
		const m365 = serviceById("m365-copilot") as AiService;
		expect([
			...(serviceById("copilot")?.hosts ?? []),
			...m365.paths.map((p) => p.host),
			...m365.hosts,
		]).toEqual(adapterForUrl("https://copilot.microsoft.com/").hosts);
	});

	it("catalogs Microsoft 365 Copilot Chat by host and by its /chat path only (BG-10)", () => {
		expect(serviceById("m365-copilot")?.category).toBe("chat");
		for (const url of [
			"https://m365.cloud.microsoft/chat",
			"https://m365.cloud.microsoft/chat/",
			"https://m365.cloud.microsoft/chat?auth=2&origindomain=microsoft365",
			"https://copilot.cloud.microsoft/",
			"https://copilot.cloud.microsoft/en-us/chat",
		])
			expect(serviceForUrl(url)?.id).toBe("m365-copilot");
		// The rest of the Microsoft 365 home is not an AI service.
		for (const url of [
			"https://m365.cloud.microsoft/",
			"https://m365.cloud.microsoft/apps",
			"https://m365.cloud.microsoft/chatter",
			"https://m365.cloud.microsoft.evil.test/chat",
			"https://x.m365.cloud.microsoft/chat",
		])
			expect(serviceForUrl(url)).toBeNull();
		expect(serviceForHost("m365.cloud.microsoft")).toBeNull();
		expect(serviceForUrl("https://copilot.microsoft.com/")?.id).toBe("copilot");
		expect(serviceOrigins([serviceById("m365-copilot") as AiService])).toEqual([
			"https://copilot.cloud.microsoft/*",
			"https://m365.cloud.microsoft/*",
		]);
	});

	it("never lists a host that is only a path of a general-purpose product", () => {
		for (const host of ["github.com", "notion.so", "www.bing.com", "www.google.com", "google.com"])
			expect(serviceForHost(host)).toBeNull();
	});

	it("matches exact hosts, then the longest parent host", () => {
		expect(serviceForUrl("https://poe.com/chat/x")?.id).toBe("poe");
		expect(serviceForUrl("http://www.midjourney.com/")?.id).toBe("midjourney");
		expect(serviceForUrl("https://cdn.app.leonardo.ai/")?.id).toBe("leonardo");
		expect(serviceForUrl("https://notebooklm.google.com/")?.id).toBe("notebooklm");
		expect(serviceForUrl("https://CHAT.QWEN.AI/")?.id).toBe("qwen");
		for (const url of [
			"https://poe.com.evil.test/",
			"https://notpoe.com/",
			"file:///poe.com",
			"chrome://poe.com/",
			"not a url",
			42,
			`https://poe.com/${"a".repeat(9000)}`,
		])
			expect(serviceForUrl(url)).toBeNull();
		expect(isAiServiceId("poe")).toBe(true);
		expect(isAiServiceId("nope")).toBe(false);
	});

	it("builds exact https host-permission origins", () => {
		expect(serviceOrigins([serviceById("perplexity") as AiService])).toEqual([
			"https://www.perplexity.ai/*",
			"https://perplexity.ai/*",
		]);
	});
});

describe("custom site adapters", () => {
	it("resolves a configured host to an adapter with id 'custom'", () => {
		const adapter = adapterForUrl("https://ai.internal.example/chat/1", [INTERNAL]);
		expect(adapter.id).toBe("custom");
		expect(adapter.label).toBe("Corp GPT");
		expect(adapter.editorSelectors[0]).toBe("#composer");
		expect(adapter.sendButtonSelectors[0]).toBe(".corp-send");
		expect(adapter.responseSelectors[0]).toBe(".corp-answer");
		// Generic fallbacks follow the configured selectors.
		expect(adapter.editorSelectors).toContain("textarea");
		expect(adapter.sendButtonSelectors).toContain('button[type="submit"]');
	});

	it("keeps built-in sites and rejects near misses", () => {
		const sites = [{ ...INTERNAL, hosts: ["ai.internal.example", "chatgpt.com"] }];
		expect(adapterForUrl("https://chatgpt.com/", sites).id).toBe("chatgpt");
		for (const url of [
			"http://ai.internal.example/",
			"https://ai.internal.example:8443/",
			"https://x.ai.internal.example/",
			"https://u:p@ai.internal.example/",
		])
			expect(adapterForUrl(url, sites)).toBe(GENERIC_ADAPTER);
		expect(adapterForUrl("https://ai.internal.example/")).toBe(GENERIC_ADAPTER);
	});

	it("drops selectors the DOM cannot parse", () => {
		expect(isUsableSelector("div.answer > p")).toBe(true);
		for (const bad of ["div[", "a{color:red}", "", "   ", "x".repeat(257), 7])
			expect(isUsableSelector(bad)).toBe(false);
		const adapter = customAdapter({ ...INTERNAL, editorSelectors: ["div[", "#composer"] });
		expect(adapter.editorSelectors[0]).toBe("#composer");
		expect(adapter.editorSelectors).not.toContain("div[");
	});
});

describe("content boot on a custom site", () => {
	const booted: { guard: { stop(): void } }[] = [];
	afterEach(() => {
		for (const b of booted.splice(0)) b.guard.stop();
		document.body.innerHTML = "";
	});

	function runtimeWith(policy: GuardPolicy): RuntimeLike & { sent: GuardMessage[] } {
		const sent: GuardMessage[] = [];
		return {
			id: "ext-id",
			sent,
			sendMessage: vi.fn(async (message: GuardMessage) => {
				sent.push(message);
				return message.type === "GET_POLICY" ? { ok: true, policy } : { ok: true };
			}),
			onMessage: { addListener: () => undefined },
		};
	}

	it("resolves the custom adapter from the policy and intercepts its own send button", async () => {
		document.body.innerHTML = `
			<textarea id="composer"></textarea>
			<div class="corp-send" role="button" tabindex="0">Go</div>
			<div class="thread"></div>`;
		const composer = document.getElementById("composer") as HTMLTextAreaElement;
		const sendButton = document.querySelector(".corp-send") as HTMLElement;
		const delivered: string[] = [];
		sendButton.addEventListener("click", () => delivered.push(composer.value));

		const runtime = runtimeWith({ ...BASE_POLICY, customSites: [INTERNAL] });
		const result = bootContentGuard({
			window,
			document,
			url: "https://ai.internal.example/chat",
			runtime,
			adapterForUrl,
			createDetectionEngine: () => fakeEngine(),
			createVault,
			vaultTag: "t3st",
			findEditor: (adapter, root) => {
				const el = root.querySelector<HTMLElement>(adapter.editorSelectors[0] ?? "textarea");
				return el ? editorAccess(el) : null;
			},
			findSendButton: (adapter, root, editor) =>
				findSendButton(adapter, root, editor, { isVisible: () => true }),
			isSyntheticEvent: isSyntheticEditorEvent,
			sanitizeFile: async () => ({ action: "allow", counts: {}, reasons: [] }),
			coachingFor: (code) => code,
			sleep: async () => undefined,
		});
		booted.push(result);
		await result.ready;

		composer.value = `please mail ${EMAIL}`;
		sendButton.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
		await expect.poll(() => delivered).toEqual(["please mail [EMAIL_1_t3st]"]);
		const records = runtime.sent.filter((m) => m.type === "RECORD");
		expect(records).toEqual([
			{ type: "RECORD", site: "custom", action: "masked", channel: "prompt", counts: { EMAIL: 1 } },
		]);
	});
});
