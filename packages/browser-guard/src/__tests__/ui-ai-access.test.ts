// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_POLICY } from "../background/policy";
import type { GuardMessage, GuardPolicy, SiteAccessStatus } from "../types";
import type { LocaleMessages, UiEnv } from "../ui/env";
import { formatMessage } from "../ui/i18n";
import { protectionStatus, siteForUrl } from "../ui/model";
import { startOptions } from "../ui/options-app";
import { blockedByShadowAi, blockedSiteFromUrl, renderBlocked } from "../ui/render-blocked";
import { usageTotals } from "../ui/render-options";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const EN: LocaleMessages = JSON.parse(
	readFileSync(join(ROOT, "_locales/en/messages.json"), "utf8"),
);
const NOW = Date.UTC(2026, 8, 24, 12, 0, 0);

const INTERNAL = {
	id: "corp-gpt",
	label: "Corp GPT",
	hosts: ["ai.internal.example"],
	editorSelectors: [],
	sendButtonSelectors: [],
	responseSelectors: [],
};

const POLICY: GuardPolicy = {
	...DEFAULT_POLICY,
	shadowAi: { mode: "block-unsanctioned", sanctioned: ["chatgpt", "claude"], blocked: [] },
	customSites: [INTERNAL],
	managedKeys: ["shadowAi", "customSites"],
};

function accessFor(granted: Set<string>): SiteAccessStatus {
	const origins = ["https://poe.com/*", "https://www.midjourney.com/*"];
	return {
		shadowAi: {
			mode: "block-unsanctioned",
			blocked: ["poe", "midjourney"],
			origins,
			missingOrigins: origins.filter((o) => !granted.has(o)),
			usage: [
				{ day: "2026-09-24", serviceId: "chatgpt", visited: 4, blocked: 0 },
				{ day: "2026-09-23", serviceId: "poe", visited: 0, blocked: 2 },
				{ day: "2026-09-01", serviceId: "gemini", visited: 9, blocked: 0 },
			],
		},
		customSites: [
			{
				id: "corp-gpt",
				label: "Corp GPT",
				hosts: ["ai.internal.example"],
				origins: ["https://ai.internal.example/*"],
				granted: granted.has("https://ai.internal.example/*"),
				active: granted.has("https://ai.internal.example/*"),
			},
		],
	};
}

function fakeEnv(policy: GuardPolicy) {
	const granted = new Set<string>();
	const requests: string[][] = [];
	const env: UiEnv & { requests: string[][]; sent: GuardMessage[] } = {
		requests,
		sent: [],
		async send(message) {
			env.sent.push(message);
			if (message.type === "GET_POLICY") return { ok: true, policy };
			if (message.type === "GET_STATS")
				return {
					ok: true,
					stats: {
						site: null,
						protectedPrompts: 0,
						maskedItems: 0,
						blockedSends: 0,
						byType: {},
						pausedUntil: null,
						nativeHost: "disabled",
					},
				};
			if (message.type === "GET_SITE_ACCESS") return { ok: true, access: accessFor(granted) };
			return { ok: false, error: "BAD_MESSAGE" };
		},
		async getActiveTab() {
			return null;
		},
		openOptionsPage() {},
		getVersion: () => "1.0.0",
		uiLanguage: () => "en-US",
		getMessage: (key, subs) => formatMessage(EN, key, subs),
		async loadLocaleMessages() {
			return EN;
		},
		async sessionGet() {
			return undefined;
		},
		async sessionSet() {},
		onInvalidate() {},
		now: () => NOW,
		requestOrigins(origins) {
			// Recorded synchronously: browsers only prompt inside the click.
			requests.push([...origins]);
			for (const origin of origins) granted.add(origin);
			return Promise.resolve(true);
		},
	};
	return env;
}

function mount() {
	document.body.innerHTML = '<main id="app"></main><div id="live" role="status"></div>';
	return {
		app: document.getElementById("app") as HTMLElement,
		live: document.getElementById("live") as HTMLElement,
	};
}

const text = (selector: string) => document.querySelector(selector)?.textContent?.trim() ?? "";
const settle = async () => {
	for (let i = 0; i < 5; i++) await new Promise((resolve) => setTimeout(resolve, 0));
};

beforeEach(() => {
	document.body.innerHTML = "";
});

describe("options: AI services section", () => {
	it("is hidden (section and table of contents) without Shadow AI or custom sites", async () => {
		const env = fakeEnv(DEFAULT_POLICY);
		await startOptions(document, env, mount()).ready;
		expect(document.getElementById("ai-access")).toBeNull();
		expect(document.querySelector('a[href="#ai-access"]')).toBeNull();
		expect(env.sent.some((m) => m.type === "GET_SITE_ACCESS")).toBe(false);
	});

	it("shows the managed Shadow AI policy, local usage and the access state", async () => {
		const env = fakeEnv(POLICY);
		await startOptions(document, env, mount()).ready;
		expect(document.querySelector('a[href="#ai-access"]')).not.toBeNull();
		expect(text("#shadow-mode")).toMatch(/Only AI services your organization approved/);
		expect(text("#shadow-sanctioned")).toBe("Approved: ChatGPT, Claude");
		expect(text("#shadow-blocked")).toBe("AI services blocked by your organization: 2");
		expect(text("#shadow-access")).toMatch(/access 2 AI service addresses/);
		const rows = [...document.querySelectorAll("#shadow-usage tbody tr")].map((row) =>
			[...row.querySelectorAll("td")].map((cell) => cell.textContent),
		);
		// The 1 September row is outside the 7-day window.
		expect(rows).toEqual([
			["ChatGPT", "4", "0"],
			["Poe", "0", "2"],
		]);
		expect(text("#custom-site-corp-gpt")).toMatch(/Corp GPT.*ai\.internal\.example.*Needs access/);
	});

	it("requests exactly the missing origins from the click and re-reads the status", async () => {
		const env = fakeEnv(POLICY);
		await startOptions(document, env, mount()).ready;
		(document.getElementById("shadow-grant") as HTMLButtonElement).click();
		expect(env.requests).toEqual([["https://poe.com/*", "https://www.midjourney.com/*"]]);
		await settle();
		expect(text("#shadow-access")).toMatch(/Access granted/);
		expect(document.getElementById("shadow-grant")).toBeNull();

		(document.getElementById("custom-grant-corp-gpt") as HTMLButtonElement).click();
		expect(env.requests[1]).toEqual(["https://ai.internal.example/*"]);
		await settle();
		expect(text("#custom-site-corp-gpt")).toMatch(/Protected/);
		expect(text("#live")).toBe("Access granted.");
	});
});

describe("usageTotals", () => {
	it("sums the window per service, busiest first", () => {
		expect(
			usageTotals(
				[
					{ day: "2026-09-24", serviceId: "poe", visited: 1, blocked: 0 },
					{ day: "2026-09-20", serviceId: "poe", visited: 2, blocked: 1 },
					{ day: "2026-09-24", serviceId: "claude", visited: 5, blocked: 0 },
					{ day: "2026-09-17", serviceId: "claude", visited: 50, blocked: 0 },
				],
				NOW,
			),
		).toEqual([
			{ serviceId: "claude", visited: 5, blocked: 0 },
			{ serviceId: "poe", visited: 3, blocked: 1 },
		]);
	});
});

describe("blocked page for Shadow AI", () => {
	it("names a catalogued service and explains the organisation decision", () => {
		document.body.innerHTML = `
			<h1 id="blocked-title">x</h1>
			<p id="blocked-detail">x</p>`;
		const href = "chrome-extension://id/blocked.html?service=midjourney";
		expect(blockedSiteFromUrl(href)).toBe("Midjourney");
		expect(blockedByShadowAi(href)).toBe(true);
		renderBlocked(
			document,
			(key, subs) => formatMessage(EN, key, subs),
			blockedSiteFromUrl(href),
			true,
		);
		expect(text("#blocked-title")).toBe("Midjourney is blocked by your organization");
		expect(text("#blocked-detail")).toMatch(/has not approved this AI service/);
		expect(blockedSiteFromUrl("chrome-extension://id/blocked.html?service=<b>x</b>")).toBeNull();
		expect(blockedByShadowAi("chrome-extension://id/blocked.html?site=gemini")).toBe(false);
	});
});

describe("popup: custom sites", () => {
	it("reports a configured internal site as protected", () => {
		const site = siteForUrl("https://ai.internal.example/chat", [INTERNAL]);
		expect(site).toBe("custom");
		expect(siteForUrl("https://ai.internal.example/chat")).toBeNull();
		const stats = {
			site: null,
			protectedPrompts: 0,
			maskedItems: 0,
			blockedSends: 0,
			byType: {},
			pausedUntil: null,
			nativeHost: "disabled" as const,
		};
		expect(protectionStatus(POLICY, stats, site, NOW)).toEqual({
			kind: "protected",
			site: "custom",
		});
	});
});
