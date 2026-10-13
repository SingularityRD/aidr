// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import {
	ADAPTERS,
	adapterById,
	adapterForUrl,
	GENERIC_ADAPTER,
	MATCH_PATTERNS,
	SITE_IDS,
} from "../sites/index";
import type { SiteAdapter, SiteId } from "../types";

const EXPECTED_HOSTS: Readonly<Record<Exclude<SiteId, "other" | "custom">, readonly string[]>> = {
	chatgpt: ["chatgpt.com", "chat.openai.com"],
	gemini: ["gemini.google.com"],
	claude: ["claude.ai"],
	copilot: ["copilot.microsoft.com", "m365.cloud.microsoft", "copilot.cloud.microsoft"],
	perplexity: ["www.perplexity.ai", "perplexity.ai"],
	deepseek: ["chat.deepseek.com"],
	mistral: ["chat.mistral.ai"],
	grok: ["grok.com"],
};

const SELECTOR_KEYS = [
	"editorSelectors",
	"sendButtonSelectors",
	"responseSelectors",
	"userMessageSelectors",
	"fileInputSelectors",
] as const;

const ALL_ADAPTERS: readonly SiteAdapter[] = [...ADAPTERS, GENERIC_ADAPTER];

describe("adapterForUrl", () => {
	for (const [id, hosts] of Object.entries(EXPECTED_HOSTS)) {
		for (const host of hosts) {
			it(`resolves https://${host} to ${id}`, () => {
				expect(adapterForUrl(`https://${host}/`).id).toBe(id);
				expect(adapterForUrl(`https://${host}/c/abc?model=x#frag`).id).toBe(id);
			});
		}
	}

	it("is case-insensitive on the host (URL normalisation)", () => {
		expect(adapterForUrl("https://ChatGPT.com/").id).toBe("chatgpt");
		expect(adapterForUrl("HTTPS://CLAUDE.AI/new").id).toBe("claude");
	});

	it("treats the explicit default port as the same origin", () => {
		// new URL() drops :443 for https, so this is the identical origin.
		expect(adapterForUrl("https://claude.ai:443/").id).toBe("claude");
	});

	const negatives = [
		// lookalikes / suffix and prefix tricks
		"https://chatgpt.com.evil.com/",
		"https://evil.com/chatgpt.com",
		"https://evilchatgpt.com/",
		"https://xchatgpt.com/",
		"https://sub.chatgpt.com/",
		"https://api.openai.com/",
		"https://openai.com/",
		"https://google.com/",
		"https://bard.google.com/",
		"https://gemini.google.com.attacker.net/",
		"https://claude.ai.evil.io/",
		"https://fakeclaude.ai/",
		"https://copilot.microsoft.com.evil.com/",
		"https://m365.cloud.microsoft.evil.com/chat",
		"https://evil.m365.cloud.microsoft/chat",
		"https://cloud.microsoft/chat",
		"https://www.office.com/chat",
		"https://github.com/features/copilot",
		"https://evil-perplexity.ai/",
		"https://labs.perplexity.ai/",
		"https://deepseek.com/",
		"https://chat.deepseek.com.cn/",
		"https://mistral.ai/",
		"https://x.com/i/grok",
		"https://grok.com.evil.com/",
		"https://chatgpt.com./",
		"https://chatgpt.co/",
		// homoglyph (Cyrillic "о") becomes punycode
		"https://chatgpt.cоm/",
		// wrong scheme
		"http://chatgpt.com/",
		"http://claude.ai/",
		"ws://chatgpt.com/",
		"file:///chatgpt.com/",
		"javascript:alert(1)//chatgpt.com",
		"data:text/html,chatgpt.com",
		// explicit non-default ports
		"https://chatgpt.com:8443/",
		"https://claude.ai:444/",
		"https://chatgpt.com:80/",
		// userinfo
		"https://user@chatgpt.com/",
		"https://user:pass@claude.ai/",
		"https://chatgpt.com@evil.com/",
		"https://:pw@gemini.google.com/",
		// garbage
		"",
		"chatgpt.com",
		"//chatgpt.com/",
		"not a url",
		`https://chatgpt.com/${"a".repeat(9000)}`,
	];
	for (const url of negatives) {
		it(`falls back to the generic adapter for ${JSON.stringify(url.slice(0, 60))}`, () => {
			expect(adapterForUrl(url)).toBe(GENERIC_ADAPTER);
			expect(adapterForUrl(url).id).toBe("other");
		});
	}

	it("returns the generic adapter for non-string input", () => {
		for (const bad of [undefined, null, 42, {}, ["https://chatgpt.com/"]]) {
			expect(adapterForUrl(bad as unknown as string)).toBe(GENERIC_ADAPTER);
		}
	});
});

describe("ADAPTERS", () => {
	it("covers exactly the supported sites with the expected hosts", () => {
		expect(ADAPTERS.map((a) => a.id).sort()).toEqual(Object.keys(EXPECTED_HOSTS).sort());
		for (const adapter of ADAPTERS) {
			expect(adapter.hosts).toEqual(EXPECTED_HOSTS[adapter.id as Exclude<SiteId, "other">]);
			expect(adapter.label.length).toBeGreaterThan(0);
		}
	});

	it("never assigns a host to more than one adapter", () => {
		const hosts = ADAPTERS.flatMap((a) => a.hosts);
		expect(new Set(hosts).size).toBe(hosts.length);
	});

	it("lists only lowercase bare hostnames", () => {
		for (const host of ADAPTERS.flatMap((a) => a.hosts)) {
			expect(host).toMatch(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/);
			expect(new URL(`https://${host}/`).hostname).toBe(host);
		}
	});

	it("exposes a generic adapter with id 'other' and no hosts", () => {
		expect(GENERIC_ADAPTER.id).toBe("other");
		expect(GENERIC_ADAPTER.hosts).toEqual([]);
		expect(GENERIC_ADAPTER.editorSelectors).toEqual([
			"textarea",
			'[contenteditable="true"]',
			'[role="textbox"]',
		]);
		expect(GENERIC_ADAPTER.sendButtonSelectors).toEqual([
			'button[type="submit"]',
			'button[aria-label*="send" i]',
		]);
		expect(GENERIC_ADAPTER.responseSelectors).toEqual([
			'[data-message-author-role="assistant"]',
			"article",
			".markdown",
			".prose",
		]);
	});

	for (const adapter of ALL_ADAPTERS) {
		describe(adapter.id, () => {
			for (const key of SELECTOR_KEYS) {
				it(`${key} is a non-empty list of unique, valid CSS selectors`, () => {
					const list = adapter[key];
					expect(list.length).toBeGreaterThan(0);
					expect(new Set(list).size).toBe(list.length);
					for (const selector of list) {
						expect(selector.trim()).toBe(selector);
						expect(selector.length).toBeGreaterThan(0);
						let error: unknown = null;
						try {
							document.querySelector(selector);
							document.createElement("div").matches(selector);
						} catch (e) {
							error = e;
						}
						expect(error, `invalid selector ${selector}`).toBeNull();
					}
				});
			}

			it("includes every generic fallback, after the site-specific selectors", () => {
				for (const key of SELECTOR_KEYS) {
					const list = adapter[key];
					const generic = GENERIC_ADAPTER[key];
					for (const selector of generic) expect(list).toContain(selector);
				}
				if (adapter !== GENERIC_ADAPTER) {
					// The broadest editor/send selectors must never outrank the site's own.
					expect(GENERIC_ADAPTER.editorSelectors).not.toContain(adapter.editorSelectors[0]);
					expect(GENERIC_ADAPTER.sendButtonSelectors).not.toContain(adapter.sendButtonSelectors[0]);
					expect(adapter.editorSelectors.at(-1)).toBe(GENERIC_ADAPTER.editorSelectors.at(-1));
					expect(adapter.sendButtonSelectors.at(-1)).toBe(
						GENERIC_ADAPTER.sendButtonSelectors.at(-1),
					);
				}
			});

			it("is immutable", () => {
				expect(Object.isFrozen(adapter)).toBe(true);
				for (const key of SELECTOR_KEYS) expect(Object.isFrozen(adapter[key])).toBe(true);
				expect(Object.isFrozen(adapter.hosts)).toBe(true);
			});
		});
	}
});

describe("selectors against representative markup", () => {
	function firstMatch(selectors: readonly string[], html: string): Element | null {
		document.body.innerHTML = html;
		for (const s of selectors) {
			const el = document.querySelector(s);
			if (el) return el;
		}
		return null;
	}

	it("ChatGPT prefers the ProseMirror composer over the hidden fallback textarea", () => {
		const chatgpt = adapterById("chatgpt");
		const el = firstMatch(
			chatgpt.editorSelectors,
			`<form data-type="unified-composer"><textarea class="_fallbackTextarea"></textarea>
			 <div id="prompt-textarea" class="ProseMirror" contenteditable="true"></div>
			 <button id="composer-submit-button" data-testid="send-button"></button></form>`,
		);
		expect(el?.id).toBe("prompt-textarea");
		expect(firstMatch(chatgpt.sendButtonSelectors, document.body.innerHTML)?.id).toBe(
			"composer-submit-button",
		);
	});

	it("Gemini finds the Quill editor inside rich-textarea", () => {
		const gemini = adapterById("gemini");
		const el = firstMatch(
			gemini.editorSelectors,
			`<textarea id="other"></textarea><rich-textarea><div class="ql-editor" contenteditable="true" role="textbox" id="q"></div></rich-textarea>`,
		);
		expect(el?.id).toBe("q");
	});

	it("aria-label send selectors are case-insensitive", () => {
		const claude = adapterById("claude");
		const el = firstMatch(
			claude.sendButtonSelectors,
			`<button aria-label="SEND MESSAGE" id="s"></button>`,
		);
		expect(el?.id).toBe("s");
	});

	it("Perplexity prefers the Lexical #ask-input", () => {
		const el = firstMatch(
			adapterById("perplexity").editorSelectors,
			`<textarea placeholder="x"></textarea><div id="ask-input" contenteditable="true" data-lexical-editor="true"></div>`,
		);
		expect(el?.id).toBe("ask-input");
	});

	it("Microsoft 365 Copilot Chat: its composer, send button and turns outrank other fields (BG-10)", () => {
		const copilot = adapterById("copilot");
		// The Microsoft 365 home also has a search textarea with a placeholder; the
		// consumer fallback `textarea[placeholder]` must not win over the chat composer.
		const html = `<textarea id="search" placeholder="Search"></textarea>
			<div data-testid="chat-turn-user-message" id="u">hi</div>
			<div data-testid="markdown-reply" id="a">answer</div>
			<span id="m365-chat-editor-target-element" contenteditable="true" role="textbox" data-lexical-editor="true"></span>
			<button class="fai-SendButton" aria-label="Send" id="send"></button>
			<button type="submit" id="search-go"></button>`;
		expect(firstMatch(copilot.editorSelectors, html)?.id).toBe("m365-chat-editor-target-element");
		expect(firstMatch(copilot.sendButtonSelectors, html)?.id).toBe("send");
		expect(firstMatch(copilot.responseSelectors, html)?.id).toBe("a");
		expect(firstMatch(copilot.userMessageSelectors, html)?.id).toBe("u");
		for (const url of [
			"https://m365.cloud.microsoft/chat",
			"https://m365.cloud.microsoft/chat/?auth=2",
			"https://copilot.cloud.microsoft/",
		])
			expect(adapterForUrl(url)).toBe(copilot);
	});

	it("consumer Copilot keeps its own composer", () => {
		const copilot = adapterById("copilot");
		const html = `<textarea id="userInput" placeholder="Message Copilot"></textarea>
			<button data-testid="submit-button" id="s"></button>`;
		expect(firstMatch(copilot.editorSelectors, html)?.id).toBe("userInput");
		expect(firstMatch(copilot.sendButtonSelectors, html)?.id).toBe("s");
	});

	it("Grok separates assistant and user turns", () => {
		const grok = adapterById("grok");
		const html = `<div id="response-1" class="items-end"><div class="message-bubble" id="u"></div></div>
			<div id="response-2" class="items-start"><div class="message-bubble"><div class="response-content-markdown" id="a"></div></div></div>`;
		expect(firstMatch(grok.responseSelectors, html)?.id).toBe("a");
		expect(firstMatch(grok.userMessageSelectors, html)?.id).toBe("u");
	});
});

describe("SITE_IDS / MATCH_PATTERNS / adapterById", () => {
	it("SITE_IDS lists every adapter id, then 'custom', then 'other' last", () => {
		expect(SITE_IDS).toEqual([...ADAPTERS.map((a) => a.id), "custom", "other"]);
		expect(new Set(SITE_IDS).size).toBe(SITE_IDS.length);
	});

	it("MATCH_PATTERNS cover every host with an exact https pattern", () => {
		const hosts = ADAPTERS.flatMap((a) => a.hosts);
		expect(MATCH_PATTERNS).toHaveLength(hosts.length);
		for (const host of hosts) expect(MATCH_PATTERNS).toContain(`https://${host}/*`);
		for (const pattern of MATCH_PATTERNS) {
			expect(pattern).toMatch(/^https:\/\/[a-z0-9.-]+\/\*$/);
			expect(pattern).not.toContain("*.");
			expect(adapterForUrl(pattern.replace("/*", "/")).id).not.toBe("other");
		}
	});

	it("adapterById maps ids to adapters and 'other' to the generic adapter", () => {
		for (const adapter of ADAPTERS) expect(adapterById(adapter.id)).toBe(adapter);
		expect(adapterById("other")).toBe(GENERIC_ADAPTER);
	});
});
