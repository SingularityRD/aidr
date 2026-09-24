import { defineAdapter } from "./generic";

/** Perplexity: Lexical editor `#ask-input` (older builds: plain textarea). */
export const perplexity = defineAdapter({
	id: "perplexity",
	label: "Perplexity",
	hosts: ["www.perplexity.ai", "perplexity.ai"],
	editor: [
		'div#ask-input[contenteditable="true"]',
		"#ask-input",
		'div[contenteditable="true"][data-lexical-editor="true"]',
		"textarea[placeholder]",
	],
	send: [
		'button[data-testid="submit-button"]',
		'button[aria-label="Submit" i]',
		'button[aria-label*="Submit" i]',
		'button[aria-label*="Send" i]',
	],
	response: ['div[id^="markdown-content-"]', ".prose"],
	userMessage: ['h1[class*="group/query"]', 'div[class*="group/query"]'],
	fileInput: ['input[type="file"]'],
});
