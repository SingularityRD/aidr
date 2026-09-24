import { defineAdapter } from "./generic";

/**
 * Grok: TipTap/ProseMirror composer (textarea in older builds). Turns are
 * `div[id^="response-"]`; assistant turns align start, user turns align end.
 */
export const grok = defineAdapter({
	id: "grok",
	label: "Grok",
	hosts: ["grok.com"],
	editor: [
		'div.tiptap.ProseMirror[contenteditable="true"]',
		'div.ProseMirror[contenteditable="true"]',
		'textarea[aria-label*="Grok" i]',
		"form textarea",
	],
	send: [
		'form button[type="submit"]',
		'button[aria-label*="Submit" i]',
		'button[aria-label*="Send" i]',
	],
	response: [
		'div[id^="response-"].items-start .response-content-markdown',
		".response-content-markdown",
		'div[id^="response-"].items-start .message-bubble',
	],
	userMessage: ['div[id^="response-"].items-end .message-bubble'],
	fileInput: ['input[type="file"]'],
});
