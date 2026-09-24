import { defineAdapter } from "./generic";

/** Mistral Le Chat: ProseMirror composer in recent builds, textarea in older ones. */
export const mistral = defineAdapter({
	id: "mistral",
	label: "Mistral Le Chat",
	hosts: ["chat.mistral.ai"],
	editor: [
		'form div.ProseMirror[contenteditable="true"]',
		'div.ProseMirror[contenteditable="true"]',
		'textarea[name="message.text"]',
		"form textarea",
	],
	send: [
		'button[aria-label="Send question" i]',
		'form button[type="submit"]',
		'button[aria-label*="Send" i]',
	],
	response: [
		'[data-message-author-role="assistant"]',
		'[data-message-part-type="answer"]',
		".markdown-container-style",
	],
	userMessage: ['[data-message-author-role="user"]'],
	fileInput: ['form input[type="file"]', 'input[type="file"]'],
});
