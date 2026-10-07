import { defineAdapter } from "./generic";

/** Claude: ProseMirror composer; assistant turns carry data-is-streaming. */
export const claude = defineAdapter({
	id: "claude",
	label: "Claude",
	hosts: ["claude.ai"],
	editor: [
		'[data-testid="chat-input"][contenteditable="true"]',
		'div.ProseMirror[contenteditable="true"]',
		'[data-testid="chat-input"]',
		'fieldset [contenteditable="true"]',
		'[contenteditable="true"][data-placeholder]',
		'textarea[data-testid="chat-input-ssr"]',
	],
	send: [
		'button[aria-label="Send message" i]',
		'fieldset button[type="submit"]',
		'button[aria-label*="Send" i]',
	],
	response: [
		".font-claude-message",
		'[data-testid="assistant-message"]',
		".font-claude-response",
		"div[data-is-streaming]",
	],
	userMessage: ['[data-testid="user-message"]', ".font-user-message"],
	fileInput: [
		'input[data-testid="file-upload"]',
		'fieldset input[type="file"]',
		'input[type="file"]',
	],
});
