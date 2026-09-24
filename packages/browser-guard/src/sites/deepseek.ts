import { defineAdapter } from "./generic";

/**
 * DeepSeek: plain `textarea#chat-input`. The send control is a hashed-class
 * `div[role="button"]`, so selectors rely on roles/labels plus Enter-key capture.
 */
export const deepseek = defineAdapter({
	id: "deepseek",
	label: "DeepSeek",
	hosts: ["chat.deepseek.com"],
	editor: ["textarea#chat-input", "textarea[placeholder]"],
	send: ['div[role="button"][aria-label*="Send" i]', 'button[aria-label*="Send" i]'],
	response: [".ds-markdown", ".ds-markdown--block"],
	userMessage: ['[data-role="user"]'],
	fileInput: ['input[type="file"]'],
});
