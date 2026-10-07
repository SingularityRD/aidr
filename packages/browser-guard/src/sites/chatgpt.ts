import { defineAdapter } from "./generic";

/** ChatGPT: ProseMirror composer `#prompt-textarea`; messages tagged with data-message-author-role. */
export const chatgpt = defineAdapter({
	id: "chatgpt",
	label: "ChatGPT",
	hosts: ["chatgpt.com", "chat.openai.com"],
	editor: [
		'#prompt-textarea[contenteditable="true"]',
		"#prompt-textarea",
		'form[data-type="unified-composer"] div.ProseMirror[contenteditable="true"]',
		'div.ProseMirror[contenteditable="true"]',
		'textarea[data-testid="prompt-textarea"]',
		'textarea[data-id="root"]',
		"form textarea",
	],
	send: [
		'button[data-testid="send-button"]',
		"#composer-submit-button",
		'form[data-type="unified-composer"] button[type="submit"]',
		'button[aria-label="Send prompt" i]',
	],
	response: [
		'[data-message-author-role="assistant"]',
		'article[data-testid^="conversation-turn-"] .markdown',
		".markdown.prose",
	],
	userMessage: [
		'[data-message-author-role="user"]',
		'article[data-testid^="conversation-turn-"] .whitespace-pre-wrap',
	],
	fileInput: ['form input[type="file"]', 'input[type="file"]'],
});
