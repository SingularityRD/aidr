import { defineAdapter } from "./generic";

/** Gemini: Angular app with a Quill editor inside `<rich-textarea>`. */
export const gemini = defineAdapter({
	id: "gemini",
	label: "Gemini",
	hosts: ["gemini.google.com"],
	editor: [
		'rich-textarea .ql-editor[contenteditable="true"]',
		'rich-textarea [contenteditable="true"]',
		'div.ql-editor[contenteditable="true"][role="textbox"]',
		'.ql-editor[contenteditable="true"]',
		'textarea[aria-label*="prompt" i]',
	],
	send: ["button.send-button", ".send-button-container button", 'button[aria-label*="Send" i]'],
	response: [
		"message-content",
		".model-response-text",
		"model-response .markdown",
		"model-response",
	],
	userMessage: ["user-query", "user-query .query-text", ".user-query-bubble-with-background"],
	fileInput: ['input[type="file"]'],
});
