import { defineAdapter } from "./generic";

/** Microsoft Copilot (consumer): React composer `textarea#userInput`. */
export const copilot = defineAdapter({
	id: "copilot",
	label: "Microsoft Copilot",
	hosts: ["copilot.microsoft.com"],
	editor: [
		"textarea#userInput",
		'textarea[data-testid="composer-input"]',
		"textarea[placeholder]",
		'[contenteditable="true"][role="textbox"]',
	],
	send: [
		'button[data-testid="submit-button"]',
		'button[aria-label*="Submit" i]',
		'button[aria-label*="Send" i]',
	],
	response: ['[data-content="ai-message"]', '[data-testid*="ai-message"]'],
	userMessage: ['[data-content="user-message"]', '[data-testid*="user-message"]'],
	fileInput: ['input[type="file"]'],
});
