import { M365_COPILOT_HOSTS } from "./frames";
import { defineAdapter } from "./generic";

/*
 * Hosts of Microsoft 365 Copilot Chat (the Entra ID, work-account Copilot), defined in
 * ./frames.ts. It runs at `m365.cloud.microsoft/chat` (where `www.microsoft365.com/chat` and
 * `www.office.com/chat` redirect) and on the dedicated `copilot.cloud.microsoft` host.
 * `m365.cloud.microsoft` also serves the rest of the Microsoft 365 web home; the guard runs
 * on the whole host (a content script cannot be scoped to a path that an SPA enters without
 * a page load), while blocking and Shadow AI counting are scoped to its `/chat` path (see
 * ./catalog.ts and background/dnr.ts).
 */

/**
 * Microsoft Copilot: the consumer product (`copilot.microsoft.com`, React composer
 * `textarea#userInput`) and Microsoft 365 Copilot Chat (Fluent UI composer, a
 * contenteditable `#m365-chat-editor-target-element`). Both share the site id `copilot`, so
 * `disabledSites` / `blockedSites` / telemetry treat them as one site; Shadow AI lists them
 * as two services (`copilot`, `m365-copilot`) so they can be sanctioned separately.
 *
 * The Microsoft 365 selectors come first: they are ids and test ids that only that composer
 * carries, while the consumer fallbacks (`textarea[placeholder]`) would also match other
 * fields on the Microsoft 365 home. The Copilot pane inside the Office web apps (Word, Excel,
 * PowerPoint, Outlook on the web) is rendered in a cross-origin iframe: on the Microsoft 365
 * Copilot hosts the guard also runs in subframes (./frames.ts), so that pane is guarded with
 * this adapter when it is served from one of those hosts. Which origin a live tenant uses for
 * the pane, and its markup, are unverified (BG-LIVE).
 */
export const copilot = defineAdapter({
	id: "copilot",
	label: "Microsoft Copilot",
	hosts: ["copilot.microsoft.com", ...M365_COPILOT_HOSTS],
	editor: [
		// Microsoft 365 Copilot Chat.
		"#m365-chat-editor-target-element",
		'[data-lexical-editor="true"][contenteditable="true"][role="textbox"]',
		// Consumer Copilot.
		"textarea#userInput",
		'textarea[data-testid="composer-input"]',
		"textarea[placeholder]",
		'[contenteditable="true"][role="textbox"]',
	],
	send: [
		// Microsoft 365 Copilot Chat (Fluent UI send button).
		"button.fai-SendButton",
		'button[data-testid="sendButton"]',
		// Consumer Copilot.
		'button[data-testid="submit-button"]',
		'button[aria-label*="Submit" i]',
		'button[aria-label*="Send" i]',
	],
	response: [
		'[data-testid="markdown-reply"]',
		'[data-testid="copilot-message-reply-div"]',
		'[data-content="ai-message"]',
		'[data-testid*="ai-message"]',
	],
	userMessage: [
		'[data-testid="chat-turn-user-message"]',
		'[data-content="user-message"]',
		'[data-testid*="user-message"]',
	],
	fileInput: ['input[type="file"]'],
});
