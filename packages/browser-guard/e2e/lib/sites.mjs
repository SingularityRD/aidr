// Simulated AI chat sites. Each entry maps a real product origin (intercepted
// with context.route, never contacted) to a local fixture page, plus the
// selectors the scenarios use to drive it. Selectors mirror the fixture markup,
// which in turn mirrors the product DOM targeted by src/sites/*.ts.

export const SITES = {
	chatgpt: {
		siteId: "chatgpt",
		origin: "https://chatgpt.com",
		path: "/",
		fixture: "chatgpt.html",
		kind: "prosemirror",
		editor: "#prompt-textarea",
		send: 'button[data-testid="send-button"]',
		response: '[data-message-author-role="assistant"]',
		endpoint: "/backend-api/conversation",
		fileInput: "#upload",
	},
	gemini: {
		siteId: "gemini",
		origin: "https://gemini.google.com",
		path: "/app",
		fixture: "gemini.html",
		// Google multi-login paths (/u/<n>/app), each signed in with another account
		// (scenarios/work-accounts.mjs).
		pathFixtures: {
			"/u/1/app": "gemini-account-workspace.html",
			"/u/2/app": "gemini-account-personal.html",
		},
		kind: "quill",
		editor: "rich-textarea .ql-editor",
		send: "button.send-button",
		response: "message-content",
		endpoint: "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate",
		fileInput: "#gemini-upload",
	},
	claude: {
		siteId: "claude",
		origin: "https://claude.ai",
		path: "/new",
		fixture: "claude.html",
		kind: "prosemirror",
		editor: 'div.ProseMirror[contenteditable="true"]',
		send: 'button[aria-label="Send message"]',
		response: ".font-claude-message",
		endpoint: "/api/organizations/fixture-org/chat_conversations/fixture-conv/completion",
		fileInput: 'input[data-testid="file-upload"]',
	},
	copilot: {
		siteId: "copilot",
		origin: "https://copilot.microsoft.com",
		path: "/",
		fixture: "copilot.html",
		kind: "textarea",
		editor: "textarea#userInput",
		send: 'button[data-testid="submit-button"]',
		response: '[data-content="ai-message"]',
		endpoint: "/c/api/chat",
		fileInput: "#copilot-upload",
	},
	perplexity: {
		siteId: "perplexity",
		origin: "https://www.perplexity.ai",
		path: "/",
		fixture: "perplexity.html",
		kind: "textarea",
		editor: "textarea[placeholder]",
		send: 'button[data-testid="submit-button"]',
		response: 'div[id^="markdown-content-"]',
		endpoint: "/rest/sse/perplexity_ask",
		fileInput: "#pplx-upload",
	},
	deepseek: {
		siteId: "deepseek",
		origin: "https://chat.deepseek.com",
		path: "/",
		fixture: "deepseek.html",
		kind: "textarea",
		editor: "textarea#chat-input",
		// A div with role=button, not a <button> (src/sites/deepseek.ts).
		send: 'div[role="button"][aria-label="Send"]',
		response: ".ds-markdown",
		endpoint: "/api/v0/chat/completion",
		fileInput: "#ds-upload",
	},
	mistral: {
		siteId: "mistral",
		origin: "https://chat.mistral.ai",
		path: "/chat",
		fixture: "mistral.html",
		kind: "prosemirror",
		editor: 'form div.ProseMirror[contenteditable="true"]',
		send: 'button[aria-label="Send question"]',
		response: '[data-message-author-role="assistant"]',
		endpoint: "/api/chat",
		fileInput: "#mistral-upload",
	},
	grok: {
		siteId: "grok",
		origin: "https://grok.com",
		path: "/",
		fixture: "grok.html",
		kind: "prosemirror",
		editor: 'div.tiptap.ProseMirror[contenteditable="true"]',
		send: 'form button[type="submit"]',
		response: 'div[id^="response-"].items-start .response-content-markdown',
		endpoint: "/rest/app-chat/conversations/new",
		fileInput: "#grok-upload",
	},
	generic: {
		siteId: "other",
		origin: "https://example.org",
		path: "/chat",
		fixture: "generic.html",
		kind: "textarea",
		editor: "#ask textarea",
		send: '#ask button[type="submit"]',
		response: "#log article",
		endpoint: "/api/chat",
		fileInput: "#generic-upload",
	},
};

/**
 * Company-internal AI portal configured through the managed `customSites` policy
 * (scenarios/managed-ai-sites.mjs); not a built-in site, so the manifest's static
 * content scripts never run there.
 */
SITES.internal = {
	siteId: "custom",
	origin: "https://ai.internal.example",
	path: "/chat",
	fixture: "internal.html",
	kind: "textarea",
	editor: "#corp-composer",
	send: ".corp-send",
	response: ".corp-answer",
	endpoint: "/api/v1/generate",
};

/**
 * A catalogued Shadow AI service outside the protected sites. Served by the generic
 * fixture so that, if the product's block rule did not act, the page would load.
 */
SITES.poe = {
	siteId: "other",
	origin: "https://poe.com",
	path: "/",
	fixture: "generic.html",
	kind: "textarea",
	editor: "#ask textarea",
	send: '#ask button[type="submit"]',
	response: "#log article",
	endpoint: "/api/chat",
};

/**
 * Microsoft 365 Copilot pane inside an Office web app (scenarios/frames.mjs). The Office
 * page (`office`) is not a protected site: it only embeds the pane (`m365pane`) as a
 * cross-origin iframe served at a Microsoft 365 Copilot host, where the extension's
 * `all_frames` content scripts run. `office` has its own comment box and endpoint so the
 * scenario can show that the Office page itself is left alone.
 */
SITES.office = {
	siteId: "office",
	origin: "https://word-edit.officeapps.live.com",
	path: "/we/wordeditorframe.aspx?ui=en-US",
	fixture: "office-word.html",
	kind: "textarea",
	editor: "#doc-comment",
	send: "#doc-comment-post",
	response: "#comments article",
	endpoint: "/we/api/comment",
};

SITES.m365pane = {
	siteId: "copilot",
	origin: "https://copilot.cloud.microsoft",
	path: "/pane?hostApp=Word",
	fixture: "m365-copilot-pane.html",
	// Microsoft 365 Copilot Chat as a top-level page, with the account manager header
	// (scenarios/work-accounts.mjs).
	pathFixtures: { "/chat": "m365-copilot-chat.html" },
	kind: "prosemirror",
	editor: "#m365-chat-editor-target-element",
	send: "button.fai-SendButton",
	response: '[data-testid="markdown-reply"]',
	endpoint: "/m365/api/chat",
};

export const UPLOAD_PATH = "/__fixture__/upload";
export const KIT_PATH = "/__fixture__/kit.js";

/** Returns the site whose origin serves `url`, or undefined. */
export function siteForUrl(url) {
	let origin;
	try {
		origin = new URL(url).origin;
	} catch {
		return undefined;
	}
	return Object.values(SITES).find((s) => s.origin === origin);
}
