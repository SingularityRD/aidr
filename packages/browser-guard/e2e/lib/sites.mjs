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
