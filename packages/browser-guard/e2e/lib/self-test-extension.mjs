// Generates a tiny throwaway MV3 extension in os.tmpdir() that implements just
// enough of the Browser Guard message contract (GET_POLICY, SET_USER_SETTINGS,
// RECORD, GET_STATS) and page behaviour (mask one email on Enter/paste/upload,
// block/confirm bubbles, local restore) to prove the harness itself works:
// the extension loads, routes intercept, requests are recorded and every
// assertion can both pass and fail. It is never committed or shipped.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SITES } from "./sites.mjs";

const BACKGROUND = `
const DEFAULTS = { mode: "auto", maskPaste: true, restoreResponses: true };
async function policy() {
	const { userSettings = {} } = await chrome.storage.local.get("userSettings");
	return { version: 1, ...DEFAULTS, ...userSettings, managedKeys: [], policyId: "self-test" };
}
async function stats() {
	const { stats = { protectedPrompts: 0, maskedItems: 0, blockedSends: 0 } } = await chrome.storage.session.get("stats");
	return stats;
}
chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
	(async () => {
		if (msg.type === "GET_POLICY") return reply(await policy());
		if (msg.type === "SET_USER_SETTINGS") {
			const { userSettings = {} } = await chrome.storage.local.get("userSettings");
			await chrome.storage.local.set({ userSettings: { ...userSettings, ...msg.settings } });
			return reply({ ok: true, policy: await policy() });
		}
		if (msg.type === "RECORD") {
			const s = await stats();
			if (msg.action === "masked") { s.protectedPrompts += 1; s.maskedItems += msg.counts.EMAIL ?? 0; }
			if (msg.action === "blocked") s.blockedSends += 1;
			await chrome.storage.session.set({ stats: s });
			return reply({ ok: true });
		}
		if (msg.type === "GET_STATS") return reply({ site: null, ...(await stats()), byType: {}, pausedUntil: null, nativeHost: "disabled" });
		reply({ ok: false, error: "unknown message" });
	})();
	return true;
});
`;

const CONTENT = `
const SECRET = "secret@example.com";
const PH = "[EMAIL_1_e2e0]";
let policy = { mode: "auto" };
chrome.runtime.sendMessage({ type: "GET_POLICY" }).then((p) => { if (p) policy = p; });
const EDITOR = 'textarea, [contenteditable="true"]';
const ours = new WeakSet();

function editorOf(node) { return node && node.closest ? node.closest(EDITOR) : null; }
function read(ed) { return ed.tagName === "TEXTAREA" ? ed.value : ed.textContent; }
function textNodes(root) {
	const out = [];
	const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
	while (walker.nextNode()) out.push(walker.currentNode);
	return out;
}
function mask(ed) {
	if (ed.tagName === "TEXTAREA") {
		const set = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
		set.call(ed, ed.value.split(SECRET).join(PH));
	} else {
		for (const n of textNodes(ed)) if (n.data.includes(SECRET)) n.data = n.data.split(SECRET).join(PH);
	}
	ed.dispatchEvent(new InputEvent("input", { bubbles: true }));
	chrome.runtime.sendMessage({ type: "RECORD", site: "other", action: "masked", channel: "prompt", counts: { EMAIL: 1 } });
}
function bubble(text, onSend) {
	document.querySelector("[data-aidr-bubble]")?.remove();
	const host = document.createElement("div");
	host.setAttribute("data-aidr-bubble", "");
	host.style.cssText = "position:fixed;right:12px;bottom:12px;width:260px;min-height:60px;background:#fff3f3;z-index:2147483647";
	const root = host.attachShadow({ mode: "open" });
	root.innerHTML = "<p></p>" + (onSend ? "<button type=button>Send masked</button>" : "");
	root.querySelector("p").textContent = text;
	root.querySelector("button")?.addEventListener("click", () => { host.remove(); onSend(); });
	document.documentElement.appendChild(host);
}
function intercept(event, ed, resend) {
	if (!ed || !read(ed).includes(SECRET) || policy.mode === "monitor") return;
	if (policy.mode === "block") {
		event.preventDefault(); event.stopImmediatePropagation();
		chrome.runtime.sendMessage({ type: "RECORD", site: "other", action: "blocked", channel: "prompt", counts: { EMAIL: 1 } });
		bubble("Blocked: this prompt contains an email address.");
		return;
	}
	if (policy.mode === "confirm") {
		event.preventDefault(); event.stopImmediatePropagation();
		bubble("This prompt contains an email address.", () => { mask(ed); resend(); });
		return;
	}
	mask(ed);
}
document.addEventListener("keydown", (e) => {
	if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
	const ed = editorOf(e.target);
	intercept(e, ed, () => ed.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true })));
}, true);
document.addEventListener("click", (e) => {
	const button = e.target.closest && e.target.closest("button");
	if (!button || button.closest("[data-aidr-bubble]")) return;
	const ed = document.querySelector(EDITOR);
	intercept(e, ed, () => button.click());
}, true);
document.addEventListener("paste", (e) => {
	const text = e.clipboardData?.getData("text/plain") ?? "";
	if (!text.includes(SECRET) || policy.mode === "monitor") return;
	e.preventDefault(); e.stopImmediatePropagation();
	document.execCommand("insertText", false, text.split(SECRET).join(PH));
}, true);
document.addEventListener("change", async (e) => {
	const input = e.target;
	if (!(input instanceof HTMLInputElement) || input.type !== "file" || ours.has(e)) return;
	e.stopImmediatePropagation();
	const dt = new DataTransfer();
	for (const f of input.files) dt.items.add(new File([(await f.text()).split(SECRET).join(PH)], f.name, { type: f.type }));
	input.files = dt.files;
	const again = new Event("change", { bubbles: true });
	ours.add(again);
	input.dispatchEvent(again);
}, true);
// Restores like the product: the placeholder stays in the light DOM (what page
// scripts read), the original is shown from a closed shadow root.
function restore(n) {
	const at = n.data.indexOf(PH);
	const ph = n.splitText(at);
	ph.splitText(PH.length);
	const span = document.createElement("span");
	span.dataset.stRestored = "";
	ph.replaceWith(span);
	span.append(ph);
	const shadow = span.attachShadow({ mode: "closed" });
	const hidden = document.createElement("span");
	hidden.style.cssText = "position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)";
	hidden.setAttribute("aria-hidden", "true");
	hidden.append(document.createElement("slot"));
	shadow.append(hidden, document.createTextNode(SECRET));
}
new MutationObserver(() => {
	for (const n of textNodes(document.body)) {
		const parent = n.parentElement;
		if (n.data.includes(PH) && !editorOf(parent) && !parent?.closest("[data-st-restored]")) restore(n);
	}
}).observe(document.documentElement, { subtree: true, childList: true, characterData: true });
`;

const POPUP_HTML = `<!doctype html><html><head><meta charset="utf-8"><title>Self-test popup</title></head>
<body><h1>Self-test guard</h1><p id="site"></p><p>Mode: <span id="mode">...</span></p><p>Protected prompts: <span id="count">0</span></p>
<script src="popup.js"></script></body></html>`;

const POPUP_JS = `(async () => {
	const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
	const host = tab && tab.url ? new URL(tab.url).hostname : "";
	if (host === "chatgpt.com") document.getElementById("site").textContent = "Sensitive data you send to ChatGPT is checked.";
	const p = await chrome.runtime.sendMessage({ type: "GET_POLICY" });
	const s = await chrome.runtime.sendMessage({ type: "GET_STATS" });
	document.getElementById("mode").textContent = p.mode;
	document.getElementById("count").textContent = String(s.protectedPrompts);
})();`;

export function createSelfTestExtension() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bg-e2e-selftest-ext-"));
	const matches = Object.values(SITES).map((s) => `${s.origin}/*`);
	const manifest = {
		manifest_version: 3,
		name: "Browser Guard E2E self-test",
		version: "0.0.1",
		background: { service_worker: "background.js" },
		action: { default_popup: "popup.html" },
		permissions: ["storage", "tabs"],
		content_scripts: [{ matches, js: ["content.js"], run_at: "document_idle" }],
	};
	fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
	fs.writeFileSync(path.join(dir, "background.js"), BACKGROUND);
	fs.writeFileSync(path.join(dir, "content.js"), CONTENT);
	fs.writeFileSync(path.join(dir, "popup.html"), POPUP_HTML);
	fs.writeFileSync(path.join(dir, "popup.js"), POPUP_JS);
	return dir;
}
