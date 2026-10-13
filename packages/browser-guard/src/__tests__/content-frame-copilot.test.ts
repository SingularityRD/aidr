// @vitest-environment jsdom
/**
 * The Microsoft 365 Copilot pane inside the Office web apps is a cross-origin iframe on a
 * Microsoft 365 Copilot host. The content script runs in that subframe (src/sites/frames.ts)
 * and must behave exactly as in the top frame: the frame URL resolves the `copilot` adapter,
 * a send is blocked until a policy arrived (fail closed), the prompt is masked on send and the
 * reply is restored locally. Wired like content/index.ts: bootContentGuard with the real site
 * adapters and editor discovery.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { type BootedGuard, bootContentGuard, type RuntimeLike } from "../content/boot";
import { visibleText } from "../content/unmask";
import {
	findEditor,
	findEditorNear,
	findSendButton,
	insertAtSelection,
	isSyntheticEditorEvent,
} from "../dom/editor";
import { createVault } from "../engine/vault";
import { guardRunsInFrame } from "../sites/frames";
import { adapterForUrl } from "../sites/index";
import type { GuardMessage } from "../types";
import { BASE_POLICY, EMAIL, fakeEngine } from "./content-helpers";

/** URL of the Copilot pane frame (the top-level page is an Office web app). */
const PANE = "https://copilot.cloud.microsoft/pane?hostApp=Word";

const booted: BootedGuard[] = [];

afterEach(() => {
	for (const b of booted.splice(0)) b.guard.stop();
	document.body.innerHTML = "";
	for (const host of document.querySelectorAll("[data-aidr-guard]")) host.remove();
});

function runtime(policyAvailable: boolean): RuntimeLike & {
	sendMessage: ReturnType<typeof vi.fn>;
	messages: GuardMessage[];
} {
	const messages: GuardMessage[] = [];
	return {
		id: "ext-id",
		messages,
		sendMessage: vi.fn(async (message: GuardMessage) => {
			messages.push(message);
			if (message.type === "GET_POLICY") {
				return policyAvailable ? { ok: true, policy: BASE_POLICY } : { ok: false };
			}
			if (message.type === "VAULT_LOAD") return { ok: true, snapshot: null, sent: [] };
			return { ok: true };
		}),
		onMessage: { addListener: () => undefined },
	};
}

/** Microsoft 365 Copilot Chat composer markup (Fluent UI / Lexical), as in the pane. */
function loadPane(rt: RuntimeLike) {
	document.body.innerHTML = `
		<div id="thread"></div>
		<div id="m365-chat-editor-target-element" contenteditable="true" role="textbox"
			data-lexical-editor="true" aria-label="Message Copilot"></div>
		<button class="fai-SendButton" type="button" aria-label="Send">Send</button>`;
	const editor = document.getElementById("m365-chat-editor-target-element") as HTMLElement;
	const button = document.querySelector("button.fai-SendButton") as HTMLButtonElement;
	const sent: string[] = [];
	button.addEventListener("click", () => sent.push(editor.textContent ?? ""));
	const guard = bootContentGuard({
		window,
		document,
		url: PANE,
		runtime: rt,
		adapterForUrl,
		createDetectionEngine: () => fakeEngine(),
		createVault,
		vaultTag: "t3st",
		findEditor,
		findEditorNear,
		findSendButton,
		insertAtSelection,
		isSyntheticEvent: isSyntheticEditorEvent,
		sanitizeFile: async () => ({ action: "allow", counts: {}, reasons: [] }),
		coachingFor: (code) => code,
		sleep: () => new Promise(() => undefined), // no retry: the first answer is final
		schedule: (cb) => queueMicrotask(cb),
	});
	booted.push(guard);
	return { guard, editor, button, sent };
}

describe("guardRunsInFrame", () => {
	it("always runs in the top frame, and in a subframe only on the Microsoft 365 Copilot hosts", () => {
		expect(guardRunsInFrame(true, "https://chatgpt.com/")).toBe(true);
		expect(guardRunsInFrame(false, PANE)).toBe(true);
		expect(guardRunsInFrame(false, "https://m365.cloud.microsoft/chat")).toBe(true);
		for (const url of [
			"https://chatgpt.com/",
			"https://copilot.microsoft.com/",
			"https://word-edit.officeapps.live.com/we/wordeditorframe.aspx",
			"https://example.org/widget",
		])
			expect(guardRunsInFrame(false, url)).toBe(false);
	});
});

describe("Copilot pane subframe guard", () => {
	it("resolves the copilot adapter from the frame URL", () => {
		const { guard } = loadPane(runtime(true));
		expect(guard.guard.ui).toBeDefined();
		expect(adapterForUrl(PANE).id).toBe("copilot");
	});

	it("fails closed: a send is blocked until a policy arrived", async () => {
		const { editor, button, sent } = loadPane(runtime(false));
		editor.focus();
		editor.textContent = `Please email ${EMAIL}`;
		button.click();
		await new Promise((resolve) => setTimeout(resolve, 20));
		expect(sent).toEqual([]);
		expect(editor.textContent).toContain(EMAIL);
	});

	it("masks the prompt on send and restores the reply locally", async () => {
		const rt = runtime(true);
		const { guard, editor, button, sent } = loadPane(rt);
		await guard.ready;
		editor.focus();
		editor.textContent = `Please email ${EMAIL}`;
		button.click();
		expect(sent).toEqual([]); // the unmasked click never reached the pane's handler
		await expect.poll(() => sent.length).toBe(1);
		expect(sent[0]).not.toContain(EMAIL);
		const placeholder = /\[EMAIL[^\]]*\]/.exec(sent[0])?.[0] ?? "";
		expect(placeholder).not.toBe("");
		// Counts only; the worker derives the site (copilot) from the frame URL.
		const records = rt.messages.filter((m) => m.type === "RECORD");
		expect(records).toHaveLength(1);
		expect(records[0]).toMatchObject({ action: "masked", channel: "prompt" });
		expect(JSON.stringify(records)).not.toContain(EMAIL);
		// The reply in the pane shows the original to the user; page text keeps the placeholder.
		const reply = document.createElement("div");
		reply.setAttribute("data-testid", "markdown-reply");
		reply.textContent = `I will write to ${placeholder}.`;
		document.getElementById("thread")?.append(reply);
		await expect.poll(() => visibleText(reply)).toContain(EMAIL);
		expect(reply.textContent).toContain(placeholder);
	});
});
