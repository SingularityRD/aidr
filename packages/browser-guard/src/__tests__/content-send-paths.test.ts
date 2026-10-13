// @vitest-environment jsdom
/**
 * Send paths other than "Enter / Send in the main composer" (GA audit BG-1, BG-2, BG-3,
 * BG-9): edit-and-resend forms on sent messages, a send click while focus is in another
 * field, editors inside open shadow roots and sites where Enter only inserts a newline.
 * Runs the guard with the real site adapters and the real editor discovery
 * (dom/editor.ts), as the content script wires them.
 */
import { afterEach, describe, expect, it } from "vitest";
import { type ContentGuard, createContentGuard } from "../content/guard";
import { STRINGS } from "../content/strings";
import {
	findEditor,
	findEditorNear,
	findSendButton,
	insertAtSelection,
	isSyntheticEditorEvent,
} from "../dom/editor";
import { createVault } from "../engine/vault";
import { chatgpt } from "../sites/chatgpt";
import { claude } from "../sites/claude";
import { gemini } from "../sites/gemini";
import { GENERIC_ADAPTER } from "../sites/generic";
import type { GuardMessage, GuardPolicy, SiteAdapter } from "../types";
import { BASE_POLICY, EMAIL, fakeEngine } from "./content-helpers";

const MASKED = "[EMAIL_1]";

let guard: ContentGuard | undefined;

afterEach(() => {
	guard?.stop();
	guard = undefined;
	document.body.innerHTML = "";
});

interface Run {
	readonly engine: ReturnType<typeof fakeEngine>;
	readonly guard: ContentGuard;
	records(): Extract<GuardMessage, { type: "RECORD" }>[];
	bubbleText(): string;
}

function start(adapter: SiteAdapter, policy: Partial<GuardPolicy> = {}): Run {
	const engine = fakeEngine();
	const messages: GuardMessage[] = [];
	guard = createContentGuard({
		window,
		document,
		adapter,
		engine,
		vault: createVault({ neverRestore: ["SECRET"] }),
		getPolicy: () => ({ ...BASE_POLICY, ...policy }),
		findEditor,
		findEditorNear,
		findSendButton,
		insertAtSelection,
		isSyntheticEvent: isSyntheticEditorEvent,
		sanitizeFile: async () => ({ action: "allow", counts: {}, reasons: [] }),
		coachingFor: () => "",
		send: async (message) => {
			messages.push(message);
			return undefined;
		},
		schedule: (callback) => queueMicrotask(callback),
		prescanDelayMs: 60_000,
	});
	guard.start();
	const root = guard.ui.root;
	return {
		engine,
		guard,
		records: () =>
			messages.filter((m): m is Extract<GuardMessage, { type: "RECORD" }> => m.type === "RECORD"),
		bubbleText: () => root.querySelector('[role="alertdialog"]')?.textContent ?? "",
	};
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
const byId = <T extends HTMLElement = HTMLElement>(id: string): T =>
	document.getElementById(id) as T;

function enter(target: EventTarget, init: KeyboardEventInit = {}): KeyboardEvent {
	const event = new KeyboardEvent("keydown", {
		key: "Enter",
		bubbles: true,
		composed: true,
		cancelable: true,
		...init,
	});
	target.dispatchEvent(event);
	return event;
}

/** Records what the "site" sends when `button` is clicked: the value of `field`. */
function siteSendsOnClick(button: HTMLElement, field: () => string): string[] {
	const sent: string[] = [];
	button.addEventListener("click", () => sent.push(field()));
	return sent;
}

describe("BG-1: edit-and-resend forms on a sent message", () => {
	const chatgptEdit = `
		<article data-testid="conversation-turn-1">
			<div data-message-author-role="user">
				<textarea id="edit"></textarea>
				<button class="btn btn-secondary" id="cancel">Cancel</button>
				<button class="btn btn-primary" id="editsend">Send</button>
			</div>
		</article>
		<form data-type="unified-composer">
			<div id="prompt-textarea" contenteditable="true"></div>
			<button data-testid="send-button" type="button">Send</button>
		</form>`;

	it("ChatGPT: the edit form's Send masks the edited text before the site sends it", async () => {
		document.body.innerHTML = chatgptEdit;
		const edit = byId<HTMLTextAreaElement>("edit");
		const sent = siteSendsOnClick(byId("editsend"), () => edit.value);
		const run = start(chatgpt);
		edit.focus();
		edit.value = `edited: ${EMAIL}`;

		byId("editsend").click();
		expect(sent).toEqual([]); // the unmasked click never reached the site

		await expect.poll(() => sent.length).toBe(1);
		expect(sent[0]).toBe(`edited: ${MASKED}`);
		expect(edit.value).toBe(`edited: ${MASKED}`);
		expect(run.engine.scan).toHaveBeenCalledTimes(1);
		expect(run.records().at(-1)).toMatchObject({ action: "masked", channel: "prompt" });
	});

	it("ChatGPT: the edit form's Send is checked even when focus already left the edit box", async () => {
		document.body.innerHTML = chatgptEdit;
		const edit = byId<HTMLTextAreaElement>("edit");
		const sent = siteSendsOnClick(byId("editsend"), () => edit.value);
		start(chatgpt);
		edit.value = `edited: ${EMAIL}`;
		byId("prompt-textarea").focus();

		byId("editsend").click();
		await expect.poll(() => sent.length).toBe(1);
		expect(sent[0]).toBe(`edited: ${MASKED}`);
	});

	it("block mode refuses the edited send instead of letting it out", async () => {
		document.body.innerHTML = chatgptEdit;
		const edit = byId<HTMLTextAreaElement>("edit");
		const sent = siteSendsOnClick(byId("editsend"), () => edit.value);
		const run = start(chatgpt, { mode: "block" });
		edit.value = `edited: ${EMAIL}`;

		byId("editsend").click();
		await expect.poll(() => run.records().length).toBe(1);
		await flush();
		expect(sent).toEqual([]);
		expect(run.records()[0]).toMatchObject({ action: "blocked", channel: "prompt" });
	});

	it("Claude: an edit form's Save button (no send selector) is a send", async () => {
		document.body.innerHTML = `
			<div data-testid="user-message-turn">
				<div class="edit-box">
					<textarea id="edit"></textarea>
					<div><button type="button" id="cancel">Cancel</button><button type="button" id="save"><span>Save</span></button></div>
				</div>
			</div>
			<fieldset><div class="ProseMirror" contenteditable="true" id="composer"></div></fieldset>`;
		const edit = byId<HTMLTextAreaElement>("edit");
		const sent = siteSendsOnClick(byId("save"), () => edit.value);
		start(claude);
		edit.value = `please write to ${EMAIL}`;

		byId("save").querySelector("span")?.click();
		expect(sent).toEqual([]);
		await expect.poll(() => sent.length).toBe(1);
		expect(sent[0]).toBe(`please write to ${MASKED}`);
	});

	it("Gemini: an edit form's Update button is a send", async () => {
		document.body.innerHTML = `
			<user-query>
				<div class="edit-container">
					<textarea id="edit" aria-label="Edit prompt"></textarea>
					<button id="update">Update</button>
				</div>
			</user-query>
			<rich-textarea><div class="ql-editor" contenteditable="true" role="textbox"></div></rich-textarea>`;
		const edit = byId<HTMLTextAreaElement>("edit");
		const sent = siteSendsOnClick(byId("update"), () => edit.value);
		start(gemini);
		edit.value = `mail ${EMAIL}`;

		byId("update").click();
		await expect.poll(() => sent.length).toBe(1);
		expect(sent[0]).toBe(`mail ${MASKED}`);
	});

	it("an edit form submitted through its own form is checked against that form's editor", async () => {
		document.body.innerHTML = `
			<form id="editform"><textarea id="edit"></textarea><button id="go">Go</button></form>
			<form data-type="unified-composer"><textarea id="prompt-textarea"></textarea></form>`;
		const edit = byId<HTMLTextAreaElement>("edit");
		const sent: string[] = [];
		byId("editform").addEventListener("submit", (event) => {
			event.preventDefault();
			sent.push(edit.value);
		});
		start(chatgpt);
		byId<HTMLTextAreaElement>("prompt-textarea").value = "clean composer text";
		edit.value = `mail ${EMAIL}`;

		byId("go").click(); // a default-type button submits its form
		await expect.poll(() => sent.length).toBe(1);
		expect(sent[0]).toBe(`mail ${MASKED}`);
	});

	it("Cancel in an edit form and a settings dialog's Save are not sends", async () => {
		document.body.innerHTML = `${chatgptEdit}
			<div role="dialog"><label>Name <span id="name">x</span></label><button id="settings-save">Save</button></div>`;
		const edit = byId<HTMLTextAreaElement>("edit");
		const cancel = siteSendsOnClick(byId("cancel"), () => edit.value);
		const save = siteSendsOnClick(byId("settings-save"), () => "saved");
		const run = start(chatgpt);
		edit.value = `edited: ${EMAIL}`;
		byId("prompt-textarea").textContent = `composer ${EMAIL}`;

		byId("cancel").click();
		byId("settings-save").click();
		await flush();
		expect(cancel).toEqual([`edited: ${EMAIL}`]);
		expect(save).toEqual(["saved"]);
		expect(run.engine.scan).not.toHaveBeenCalled();
	});
});

describe("BG-2: a send click scans the composer of the clicked button, not the focused field", () => {
	const layout = `
		<nav><input type="search" id="q"></nav>
		<form data-type="unified-composer">
			<textarea id="prompt-textarea"></textarea>
			<button data-testid="send-button" type="button" id="send">Send</button>
		</form>`;

	it("an empty, focused search box does not let the composer's prompt out unscanned", async () => {
		document.body.innerHTML = layout;
		const composer = byId<HTMLTextAreaElement>("prompt-textarea");
		const sent = siteSendsOnClick(byId("send"), () => composer.value);
		const run = start(chatgpt);
		composer.value = `mail ${EMAIL}`;
		byId("q").focus();

		byId("send").click();
		expect(sent).toEqual([]);
		await expect.poll(() => sent.length).toBe(1);
		expect(sent[0]).toBe(`mail ${MASKED}`);
		expect(run.engine.scan.mock.calls[0]?.[0]).toBe(`mail ${EMAIL}`);
	});

	it("clean text in the focused search box is not what gets checked", async () => {
		document.body.innerHTML = layout;
		const composer = byId<HTMLTextAreaElement>("prompt-textarea");
		const sent = siteSendsOnClick(byId("send"), () => composer.value);
		start(chatgpt);
		composer.value = `mail ${EMAIL}`;
		const search = byId<HTMLInputElement>("q");
		search.value = "weather";
		search.focus();

		byId("send").click();
		await expect.poll(() => sent.length).toBe(1);
		expect(sent[0]).toBe(`mail ${MASKED}`);
		expect(search.value).toBe("weather");
	});

	it("refuses (fails closed) when several editors in the button's container hold text", async () => {
		document.body.innerHTML = `
			<form data-type="unified-composer">
				<textarea id="a"></textarea><textarea id="b"></textarea>
				<button data-testid="send-button" type="button" id="send">Send</button>
			</form>`;
		const sent = siteSendsOnClick(byId("send"), () => "sent");
		const run = start(chatgpt);
		byId<HTMLTextAreaElement>("a").value = "first";
		byId<HTMLTextAreaElement>("b").value = `second ${EMAIL}`;

		const click = new MouseEvent("click", { bubbles: true, cancelable: true, composed: true });
		byId("send").dispatchEvent(click);
		await flush();
		expect(click.defaultPrevented).toBe(true);
		expect(sent).toEqual([]);
		expect(run.bubbleText()).toContain(STRINGS.en.editorAmbiguous);
		expect(run.records()).toEqual([expect.objectContaining({ action: "blocked" })]);
	});

	it("a known send button with no editor on the page is refused (fail closed)", async () => {
		document.body.innerHTML = `<button data-testid="send-button" type="button" id="send">Send</button>`;
		const sent = siteSendsOnClick(byId("send"), () => "sent");
		const run = start(chatgpt);

		byId("send").click();
		await flush();
		expect(sent).toEqual([]);
		expect(run.bubbleText()).toContain(STRINGS.en.editorMissing);
	});
});

describe("BG-3: editors inside open shadow roots", () => {
	function shadowComposer(html: string): ShadowRoot {
		document.body.innerHTML = `<my-chat id="host"></my-chat>`;
		const root = byId("host").attachShadow({ mode: "open" });
		root.innerHTML = html;
		return root;
	}

	it("Enter in a shadow-DOM textarea is intercepted and masked", async () => {
		const root = shadowComposer(`<form><textarea id="ta"></textarea></form>`);
		const ta = root.getElementById("ta") as HTMLTextAreaElement;
		const sent: string[] = [];
		ta.addEventListener("keydown", (event) => {
			if (event.key === "Enter" && !event.shiftKey) {
				event.preventDefault();
				sent.push(ta.value);
			}
		});
		const run = start(GENERIC_ADAPTER);
		ta.value = `mail ${EMAIL}`;
		ta.focus();

		const original = enter(ta);
		expect(original.defaultPrevented).toBe(true);
		expect(sent).toEqual([]);
		await expect.poll(() => sent.length).toBe(1);
		expect(sent[0]).toBe(`mail ${MASKED}`);
		expect(run.engine.scan).toHaveBeenCalledTimes(1);
	});

	it("Enter in a shadow-DOM contenteditable is intercepted", async () => {
		const root = shadowComposer(`<div id="ce" contenteditable="true"><p>x</p></div>`);
		const ce = root.getElementById("ce") as HTMLElement;
		const sent: string[] = [];
		ce.addEventListener("keydown", (event) => {
			if (event.key === "Enter") {
				event.preventDefault();
				sent.push(ce.textContent ?? "");
			}
		});
		start(GENERIC_ADAPTER);
		ce.innerHTML = `<p>mail ${EMAIL}</p>`;

		const original = enter(ce.querySelector("p") as HTMLElement);
		expect(original.defaultPrevented).toBe(true);
		await expect.poll(() => sent.length).toBe(1);
		expect(sent[0]).toBe(`mail ${MASKED}`);
	});

	it("a send button inside the same shadow root sends the shadow editor's text masked", async () => {
		const root = shadowComposer(
			`<div class="composer"><textarea id="ta"></textarea><button id="go" aria-label="Send">Go</button></div>`,
		);
		const ta = root.getElementById("ta") as HTMLTextAreaElement;
		const sent = siteSendsOnClick(root.getElementById("go") as HTMLElement, () => ta.value);
		start(GENERIC_ADAPTER);
		ta.value = `mail ${EMAIL}`;

		(root.getElementById("go") as HTMLButtonElement).click();
		expect(sent).toEqual([]);
		await expect.poll(() => sent.length).toBe(1);
		expect(sent[0]).toBe(`mail ${MASKED}`);
	});
});

describe("BG-9: Enter only sends where the site sends on Enter", () => {
	const layout = `
		<form data-type="unified-composer">
			<textarea id="prompt-textarea"></textarea>
			<button data-testid="send-button" type="button" id="send">Send</button>
		</form>`;

	it("a site without an Enter handler gets a newline, not a send", async () => {
		document.body.innerHTML = layout;
		const ta = byId<HTMLTextAreaElement>("prompt-textarea");
		const sent = siteSendsOnClick(byId("send"), () => ta.value);
		start(chatgpt);
		ta.value = "first line hello";
		ta.focus();

		enter(ta);
		await expect.poll(() => ta.value).toBe("first line hello\n");
		await new Promise((resolve) => setTimeout(resolve, 400)); // past every button retry
		expect(sent).toEqual([]);
	});

	it("sensitive text is still masked on such a site, and still not sent", async () => {
		document.body.innerHTML = layout;
		const ta = byId<HTMLTextAreaElement>("prompt-textarea");
		const sent = siteSendsOnClick(byId("send"), () => ta.value);
		start(chatgpt);
		ta.value = `mail ${EMAIL}`;
		ta.focus();

		enter(ta);
		await expect.poll(() => ta.value).toBe(`mail ${MASKED}\n`);
		await new Promise((resolve) => setTimeout(resolve, 400));
		expect(sent).toEqual([]);
	});

	it("Ctrl+Enter the site ignores neither sends nor inserts anything", async () => {
		document.body.innerHTML = layout;
		const ta = byId<HTMLTextAreaElement>("prompt-textarea");
		const sent = siteSendsOnClick(byId("send"), () => ta.value);
		const run = start(chatgpt);
		ta.value = "hello";
		ta.focus();

		enter(ta, { ctrlKey: true });
		await expect.poll(() => run.records().length).toBe(1);
		await new Promise((resolve) => setTimeout(resolve, 400));
		expect(sent).toEqual([]);
		expect(ta.value).toBe("hello");
	});

	it("a single-line input still sends on Enter through implicit form submission", async () => {
		document.body.innerHTML = `
			<form id="f"><input type="text" id="prompt"><button id="go">Go</button></form>`;
		const input = byId<HTMLInputElement>("prompt");
		const clicked = siteSendsOnClick(byId("go"), () => input.value);
		const submitted: string[] = [];
		byId("f").addEventListener("submit", (event) => {
			event.preventDefault();
			submitted.push(input.value);
		});
		start(GENERIC_ADAPTER);
		input.value = `mail ${EMAIL}`;
		input.focus();

		enter(input);
		await expect.poll(() => submitted.length).toBe(1);
		expect(submitted[0]).toBe(`mail ${MASKED}`);
		expect(clicked).toEqual([`mail ${MASKED}`]); // the form's default button, once
	});

	it("an unhandled Enter in a single-line input outside a form never clicks another send button", async () => {
		document.body.innerHTML = `
			<input type="text" id="rename">
			<form data-type="unified-composer">
				<textarea id="prompt-textarea"></textarea>
				<button data-testid="send-button" type="button" id="send">Send</button>
			</form>`;
		const composer = byId<HTMLTextAreaElement>("prompt-textarea");
		const sent = siteSendsOnClick(byId("send"), () => composer.value);
		const run = start(chatgpt);
		composer.value = "draft in the composer";
		const rename = byId<HTMLInputElement>("rename");
		rename.value = "new chat title";
		rename.focus();

		enter(rename);
		await expect.poll(() => run.records().length).toBe(1);
		await new Promise((resolve) => setTimeout(resolve, 400));
		expect(sent).toEqual([]);
	});

	it("Shift+Enter is never intercepted", () => {
		document.body.innerHTML = layout;
		const ta = byId<HTMLTextAreaElement>("prompt-textarea");
		const run = start(chatgpt);
		ta.value = `mail ${EMAIL}`;
		const event = enter(ta, { shiftKey: true });
		expect(event.defaultPrevented).toBe(false);
		expect(run.engine.scan).not.toHaveBeenCalled();
	});
});
