// @vitest-environment jsdom
/**
 * Per-vault placeholder tags (review regression): numbering restarts with every vault,
 * so another conversation's (or tab's) `[EMAIL_1]` used to be restored with this tab's
 * value. A vault created with a tag mints `[EMAIL_1_<tag>]`; the content script uses a
 * fresh random tag per page life, and untagged entries of older snapshots stay valid.
 */
import { afterEach, describe, expect, it } from "vitest";
import { bootContentGuard, type RuntimeLike } from "../content/boot";
import { placeholderRegex } from "../content/unmask";
import { editorAccess, insertAtSelection, isSyntheticEditorEvent } from "../dom/editor";
import { createVault, newVaultTag, VAULT_TAG_RE } from "../engine/vault";
import type { Finding, GuardMessage, PlaceholderVault } from "../types";
import { ADAPTER, BASE_POLICY, EMAIL, fakeEngine, type Harness, setupGuard } from "./content-helpers";

let h: Harness | undefined;

afterEach(() => {
	h?.guard.stop();
	h = undefined;
	document.body.innerHTML = "";
});

const email = (text: string, value: string): Finding => {
	const start = text.indexOf(value);
	return { type: "EMAIL", start, end: start + value.length, score: 1, source: "rule" };
};

const maskEmail = (vault: PlaceholderVault, value: string): string =>
	vault.mask(value, [email(value, value)]).masked;

describe("vault tags", () => {
	it("newVaultTag returns random 4-character lower-case tags", () => {
		const tags = new Set(Array.from({ length: 50 }, () => newVaultTag()));
		for (const tag of tags) expect(tag).toMatch(VAULT_TAG_RE);
		expect(tags.size).toBeGreaterThan(40);
	});

	it("rejects malformed tags", () => {
		for (const tag of ["", "abc", "ABCD", "ab_cd", "abcdefghi"]) {
			expect(() => createVault({ neverRestore: [], tag })).toThrow(RangeError);
		}
	});

	it("mints tagged placeholders and restores every echo form of them", () => {
		const vault = createVault({ neverRestore: [], tag: "k3f9" });
		expect(maskEmail(vault, EMAIL)).toBe("[EMAIL_1_k3f9]");
		expect(maskEmail(vault, "b@example.com")).toBe("[EMAIL_2_k3f9]");
		expect(vault.unmask("to [EMAIL_1_k3f9], EMAIL\\_2\\_k3f9 and **EMAIL_1_k3f9**")).toBe(
			`to ${EMAIL}, b@example.com and **${EMAIL}**`,
		);
		expect(vault.lookup("[EMAIL_1_k3f9]")).toBe(EMAIL);
		expect(placeholderRegex().test("[EMAIL_1_k3f9]")).toBe(true);
	});

	it("never restores another vault's placeholder with the same number", () => {
		const ours = createVault({ neverRestore: [], tag: "aaaa" });
		maskEmail(ours, EMAIL);
		expect(ours.unmask("[EMAIL_1] [EMAIL_1_bbbb] EMAIL_1")).toBe("[EMAIL_1] [EMAIL_1_bbbb] EMAIL_1");
		expect(ours.lookup("[EMAIL_1]")).toBeUndefined();
	});

	it("imports untagged snapshot entries, keeps restoring them and continues the numbering", () => {
		const legacy = createVault({ neverRestore: [] });
		expect(maskEmail(legacy, EMAIL)).toBe("[EMAIL_1]");
		const resumed = createVault({
			neverRestore: [],
			snapshot: legacy.exportSession(),
			tag: "c0de",
		});
		expect(resumed.unmask("[EMAIL_1]")).toBe(EMAIL);
		expect(maskEmail(resumed, EMAIL)).toBe("[EMAIL_1]"); // same value, same placeholder
		expect(maskEmail(resumed, "new@example.com")).toBe("[EMAIL_2_c0de]");
		// And a tagged snapshot round-trips through another tag.
		const again = createVault({ neverRestore: [], snapshot: resumed.exportSession(), tag: "beef" });
		expect(again.unmask("[EMAIL_1] [EMAIL_2_c0de]")).toBe(`${EMAIL} new@example.com`);
		expect(maskEmail(again, "third@example.com")).toBe("[EMAIL_3_beef]");
	});

	it("skips a tagged name the user typed that the vault does not own", () => {
		const vault = createVault({ neverRestore: [], tag: "k3f9" });
		const text = `see [EMAIL_1_k3f9] then ${EMAIL}`;
		expect(vault.mask(text, [email(text, EMAIL)]).masked).toBe(
			"see [EMAIL_1_k3f9] then [EMAIL_2_k3f9]",
		);
	});
});

describe("content guard: placeholders from another conversation", () => {
	it("does not restore another vault's [EMAIL_1] with this tab's value", async () => {
		// Old conversation (another tab / earlier page life): alice -> [EMAIL_1_old1].
		const old = maskEmail(createVault({ neverRestore: [], tag: "old1" }), "alice@corp.example");
		const legacyOld = maskEmail(createVault({ neverRestore: [] }), "alice@corp.example");
		const g = (h = setupGuard({ vaultTag: "new2" }));
		g.editor.value = `mail ${EMAIL}`;
		g.enter();
		await expect.poll(() => g.sent).toEqual(["mail [EMAIL_1_new2]"]);
		// SPA navigation to the old conversation: its history renders after the send.
		const node = document.createElement("div");
		node.setAttribute("data-role", "assistant");
		node.textContent = `Pay invoices to ${old} or ${legacyOld}`;
		document.body.append(node);
		await new Promise((r) => setTimeout(r, 10));
		g.guard.unmasker.flush();
		expect(g.guard.unmasker.restoredCount).toBe(0);
		expect(node.querySelector(".aidr-restored")).toBeNull();
		// This conversation's own answer is still restored.
		const answer = document.createElement("div");
		answer.setAttribute("data-role", "assistant");
		answer.textContent = "Writing to [EMAIL_1_new2] now";
		document.body.append(answer);
		await new Promise((r) => setTimeout(r, 10));
		g.guard.unmasker.flush();
		expect(answer.querySelector(".aidr-restored")).not.toBeNull();
	});
});

describe("content boot: random tag per page life", () => {
	function bootOnce(): { sent: string[]; stop(): void; editor: HTMLTextAreaElement } {
		document.body.innerHTML = '<textarea id="editor"></textarea><button id="send">Send</button>';
		const editor = document.getElementById("editor") as HTMLTextAreaElement;
		const sent: string[] = [];
		editor.addEventListener("keydown", (event) => {
			if (event.key === "Enter") {
				event.preventDefault();
				sent.push(editor.value);
			}
		});
		const runtime: RuntimeLike = {
			id: "ext",
			sendMessage: async (message: GuardMessage) =>
				message.type === "GET_POLICY" ? { policy: BASE_POLICY } : undefined,
			onMessage: { addListener: () => undefined },
		};
		const booted = bootContentGuard({
			window,
			document,
			url: "https://chatgpt.com/c/1",
			runtime,
			adapterForUrl: () => ADAPTER,
			createDetectionEngine: () => fakeEngine(),
			createVault,
			findEditor: (_adapter, root) => {
				const el = root.getElementById("editor");
				return el ? editorAccess(el) : null;
			},
			findSendButton: (_adapter, root) => root.getElementById("send"),
			insertAtSelection,
			isSyntheticEvent: isSyntheticEditorEvent,
			sanitizeFile: async () => ({ action: "allow", counts: {}, reasons: [] }),
			coachingFor: () => "",
			schedule: (cb) => queueMicrotask(cb),
			prescanDelayMs: 60_000,
			sleep: async () => undefined,
		});
		return { sent, editor, stop: () => booted.guard.stop() };
	}

	it("masks with a fresh random tag on every boot", async () => {
		const tags: string[] = [];
		for (let i = 0; i < 2; i++) {
			const b = bootOnce();
			await new Promise((r) => setTimeout(r, 20));
			b.editor.value = `mail ${EMAIL}`;
			b.editor.dispatchEvent(
				new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }),
			);
			await expect.poll(() => b.sent.length).toBe(1);
			const match = /^mail \[EMAIL_1_([a-z0-9]{4})\]$/.exec(b.sent[0] as string);
			expect(match).not.toBeNull();
			tags.push(match?.[1] as string);
			b.stop();
		}
		expect(tags[0]).not.toBe(tags[1]);
	});
});
