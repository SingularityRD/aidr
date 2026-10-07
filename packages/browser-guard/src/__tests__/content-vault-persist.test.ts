// @vitest-environment jsdom
/**
 * Vault persistence across page reloads (content side): the content script mirrors its
 * vault and sent set to the worker (VAULT_SAVE) and rehydrates them on boot
 * (VAULT_LOAD), so answers after a reload still restore - but only placeholders that
 * were actually sent from this tab, and never secrets (neverRestore types).
 *
 * The worker is faked by a runtime that keeps the last VAULT_SAVE payload, like
 * background/vault-store.ts does per tab + origin.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	type BootedGuard,
	bootContentGuard,
	extractVault,
	type RuntimeLike,
} from "../content/boot";
import { visibleText } from "../content/unmask";
import { editorAccess, isSyntheticEditorEvent } from "../dom/editor";
import { createVault } from "../engine/vault";
import type { DetectionEngine, Finding, GuardMessage, VaultSnapshot } from "../types";
import { ADAPTER, BASE_POLICY, EMAIL } from "./content-helpers";

const SECRET = "sk-live-abcdefghijklmnop";
const OTHER_EMAIL = "other.person@example.org";

const booted: BootedGuard[] = [];

afterEach(() => {
	for (const b of booted.splice(0)) b.guard.stop();
	document.body.innerHTML = "";
	for (const host of document.querySelectorAll("[data-aidr-guard]")) host.remove();
});

/** Finds e-mail addresses and `sk-...` secrets. */
function engine(): DetectionEngine {
	return {
		async scan(text) {
			const findings: Finding[] = [];
			for (const [re, type] of [
				[/[\w.+-]+@[\w-]+\.[\w.]+/g, "EMAIL"],
				[/sk-[\w-]+/g, "SECRET"],
			] as const) {
				for (const m of text.matchAll(re))
					findings.push({
						type,
						start: m.index,
						end: m.index + m[0].length,
						score: 1,
						source: "rule",
					});
			}
			return { findings, signals: [], counts: {}, incomplete: false, elapsedMs: 1 };
		},
	};
}

interface Store {
	saved: { snapshot: VaultSnapshot; sent: readonly string[] } | null;
	saves: number;
}

function workerRuntime(
	store: Store,
	options: { load?: (message: GuardMessage) => unknown } = {},
): RuntimeLike & { sendMessage: ReturnType<typeof vi.fn> } {
	return {
		id: "ext-id",
		sendMessage: vi.fn(async (message: GuardMessage) => {
			switch (message.type) {
				case "GET_POLICY":
					return { ok: true, policy: { ...BASE_POLICY, neverRestore: ["SECRET"] } };
				case "VAULT_SAVE":
					store.saves += 1;
					store.saved = structuredClone({ snapshot: message.snapshot, sent: message.sent });
					return { ok: true };
				case "VAULT_LOAD":
					if (options.load) return options.load(message);
					return {
						ok: true,
						snapshot: store.saved?.snapshot ?? null,
						sent: store.saved?.sent ?? [],
					};
				default:
					return { ok: true };
			}
		}),
		onMessage: { addListener: () => undefined },
	};
}

/** Loads (or reloads) the page: fresh DOM + content script against the same worker. */
function loadPage(runtime: RuntimeLike, history = "") {
	for (const b of booted.splice(0)) b.guard.stop();
	document.body.innerHTML = `<textarea id="editor"></textarea><div id="thread">${history}</div>`;
	const editor = document.getElementById("editor") as HTMLTextAreaElement;
	const sent: string[] = [];
	editor.addEventListener("keydown", (event) => {
		if (event.key === "Enter") {
			event.preventDefault();
			sent.push(editor.value);
		}
	});
	const guard = bootContentGuard({
		window,
		document,
		url: "https://chatgpt.com/c/1",
		runtime,
		adapterForUrl: () => ADAPTER,
		createDetectionEngine: engine,
		createVault,
		vaultTag: "t3st",
		findEditor: (_adapter, root) => {
			const el = root.getElementById("editor");
			return el ? editorAccess(el) : null;
		},
		findSendButton: () => null,
		isSyntheticEvent: isSyntheticEditorEvent,
		sanitizeFile: async () => ({ action: "allow", counts: {}, reasons: [] }),
		coachingFor: (code) => code,
		sleep: async () => undefined,
		schedule: (cb) => queueMicrotask(cb),
	});
	booted.push(guard);
	const send = (text: string) => {
		editor.value = text;
		editor.dispatchEvent(
			new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }),
		);
	};
	const reply = (text: string) => {
		const answer = document.createElement("div");
		answer.dataset.role = "assistant";
		answer.textContent = text;
		document.getElementById("thread")?.append(answer);
		return answer;
	};
	return { guard, editor, sent, send, reply };
}

async function settle(): Promise<void> {
	for (let i = 0; i < 5; i++) await new Promise((resolve) => setTimeout(resolve, 0));
}

describe("vault persistence across reloads", () => {
	it("restores an answer after a reload, for placeholders sent from this tab only", async () => {
		const store: Store = { saved: null, saves: 0 };
		const runtime = workerRuntime(store);
		const first = loadPage(runtime);
		await first.guard.ready;
		first.send(`mail ${EMAIL} with key ${SECRET}`);
		await expect.poll(() => first.sent).toEqual(["mail [EMAIL_1_t3st] with key [SECRET_1_t3st]"]);
		await settle();
		expect(store.saved?.sent).toEqual(["[EMAIL_1_t3st]"]);
		// Secrets are never persisted.
		expect(store.saved?.snapshot.entries.map((e) => e.type)).toEqual(["EMAIL"]);
		expect(JSON.stringify(store.saved)).not.toContain(SECRET);

		// Reload: the SPA re-renders the conversation after the content script started.
		const second = loadPage(runtime);
		await second.guard.ready;
		const answer = second.reply("I will write to [EMAIL_1_t3st] and keep [SECRET_1_t3st] private.");
		await settle();
		second.guard.guard.unmasker.flush();
		expect(visibleText(answer)).toBe(`I will write to ${EMAIL} and keep [SECRET_1_t3st] private.`);
		// The page itself still reads the placeholder.
		expect(answer.textContent).toContain("[EMAIL_1_t3st]");
	});

	it("restores history that was already rendered before the content script booted", async () => {
		const store: Store = { saved: null, saves: 0 };
		const runtime = workerRuntime(store);
		const first = loadPage(runtime);
		await first.guard.ready;
		first.send(`mail ${EMAIL}`);
		await expect.poll(() => store.saved?.sent).toEqual(["[EMAIL_1_t3st]"]);

		const second = loadPage(
			runtime,
			'<div data-role="assistant" id="old">Sent to [EMAIL_1_t3st], not [EMAIL_2_t3st].</div>',
		);
		await second.guard.ready;
		await settle();
		second.guard.guard.unmasker.flush();
		const old = document.getElementById("old") as HTMLElement;
		expect(visibleText(old)).toBe(`Sent to ${EMAIL}, not [EMAIL_2_t3st].`);
	});

	it("does not restore placeholders that were masked but never sent", async () => {
		const store: Store = { saved: null, saves: 0 };
		const runtime = workerRuntime(store);
		const first = loadPage(runtime);
		await first.guard.ready;
		first.send(`mail ${EMAIL}`);
		await expect.poll(() => store.saved?.sent).toEqual(["[EMAIL_1_t3st]"]);
		// Masked (e.g. a paste) but the user never sent it.
		first.editor.value = "";
		const paste = new Event("paste", { bubbles: true, cancelable: true });
		Object.defineProperty(paste, "clipboardData", {
			value: { getData: () => OTHER_EMAIL, files: [], items: [] },
		});
		first.editor.dispatchEvent(paste);
		await expect
			.poll(() => store.saved?.snapshot.entries.map((e) => e.placeholder))
			.toEqual(["[EMAIL_1_t3st]", "[EMAIL_2_t3st]"]);
		expect(store.saved?.sent).toEqual(["[EMAIL_1_t3st]"]);

		const second = loadPage(runtime);
		await second.guard.ready;
		const answer = second.reply("[EMAIL_1_t3st] and [EMAIL_2_t3st]");
		await settle();
		second.guard.guard.unmasker.flush();
		expect(visibleText(answer)).toBe(`${EMAIL} and [EMAIL_2_t3st]`);

		// New placeholders continue the numbering instead of reusing [EMAIL_2_t3st].
		second.send(`also ${EMAIL} and third@example.net`);
		await expect.poll(() => second.sent).toEqual([`also [EMAIL_1_t3st] and [EMAIL_3_t3st]`]);
	});

	it("starts with an empty vault when VAULT_LOAD fails, hangs or returns garbage", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
		try {
			const store: Store = { saved: null, saves: 0 };
			const hanging = loadPage(workerRuntime(store, { load: () => new Promise(() => undefined) }));
			await vi.advanceTimersByTimeAsync(1_600);
			await hanging.guard.ready;
			expect(hanging.guard.policy()).not.toBeNull();
		} finally {
			vi.useRealTimers();
		}
		const store: Store = { saved: null, saves: 0 };
		const garbage = loadPage(
			workerRuntime(store, {
				load: () => ({
					ok: true,
					snapshot: { version: 1, createdAt: 1, entries: [{ placeholder: "x" }] },
					sent: [],
				}),
			}),
		);
		await garbage.guard.ready;
		garbage.send(`mail ${EMAIL}`);
		await expect.poll(() => garbage.sent).toEqual(["mail [EMAIL_1_t3st]"]);
		const failing = loadPage(
			workerRuntime(store, {
				load: () => {
					throw new Error("worker asleep");
				},
			}),
		);
		await failing.guard.ready;
		expect(failing.guard.policy()).not.toBeNull();
	});

	it("extractVault accepts only a successful reply with a snapshot", () => {
		expect(extractVault(undefined)).toBeNull();
		expect(extractVault({ ok: false, error: "NOT_ALLOWED" })).toBeNull();
		expect(extractVault({ ok: true, snapshot: null, sent: [] })).toBeNull();
		const snapshot = { version: 1, createdAt: 1, entries: [] };
		expect(extractVault({ ok: true, snapshot, sent: ["[EMAIL_1_t3st]", 5] })).toEqual({
			snapshot,
			sent: ["[EMAIL_1_t3st]"],
		});
	});
});
