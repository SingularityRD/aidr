// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	bootContentGuard,
	detectionOptions,
	extractPolicy,
	type RuntimeLike,
} from "../content/boot";
import { formatCounts, resolveLanguage, STRINGS, totalCount } from "../content/strings";
import { createGuardUi, DISMISSED, type GuardUi } from "../content/ui";
import { editorAccess, isSyntheticEditorEvent } from "../dom/editor";
import { createVault } from "../engine/vault";
import type { GuardMessage, VaultSnapshot } from "../types";
import { ADAPTER, BASE_POLICY, EMAIL, fakeEngine } from "./content-helpers";

const booted: { guard: { stop(): void } }[] = [];

afterEach(() => {
	for (const b of booted.splice(0)) b.guard.stop();
	document.body.innerHTML = "";
	for (const host of document.querySelectorAll("[data-aidr-guard]")) host.remove();
});

describe("extractPolicy", () => {
	it("accepts a bare policy or { policy }", () => {
		expect(extractPolicy(BASE_POLICY)).toBe(BASE_POLICY);
		expect(extractPolicy({ policy: BASE_POLICY })).toBe(BASE_POLICY);
	});

	it("rejects malformed policies so the guard keeps failing closed", () => {
		expect(extractPolicy(null)).toBeNull();
		expect(extractPolicy("auto")).toBeNull();
		expect(extractPolicy({ ...BASE_POLICY, version: 2 })).toBeNull();
		expect(extractPolicy({ ...BASE_POLICY, mode: "yolo" })).toBeNull();
		expect(extractPolicy({ ...BASE_POLICY, disabledSites: "chatgpt" })).toBeNull();
		expect(extractPolicy({ ...BASE_POLICY, maskPaste: undefined })).toBeNull();
		expect(extractPolicy({ ...BASE_POLICY, signalAction: "maybe" })).toBeNull();
		expect(extractPolicy({ ...BASE_POLICY, fileHandling: undefined })).toBeNull();
		expect(extractPolicy({ ...BASE_POLICY, maxFileBytes: Number.NaN })).toBeNull();
	});

	it("maps the policy to detection options with engine limits", () => {
		expect(detectionOptions(BASE_POLICY)).toMatchObject({
			enabledEntities: ["EMAIL"],
			detectSignals: true,
			maxInputChars: 200_000,
			maxScanMs: 1_000,
		});
	});
});

function fakeRuntime(responses: unknown[]): RuntimeLike & {
	listeners: ((message: unknown, sender: { id?: string }) => void)[];
	sendMessage: ReturnType<typeof vi.fn>;
} {
	const listeners: ((message: unknown, sender: { id?: string }) => void)[] = [];
	return {
		id: "ext-id",
		listeners,
		sendMessage: vi.fn(async (message: GuardMessage) => {
			if (message.type !== "GET_POLICY") return undefined;
			const next = responses.shift();
			if (next instanceof Error) throw next;
			return next;
		}),
		onMessage: { addListener: (listener) => listeners.push(listener) },
	};
}

function boot(runtime: ReturnType<typeof fakeRuntime>) {
	document.body.innerHTML = '<textarea id="editor"></textarea>';
	const editor = document.getElementById("editor") as HTMLTextAreaElement;
	const sent: string[] = [];
	editor.addEventListener("keydown", (event) => {
		if (event.key === "Enter") {
			event.preventDefault();
			sent.push(editor.value);
		}
	});
	const createVaultSpy = vi.fn(
		(options: {
			neverRestore: readonly never[] | readonly string[];
			snapshot?: VaultSnapshot;
			tag?: string;
		}) =>
			createVault(options as Parameters<typeof createVault>[0]),
	);
	const result = bootContentGuard({
		window,
		document,
		url: "https://chatgpt.com/c/1",
		runtime,
		adapterForUrl: () => ADAPTER,
		createDetectionEngine: () => fakeEngine(),
		createVault: createVaultSpy,
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
	});
	booted.push(result);
	const enter = () =>
		editor.dispatchEvent(
			new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }),
		);
	return { booted: result, editor, sent, enter, createVaultSpy };
}

describe("bootContentGuard", () => {
	it("fails closed until GET_POLICY succeeds, retrying through worker errors", async () => {
		const runtime = fakeRuntime([
			new Error("worker asleep"),
			{ bogus: true },
			{ policy: BASE_POLICY },
		]);
		const { booted, editor, sent, enter } = boot(runtime);
		editor.value = "hello";
		enter();
		expect(sent).toEqual([]); // blocked: no policy yet
		await booted.ready;
		const policyCalls = runtime.sendMessage.mock.calls.filter(([m]) => m.type === "GET_POLICY");
		expect(policyCalls).toHaveLength(3);
		expect(booted.policy()).toBe(BASE_POLICY);
		enter();
		await expect.poll(() => sent).toEqual(["hello"]);
		booted.guard.stop();
	});

	it("masks through the real vault and reports counts via runtime.sendMessage", async () => {
		const runtime = fakeRuntime([BASE_POLICY]);
		const { booted, editor, sent, enter } = boot(runtime);
		await booted.ready;
		editor.value = `to ${EMAIL}`;
		enter();
		await expect.poll(() => sent).toEqual(["to [EMAIL_1_t3st]"]);
		const records = runtime.sendMessage.mock.calls
			.map(([m]) => m as GuardMessage)
			.filter((m) => m.type === "RECORD");
		expect(records).toEqual([
			{
				type: "RECORD",
				site: "chatgpt",
				action: "masked",
				channel: "prompt",
				counts: { EMAIL: 1 },
			},
		]);
		booted.guard.stop();
	});

	it("applies POLICY_CHANGED only from the extension itself and keeps placeholders across vault rebuilds", async () => {
		const runtime = fakeRuntime([BASE_POLICY]);
		const { booted, editor, sent, enter, createVaultSpy } = boot(runtime);
		await booted.ready;
		editor.value = `to ${EMAIL}`;
		enter();
		await expect.poll(() => sent).toHaveLength(1);

		const monitor = { ...BASE_POLICY, mode: "monitor" as const };
		for (const listener of runtime.listeners)
			listener({ type: "POLICY_CHANGED", policy: monitor }, { id: "evil" });
		expect(booted.policy()?.mode).toBe("auto");

		const changed = {
			...BASE_POLICY,
			mode: "block" as const,
			neverRestore: ["SECRET", "IBAN"] as const,
		};
		for (const listener of runtime.listeners) {
			listener({ type: "POLICY_CHANGED", policy: changed }, { id: "ext-id" });
		}
		expect(booted.policy()?.mode).toBe("block");
		expect(createVaultSpy).toHaveBeenCalledTimes(3); // initial, first policy, neverRestore change
		const lastCall = createVaultSpy.mock.calls.at(-1)?.[0];
		expect(lastCall?.snapshot?.entries.map((e) => e.placeholder)).toEqual(["[EMAIL_1_t3st]"]);

		for (const listener of runtime.listeners) {
			listener({ type: "SET_RESTORE_VISIBLE", visible: false }, { id: "ext-id" });
		}
		expect(booted.guard.unmasker.visible).toBe(false);
		booted.guard.stop();
	});
});

describe("guard UI", () => {
	const make = (): GuardUi =>
		createGuardUi({ document, window, strings: () => STRINGS.en, toastMs: 10_000 });

	it("renders a status toast in a closed shadow root", () => {
		const ui = make();
		ui.toast("3 items masked");
		const host = document.querySelector("[data-aidr-guard]") as HTMLElement;
		expect(host).toBe(ui.host);
		expect(host.shadowRoot).toBeNull(); // closed
		const toast = ui.root.querySelector('[role="status"]') as HTMLElement;
		expect(toast.hidden).toBe(false);
		expect(toast.getAttribute("aria-live")).toBe("polite");
		expect(toast.textContent).toBe("AIDR3 items masked");
		expect(ui.root.querySelector("style")?.textContent).toContain("#3862E8");
		expect(ui.root.querySelector("style")?.textContent).toContain("prefers-color-scheme: dark");
		ui.destroy();
	});

	it("is an accessible alertdialog with focus management, Tab loop and Escape", async () => {
		const outside = document.createElement("button");
		document.body.append(outside);
		outside.focus();
		const ui = make();
		const choice = ui.bubble({
			title: "Check",
			lines: ["line one"],
			actions: [
				{ id: "a", label: "A", primary: true },
				{ id: "b", label: "B" },
			],
			tone: "warn",
		});
		const dialog = ui.root.querySelector('[role="alertdialog"]') as HTMLElement;
		expect(dialog.getAttribute("aria-labelledby")).toBeTruthy();
		expect(
			ui.root.getElementById(dialog.getAttribute("aria-labelledby") as string)?.textContent,
		).toContain("Check");
		const [a, b] = [...dialog.querySelectorAll("button")];
		expect(ui.root.activeElement).toBe(a);
		dialog.dispatchEvent(
			new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true }),
		);
		expect(ui.root.activeElement).toBe(b);
		dialog.dispatchEvent(
			new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true }),
		);
		expect(ui.root.activeElement).toBe(a);
		dialog.dispatchEvent(
			new KeyboardEvent("keydown", { key: "Tab", shiftKey: true, bubbles: true, cancelable: true }),
		);
		expect(ui.root.activeElement).toBe(b);
		dialog.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
		await expect(choice).resolves.toBe(DISMISSED);
		expect(ui.bubbleOpen).toBe(false);
		expect(document.activeElement).toBe(outside);
		ui.destroy();
	});

	it("resolves with the clicked action and treats events inside it as its own", async () => {
		const ui = make();
		const choice = ui.bubble({
			title: "t",
			lines: [],
			actions: [{ id: "go", label: "Go" }],
			tone: "info",
		});
		const button = ui.root.querySelector("button") as HTMLButtonElement;
		let own = false;
		button.addEventListener("click", (event) => {
			own = ui.isOwnEvent(event);
		});
		button.click();
		await expect(choice).resolves.toBe("go");
		expect(own).toBe(true);
		ui.destroy();
	});
});

describe("strings", () => {
	it("picks the language from policy, then navigator", () => {
		expect(resolveLanguage("tr", "en-US")).toBe("tr");
		expect(resolveLanguage("en", "tr-TR")).toBe("en");
		expect(resolveLanguage("auto", "tr-TR")).toBe("tr");
		expect(resolveLanguage("auto", undefined)).toBe("en");
	});

	it("formats counts with placeholder prefixes in canonical order", () => {
		const counts = { TC_KIMLIK: 1, EMAIL: 2 } as const;
		expect(formatCounts(counts)).toBe("2 EMAIL, 1 TCKN");
		expect(totalCount(counts)).toBe(3);
		expect(STRINGS.en.maskedToast(3, "2 EMAIL, 1 TCKN")).toBe("3 items masked: 2 EMAIL, 1 TCKN");
		expect(STRINGS.en.maskedToast(1, "1 EMAIL")).toBe("1 item masked: 1 EMAIL");
	});

	it("has every English key translated to Turkish", () => {
		expect(Object.keys(STRINGS.tr).sort()).toEqual(Object.keys(STRINGS.en).sort());
	});
});
