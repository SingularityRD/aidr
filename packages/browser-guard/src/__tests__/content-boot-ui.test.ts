// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	bootContentGuard,
	detectionOptions,
	extractPolicy,
	type RuntimeLike,
} from "../content/boot";
import {
	exampleLabel,
	formatCounts,
	resolveLanguage,
	STRINGS,
	totalCount,
} from "../content/strings";
import { createGuardUi, DISMISSED, type GuardUi, toastLifetime } from "../content/ui";
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
		}) => createVault(options as Parameters<typeof createVault>[0]),
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
		expect(toast.querySelector(".msg")?.textContent).toBe("Singularity AIDR3 items masked");
		// The brand keeps its English casing under a Turkish page (no "SİNGULARİTY").
		const brand = toast.querySelector(".brand") as HTMLElement;
		expect(brand.lang).toBe("en");
		expect(ui.root.querySelector("style")?.textContent).not.toContain("text-transform");
		expect(ui.root.querySelector("style")?.textContent).toContain("#3862E8");
		expect(ui.root.querySelector("style")?.textContent).toContain("prefers-color-scheme: dark");
		ui.destroy();
	});

	it("keeps a toast up for a time that grows with its length (5 s to 20 s)", () => {
		expect(toastLifetime("short")).toBe(5_000);
		expect(toastLifetime("x".repeat(150))).toBe(9_000);
		expect(toastLifetime("x".repeat(1_000))).toBe(20_000);
		vi.useFakeTimers();
		try {
			const ui = createGuardUi({ document, window, strings: () => STRINGS.en });
			const message = "x".repeat(150);
			ui.toast(message);
			const toast = ui.root.querySelector(".toast") as HTMLElement;
			vi.advanceTimersByTime(8_900);
			expect(toast.hidden).toBe(false);
			vi.advanceTimersByTime(200);
			expect(toast.hidden).toBe(true);
			ui.destroy();
		} finally {
			vi.useRealTimers();
		}
	});

	it("pauses a toast while hovered or focused and resumes when left", () => {
		vi.useFakeTimers();
		try {
			const ui = createGuardUi({ document, window, strings: () => STRINGS.en });
			ui.toast("hello");
			const toast = ui.root.querySelector(".toast") as HTMLElement;
			vi.advanceTimersByTime(4_000);
			toast.dispatchEvent(new MouseEvent("mouseenter"));
			vi.advanceTimersByTime(60_000);
			expect(toast.hidden).toBe(false);
			toast.dispatchEvent(new MouseEvent("mouseleave"));
			vi.advanceTimersByTime(1_900);
			expect(toast.hidden).toBe(false);
			vi.advanceTimersByTime(200);
			expect(toast.hidden).toBe(true);

			ui.toast("again");
			const close = toast.querySelector("button") as HTMLButtonElement;
			close.focus();
			vi.advanceTimersByTime(60_000);
			expect(toast.hidden).toBe(false);
			ui.destroy();
		} finally {
			vi.useRealTimers();
		}
	});

	it("closes a toast with its labelled close button or Escape, and alerts on errors", () => {
		const ui = make();
		ui.toast("one");
		const toast = ui.root.querySelector(".toast") as HTMLElement;
		const close = toast.querySelector("button") as HTMLButtonElement;
		expect(close.getAttribute("aria-label")).toBe("Close");
		close.click();
		expect(toast.hidden).toBe(true);

		ui.toast("two", "error");
		expect(toast.getAttribute("role")).toBe("alert");
		expect(toast.getAttribute("aria-live")).toBe("assertive");
		const pageKeys = vi.fn();
		document.addEventListener("keydown", pageKeys);
		toast.dispatchEvent(
			new KeyboardEvent("keydown", { key: "Escape", bubbles: true, composed: true }),
		);
		expect(toast.hidden).toBe(true);
		expect(pageKeys).not.toHaveBeenCalled();
		document.removeEventListener("keydown", pageKeys);

		ui.toast("three");
		expect(toast.getAttribute("role")).toBe("status");
		ui.destroy();
	});

	it("shows a toastWhenIdle message only after the current toast is gone", () => {
		const ui = make();
		ui.toast("first");
		ui.toastWhenIdle("legend");
		const toast = ui.root.querySelector(".toast") as HTMLElement;
		expect(toast.textContent).toContain("first");
		(toast.querySelector("button") as HTMLButtonElement).click();
		expect(toast.hidden).toBe(false);
		expect(toast.textContent).toContain("legend");
		ui.destroy();
	});

	it("renders a footnote under the buttons and describes the dialog with it", () => {
		const ui = make();
		void ui.bubble({
			title: "t",
			lines: ["body"],
			actions: [{ id: "go", label: "Go" }],
			tone: "warn",
			footnote: "What Go means",
		});
		const dialog = ui.root.querySelector('[role="alertdialog"]') as HTMLElement;
		const note = dialog.lastElementChild as HTMLElement;
		expect(note.textContent).toBe("What Go means");
		expect(note.previousElementSibling?.className).toBe("actions");
		expect(dialog.getAttribute("aria-describedby")?.split(" ")).toContain(note.id);
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

	it("names the data in plain words, in canonical order", () => {
		const counts = { TC_KIMLIK: 1, EMAIL: 2, IBAN: 1, PHONE: 1 } as const;
		expect(formatCounts(counts, "en")).toBe(
			"2 email addresses, 1 phone number, 1 Turkish ID number (TCKN), 1 IBAN",
		);
		expect(formatCounts(counts, "tr")).toBe(
			"2 e-posta adresi, 1 telefon numarası, 1 T.C. kimlik numarası, 1 IBAN",
		);
		expect(totalCount(counts)).toBe(5);
		expect(exampleLabel(counts)).toBe("[EMAIL_1]");
		expect(exampleLabel({ TC_KIMLIK: 1 })).toBe("[TCKN_1]");
		expect(STRINGS.en.maskedToast("1 IBAN")).toBe("Masked before sending: 1 IBAN.");
	});

	it("explains the confirm choices in plain words (audit wording)", () => {
		const summary = formatCounts({ TC_KIMLIK: 1, IBAN: 1 }, "tr");
		expect(STRINGS.tr.confirmTitle).toBe("Mesajınızda kişisel veya gizli bilgi var");
		expect(STRINGS.en.confirmTitle).toBe("Your message contains personal or confidential data");
		expect(STRINGS.tr.confirmBody(summary, "[TCKN_1]", true)).toBe(
			'Bulunanlar: 1 T.C. kimlik numarası, 1 IBAN. "Maskeli gönder" bunları, mesaj bilgisayarınızdan çıkmadan önce [TCKN_1] gibi etiketlerle değiştirir; yanıtta gerçek değerler yalnızca bu bilgisayarda yeniden gösterilir.',
		);
		expect(STRINGS.en.confirmBody("1 IBAN", "[IBAN_1]", false)).not.toContain("answer");
		expect(STRINGS.en.sendOriginalNote("ChatGPT")).toBe(
			'"Send original" sends the real values to ChatGPT. This choice is counted; the message itself is never reported.',
		);
		expect(STRINGS.tr.sendOriginalNote(null)).toContain("bu yapay zekâ hizmetine");
		// Telemetry is counts-only (docs/contracts/privacy-telemetry.md): never "recorded".
		for (const lang of ["en", "tr"] as const) {
			expect(STRINGS[lang].sendOriginalNote("ChatGPT")).not.toMatch(/record|kaydedil/i);
		}
	});

	it("uses plain words: no prompt/istem, placeholder/yer tutucu, and the full brand", () => {
		for (const lang of ["en", "tr"] as const) {
			const s = STRINGS[lang];
			expect(s.brand).toBe("Singularity AIDR");
			const text = Object.values(s)
				.map((v) => (typeof v === "function" ? v("X", "[EMAIL_1]", true) : String(v)))
				.join("\n");
			expect(text).not.toMatch(/\bprompt\b|\bistem|yer tutucu|placeholder/i);
		}
	});

	it("has every English key translated to Turkish", () => {
		expect(Object.keys(STRINGS.tr).sort()).toEqual(Object.keys(STRINGS.en).sort());
	});
});
