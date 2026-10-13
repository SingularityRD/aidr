// @vitest-environment jsdom
/**
 * policy.requireNativeNer (managed): native NER must take part in every prompt, paste and
 * upload check. Any outcome other than "used" (host off, crash, timeout, rules-only host,
 * malformed reply, text over NATIVE_MAX_CHARS) blocks with a clear reason and is recorded
 * as `native: "unavailable"`, never as a clean check. Without the flag the guard keeps
 * today's degraded-but-warned rules-only behaviour. The worker's bridge is faked through
 * the guard's `send` dependency.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { NATIVE_MAX_CHARS, nativeNerRequired } from "../content/guard";
import { type SanitizeDeps, sanitizeFile } from "../engine/files.js";
import type { Finding, GuardMessage, GuardPolicy } from "../types";
import {
	BASE_POLICY,
	EMAIL,
	FakeDataTransfer,
	type Harness,
	makeFilesWritable,
	readText,
	setupGuard,
} from "./content-helpers";

let h: Harness | undefined;
const scope = window as unknown as Record<string, unknown>;

beforeEach(() => {
	scope.DataTransfer = FakeDataTransfer;
});

afterEach(() => {
	h?.guard.stop();
	h = undefined;
	document.body.innerHTML = "";
	delete scope.DataTransfer;
});

const NAME = "Ada Lovelace";
const REQUIRED = {
	useNativeHost: true,
	requireNativeNer: true,
	enabledEntities: ["EMAIL", "PERSON"],
} as const;
const OPTIONAL = { useNativeHost: true, enabledEntities: ["EMAIL", "PERSON"] } as const;
const BLOCK_REASON = "requires the AIDR Privacy helper app";

/** A working NER host: a PERSON span for every occurrence of NAME. */
function personBridge(message: GuardMessage): unknown {
	if (message.type !== "NATIVE_SCAN") return undefined;
	const findings: Finding[] = [];
	for (let at = message.text.indexOf(NAME); at >= 0; at = message.text.indexOf(NAME, at + 1)) {
		findings.push({
			type: "PERSON",
			start: at,
			end: at + NAME.length,
			score: 0.9,
			source: "native-ner",
		});
	}
	return { ok: true, findings, status: "connected" };
}

/** Worker replies for the ways the host can fail to give a NER answer. */
const FAILURES: ReadonlyArray<[string, (m: GuardMessage) => unknown, number?]> = [
	// Host not installed / permission missing / bridge disabled: the worker answers findings null.
	[
		"host off",
		(m) =>
			m.type === "NATIVE_SCAN" ? { ok: true, findings: null, status: "unavailable" } : undefined,
	],
	// The worker (or its bridge) throws: the message channel rejects.
	[
		"crash",
		(m) => (m.type === "NATIVE_SCAN" ? Promise.reject(new Error("host crashed")) : undefined),
	],
	// The host never answers: bounded by nativeTimeoutMs.
	["timeout", (m) => (m.type === "NATIVE_SCAN" ? new Promise(() => undefined) : undefined), 20],
	// A rules-only host: the worker's bridge maps a non-NER coverage answer to findings null.
	[
		"rules-only host",
		(m) =>
			m.type === "NATIVE_SCAN" ? { ok: true, findings: null, status: "connected" } : undefined,
	],
	// A malformed reply.
	[
		"malformed reply",
		(m) => (m.type === "NATIVE_SCAN" ? { ok: true, findings: "junk" } : undefined),
	],
	[
		"error reply",
		(m) => (m.type === "NATIVE_SCAN" ? { ok: false, error: "BAD_MESSAGE" } : undefined),
	],
];

function start(
	policy: Partial<GuardPolicy>,
	respond: (m: GuardMessage) => unknown,
	nativeTimeoutMs?: number,
	extra: Parameters<typeof setupGuard>[0] = {},
): Harness {
	h = setupGuard({ policy, respond, ...(nativeTimeoutMs ? { nativeTimeoutMs } : {}), ...extra });
	return h;
}

function pasteText(g: Harness, text: string): void {
	const event = new Event("paste", { bubbles: true, cancelable: true });
	Object.defineProperty(event, "clipboardData", {
		value: { getData: () => text, files: [], items: [] },
	});
	g.editor.dispatchEvent(event);
}

const realSanitizer = {
	sanitizeFile: (file: Parameters<typeof sanitizeFile>[0], deps: unknown) =>
		sanitizeFile(file, deps as SanitizeDeps),
};

describe("nativeNerRequired", () => {
	it("needs the flag and at least one NER entity type", () => {
		expect(nativeNerRequired(null)).toBe(false);
		expect(nativeNerRequired({ ...BASE_POLICY, ...OPTIONAL })).toBe(false);
		expect(nativeNerRequired({ ...BASE_POLICY, ...REQUIRED })).toBe(true);
		expect(
			nativeNerRequired({ ...BASE_POLICY, requireNativeNer: true, enabledEntities: ["EMAIL"] }),
		).toBe(false);
	});
});

describe("content guard: requireNativeNer, prompts", () => {
	for (const [name, respond, timeout] of FAILURES) {
		it(`blocks the send when the native host gives no NER answer (${name})`, async () => {
			const g = start(REQUIRED, respond, timeout);
			g.editor.value = `Write to ${NAME} at ${EMAIL}`;
			const event = g.enter();
			expect(event.defaultPrevented).toBe(true);
			await expect.poll(() => g.bubble()?.textContent ?? "").toContain(BLOCK_REASON);
			expect(g.sent).toEqual([]);
			expect(g.editor.value).toBe(`Write to ${NAME} at ${EMAIL}`);
			expect(g.records().at(-1)).toMatchObject({
				action: "blocked",
				channel: "prompt",
				native: "unavailable",
				counts: { EMAIL: 1 },
			});
		});
	}

	it("blocks a prompt over NATIVE_MAX_CHARS without sending it to the host", async () => {
		const g = start(REQUIRED, personBridge);
		g.editor.value = "a".repeat(NATIVE_MAX_CHARS + 1);
		g.enter();
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain(BLOCK_REASON);
		expect(g.messages.filter((m) => m.type === "NATIVE_SCAN")).toEqual([]);
		expect(g.sent).toEqual([]);
		expect(g.records().at(-1)).toMatchObject({ action: "blocked", native: "unavailable" });
	});

	it("blocks a clean prompt too: no findings is not a clean check without NER", async () => {
		const g = start(REQUIRED, FAILURES[0]?.[1] as (m: GuardMessage) => unknown);
		g.editor.value = "hello there";
		g.enter();
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain(BLOCK_REASON);
		expect(g.sent).toEqual([]);
		expect(g.records().at(-1)).toMatchObject({ action: "blocked", counts: {} });
	});

	it("does not reuse a pre-scan the host did not answer: the send asks again", async () => {
		let up = false;
		const g = start(REQUIRED, (m) => (up ? personBridge(m) : FAILURES[0]?.[1](m)), undefined, {
			prescanDelayMs: 0,
		});
		g.editor.value = `Hi ${NAME}`;
		g.editor.dispatchEvent(new Event("input", { bubbles: true }));
		await expect.poll(() => g.messages.filter((m) => m.type === "NATIVE_SCAN").length).toBe(1);
		up = true;
		g.enter();
		await expect.poll(() => g.sent).toEqual(["Hi [PERSON_1]"]);
		expect(g.records().at(-1)).toMatchObject({ action: "masked", native: "used" });
	});

	it("masks and sends when the host answers, recording native: used", async () => {
		const g = start(REQUIRED, personBridge);
		g.editor.value = `Write to ${NAME} at ${EMAIL}`;
		g.enter();
		await expect.poll(() => g.sent).toEqual(["Write to [PERSON_1] at [EMAIL_1]"]);
		expect(g.records().at(-1)).toMatchObject({ action: "masked", native: "used" });
	});

	it("does not apply when no NER entity type is enabled", async () => {
		const g = start(
			{ ...REQUIRED, enabledEntities: ["EMAIL"] },
			FAILURES[0]?.[1] as (m: GuardMessage) => unknown,
		);
		g.editor.value = "hello there";
		g.enter();
		await expect.poll(() => g.sent).toEqual(["hello there"]);
		expect(g.messages.filter((m) => m.type === "NATIVE_SCAN")).toEqual([]);
	});

	it("monitor mode never blocks but records the check as not NER-checked", async () => {
		const g = start(
			{ ...REQUIRED, mode: "monitor" },
			FAILURES[0]?.[1] as (m: GuardMessage) => unknown,
		);
		g.editor.value = "hello there";
		const event = g.enter();
		expect(event.defaultPrevented).toBe(true); // the site's own handler sent it
		expect(g.sent).toEqual(["hello there"]);
		await expect
			.poll(() => g.records().at(-1))
			.toMatchObject({
				action: "allowed",
				channel: "prompt",
				native: "unavailable",
			});
	});

	it("optional policy keeps the degraded-but-warned rules-only behaviour", async () => {
		const g = start(OPTIONAL, FAILURES[0]?.[1] as (m: GuardMessage) => unknown);
		g.editor.value = `Write to ${NAME} at ${EMAIL}`;
		g.enter();
		await expect.poll(() => g.sent).toEqual([`Write to ${NAME} at [EMAIL_1]`]);
		expect(g.toastText()).toContain("checked with built-in rules only");
		expect(g.bubble()).toBeNull();
		expect(g.records().at(-1)).toMatchObject({ action: "masked", native: "unavailable" });
	});

	it("optional policy over NATIVE_MAX_CHARS still sends rules-only", async () => {
		const g = start(OPTIONAL, personBridge);
		g.editor.value = "a".repeat(NATIVE_MAX_CHARS + 1);
		g.enter();
		await expect.poll(() => g.sent).toHaveLength(1);
		expect(g.toastText()).toContain("built-in rules only");
	});
});

describe("content guard: requireNativeNer, pastes", () => {
	for (const [name, respond, timeout] of FAILURES) {
		it(`blocks the paste when the native host gives no NER answer (${name})`, async () => {
			const g = start(REQUIRED, respond, timeout);
			pasteText(g, `Customer ${NAME}`);
			await expect.poll(() => g.bubble()?.textContent ?? "").toContain(BLOCK_REASON);
			expect(g.editor.value).toBe("");
			expect(g.records().at(-1)).toMatchObject({
				action: "blocked",
				channel: "paste",
				native: "unavailable",
			});
		});
	}

	it("blocks a paste over NATIVE_MAX_CHARS", async () => {
		const g = start(REQUIRED, personBridge);
		pasteText(g, "b".repeat(NATIVE_MAX_CHARS + 1));
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain(BLOCK_REASON);
		expect(g.editor.value).toBe("");
	});

	it("masks the paste when the host answers", async () => {
		const g = start(REQUIRED, personBridge);
		pasteText(g, `Customer ${NAME}`);
		await expect.poll(() => g.editor.value).toBe("Customer [PERSON_1]");
		expect(g.records().at(-1)).toMatchObject({ action: "masked", native: "used" });
	});

	it("optional policy inserts the paste rules-only with a warning", async () => {
		const g = start(OPTIONAL, FAILURES[0]?.[1] as (m: GuardMessage) => unknown);
		pasteText(g, `Customer ${NAME}`);
		await expect.poll(() => g.editor.value).toBe(`Customer ${NAME}`);
		expect(g.toastText()).toContain("built-in rules only");
	});
});

describe("content guard: requireNativeNer, uploads", () => {
	function upload(g: Harness, file: File): Event[] {
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [file]);
		const replayed: Event[] = [];
		input.addEventListener("change", (event) => replayed.push(event));
		input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
		return replayed;
	}

	for (const [name, respond, timeout] of FAILURES) {
		it(`blocks a text upload the native host did not check (${name})`, async () => {
			const g = start(REQUIRED, respond, timeout, realSanitizer);
			const replayed = upload(
				g,
				new File([`Customer ${NAME}`], "notes.txt", { type: "text/plain" }),
			);
			await expect
				.poll(() => g.bubble()?.textContent ?? "")
				.toContain("requires the AIDR Privacy helper app to check uploads");
			expect(g.bubble()?.textContent).toContain(BLOCK_REASON);
			expect(g.records().at(-1)).toMatchObject({
				action: "blocked",
				channel: "file",
				native: "unavailable",
			});
			expect(replayed).toHaveLength(0);
		});
	}

	it("asks the host only once per upload after it failed", async () => {
		const g = start(REQUIRED, FAILURES[2]?.[1] as (m: GuardMessage) => unknown, 20, realSanitizer);
		const csv = `name,mail\n${Array.from({ length: 40 }, (_, i) => `${NAME} ${i},${EMAIL}`).join("\n")}`;
		upload(g, new File([csv], "people.csv", { type: "text/csv" }));
		await expect.poll(() => g.records().at(-1)?.action).toBe("blocked");
		expect(g.messages.filter((m) => m.type === "NATIVE_SCAN")).toHaveLength(1);
	});

	it("blocks a text upload over NATIVE_MAX_CHARS only if a NER window also fails", async () => {
		const g = start(REQUIRED, personBridge, undefined, realSanitizer);
		const big = `${"lorem ipsum ".repeat(Math.ceil(NATIVE_MAX_CHARS / 12))} ${NAME}`;
		const replayed = upload(g, new File([big], "big.txt", { type: "text/plain" }));
		// Over the host limit as a whole, but the sanitiser's smaller windows are NER-checked.
		await expect.poll(() => g.records().at(-1)?.action, { timeout: 10_000 }).toBe("masked");
		expect(g.records().at(-1)).toMatchObject({ native: "used", counts: { PERSON: 1 } });
		expect(replayed).toHaveLength(1);
		const input = document.getElementById("file") as HTMLInputElement;
		expect(await readText(input.files?.[0] as File)).toContain("[PERSON_1]");
	});

	it("masks native findings in an uploaded text file when the host answers", async () => {
		const g = start(REQUIRED, personBridge, undefined, realSanitizer);
		const replayed = upload(g, new File([`Customer ${NAME}`], "notes.txt", { type: "text/plain" }));
		await expect.poll(() => replayed.length).toBe(1);
		const input = document.getElementById("file") as HTMLInputElement;
		expect(await readText(input.files?.[0] as File)).toBe("Customer [PERSON_1]");
		expect(g.records().at(-1)).toMatchObject({ action: "masked", native: "used" });
	});

	it("blocks an image the host could not OCR", async () => {
		const g = start(
			REQUIRED,
			(m) => (m.type === "NATIVE_IMAGE_SCAN" ? { ok: true, inspection: null } : undefined),
			undefined,
			{ ...realSanitizer, nativeImageTimeoutMs: 20 },
		);
		const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]);
		upload(g, new File([png], "shot.png", { type: "image/png" }));
		await expect
			.poll(() => g.bubble()?.textContent ?? "")
			.toContain("requires the AIDR Privacy helper app to check uploads");
		expect(g.records().at(-1)).toMatchObject({ action: "blocked", native: "unavailable" });
	});

	it("blocks text pasted with files when the host gives no answer", async () => {
		const g = start(REQUIRED, FAILURES[0]?.[1] as (m: GuardMessage) => unknown, undefined, {
			sanitizeFile: async () => ({ action: "allow", counts: {}, reasons: [] }),
		});
		const event = new Event("paste", { bubbles: true, cancelable: true });
		const file = new File(["x"], "a.bin");
		Object.defineProperty(event, "clipboardData", {
			value: { getData: () => `Customer ${NAME}`, files: [file], items: [] },
		});
		g.editor.dispatchEvent(event);
		await expect
			.poll(() => g.bubble()?.textContent ?? "")
			.toContain("requires the AIDR Privacy helper app to check uploads");
		expect(g.records().at(-1)).toMatchObject({ action: "blocked", native: "unavailable" });
	});

	it("optional policy uploads rules-only, without asking the host for file text", async () => {
		const g = start(
			OPTIONAL,
			FAILURES[0]?.[1] as (m: GuardMessage) => unknown,
			undefined,
			realSanitizer,
		);
		const replayed = upload(g, new File([`Customer ${NAME}`], "notes.txt", { type: "text/plain" }));
		await expect.poll(() => replayed.length).toBe(1);
		expect(g.messages.filter((m) => m.type === "NATIVE_SCAN")).toEqual([]);
		expect(g.records().at(-1)).toMatchObject({ action: "allowed", channel: "file" });
		expect(g.records().at(-1)).not.toHaveProperty("native");
	});

	it("monitor mode passes the upload but records it as not NER-checked", async () => {
		const g = start(
			{ ...REQUIRED, mode: "monitor" },
			FAILURES[0]?.[1] as (m: GuardMessage) => unknown,
			undefined,
			realSanitizer,
		);
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [new File([`Customer ${NAME}`], "notes.txt", { type: "text/plain" })]);
		const change = new Event("change", { bubbles: true, cancelable: true });
		input.dispatchEvent(change);
		expect(change.defaultPrevented).toBe(false);
		await expect
			.poll(() => g.records().at(-1))
			.toMatchObject({
				action: "allowed",
				channel: "file",
				native: "unavailable",
			});
	});
});
