// @vitest-environment jsdom
/**
 * Findings that span one of our own vault placeholders (review regression): a labelled
 * field such as `Name: [EMAIL_1] John Smith` used to be dropped whole because it
 * overlapped the placeholder, so the rest of the sensitive text left the page in clear.
 * The placeholder is now cut out of the finding and every remaining sub-span is masked,
 * on the prompt, paste, pasted-file text and native NER paths.
 */
import { afterEach, describe, expect, it } from "vitest";
import { subtractPlaceholders } from "../content/guard";
import { createDetectionEngine } from "../engine/detect";
import { ENTITY_TYPES, type Finding, type GuardMessage } from "../types";
import {
	EMAIL,
	FakeDataTransfer,
	fakeEngine,
	type Harness,
	setupGuard,
} from "./content-helpers";

(window as unknown as { DataTransfer: unknown }).DataTransfer = FakeDataTransfer;

let h: Harness | undefined;

afterEach(() => {
	h?.guard.stop();
	h = undefined;
	document.body.innerHTML = "";
});

const realEngine = () =>
	createDetectionEngine({
		enabledEntities: [...ENTITY_TYPES],
		literals: [],
		exactData: [],
		detectSignals: false,
		maxInputChars: 200_000,
		maxScanMs: 5_000,
	});

const finding = (type: Finding["type"], start: number, end: number): Finding => ({
	type,
	start,
	end,
	score: 0.9,
	source: "rule",
});

/** Masks EMAIL once in the harness vault, as an earlier masked paste would have. */
const priorPlaceholder = (g: Harness): string =>
	g.vault.mask(EMAIL, [finding("EMAIL", 0, EMAIL.length)]).masked;

function pasteEvent(text: string): Event {
	const event = new Event("paste", { bubbles: true, cancelable: true });
	const data = new FakeDataTransfer();
	data.setData("text/plain", text);
	Object.defineProperty(event, "clipboardData", { value: data });
	return event;
}

describe("subtractPlaceholders", () => {
	it("keeps findings that do not touch a placeholder unchanged", () => {
		const f = finding("PERSON", 0, 4);
		expect(subtractPlaceholders("John [EMAIL_1]", [f], [[5, 14]])).toEqual([f]);
	});

	it("drops findings wholly inside a placeholder", () => {
		expect(subtractPlaceholders("[EMAIL_1]", [finding("EMAIL", 1, 8)], [[0, 9]])).toEqual([]);
	});

	it("masks the remainder after, before and around a placeholder, trimmed", () => {
		const text = "Name: [EMAIL_1] John Smith";
		expect(subtractPlaceholders(text, [finding("PERSON", 6, text.length)], [[6, 15]])).toEqual([
			finding("PERSON", 16, 26),
		]);
		const around = "Ada [EMAIL_1] Lovelace";
		expect(subtractPlaceholders(around, [finding("PERSON", 0, around.length)], [[4, 13]])).toEqual(
			[finding("PERSON", 0, 3), finding("PERSON", 14, 22)],
		);
	});

	it("drops remainders without a letter or digit and handles several placeholders", () => {
		const text = "[EMAIL_1], [EMAIL_2] x9";
		expect(
			subtractPlaceholders(
				text,
				[finding("ADDRESS", 0, text.length)],
				[
					[11, 20],
					[0, 9],
				],
			),
		).toEqual([finding("ADDRESS", 21, 23)]);
	});
});

describe("content guard: findings spanning an existing placeholder", () => {
	it("masks a labelled name and secret next to a placeholder (real engine, prompt path)", async () => {
		const real = realEngine();
		const g = (h = setupGuard({
			engine: fakeEngine(),
			policy: { enabledEntities: [...ENTITY_TYPES] },
		}));
		g.engine.scan.mockImplementation((text: string) => real.scan(text));
		const placeholder = priorPlaceholder(g);
		g.editor.value = `Name: ${placeholder} John Smith\npassword: ${placeholder} hunter2xyz`;
		g.enter();
		await expect.poll(() => g.sent.length, { timeout: 3_000 }).toBe(1);
		const sent = g.sent[0] as string;
		expect(sent).not.toContain("John Smith");
		expect(sent).not.toContain("hunter2xyz");
		// The earlier placeholder is kept as it was, never re-masked.
		expect(sent.split(placeholder).length - 1).toBe(2);
	});

	it("scans with this vault's placeholders blanked (offsets preserved), foreign ones kept", async () => {
		const g = (h = setupGuard());
		const placeholder = priorPlaceholder(g);
		g.editor.value = `a ${placeholder} b [EMAIL_77]`;
		g.enter();
		await expect.poll(() => g.sent.length).toBe(1);
		expect(g.engine.scan).toHaveBeenCalledWith(`a ${" ".repeat(placeholder.length)} b [EMAIL_77]`);
	});

	it("masks the remainder on the paste path", async () => {
		const g = (h = setupGuard());
		const placeholder = priorPlaceholder(g);
		const text = `Owner: ${placeholder} Jane Roe`;
		const at = text.indexOf(placeholder);
		g.engine.scan.mockImplementation(async (t: string) => ({
			findings: t.length === text.length ? [finding("PERSON", at, text.length)] : [],
			signals: [],
			counts: {},
			incomplete: false,
			elapsedMs: 1,
		}));
		g.editor.focus();
		g.editor.dispatchEvent(pasteEvent(text));
		await expect.poll(() => g.editor.value).toContain(placeholder);
		expect(g.editor.value).not.toContain("Jane Roe");
		expect(g.editor.value).toMatch(/\[PERSON_1(?:_[a-z0-9]{4})?\]/);
	});

	it("masks the remainder of a native NER finding", async () => {
		const respond = (message: GuardMessage): unknown => {
			if (message.type !== "NATIVE_SCAN") return undefined;
			const at = "Contact ".length;
			return {
				ok: true,
				findings: [
					{ type: "PERSON", start: at, end: message.text.length, score: 0.9, source: "native-ner" },
				],
			};
		};
		const g = (h = setupGuard({
			policy: { useNativeHost: true, enabledEntities: ["EMAIL", "PERSON"] },
			respond,
		}));
		const placeholder = priorPlaceholder(g);
		g.editor.value = `Contact ${placeholder} Ada Lovelace`;
		g.enter();
		await expect.poll(() => g.sent.length).toBe(1);
		expect(g.sent[0]).toBe(`Contact ${placeholder} [PERSON_1]`);
	});

	it("masks the remainder in text pasted together with files", async () => {
		const g = (h = setupGuard());
		const placeholder = priorPlaceholder(g);
		const text = `Sender: ${placeholder} Jane Roe`;
		const at = text.indexOf(placeholder);
		g.engine.scan.mockImplementation(async (t: string) => ({
			findings: t.length === text.length ? [finding("PERSON", at, text.length)] : [],
			signals: [],
			counts: {},
			incomplete: false,
			elapsedMs: 1,
		}));
		const event = new Event("paste", { bubbles: true, cancelable: true });
		const data = new FakeDataTransfer();
		data.setData("text/plain", text);
		data.items.add(new File(["hello"], "a.txt", { type: "text/plain" }));
		Object.defineProperty(event, "clipboardData", { value: data });
		let replayed = "";
		g.editor.addEventListener("paste", (e) => {
			const cd = (e as ClipboardEvent).clipboardData;
			if (cd && e !== event) replayed = cd.getData("text/plain");
		});
		g.editor.dispatchEvent(event);
		await expect.poll(() => replayed).not.toBe("");
		expect(replayed).toContain(placeholder);
		expect(replayed).not.toContain("Jane Roe");
	});
});
