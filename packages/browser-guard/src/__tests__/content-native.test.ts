// @vitest-environment jsdom
/**
 * Native host NER in the content guard: NATIVE_SCAN is requested in parallel with the
 * rule engine when the policy enables it, its PERSON/ADDRESS/LOCATION findings are
 * merged before masking, and an unavailable host degrades to rules-only with a notice.
 * The worker's bridge is faked through the guard's `send` dependency.
 */
import { afterEach, describe, expect, it } from "vitest";
import { NATIVE_TIMEOUT_MS } from "../background/native";
import { mergeNativeFindings, NATIVE_MAX_CHARS, NATIVE_REPLY_TIMEOUT_MS } from "../content/guard";
import type { Finding, GuardMessage, ScanResult } from "../types";
import { EMAIL, type Harness, setupGuard } from "./content-helpers";

let h: Harness | undefined;

afterEach(() => {
	h?.guard.stop();
	h = undefined;
	document.body.innerHTML = "";
});

const NAME = "Ada Lovelace";
const NATIVE_POLICY = { useNativeHost: true, enabledEntities: ["EMAIL", "PERSON"] } as const;

/** A fake bridge: answers NATIVE_SCAN with a PERSON span for every occurrence of NAME. */
function personBridge(message: GuardMessage): unknown {
	if (message.type !== "NATIVE_SCAN") return undefined;
	const findings: Finding[] = [];
	let at = message.text.indexOf(NAME);
	while (at >= 0) {
		findings.push({
			type: "PERSON",
			start: at,
			end: at + NAME.length,
			score: 0.9,
			source: "native-ner",
		});
		at = message.text.indexOf(NAME, at + 1);
	}
	return { ok: true, findings, status: "connected" };
}

const nativeScans = (g: Harness) => g.messages.filter((m) => m.type === "NATIVE_SCAN");

describe("content guard: native NER", () => {
	it("merges native PERSON findings with rule findings before masking", async () => {
		const g = (h = setupGuard({ policy: NATIVE_POLICY, respond: personBridge }));
		g.editor.value = `Write to ${NAME} at ${EMAIL}`;
		g.enter();
		await expect.poll(() => g.sent).toEqual(["Write to [PERSON_1] at [EMAIL_1]"]);
		expect(nativeScans(g)).toEqual([{ type: "NATIVE_SCAN", text: `Write to ${NAME} at ${EMAIL}` }]);
		expect(g.toastText()).toContain("2 items masked");
		expect(g.toastText()).not.toContain("built-in rules only");
		expect(g.records().at(-1)).toMatchObject({ action: "masked", counts: { PERSON: 1, EMAIL: 1 } });
	});

	it("ignores native findings of types the policy does not enable, or outside the text", async () => {
		const g = (h = setupGuard({
			policy: { useNativeHost: true, enabledEntities: ["EMAIL", "PERSON"] },
			respond: (m) =>
				m.type === "NATIVE_SCAN"
					? {
							ok: true,
							findings: [
								{ type: "LOCATION", start: 0, end: 5, score: 0.9, source: "native-ner" },
								{ type: "EMAIL", start: 0, end: 5, score: 0.9, source: "native-ner" },
								{ type: "PERSON", start: 3, end: 999, score: 0.9, source: "native-ner" },
								{ type: "PERSON", start: 4, end: 2, score: 0.9, source: "native-ner" },
								"junk",
							],
						}
					: undefined,
		}));
		g.editor.value = "Paris is nice";
		g.enter();
		await expect.poll(() => g.sent).toEqual(["Paris is nice"]);
		expect(g.vault.size()).toBe(0);
	});

	it("does not ask the host when useNativeHost is off or no NER type is enabled", async () => {
		const off = (h = setupGuard({ respond: personBridge }));
		off.editor.value = `Write to ${NAME}`;
		off.enter();
		await expect.poll(() => off.sent).toEqual([`Write to ${NAME}`]);
		expect(nativeScans(off)).toEqual([]);
		off.guard.stop();

		const emailOnly = (h = setupGuard({
			policy: { useNativeHost: true, enabledEntities: ["EMAIL"] },
			respond: personBridge,
		}));
		emailOnly.editor.value = `Write to ${NAME}`;
		emailOnly.enter();
		await expect.poll(() => emailOnly.sent).toEqual([`Write to ${NAME}`]);
		expect(nativeScans(emailOnly)).toEqual([]);
		expect(emailOnly.toastText()).toBe("");
	});

	it("proceeds rules-only and says so when the host is unavailable", async () => {
		const g = (h = setupGuard({
			policy: NATIVE_POLICY,
			respond: (m) =>
				m.type === "NATIVE_SCAN" ? { ok: true, findings: null, status: "unavailable" } : undefined,
		}));
		g.editor.value = `Write to ${NAME} at ${EMAIL}`;
		g.enter();
		await expect.poll(() => g.sent).toEqual([`Write to ${NAME} at [EMAIL_1]`]);
		expect(g.toastText()).toContain("1 item masked");
		expect(g.toastText()).toContain("checked with built-in rules only");
	});

	it("times out a hanging host, sends a clean prompt and warns once", async () => {
		const g = (h = setupGuard({
			policy: NATIVE_POLICY,
			nativeTimeoutMs: 20,
			respond: (m) => (m.type === "NATIVE_SCAN" ? new Promise(() => undefined) : undefined),
		}));
		g.editor.value = "hello there";
		g.enter();
		await expect.poll(() => g.sent).toEqual(["hello there"]);
		expect(g.toastText()).toContain("built-in rules only");
		g.guard.ui.toast("", "info"); // clear
		g.editor.value = "hello again";
		g.enter();
		await expect.poll(() => g.sent).toEqual(["hello there", "hello again"]);
		expect(g.toastText()).not.toContain("built-in rules only");
	});

	it("does not send text longer than the host limit", async () => {
		const g = (h = setupGuard({ policy: NATIVE_POLICY, respond: personBridge }));
		g.editor.value = "a".repeat(NATIVE_MAX_CHARS + 1);
		g.enter();
		await expect.poll(() => g.sent).toHaveLength(1);
		expect(nativeScans(g)).toEqual([]);
		expect(g.toastText()).toContain("built-in rules only");
	});

	it("merges native findings into pasted text", async () => {
		const g = (h = setupGuard({ policy: NATIVE_POLICY, respond: personBridge }));
		const event = new Event("paste", { bubbles: true, cancelable: true });
		Object.defineProperty(event, "clipboardData", {
			value: { getData: () => `Customer ${NAME}`, files: [], items: [] },
		});
		g.editor.dispatchEvent(event);
		await expect.poll(() => g.editor.value).toBe("Customer [PERSON_1]");
		expect(g.records().at(-1)).toMatchObject({
			action: "masked",
			channel: "paste",
			counts: { PERSON: 1 },
		});
	});

	it("waits longer than the worker's own bridge deadline", () => {
		expect(NATIVE_REPLY_TIMEOUT_MS).toBeGreaterThan(NATIVE_TIMEOUT_MS);
	});
});

describe("mergeNativeFindings", () => {
	const rule = (type: Finding["type"], start: number, end: number): Finding => ({
		type,
		start,
		end,
		score: 0.99,
		source: "rule",
	});
	const base: ScanResult = {
		findings: [rule("ADDRESS", 10, 30)],
		signals: [],
		counts: { ADDRESS: 1 },
		incomplete: false,
		elapsedMs: 1,
	};

	it("drops native spans a finding already covers and keeps overlapping ones", () => {
		const merged = mergeNativeFindings(
			base,
			[
				{ type: "ADDRESS", start: 12, end: 20, score: 0.9, source: "native-ner" },
				{ type: "ADDRESS", start: 25, end: 40, score: 0.9, source: "native-ner" },
				{ type: "PERSON", start: 0, end: 5, score: Number.NaN, source: "native-ner" },
			],
			"used",
		);
		expect(merged.native).toBe("used");
		expect(merged.findings.map((f) => [f.type, f.start, f.end, f.source])).toEqual([
			["PERSON", 0, 5, "native-ner"],
			["ADDRESS", 10, 30, "rule"],
			["ADDRESS", 25, 40, "native-ner"],
		]);
		expect(merged.findings[0]?.score).toBe(0);
		expect(merged.counts).toEqual({ PERSON: 1, ADDRESS: 2 });
	});
});
