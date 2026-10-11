import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { normalize } from "../../../privacy/src/normalize.js";
import { createDetectionEngine } from "../engine/detect.js";
import {
	createExactDataMatcher,
	EXACT_DATA_MAX_HMACS,
	EXACT_DATA_MAX_TOKENS,
	ExactDataConfigError,
	exactDataTokens,
	fingerprintValue,
} from "../engine/exact-data.js";
import type { DetectionOptions, ExactDataSet, ScanResult } from "../types.js";

// 32 fixed test bytes; real keys are distributed by managed policy.
const KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i * 7 + 3)).toString("base64");
const OTHER_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => 255 - i)).toString("base64");

async function dataset(
	values: string[],
	overrides: Partial<ExactDataSet> = {},
): Promise<ExactDataSet> {
	const keyB64 = overrides.keyB64 ?? KEY;
	return {
		datasetId: "customers",
		keyB64,
		fingerprints: await Promise.all(values.map((v) => fingerprintValue(keyB64, v))),
		type: "PERSON",
		...overrides,
	};
}

function engineOptions(
	exactData: ExactDataSet[],
	overrides: Partial<DetectionOptions> = {},
): DetectionOptions {
	return {
		enabledEntities: [],
		literals: [],
		exactData,
		detectSignals: false,
		maxInputChars: 200_000,
		maxScanMs: 10_000,
		...overrides,
	};
}

const spans = (text: string, result: ScanResult) =>
	result.findings.map((f) => [f.type, text.slice(f.start, f.end), f.source]);

describe("exact-data fingerprints", () => {
	it("tokenises with NFKC, lowercasing, zero-width removal and Turkish i folding", () => {
		expect(exactDataTokens("Ahmet YILMAZ").map((t) => t.value)).toEqual(["ahmet", "yilmaz"]);
		expect(exactDataTokens("AHMET YıLMAZ").map((t) => t.value)).toEqual(["ahmet", "yilmaz"]);
		expect(exactDataTokens("İSTANBUL").map((t) => t.value)).toEqual(["istanbul"]);
		expect(exactDataTokens("Ah​met").map((t) => t.value)).toEqual(["ahmet"]);
		expect(exactDataTokens("ＡＢＣ-１２３").map((t) => t.value)).toEqual(["abc", "123"]);
	});

	it("keeps token offsets in the tokenised text", () => {
		const text = "x İSTANBUL, Kadıköy";
		const tokens = exactDataTokens(text);
		expect(tokens.map((t) => text.slice(t.start, t.end))).toEqual(["x", "İSTANBUL", "Kadıköy"]);
	});

	it("is HMAC-SHA256 over the JSON token sequence (interoperable with Node tooling)", async () => {
		const expected = createHmac("sha256", Buffer.from(KEY, "base64"))
			.update(JSON.stringify(["ahmet", "yilmaz"]))
			.digest("hex");
		expect(await fingerprintValue(KEY, "  Ahmet   YILMAZ ")).toBe(expected);
		expect(await fingerprintValue(KEY, "ahmet-yılmaz")).toBe(expected);
		expect(await fingerprintValue(OTHER_KEY, "Ahmet Yılmaz")).not.toBe(expected);
	});

	it("rejects values that are too short or too long to fingerprint", async () => {
		await expect(fingerprintValue(KEY, "ab")).rejects.toThrow(RangeError);
		await expect(fingerprintValue(KEY, "  -- ")).rejects.toThrow(RangeError);
		const long = Array.from({ length: EXACT_DATA_MAX_TOKENS + 1 }, (_, i) => `w${i}`).join(" ");
		await expect(fingerprintValue(KEY, long)).rejects.toThrow(RangeError);
	});

	it("refuses a managed dataset over the 250,000-fingerprint capacity instead of truncating it", async () => {
		const good = await dataset(["Ahmet Yılmaz"]);
		const atLimit = Array.from({ length: 250_000 }, (_, i) => i.toString(16).padStart(64, "0"));
		expect(() => createExactDataMatcher([{ ...good, fingerprints: atLimit }])).not.toThrow();
		const over = [...atLimit, "f".repeat(64)];
		expect(() => createExactDataMatcher([{ ...good, fingerprints: over }])).toThrow(
			"EXACT_DATA_CAPACITY",
		);
		// Split across datasets the total still counts; the engine refuses to build (the guard then fails closed).
		expect(() =>
			createDetectionEngine(
				engineOptions([
					{ ...good, fingerprints: atLimit },
					{ ...good, datasetId: "second", fingerprints: ["e".repeat(64)] },
				]),
			),
		).toThrow("EXACT_DATA_CAPACITY");
	});

	it("rejects malformed keys, fingerprints and entity types", async () => {
		const good = await dataset(["Ahmet Yılmaz"]);
		expect(() => createExactDataMatcher([{ ...good, keyB64: "c2hvcnQ=" }])).toThrow(
			ExactDataConfigError,
		);
		expect(() => createExactDataMatcher([{ ...good, keyB64: "not base64!" }])).toThrow(
			ExactDataConfigError,
		);
		expect(() => createExactDataMatcher([{ ...good, fingerprints: ["abc"] }])).toThrow(
			ExactDataConfigError,
		);
		expect(() =>
			createExactDataMatcher([{ ...good, type: "NOPE" as ExactDataSet["type"] }]),
		).toThrow(ExactDataConfigError);
		expect(() => createExactDataMatcher([{ ...good, datasetId: " " }])).toThrow(
			ExactDataConfigError,
		);
		expect(() => createDetectionEngine(engineOptions([{ ...good, fingerprints: ["zz"] }]))).toThrow(
			ExactDataConfigError,
		);
	});
});

describe("exact-data matching in the detection engine", () => {
	it("finds a protected record regardless of case, spacing and Turkish letters", async () => {
		const engine = createDetectionEngine(
			engineOptions([await dataset(["Ahmet Yılmaz", "Zeynep Kaya"])]),
		);
		const text = "Müşteri AHMET   YILMAZ ve zeynep kaya bugün aradı.";
		const result = await engine.scan(text);
		expect(result.incomplete).toBe(false);
		expect(spans(text, result)).toEqual([
			["PERSON", "AHMET   YILMAZ", "exact-data"],
			["PERSON", "zeynep kaya", "exact-data"],
		]);
		expect(result.signals).toEqual(["EXACT_DATA_MATCH"]);
		expect(result.counts).toEqual({ PERSON: 2 });
	});

	it("reports the dataset's configured type even when that type is not enabled for rules", async () => {
		const set = await dataset(["ACME-CUST-004217"], { type: "INTERNAL", datasetId: "accounts" });
		const text = "account acme cust 004217 escalated";
		const result = await createDetectionEngine(engineOptions([set])).scan(text);
		expect(spans(text, result)).toEqual([["INTERNAL", "acme cust 004217", "exact-data"]]);
	});

	it("does not match partial records, other values or a different key", async () => {
		const engine = createDetectionEngine(engineOptions([await dataset(["Ahmet Yılmaz"])]));
		for (const text of ["Ahmet bugün aradı", "Mehmet Yılmaz aradı", "Ahmet Yılmazoğlu"]) {
			const result = await engine.scan(text);
			expect(result.findings, text).toEqual([]);
			expect(result.signals, text).toEqual([]);
			expect(result.incomplete).toBe(false);
		}
		const keyed = await dataset(["Ahmet Yılmaz"], { keyB64: OTHER_KEY });
		const other = createDetectionEngine(engineOptions([{ ...keyed, keyB64: KEY }]));
		expect((await other.scan("Ahmet Yılmaz")).findings).toEqual([]);
	});

	it("matches through zero-width characters and full-width letters", async () => {
		const engine = createDetectionEngine(engineOptions([await dataset(["Ahmet Yılmaz"])]));
		const text = "Ah​met ＹＩＬＭＡＺ";
		const result = await engine.scan(text);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]).toMatchObject({ start: 0, end: text.length, source: "exact-data" });
	});

	it("merges exact-data hits with rule findings", async () => {
		const set = await dataset(["Ahmet Yılmaz"]);
		const engine = createDetectionEngine(engineOptions([set], { enabledEntities: ["EMAIL"] }));
		const text = "Ahmet Yılmaz <ahmet@example.com>";
		const result = await engine.scan(text);
		expect(spans(text, result)).toEqual([
			["PERSON", "Ahmet Yılmaz", "exact-data"],
			["EMAIL", "ahmet@example.com", "rule"],
		]);
	});

	it("supports several datasets and keys at once", async () => {
		const people = await dataset(["Ahmet Yılmaz"]);
		const codes = await dataset(["Proje Kartal"], {
			datasetId: "codes",
			type: "INTERNAL",
			keyB64: OTHER_KEY,
		});
		const text = "Ahmet Yılmaz proje kartal için yazdı";
		const result = await createDetectionEngine(engineOptions([people, codes])).scan(text);
		expect(result.counts).toEqual({ PERSON: 1, INTERNAL: 1 });
	});

	it("bounds HMAC work per scan and marks larger inputs incomplete", async () => {
		const matcher = createExactDataMatcher([await dataset(["Ahmet Yılmaz"])]);
		// Unique tokens make every window distinct: tokens * 16 windows > 65536 HMACs.
		const words = Array.from({ length: 5000 }, (_, i) => `w${i.toString(36)}x`);
		const view = normalize(words.join(" "));
		const result = await matcher.scan([view], Number.POSITIVE_INFINITY);
		expect(result.incomplete).toBe(true);
		expect(EXACT_DATA_MAX_HMACS).toBe(65_536);
	});

	it("marks the scan incomplete when the deadline has passed", async () => {
		const matcher = createExactDataMatcher([await dataset(["Ahmet Yılmaz"])]);
		const result = await matcher.scan([normalize("Ahmet Yılmaz aradı")], performance.now() - 1);
		expect(result.incomplete).toBe(true);
	});

	it("returns an empty complete scan for no datasets", async () => {
		const result = await createExactDataMatcher([]).scan(
			[normalize("Ahmet Yılmaz")],
			Number.POSITIVE_INFINITY,
		);
		expect(result).toEqual({ hits: [], incomplete: false });
	});
});
