import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { DEFAULT_POLICY } from "../background/policy.js";
import { createDetectionEngine } from "../engine/detect.js";
import {
	detectLabelled,
	validKvnr,
	validNhsNumber,
	validTurkishPlate,
} from "../engine/labelled.js";
import { type DetectionOptions, ENTITY_TYPES, type EntityType, type ScanResult } from "../types.js";
import { BENIGN_PROSE, BENIGN_SNIPPETS } from "./helpers/benign-corpus.js";

const LABELLED_TYPES: readonly EntityType[] = [
	"USERNAME",
	"HEALTH_ID",
	"LICENSE_PLATE",
	"LOCATION",
];

function options(overrides: Partial<DetectionOptions> = {}): DetectionOptions {
	return {
		enabledEntities: ENTITY_TYPES,
		literals: [],
		exactData: [],
		detectSignals: false,
		maxInputChars: 200_000,
		maxScanMs: 10_000,
		...overrides,
	};
}

async function scan(text: string, overrides: Partial<DetectionOptions> = {}): Promise<ScanResult> {
	return createDetectionEngine(options(overrides)).scan(text);
}

const spans = (text: string, result: ScanResult): Array<[EntityType, string]> =>
	result.findings.map((f) => [f.type, text.slice(f.start, f.end)]);

async function expectSpan(text: string, type: EntityType, value: string, overrides = {}) {
	const result = await scan(text, overrides);
	expect(result.incomplete).toBe(false);
	expect(spans(text, result)).toContainEqual([type, value]);
}

async function expectNone(text: string, type: EntityType, overrides = {}) {
	const result = await scan(text, overrides);
	expect(spans(text, result).filter(([t]) => t === type)).toEqual([]);
}

describe("labelled detectors: USERNAME", () => {
	const positives: Array<[string, string]> = [
		["Kullanıcı adı: ahmet.yilmaz42", "ahmet.yilmaz42"],
		["KULLANICI ADI = ayse_k", "ayse_k"],
		["Giriş adı: mehmet-01", "mehmet-01"],
		["username: jdoe_admin", "jdoe_admin"],
		["Please reset it. Login: jsmith, thanks", "jsmith"],
		["user_id=48213 tried again", "48213"],
	];
	for (const [text, value] of positives) {
		it(`finds ${JSON.stringify(value)} in ${JSON.stringify(text)}`, () =>
			expectSpan(text, "USERNAME", value));
	}

	const negatives = [
		"User: how do I reset my password?",
		"The login page is slow today.",
		"username: string",
		"login: failed after 3 attempts",
		"Kullanıcı adı: boş",
		"const user = { username: req.body.username };",
		"kullanıcı adınızı girin ve devam edin",
		"Enter your username and password.",
	];
	for (const text of negatives) {
		it(`ignores ${JSON.stringify(text)}`, () => expectNone(text, "USERNAME"));
	}

	it("reclassifies the privacy layer's contextual PERSON as USERNAME only when enabled", async () => {
		const text = "username: jdoe_admin";
		expect(spans(text, await scan(text))).toEqual([["USERNAME", "jdoe_admin"]]);
		// Default policy keeps USERNAME off; the value stays protected by the existing PERSON rule.
		const off = await scan(text, { enabledEntities: DEFAULT_POLICY.enabledEntities });
		expect(spans(text, off).map(([t]) => t)).not.toContain("USERNAME");
	});
});

describe("labelled detectors: HEALTH_ID", () => {
	const positives: Array<[string, string]> = [
		["SGK sicil no: 1234567890123", "1234567890123"],
		["Sağlık sigortası numarası: 12345678901", "12345678901"],
		["Hasta protokol no: 2026-004512 kayıtlı", "2026-004512"],
		["MEDULA takip no: 4KX91234", "4KX91234"],
		["Health insurance number: 80276001234567890123", "80276001234567890123"],
		["Patient ID: 55821 was admitted", "55821"],
		["MRN: 00731982", "00731982"],
		["NHS number: 943 476 5919", "943 476 5919"],
		["KVNR: A123456780", "A123456780"],
		["EHIC number = 80380000012345678901", "80380000012345678901"],
	];
	for (const [text, value] of positives) {
		it(`finds ${JSON.stringify(value)} in ${JSON.stringify(text)}`, () =>
			expectSpan(text, "HEALTH_ID", value));
	}

	const negatives = [
		"Hasta yarın taburcu olacak, 3 gün dinlenmeli.",
		"Health check passed in 1234 ms",
		"patient id field is required",
		"NHS number: 943 476 5918", // fails the mod-11 check
		"KVNR: A123456789", // fails the KVNR check
		"SGK sicil no: 12", // too short to be an identifier
		"Sağlık: iyi",
	];
	for (const text of negatives) {
		it(`ignores ${JSON.stringify(text)}`, () => expectNone(text, "HEALTH_ID"));
	}
});

describe("labelled detectors: LICENSE_PLATE", () => {
	const positives: Array<[string, string]> = [
		["Aracın plakası 34 ABC 123 olarak kayıtlı.", "34 ABC 123"],
		["06 AB 1234 plakalı araç", "06 AB 1234"],
		["Car 35 A 12345 was towed", "35 A 12345"],
		["Plaka: 06-AB-1234", "06-AB-1234"],
		["Plaka no: 34abc123", "34abc123"],
		["License plate: B-MW 1234", "B-MW 1234"],
		["Kennzeichen: M AB 1234", "M AB 1234"],
		["Registration plate: AB12 CDE", "AB12 CDE"],
	];
	for (const [text, value] of positives) {
		it(`finds ${JSON.stringify(value)} in ${JSON.stringify(text)}`, () =>
			expectSpan(text, "LICENSE_PLATE", value));
	}

	const negatives = [
		"16 GB 3200 MHz RAM is enough",
		"Meeting at 10 AM 2026 schedule",
		"Paid 12 TL 2500 kuruş",
		"99 ABC 123", // province 99 does not exist
		"34 ABQ 123", // Q is not on Turkish plates
		"34 AB 12", // two letters need three or four digits
		"34 abc 123 lowercase is not a plate without a label",
		"Order 34 ABC 123.45 total",
		"Plaka: yok",
		"license plate: unknown",
	];
	for (const text of negatives) {
		it(`ignores ${JSON.stringify(text)}`, () => expectNone(text, "LICENSE_PLATE"));
	}
});

describe("labelled detectors: LOCATION (no NER host)", () => {
	const positives: Array<[string, string]> = [
		["Konum: Kadıköy, İstanbul", "Kadıköy, İstanbul"],
		["Şehir: Ankara. Toplantı yarın.", "Ankara"],
		["Doğum yeri: İzmir", "İzmir"],
		["Location: San Francisco, CA", "San Francisco, CA"],
		["Place of birth: Rio de Janeiro", "Rio de Janeiro"],
		["city=Berlin", "Berlin"],
	];
	for (const [text, value] of positives) {
		it(`finds ${JSON.stringify(value)} in ${JSON.stringify(text)}`, () =>
			expectSpan(text, "LOCATION", value));
	}

	const negatives = [
		"Location: https://example.com/next",
		"location: eastus",
		"location: /api { proxy_pass http://backend; }",
		"Bu konuda konum belirtmedi.",
		"The city is lovely in spring.",
		"Profil: Admin",
	];
	for (const text of negatives) {
		it(`ignores ${JSON.stringify(text)}`, () => expectNone(text, "LOCATION"));
	}

	it("reuses address labels for LOCATION only while ADDRESS is disabled", async () => {
		const text = "Adres: Bağdat Caddesi No 5, Kadıköy";
		const withAddress = await scan(text);
		expect(spans(text, withAddress)).toEqual([["ADDRESS", "Bağdat Caddesi No 5, Kadıköy"]]);
		const locationOnly = await scan(text, {
			enabledEntities: ENTITY_TYPES.filter((t) => t !== "ADDRESS"),
		});
		expect(spans(text, locationOnly)).toEqual([["LOCATION", "Bağdat Caddesi No 5, Kadıköy"]]);
		const en = "Home address: 221B Baker Street, London.";
		const enOnly = await scan(en, { enabledEntities: ["LOCATION"] });
		expect(spans(en, enOnly)).toEqual([["LOCATION", "221B Baker Street, London"]]);
	});
});

describe("labelled detectors: policy gating", () => {
	const sample =
		"Kullanıcı adı: ahmet42; SGK sicil no: 1234567890123; Plaka: 34 ABC 123; Konum: Ankara";

	it("keeps USERNAME and LOCATION off in the default policy", async () => {
		expect(DEFAULT_POLICY.enabledEntities).not.toContain("USERNAME");
		expect(DEFAULT_POLICY.enabledEntities).not.toContain("LOCATION");
		const result = await scan(sample, { enabledEntities: DEFAULT_POLICY.enabledEntities });
		const types = result.findings.map((f) => f.type);
		expect(types).not.toContain("USERNAME");
		expect(types).not.toContain("LOCATION");
		expect(types).toContain("HEALTH_ID");
		expect(types).toContain("LICENSE_PLATE");
	});

	it("emits nothing for types that are not enabled", () => {
		const found: EntityType[] = [];
		detectLabelled(sample, new Set<EntityType>(["EMAIL"]), (_a, _b, type) => found.push(type));
		expect(found).toEqual([]);
	});

	it("detects every labelled type when enabled", async () => {
		const result = await scan(sample, { enabledEntities: LABELLED_TYPES });
		expect(spans(sample, result)).toEqual([
			["USERNAME", "ahmet42"],
			["HEALTH_ID", "1234567890123"],
			["LICENSE_PLATE", "34 ABC 123"],
			["LOCATION", "Ankara"],
		]);
	});
});

describe("labelled detectors: validators", () => {
	it("validates Turkish plates", () => {
		expect(validTurkishPlate("34", "ABC", "123")).toBe(true);
		expect(validTurkishPlate("01", "A", "1234")).toBe(true);
		expect(validTurkishPlate("81", "AB", "999")).toBe(true);
		expect(validTurkishPlate("00", "AB", "123")).toBe(false);
		expect(validTurkishPlate("82", "AB", "123")).toBe(false);
		expect(validTurkishPlate("34", "A", "123")).toBe(false);
		expect(validTurkishPlate("34", "ABC", "1234")).toBe(false);
		expect(validTurkishPlate("34", "ÇAB", "123")).toBe(false);
		expect(validTurkishPlate("34", "AB", "000")).toBe(false);
	});

	it("validates NHS numbers and KVNRs", () => {
		expect(validNhsNumber("943 476 5919")).toBe(true);
		expect(validNhsNumber("9434765918")).toBe(false);
		expect(validNhsNumber("12345")).toBe(false);
		expect(validKvnr("A123456780")).toBe(true);
		expect(validKvnr("A123456789")).toBe(false);
		expect(validKvnr("1123456780")).toBe(false);
	});
});

describe("labelled detectors: false-positive corpus", () => {
	const fixtureDir = new URL("../../e2e/fixtures/", import.meta.url);
	const fixtures = readdirSync(fixtureDir).map(
		(name) => [`e2e fixture ${name}`, readFileSync(new URL(name, fixtureDir), "utf8")] as const,
	);
	const corpus: Array<readonly [string, string]> = [
		...BENIGN_SNIPPETS,
		...BENIGN_PROSE.map((text, i) => [`benign prose ${i}`, text] as const),
		["e2e clean prompt", "Summarise the plot of Hamlet in three sentences."],
		...fixtures,
		[
			"near-miss Turkish prose",
			"Kullanıcı girişi sırasında 3 hata oluştu. Şehir merkezinde 16 GB RAM'li bilgisayar 25 bin TL. Hasta yakınları saat 14:30'da geldi.",
		],
		[
			"near-miss English prose",
			"Login with SSO, then pick a location from the list. The patient portal handles 1200 users at 10 AM; plate count 34 per batch.",
		],
	];

	it("adds no labelled findings to benign text", async () => {
		expect(fixtures.length).toBeGreaterThan(0);
		const engine = createDetectionEngine(options());
		for (const [name, text] of corpus) {
			const result = await engine.scan(text);
			const added = spans(text, result).filter(([t]) => LABELLED_TYPES.includes(t));
			expect({ name, added }).toEqual({ name, added: [] });
		}
	});
});
