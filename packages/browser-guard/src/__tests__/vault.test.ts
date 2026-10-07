import { afterEach, describe, expect, it, vi } from "vitest";
import {
	canonicalValue,
	createVault,
	DEFAULT_VAULT_TTL_MS,
	MAX_VAULT_ENTRIES,
	VaultSnapshotError,
} from "../engine/vault";
import type { EntityType, Finding, VaultSnapshot } from "../types";

/** Finding for the `occurrence`-th appearance of `value` in `text`. */
function at(text: string, value: string, type: EntityType, score = 0.9, occurrence = 1): Finding {
	let start = -1;
	for (let i = 0; i < occurrence; i++) start = text.indexOf(value, start + 1);
	if (start < 0) throw new Error(`test setup: value not found for ${type}`);
	return { type, start, end: start + value.length, score, source: "rule" };
}

function span(type: EntityType, start: number, end: number, score = 0.9): Finding {
	return { type, start, end, score, source: "rule" };
}

function fakeClock(start = 1_700_000_000_000) {
	let t = start;
	return {
		now: () => t,
		advance: (ms: number) => {
			t += ms;
		},
	};
}

const MIXED =
	"Merhaba, ben Ayşe Yılmaz. E-posta: ayse.yilmaz@ornek.com.tr, telefon +90 532 123 45 67, " +
	"TCKN 10000000146, IBAN TR33 0006 1005 1978 6457 8413 26. Please email john.doe@example.com " +
	"about card 4111 1111 1111 1111 — teşekkürler, Ayşe Yılmaz.";

function mixedFindings(): Finding[] {
	return [
		at(MIXED, "Ayşe Yılmaz", "PERSON", 0.7),
		at(MIXED, "ayse.yilmaz@ornek.com.tr", "EMAIL", 0.99),
		at(MIXED, "+90 532 123 45 67", "PHONE", 0.95),
		at(MIXED, "10000000146", "TC_KIMLIK", 0.99),
		at(MIXED, "TR33 0006 1005 1978 6457 8413 26", "IBAN", 0.99),
		at(MIXED, "john.doe@example.com", "EMAIL", 0.99),
		at(MIXED, "4111 1111 1111 1111", "CREDIT_CARD", 0.99),
		at(MIXED, "Ayşe Yılmaz", "PERSON", 0.7, 2),
	];
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe("vault mask/unmask round trip", () => {
	it("round-trips mixed Turkish/English text exactly", () => {
		const vault = createVault({ neverRestore: [] });
		const result = vault.mask(MIXED, mixedFindings());

		expect(result.masked).toBe(
			"Merhaba, ben [PERSON_1]. E-posta: [EMAIL_1], telefon [PHONE_1], TCKN [TCKN_1], " +
				"IBAN [IBAN_1]. Please email [EMAIL_2] about card [CARD_1] — teşekkürler, [PERSON_1].",
		);
		for (const secret of [
			"Ayşe",
			"ayse.yilmaz",
			"532",
			"10000000146",
			"TR33",
			"john.doe",
			"4111",
		]) {
			expect(result.masked).not.toContain(secret);
		}
		expect(result.placeholders).toEqual([
			"[PERSON_1]",
			"[EMAIL_1]",
			"[PHONE_1]",
			"[TCKN_1]",
			"[IBAN_1]",
			"[EMAIL_2]",
			"[CARD_1]",
		]);
		expect(result.counts).toEqual({
			PERSON: 2,
			EMAIL: 2,
			PHONE: 1,
			TC_KIMLIK: 1,
			IBAN: 1,
			CREDIT_CARD: 1,
		});
		expect(vault.size()).toBe(7);
		expect(vault.unmask(result.masked)).toBe(MIXED);
	});

	it("returns the text unchanged when there are no findings", () => {
		const vault = createVault({ neverRestore: [] });
		const result = vault.mask("nothing sensitive here", []);
		expect(result).toEqual({ masked: "nothing sensitive here", placeholders: [], counts: {} });
		expect(vault.unmask("nothing sensitive here")).toBe("nothing sensitive here");
		expect(vault.size()).toBe(0);
	});

	it("restores placeholders inside an LLM response that rephrases the prompt", () => {
		const vault = createVault({ neverRestore: [] });
		const { masked } = vault.mask(MIXED, mixedFindings());
		expect(masked).toContain("[EMAIL_2]");
		const response = "Sure — I will write to [EMAIL_2] and cc [EMAIL_1]; [PERSON_1] asked for it.";
		expect(vault.unmask(response)).toBe(
			"Sure — I will write to john.doe@example.com and cc ayse.yilmaz@ornek.com.tr; Ayşe Yılmaz asked for it.",
		);
	});

	it("inserts values literally (no $-pattern expansion)", () => {
		const vault = createVault({ neverRestore: [] });
		const text = "token $& and $1 here";
		const { masked } = vault.mask(text, [at(text, "$& and $1", "INTERNAL")]);
		expect(masked).toBe("token [INTERNAL_1] here");
		expect(vault.unmask(masked)).toBe(text);
	});
});

describe("vault stability and numbering", () => {
	it("maps the same value to the same placeholder across calls", () => {
		const vault = createVault({ neverRestore: [] });
		const a = "Mail ali@example.com now";
		const b = "Again: ali@example.com, and veli@example.com";
		const first = vault.mask(a, [at(a, "ali@example.com", "EMAIL")]);
		const second = vault.mask(b, [
			at(b, "ali@example.com", "EMAIL"),
			at(b, "veli@example.com", "EMAIL"),
		]);
		expect(first.masked).toBe("Mail [EMAIL_1] now");
		expect(second.masked).toBe("Again: [EMAIL_1], and [EMAIL_2]");
		expect(second.placeholders).toEqual(["[EMAIL_1]", "[EMAIL_2]"]);
		expect(vault.size()).toBe(2);
	});

	it("normalises values: email case, phone/TCKN/card digits, IBAN spacing, NFKC and whitespace", () => {
		const vault = createVault({ neverRestore: [] });
		const pairs: Array<[EntityType, string, string]> = [
			["EMAIL", "Ali@Example.COM", "ali@example.com"],
			["PHONE", "+90 (532) 123-45-67", "905321234567"],
			["TC_KIMLIK", "100 000 001 46", "10000000146"],
			["CREDIT_CARD", "4111-1111-1111-1111", "4111111111111111"],
			["IBAN", "tr33 0006 1005 1978 6457 8413 26", "TR330006100519786457841326"],
			["PERSON", "Ayşe   Yılmaz", "Ayşe Yılmaz"],
			["INTERNAL", "ＡＢＣ", "ABC"],
		];
		for (const [type, variantA, variantB] of pairs) {
			const pa = vault.mask(variantA, [span(type, 0, variantA.length)]).placeholders[0];
			const pb = vault.mask(variantB, [span(type, 0, variantB.length)]).placeholders[0];
			expect(pa, type).toBeDefined();
			expect(pb, type).toBe(pa);
		}
		// Restoration yields the first-seen original form.
		expect(vault.lookup("[EMAIL_1]")).toBe("Ali@Example.COM");
	});

	it("keeps IBAN country codes significant and separates types", () => {
		expect(canonicalValue("IBAN", "TR33 0006")).not.toBe(canonicalValue("IBAN", "DE33 0006"));
		const vault = createVault({ neverRestore: [] });
		const text = "12345 12345";
		const { masked } = vault.mask(text, [span("PHONE", 0, 5), span("BANK_ACCOUNT", 6, 11)]);
		expect(masked).toBe("[PHONE_1] [ACCOUNT_1]");
	});

	it("numbers per type starting at 1 in order of appearance, regardless of findings order", () => {
		const vault = createVault({ neverRestore: [] });
		const text = "a@x.io b@x.io 0532 111 22 33 c@x.io 10.0.0.1 Veli";
		const findings = [
			at(text, "Veli", "PERSON"),
			at(text, "10.0.0.1", "IP_ADDRESS"),
			at(text, "c@x.io", "EMAIL"),
			at(text, "0532 111 22 33", "PHONE"),
			at(text, "b@x.io", "EMAIL"),
			at(text, "a@x.io", "EMAIL"),
		];
		const { masked } = vault.mask(text, findings);
		expect(masked).toBe("[EMAIL_1] [EMAIL_2] [PHONE_1] [EMAIL_3] [IP_1] [PERSON_1]");
	});

	it("uses the contract prefixes for every type", () => {
		const vault = createVault({ neverRestore: [] });
		const text = "V1 V2 V3 V4";
		const { masked } = vault.mask(text, [
			span("TC_KIMLIK", 0, 2),
			span("CREDIT_CARD", 3, 5),
			span("LICENSE_PLATE", 6, 8),
			span("NATIONAL_ID", 9, 11),
		]);
		expect(masked).toBe("[TCKN_1] [CARD_1] [PLATE_1] [NATIONAL_ID_1]");
		expect(vault.unmask(masked)).toBe(text);
	});
});

describe("vault overlapping and malformed findings", () => {
	it("lets the longest span win and masks the union", () => {
		const vault = createVault({ neverRestore: [] });
		const text = "Contact ali.veli@example.com today";
		const { masked, counts } = vault.mask(text, [
			at(text, "ali.veli", "PERSON", 0.99),
			at(text, "ali.veli@example.com", "EMAIL", 0.8),
		]);
		expect(masked).toBe("Contact [EMAIL_1] today");
		expect(counts).toEqual({ EMAIL: 1 });
	});

	it("uses the highest score when overlapping spans have the same length", () => {
		const vault = createVault({ neverRestore: [] });
		const text = "id 12345678901 end";
		const { masked } = vault.mask(text, [
			at(text, "12345678901", "PHONE", 0.4),
			at(text, "12345678901", "TC_KIMLIK", 0.95),
		]);
		expect(masked).toBe("id [TCKN_1] end");
	});

	it("covers the union of partially overlapping spans so nothing leaks", () => {
		const vault = createVault({ neverRestore: [] });
		const text = "xx AAAABBBBCC yy";
		const { masked } = vault.mask(text, [span("PERSON", 3, 11, 0.9), span("ADDRESS", 7, 13, 0.5)]);
		expect(masked).toBe("xx [PERSON_1] yy");
		expect(vault.lookup("[PERSON_1]")).toBe("AAAABBBBCC");
		expect(vault.unmask(masked)).toBe(text);
	});

	it("gives a never-restore type priority inside an overlap cluster", () => {
		const vault = createVault({ neverRestore: ["SECRET"] });
		const text = "note: user sk_live_abcdef here";
		const { masked } = vault.mask(text, [
			at(text, "user sk_live_abcdef", "USERNAME", 0.9),
			at(text, "sk_live_abcdef", "SECRET", 0.99),
		]);
		expect(masked).toBe("note: [SECRET_1] here");
		expect(vault.unmask(masked)).toBe(masked);
	});

	it("keeps touching spans separate", () => {
		const vault = createVault({ neverRestore: [] });
		const text = "AAABBB";
		expect(vault.mask(text, [span("PERSON", 0, 3), span("USERNAME", 3, 6)]).masked).toBe(
			"[PERSON_1][USERNAME_1]",
		);
	});

	it("trims whitespace from spans, clamps out-of-range offsets and skips empty spans", () => {
		const vault = createVault({ neverRestore: [] });
		const text = "hi  ali@x.io  bye";
		const { masked } = vault.mask(text, [
			span("EMAIL", 2, 14),
			span("PERSON", 15, 999),
			span("USERNAME", -5, 1),
			span("PHONE", 5, 5),
			span("ADDRESS", 13, 14),
		]);
		expect(masked).toBe("[USERNAME_1]i  [EMAIL_1]  b[PERSON_1]");
		expect(vault.unmask(masked)).toBe(text);
	});

	it("never splits a surrogate pair", () => {
		const vault = createVault({ neverRestore: [] });
		const text = "a😀b";
		const { masked } = vault.mask(text, [span("PERSON", 2, 3)]);
		expect(masked).toBe("a[PERSON_1]b");
		expect(vault.lookup("PERSON_1")).toBe("😀");
	});

	it("throws on an unknown entity type or non-numeric offsets (callers fail closed)", () => {
		const vault = createVault({ neverRestore: [] });
		const bad = { type: "NOPE", start: 0, end: 1, score: 1, source: "rule" } as unknown as Finding;
		expect(() => vault.mask("x", [bad])).toThrow(TypeError);
		const nan = { ...span("EMAIL", 0, 1), start: Number.NaN };
		expect(() => vault.mask("x", [nan])).toThrow(TypeError);
		expect(() => vault.mask(1 as unknown as string, [])).toThrow(TypeError);
		expect(() => vault.mask("x", null as unknown as Finding[])).toThrow(TypeError);
	});
});

describe("vault placeholder collision avoidance", () => {
	it("skips numbers already present as literals in the input", () => {
		const vault = createVault({ neverRestore: [] });
		const text = "Template uses [EMAIL_1] and EMAIL_2; real one is ali@x.io";
		const { masked } = vault.mask(text, [at(text, "ali@x.io", "EMAIL")]);
		expect(masked).toBe("Template uses [EMAIL_1] and EMAIL_2; real one is [EMAIL_3]");
		// Foreign placeholders are never touched.
		expect(vault.unmask(masked)).toBe(text);
		expect(vault.unmask("[EMAIL_1] EMAIL_2")).toBe("[EMAIL_1] EMAIL_2");
	});

	it("remembers foreign literals across calls", () => {
		const vault = createVault({ neverRestore: [] });
		vault.mask("see [PHONE_1] in the doc", []);
		const text = "call 0532 000 00 00";
		expect(vault.mask(text, [at(text, "0532 000 00 00", "PHONE")]).masked).toBe("call [PHONE_2]");
	});

	it("does not treat its own placeholders in re-masked text as foreign", () => {
		const vault = createVault({ neverRestore: [] });
		const a = "a@x.io";
		vault.mask(a, [span("EMAIL", 0, a.length)]);
		const b = "[EMAIL_1] and b@x.io";
		expect(vault.mask(b, [at(b, "b@x.io", "EMAIL")]).masked).toBe("[EMAIL_1] and [EMAIL_2]");
		expect(vault.unmask("[EMAIL_1] and [EMAIL_2]")).toBe("a@x.io and b@x.io");
	});

	it("recognises markdown-escaped foreign literals too", () => {
		const vault = createVault({ neverRestore: [] });
		const text = String.raw`\[TAX\_ID\_1\] then 1234567890`;
		expect(vault.mask(text, [at(text, "1234567890", "TAX_ID")]).masked).toBe(
			String.raw`\[TAX\_ID\_1\] then [TAX_ID_2]`,
		);
	});
});

describe("vault unmask robustness", () => {
	function seeded() {
		const vault = createVault({ neverRestore: [] });
		const text = "a@x.io 12345678901";
		vault.mask(text, [span("EMAIL", 0, 6), span("NATIONAL_ID", 7, 18)]);
		return vault;
	}

	it.each([
		["[EMAIL_1]", "a@x.io"],
		["**[EMAIL_1]**", "**a@x.io**"],
		["*[EMAIL_1]*", "*a@x.io*"],
		["_[EMAIL_1]_", "_a@x.io_"],
		[String.raw`[EMAIL\_1]`, "a@x.io"],
		[String.raw`\[EMAIL_1\]`, "a@x.io"],
		[String.raw`\[EMAIL\_1\]`, "a@x.io"],
		["`[EMAIL_1]`", "`a@x.io`"],
		["`EMAIL_1`", "`a@x.io`"],
		["Write to EMAIL_1.", "Write to a@x.io."],
		["(EMAIL_1)", "(a@x.io)"],
		["**EMAIL_1**", "**a@x.io**"],
		["_EMAIL_1_", "_a@x.io_"],
		["__EMAIL_1__", "__a@x.io__"],
		[String.raw`NATIONAL\_ID\_1`, "12345678901"],
		["[NATIONAL_ID_1]", "12345678901"],
		["EMAIL_1,[EMAIL_1]", "a@x.io,a@x.io"],
	])("restores %s", (input, expected) => {
		expect(seeded().unmask(input)).toBe(expected);
	});

	it.each([
		"MY_EMAIL_1",
		"EMAIL_1x",
		"xEMAIL_1",
		"EMAIL_12",
		"[EMAIL_12]",
		"[EMAIL_2]",
		"EMAIL_01",
		"email_1",
		"[email_1]",
		"PHONE_1",
		"[FOO_1]",
	])("leaves %s untouched", (input) => {
		expect(seeded().unmask(input)).toBe(input);
	});

	it("does not re-expand placeholders that appear inside restored values", () => {
		const vault = createVault({ neverRestore: [] });
		const text = "literal EMAIL_9 text and b@x.io";
		vault.mask(text, [at(text, "literal EMAIL_9 text", "INTERNAL"), at(text, "b@x.io", "EMAIL")]);
		expect(vault.unmask("[INTERNAL_1]")).toBe("literal EMAIL_9 text");
	});
});

describe("vault neverRestore", () => {
	it("masks but never restores or reveals locked types", () => {
		const vault = createVault({ neverRestore: ["SECRET", "PRIVATE_KEY"] });
		const text = "key=AKIAABCDEFGHIJKLMNOP for ali@x.io";
		const { masked } = vault.mask(text, [
			at(text, "AKIAABCDEFGHIJKLMNOP", "SECRET"),
			at(text, "ali@x.io", "EMAIL"),
		]);
		expect(masked).toBe("key=[SECRET_1] for [EMAIL_1]");
		expect(vault.unmask(masked)).toBe("key=[SECRET_1] for ali@x.io");
		expect(vault.unmask("SECRET_1 **[SECRET_1]**")).toBe("SECRET_1 **[SECRET_1]**");
		expect(vault.lookup("[SECRET_1]")).toBeUndefined();
		expect(vault.lookup("[EMAIL_1]")).toBe("ali@x.io");
		// Still stable: the same secret keeps its placeholder.
		expect(vault.mask("AKIAABCDEFGHIJKLMNOP", [span("SECRET", 0, 20)]).masked).toBe("[SECRET_1]");
	});
});

describe("vault TTL", () => {
	it("forgets entries unused for longer than the TTL and never reuses their numbers", () => {
		const clock = fakeClock();
		const vault = createVault({ neverRestore: [], ttlMs: 1000, now: clock.now });
		vault.mask("a@x.io", [span("EMAIL", 0, 6)]);
		clock.advance(1000);
		expect(vault.unmask("[EMAIL_1]")).toBe("a@x.io");
		clock.advance(1001);
		expect(vault.unmask("[EMAIL_1]")).toBe("[EMAIL_1]");
		expect(vault.lookup("[EMAIL_1]")).toBeUndefined();
		expect(vault.size()).toBe(0);
		expect(vault.mask("a@x.io", [span("EMAIL", 0, 6)]).masked).toBe("[EMAIL_2]");
	});

	it("measures age from last use, so active entries stay alive", () => {
		const clock = fakeClock();
		const vault = createVault({ neverRestore: [], ttlMs: 1000, now: clock.now });
		vault.mask("a@x.io b@x.io", [span("EMAIL", 0, 6), span("EMAIL", 7, 13)]);
		clock.advance(800);
		vault.mask("a@x.io", [span("EMAIL", 0, 6)]);
		clock.advance(800);
		expect(vault.size()).toBe(1);
		expect(vault.unmask("[EMAIL_1] [EMAIL_2]")).toBe("a@x.io [EMAIL_2]");
	});

	it("defaults to four hours and rejects invalid TTLs", () => {
		expect(DEFAULT_VAULT_TTL_MS).toBe(4 * 60 * 60 * 1000);
		const clock = fakeClock();
		const vault = createVault({ neverRestore: [], now: clock.now });
		vault.mask("a@x.io", [span("EMAIL", 0, 6)]);
		clock.advance(DEFAULT_VAULT_TTL_MS);
		expect(vault.size()).toBe(1);
		clock.advance(1);
		expect(vault.size()).toBe(0);
		expect(() => createVault({ neverRestore: [], ttlMs: 0 })).toThrow(RangeError);
		expect(() => createVault({ neverRestore: [], ttlMs: -1 })).toThrow(RangeError);
		expect(() => createVault({ neverRestore: [], ttlMs: Number.NaN })).toThrow(RangeError);
	});
});

describe("vault snapshots", () => {
	function exported() {
		const clock = fakeClock();
		const vault = createVault({ neverRestore: ["SECRET"], now: clock.now });
		const { masked } = vault.mask(MIXED, mixedFindings());
		vault.mask("tok_abcdef", [span("SECRET", 0, 10)]);
		return { clock, vault, masked, snapshot: vault.exportSession() };
	}

	it("exports and re-imports a session (through JSON) with stable numbering", () => {
		const { clock, masked, snapshot } = exported();
		expect(snapshot.version).toBe(1);
		expect(snapshot.createdAt).toBe(clock.now());
		expect(snapshot.entries).toHaveLength(8);

		const restored = createVault({
			neverRestore: ["SECRET"],
			snapshot: JSON.parse(JSON.stringify(snapshot)) as VaultSnapshot,
			now: clock.now,
		});
		expect(restored.size()).toBe(8);
		expect(restored.unmask(masked)).toBe(MIXED);
		expect(restored.unmask("[SECRET_1]")).toBe("[SECRET_1]");
		const text = "JOHN.DOE@example.com and new@x.io and tok_abcdef";
		expect(
			restored.mask(text, [
				at(text, "JOHN.DOE@example.com", "EMAIL"),
				at(text, "new@x.io", "EMAIL"),
				at(text, "tok_abcdef", "SECRET"),
			]).masked,
		).toBe("[EMAIL_2] and [EMAIL_3] and [SECRET_1]");
	});

	it("imports an expired snapshot as empty but keeps its numbers reserved", () => {
		const { clock, snapshot } = exported();
		clock.advance(DEFAULT_VAULT_TTL_MS + 1);
		const restored = createVault({ neverRestore: [], snapshot, now: clock.now });
		expect(restored.size()).toBe(0);
		expect(restored.unmask("[EMAIL_1]")).toBe("[EMAIL_1]");
		expect(restored.mask("z@x.io", [span("EMAIL", 0, 6)]).masked).toBe("[EMAIL_3]");
	});

	it("gives imported entries a TTL measured from the snapshot time", () => {
		const { clock, snapshot } = exported();
		clock.advance(DEFAULT_VAULT_TTL_MS - 10);
		const restored = createVault({ neverRestore: [], snapshot, now: clock.now });
		expect(restored.size()).toBe(8);
		clock.advance(11);
		expect(restored.size()).toBe(0);
	});

	it("returns frozen snapshots that do not alias vault state", () => {
		const { vault, snapshot } = exported();
		expect(Object.isFrozen(snapshot)).toBe(true);
		expect(Object.isFrozen(snapshot.entries)).toBe(true);
		vault.clear();
		expect(snapshot.entries).toHaveLength(8);
	});

	const valid = (): Record<string, unknown> => ({
		version: 1,
		createdAt: 1_700_000_000_000,
		entries: [{ placeholder: "[EMAIL_1]", value: "a@x.io", type: "EMAIL" }],
	});
	const entry = (patch: Record<string, unknown>) => ({
		...valid(),
		entries: [{ placeholder: "[EMAIL_1]", value: "a@x.io", type: "EMAIL", ...patch }],
	});

	it("accepts the minimal valid snapshot", () => {
		const clock = fakeClock();
		const vault = createVault({
			neverRestore: [],
			snapshot: valid() as unknown as VaultSnapshot,
			now: clock.now,
		});
		expect(vault.lookup("[EMAIL_1]")).toBe("a@x.io");
	});

	const tooMany = Array.from({ length: MAX_VAULT_ENTRIES + 1 }, (_, i) => ({
		placeholder: `[EMAIL_${i + 1}]`,
		value: `u${i}@x.io`,
		type: "EMAIL",
	}));
	const malformed: Array<[string, unknown]> = [
		["null", null],
		["array", []],
		["string", "snapshot"],
		["wrong version", { ...valid(), version: 2 }],
		["missing entries", { version: 1, createdAt: 1 }],
		["extra top-level key", { ...valid(), extra: true }],
		["non-numeric createdAt", { ...valid(), createdAt: "yesterday" }],
		["negative createdAt", { ...valid(), createdAt: -1 }],
		["future createdAt", { ...valid(), createdAt: 1_700_000_000_000 + 3_600_000 }],
		["entries not an array", { ...valid(), entries: {} }],
		["too many entries", { ...valid(), entries: tooMany }],
		["entry not an object", { ...valid(), entries: ["[EMAIL_1]"] }],
		["entry extra key", entry({ extra: 1 })],
		["unknown type", entry({ type: "NOPE" })],
		["placeholder without brackets", entry({ placeholder: "EMAIL_1" })],
		["placeholder zero", entry({ placeholder: "[EMAIL_0]" })],
		["placeholder lower case", entry({ placeholder: "[email_1]" })],
		["placeholder/type mismatch", entry({ placeholder: "[PHONE_1]" })],
		["placeholder not a string", entry({ placeholder: 1 })],
		["empty value", entry({ value: "   " })],
		["non-string value", entry({ value: 42 })],
		["over-long value", entry({ value: "x".repeat(65_537) })],
		[
			"duplicate placeholder",
			{
				...valid(),
				entries: [
					{ placeholder: "[EMAIL_1]", value: "a@x.io", type: "EMAIL" },
					{ placeholder: "[EMAIL_1]", value: "b@x.io", type: "EMAIL" },
				],
			},
		],
		[
			"duplicate canonical value",
			{
				...valid(),
				entries: [
					{ placeholder: "[EMAIL_1]", value: "a@x.io", type: "EMAIL" },
					{ placeholder: "[EMAIL_2]", value: "A@X.IO", type: "EMAIL" },
				],
			},
		],
	];

	it.each(malformed)("rejects a snapshot with %s", (_label, snapshot) => {
		const clock = fakeClock();
		let error: unknown;
		try {
			createVault({ neverRestore: [], snapshot: snapshot as VaultSnapshot, now: clock.now });
		} catch (e) {
			error = e;
		}
		expect(error).toBeInstanceOf(VaultSnapshotError);
		const message = (error as Error).message;
		expect(message).not.toContain("a@x.io");
		expect(message).not.toContain("b@x.io");
	});
});

describe("vault memory bounds and clear", () => {
	it("keeps at most MAX_VAULT_ENTRIES entries, evicting least recently used", () => {
		const clock = fakeClock();
		const vault = createVault({ neverRestore: [], now: clock.now });
		const values = Array.from({ length: MAX_VAULT_ENTRIES + 1 }, (_, i) => `u${i}@x.io`);
		const text = values.join(" ");
		const findings: Finding[] = [];
		let offset = 0;
		for (const value of values) {
			findings.push(span("EMAIL", offset, offset + value.length));
			offset += value.length + 1;
		}
		vault.mask(text, findings);
		expect(vault.size()).toBe(MAX_VAULT_ENTRIES);
		expect(vault.lookup("[EMAIL_1]")).toBeUndefined();
		expect(vault.lookup("[EMAIL_2]")).toBe("u1@x.io");
		expect(vault.lookup(`[EMAIL_${MAX_VAULT_ENTRIES + 1}]`)).toBe(`u${MAX_VAULT_ENTRIES}@x.io`);
		expect(vault.exportSession().entries).toHaveLength(MAX_VAULT_ENTRIES);
	});

	it("clear() forgets every value and restarts numbering", () => {
		const vault = createVault({ neverRestore: [] });
		vault.mask("[EMAIL_1] a@x.io", [span("EMAIL", 10, 16)]);
		expect(vault.lookup("[EMAIL_2]")).toBe("a@x.io");
		vault.clear();
		expect(vault.size()).toBe(0);
		expect(vault.unmask("[EMAIL_2]")).toBe("[EMAIL_2]");
		expect(vault.exportSession().entries).toEqual([]);
		expect(vault.mask("b@x.io", [span("EMAIL", 0, 6)]).masked).toBe("[EMAIL_1]");
	});

	it("lookup accepts bracketed, bare and escaped forms and rejects junk", () => {
		const vault = createVault({ neverRestore: [] });
		vault.mask("a@x.io", [span("EMAIL", 0, 6)]);
		expect(vault.lookup("[EMAIL_1]")).toBe("a@x.io");
		expect(vault.lookup("EMAIL_1")).toBe("a@x.io");
		expect(vault.lookup(String.raw`\[EMAIL\_1\]`)).toBe("a@x.io");
		expect(vault.lookup("[EMAIL_2]")).toBeUndefined();
		expect(vault.lookup(undefined as unknown as string)).toBeUndefined();
	});

	it("never writes to the console", () => {
		const spies = (["log", "info", "warn", "error", "debug", "trace"] as const).map((m) =>
			vi.spyOn(console, m).mockImplementation(() => undefined),
		);
		const vault = createVault({ neverRestore: ["SECRET"] });
		const { masked } = vault.mask(MIXED, mixedFindings());
		vault.unmask(masked);
		vault.lookup("[EMAIL_1]");
		createVault({ neverRestore: [], snapshot: vault.exportSession() });
		expect(() =>
			createVault({ neverRestore: [], snapshot: { bogus: true } as unknown as VaultSnapshot }),
		).toThrow();
		for (const spy of spies) expect(spy).not.toHaveBeenCalled();
	});
});

describe("vault performance", () => {
	it("masks and unmasks 100 KB of text in under 100 ms each", () => {
		const unit =
			"Müşteri Ali Veli (ali.veli@example.com, +90 532 123 45 67) IBAN TR33 0006 1005 1978 6457 8413 26 " +
			"asked about invoice 42 and said hello to the team. ";
		const chunks: string[] = [];
		const findings: Finding[] = [];
		let length = 0;
		let i = 0;
		while (length < 100_000) {
			const chunk = unit.replace("ali.veli", `ali.veli${i % 500}`);
			for (const [value, type] of [
				["Ali Veli", "PERSON"],
				[`ali.veli${i % 500}@example.com`, "EMAIL"],
				["+90 532 123 45 67", "PHONE"],
				["TR33 0006 1005 1978 6457 8413 26", "IBAN"],
			] as const) {
				const start = length + chunk.indexOf(value);
				findings.push(span(type, start, start + value.length));
			}
			chunks.push(chunk);
			length += chunk.length;
			i++;
		}
		const text = chunks.join("");
		expect(text.length).toBeGreaterThanOrEqual(100_000);

		// Best of three fresh runs to damp scheduler noise on shared CI machines.
		let bestMask = Number.POSITIVE_INFINITY;
		let bestUnmask = Number.POSITIVE_INFINITY;
		for (let run = 0; run < 3; run++) {
			const vault = createVault({ neverRestore: [] });
			const t0 = performance.now();
			const { masked } = vault.mask(text, findings);
			const t1 = performance.now();
			const restored = vault.unmask(masked);
			const t2 = performance.now();
			expect(restored).toBe(text);
			expect(vault.size()).toBe(503);
			bestMask = Math.min(bestMask, t1 - t0);
			bestUnmask = Math.min(bestUnmask, t2 - t1);
		}
		expect(bestMask).toBeLessThan(100);
		expect(bestUnmask).toBeLessThan(100);
	});
});
