import { describe, expect, it } from "vitest";
import { createDetectionEngine } from "../engine/detect.js";
import { detectStructured } from "../engine/structured.js";
import { ENTITY_TYPES, type EntityType } from "../types.js";

const ALL: ReadonlySet<EntityType> = new Set(ENTITY_TYPES);

function found(text: string, enabled = ALL): Array<[EntityType, string]> {
	const out: Array<[EntityType, string]> = [];
	detectStructured(text, enabled, (start, end, type) => out.push([type, text.slice(start, end)]));
	return out;
}

describe("detectStructured: pasted JSON", () => {
	it("masks values under sensitive keys, quoted or numeric", () => {
		expect(found('{"customer":{"fullName":"Deniz Aydın","gsm":5051234567,"note":"ok"}}')).toEqual([
			["PERSON", "Deniz Aydın"],
			["PHONE", "5051234567"],
		]);
	});

	it("reads Python dict literals", () => {
		expect(found("{'email': 'a@b.co', 'surname': 'Kaya'}")).toEqual([
			["EMAIL", "a@b.co"],
			["PERSON", "Kaya"],
		]);
	});

	it("keeps ambiguous keys and non-sensitive keys untouched", () => {
		expect(found('{"name": "my-app", "version": "1.0.0", "max_tokens": 1024}')).toEqual([]);
	});

	it("respects disabled entity types", () => {
		expect(found('{"email":"a@b.co"}', new Set<EntityType>(["PERSON"]))).toEqual([]);
	});
});

describe("detectStructured: pasted tables", () => {
	it("masks sensitive CSV columns, including ambiguous headers next to a strict one", () => {
		expect(found("ad,soyad,şehir\nAhmet,Yılmaz,Ankara\nAyşe,Kara,İzmir")).toEqual([
			["PERSON", "Ahmet"],
			["PERSON", "Yılmaz"],
			["PERSON", "Ayşe"],
			["PERSON", "Kara"],
		]);
	});

	it("reads TSV and quoted CSV cells", () => {
		expect(found("first_name\tlast_name\nMichael\tBrown")).toEqual([
			["PERSON", "Michael"],
			["PERSON", "Brown"],
		]);
		expect(found('email,city\n"x@y.com","Paris, FR"')).toEqual([["EMAIL", "x@y.com"]]);
	});

	it("reads Markdown tables and skips the rule row", () => {
		expect(found("| Ad | Telefon |\n|---|:---:|\n| Burak Koç | 0542 765 43 21 |")).toEqual([
			["PERSON", "Burak Koç"],
			["PHONE", "0542 765 43 21"],
		]);
	});

	it("ignores tables whose only sensitive-looking header is ambiguous", () => {
		expect(found("name,version\nreact,18.2.0")).toEqual([]);
		expect(found("| Name | Version |\n|---|---|\n| lodash | 4.17.21 |")).toEqual([]);
	});

	it("stops at the first row with a different cell count", () => {
		expect(found("email,city\nx@y.com,Paris\n\nfree text, with a comma, here")).toEqual([
			["EMAIL", "x@y.com"],
		]);
	});
});

describe("detection engine wiring", () => {
	it("masks a pasted customer table end to end", async () => {
		const engine = createDetectionEngine({
			enabledEntities: ENTITY_TYPES,
			literals: [],
			exactData: [],
			detectSignals: false,
			maxInputChars: 10_000,
			maxScanMs: 2_000,
		});
		const text = "ad,soyad,telefon\nAhmet,Yılmaz,05321112233";
		const result = await engine.scan(text);
		expect(result.findings.map((f) => [f.type, text.slice(f.start, f.end)])).toEqual([
			["PERSON", "Ahmet"],
			["PERSON", "Yılmaz"],
			["PHONE", "05321112233"],
		]);
	});
});
