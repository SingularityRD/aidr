import { describe, expect, it } from "vitest";
import {
	createDlpMatchFingerprint,
	DLP_DETECTOR_ENTITY_TYPES,
	type DlpDetector,
	DlpDetectorSchema,
	type DlpInspectedResult,
	DlpPolicySchema,
	type DlpScanResult,
	scanDlpInput,
	scanPrivacyDetectors,
} from "../../dlp/index.js";
import { PiiDetectorImpl } from "../../dlp/pii-detector.js";
import { ENTITY_TYPES } from "../../dlp/privacy-rules/types.js";

const TENANT = "tenant-tr";
const VALID_TCKN = "10000000146";
const INVALID_TCKN = "10000000147";
const VALID_IBAN = "TR33 0006 1005 1978 6457 8413 26";
const INVALID_IBAN = "TR33 0006 1005 1978 6457 8413 27";

function detectorPolicy(
	detectors: DlpDetector[],
	options: {
		action?: "redact" | "block" | "ask";
		replacement?: string;
		maxContentBytes?: number;
	} = {},
	exceptions: unknown[] = [],
) {
	return DlpPolicySchema.parse({
		version: 1,
		tenantId: TENANT,
		maxContentBytes: options.maxContentBytes ?? 1024 * 1024,
		supportedFormats: ["text/*", "application/json"],
		unavailableAction: "block",
		labels: [
			{ id: "label-personal", tenantId: TENANT, name: "Personal data", sensitivity: "restricted" },
		],
		rules: [
			{
				id: "rule-privacy",
				tenantId: TENANT,
				labelId: "label-personal",
				name: "AIDR Privacy detectors",
				action: options.action ?? "redact",
				matchers: [{ type: "detector", detectors }],
				...(options.replacement ? { replacement: options.replacement } : {}),
			},
		],
		exceptions,
	});
}

function scan(
	content: string,
	detectors: DlpDetector[],
	contentType = "text/plain",
	options: Parameters<typeof detectorPolicy>[1] = {},
): DlpScanResult {
	return scanDlpInput(detectorPolicy(detectors, options), {
		tenantId: TENANT,
		content,
		contentType,
	});
}

function inspected(result: DlpScanResult): DlpInspectedResult {
	expect(result.status).toBe("inspected");
	return result as DlpInspectedResult;
}

describe("DLP detector matcher schema", () => {
	it("accepts every built-in detector and maps each to a privacy entity type", () => {
		for (const detector of DlpDetectorSchema.options) {
			expect(ENTITY_TYPES).toContain(DLP_DETECTOR_ENTITY_TYPES[detector]);
		}
		expect(() => detectorPolicy([...DlpDetectorSchema.options])).not.toThrow();
	});

	it("rejects unknown and duplicate detectors", () => {
		expect(() => detectorPolicy(["tc_kimlik", "nope" as DlpDetector])).toThrow();
		expect(() => detectorPolicy(["iban", "iban"])).toThrow(/detectors must be unique/);
		expect(() => detectorPolicy([])).toThrow();
	});
});

describe("DLP built-in TR/EN detectors", () => {
	it("redacts a checksum-valid TC Kimlik with a type placeholder and never returns the value", () => {
		const content = `Musteri ${VALID_TCKN} kaydi`;
		const result = inspected(scan(content, ["tc_kimlik"]));
		expect(result.action).toBe("redact");
		expect(result.transformedContent).toBe("Musteri [TC_KIMLIK] kaydi");
		expect(result.findings).toEqual([
			expect.objectContaining({
				ruleId: "rule-privacy",
				detector: "tc_kimlik",
				start: 8,
				end: 19,
				maskedPreview: "*".repeat(11),
				matchFingerprint: createDlpMatchFingerprint(TENANT, "rule-privacy", VALID_TCKN),
			}),
		]);
		expect(JSON.stringify(result)).not.toContain(VALID_TCKN);
	});

	it("ignores an invalid TCKN checksum unless an explicit label marks it sensitive", () => {
		expect(inspected(scan(`Musteri ${INVALID_TCKN} kaydi`, ["tc_kimlik"])).action).toBe("allow");
		expect(inspected(scan("11111111111", ["tc_kimlik"])).findings).toEqual([]);
		const labelled = inspected(scan(`TC Kimlik No: ${INVALID_TCKN}`, ["tc_kimlik"]));
		expect(labelled.transformedContent).toBe("TC Kimlik No: [TC_KIMLIK]");
	});

	it("validates IBAN mod-97 for every registry country", () => {
		for (const iban of [
			VALID_IBAN,
			"DE89 3704 0044 0532 0130 00",
			"AL47 2121 1009 0000 0002 3569 8741",
			"MU17 BOMM 0101 1010 3030 0200 000M UR",
		]) {
			const result = inspected(scan(`pay ${iban} today`, ["iban"]));
			expect(result.transformedContent).toBe("pay [IBAN] today");
			expect(result.findings[0]?.detector).toBe("iban");
		}
		expect(inspected(scan(`pay ${INVALID_IBAN} today`, ["iban"])).findings).toEqual([]);
		expect(
			inspected(scan("pay AL48 2121 1009 0000 0002 3569 8741 today", ["iban"])).findings,
		).toEqual([]);
	});

	it("detects TR phone numbers in mobile, landline and international forms", () => {
		for (const phone of [
			"0532 123 45 67",
			"+90 (532) 123 45 67",
			"0212 555 12 34",
			"0090 532 1234567",
		]) {
			const result = inspected(scan(`ara ${phone} lutfen`, ["phone"]));
			expect(result.transformedContent, phone).toBe("ara [PHONE] lutfen");
		}
		expect(inspected(scan("versiyon 1.2.3 build 45", ["phone"])).findings).toEqual([]);
	});

	it("detects TR addresses and person names only with context", () => {
		const content =
			"Adres: Atatürk Mahallesi Cumhuriyet Caddesi No:5 Kadıköy\nMerhaba, benim adım Ayşe Demir.";
		const result = inspected(scan(content, ["address", "person"]));
		expect(result.transformedContent).toBe("Adres: [ADDRESS]\nMerhaba, benim adım [PERSON].");
		expect(result.findings.map((finding) => finding.detector)).toEqual(["address", "person"]);
		expect(inspected(scan("Ayşe Demir bugün geldi", ["person"])).findings).toEqual([]);
	});

	it("protects labelled TR/EN identity fields", () => {
		const content =
			"Doğum Tarihi: 01.02.1990; Pasaport No: U12345678; Vergi No: 1234567890; Hesap No: 12345678";
		const result = inspected(
			scan(content, ["date_of_birth", "passport", "tax_id", "bank_account", "national_id"]),
		);
		expect(result.transformedContent).toBe(
			"Doğum Tarihi: [DATE_OF_BIRTH]; Pasaport No: [PASSPORT]; Vergi No: [TAX_ID]; Hesap No: [BANK_ACCOUNT]",
		);
	});

	it.each([
		["sk-proj-abcdefghijklmnop1234", "sk-proj-abcdefghijklmnop1234"],
		["sk-ant-api03-abcdefghijklmnopqrstu", "sk-ant-api03-abcdefghijklmnopqrstu"],
		["github_pat_11ABCDEFG0123456789abcdef", "github_pat_11ABCDEFG0123456789abcdef"],
		["glpat-abcdefghijklmnop1234", "glpat-abcdefghijklmnop1234"],
		[
			"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdEFGHijkl",
			"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdEFGHijkl",
		],
		["https://user:pass@example.com/x", "user:pass@"],
		["şifre=Gizli123!", "Gizli123!"],
	])("blocks the credential pattern %s", (text, secret) => {
		const content = `x ${text} y`;
		const result = inspected(scan(content, ["secret"], "text/plain", { action: "block" }));
		expect(result.action).toBe("block");
		const finding = result.findings[0];
		expect(finding?.detector).toBe("secret");
		expect(content.slice(finding?.start, finding?.end)).toBe(secret);
		expect(result.transformedContent).toBeUndefined();
		expect(JSON.stringify(result)).not.toContain(secret);
	});

	it("covers a complete PEM private key block", () => {
		const pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkq\n-----END PRIVATE KEY-----";
		const result = inspected(scan(`key:\n${pem}\nend`, ["private_key"]));
		expect(result.transformedContent).toBe("key:\n[PRIVATE_KEY]\nend");
	});

	it("is quiet on benign developer text", () => {
		const content = [
			"export function add(a: number, b: number) { return a + b; }",
			"version 2.14.3 released on 2024-05-01; see issue #12345",
			"const id = 12345678901234; // not a checksum-valid identifier",
		].join("\n");
		const detectors = DlpDetectorSchema.options.filter((detector) => detector !== "classified");
		expect(inspected(scan(content, [...detectors])).findings).toEqual([]);
	});

	it("lets an explicit rule replacement override the type placeholder", () => {
		const result = inspected(
			scan(`id ${VALID_TCKN}`, ["tc_kimlik"], "text/plain", { replacement: "<kimlik>" }),
		);
		expect(result.transformedContent).toBe("id <kimlik>");
	});

	it("suppresses a detector finding with a match-scoped exception", () => {
		const policy = detectorPolicy(["tc_kimlik"], {}, [
			{
				id: "exception-test-id",
				tenantId: TENANT,
				ruleId: "rule-privacy",
				ownerId: "owner-1",
				justification: "Synthetic test identifier",
				scope: "match",
				fingerprint: createDlpMatchFingerprint(TENANT, "rule-privacy", VALID_TCKN),
				expiresAt: "2999-01-01T00:00:00Z",
			},
		]);
		const result = inspected(
			scanDlpInput(policy, {
				tenantId: TENANT,
				content: `id ${VALID_TCKN}`,
				contentType: "text/plain",
			}),
		);
		expect(result).toMatchObject({ action: "allow", appliedExceptionIds: ["exception-test-id"] });
	});
});

describe("DLP detectors on JSON content", () => {
	it("maps findings inside escaped JSON strings to raw spans and keeps the output valid JSON", () => {
		const content = JSON.stringify({
			musteri: { note: `Kimlik:\t"${VALID_TCKN}"`, iban: VALID_IBAN },
			tel: "Tel: 0532 123 45 67",
		}).replace("10000000146", "1000000014\\u0036");
		const result = inspected(scan(content, ["tc_kimlik", "iban", "phone"], "application/json"));
		expect(result.action).toBe("redact");
		const transformed = result.transformedContent ?? "";
		expect(JSON.parse(transformed)).toEqual({
			musteri: { note: 'Kimlik:\t"[TC_KIMLIK]"', iban: "[IBAN]" },
			tel: "Tel: [PHONE]",
		});
		const kimlik = result.findings.find((finding) => finding.detector === "tc_kimlik");
		expect(content.slice(kimlik?.start, kimlik?.end)).toBe("1000000014\\u0036");
		expect(kimlik?.matchFingerprint).toBe(
			createDlpMatchFingerprint(TENANT, "rule-privacy", VALID_TCKN),
		);
	});

	it("types whole values by sensitive key, including numbers, and keeps strings apart", () => {
		const content = JSON.stringify({
			tckn: 10000000147,
			telefon: "05321234567",
			phone: "string",
			a: "Tel: 0532 123 45 67",
			b: "ok",
		});
		const result = inspected(scan(content, ["tc_kimlik", "phone"], "application/json"));
		expect(JSON.parse(result.transformedContent ?? "")).toEqual({
			tckn: "[TC_KIMLIK]",
			telefon: "[PHONE]",
			phone: "string",
			a: "Tel: [PHONE]",
			b: "ok",
		});
		const number = result.findings.find((finding) => finding.detector === "tc_kimlik");
		expect(content.slice(number?.start, number?.end)).toBe("10000000147");
	});

	it("detects a secret split across a JSON key and value", () => {
		const content = JSON.stringify({ password: "Gizli123!", user: "x" });
		const result = inspected(scan(content, ["secret"], "application/json"));
		expect(JSON.parse(result.transformedContent ?? "")).toEqual({
			password: "[SECRET]",
			user: "x",
		});
	});
});

describe("DLP detectors fail closed when inspection is incomplete", () => {
	it("returns unavailable for an unterminated sensitive field", () => {
		const result = scan('password: "abc and 10000000146', ["secret", "tc_kimlik"]);
		expect(result).toMatchObject({
			status: "unavailable",
			action: "block",
			findings: [],
			unavailable: { reason: "incomplete_inspection" },
		});
		expect(JSON.stringify(result)).not.toContain("10000000146");
	});

	it("returns unavailable when content exceeds the detector input limit", () => {
		const result = scan("a".repeat(1024 * 1024 + 1), ["iban"], "text/plain", {
			maxContentBytes: 2 * 1024 * 1024,
		});
		expect(result).toMatchObject({
			status: "unavailable",
			unavailable: { reason: "incomplete_inspection" },
		});
	});

	it("reports incomplete scans from the adapter with static reason codes only", () => {
		expect(scanPrivacyDetectors('şifre: "Gizli', ["secret"])).toEqual({
			matches: [],
			incomplete: true,
			reasons: ["INCOMPLETE_SECRET"],
		});
	});
});

describe("PiiDetectorImpl with AIDR Privacy detectors", () => {
	it("reports TC Kimlik, IBAN and private keys by default and credentials on opt-in", () => {
		const detector = new PiiDetectorImpl();
		const input = [
			`kimlik ${VALID_TCKN}`,
			`iban ${VALID_IBAN}`,
			"token glpat-abcdefghijklmnop1234",
			"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
		].join("\n");
		const types = detector.detect(input).map((match) => match.type);
		expect(types).toEqual(expect.arrayContaining(["tc_kimlik", "iban", "private_key"]));
		expect(types).not.toContain("secret");
		const withSecrets = new PiiDetectorImpl({ enableSecret: true }).detect(input);
		expect(withSecrets.find((match) => match.type === "secret")?.value).toBe(
			"glpat-abcdefghijklmnop1234",
		);
		const kimlik = detector.detect(input).find((match) => match.type === "tc_kimlik");
		expect(kimlik).toMatchObject({ value: VALID_TCKN, severity: "critical" });
	});

	it("orders a checksum-valid TC Kimlik ahead of the generic phone pattern on the same digits", () => {
		expect(new PiiDetectorImpl().detect(`no ${VALID_TCKN}`)[0]?.type).toBe("tc_kimlik");
		expect(new PiiDetectorImpl().detect(`no ${INVALID_TCKN}`).map((m) => m.type)).not.toContain(
			"tc_kimlik",
		);
	});

	it("does not duplicate a credential already reported as api_key", () => {
		const matches = new PiiDetectorImpl({ enableSecret: true }).detect(
			"key sk-proj-abcdefghijklmnop1234 end",
		);
		expect(matches.map((match) => match.type)).toEqual(["api_key"]);
	});

	it("keeps contextual types opt-in so source code does not trip them", () => {
		const code = [
			"interface User { name: string; address: string; phone: string; tc: string; iban: Iban }",
			"const tel = 'x'; const password = readSecret();",
		].join("\n");
		expect(new PiiDetectorImpl().detect(code)).toEqual([]);
		const text = "Ad Soyad: Ahmet Yılmaz; Adres: Bağdat Caddesi No:5; Pasaport No: U1234567";
		const opted = new PiiDetectorImpl({
			enablePerson: true,
			enableAddress: true,
			enableLabelledFields: true,
		});
		expect(opted.detect(text).map((match) => match.type)).toEqual([
			"person",
			"address",
			"passport",
		]);
		expect(new PiiDetectorImpl().detect(text).map((match) => match.type)).toEqual([]);
	});

	it("honours the per-type flags and minConfidence", () => {
		const input = `kimlik ${VALID_TCKN} iban ${VALID_IBAN}`;
		const types = new PiiDetectorImpl({ enableTcKimlik: false, enablePhone: false })
			.detect(input)
			.map((match) => match.type);
		expect(types).toContain("iban");
		expect(types).not.toContain("tc_kimlik");
		expect(new PiiDetectorImpl({ minConfidence: 1, enablePhone: false }).detect(input)).toEqual([]);
	});

	it("exposes incomplete coverage instead of reporting a clean result", () => {
		const detection = new PiiDetectorImpl().detectWithCoverage('password: "abc');
		expect(detection).toMatchObject({ incomplete: true, reasons: ["INCOMPLETE_SECRET"] });
	});
});

describe("DLP detector performance", () => {
	function best(run: () => void, rounds = 5): number {
		run();
		let fastest = Number.POSITIVE_INFINITY;
		for (let round = 0; round < rounds; round++) {
			const started = performance.now();
			run();
			fastest = Math.min(fastest, performance.now() - started);
		}
		return fastest;
	}

	it("scans 50 KB of mixed text with every detector in under 100 ms", () => {
		const line = `Ad Soyad: Ahmet Yılmaz; Tel: 0532 123 45 67; IBAN ${VALID_IBAN}; const a = f(b, 12345);\n`;
		const content = line.repeat(Math.ceil(51_200 / line.length)).slice(0, 51_200);
		const policy = detectorPolicy([...DlpDetectorSchema.options]);
		const elapsed = best(() =>
			scanDlpInput(policy, { tenantId: TENANT, content, contentType: "text/plain" }),
		);
		expect(elapsed).toBeLessThan(100);
	});

	it("scans 50 KB of JSON with every detector in under 100 ms", () => {
		const records: unknown[] = [];
		while (JSON.stringify(records).length < 51_200) {
			records.push({
				ad: "Ahmet Yılmaz",
				tckn: VALID_TCKN,
				iban: VALID_IBAN,
				not: "Tel: 0532 123 45 67 \u00e7",
				count: 12345,
			});
		}
		const content = JSON.stringify(records);
		const policy = detectorPolicy([...DlpDetectorSchema.options]);
		const run = () =>
			scanDlpInput(policy, { tenantId: TENANT, content, contentType: "application/json" });
		expect(inspected(run()).action).toBe("redact");
		expect(best(run)).toBeLessThan(100);
	});
});
