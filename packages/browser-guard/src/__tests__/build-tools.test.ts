import { spawnSync } from "node:child_process";
import { webcrypto } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { deriveEdmKey, EDM_KEY_LABEL } from "../../../privacy/src/native/edm";
// @ts-expect-error -- plain ESM build script without type declarations
import * as fingerprint from "../../scripts/fingerprint-dataset.mjs";
// @ts-expect-error -- plain ESM build script without type declarations
import { decodePng, ICON_SIZES, MASTER_ICON, renderIcons } from "../../scripts/icons.mjs";
// @ts-expect-error -- plain ESM build script without type declarations
import { crc32, createZip, readZip } from "../../scripts/zip.mjs";
import { EXACT_DATA_MIN_ENTROPY_BITS, evaluatePolicy } from "../background/policy";
import { createExactDataMatcher, ExactDataConfigError } from "../engine/exact-data";
import { ENTITY_TYPES, type ExactDataSet } from "../types";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const REPO_ROOT = resolve(PACKAGE_ROOT, "..", "..");
const DEPLOY = join(REPO_ROOT, "deploy", "browser-guard");
const FINGERPRINT_SCRIPT = join(PACKAGE_ROOT, "scripts", "fingerprint-dataset.mjs");

const temps: string[] = [];
function tempDir(): string {
	const dir = mkdtempSync(join(tmpdir(), "aidr-bg-tools-"));
	temps.push(dir);
	return dir;
}
afterAll(() => {
	for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

/** Mirrors the extension side: WebCrypto HMAC-SHA256 over JSON.stringify(tokens). */
async function webCryptoFingerprint(keyB64: string, tokens: readonly string[]): Promise<string> {
	const key = await webcrypto.subtle.importKey(
		"raw",
		Buffer.from(keyB64, "base64"),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const mac = await webcrypto.subtle.sign(
		"HMAC",
		key,
		new TextEncoder().encode(JSON.stringify(tokens)),
	);
	return Buffer.from(mac).toString("hex");
}

const KEY = Buffer.alloc(32, 7);
/** The organisation's EDM secret (test bytes); dataset keys are derived from it. */
const SECRET = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 11 + 5) & 0xff));
const NATIVE_FORCED =
	'"useNativeHost" forced on because managed "exactData" needs the native host for its keys';

describe("fingerprint-dataset", () => {
	it("keeps its entity list in sync with src/types.ts", () => {
		expect([...fingerprint.ENTITY_TYPES]).toEqual([...ENTITY_TYPES]);
	});

	it("normalises with NFKC, lowercase, Turkish folding and zero-width stripping", () => {
		expect(fingerprint.normaliseTokens("İsmail IŞIK")).toEqual(["ismail", "işik"]);
		expect(fingerprint.normaliseTokens("ısparta")).toEqual(["isparta"]);
		expect(fingerprint.normaliseTokens("Ay\u200bşe\ufeff  Yılmaz!")).toEqual(["ayşe", "yilmaz"]);
		expect(fingerprint.normaliseTokens("ＡＣＭＥ－42")).toEqual(["acme", "42"]);
		expect(fingerprint.normaliseTokens("--- ...")).toEqual([]);
	});

	it("produces the same fingerprint as the extension's WebCrypto HMAC", async () => {
		const tokens = fingerprint.normaliseTokens("Jane Q. Doe");
		expect(fingerprint.fingerprintTokens(KEY, tokens)).toBe(
			await webCryptoFingerprint(KEY.toString("base64"), tokens),
		);
	});

	it("parses RFC 4180 CSV", () => {
		expect(fingerprint.parseCsv('\ufeffa,b\r\n"x, y","say ""hi"""\n\n"multi\nline",z')).toEqual([
			["a", "b"],
			["x, y", 'say "hi"'],
			["multi\nline", "z"],
		]);
		expect(() => fingerprint.parseCsv('"open')).toThrow("CSV_UNTERMINATED_QUOTE");
	});

	it("builds a sorted, de-duplicated, keyless ExactDataSet from composite columns", () => {
		const rows = fingerprint.parseCsv(
			"id,name,account\n1,Ayşe Yılmaz,1234567890123456\n2,AYŞE YILMAZ,1234567890123456\n3,Al,\n",
		);
		const { dataset, stats } = fingerprint.buildDataset({
			rows,
			datasetId: "crm.customers",
			type: "PERSON",
			secret: SECRET,
			columns: ["name", "account"],
			composite: true,
		});
		const key = fingerprint.deriveDatasetKey(SECRET, "crm.customers");
		expect(dataset).toEqual({
			datasetId: "crm.customers",
			keySource: "native-host",
			// ayşe (8) + yilmaz (12) + 16 digits (53.2)
			minEntropyBits: 73,
			fingerprints: [fingerprint.fingerprintTokens(key, ["ayşe", "yilmaz", "1234567890123456"])],
			type: "PERSON",
		});
		expect(stats).toEqual({
			values: 2,
			fingerprints: 1,
			skipped: { tooShort: 0, tooManyTokens: 0, lowEntropy: 0 },
		});
		// No value, no key and no secret in the output.
		const json = JSON.stringify(dataset);
		expect(json).not.toMatch(/ay[sş]e|1234567890/i);
		expect(json).not.toContain(key.toString("base64"));
		expect(json).not.toContain(SECRET.toString("base64"));
		expect(json).not.toContain("keyB64");
	});

	it("derives the dataset key exactly like the native host (BG-8)", () => {
		expect(fingerprint.EDM_KEY_LABEL).toBe(EDM_KEY_LABEL);
		expect(fingerprint.MIN_ENTROPY_BITS).toBe(EXACT_DATA_MIN_ENTROPY_BITS);
		for (const id of ["crm.customers", "a", "x".repeat(64)]) {
			expect(fingerprint.deriveDatasetKey(SECRET, id).equals(deriveEdmKey(SECRET, id))).toBe(true);
		}
		expect(
			fingerprint.deriveDatasetKey(SECRET, "a").equals(fingerprint.deriveDatasetKey(SECRET, "b")),
		).toBe(false);
	});

	it("estimates entropy conservatively and caps structured identifiers", () => {
		const bits = (value: string, type: string) =>
			fingerprint.estimateEntropyBits(fingerprint.normaliseTokens(value), type);
		expect(bits("4829173", "BANK_ACCOUNT")).toBeCloseTo(7 * Math.log2(10));
		expect(bits("10000000146", "TC_KIMLIK")).toBe(30);
		expect(bits("10000000146", "PERSON")).toBeCloseTo(11 * Math.log2(10));
		expect(bits("Ayşe Yılmaz", "PERSON")).toBe(20);
		expect(bits("Muhammedmustafa Abdurrahmanoğlu", "PERSON")).toBe(32);
		expect(bits("4111 1111 1111 1111", "CREDIT_CARD")).toBe(30);
		expect(bits("TR33 0006 1005 1978 6457 8413 26", "IBAN")).toBe(56);
		expect(bits("ACME42", "INTERNAL")).toBeCloseTo(8 + 2 * Math.log2(10));
	});

	it("refuses a dataset of enumerable values, the auditor's brute-force case (BG-8)", () => {
		// 7-digit account numbers: about 23 bits, recovered in ~30 s on one core when the key leaks.
		const accounts = [["4829173"], ["7710452"]];
		const base = { rows: accounts, datasetId: "crm-acct", type: "BANK_ACCOUNT", secret: SECRET };
		expect(() => fingerprint.buildDataset(base)).toThrow(/^LOW_ENTROPY: 2 of 2 value\(s\)/);
		for (const [rows, type] of [
			[[["10000000146"]], "TC_KIMLIK"],
			[[["Ayşe Yılmaz"]], "PERSON"],
			[[["+90 532 123 45 67"]], "PHONE"],
			[[["ayse.yilmaz@example.com"]], "EMAIL"],
		] as const)
			expect(() => fingerprint.buildDataset({ ...base, rows, type })).toThrow("LOW_ENTROPY");
		expect(() => fingerprint.buildDataset({ ...base, dropLowEntropy: true })).toThrow(
			"DATASET_EMPTY",
		);
		const mixed = fingerprint.buildDataset({
			...base,
			type: "INTERNAL",
			rows: [["4829173"], ["7f3k9q2m8x4w1z6p5r2t9y4u8i3o7a1s"]],
			dropLowEntropy: true,
		});
		expect(mixed.stats.skipped.lowEntropy).toBe(1);
		expect(mixed.dataset.fingerprints).toHaveLength(1);
		expect(mixed.dataset.minEntropyBits).toBeGreaterThanOrEqual(EXACT_DATA_MIN_ENTROPY_BITS);
	});

	it("rejects invalid inputs", () => {
		const rows = [["Ayşe Yılmaz 1234567890123456"]];
		const base = { rows, datasetId: "ds", type: "PERSON", secret: SECRET };
		expect(fingerprint.buildDataset(base).dataset.fingerprints).toHaveLength(1);
		expect(() => fingerprint.buildDataset({ ...base, datasetId: "bad id" })).toThrow(
			"DATASET_ID_INVALID",
		);
		expect(() => fingerprint.buildDataset({ ...base, type: "SHOE_SIZE" })).toThrow("TYPE_INVALID");
		expect(() => fingerprint.buildDataset({ ...base, secret: Buffer.alloc(16) })).toThrow(
			"SECRET_TOO_SHORT",
		);
		expect(() => fingerprint.buildDataset({ ...base, minEntropyBits: 32 })).toThrow(
			"MIN_ENTROPY_INVALID",
		);
		expect(() => fingerprint.buildDataset({ ...base, composite: true, columns: ["a"] })).toThrow(
			"COMPOSITE_NEEDS_COLUMNS",
		);
		expect(() => fingerprint.buildDataset({ ...base, rows: [["a"]] })).toThrow("DATASET_EMPTY");
		expect(() =>
			fingerprint.buildDataset({ ...base, rows: [["h"], ["v"]], columns: ["missing"] }),
		).toThrow("COLUMN_NOT_FOUND");
		const long = Array.from({ length: 17 }, (_, i) => `w${i}`).join(" ");
		expect(() => fingerprint.buildDataset({ ...base, rows: [[long]] })).toThrow("DATASET_EMPTY");
	});

	it("CLI makes a secret, writes a keyless dataset owner-only and never echoes values", () => {
		const dir = tempDir();
		writeFileSync(join(dir, "in.csv"), "name,no\nİsmail Işık,90412233445566778\n");
		const secretFile = join(dir, "edm.b64");
		const made = spawnSync(process.execPath, [FINGERPRINT_SCRIPT, "--new-secret", secretFile], {
			encoding: "utf8",
		});
		expect(made.status).toBe(0);
		const secret = fingerprint.decodeSecret(readFileSync(secretFile, "utf8"));
		expect(secret).toHaveLength(32);
		if (process.platform !== "win32") expect(statSync(secretFile).mode & 0o777).toBe(0o600);
		// Never overwrites an existing secret.
		expect(
			spawnSync(process.execPath, [FINGERPRINT_SCRIPT, "--new-secret", secretFile]).status,
		).toBe(1);
		const out = join(dir, "dataset.json");
		const args = (...extra: string[]) => [
			FINGERPRINT_SCRIPT,
			"--in",
			join(dir, "in.csv"),
			"--dataset-id",
			"hr",
			"--type",
			"PERSON",
			"--header",
			...extra,
		];
		const run = spawnSync(
			process.execPath,
			args("--columns", "name,no", "--composite", "--secret-file", secretFile, "--out", out),
			{ encoding: "utf8" },
		);
		expect(run.status).toBe(0);
		expect(run.stdout).toBe("");
		expect(run.stderr).toContain("1 value(s) -> 1 fingerprint(s)");
		expect(run.stderr).not.toMatch(/smail|ş[iı]k|9041223/i);
		const text = readFileSync(out, "utf8");
		const dataset = JSON.parse(text);
		const key = fingerprint.deriveDatasetKey(secret, "hr");
		expect(dataset.fingerprints).toEqual([
			fingerprint.fingerprintTokens(key, ["ismail", "işik", "90412233445566778"]),
		]);
		expect(text).not.toContain(secret.toString("base64"));
		expect(dataset.keyB64).toBeUndefined();
		if (process.platform !== "win32") expect(statSync(out).mode & 0o777).toBe(0o600);

		// A name column alone is refused, without echoing a value.
		const weak = spawnSync(
			process.execPath,
			args("--columns", "name", "--secret-file", secretFile),
			{ encoding: "utf8" },
		);
		expect(weak.status).toBe(1);
		expect(weak.stderr).toContain("LOW_ENTROPY");
		expect(weak.stderr).not.toMatch(/smail|ş[iı]k/i);
		// The old key options are refused: a dataset must not carry its key any more.
		const legacy = spawnSync(process.execPath, args("--key-b64", KEY.toString("base64")), {
			encoding: "utf8",
		});
		expect(legacy.status).toBe(1);
		expect(legacy.stderr).toContain("--key-b64 is no longer supported");

		const usage = spawnSync(process.execPath, [FINGERPRINT_SCRIPT], { encoding: "utf8" });
		expect(usage.status).toBe(2);
		expect(usage.stderr).toContain("Usage:");
	});

	const exactDataModule = join(PACKAGE_ROOT, "src", "engine", "exact-data.ts");
	it("matches the engine's fingerprintValue() with the host-derived key", async () => {
		const engine = (await import(/* @vite-ignore */ exactDataModule)) as {
			fingerprintValue(keyB64: string, value: string): Promise<string>;
		};
		const key = deriveEdmKey(SECRET, "crm");
		for (const value of ["İsmail Işık", "Jane Q. Doe", "TR33 0006 1005 1978 6457 8413 26"]) {
			expect(await engine.fingerprintValue(key.toString("base64"), value)).toBe(
				fingerprint.fingerprintTokens(
					fingerprint.deriveDatasetKey(SECRET, "crm"),
					fingerprint.normaliseTokens(value),
				),
			);
		}
	});
});

describe("zip writer", () => {
	it("computes the standard CRC-32 check value", () => {
		expect(crc32(Buffer.from("123456789"))).toBe(0xcbf43926);
	});

	it("round-trips entries sorted with fixed timestamps", () => {
		const entries = [
			{ name: "b/two.txt", data: Buffer.from("two ".repeat(50)) },
			{ name: "a.bin", data: Buffer.from([0, 1, 2, 3]) },
		];
		const archive = createZip(entries);
		expect(createZip([...entries].reverse())).toEqual(archive);
		const files = readZip(archive);
		expect([...files.keys()]).toEqual(["a.bin", "b/two.txt"]);
		expect(files.get("b/two.txt")).toEqual(entries[0].data);
	});

	it("rejects unsafe or duplicate entry names", () => {
		for (const name of ["", "/abs", "../up", "a//b", "a\\b", "./x"]) {
			expect(() => createZip([{ name, data: Buffer.alloc(1) }])).toThrow("ZIP_INVALID_ENTRY_NAME");
		}
		expect(() =>
			createZip([
				{ name: "x", data: Buffer.alloc(1) },
				{ name: "x", data: Buffer.alloc(1) },
			]),
		).toThrow("ZIP_DUPLICATE_ENTRY");
	});

	const unzip = spawnSync("unzip", ["-v"], { encoding: "utf8" });
	// AIDR-SKIP: AIDR-063 qa-owner - cross-checks the ZIP writer against Info-ZIP unzip, an optional host tool
	it.skipIf(unzip.status !== 0)("is accepted by Info-ZIP unzip", () => {
		const dir = tempDir();
		const file = join(dir, "t.zip");
		writeFileSync(
			file,
			createZip([
				{ name: "manifest.json", data: Buffer.from('{"manifest_version":3}') },
				{
					name: "icons/icon-16.png",
					data: readFileSync(join(PACKAGE_ROOT, "static/icons/icon-16.png")),
				},
			]),
		);
		const test = spawnSync("unzip", ["-t", file], { encoding: "utf8" });
		expect(test.status).toBe(0);
		expect(test.stdout).toContain("No errors detected");
	});
});

describe("icons", () => {
	it("committed icons are the current rendering of the brand master", () => {
		const rendered = renderIcons(readFileSync(MASTER_ICON));
		for (const size of ICON_SIZES) {
			const committed = readFileSync(join(PACKAGE_ROOT, "static", "icons", `icon-${size}.png`));
			expect(committed.equals(rendered.get(size))).toBe(true);
			const image = decodePng(committed);
			expect([image.width, image.height]).toEqual([size, size]);
			// The shield is opaque in the centre and the corners are transparent.
			const centre = ((size >> 1) * size + (size >> 1)) * 4;
			expect(image.data[centre + 3]).toBe(255);
			expect(image.data[3]).toBe(0);
		}
	});
});

// ---------------------------------------------------------------------------
// Deployment examples
// ---------------------------------------------------------------------------

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** Managed policy keys the background worker accepts (src/background/policy.ts mergePolicy). */
const MANAGED_KEYS = [
	"mode",
	"enabledEntities",
	"neverRestore",
	"literals",
	"exactData",
	"detectSignals",
	"signalAction",
	"blockedSites",
	"disabledSites",
	"customSites",
	"shadowAi",
	"allowUserPause",
	"allowSendAnyway",
	"maskPaste",
	"fileHandling",
	"maxFileBytes",
	"restoreResponses",
	"useNativeHost",
	"requireNativeNer",
	"telemetry",
	"language",
	"policyId",
	"allowUserOverrides",
];
const SITE_IDS = [
	"chatgpt",
	"gemini",
	"claude",
	"copilot",
	"perplexity",
	"deepseek",
	"mistral",
	"grok",
	"custom",
	"other",
];
const EXACT_DATA_PLACEHOLDER_WARNING =
	'managed: "exactData" still holds the example placeholder key; ignored. Build each dataset with fingerprint-dataset.mjs';
const CHROME_ID = "REPLACE_WITH_CHROME_EXTENSION_ID";
const EDGE_ID = "REPLACE_WITH_EDGE_EXTENSION_ID";

function readDeploy(name: string): string {
	return readFileSync(join(DEPLOY, name), "utf8");
}

function assertValidPolicy(policy: Record<string, Json>): void {
	expect(Object.keys(policy).sort()).toEqual([...MANAGED_KEYS].sort());
	expect(["auto", "confirm", "block", "monitor"]).toContain(policy.mode);
	for (const key of ["enabledEntities", "neverRestore"]) {
		for (const type of policy[key] as string[]) expect(ENTITY_TYPES).toContain(type);
	}
	for (const key of ["blockedSites", "disabledSites"]) {
		for (const site of policy[key] as string[]) expect(SITE_IDS).toContain(site);
	}
	for (const literal of policy.literals as { value: string; type: string }[]) {
		expect(literal.value.length).toBeGreaterThanOrEqual(2);
		expect(literal.value.length).toBeLessThanOrEqual(256);
		expect(ENTITY_TYPES).toContain(literal.type);
	}
	expect(["off", "warn", "block"]).toContain(policy.signalAction);
	expect(["scan", "block", "allow"]).toContain(policy.fileHandling);
	expect(["auto", "en", "tr"]).toContain(policy.language);
	expect(policy.maxFileBytes).toBeLessThanOrEqual(50 * 1024 * 1024);
	expect(policy.policyId).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
	// Documented, but off: requiring native NER blocks every send where no host is installed.
	expect(policy.requireNativeNer).toBe(false);
	expect(policy.useNativeHost).toBe(false);
	const telemetry = policy.telemetry as { controlPlaneUrl: string; apiKey: string };
	expect(Object.keys(telemetry).sort()).toEqual(["apiKey", "controlPlaneUrl"]);
	expect(telemetry.controlPlaneUrl).toMatch(/^https:\/\//);
	// The worker's own validator accepts every key (nothing silently ignored) except the
	// example exact-data set, which is a placeholder the worker refuses by name.
	const evaluation = evaluatePolicy(policy, undefined);
	expect(evaluation.warnings).toEqual([EXACT_DATA_PLACEHOLDER_WARNING]);
	expect(evaluation.policy.exactData).toEqual([]);
	expect(evaluation.policy.customSites.map((site) => site.hosts)).toEqual([["gpt.acme.example"]]);
	expect(evaluation.policy.shadowAi.mode).toBe("block-unsanctioned");
}

/** Minimal XML plist reader for the example profile (dict/array/string/integer/true/false). */
function parsePlist(xml: string): Json {
	const tokens = [
		...xml
			.replace(/<\?xml[^>]*>|<!DOCTYPE[^>]*>/g, "")
			.matchAll(/<(\/?)(\w+)(?:\s[^>]*?)?(\/?)>([^<]*)/g),
	];
	let i = 0;
	const decode = (text: string) =>
		text
			.replace(/&lt;/g, "<")
			.replace(/&gt;/g, ">")
			.replace(/&quot;/g, '"')
			.replace(/&amp;/g, "&");
	/** Reads children until the closing tag of the current container, then consumes it. */
	function children<T>(read: () => T): T[] {
		const out: T[] = [];
		while (!tokens[i][1]) out.push(read());
		i++;
		return out;
	}
	const entry = (): [string, Json] => {
		const key = decode(tokens[i][4]);
		i += 2;
		return [key, value()];
	};
	const readers: Record<string, (text: string, selfClosing: boolean) => Json> = {
		true: () => true,
		false: () => false,
		string: (text) => (i++, decode(text)),
		integer: (text) => (i++, Number(text)),
		array: (_text, selfClosing) => (selfClosing ? [] : children(value)),
		dict: (_text, selfClosing) => (selfClosing ? {} : Object.fromEntries(children(entry))),
		plist: () => children(value)[0],
	};
	function value(): Json {
		const [, close, tag, selfClosing, text] = tokens[i++];
		const read = readers[tag];
		if (close || !read) throw new Error(`unexpected plist tag ${close}${tag}`);
		return read(text, selfClosing === "/");
	}
	return value();
}

/** Parses a .reg export into { keyPath: { valueName: string | number } }. */
function parseReg(text: string): Record<string, Record<string, string | number>> {
	const keys: Record<string, Record<string, string | number>> = {};
	let current: Record<string, string | number> | null = null;
	for (const line of text.split(/\r?\n/)) {
		if (line.startsWith("[")) {
			current = {};
			keys[line.slice(1, -1)] = current;
			continue;
		}
		const match = /^"([^"]+)"=(?:dword:([0-9a-f]{8})|"((?:[^"\\]|\\.)*)")$/.exec(line);
		if (!match) continue;
		if (!current) throw new Error(`value outside a key: ${line}`);
		current[match[1]] =
			match[2] !== undefined ? Number.parseInt(match[2], 16) : match[3].replace(/\\(["\\])/g, "$1");
	}
	return keys;
}

/** Converts registry-typed values back to the managed-storage JSON shape. */
function fromRegistry(values: Record<string, string | number>): Record<string, Json> {
	const out: Record<string, Json> = {};
	for (const [key, raw] of Object.entries(values)) {
		if (typeof raw === "number") out[key] = key === "maxFileBytes" ? raw : raw === 1;
		else out[key] = /^[[{]/.test(raw) ? JSON.parse(raw) : raw;
	}
	return out;
}

describe("deployment examples", () => {
	const chrome = JSON.parse(readDeploy("chrome-managed-policy.example.json"));
	const canonical = chrome["3rdparty"].extensions[CHROME_ID] as Record<string, Json>;

	it("Chrome policy force-installs the extension and sets a complete, valid policy", () => {
		expect(chrome.ExtensionSettings[CHROME_ID].installation_mode).toBe("force_installed");
		expect(chrome.ExtensionInstallForcelist).toEqual([
			`${CHROME_ID};https://clients2.google.com/service/update2/crx`,
		]);
		assertValidPolicy(canonical);
	});

	it("the example exact-data set is a keyless placeholder (BG-8)", () => {
		const [dataset] = canonical.exactData as unknown as ExactDataSet[];
		expect(dataset.keyB64).toBeUndefined();
		expect(dataset.keySource).toBe("native-host");
		expect(dataset.minEntropyBits).toBe(EXACT_DATA_MIN_ENTROPY_BITS);
		expect(dataset.fingerprints).toEqual(["REPLACE_WITH_FINGERPRINTS_FROM_FINGERPRINT_DATASET"]);
		expect(() => createExactDataMatcher([dataset])).toThrow(ExactDataConfigError);
		// No example file carries a key any more (managed policy is readable by every user).
		for (const file of [
			"chrome-managed-policy.example.json",
			"firefox-policies.example.json",
			"edge-intune.example.json",
			"macos-jamf.example.mobileconfig",
			"windows-registry.example.reg",
		]) {
			const text = readDeploy(file);
			expect(text).toContain("REPLACE_WITH_FINGERPRINTS_FROM_FINGERPRINT_DATASET");
			expect(text).not.toContain("keyB64");
		}
	});

	it("a dataset built with fingerprint-dataset replaces the placeholder and is accepted", async () => {
		const [example] = canonical.exactData as unknown as ExactDataSet[];
		const { dataset } = fingerprint.buildDataset({
			rows: [["Ayşe Yılmaz 4111111111111111"], ["Jane Q. Doe 99887766554433221"]],
			datasetId: example.datasetId,
			type: example.type,
			secret: SECRET,
		});
		expect(dataset.fingerprints).toHaveLength(2);
		// The extension fingerprints with the key the native host derives for this dataset.
		const hostKey = deriveEdmKey(SECRET, example.datasetId).toString("base64");
		expect(await webCryptoFingerprint(hostKey, ["jane", "q", "doe", "99887766554433221"])).toBe(
			fingerprint.fingerprintTokens(fingerprint.deriveDatasetKey(SECRET, example.datasetId), [
				"jane",
				"q",
				"doe",
				"99887766554433221",
			]),
		);
		const evaluation = evaluatePolicy({ ...canonical, exactData: [dataset] }, undefined);
		expect(evaluation.warnings).toEqual([NATIVE_FORCED]);
		expect(evaluation.policy.exactData).toEqual([dataset]);
		expect(evaluation.policy.useNativeHost).toBe(true);
	});

	it("Firefox policies.json carries the same policy for the gecko id", () => {
		const firefox = JSON.parse(readDeploy("firefox-policies.example.json")).policies;
		const id = "browser-guard@singularityrd.com";
		expect(firefox.ExtensionSettings[id].installation_mode).toBe("force_installed");
		expect(firefox.ExtensionSettings[id].install_url).toMatch(/^https:\/\/.+\.xpi$/);
		expect(firefox["3rdparty"].Extensions[id]).toEqual(canonical);
	});

	it("the Windows .reg file carries the same policy for Chrome and Edge", () => {
		const text = readDeploy("windows-registry.example.reg");
		expect(text).toMatch(/^Windows Registry Editor Version 5\.00\r?\n/);
		const keys = parseReg(text);
		const chromeBase = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome";
		const edgeBase = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Edge";
		expect(keys[`${chromeBase}\\ExtensionInstallForcelist`]["1"]).toMatch(
			new RegExp(`^${CHROME_ID};https://`),
		);
		expect(keys[`${edgeBase}\\ExtensionInstallForcelist`]["1"]).toMatch(
			new RegExp(`^${EDGE_ID};https://`),
		);
		expect(fromRegistry(keys[`${chromeBase}\\3rdparty\\extensions\\${CHROME_ID}\\policy`])).toEqual(
			canonical,
		);
		expect(fromRegistry(keys[`${edgeBase}\\3rdparty\\extensions\\${EDGE_ID}\\policy`])).toEqual(
			canonical,
		);
	});

	it("the Intune example carries the same policy as registry values", () => {
		const intune = JSON.parse(readDeploy("edge-intune.example.json"));
		expect(intune.managedConfiguration.registryKey).toBe(
			`HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\3rdparty\\extensions\\${EDGE_ID}\\policy`,
		);
		const values: Record<string, string | number> = {};
		for (const [key, entry] of Object.entries(
			intune.managedConfiguration.values as Record<
				string,
				{ type: string; value: string | number }
			>,
		)) {
			expect(["REG_SZ", "REG_DWORD"]).toContain(entry.type);
			expect(typeof entry.value).toBe(entry.type === "REG_DWORD" ? "number" : "string");
			values[key] = entry.value;
		}
		expect(fromRegistry(values)).toEqual(canonical);
		const forcelist = intune.settingsCatalog.find(
			(s: { policy: string }) => s.policy === "ExtensionInstallForcelist",
		);
		expect(forcelist.value).toEqual([
			`${EDGE_ID};https://edge.microsoft.com/extensionwebstorebase/v1/crx`,
		]);
	});

	it("the macOS profile installs in Chrome and Edge and carries the same policy", () => {
		const profile = parsePlist(readDeploy("macos-jamf.example.mobileconfig")) as Record<
			string,
			Json
		>;
		expect(profile.PayloadType).toBe("Configuration");
		const payloads = profile.PayloadContent as Record<string, Json>[];
		const byType = new Map(payloads.map((p) => [p.PayloadType as string, p]));
		const uuids = new Set(payloads.map((p) => p.PayloadUUID));
		expect(uuids.size).toBe(payloads.length);
		expect(byType.get("com.google.Chrome")?.ExtensionInstallForcelist).toEqual(
			chrome.ExtensionInstallForcelist,
		);
		expect(byType.get("com.microsoft.Edge")?.ExtensionInstallForcelist).toEqual([
			`${EDGE_ID};https://edge.microsoft.com/extensionwebstorebase/v1/crx`,
		]);
		for (const type of [
			`com.google.Chrome.extensions.${CHROME_ID}`,
			`com.microsoft.Edge.extensions.${EDGE_ID}`,
		]) {
			const payload = { ...byType.get(type) } as Record<string, Json>;
			for (const key of Object.keys(payload)) if (key.startsWith("Payload")) delete payload[key];
			expect(payload).toEqual(canonical);
		}
	});

	// GA audit BG-5: without these a private window, a Guest profile, the page console or
	// another extension gives an unprotected path to the same AI sites.
	const hardening = (privateMode: string, id: string) => ({
		[privateMode]: 1,
		BrowserGuestModeEnabled: false,
		DeveloperToolsAvailability: 2,
		ExtensionInstallBlocklist: ["*"],
		ExtensionInstallAllowlist: [id],
	});

	it("every example carries the browser hardening policies (private mode, Guest, DevTools, extensions)", () => {
		expect(chrome).toMatchObject(hardening("IncognitoModeAvailability", CHROME_ID));

		const firefox = JSON.parse(readDeploy("firefox-policies.example.json")).policies;
		expect(firefox.DisablePrivateBrowsing).toBe(true);
		expect(firefox.DisableDeveloperTools).toBe(true);
		expect(firefox.ExtensionSettings["*"].installation_mode).toBe("blocked");

		const intune = JSON.parse(readDeploy("edge-intune.example.json"));
		const catalog = Object.fromEntries(
			(intune.settingsCatalog as { policy: string; value: Json }[]).map((s) => [s.policy, s.value]),
		);
		expect(catalog).toMatchObject(hardening("InPrivateModeAvailability", EDGE_ID));

		const reg = parseReg(readDeploy("windows-registry.example.reg"));
		for (const [base, privateMode, id] of [
			[
				"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome",
				"IncognitoModeAvailability",
				CHROME_ID,
			],
			[
				"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Edge",
				"InPrivateModeAvailability",
				EDGE_ID,
			],
		]) {
			expect(reg[base]).toEqual({
				[privateMode]: 1,
				BrowserGuestModeEnabled: 0,
				DeveloperToolsAvailability: 2,
			});
			expect(reg[`${base}\\ExtensionInstallBlocklist`]).toEqual({ "1": "*" });
			expect(reg[`${base}\\ExtensionInstallAllowlist`]).toEqual({ "1": id });
		}

		const profile = parsePlist(readDeploy("macos-jamf.example.mobileconfig")) as Record<
			string,
			Json
		>;
		const byType = new Map(
			(profile.PayloadContent as Record<string, Json>[]).map((p) => [p.PayloadType as string, p]),
		);
		expect(byType.get("com.google.Chrome")).toMatchObject(
			hardening("IncognitoModeAvailability", CHROME_ID),
		);
		expect(byType.get("com.microsoft.Edge")).toMatchObject(
			hardening("InPrivateModeAvailability", EDGE_ID),
		);
	});

	const schemaFile = join(PACKAGE_ROOT, "static", "managed_schema.json");
	it("every example key is declared in static/managed_schema.json", () => {
		const schema = JSON.parse(readFileSync(schemaFile, "utf8"));
		for (const key of Object.keys(canonical)) expect(schema.properties).toHaveProperty(key);
	});
});
