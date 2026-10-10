import { spawnSync } from "node:child_process";
import { webcrypto } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
// @ts-expect-error -- plain ESM build script without type declarations
import * as fingerprint from "../../scripts/fingerprint-dataset.mjs";
// @ts-expect-error -- plain ESM build script without type declarations
import { decodePng, ICON_SIZES, MASTER_ICON, renderIcons } from "../../scripts/icons.mjs";
// @ts-expect-error -- plain ESM build script without type declarations
import { crc32, createZip, readZip } from "../../scripts/zip.mjs";
import { evaluatePolicy } from "../background/policy";
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

	it("builds a sorted, de-duplicated ExactDataSet from selected columns", () => {
		const rows = fingerprint.parseCsv("id,name\n1,Ayşe Yılmaz\n2,AYŞE YILMAZ\n3,Al\n4,\n");
		const { dataset, stats } = fingerprint.buildDataset({
			rows,
			datasetId: "crm.customers",
			type: "PERSON",
			key: KEY,
			columns: ["name"],
		});
		expect(dataset.datasetId).toBe("crm.customers");
		expect(dataset.type).toBe("PERSON");
		expect(dataset.keyB64).toBe(KEY.toString("base64"));
		expect(dataset.fingerprints).toEqual([fingerprint.fingerprintTokens(KEY, ["ayşe", "yilmaz"])]);
		expect(stats).toEqual({
			values: 3,
			fingerprints: 1,
			skipped: { tooShort: 1, tooManyTokens: 0 },
		});
		expect(JSON.stringify(dataset)).not.toMatch(/ay[sş]e/i);
	});

	it("rejects invalid inputs", () => {
		const rows = [["Ayşe Yılmaz"]];
		const base = { rows, datasetId: "ds", type: "PERSON", key: KEY };
		expect(() => fingerprint.buildDataset({ ...base, datasetId: "bad id" })).toThrow(
			"DATASET_ID_INVALID",
		);
		expect(() => fingerprint.buildDataset({ ...base, type: "SHOE_SIZE" })).toThrow("TYPE_INVALID");
		expect(() => fingerprint.buildDataset({ ...base, key: Buffer.alloc(16) })).toThrow(
			"KEY_TOO_SHORT",
		);
		expect(() => fingerprint.buildDataset({ ...base, rows: [["a"]] })).toThrow("DATASET_EMPTY");
		expect(() =>
			fingerprint.buildDataset({ ...base, rows: [["h"], ["v"]], columns: ["missing"] }),
		).toThrow("COLUMN_NOT_FOUND");
		const long = Array.from({ length: 17 }, (_, i) => `w${i}`).join(" ");
		expect(() => fingerprint.buildDataset({ ...base, rows: [[long]] })).toThrow("DATASET_EMPTY");
	});

	it("CLI writes the dataset with owner-only permissions and never echoes values", () => {
		const dir = tempDir();
		writeFileSync(join(dir, "in.csv"), "name\nİsmail Işık\n");
		writeFileSync(join(dir, "key.b64"), `${KEY.toString("base64")}\n`);
		const out = join(dir, "dataset.json");
		const run = spawnSync(
			process.execPath,
			[
				FINGERPRINT_SCRIPT,
				"--in",
				join(dir, "in.csv"),
				"--dataset-id",
				"hr",
				"--type",
				"PERSON",
				"--header",
				"--key-file",
				join(dir, "key.b64"),
				"--out",
				out,
			],
			{ encoding: "utf8" },
		);
		expect(run.status).toBe(0);
		expect(run.stdout).toBe("");
		expect(run.stderr).toContain("1 value(s) -> 1 fingerprint(s)");
		expect(run.stderr).not.toMatch(/smail|ş[iı]k/i);
		const dataset = JSON.parse(readFileSync(out, "utf8"));
		expect(dataset.fingerprints).toEqual([fingerprint.fingerprintTokens(KEY, ["ismail", "işik"])]);
		if (process.platform !== "win32") expect(statSync(out).mode & 0o777).toBe(0o600);

		const usage = spawnSync(process.execPath, [FINGERPRINT_SCRIPT], { encoding: "utf8" });
		expect(usage.status).toBe(2);
		expect(usage.stderr).toContain("Usage:");
	});

	const exactDataModule = join(PACKAGE_ROOT, "src", "engine", "exact-data.ts");
	it("matches the engine's fingerprintValue()", async () => {
		const engine = (await import(/* @vite-ignore */ exactDataModule)) as {
			fingerprintValue(keyB64: string, value: string): Promise<string>;
		};
		for (const value of ["İsmail Işık", "Jane Q. Doe", "TR33 0006 1005 1978 6457 8413 26"]) {
			expect(await engine.fingerprintValue(KEY.toString("base64"), value)).toBe(
				fingerprint.fingerprintTokens(KEY, fingerprint.normaliseTokens(value)),
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
	// The worker's own validator accepts every key (nothing silently ignored).
	const evaluation = evaluatePolicy(policy, undefined);
	expect(evaluation.warnings).toEqual([]);
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

	it("the example exact-data set is reproducible with fingerprint-dataset", async () => {
		const [dataset] = canonical.exactData as unknown as ExactDataSet[];
		const key = Buffer.from(dataset.keyB64, "base64");
		const { dataset: rebuilt } = fingerprint.buildDataset({
			rows: [["Ayşe Yılmaz"], ["İsmail Işık"], ["Jane Q. Doe"]],
			datasetId: dataset.datasetId,
			type: dataset.type,
			key,
		});
		expect(rebuilt).toEqual(dataset);
		expect(await webCryptoFingerprint(dataset.keyB64, ["jane", "q", "doe"])).toBe(
			fingerprint.fingerprintTokens(key, ["jane", "q", "doe"]),
		);
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

	const schemaFile = join(PACKAGE_ROOT, "static", "managed_schema.json");
	it("every example key is declared in static/managed_schema.json", () => {
		const schema = JSON.parse(readFileSync(schemaFile, "utf8"));
		for (const key of Object.keys(canonical)) expect(schema.properties).toHaveProperty(key);
	});
});
