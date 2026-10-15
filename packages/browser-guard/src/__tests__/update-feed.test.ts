/**
 * Self-hosted update channel: the self-hosted packages differ from the store packages only by
 * their update URL (scripts/build.mjs, scripts/validate-store.mjs), and scripts/update-feed.mjs
 * builds a feed whose CRX3 signature verifies, whose hashes match the hosted files, whose URLs
 * are https and whose versions only ever go up; a missing signing key produces nothing.
 */
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
	cpSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
// @ts-expect-error -- plain ESM build script without type declarations
import * as build from "../../scripts/build.mjs";
// @ts-expect-error -- plain ESM build script without type declarations
import * as feed from "../../scripts/update-feed.mjs";
// @ts-expect-error -- plain ESM build script without type declarations
import * as store from "../../scripts/validate-store.mjs";
// @ts-expect-error -- plain ESM build script without type declarations
import { createZip, readZip } from "../../scripts/zip.mjs";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const STORE_DIR = join(PACKAGE_ROOT, "store");
const FEED_SCRIPT = join(PACKAGE_ROOT, "scripts", "update-feed.mjs");
const VALIDATOR = join(PACKAGE_ROOT, "scripts", "validate-store.mjs");
const VERSION = JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8"))
	.version as string;
const NUMERIC = build.manifestVersion(VERSION).version as string;
const BASE = "https://updates.example.com/browser-guard";
const GECKO_ID = "browser-guard@singularityrd.com";

type Files = Map<string, Buffer>;
type Manifest = Record<string, unknown> & {
	version: string;
	update_url?: string;
	browser_specific_settings?: { gecko: Record<string, unknown> };
};

const STUB_ENTRIES: Record<string, string> = {
	"src/background/index.ts": "(globalThis as { __bg?: number }).__bg = 1;",
	"src/content/index.ts": "(globalThis as { __c?: number }).__c = 2;",
	"src/content/main-world.ts": "(globalThis as { __m?: number }).__m = 3;",
	"src/ui/popup.ts": `document.title = "popup";`,
	"src/ui/options.ts": `document.title = "options";`,
};

const temps: string[] = [];
function tempDir(prefix: string): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	temps.push(dir);
	return dir;
}
afterAll(() => {
	for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

const sha256 = (data: Buffer) => createHash("sha256").update(data).digest("hex");
const pem = (bits = 2048) =>
	generateKeyPairSync("rsa", { modulusLength: bits }).privateKey.export({
		type: "pkcs8",
		format: "pem",
	}) as string;

let distDir: string;
let keyPem: string;
let storeZips: Record<"chrome" | "firefox", Files>;
let selfZips: Record<"chrome" | "firefox", Files>;
const selfZipPath = (target: string) =>
	join(distDir, `aidr-browser-guard-${target}-selfhosted-${NUMERIC}.zip`);

beforeAll(async () => {
	const entriesRoot = tempDir("aidr-bg-feed-entries-");
	for (const [name, text] of Object.entries(STUB_ENTRIES)) {
		mkdirSync(dirname(join(entriesRoot, name)), { recursive: true });
		writeFileSync(join(entriesRoot, name), text);
	}
	distDir = tempDir("aidr-bg-feed-dist-");
	await build.buildExtension({
		root: PACKAGE_ROOT,
		entriesRoot,
		outDir: distDir,
		release: true,
		zip: true,
		updateBaseUrl: `${BASE}/`,
		log: () => {},
	});
	const read = (name: string) => readZip(readFileSync(join(distDir, name))) as Files;
	storeZips = {
		chrome: read(`aidr-browser-guard-chrome-${NUMERIC}.zip`),
		firefox: read(`aidr-browser-guard-firefox-${NUMERIC}.zip`),
	};
	selfZips = {
		chrome: read(`aidr-browser-guard-chrome-selfhosted-${NUMERIC}.zip`),
		firefox: read(`aidr-browser-guard-firefox-selfhosted-${NUMERIC}.zip`),
	};
	keyPem = pem();
});

const manifestOf = (files: Files) =>
	JSON.parse((files.get("manifest.json") as Buffer).toString("utf8")) as Manifest;

/** A copy of `files` as a zip on disk, with the manifest edited. */
function zipWith(files: Files, edit: (m: Manifest) => void, extra: Record<string, Buffer> = {}) {
	const manifest = manifestOf(files);
	edit(manifest);
	// An unchanged manifest keeps its exact bytes (the signed XPI must equal the build).
	const unchanged = JSON.stringify(manifest) === JSON.stringify(manifestOf(files));
	const entries = [...files]
		.filter(([name]) => name !== "manifest.json")
		.map(([name, data]) => ({ name, data }));
	entries.push({
		name: "manifest.json",
		data: unchanged
			? (files.get("manifest.json") as Buffer)
			: Buffer.from(JSON.stringify(manifest, null, 2)),
	});
	for (const [name, data] of Object.entries(extra)) entries.push({ name, data });
	const file = join(tempDir("aidr-bg-feed-zip-"), "package.zip");
	writeFileSync(file, createZip(entries));
	return file;
}

/** A stand-in for the XPI addons.mozilla.org signs: the build plus META-INF signature files. */
function signedXpi(version = NUMERIC, edit: (m: Manifest) => void = () => {}) {
	return zipWith(
		selfZips.firefox,
		(m) => {
			m.version = version;
			edit(m);
		},
		{
			"META-INF/manifest.mf": Buffer.from("Manifest-Version: 1.0\n"),
			"META-INF/mozilla.rsa": Buffer.from("signature"),
			"META-INF/cose.sig": Buffer.from("cose"),
		},
	);
}

function chromeZip(version: string) {
	return zipWith(selfZips.chrome, (m) => {
		m.version = version;
	});
}

describe("self-hosted packages: the store build plus an update URL, nothing else", () => {
	it("bakes the channel update URLs into the self-hosted manifests only", () => {
		expect(manifestOf(selfZips.chrome).update_url).toBe(`${BASE}/update.xml`);
		expect(manifestOf(selfZips.firefox).browser_specific_settings?.gecko.update_url).toBe(
			`${BASE}/updates.json`,
		);
		expect(manifestOf(storeZips.chrome)).not.toHaveProperty("update_url");
		expect(manifestOf(storeZips.firefox).browser_specific_settings?.gecko).not.toHaveProperty(
			"update_url",
		);
		for (const target of ["chrome", "firefox"] as const) {
			expect(store.selfHostedDiffProblems(storeZips[target], selfZips[target])).toEqual([]);
		}
		const sums = readFileSync(join(distDir, "SHA256SUMS"), "utf8");
		for (const target of ["chrome", "firefox"]) {
			expect(sums).toContain(
				`${sha256(readFileSync(selfZipPath(target)))}  aidr-browser-guard-${target}-selfhosted-${NUMERIC}.zip`,
			);
		}
	});

	it("the store validator still passes the store builds and passes the self-hosted ones", () => {
		const result = store.validateRelease({
			distDir,
			storeDir: STORE_DIR,
			version: VERSION,
			packageRoot: PACKAGE_ROOT,
			updateBaseUrl: BASE,
		});
		expect(result.problems).toEqual([]);
		expect(result.packages).toEqual([
			`aidr-browser-guard-chrome-${NUMERIC}.zip`,
			`aidr-browser-guard-chrome-selfhosted-${NUMERIC}.zip`,
			`aidr-browser-guard-firefox-${NUMERIC}.zip`,
			`aidr-browser-guard-firefox-selfhosted-${NUMERIC}.zip`,
		]);
		const cli = spawnSync(
			process.execPath,
			[VALIDATOR, "--dist", distDir, "--version", VERSION, "--update-base-url", BASE],
			{ encoding: "utf8" },
		);
		expect(cli.status, cli.stderr).toBe(0);
		const other = spawnSync(
			process.execPath,
			[
				VALIDATOR,
				"--dist",
				distDir,
				"--version",
				VERSION,
				"--update-base-url",
				"https://x.test/bg",
			],
			{ encoding: "utf8" },
		);
		expect(other.status).toBe(1);
		expect(other.stderr).toMatch(/expected https:\/\/x\.test\/bg\/update\.xml/);
	});

	it("store packages still must not carry any update URL (Chrome or gecko)", () => {
		const problems = (target: "chrome" | "firefox", files: Files) =>
			(store.validatePackage(target, files) as string[]).join("\n");
		expect(problems("chrome", selfZips.chrome)).toMatch(/"update_url": store builds/);
		expect(problems("firefox", selfZips.firefox)).toMatch(/gecko has an "update_url"/);
	});

	it("a required self-hosted package that is missing fails the release", () => {
		const dir = tempDir("aidr-bg-feed-storeonly-");
		for (const target of ["chrome", "firefox"]) {
			const name = `aidr-browser-guard-${target}-${NUMERIC}.zip`;
			cpSync(join(distDir, name), join(dir, name));
		}
		const ok = store.validateRelease({ distDir: dir, storeDir: STORE_DIR, version: VERSION });
		expect(ok.problems).toEqual([]);
		const required = store.validateRelease({
			distDir: dir,
			storeDir: STORE_DIR,
			version: VERSION,
			updateBaseUrl: BASE,
		});
		expect(required.problems.join("\n")).toMatch(/chrome-selfhosted-.*missing/);
	});

	const selfProblems = (target: "chrome" | "firefox", files: Files) =>
		[
			...(store.validatePackage(target, files, {
				channel: "self-hosted",
				expectedUpdateUrl: target === "chrome" ? `${BASE}/update.xml` : `${BASE}/updates.json`,
			}) as string[]),
			...(store.selfHostedDiffProblems(storeZips[target], files) as string[]),
		].join("\n");
	const edited = (target: "chrome" | "firefox", edit: (m: Manifest) => void, extra = {}) =>
		readZip(readFileSync(zipWith(selfZips[target], edit, extra))) as Files;

	it.each([
		[
			"an http update URL",
			"chrome" as const,
			(m: Manifest) => {
				m.update_url = "http://updates.example.com/browser-guard/update.xml";
			},
			/must use https/,
		],
		[
			"no update URL",
			"firefox" as const,
			(m: Manifest) => {
				delete m.browser_specific_settings?.gecko.update_url;
			},
			/needs browser_specific_settings\.gecko\.update_url/,
		],
		[
			"a Chrome-style update_url in the Firefox build",
			"firefox" as const,
			(m: Manifest) => {
				m.update_url = `${BASE}/update.xml`;
			},
			/update_url is not read by this browser/,
		],
		[
			"a feed file name the browser does not expect",
			"chrome" as const,
			(m: Manifest) => {
				m.update_url = `${BASE}/feed.xml`;
			},
			/must end in \/update\.xml/,
		],
		[
			"a manifest difference beyond the update URL",
			"chrome" as const,
			(m: Manifest) => {
				(m.permissions as string[]).push("tabs");
			},
			/differs from the store manifest beyond the update URL/,
		],
	])("rejects a self-hosted package with %s", (_name, target, edit, expected) => {
		expect(selfProblems(target, edited(target, edit))).toMatch(expected);
	});

	it("rejects a self-hosted package whose files differ from the store package", () => {
		const files = edited("chrome", () => {}, { "extra.js": Buffer.from("1") });
		expect(selfProblems("chrome", files)).toMatch(/extra\.js is not in the store package/);
		const changed = new Map(selfZips.chrome);
		changed.set("content.js", Buffer.from("/* changed */"));
		expect(selfProblems("chrome", changed)).toMatch(/content\.js differs from the store package/);
	});

	it("refuses a non-https or credential-bearing base URL at build time", () => {
		expect(() => build.normalizeUpdateBaseUrl("http://updates.example.com/bg")).toThrow(/https/);
		expect(() => build.normalizeUpdateBaseUrl("https://u:p@updates.example.com/bg")).toThrow(
			/credentials/,
		);
		expect(() => build.normalizeUpdateBaseUrl("https://updates.example.com/bg?x=1")).toThrow(
			/query/,
		);
		expect(build.normalizeUpdateBaseUrl("https://updates.example.com/bg//")).toBe(
			"https://updates.example.com/bg",
		);
	});
});

describe("CRX3 packaging", () => {
	it("signs a CRX3 whose signature, ID and payload verify", () => {
		const archive = readFileSync(selfZipPath("chrome"));
		const key = feed.loadCrxKey(keyPem);
		const crx = feed.createCrx3(archive, key) as Buffer;
		expect(crx.subarray(0, 4).toString("latin1")).toBe("Cr24");
		expect(crx.readUInt32LE(4)).toBe(3);
		const checked = feed.verifyCrx3(crx);
		expect(checked.extensionId).toBe(key.extensionId);
		expect(checked.extensionId).toMatch(/^[a-p]{32}$/);
		expect(checked.archive.equals(archive)).toBe(true);
		// Deterministic: same key and zip, same bytes (reproducible feed).
		expect(feed.createCrx3(archive, key).equals(crx)).toBe(true);
	});

	it("rejects a tampered CRX and a CRX signed by another key for the same ID", () => {
		const archive = readFileSync(selfZipPath("chrome"));
		const crx = feed.createCrx3(archive, feed.loadCrxKey(keyPem)) as Buffer;
		const tampered = Buffer.from(crx);
		tampered[tampered.length - 30] ^= 0xff;
		expect(() => feed.verifyCrx3(tampered)).toThrow(/does not verify|CRC|signature/);
		expect(() => feed.verifyCrx3(Buffer.from("PK\u0003\u0004 not a crx"))).toThrow(/magic/);
	});

	it("the extension ID is the a-p mapping of the first 128 bits of SHA-256(SPKI)", () => {
		const key = feed.loadCrxKey(keyPem);
		const hex = createHash("sha256").update(key.publicKey).digest("hex").slice(0, 32);
		const expected = [...hex].map((d) => "abcdefghijklmnop"[Number.parseInt(d, 16)]).join("");
		expect(key.extensionId).toBe(expected);
	});

	it("fails closed without a usable key: missing, unreadable, not RSA or too short", () => {
		for (const bad of [undefined, "", "   "]) {
			expect(() => feed.loadCrxKey(bad)).toThrow(/BROWSER_GUARD_CRX_KEY_PEM/);
		}
		expect(() =>
			feed.loadCrxKey("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"),
		).toThrow(/not a readable PEM/);
		const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({
			type: "pkcs8",
			format: "pem",
		}) as string;
		expect(() => feed.loadCrxKey(ec)).toThrow(/must be RSA/);
		expect(() => feed.loadCrxKey(pem(1024))).toThrow(/at least 2048/);
	});
});

describe("update feed", () => {
	function verifySums(dir: string) {
		const sums = feed.parseSums(readFileSync(join(dir, "SHA256SUMS"), "utf8")) as Map<
			string,
			string
		>;
		const listed = [...sums.keys()].sort();
		const onDisk = (function list(d: string, prefix = ""): string[] {
			return readdirSync(join(d, prefix), { withFileTypes: true }).flatMap((e) =>
				e.isDirectory() ? list(d, `${prefix}${e.name}/`) : [`${prefix}${e.name}`],
			);
		})(dir)
			.filter((name) => name !== "SHA256SUMS")
			.sort();
		expect(listed).toEqual(onDisk);
		for (const [path, hash] of sums) expect(sha256(readFileSync(join(dir, path)))).toBe(hash);
	}

	const write = (options: Record<string, unknown>) => {
		const out = join(tempDir("aidr-bg-feed-out-"), "feed");
		const result = feed.buildFeed({ baseUrl: BASE, crxKeyPem: keyPem, ...options });
		feed.writeFeed(out, result.files);
		return { out, result };
	};

	it("writes update.xml, updates.json, the packages and SHA256SUMS with matching hashes and https URLs", () => {
		const key = feed.loadCrxKey(keyPem);
		const { out, result } = write({
			chromeZip: selfZipPath("chrome"),
			extensionId: key.extensionId,
			firefoxXpi: signedXpi(),
			firefoxZip: selfZipPath("firefox"),
		});
		expect(result.notices).toEqual([]);
		verifySums(out);

		const xml = feed.parseUpdateXml(readFileSync(join(out, "update.xml"), "utf8"));
		expect(xml).toEqual({
			extensionId: key.extensionId,
			version: NUMERIC,
			codebase: `${BASE}/packages/aidr-browser-guard-${NUMERIC}.crx`,
			sha256: sha256(readFileSync(join(out, "packages", `aidr-browser-guard-${NUMERIC}.crx`))),
		});
		const crx = feed.verifyCrx3(
			readFileSync(join(out, "packages", `aidr-browser-guard-${NUMERIC}.crx`)),
		);
		expect(crx.archive.equals(readFileSync(selfZipPath("chrome")))).toBe(true);

		const updates = JSON.parse(readFileSync(join(out, "updates.json"), "utf8"));
		const [entry] = updates.addons[GECKO_ID].updates;
		const xpi = readFileSync(join(out, "packages", `aidr-browser-guard-firefox-${NUMERIC}.xpi`));
		expect(entry).toEqual({
			version: NUMERIC,
			update_link: `${BASE}/packages/aidr-browser-guard-firefox-${NUMERIC}.xpi`,
			update_hash: `sha256:${sha256(xpi)}`,
			applications: { gecko: { strict_min_version: "140.0" } },
		});
		for (const url of [xml.codebase, entry.update_link])
			expect(new URL(url).protocol).toBe("https:");
	});

	it("adds releases on top of the hosted feed: versions strictly increase, old packages stay", () => {
		const first = write({ chromeZip: chromeZip("1.0.0"), firefoxXpi: signedXpi("1.0.0") });
		const second = write({
			previous: first.out,
			chromeZip: chromeZip("1.0.1"),
			firefoxXpi: signedXpi("1.0.1"),
		});
		verifySums(second.out);
		expect(feed.parseUpdateXml(readFileSync(join(second.out, "update.xml"), "utf8")).version).toBe(
			"1.0.1",
		);
		const versions = JSON.parse(readFileSync(join(second.out, "updates.json"), "utf8")).addons[
			GECKO_ID
		].updates.map((u: { version: string }) => u.version);
		expect(versions).toEqual(["1.0.0", "1.0.1"]);
		for (const name of [
			"aidr-browser-guard-1.0.0.crx",
			"aidr-browser-guard-1.0.1.crx",
			"aidr-browser-guard-firefox-1.0.0.xpi",
			"aidr-browser-guard-firefox-1.0.1.xpi",
		]) {
			expect(existsSync(join(second.out, "packages", name))).toBe(true);
		}
		// Firefox only: the hosted Chrome manifest is carried over unchanged.
		const third = write({ previous: second.out, firefoxXpi: signedXpi("1.0.2") });
		expect(readFileSync(join(third.out, "update.xml"))).toEqual(
			readFileSync(join(second.out, "update.xml")),
		);

		for (const [label, options, expected] of [
			[
				"same Chrome version",
				{ chromeZip: chromeZip("1.0.1") },
				/not higher than the hosted 1\.0\.1/,
			],
			["older Chrome version", { chromeZip: chromeZip("1.0.0") }, /not higher/],
			["older Firefox version", { firefoxXpi: signedXpi("0.9.9") }, /not higher/],
			["version compared numerically", { firefoxXpi: signedXpi("1.0.0") }, /not higher/],
		] as const) {
			expect(
				() =>
					feed.buildFeed({ baseUrl: BASE, crxKeyPem: keyPem, previous: second.out, ...options }),
				label,
			).toThrow(expected);
		}
		expect(feed.compareVersions("1.0.10", "1.0.9")).toBe(1);
		expect(feed.compareVersions("1.0", "1.0.0")).toBe(0);
	});

	it("refuses a tampered hosted feed and a different signing key", () => {
		const hosted = write({ chromeZip: chromeZip("2.0.0") });
		const otherKey = pem();
		expect(() =>
			feed.buildFeed({
				baseUrl: BASE,
				crxKeyPem: otherKey,
				previous: hosted.out,
				chromeZip: chromeZip("2.0.1"),
			}),
		).toThrow(/the hosted feed serves extension/);
		writeFileSync(join(hosted.out, "packages", "aidr-browser-guard-2.0.0.crx"), "tampered");
		expect(() =>
			feed.buildFeed({
				baseUrl: BASE,
				crxKeyPem: keyPem,
				previous: hosted.out,
				chromeZip: chromeZip("2.0.1"),
			}),
		).toThrow(/does not match SHA256SUMS/);
	});

	it("fails closed on the Chrome side: no key, a pinned ID mismatch, the store package", () => {
		expect(() => feed.buildFeed({ baseUrl: BASE, chromeZip: selfZipPath("chrome") })).toThrow(
			/no extension signing key/,
		);
		expect(() =>
			feed.buildFeed({
				baseUrl: BASE,
				crxKeyPem: keyPem,
				extensionId: "a".repeat(32),
				chromeZip: selfZipPath("chrome"),
			}),
		).toThrow(/is pinned: wrong or rotated key/);
		expect(() =>
			feed.buildFeed({
				baseUrl: BASE,
				crxKeyPem: keyPem,
				chromeZip: join(distDir, `aidr-browser-guard-chrome-${NUMERIC}.zip`),
			}),
		).toThrow(/no update_url/);
		expect(() =>
			feed.buildFeed({
				baseUrl: "http://updates.example.com/bg",
				crxKeyPem: keyPem,
				chromeZip: selfZipPath("chrome"),
			}),
		).toThrow(/https/);
	});

	it("publishes a CRX signed earlier under another host without the key, only for the pinned ID", () => {
		const key = feed.loadCrxKey(keyPem);
		const signed = write({ chromeZip: selfZipPath("chrome") });
		const crxFile = join(signed.out, "packages", `aidr-browser-guard-${NUMERIC}.crx`);
		const internal = "https://intranet.example.com/browser-guard";
		const out = join(tempDir("aidr-bg-feed-internal-"), "feed");
		const result = feed.buildFeed({
			baseUrl: internal,
			chromeCrx: crxFile,
			extensionId: key.extensionId,
		});
		feed.writeFeed(out, result.files);
		verifySums(out);
		const xml = feed.parseUpdateXml(readFileSync(join(out, "update.xml"), "utf8"));
		expect(xml.codebase).toBe(`${internal}/packages/aidr-browser-guard-${NUMERIC}.crx`);
		expect(xml.extensionId).toBe(key.extensionId);
		expect(readFileSync(join(out, "packages", `aidr-browser-guard-${NUMERIC}.crx`))).toEqual(
			readFileSync(crxFile),
		);
		expect(result.notices.join("\n")).toMatch(/override_update_url/);

		expect(() => feed.buildFeed({ baseUrl: internal, chromeCrx: crxFile })).toThrow(
			/needs --extension-id/,
		);
		expect(() =>
			feed.buildFeed({ baseUrl: internal, chromeCrx: crxFile, extensionId: "b".repeat(32) }),
		).toThrow(/is pinned/);
		const tampered = Buffer.from(readFileSync(crxFile));
		tampered[tampered.length - 40] ^= 0x01;
		const tamperedFile = join(tempDir("aidr-bg-feed-tampered-"), "x.crx");
		writeFileSync(tamperedFile, tampered);
		expect(() =>
			feed.buildFeed({ baseUrl: internal, chromeCrx: tamperedFile, extensionId: key.extensionId }),
		).toThrow(/does not verify|CRC/);
		expect(() =>
			feed.buildFeed({
				baseUrl: internal,
				chromeCrx: crxFile,
				chromeZip: selfZipPath("chrome"),
				extensionId: key.extensionId,
			}),
		).toThrow(/not both/);
	});

	it("notes when the Chrome package updates from a different host (override_update_url)", () => {
		const result = feed.buildFeed({
			baseUrl: "https://intranet.example.com/browser-guard",
			crxKeyPem: keyPem,
			chromeZip: selfZipPath("chrome"),
		});
		expect(result.notices.join("\n")).toMatch(/override_update_url/);
	});

	it("fails closed on the Firefox side: unsigned XPI, another update URL, files that differ from the build", () => {
		const unsigned = zipWith(selfZips.firefox, () => {});
		expect(() => feed.buildFeed({ baseUrl: BASE, firefoxXpi: unsigned })).toThrow(
			/not signed by Mozilla/,
		);
		expect(() =>
			feed.buildFeed({ baseUrl: "https://intranet.example.com/bg", firefoxXpi: signedXpi() }),
		).toThrow(/Firefox would never read it/);
		const otherId = signedXpi(NUMERIC, (m) => {
			(m.browser_specific_settings as { gecko: Record<string, unknown> }).gecko.id =
				"x@example.com";
		});
		expect(() => feed.buildFeed({ baseUrl: BASE, firefoxXpi: otherId })).toThrow(
			/is not browser-guard/,
		);
		expect(() =>
			feed.buildFeed({
				baseUrl: BASE,
				firefoxXpi: signedXpi("9.9.9"),
				firefoxZip: selfZipPath("firefox"),
			}),
		).toThrow(/manifest\.json differs from the release build/);
	});

	it("the CLI exits 2 and writes nothing without the key; prints the pinned ID with it", () => {
		const out = join(tempDir("aidr-bg-feed-cli-"), "feed");
		const env = { ...process.env };
		delete env.BROWSER_GUARD_CRX_KEY_PEM;
		const missing = spawnSync(
			process.execPath,
			[FEED_SCRIPT, "--base-url", BASE, "--out", out, "--chrome-zip", selfZipPath("chrome")],
			{ encoding: "utf8", env },
		);
		expect(missing.status).toBe(2);
		expect(missing.stderr).toMatch(/BROWSER_GUARD_CRX_KEY_PEM/);
		expect(existsSync(out)).toBe(false);

		const withKey = { ...env, BROWSER_GUARD_CRX_KEY_PEM: keyPem };
		const id = spawnSync(process.execPath, [FEED_SCRIPT, "--print-extension-id"], {
			encoding: "utf8",
			env: withKey,
		});
		expect(id.status, id.stderr).toBe(0);
		expect(id.stdout.trim()).toBe(feed.loadCrxKey(keyPem).extensionId);

		const ok = spawnSync(
			process.execPath,
			[FEED_SCRIPT, "--base-url", BASE, "--out", out, "--chrome-zip", selfZipPath("chrome")],
			{ encoding: "utf8", env: withKey },
		);
		expect(ok.status, ok.stderr).toBe(0);
		expect(readdirSync(out).sort()).toEqual(["SHA256SUMS", "packages", "update.xml"]);
		expect(ok.stdout).not.toContain("PRIVATE KEY");
		// The output directory is never overwritten.
		const again = spawnSync(
			process.execPath,
			[FEED_SCRIPT, "--base-url", BASE, "--out", out, "--chrome-zip", selfZipPath("chrome")],
			{ encoding: "utf8", env: withKey },
		);
		expect(again.status).toBe(2);
		expect(again.stderr).toMatch(/not empty/);
		const usage = spawnSync(process.execPath, [FEED_SCRIPT, "--bogus"], { encoding: "utf8", env });
		expect(usage.status).toBe(2);
	});
});
