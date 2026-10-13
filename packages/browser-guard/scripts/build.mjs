#!/usr/bin/env node
/**
 * Builds the Singularity AIDR Browser Guard extension for Chrome/Edge and Firefox.
 *
 *   node scripts/build.mjs                    # development build -> dist/chrome, dist/firefox
 *   node scripts/build.mjs --release          # minified, no source maps
 *   node scripts/build.mjs --release --zip    # + dist/aidr-browser-guard-<target>-<version>.zip, dist/SHA256SUMS
 *   node scripts/build.mjs --root <dir> --out <dir>   # alternate package root / output (tests)
 *   node scripts/build.mjs --entries-root <dir>        # resolve src/ entry points under <dir> (tests)
 *
 * Every entry point is bundled by esbuild into a single classic (IIFE) script, so
 * the Chrome service worker needs no `type: module` and Firefox can load the
 * same code as an event page. The build fails closed: a missing entry, a missing
 * static asset, a locale without the manifest strings, an HTML page that would
 * violate the extension CSP, or a bundle containing dynamic code evaluation or a
 * reference to an unexpected remote origin all abort the build with a message
 * naming the file.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createZip } from "./zip.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
export const PACKAGE_ROOT = resolve(scriptDir, "..");

/**
 * HTTPS hosts of the eight supported AI chat products. The build takes the
 * authoritative list from `MATCH_PATTERNS` in src/sites/index.ts whenever that
 * module exists under the entries root; this copy is the fallback for stub entry
 * roots and is kept in sync by src/__tests__/build.test.ts.
 */
export const SITE_HOSTS = Object.freeze([
	"chatgpt.com",
	"chat.openai.com",
	"gemini.google.com",
	"claude.ai",
	"copilot.microsoft.com",
	"m365.cloud.microsoft",
	"copilot.cloud.microsoft",
	"www.perplexity.ai",
	"perplexity.ai",
	"chat.deepseek.com",
	"chat.mistral.ai",
	"grok.com",
]);
export const SITE_MATCHES = Object.freeze(SITE_HOSTS.map((host) => `https://${host}/*`));

/** Entry points (see src/types.ts) and the classic scripts they become. */
export const ENTRIES = Object.freeze([
	{ source: "src/background/index.ts", output: "background.js" },
	{ source: "src/content/index.ts", output: "content.js" },
	{ source: "src/content/main-world.ts", output: "content-main.js" },
	{ source: "src/ui/popup.ts", output: "popup.js" },
	{ source: "src/ui/options.ts", output: "options.js" },
]);

/** Static pages every build must ship. Other static/*.html and *.css files are copied too. */
export const REQUIRED_STATIC = Object.freeze(["popup.html", "options.html", "ui.css", "managed_schema.json"]);
export const ICON_SIZES = Object.freeze([16, 32, 48, 128]);

export const TARGETS = Object.freeze({
	chrome: { esbuildTarget: "chrome120" },
	firefox: { esbuildTarget: "firefox140" },
});

export const GECKO_ID = "browser-guard@singularityrd.com";

/**
 * Page a tab lands on when it navigates to an AI site blocked by policy
 * (src/background/dnr.ts). The declarativeNetRequest rule blocks the request and the
 * background worker then navigates the tab to this page itself (`tabs.update`), an
 * extension-initiated navigation that needs no web_accessible_resources entry. The
 * page is therefore not reachable from web pages at all, so it cannot be used to
 * fingerprint the extension (a web-accessible page could be probed at the stable
 * extension id, and Chrome refuses DNR redirects to `use_dynamic_url` resources).
 */
export const BLOCKED_PAGE = "blocked.html";

/**
 * Extension-page CSP. `connect-src` allows HTTPS (the control-plane URL is
 * configurable per tenant, including self-hosted), loopback HTTP for local
 * development control planes, and `'self'` so pages can read bundled locale files.
 */
export const EXTENSION_CSP = [
	"default-src 'none'",
	"script-src 'self'",
	"style-src 'self'",
	"img-src 'self' data:",
	"connect-src 'self' https: http://localhost:* http://127.0.0.1:*",
	"object-src 'none'",
	"base-uri 'none'",
	"form-action 'none'",
	"frame-ancestors 'none'",
].join("; ");

/**
 * `scripting` registers content.js at runtime for administrator-configured internal AI
 * sites (managed `customSites`, src/background/custom-sites.ts), only on hosts the user
 * granted from the optional host permissions below. It carries no install warning and
 * gives no access by itself: injection still needs host access to the page.
 *
 * `declarativeNetRequest` (not `declarativeNetRequestWithHostAccess`): the extension only
 * installs `block` rules (src/background/dnr.ts, src/background/shadow-ai.ts), and under the
 * host-access variant a block applies only where the user granted host access to BOTH the
 * blocked site and the page that started the navigation. An administrator's `blockedSites`
 * or Shadow AI block would then depend on the policed user's own grant (declining or
 * revoking it, or following a link from any other site, bypassed it). Block rules under
 * `declarativeNetRequest` need no host permission at all. Install warning: "Block content
 * on any page". No redirect or header-modifying rule is ever installed.
 */
export const PERMISSIONS = Object.freeze(["storage", "alarms", "declarativeNetRequest", "scripting"]);
/** Requested at runtime only, when an admin or user enables the local NER host. */
export const OPTIONAL_PERMISSIONS = Object.freeze(["nativeMessaging"]);
/**
 * Requested at runtime, per origin, from the options page: custom internal AI sites and
 * the Shadow AI catalog hosts (visit counts and the blocked.html explanation page; the block
 * itself needs no grant). Never `tabs`, `webNavigation` or `<all_urls>`.
 */
export const OPTIONAL_HOST_PERMISSIONS = Object.freeze(["https://*/*"]);

/** Hosts (besides the site hosts) a bundle may mention in a URL literal. Anything else fails the build. */
const ALLOWED_URL_HOSTS = [
	"localhost",
	"127.0.0.1",
	"www.w3.org", // XML namespaces (SVG/XHTML) are identifiers, not fetches
	"singularityrd.com",
];
const PLACEHOLDER_TLDS = [".example", ".invalid", ".test", ".localhost"];
const PLACEHOLDER_DOMAINS = ["example.com", "example.org", "example.net"];

/** Chrome/Firefox both require 1-4 dot-separated integers; pre-release goes to version_name. */
export function manifestVersion(packageVersion) {
	const match = /^(\d+(?:\.\d+){0,3})(?:[-+].*)?$/.exec(packageVersion);
	if (!match) throw new Error(`BUILD_BAD_VERSION: ${packageVersion}`);
	return { version: match[1], versionName: match[1] === packageVersion ? null : packageVersion };
}

/**
 * Generates manifest.json for one target.
 * @param {"chrome" | "firefox"} target
 * @param {{ version: string; contentCss?: boolean; matches?: readonly string[] }} options
 */
export function createManifest(target, { version, contentCss = false, matches = SITE_MATCHES }) {
	if (!TARGETS[target]) throw new Error(`BUILD_UNKNOWN_TARGET: ${target}`);
	const { version: numeric, versionName } = manifestVersion(version);
	const icons = Object.fromEntries(ICON_SIZES.map((size) => [String(size), `icons/icon-${size}.png`]));
	const contentScript = {
		matches: [...matches],
		js: ["content.js"],
		...(contentCss ? { css: ["content.css"] } : {}),
		run_at: "document_start",
		all_frames: false,
	};
	// Page-world file-input hook (src/content/file-input-hook.ts): routes detached and
	// shadow-DOM <input type=file> selections to content.js. No extension APIs, no data.
	const mainWorldScript = {
		matches: [...matches],
		js: ["content-main.js"],
		run_at: "document_start",
		all_frames: false,
		world: "MAIN",
	};
	const manifest = {
		manifest_version: 3,
		name: "__MSG_extName__",
		description: "__MSG_extDescription__",
		default_locale: "en",
		version: numeric,
		icons,
		permissions: [...PERMISSIONS],
		optional_permissions: [...OPTIONAL_PERMISSIONS],
		host_permissions: [...matches],
		optional_host_permissions: [...OPTIONAL_HOST_PERMISSIONS],
		content_scripts: [contentScript, mainWorldScript],
		action: {
			default_title: "__MSG_extName__",
			default_popup: "popup.html",
			default_icon: icons,
		},
		incognito: "not_allowed",
		content_security_policy: { extension_pages: EXTENSION_CSP },
	};
	if (target === "chrome") {
		if (versionName) manifest.version_name = versionName;
		manifest.minimum_chrome_version = "120";
		manifest.background = { service_worker: "background.js" };
		manifest.options_page = "options.html";
		manifest.storage = { managed_schema: "managed_schema.json" };
	} else {
		// Firefox has no MV3 service workers; background.scripts runs as an event page.
		// Managed settings come from policies.json `3rdparty.Extensions`, so there is
		// no storage.managed_schema key.
		manifest.background = { scripts: ["background.js"] };
		manifest.options_ui = { page: "options.html", open_in_tab: true };
		manifest.browser_specific_settings = {
			// 140 (ESR) / Android 142 are the first releases that understand
			// data_collection_permissions, which addons.mozilla.org requires.
			gecko: {
				id: GECKO_ID,
				strict_min_version: "140.0",
				// No data is sent to the publisher. Optional telemetry (entity counts only)
				// goes to the organisation's own control plane when an admin configures it.
				data_collection_permissions: { required: ["none"] },
			},
			gecko_android: { strict_min_version: "142.0" },
		};
	}
	return manifest;
}

/** Patterns that must never appear in shipped JavaScript. */
const FORBIDDEN_CODE = [
	[/\beval\s*\(/, "eval()"],
	[/\bnew\s+Function\s*\(/, "new Function()"],
	[/(?<![.\w$])Function\s*\(\s*["'`]/, "Function(string)"],
	[/\bset(?:Timeout|Interval)\s*\(\s*["'`]/, "string timer callback"],
	[/\bimportScripts\s*\(/, "importScripts()"],
	[/(?<![.\w$])import\s*\(/, "dynamic import()"],
	[/\bdocument\.write(?:ln)?\s*\(/, "document.write()"],
];
const URL_PATTERN = /\bhttps?:\/\/([a-z0-9.-]*[a-z0-9])(?::\d+)?/gi;

function hostAllowed(host, siteHosts) {
	const h = host.toLowerCase();
	if (siteHosts.includes(h)) return true;
	if (ALLOWED_URL_HOSTS.some((allowed) => h === allowed || h.endsWith(`.${allowed}`))) return true;
	if (PLACEHOLDER_TLDS.some((tld) => h.endsWith(tld))) return true;
	return PLACEHOLDER_DOMAINS.some((domain) => h === domain || h.endsWith(`.${domain}`));
}

/** Returns human-readable violations for one text asset (JS/CSS/HTML). */
export function scanForRemoteUrls(text, siteHosts = SITE_HOSTS) {
	const violations = [];
	for (const match of text.matchAll(URL_PATTERN)) {
		if (!hostAllowed(match[1], siteHosts)) violations.push(`remote URL ${match[0]}`);
	}
	return violations;
}

/** Returns violations for a built JavaScript bundle. */
export function scanBundle(code, siteHosts = SITE_HOSTS) {
	const violations = FORBIDDEN_CODE.filter(([pattern]) => pattern.test(code)).map(([, label]) => label);
	return [...violations, ...scanForRemoteUrls(code, siteHosts)];
}

/**
 * Returns violations for an extension page: anything the CSP would block
 * (inline scripts/styles/handlers) and any reference that is not a bundled file.
 */
export function scanHtml(html, availableFiles) {
	const violations = [];
	for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
		if (!/\bsrc\s*=/.test(match[1])) violations.push("inline <script>");
		else if (match[2].trim() !== "") violations.push("<script src> with inline body");
	}
	if (/<style\b/i.test(html)) violations.push("inline <style> (blocked by style-src 'self')");
	if (/\sstyle\s*=/i.test(html)) violations.push("inline style attribute (blocked by style-src 'self')");
	if (/\son[a-z]+\s*=/i.test(html)) violations.push("inline event handler attribute");
	if (/javascript:/i.test(html)) violations.push("javascript: URL");
	for (const match of html.matchAll(/\b(?:src|href)\s*=\s*["']([^"']*)["']/gi)) {
		const ref = match[1];
		if (ref === "" || ref.startsWith("#")) continue;
		if (/^[a-z][a-z0-9+.-]*:/i.test(ref) || ref.startsWith("//")) {
			violations.push(`external reference ${ref}`);
			continue;
		}
		const path = ref.replace(/^\.\//, "").split(/[?#]/)[0];
		if (!availableFiles.has(path)) violations.push(`reference to missing file ${ref}`);
	}
	return violations;
}

function fail(message) {
	throw new Error(`[browser-guard build] ${message}`);
}

/** RE2 (Chrome's policy-schema regex engine) caps every repetition count, nested ones multiplied. */
export const RE2_MAX_REPEAT = 1000;

/**
 * Returns why `pattern` cannot be compiled by RE2, or [] when it can. Chrome
 * validates `pattern` / `patternProperties` of storage.managed_schema with RE2
 * when the extension loads, and an invalid schema makes Chrome refuse to load
 * the whole extension (no service worker, no content scripts).
 */
export function re2PatternProblems(pattern) {
	const problems = [];
	try {
		new RegExp(pattern);
	} catch (error) {
		return [`${JSON.stringify(pattern)} is not a valid regular expression (${error.message})`];
	}
	if (/\(\?<?[=!]/.test(pattern)) problems.push(`${JSON.stringify(pattern)} uses lookaround (unsupported by RE2)`);
	if (/(?<!\\)\\[1-9]/.test(pattern)) problems.push(`${JSON.stringify(pattern)} uses a backreference (unsupported by RE2)`);
	// Track the largest repetition product per group: RE2 rejects `x{1001}` and
	// also `(x{4}){3,255}` (4 * 255 > 1000).
	const stack = [{ max: 1, last: 1 }];
	for (let i = 0; i < pattern.length; i++) {
		const frame = stack[stack.length - 1];
		const ch = pattern[i];
		if (ch === "\\") {
			i++;
			frame.last = 1;
		} else if (ch === "[") {
			i++;
			if (pattern[i] === "^") i++;
			if (pattern[i] === "]") i++;
			while (i < pattern.length && pattern[i] !== "]") i += pattern[i] === "\\" ? 2 : 1;
			frame.last = 1;
		} else if (ch === "(") {
			stack.push({ max: 1, last: 1 });
		} else if (ch === ")") {
			const inner = stack.length > 1 ? stack.pop() : { max: 1 };
			stack[stack.length - 1].last = inner.max;
		} else if (ch === "|") {
			frame.last = 1;
		} else if (ch === "{") {
			const m = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.slice(i));
			if (!m) {
				frame.last = 1;
			} else {
				const count = Math.max(Number(m[1]), m[2] ? Number(m[2]) : 0);
				if (count > RE2_MAX_REPEAT) {
					problems.push(`${JSON.stringify(pattern)} repeats ${count} times (RE2 limit ${RE2_MAX_REPEAT})`);
				}
				frame.last *= Math.max(count, 1);
				if (frame.last > RE2_MAX_REPEAT && count <= RE2_MAX_REPEAT) {
					problems.push(
						`${JSON.stringify(pattern)} nests repetitions to ${frame.last} (RE2 limit ${RE2_MAX_REPEAT})`,
					);
				}
				i += m[0].length - 1;
			}
		} else if (!"*+?".includes(ch)) {
			frame.last = 1;
		}
		const top = stack[stack.length - 1];
		top.max = Math.max(top.max, top.last);
	}
	return problems;
}

/** Walks a managed-storage schema and returns every problem Chrome would reject it for. */
export function managedSchemaProblems(schema, path = "$") {
	const problems = [];
	if (schema === null || typeof schema !== "object" || Array.isArray(schema)) return problems;
	if (typeof schema.pattern === "string") {
		for (const p of re2PatternProblems(schema.pattern)) problems.push(`${path}.pattern: ${p}`);
	}
	for (const [key, child] of Object.entries(schema.properties ?? {})) {
		problems.push(...managedSchemaProblems(child, `${path}.properties.${key}`));
	}
	for (const [key, child] of Object.entries(schema.patternProperties ?? {})) {
		for (const p of re2PatternProblems(key)) problems.push(`${path}.patternProperties: ${p}`);
		problems.push(...managedSchemaProblems(child, `${path}.patternProperties[${JSON.stringify(key)}]`));
	}
	if (schema.items) problems.push(...managedSchemaProblems(schema.items, `${path}.items`));
	if (typeof schema.additionalProperties === "object") {
		problems.push(...managedSchemaProblems(schema.additionalProperties, `${path}.additionalProperties`));
	}
	return problems;
}

function readJson(file, label) {
	try {
		return JSON.parse(readFileSync(file, "utf8"));
	} catch (error) {
		fail(`${label} is not valid JSON (${file}): ${error.message}`);
	}
}

function listFiles(dir, base = dir) {
	const out = [];
	for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...listFiles(full, base));
		else if (entry.isFile()) out.push(relative(base, full).split(sep).join("/"));
	}
	return out;
}

function writeFile(file, data) {
	mkdirSync(dirname(file), { recursive: true });
	writeFileSync(file, data);
}

/** Checks inputs up front so a missing file is reported once, by name, before esbuild runs. */
function collectInputs(root, entriesRoot) {
	const missing = [];
	for (const entry of ENTRIES) {
		const file = join(entriesRoot, entry.source);
		// Report the POSIX entry path (stable across platforms); name a separate
		// entries root alongside it instead of a platform-joined absolute path.
		if (!existsSync(file)) {
			missing.push(entriesRoot === root ? entry.source : `${entry.source} (entries root ${entriesRoot})`);
		}
	}
	for (const name of REQUIRED_STATIC) if (!existsSync(join(root, "static", name))) missing.push(`static/${name}`);
	for (const size of ICON_SIZES) {
		if (!existsSync(join(root, "static", "icons", `icon-${size}.png`))) missing.push(`static/icons/icon-${size}.png`);
	}
	if (!existsSync(join(root, "_locales", "en", "messages.json"))) missing.push("_locales/en/messages.json");
	if (missing.length > 0) {
		fail(`missing required input(s) under ${root}:\n  - ${missing.join("\n  - ")}`);
	}

	const packageJson = readJson(join(root, "package.json"), "package.json");
	const staticFiles = readdirSync(join(root, "static"))
		.filter((name) => /\.(html|css)$/.test(name))
		.sort();

	const locales = new Map();
	for (const locale of readdirSync(join(root, "_locales")).sort()) {
		const file = join(root, "_locales", locale, "messages.json");
		if (!existsSync(file)) continue;
		const messages = readJson(file, `_locales/${locale}/messages.json`);
		for (const [key, limit] of [
			["extName", 75],
			["extDescription", 132],
		]) {
			const text = messages?.[key]?.message;
			if (typeof text !== "string" || text.trim() === "") {
				fail(`_locales/${locale}/messages.json lacks the "${key}" message required by manifest.json`);
			}
			if (text.length > limit) fail(`_locales/${locale}/messages.json "${key}" exceeds ${limit} characters`);
		}
		locales.set(locale, readFileSync(file));
	}

	const schema = readJson(join(root, "static", "managed_schema.json"), "static/managed_schema.json");
	if (schema?.type !== "object" || typeof schema.properties !== "object") {
		fail("static/managed_schema.json must be a JSON schema with type object and properties");
	}
	const schemaProblems = managedSchemaProblems(schema);
	if (schemaProblems.length > 0) {
		fail(
			`static/managed_schema.json would make Chrome refuse to load the extension:\n  - ${schemaProblems.join("\n  - ")}`,
		);
	}

	return { version: String(packageJson.version), staticFiles, locales };
}

const MATCH_PATTERN_SHAPE = /^https:\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)+)\/\*$/;

/**
 * Loads `MATCH_PATTERNS` from src/sites/index.ts (bundled in memory and imported
 * as a data: URL module) so the manifest can never drift from the adapters.
 * Falls back to {@link SITE_MATCHES} only when the module does not exist.
 * @returns {Promise<{ matches: string[]; source: string }>}
 */
export async function loadSiteMatches(entriesRoot) {
	const sitesModule = join(entriesRoot, "src", "sites", "index.ts");
	if (!existsSync(sitesModule)) return { matches: [...SITE_MATCHES], source: "scripts/build.mjs SITE_HOSTS" };
	const esbuild = await import("esbuild");
	let patterns;
	try {
		const result = await esbuild.build({
			entryPoints: [sitesModule],
			bundle: true,
			write: false,
			format: "esm",
			platform: "neutral",
			logLevel: "silent",
		});
		const url = `data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString("base64")}`;
		patterns = (await import(url)).MATCH_PATTERNS;
	} catch (error) {
		fail(`could not load MATCH_PATTERNS from src/sites/index.ts: ${error.message}`);
	}
	if (!Array.isArray(patterns) || patterns.length === 0) fail("src/sites/index.ts MATCH_PATTERNS is empty or missing");
	for (const pattern of patterns) {
		if (typeof pattern !== "string" || !MATCH_PATTERN_SHAPE.test(pattern)) {
			fail(`src/sites/index.ts MATCH_PATTERNS entry ${JSON.stringify(pattern)} is not an exact https://<host>/* pattern`);
		}
	}
	return { matches: [...new Set(patterns)], source: "src/sites/index.ts MATCH_PATTERNS" };
}

async function bundleEntries({ entriesRoot, outDir, target, release, version }) {
	const esbuild = await import("esbuild");
	const outputs = new Map();
	for (const entry of ENTRIES) {
		let result;
		try {
			result = await esbuild.build({
				absWorkingDir: entriesRoot,
				entryPoints: [join(entriesRoot, entry.source)],
				bundle: true,
				write: false,
				format: "iife",
				platform: "browser",
				target: [TARGETS[target].esbuildTarget],
				minify: release,
				sourcemap: release ? false : "inline",
				sourcesContent: !release,
				legalComments: "none",
				charset: "utf8",
				logLevel: "silent",
				define: {
					__AIDR_VERSION__: JSON.stringify(version),
					__AIDR_TARGET__: JSON.stringify(target),
				},
				outfile: join(outDir, target, entry.output),
			});
		} catch (error) {
			const details = (error.errors ?? [])
				.map((e) => `${e.location ? `${e.location.file}:${e.location.line}: ` : ""}${e.text}`)
				.join("\n  ");
			fail(`esbuild failed for ${entry.source} (${target}):\n  ${details || error.message}`);
		}
		const file = result.outputFiles.find((f) => f.path.endsWith(".js"));
		outputs.set(entry.output, file.text);
	}
	return outputs;
}

function displayPath(path) {
	const rel = relative(process.cwd(), path);
	return rel && !rel.startsWith("..") ? rel : path;
}

function sha256(data) {
	return createHash("sha256").update(data).digest("hex");
}

/**
 * Builds both targets.
 * `root` holds package.json, static/ and _locales/; `entriesRoot` (default: `root`)
 * holds the src/ entry points.
 * @param {{ root?: string; entriesRoot?: string; outDir?: string; release?: boolean; zip?: boolean; log?: (line: string) => void }} options
 */
export async function buildExtension(options = {}) {
	const root = resolve(options.root ?? PACKAGE_ROOT);
	const entriesRoot = resolve(options.entriesRoot ?? root);
	const outDir = resolve(options.outDir ?? join(root, "dist"));
	const release = options.release === true;
	const log = options.log ?? ((line) => console.log(line));
	const inputs = collectInputs(root, entriesRoot);
	const { version } = manifestVersion(inputs.version);
	const contentCss = existsSync(join(root, "static", "content.css"));
	const { matches } = await loadSiteMatches(entriesRoot);
	const siteHosts = matches.map((pattern) => MATCH_PATTERN_SHAPE.exec(pattern)[1]);

	rmSync(outDir, { recursive: true, force: true });
	const result = { version, outDir, targets: {}, archives: [] };

	for (const target of Object.keys(TARGETS)) {
		const targetDir = join(outDir, target);
		const bundles = await bundleEntries({ entriesRoot, outDir, target, release, version: inputs.version });
		const problems = [];
		for (const [name, code] of bundles) {
			for (const violation of scanBundle(code, siteHosts)) problems.push(`${target}/${name}: ${violation}`);
			if (release && (code.includes(root) || code.includes(entriesRoot))) problems.push(`${target}/${name}: build-machine path leaked`);
			writeFile(join(targetDir, name), code);
		}

		for (const name of inputs.staticFiles) writeFile(join(targetDir, name), readFileSync(join(root, "static", name)));
		if (target === "chrome") {
			writeFile(join(targetDir, "managed_schema.json"), readFileSync(join(root, "static", "managed_schema.json")));
		}
		for (const size of ICON_SIZES) {
			const name = `icons/icon-${size}.png`;
			writeFile(join(targetDir, name), readFileSync(join(root, "static", name)));
		}
		for (const [locale, bytes] of inputs.locales) writeFile(join(targetDir, "_locales", locale, "messages.json"), bytes);

		const manifest = createManifest(target, {
			version: inputs.version,
			contentCss,
			matches,
		});
		writeFile(join(targetDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

		const files = new Set(listFiles(targetDir));
		for (const name of inputs.staticFiles) {
			const text = readFileSync(join(targetDir, name), "utf8");
			const violations = name.endsWith(".html") ? scanHtml(text, files) : [];
			for (const violation of [...violations, ...scanForRemoteUrls(text, siteHosts)]) problems.push(`${target}/${name}: ${violation}`);
		}
		if (problems.length > 0) {
			fail(`output rejected by the security scan:\n  - ${problems.join("\n  - ")}`);
		}
		result.targets[target] = { dir: targetDir, files: [...files].sort() };
		log(`[browser-guard] built ${target} ${version}${release ? " (release)" : ""} -> ${displayPath(targetDir)}`);
	}

	if (options.zip) {
		const sums = [];
		for (const target of Object.keys(TARGETS)) {
			const { dir, files } = result.targets[target];
			const archive = createZip(files.map((name) => ({ name, data: readFileSync(join(dir, name)) })));
			const name = `aidr-browser-guard-${target}-${version}.zip`;
			writeFileSync(join(outDir, name), archive);
			sums.push(`${sha256(archive)}  ${name}`);
			result.archives.push(join(outDir, name));
			log(`[browser-guard] packaged ${name} (${statSync(join(outDir, name)).size} bytes)`);
		}
		writeFileSync(join(outDir, "SHA256SUMS"), `${sums.sort().join("\n")}\n`);
	}
	return result;
}

function parseArgs(argv) {
	const options = { release: false, zip: false };
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];
		if (arg === "--release") options.release = true;
		else if (arg === "--zip") options.zip = true;
		else if (arg === "--root" || arg === "--out" || arg === "--entries-root") {
			const value = argv[++i];
			if (!value) fail(`${arg} needs a directory`);
			options[{ "--root": "root", "--out": "outDir", "--entries-root": "entriesRoot" }[arg]] = value;
		} else fail(`unknown argument ${arg}`);
	}
	return options;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		await buildExtension(parseArgs(process.argv.slice(2)));
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
