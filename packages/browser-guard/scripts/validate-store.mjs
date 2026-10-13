#!/usr/bin/env node
/**
 * Offline store validation for the Browser Guard upload packages and listing kit.
 *
 *   node scripts/validate-store.mjs                 # dist/ zips of package.json's version + store/
 *   node scripts/validate-store.mjs --dist <dir> --store <dir> [--version <x.y.z>]
 *
 * Checks the exact zips that are uploaded (aidr-browser-guard-{chrome,firefox}-<version>.zip)
 * against the rules of the Chrome Web Store, Microsoft Edge Add-ons and addons.mozilla.org
 * that can be verified without the stores: manifest fields and their store limits, the
 * version format, icons (16/32/48/128, real PNGs of the declared size), no `key` /
 * `update_url` in a store build, a permission set limited to what the listing kit
 * justifies (and no justification for a permission that is gone), the extension-page CSP,
 * no remote code (the build's own bundle scanner), no source maps, no stray files, every
 * file the manifest references present, and the per-browser keys (service worker vs event
 * page, the gecko id and data_collection_permissions). The listing kit (store/) is checked
 * too: short descriptions equal the manifest descriptions, detailed descriptions are within
 * the store limits, keep their "not covered" section and avoid unverifiable claims, and
 * the screenshots and promo tiles have the store sizes.
 *
 * Exit code 0 = no violation, 1 = violations (each printed with the file it concerns),
 * 2 = usage error or missing input.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { GECKO_ID, ICON_SIZES, manifestVersion, scanBundle, scanHtml } from "./build.mjs";
import { readZip } from "./zip.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
export const PACKAGE_ROOT = resolve(scriptDir, "..");

/** Store limits that hold for all three stores (the strictest one wins). */
export const LIMITS = Object.freeze({
	name: 75, // Chrome Web Store / Edge: manifest name
	shortName: 12,
	shortDescription: 132, // manifest description (Chrome, Edge); AMO summary allows 250
	detailedMin: 250, // Edge Add-ons requires a description of at least 250 characters
	detailedMax: 10_000, // Edge Add-ons maximum (the Chrome Web Store allows more)
	singlePurposeMax: 1_000,
	packageBytes: 200 * 1024 * 1024, // addons.mozilla.org upload limit (Chrome/Edge allow more)
});

export const LISTING_LOCALES = Object.freeze(["en", "tr"]);

/** Required headings of the detailed description: what is not covered must stay in the listing. */
export const NOT_COVERED_HEADINGS = Object.freeze({ en: "WHAT IT DOES NOT COVER", tr: "KAPSAMADIKLARI" });

/** Store sizes of the generated images in store/images/. */
export const IMAGE_SIZES = Object.freeze({
	screenshot: [1280, 800],
	"promo-small": [440, 280],
});

/** Wording a store reviewer (or a customer) cannot verify. */
export const UNVERIFIABLE_CLAIMS = Object.freeze([
	[/\b100\s?%|%\s?100\b/i, "100%"],
	[/\bguarantee/i, "guarantee"],
	[/\bgaranti/i, "garanti"],
	[/\bmilitary[- ]grade|askeri düzey/i, "military-grade"],
	[/\bunhackable|\bbulletproof/i, "unhackable/bulletproof"],
	[/\bnever miss|\bhiçbir (?:veriyi|şeyi) kaçırmaz/i, "never misses"],
	[/\bcomplete (?:protection|privacy)|\beksiksiz koruma|\btam koruma/i, "complete protection"],
	[/\b(?:GDPR|KVKK|HIPAA)[- ](?:compliant|uyumlu)/i, "regulatory compliance claim"],
	[/\b(?:#1|number one|best[- ]in[- ]class|industry[- ]leading)\b/i, "superlative"],
	[/\ball (?:sensitive|personal) data\b|\btüm (?:hassas|kişisel) veriler/i, "all sensitive data"],
]);

/** Permissions a store build must never request, whatever the listing says. */
export const FORBIDDEN_PERMISSIONS = Object.freeze([
	"<all_urls>",
	"tabs",
	"webNavigation",
	"history",
	"cookies",
	"webRequest",
	"webRequestBlocking",
	"debugger",
	"management",
	"proxy",
	"privacy",
	"downloads",
	"clipboardRead",
	"declarativeNetRequestFeedback",
	"declarativeNetRequestWithHostAccess",
]);

/** File types a store package may contain. Anything else (maps, sources, keys, archives, dotfiles) fails. */
const ALLOWED_FILE = /^(?!.*(?:^|\/)\.)[A-Za-z0-9_\-/]+(?:\.[A-Za-z0-9_-]+)*\.(?:js|json|html|css|png)$/;
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const VERSION_SHAPE = /^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){0,3}$/;
const MESSAGE_REF = /^__MSG_([A-Za-z0-9_@]+)__$/;
const EXACT_HOST_PATTERN = /^https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)+\/\*$/;

/** Reads width/height from a PNG IHDR, or null when the bytes are not a PNG. */
export function pngSize(bytes) {
	if (!bytes || bytes.length < 24 || !bytes.subarray(0, 8).equals(PNG_SIGNATURE)) return null;
	if (bytes.toString("latin1", 12, 16) !== "IHDR") return null;
	return [bytes.readUInt32BE(16), bytes.readUInt32BE(20)];
}

function parseJson(bytes, label, problems) {
	try {
		return JSON.parse(Buffer.from(bytes).toString("utf8").replace(/^﻿/, ""));
	} catch (error) {
		problems.push(`${label}: not valid JSON (${error.message})`);
		return null;
	}
}

/** Parses a CSP string into a map of directive -> sources. */
export function parseCsp(csp) {
	const directives = new Map();
	for (const part of String(csp).split(";")) {
		const [name, ...sources] = part.trim().split(/\s+/);
		if (name) directives.set(name.toLowerCase(), sources);
	}
	return directives;
}

/** Violations of the store rules for the extension-page CSP (Manifest V3). */
export function cspProblems(csp) {
	const problems = [];
	if (typeof csp !== "string" || csp.trim() === "") return ["content_security_policy.extension_pages is missing"];
	const directives = parseCsp(csp);
	const script = directives.get("script-src") ?? directives.get("default-src");
	if (!script) problems.push("CSP has neither script-src nor default-src");
	else {
		for (const source of script) {
			if (source !== "'self'" && source !== "'none'") problems.push(`CSP script-src allows ${source} (only 'self' is allowed)`);
		}
	}
	const object = directives.get("object-src") ?? directives.get("default-src");
	if (!object || object.some((s) => s !== "'self'" && s !== "'none'")) problems.push("CSP must restrict object-src to 'self' or 'none'");
	for (const [name, sources] of directives) {
		for (const source of sources) {
			if (/^'unsafe-(?:eval|inline|hashes)'$/.test(source) || source === "'wasm-unsafe-eval'") {
				problems.push(`CSP ${name} allows ${source}`);
			}
		}
	}
	return problems;
}

function resolveMessage(value, messages) {
	const match = MESSAGE_REF.exec(String(value ?? ""));
	if (!match) return value;
	return messages?.[match[1]]?.message ?? messages?.[match[1].toLowerCase()]?.message;
}

/** Collects every file path the manifest references. */
export function manifestReferences(manifest) {
	const refs = new Set();
	const add = (value) => typeof value === "string" && value !== "" && refs.add(value.replace(/^\.?\//, ""));
	for (const icon of Object.values(manifest.icons ?? {})) add(icon);
	for (const icon of Object.values(manifest.action?.default_icon ?? {})) add(icon);
	add(manifest.action?.default_popup);
	add(manifest.background?.service_worker);
	for (const script of manifest.background?.scripts ?? []) add(script);
	add(manifest.options_page);
	add(manifest.options_ui?.page);
	add(manifest.storage?.managed_schema);
	for (const entry of manifest.content_scripts ?? []) {
		for (const file of [...(entry.js ?? []), ...(entry.css ?? [])]) add(file);
	}
	return [...refs].sort();
}

/**
 * Validates one store package.
 * @param {"chrome" | "firefox"} target
 * @param {Map<string, Buffer>} files package entries (path -> bytes)
 * @param {{ justifications?: object; label?: string; expectedVersion?: string }} options
 * @returns {string[]} violations
 */
export function validatePackage(target, files, { justifications, label = target, expectedVersion } = {}) {
	const problems = [];
	const at = (message) => problems.push(`${label}: ${message}`);

	const manifestBytes = files.get("manifest.json");
	if (!manifestBytes) return [`${label}: manifest.json is missing from the package root`];
	const manifest = parseJson(manifestBytes, `${label}/manifest.json`, problems);
	if (!manifest) return problems;

	if (manifest.manifest_version !== 3) at(`manifest_version must be 3 (found ${manifest.manifest_version})`);
	if ("key" in manifest) at('manifest.json has a "key" field: store builds must not carry one (the store assigns the id)');
	if ("update_url" in manifest) at('manifest.json has an "update_url": store builds are updated by the store');

	// Version: 1-4 dot-separated integers 0-65535 without leading zeros, not all zero.
	const version = String(manifest.version ?? "");
	if (!VERSION_SHAPE.test(version) || version.split(".").some((n) => Number(n) > 65535) || /^0(\.0)*$/.test(version)) {
		at(`version "${version}" is not 1-4 dot-separated integers (0-65535, no leading zeros, not all zero)`);
	}
	if (expectedVersion && version !== expectedVersion) at(`version ${version} does not match package.json (${expectedVersion})`);

	// Locales and the name / description the stores show.
	const localeDirs = new Set(
		[...files.keys()].map((name) => /^_locales\/([^/]+)\/messages\.json$/.exec(name)?.[1]).filter(Boolean),
	);
	const usesMessages = [manifest.name, manifest.description, manifest.short_name].some((v) => MESSAGE_REF.test(String(v ?? "")));
	if (localeDirs.size > 0 || usesMessages) {
		if (!manifest.default_locale) at("default_locale is required when _locales/ is present");
		else if (!localeDirs.has(manifest.default_locale)) at(`default_locale "${manifest.default_locale}" has no _locales/${manifest.default_locale}/messages.json`);
	} else if (manifest.default_locale) at(`default_locale "${manifest.default_locale}" is set but the package has no _locales/`);
	const locales = localeDirs.size > 0 ? [...localeDirs].sort() : [null];
	for (const locale of locales) {
		const where = locale ? ` (_locales/${locale})` : "";
		const messages = locale ? parseJson(files.get(`_locales/${locale}/messages.json`), `${label}/_locales/${locale}/messages.json`, problems) : {};
		for (const [key, limit, required] of [
			["name", LIMITS.name, true],
			["description", LIMITS.shortDescription, true],
			["short_name", LIMITS.shortName, false],
		]) {
			if (manifest[key] === undefined && !required) continue;
			const text = resolveMessage(manifest[key], messages);
			if (text === undefined && locale !== manifest.default_locale && MESSAGE_REF.test(String(manifest[key]))) continue; // falls back to default_locale
			if (typeof text !== "string" || text.trim() === "") at(`${key}${where} is missing or empty`);
			else if ([...text].length > limit) at(`${key}${where} has ${[...text].length} characters (store limit ${limit})`);
		}
	}

	// Icons: every store size declared, present and a real PNG of that size.
	for (const [field, icons] of [
		["icons", manifest.icons],
		["action.default_icon", manifest.action?.default_icon],
	]) {
		if (!icons || typeof icons !== "object") {
			at(`${field} is missing`);
			continue;
		}
		for (const size of ICON_SIZES) {
			const path = icons[String(size)];
			if (!path) {
				at(`${field} lacks the ${size}x${size} icon`);
				continue;
			}
			const bytes = files.get(String(path).replace(/^\.?\//, ""));
			const actual = pngSize(bytes);
			if (!bytes) at(`${field}["${size}"] -> ${path} is not in the package`);
			else if (!actual) at(`${field}["${size}"] -> ${path} is not a PNG`);
			else if (actual[0] !== size || actual[1] !== size) at(`${field}["${size}"] -> ${path} is ${actual[0]}x${actual[1]}, expected ${size}x${size}`);
		}
	}

	// Permissions: minimum set, each one justified in the listing kit.
	const requested = {
		permissions: manifest.permissions ?? [],
		optional_permissions: manifest.optional_permissions ?? [],
		host_permissions: manifest.host_permissions ?? [],
		optional_host_permissions: manifest.optional_host_permissions ?? [],
	};
	for (const [field, list] of Object.entries(requested)) {
		if (!Array.isArray(list)) {
			at(`${field} must be an array`);
			continue;
		}
		for (const permission of list) {
			if (FORBIDDEN_PERMISSIONS.includes(permission)) at(`${field} requests "${permission}", which this extension must not request`);
		}
	}
	for (const host of requested.host_permissions) {
		if (!EXACT_HOST_PATTERN.test(host)) at(`host_permissions entry "${host}" is not an exact https://<host>/* pattern`);
	}
	if (justifications) {
		const justified = {
			permissions: Object.keys(justifications.permissions ?? {}),
			optional_permissions: Object.keys(justifications.optional_permissions ?? {}),
			host_permissions: Object.keys(justifications.host_permissions?.hosts ?? {}),
			optional_host_permissions: Object.keys(justifications.optional_host_permissions ?? {}),
		};
		for (const [field, list] of Object.entries(requested)) {
			for (const permission of list) {
				if (!justified[field].includes(permission)) at(`${field} "${permission}" has no justification in store/permissions.json`);
			}
		}
		if (target === "chrome") {
			// Chrome's manifest is the complete permission set; a stale justification misleads reviewers.
			for (const [field, list] of Object.entries(justified)) {
				for (const permission of list) {
					if (!requested[field].includes(permission)) at(`store/permissions.json justifies ${field} "${permission}", which the manifest no longer requests`);
				}
			}
		}
	}

	// CSP.
	if (typeof manifest.content_security_policy === "string") at("content_security_policy must be an object in Manifest V3");
	if (manifest.content_security_policy?.sandbox) at("content_security_policy.sandbox is not expected in this extension");
	for (const problem of cspProblems(manifest.content_security_policy?.extension_pages)) at(problem);

	// Files: allowlisted types only, no source maps, every referenced file present.
	const siteHosts = requested.host_permissions.map((p) => EXACT_HOST_PATTERN.test(p) && new URL(p.replace("/*", "/")).hostname).filter(Boolean);
	const names = new Set(files.keys());
	for (const name of [...names].sort()) {
		if (!ALLOWED_FILE.test(name)) at(`unexpected file in a store package: ${name}`);
		const bytes = files.get(name);
		if (/\.(?:js|css|html)$/.test(name)) {
			const text = bytes.toString("utf8");
			if (/[#@]\s*sourceMappingURL\s*=/.test(text)) at(`${name} references a source map`);
			if (name.endsWith(".js")) for (const violation of scanBundle(text, siteHosts)) at(`${name}: ${violation}`);
			if (name.endsWith(".html")) for (const violation of scanHtml(text, names)) at(`${name}: ${violation}`);
		}
	}
	for (const ref of manifestReferences(manifest)) {
		if (!names.has(ref)) at(`manifest references ${ref}, which is not in the package`);
	}

	// Per-browser keys.
	if (target === "chrome") {
		if (!manifest.background?.service_worker) at("Chrome/Edge build needs background.service_worker");
		if (manifest.background?.scripts) at("Chrome/Edge build must not declare background.scripts");
		if (manifest.browser_specific_settings) at("Chrome/Edge build must not carry browser_specific_settings");
	} else {
		const gecko = manifest.browser_specific_settings?.gecko;
		if (gecko?.id !== GECKO_ID) at(`browser_specific_settings.gecko.id must be ${GECKO_ID} (found ${gecko?.id})`);
		if (!gecko?.strict_min_version) at("browser_specific_settings.gecko.strict_min_version is required");
		const required = gecko?.data_collection_permissions?.required;
		if (!Array.isArray(required) || required.length === 0) {
			at("browser_specific_settings.gecko.data_collection_permissions.required is required by addons.mozilla.org");
		}
		if (!Array.isArray(manifest.background?.scripts) || manifest.background.scripts.length === 0) {
			at("Firefox build needs background.scripts (event page)");
		}
		if (manifest.background?.service_worker) at("Firefox build must not declare background.service_worker");
		if (manifest.storage?.managed_schema) at("Firefox build must not declare storage.managed_schema");
	}
	return problems;
}

function readText(file, problems, label) {
	if (!existsSync(file)) {
		problems.push(`${label}: missing`);
		return null;
	}
	return readFileSync(file, "utf8");
}

/** Wording problems in one listing text. */
export function claimProblems(text, label) {
	return UNVERIFIABLE_CLAIMS.filter(([pattern]) => pattern.test(text)).map(([, what]) => `${label}: unverifiable claim (${what})`);
}

/**
 * Validates the listing kit in `storeDir` against the package's locales.
 * @returns {{ problems: string[]; notices: string[] }}
 */
export function validateListingKit(storeDir, packageRoot = PACKAGE_ROOT) {
	const problems = [];
	const notices = [];
	for (const locale of LISTING_LOCALES) {
		const messagesFile = join(packageRoot, "_locales", locale, "messages.json");
		const messages = existsSync(messagesFile) ? JSON.parse(readFileSync(messagesFile, "utf8")) : null;
		if (!messages) problems.push(`_locales/${locale}/messages.json: missing (the listing is localised in ${locale})`);

		const short = readText(join(storeDir, locale, "short-description.txt"), problems, `store/${locale}/short-description.txt`);
		if (short !== null) {
			const text = short.trim();
			if ([...text].length > LIMITS.shortDescription) problems.push(`store/${locale}/short-description.txt: ${[...text].length} characters (limit ${LIMITS.shortDescription})`);
			if (messages && text !== messages.extDescription?.message) {
				problems.push(`store/${locale}/short-description.txt: differs from _locales/${locale} extDescription (the stores show the manifest description)`);
			}
			problems.push(...claimProblems(text, `store/${locale}/short-description.txt`));
		}

		const detailed = readText(join(storeDir, locale, "description.txt"), problems, `store/${locale}/description.txt`);
		if (detailed !== null) {
			const length = [...detailed.trim()].length;
			if (length < LIMITS.detailedMin || length > LIMITS.detailedMax) {
				problems.push(`store/${locale}/description.txt: ${length} characters (stores accept ${LIMITS.detailedMin}-${LIMITS.detailedMax})`);
			}
			if (!detailed.split(/\r?\n/).some((line) => line.trim() === NOT_COVERED_HEADINGS[locale])) {
				problems.push(`store/${locale}/description.txt: the "${NOT_COVERED_HEADINGS[locale]}" section is missing`);
			}
			if (/<[a-z][^>]*>/i.test(detailed)) problems.push(`store/${locale}/description.txt: stores take plain text, found HTML markup`);
			problems.push(...claimProblems(detailed, `store/${locale}/description.txt`));
		}

		const purpose = readText(join(storeDir, locale, "single-purpose.txt"), problems, `store/${locale}/single-purpose.txt`);
		if (purpose !== null) {
			if (purpose.trim() === "" || [...purpose.trim()].length > LIMITS.singlePurposeMax) {
				problems.push(`store/${locale}/single-purpose.txt: must be 1-${LIMITS.singlePurposeMax} characters`);
			}
			problems.push(...claimProblems(purpose, `store/${locale}/single-purpose.txt`));
		}

		const policy = readText(join(storeDir, `privacy-policy.${locale}.html`), problems, `store/privacy-policy.${locale}.html`);
		if (policy !== null) {
			if (/<script\b/i.test(policy)) problems.push(`store/privacy-policy.${locale}.html: must not contain scripts`);
			if (/\b(?:src|href)\s*=\s*["'](?:https?:)?\/\//i.test(policy)) problems.push(`store/privacy-policy.${locale}.html: must not load external resources`);
			if (policy.includes("&lt;PRIVACY_CONTACT_EMAIL&gt;")) notices.push(`store/privacy-policy.${locale}.html: replace <PRIVACY_CONTACT_EMAIL> before hosting`);
		}
	}

	const permissionsFile = join(storeDir, "permissions.json");
	const justifications = existsSync(permissionsFile) ? JSON.parse(readFileSync(permissionsFile, "utf8")) : null;
	if (!justifications) problems.push("store/permissions.json: missing");
	else {
		const texts = [
			...Object.entries(justifications.permissions ?? {}),
			...Object.entries(justifications.optional_permissions ?? {}),
			...Object.entries(justifications.optional_host_permissions ?? {}),
			["host_permissions", justifications.host_permissions?.justification],
			["remote_code", justifications.remote_code],
		];
		for (const [key, text] of texts) {
			for (const locale of LISTING_LOCALES) {
				if (typeof text?.[locale] !== "string" || text[locale].trim().length < 20) {
					problems.push(`store/permissions.json: "${key}" needs a ${locale} justification`);
				}
			}
		}
		for (const [host, product] of Object.entries(justifications.host_permissions?.hosts ?? {})) {
			if (typeof product !== "string" || product.trim() === "") problems.push(`store/permissions.json: host ${host} needs a product name`);
		}
	}

	const imagesDir = join(storeDir, "images");
	if (!existsSync(imagesDir)) problems.push("store/images/: missing (run node scripts/store-assets.mjs)");
	else {
		const images = readdirSync(imagesDir).filter((name) => name.endsWith(".png"));
		for (const [kind, [width, height]] of Object.entries(IMAGE_SIZES)) {
			const matching = images.filter((name) => name.startsWith(`${kind}-`));
			if (matching.length === 0) problems.push(`store/images/: no ${kind}-*.png`);
			for (const name of matching) {
				const size = pngSize(readFileSync(join(imagesDir, name)));
				if (!size || size[0] !== width || size[1] !== height) {
					problems.push(`store/images/${name}: ${size ? size.join("x") : "not a PNG"}, store size is ${width}x${height}`);
				}
			}
		}
		for (const name of images) {
			if (!Object.keys(IMAGE_SIZES).some((kind) => name.startsWith(`${kind}-`))) problems.push(`store/images/${name}: unknown image kind`);
		}
	}
	return { problems, notices, justifications };
}

/** Validates the release zips in `distDir` and the listing kit in `storeDir`. */
export function validateRelease({ distDir, storeDir, version, packageRoot = PACKAGE_ROOT }) {
	const kit = validateListingKit(storeDir, packageRoot);
	const problems = [...kit.problems];
	const { version: numeric } = manifestVersion(version);
	const packages = [];
	for (const target of ["chrome", "firefox"]) {
		const name = `aidr-browser-guard-${target}-${numeric}.zip`;
		const file = join(distDir, name);
		if (!existsSync(file)) {
			problems.push(`${name}: missing in ${distDir} (run pnpm package:browser-guard)`);
			continue;
		}
		const bytes = readFileSync(file);
		if (bytes.length > LIMITS.packageBytes) problems.push(`${name}: ${bytes.length} bytes exceeds ${LIMITS.packageBytes}`);
		let files;
		try {
			files = readZip(bytes);
		} catch (error) {
			problems.push(`${name}: not a readable zip (${error.message})`);
			continue;
		}
		problems.push(...validatePackage(target, files, { justifications: kit.justifications, label: name, expectedVersion: numeric }));
		packages.push(name);
	}
	return { problems, notices: kit.notices, packages };
}

function parseArgs(argv) {
	const options = {};
	for (let i = 0; i < argv.length; i++) {
		const flag = argv[i];
		const key = { "--dist": "distDir", "--store": "storeDir", "--version": "version" }[flag];
		if (!key || !argv[i + 1]) throw new Error(`usage: validate-store.mjs [--dist <dir>] [--store <dir>] [--version <x.y.z>] (bad argument ${flag})`);
		options[key] = argv[++i];
	}
	return options;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	let options;
	try {
		options = parseArgs(process.argv.slice(2));
	} catch (error) {
		console.error(error.message);
		process.exit(2);
	}
	const version = options.version ?? JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8")).version;
	const { problems, notices, packages } = validateRelease({
		distDir: resolve(options.distDir ?? join(PACKAGE_ROOT, "dist")),
		storeDir: resolve(options.storeDir ?? join(PACKAGE_ROOT, "store")),
		version,
	});
	for (const notice of notices) console.log(`[browser-guard store] notice: ${notice}`);
	if (problems.length > 0) {
		console.error(`[browser-guard store] ${problems.length} store violation(s):\n  - ${problems.join("\n  - ")}`);
		process.exit(1);
	}
	console.log(`[browser-guard store] ${packages.join(", ")} and the listing kit pass the offline store checks`);
}
