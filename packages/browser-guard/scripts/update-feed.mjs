#!/usr/bin/env node
/**
 * Builds the self-hosted update feed of Browser Guard: a directory to upload to any static
 * HTTPS host (an internal web server for air-gapped networks, or the publisher's download
 * host), from which Chrome, Edge and Firefox update the extension by themselves.
 *
 *   node scripts/update-feed.mjs --base-url https://<host>/browser-guard --out <dir> \
 *     [--chrome-zip dist/aidr-browser-guard-chrome-selfhosted-<v>.zip --extension-id <pinned id>] \
 *     [--chrome-crx aidr-browser-guard-<v>.crx --extension-id <pinned id>]   # already signed: no key needed \
 *     [--firefox-xpi <Mozilla-signed .xpi> [--firefox-zip dist/aidr-browser-guard-firefox-selfhosted-<v>.zip]] \
 *     [--previous <the feed directory currently hosted>]
 *   node scripts/update-feed.mjs --print-extension-id      # the ID the owner key gives (pin it)
 *
 * The Chrome/Edge package is signed here as a CRX3 with the owner's extension key, read
 * from the BROWSER_GUARD_CRX_KEY_PEM environment variable (or --crx-key-file). The key is
 * never written anywhere. Without it nothing is produced (exit 2): there is no unsigned
 * or throw-away-key fallback, because a different key means a different extension ID and
 * every managed policy would silently stop matching. --extension-id pins the expected ID
 * and fails on a mismatch (a rotated or wrong key). A CRX the release workflow already
 * signed (--chrome-crx) needs no key: its CRX3 signature is verified and its ID must equal
 * the pinned --extension-id, so an internal host can publish it under its own URL.
 *
 * The Firefox package must be the XPI Mozilla signed through the addons.mozilla.org
 * unlisted channel (Firefox refuses unsigned add-ons); its gecko.update_url must be this
 * feed's updates.json, otherwise Firefox would never read the feed.
 *
 * Output (written to a temporary directory and renamed into place only when complete):
 *   update.xml                       gupdate manifest for Chrome/Edge (latest version)
 *   updates.json                     Firefox update manifest (every hosted version)
 *   packages/aidr-browser-guard-<v>.crx
 *   packages/aidr-browser-guard-firefox-<v>.xpi
 *   SHA256SUMS                       every file above
 *
 * With --previous, the hosted feed is verified against its SHA256SUMS, its packages are
 * carried over (older versions stay downloadable for pinning and rollback) and every new
 * version must be strictly higher than the hosted one: a feed never moves backwards.
 *
 * Exit code 0 = feed written, 1 = rejected input (each reason printed), 2 = usage error or
 * missing signing key.
 */
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { GECKO_ID, normalizeUpdateBaseUrl, selfHostedUpdateUrl } from "./build.mjs";
import { readZip } from "./zip.mjs";

export const CRX_KEY_ENV = "BROWSER_GUARD_CRX_KEY_PEM";
const CRX_MAGIC = Buffer.from("Cr24", "latin1");
const CRX_SIGNED_DATA_PREFIX = Buffer.from("CRX3 SignedData\x00", "latin1");
const MIN_RSA_BITS = 2048;
const VERSION_SHAPE = /^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){0,3}$/;
const EXTENSION_ID_SHAPE = /^[a-p]{32}$/;

export class FeedError extends Error {
	constructor(message, exitCode = 1) {
		super(message);
		this.exitCode = exitCode;
	}
}

const sha256 = (data) => createHash("sha256").update(data).digest("hex");

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

/** Compares two 1-4 part numeric versions (Chrome and Firefox order them the same way). */
export function compareVersions(a, b) {
	for (const value of [a, b]) {
		if (!VERSION_SHAPE.test(String(value))) throw new FeedError(`not an extension version: ${JSON.stringify(value)}`);
	}
	const pa = a.split(".").map(Number);
	const pb = b.split(".").map(Number);
	for (let i = 0; i < 4; i++) {
		const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
		if (diff !== 0) return Math.sign(diff);
	}
	return 0;
}

// ---------------------------------------------------------------------------
// CRX3 (Chromium components/crx_file: crx3.proto)
// ---------------------------------------------------------------------------

function varint(value) {
	const out = [];
	let n = value;
	while (n >= 0x80) {
		out.push((n & 0x7f) | 0x80);
		n = Math.floor(n / 128);
	}
	out.push(n);
	return Buffer.from(out);
}

/** A length-delimited protobuf field. */
function field(number, bytes) {
	return Buffer.concat([varint(number * 8 + 2), varint(bytes.length), bytes]);
}

function readVarint(buffer, offset) {
	let value = 0;
	let factor = 1;
	for (let i = offset; i < buffer.length && i < offset + 10; i++) {
		value += (buffer[i] & 0x7f) * factor;
		factor *= 128;
		if ((buffer[i] & 0x80) === 0) return [value, i + 1];
	}
	throw new FeedError("CRX header: truncated varint");
}

/** Length-delimited fields of a protobuf message as [number, bytes] pairs (varints skipped). */
function readFields(buffer) {
	const fields = [];
	let offset = 0;
	while (offset < buffer.length) {
		const [tag, next] = readVarint(buffer, offset);
		const number = Math.floor(tag / 8);
		const wire = tag % 8;
		if (wire === 0) {
			offset = readVarint(buffer, next)[1];
		} else if (wire === 2) {
			const [length, start] = readVarint(buffer, next);
			if (start + length > buffer.length) throw new FeedError("CRX header: truncated field");
			fields.push([number, buffer.subarray(start, start + length)]);
			offset = start + length;
		} else {
			throw new FeedError(`CRX header: unsupported wire type ${wire}`);
		}
	}
	return fields;
}

/** Chromium's extension ID: the first 128 bits of SHA-256(SubjectPublicKeyInfo), hex digits mapped to a-p. */
export function extensionIdFromPublicKey(spkiDer) {
	return [...createHash("sha256").update(spkiDer).digest("hex").slice(0, 32)]
		.map((digit) => String.fromCharCode(97 + Number.parseInt(digit, 16)))
		.join("");
}

/** Loads the owner's RSA private key (PKCS#1 or PKCS#8 PEM). */
export function loadCrxKey(pem) {
	if (typeof pem !== "string" || pem.trim() === "") {
		throw new FeedError(
			`no extension signing key: set ${CRX_KEY_ENV} (the owner's CRX private key, PEM) or pass --crx-key-file. ` +
				"Nothing was signed; a throw-away key would change the extension ID.",
			2,
		);
	}
	let key;
	try {
		key = createPrivateKey(pem);
	} catch (error) {
		throw new FeedError(`the extension signing key is not a readable PEM private key (${error.message})`, 2);
	}
	if (key.asymmetricKeyType !== "rsa") throw new FeedError(`the extension signing key must be RSA (found ${key.asymmetricKeyType})`, 2);
	const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
	if (bits < MIN_RSA_BITS) throw new FeedError(`the extension signing key has ${bits} bits; at least ${MIN_RSA_BITS} are required`, 2);
	const publicKey = createPublicKey(key).export({ type: "spki", format: "der" });
	return { privateKey: key, publicKey, extensionId: extensionIdFromPublicKey(publicKey) };
}

function signedPayload(signedHeaderData, archive) {
	const length = Buffer.alloc(4);
	length.writeUInt32LE(signedHeaderData.length, 0);
	return Buffer.concat([CRX_SIGNED_DATA_PREFIX, length, signedHeaderData, archive]);
}

/**
 * Packs `archive` (the extension zip) as a CRX3 signed with SHA256withRSA.
 * RSA PKCS#1 v1.5 signatures are deterministic, so the same key and zip give the same CRX.
 */
export function createCrx3(archive, key) {
	const crxId = createHash("sha256").update(key.publicKey).digest().subarray(0, 16);
	const signedHeaderData = field(1, crxId);
	const signature = sign("sha256", signedPayload(signedHeaderData, archive), key.privateKey);
	const header = Buffer.concat([
		field(2, Buffer.concat([field(1, key.publicKey), field(2, signature)])),
		field(10000, signedHeaderData),
	]);
	const prefix = Buffer.alloc(12);
	CRX_MAGIC.copy(prefix, 0);
	prefix.writeUInt32LE(3, 4);
	prefix.writeUInt32LE(header.length, 8);
	return Buffer.concat([prefix, header, archive]);
}

/**
 * Parses and verifies a CRX3: the RSA proof whose key matches the signed crx_id must verify
 * over the signed header data and the archive. Returns the extension ID and the zip.
 */
export function verifyCrx3(crx) {
	if (crx.length < 12 || !crx.subarray(0, 4).equals(CRX_MAGIC)) throw new FeedError("not a CRX file (magic)");
	if (crx.readUInt32LE(4) !== 3) throw new FeedError(`CRX version ${crx.readUInt32LE(4)} is not 3`);
	const headerLength = crx.readUInt32LE(8);
	if (12 + headerLength > crx.length) throw new FeedError("CRX header is truncated");
	const header = crx.subarray(12, 12 + headerLength);
	const archive = crx.subarray(12 + headerLength);
	const fields = readFields(header);
	const signedHeaderData = fields.find(([n]) => n === 10000)?.[1];
	if (!signedHeaderData) throw new FeedError("CRX header has no signed_header_data");
	const crxId = readFields(signedHeaderData).find(([n]) => n === 1)?.[1];
	if (!crxId || crxId.length !== 16) throw new FeedError("CRX signed_header_data has no 16-byte crx_id");
	const payload = signedPayload(signedHeaderData, archive);
	for (const [, proofBytes] of fields.filter(([n]) => n === 2)) {
		const proof = readFields(proofBytes);
		const publicKey = proof.find(([n]) => n === 1)?.[1];
		const signature = proof.find(([n]) => n === 2)?.[1];
		if (!publicKey || !signature) continue;
		if (!createHash("sha256").update(publicKey).digest().subarray(0, 16).equals(crxId)) continue;
		const key = createPublicKey({ key: Buffer.from(publicKey), format: "der", type: "spki" });
		if (!verify("sha256", payload, key, signature)) throw new FeedError("CRX signature does not verify");
		return { extensionId: extensionIdFromPublicKey(publicKey), archive: Buffer.from(archive) };
	}
	throw new FeedError("CRX has no RSA proof for its crx_id");
}

// ---------------------------------------------------------------------------
// Update manifests
// ---------------------------------------------------------------------------

const xmlAttr = (value) =>
	String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");

/** gupdate update manifest (Chrome and Edge autoupdate protocol 2.0). */
export function renderUpdateXml({ extensionId, version, codebase, sha256: hash }) {
	return [
		"<?xml version='1.0' encoding='UTF-8'?>",
		"<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>",
		`  <app appid='${xmlAttr(extensionId)}'>`,
		`    <updatecheck codebase='${xmlAttr(codebase)}' version='${xmlAttr(version)}' hash_sha256='${xmlAttr(hash)}' />`,
		"  </app>",
		"</gupdate>",
		"",
	].join("\n");
}

const XML_DECODE = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

/** Reads the update.xml this script writes (one app, one updatecheck). */
export function parseUpdateXml(text) {
	const attrs = (tag) => {
		const match = new RegExp(`<${tag}\\b([^>]*)>`).exec(text);
		if (!match) throw new FeedError(`update.xml has no <${tag}>`);
		return Object.fromEntries(
			[...match[1].matchAll(/([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['"])(.*?)\2/g)].map(([, name, , value]) => [
				name,
				value.replace(/&(amp|lt|gt|quot|apos);/g, (_, entity) => XML_DECODE[entity]),
			]),
		);
	};
	const app = attrs("app");
	const check = attrs("updatecheck");
	return { extensionId: app.appid, version: check.version, codebase: check.codebase, sha256: check.hash_sha256 };
}

/** Firefox update manifest; `updates` must be in ascending version order. */
export function renderUpdatesJson(updates) {
	return `${JSON.stringify({ addons: { [GECKO_ID]: { updates } } }, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Feed
// ---------------------------------------------------------------------------

function requireHttps(url, label) {
	const parsed = new URL(url);
	if (parsed.protocol !== "https:") throw new FeedError(`${label} ${url} is not https`);
	return url;
}

function readManifest(files, label) {
	const bytes = files.get("manifest.json");
	if (!bytes) throw new FeedError(`${label}: manifest.json is missing`);
	try {
		return JSON.parse(bytes.toString("utf8"));
	} catch (error) {
		throw new FeedError(`${label}: manifest.json is not valid JSON (${error.message})`);
	}
}

function readZipFile(file, label) {
	if (!existsSync(file)) throw new FeedError(`${label}: ${file} does not exist`);
	const bytes = readFileSync(file);
	try {
		return { bytes, files: readZip(bytes) };
	} catch (error) {
		throw new FeedError(`${label}: ${file} is not a readable zip (${error.message})`);
	}
}

/** Parses SHA256SUMS ("<hex>  <path>") into a Map path -> hex. */
export function parseSums(text) {
	const sums = new Map();
	for (const line of text.split("\n")) {
		if (line.trim() === "") continue;
		const match = /^([0-9a-f]{64}) [ *]([^\s].*)$/.exec(line);
		if (!match || match[2].split("/").some((part) => part === ".." || part === "")) {
			throw new FeedError(`SHA256SUMS: malformed line ${JSON.stringify(line)}`);
		}
		sums.set(match[2], match[1]);
	}
	return sums;
}

/** Reads and verifies a hosted feed directory. */
export function readFeed(dir) {
	const sumsFile = join(dir, "SHA256SUMS");
	if (!existsSync(sumsFile)) throw new FeedError(`previous feed ${dir} has no SHA256SUMS`);
	const sums = parseSums(readFileSync(sumsFile, "utf8"));
	const files = new Map();
	for (const [path, hash] of sums) {
		const file = join(dir, path);
		if (!existsSync(file)) throw new FeedError(`previous feed: ${path} is listed in SHA256SUMS but missing`);
		const bytes = readFileSync(file);
		if (sha256(bytes) !== hash) throw new FeedError(`previous feed: ${path} does not match SHA256SUMS (tampered or partial upload)`);
		files.set(path, bytes);
	}
	const chrome = files.has("update.xml") ? parseUpdateXml(files.get("update.xml").toString("utf8")) : null;
	let firefox = [];
	if (files.has("updates.json")) {
		try {
			firefox = JSON.parse(files.get("updates.json").toString("utf8")).addons?.[GECKO_ID]?.updates ?? [];
		} catch (error) {
			throw new FeedError(`previous feed: updates.json is not valid JSON (${error.message})`);
		}
	}
	return { files, chrome, firefox };
}

function isMozillaSigned(files) {
	return files.has("META-INF/manifest.mf") && (files.has("META-INF/mozilla.rsa") || files.has("META-INF/cose.sig"));
}

/**
 * The signed Chrome/Edge package: --chrome-zip is signed here with the owner key;
 * --chrome-crx (signed earlier, for example by the release workflow) is verified instead and
 * needs no key, but its ID must be pinned with --extension-id.
 * @returns {{ crx: Buffer; archive: Buffer; extensionId: string }}
 */
function signedChromePackage(options) {
	if (options.chromeCrx) {
		if (!options.extensionId) throw new FeedError("--chrome-crx needs --extension-id (the pinned ID of the self-hosted extension)", 2);
		if (!existsSync(options.chromeCrx)) throw new FeedError(`--chrome-crx: ${options.chromeCrx} does not exist`);
		const crx = readFileSync(options.chromeCrx);
		const checked = verifyCrx3(crx);
		if (checked.extensionId !== options.extensionId) {
			throw new FeedError(`--chrome-crx is signed for extension ${checked.extensionId}, but ${options.extensionId} is pinned`);
		}
		return { crx, archive: checked.archive, extensionId: checked.extensionId };
	}
	const key = loadCrxKey(options.crxKeyPem);
	if (options.extensionId && key.extensionId !== options.extensionId) {
		throw new FeedError(
			`the signing key gives extension ID ${key.extensionId}, but ${options.extensionId} is pinned: wrong or rotated key, nothing was signed`,
		);
	}
	const archive = readZipFile(options.chromeZip, "--chrome-zip").bytes;
	const crx = createCrx3(archive, key);
	const checked = verifyCrx3(crx);
	if (checked.extensionId !== key.extensionId || !checked.archive.equals(archive)) throw new FeedError("CRX self-check failed");
	return { crx, archive, extensionId: key.extensionId };
}

/**
 * Builds the feed in memory.
 * @param {{
 *   baseUrl: string;
 *   chromeZip?: string; crxKeyPem?: string; chromeCrx?: string; extensionId?: string;
 *   firefoxXpi?: string; firefoxZip?: string;
 *   previous?: string;
 * }} options
 * @returns {{ files: Map<string, Buffer>; extensionId: string | null; chromeVersion: string | null; firefoxVersion: string | null; notices: string[] }}
 */
export function buildFeed(options) {
	let baseUrl;
	try {
		baseUrl = normalizeUpdateBaseUrl(options.baseUrl);
	} catch (error) {
		throw new FeedError(`--base-url: ${error.message}`, 2);
	}
	if (!options.chromeZip && !options.chromeCrx && !options.firefoxXpi) {
		throw new FeedError("nothing to publish: pass --chrome-zip or --chrome-crx, and/or --firefox-xpi", 2);
	}
	if (options.chromeZip && options.chromeCrx) throw new FeedError("pass either --chrome-zip (sign it) or --chrome-crx (already signed), not both", 2);
	if (options.extensionId && !EXTENSION_ID_SHAPE.test(options.extensionId)) {
		throw new FeedError(`--extension-id ${options.extensionId} is not a 32-letter (a-p) extension ID`, 2);
	}
	const notices = [];
	const previous = options.previous ? readFeed(options.previous) : { files: new Map(), chrome: null, firefox: [] };
	const out = new Map();
	// Older packages stay downloadable (pinning, rollback by policy); the manifests are rebuilt.
	for (const [path, bytes] of previous.files) if (path.startsWith("packages/")) out.set(path, bytes);

	let extensionId = previous.chrome?.extensionId ?? null;
	let chromeVersion = previous.chrome?.version ?? null;
	if (previous.chrome) out.set("update.xml", previous.files.get("update.xml"));

	if (options.chromeZip || options.chromeCrx) {
		const chrome = signedChromePackage(options);
		if (previous.chrome && previous.chrome.extensionId !== chrome.extensionId) {
			throw new FeedError(
				`the hosted feed serves extension ${previous.chrome.extensionId}; this package is ${chrome.extensionId} (managed browsers would not accept it)`,
			);
		}
		const manifest = readManifest(readZip(chrome.archive), "Chrome/Edge package");
		const version = String(manifest.version);
		if (manifest.manifest_version !== 3) throw new FeedError("Chrome/Edge package: not a Manifest V3 package");
		if (typeof manifest.update_url !== "string") {
			throw new FeedError("Chrome/Edge package: the manifest has no update_url (use the -selfhosted- package, not the store package)");
		}
		requireHttps(manifest.update_url, "Chrome/Edge package update_url");
		const feedUrl = selfHostedUpdateUrl("chrome", baseUrl);
		if (manifest.update_url !== feedUrl) {
			notices.push(
				`the package updates from ${manifest.update_url}; browsers reach this feed (${feedUrl}) only with ExtensionSettings "override_update_url": true`,
			);
		}
		if (previous.chrome && compareVersions(version, previous.chrome.version) <= 0) {
			throw new FeedError(`Chrome/Edge version ${version} is not higher than the hosted ${previous.chrome.version}: a feed never moves backwards`);
		}
		const path = `packages/aidr-browser-guard-${version}.crx`;
		if (out.has(path)) throw new FeedError(`${path} is already hosted`);
		out.set(path, chrome.crx);
		out.set(
			"update.xml",
			Buffer.from(
				renderUpdateXml({
					extensionId: chrome.extensionId,
					version,
					codebase: requireHttps(`${baseUrl}/${path}`, "codebase"),
					sha256: sha256(chrome.crx),
				}),
			),
		);
		extensionId = chrome.extensionId;
		chromeVersion = version;
	}

	const firefoxUpdates = [...previous.firefox];
	let firefoxVersion = firefoxUpdates.at(-1)?.version ?? null;
	if (options.firefoxXpi) {
		const { bytes, files } = readZipFile(options.firefoxXpi, "--firefox-xpi");
		if (!isMozillaSigned(files)) {
			throw new FeedError(
				"--firefox-xpi is not signed by Mozilla (no META-INF signature): Firefox refuses it. Use the XPI that addons.mozilla.org signed (unlisted channel).",
			);
		}
		const manifest = readManifest(files, "--firefox-xpi");
		const gecko = manifest.browser_specific_settings?.gecko ?? {};
		if (gecko.id !== GECKO_ID) throw new FeedError(`--firefox-xpi: add-on id ${gecko.id} is not ${GECKO_ID}`);
		const feedUrl = selfHostedUpdateUrl("firefox", baseUrl);
		if (gecko.update_url !== feedUrl) {
			throw new FeedError(
				`--firefox-xpi: gecko.update_url is ${gecko.update_url ?? "missing"}, but this feed is ${feedUrl}; Firefox would never read it (Firefox has no policy to override the signed update URL)`,
			);
		}
		if (options.firefoxZip) {
			const built = readZipFile(options.firefoxZip, "--firefox-zip").files;
			// Mozilla adds only META-INF/ (the signature); every other file must be the attested build's.
			const names = new Set([...built.keys(), ...[...files.keys()].filter((name) => !name.startsWith("META-INF/"))]);
			for (const name of names) {
				const expected = built.get(name);
				const actual = files.get(name);
				if (!expected || !actual || !expected.equals(actual)) {
					throw new FeedError(`--firefox-xpi: ${name} differs from the release build ${basename(options.firefoxZip)}`);
				}
			}
		}
		const version = String(manifest.version);
		if (firefoxVersion && compareVersions(version, firefoxVersion) <= 0) {
			throw new FeedError(`Firefox version ${version} is not higher than the hosted ${firefoxVersion}: a feed never moves backwards`);
		}
		const path = `packages/aidr-browser-guard-firefox-${version}.xpi`;
		if (out.has(path)) throw new FeedError(`${path} is already hosted`);
		out.set(path, bytes);
		firefoxUpdates.push({
			version,
			update_link: requireHttps(`${baseUrl}/${path}`, "update_link"),
			update_hash: `sha256:${sha256(bytes)}`,
			...(gecko.strict_min_version ? { applications: { gecko: { strict_min_version: gecko.strict_min_version } } } : {}),
		});
		firefoxVersion = version;
	}
	for (let i = 1; i < firefoxUpdates.length; i++) {
		if (compareVersions(firefoxUpdates[i].version, firefoxUpdates[i - 1].version) <= 0) {
			throw new FeedError("updates.json versions are not strictly ascending");
		}
	}
	if (firefoxUpdates.length > 0) out.set("updates.json", Buffer.from(renderUpdatesJson(firefoxUpdates)));

	const sums = [...out]
		.map(([path, bytes]) => `${sha256(bytes)}  ${path}`)
		.sort((a, b) => (a.slice(66) < b.slice(66) ? -1 : 1));
	out.set("SHA256SUMS", Buffer.from(`${sums.join("\n")}\n`));
	return { files: out, extensionId, chromeVersion, firefoxVersion, notices };
}

/** Writes the feed atomically: a sibling temporary directory renamed into place; removed on failure. */
export function writeFeed(outDir, files) {
	const target = resolve(outDir);
	if (existsSync(target) && readdirSync(target).length > 0) throw new FeedError(`--out ${outDir} exists and is not empty`, 2);
	const temp = `${target}.tmp-${process.pid}`;
	rmSync(temp, { recursive: true, force: true });
	try {
		for (const [path, bytes] of files) {
			const file = join(temp, path);
			mkdirSync(dirname(file), { recursive: true });
			writeFileSync(file, bytes);
		}
		if (existsSync(target)) rmSync(target, { recursive: true });
		renameSync(temp, target);
	} catch (error) {
		rmSync(temp, { recursive: true, force: true });
		throw error;
	}
	return target;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE =
	"usage: update-feed.mjs --base-url <https url> --out <dir> [--chrome-zip <zip> [--extension-id <id>] [--crx-key-file <pem>] | --chrome-crx <crx> --extension-id <id>] " +
	"[--firefox-xpi <signed xpi> [--firefox-zip <zip>]] [--previous <feed dir>]\n" +
	"       update-feed.mjs --print-extension-id [--crx-key-file <pem>]";

const FLAGS = {
	"--base-url": "baseUrl",
	"--out": "out",
	"--chrome-zip": "chromeZip",
	"--chrome-crx": "chromeCrx",
	"--extension-id": "extensionId",
	"--crx-key-file": "crxKeyFile",
	"--firefox-xpi": "firefoxXpi",
	"--firefox-zip": "firefoxZip",
	"--previous": "previous",
};

export function parseArgs(argv) {
	const options = {};
	for (let i = 0; i < argv.length; i++) {
		if (argv[i] === "--print-extension-id") {
			options.printExtensionId = true;
			continue;
		}
		const key = FLAGS[argv[i]];
		if (!key || !argv[i + 1]) throw new FeedError(`${USAGE}\n(bad argument ${argv[i]})`, 2);
		options[key] = argv[++i];
	}
	if (!options.printExtensionId && (!options.baseUrl || !options.out)) throw new FeedError(USAGE, 2);
	return options;
}

function keyPem(options) {
	if (options.crxKeyFile) {
		if (!existsSync(options.crxKeyFile)) throw new FeedError(`--crx-key-file ${options.crxKeyFile} does not exist`, 2);
		return readFileSync(options.crxKeyFile, "utf8");
	}
	return process.env[CRX_KEY_ENV];
}

export function main(argv, log = console.log) {
	const options = parseArgs(argv);
	if (options.printExtensionId) {
		log(loadCrxKey(keyPem(options)).extensionId);
		return;
	}
	const feed = buildFeed({ ...options, crxKeyPem: options.chromeZip ? keyPem(options) : undefined });
	const dir = writeFeed(options.out, feed.files);
	for (const notice of feed.notices) log(`[browser-guard feed] notice: ${notice}`);
	log(
		`[browser-guard feed] ${dir}: Chrome/Edge ${feed.chromeVersion ?? "-"}${feed.extensionId ? ` (extension ID ${feed.extensionId})` : ""}, Firefox ${feed.firefoxVersion ?? "-"}; upload the whole directory to ${normalizeUpdateBaseUrl(options.baseUrl)}/`,
	);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		main(process.argv.slice(2));
	} catch (error) {
		console.error(`[browser-guard feed] ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = error instanceof FeedError ? error.exitCode : 1;
	}
}
