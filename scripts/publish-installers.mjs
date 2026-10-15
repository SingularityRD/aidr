#!/usr/bin/env node

/**
 * Publish a promoted release's customer installers to the download portal.
 *
 * The AIDR dashboard Download page (packages/dashboard, `installer-download`
 * Edge Function) serves installers from a PRIVATE Supabase Storage bucket. This
 * script is the only writer of that bucket. It never builds or signs an
 * installer; it republishes the exact bytes of an already promoted release:
 *
 *   1. Verify the release bundle against the trusted release-signer policy with
 *      the same primitives as scripts/release-verify.mjs (Ed25519 signature,
 *      trusted signer window, expiry, metadata/inventory bindings, every
 *      artifact digest and size). Nothing is read from an unverified bundle.
 *   2. Select the installers (explicit `--installer <platform>=<path>`, repeatable
 *      once per format, or the `installers/<platform>/<file>` convention, where the
 *      file extension names the format: FORMATS below) and require each one to be
 *      a signed artifact of that manifest and to appear in SHA256SUMS with the
 *      same digest. The bytes that were hashed are the bytes that are uploaded.
 *      A platform carries one file per format (Windows .msi; Linux .deb, .rpm
 *      and .tar.gz).
 *   3. Write the storage contract for this version (docs/installation/download-portal.md):
 *
 *        <version>/<platform>/<file>                  installer bytes (immutable)
 *        <version>/SHA256SUMS                          `<sha256>  <platform>/<file>`
 *        <version>/release/aidr-release.manifest.json  signed release manifest (verbatim)
 *        <version>/release/aidr-release.manifest.sig   its Ed25519 signature
 *        <version>/manifest.json                       installer catalog (below; schema 1, or 2 when a platform has several formats)
 *        <version>/manifest.json.sig                   Ed25519 signature over manifest.json bytes
 *        latest.json / latest.json.sig                 signed pointer to the current version
 *
 *      Signatures use the release signature envelope of
 *      scripts/release-signing-lib.mjs (`signReleaseManifest`) with a dedicated
 *      installer-catalog key; the Edge Function verifies them with
 *      AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64 and refuses to serve otherwise.
 *   4. Upload with the service-role key. Versioned objects are written without
 *      upsert: an existing object is accepted only when its bytes are identical
 *      (an idempotent re-run), never replaced. latest.json is written last and
 *      refuses to move to a lower release sequence than the current pointer.
 *
 * Fail closed: a publish (not --dry-run) without the catalog signing key, its
 * key id, SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY stops before any upload.
 * Nothing is ever published unsigned.
 *
 * Usage:
 *   node scripts/publish-installers.mjs --bundle <release-output> --policy <signer-policy.json>
 *     [--sha256sums <file>] [--installer <platform>=<bundle path>]... [--min-os <platform>=<text>]...
 *     [--release-notes-url <https url>] [--signing-key <pem>] [--key-id <id>]
 *     [--out <dir>] [--dry-run] [--allow-downgrade]
 *
 * Environment:
 *   AIDR_INSTALLER_MANIFEST_SIGNING_KEY_PATH  Ed25519 PKCS#8 PEM (outside the bundle) when --signing-key is absent
 *   AIDR_INSTALLER_MANIFEST_KEY_ID            key id when --key-id is absent
 *   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY   upload target (not read by --dry-run)
 *   AIDR_INSTALLERS_BUCKET                    bucket name (default aidr-installers)
 *
 * --dry-run verifies and stages everything into --out (default: a new temporary
 * directory) and makes no network request. Without a signing key it stages an
 * UNSIGNED catalog for inspection only (no .sig files, "signed": false).
 *
 * Release promotion (.github/workflows/release-promote.yml, `promote` job) runs,
 * after "Publish final GitHub release from the same bundle":
 *
 *   node .trusted-release-verifier/scripts/publish-installers.mjs \
 *     --bundle release-output \
 *     --policy "${AIDR_RELEASE_SIGNER_POLICY_PATH}" \
 *     --signing-key "${RUNNER_TEMP}/aidr-installer-catalog-key.pem" \
 *     --key-id "${AIDR_INSTALLER_MANIFEST_KEY_ID}" \
 *     --release-notes-url "https://<release notes host>/<tag>"
 *
 * with SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / AIDR_INSTALLERS_BUCKET from the
 * production environment and the PEM written (umask 077) from the
 * AIDR_INSTALLER_MANIFEST_SIGNING_KEY_PEM secret. See docs/installation/download-portal.md.
 */

import { createPrivateKey, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
	loadEd25519PrivateKey,
	loadReleaseBundle,
	loadSignerPolicy,
	RELEASE_MANIFEST_NAME,
	RELEASE_SIGNATURE_NAME,
	readJsonFile,
	sha256,
	signReleaseManifest,
	validateReleaseManifest,
	verifyManifestSignature,
} from "./release-signing-lib.mjs";

const DEFAULT_INSTALLERS_BUCKET = "aidr-installers";
const CATALOG_TYPE = "aidr-installer-catalog";
const LATEST_TYPE = "aidr-installer-latest";
const PLATFORMS = Object.freeze([
	"windows-x64",
	"windows-arm64",
	"linux-x64",
	"linux-arm64",
]);

// Minimum OS of the bundled Node.js 22 SEA runtime; override with --min-os.
// Windows and Linux only: no macOS installer is offered yet. Adding a platform is a
// data change here, in _shared/installer-catalog.ts and in the audit RPC check.
const DEFAULT_MINIMUM_OS = Object.freeze({
	windows: "Windows 10 / Windows Server 2016",
	linux: "glibc 2.28 (e.g. Ubuntu 20.04, RHEL 8)",
});
// The installer formats of each OS, in display order; a file's extension names its
// format. Adding a format is a data change here and in INSTALLER_FORMATS of
// supabase/functions/_shared/installer-catalog.ts (and, for `aidr update` to install
// it, in packages/cli/src/utils/update-installer.ts).
const FORMATS = Object.freeze({
	windows: Object.freeze(["msi"]),
	linux: Object.freeze(["deb", "rpm", "tar.gz"]),
});
// Catalog schema 1 lists one file per platform; schema 2 one per platform and format.
// A release with a single file per platform keeps writing schema 1 so endpoints that
// only read schema 1 keep updating (docs/installation/download-portal.md).
const SINGLE_FORMAT_SCHEMA = 1;
const MULTI_FORMAT_SCHEMA = 2;
const INSTALLER_VERSION_RE = /^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z.-]{1,64})?$/;
const FILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/;
const KEY_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const BUCKET_RE = /^[a-z0-9][a-z0-9._-]{1,62}$/;
const CONVENTION_RE = /^installers\/([a-z0-9-]+)\/([^/]+)$/;

class PublishError extends Error {
	constructor(message) {
		super(message);
		this.name = "PublishError";
	}
}

function fail(message) {
	throw new PublishError(message);
}

/** Parse SHA256SUMS (`<hex>  <name>` or `<hex> *<name>`) into name -> digest. */
export function parseSha256Sums(text) {
	const entries = new Map();
	for (const [index, raw] of String(text).split(/\r?\n/).entries()) {
		const line = raw.trim();
		if (!line || line.startsWith("#")) continue;
		const match = /^([0-9a-fA-F]{64}) [ *](.+)$/.exec(line);
		if (!match) fail(`SHA256SUMS line ${index + 1} is malformed`);
		const name = match[2].replace(/^\.\//, "");
		const digest = match[1].toLowerCase();
		if (entries.has(name) && entries.get(name) !== digest) fail(`SHA256SUMS lists ${name} twice with different digests`);
		entries.set(name, digest);
	}
	if (entries.size === 0) fail("SHA256SUMS is empty");
	return entries;
}

function splitPair(value, label) {
	const separator = value.indexOf("=");
	const key = separator > 0 ? value.slice(0, separator).trim() : "";
	const rest = separator > 0 ? value.slice(separator + 1).trim() : "";
	if (!key || !rest) fail(`${label} must be <platform>=<value>: ${value}`);
	if (!PLATFORMS.includes(key)) fail(`${label} names an unknown platform ${key} (allowed: ${PLATFORMS.join(", ")})`);
	return [key, rest];
}

function parsePairs(values, label) {
	const pairs = new Map();
	for (const value of values ?? []) {
		const [key, rest] = splitPair(value, label);
		if (pairs.has(key)) fail(`${label} repeats platform ${key}`);
		pairs.set(key, rest);
	}
	return pairs;
}

/** The format a platform's installer file is published as (by extension), or null. */
function installerFormat(platform, file) {
	const lower = file.toLowerCase();
	return FORMATS[platform.split("-")[0]]?.find((format) => lower.endsWith(`.${format}`)) ?? null;
}

function selectionKey(platform, format) {
	return `${platform}\u0000${format}`;
}

/** Explicit `--installer <platform>=<bundle path>` choices; any number of formats per platform. */
function explicitSelection(values) {
	const selection = new Map();
	for (const value of values ?? []) {
		const [platform, artifactPath] = splitPair(value, "--installer");
		const format = installerFormat(platform, path.posix.basename(artifactPath));
		if (!format) {
			fail(`--installer ${artifactPath} is not a ${platform} installer (allowed: ${FORMATS[platform.split("-")[0]].map((entry) => `.${entry}`).join(", ")})`);
		}
		if (selection.has(selectionKey(platform, format))) fail(`--installer repeats the .${format} installer for ${platform}`);
		selection.set(selectionKey(platform, format), { platform, format, artifactPath });
	}
	return selection;
}

/** Every signed `installers/<platform>/<file>` whose extension is a format of that platform. */
function conventionSelection(artifactPaths) {
	const selection = new Map();
	const skipped = [];
	for (const artifactPath of artifactPaths) {
		const match = CONVENTION_RE.exec(artifactPath);
		if (!match) continue;
		const [, platform, file] = match;
		if (!PLATFORMS.includes(platform)) fail(`signed installer ${artifactPath} uses an unknown platform directory`);
		const format = installerFormat(platform, file);
		if (!format) {
			skipped.push(artifactPath);
			continue;
		}
		if (selection.has(selectionKey(platform, format))) {
			fail(`more than one signed .${format} installer for ${platform}; pass --installer explicitly`);
		}
		selection.set(selectionKey(platform, format), { platform, format, artifactPath });
	}
	if (selection.size === 0) fail("the signed release contains no installers/<platform>/<file> artifacts; pass --installer");
	return { selection, skipped };
}

/** Platform order, then the platform's format order. */
function selectionOrder(left, right) {
	const formats = FORMATS[left.platform.split("-")[0]];
	return PLATFORMS.indexOf(left.platform) - PLATFORMS.indexOf(right.platform) ||
		formats.indexOf(left.format) - formats.indexOf(right.format);
}

function httpsUrl(value, label) {
	if (value === undefined || value === null || value === "") return null;
	let url;
	try {
		url = new URL(value);
	} catch {
		fail(`${label} is not a URL`);
	}
	if (url.protocol !== "https:" || url.username || url.password) fail(`${label} must be an https URL without credentials`);
	return url.toString();
}

/** Ed25519 signature envelope over exact bytes (release-signing-lib format). */
export function verifyEnvelope(raw, envelope, publicKey) {
	if (
		!envelope ||
		envelope.schema_version !== 1 ||
		envelope.algorithm !== "Ed25519" ||
		typeof envelope.signature_b64 !== "string"
	) return false;
	const signature = Buffer.from(envelope.signature_b64, "base64");
	return signature.byteLength === 64 && cryptoVerify(null, raw, publicKey, signature);
}

/**
 * Verify the signed release and assemble every object of the installer storage
 * contract in memory. Returns { version, objects: [{ path, bytes, contentType, immutable }], catalog, ... }.
 */
export async function buildInstallerRelease(options) {
	const now = options.now ?? new Date();
	if (!options.bundle || !options.policy) fail("--bundle and --policy are required");
	const bundle = await loadReleaseBundle(options.bundle, { allowSignedControlFiles: true });
	const policy = await loadSignerPolicy(options.policy, bundle.bundle);
	const manifestRaw = (await readJsonFile(path.join(bundle.bundle, RELEASE_MANIFEST_NAME), "release manifest")).raw;
	const signatureRecord = await readJsonFile(path.join(bundle.bundle, RELEASE_SIGNATURE_NAME), "release signature");
	const releaseManifest = JSON.parse(manifestRaw.toString("utf8"));
	const validated = validateReleaseManifest(releaseManifest, bundle, policy, now);
	verifyManifestSignature(manifestRaw, signatureRecord.value, validated);

	const version = releaseManifest.release_version;
	if (!INSTALLER_VERSION_RE.test(version)) fail(`release version ${version} is not a publishable installer version`);
	const signedArtifacts = new Map(releaseManifest.artifacts.map((artifact) => [artifact.path, artifact]));

	let selection = explicitSelection(options.installers);
	let skipped = [];
	if (selection.size === 0) ({ selection, skipped } = conventionSelection(signedArtifacts.keys()));
	const selected = [...selection.values()].sort(selectionOrder);
	const minimumOs = parsePairs(options.minOs, "--min-os");

	const sumsPath = options.sha256sums ?? path.join(bundle.bundle, "SHA256SUMS");
	let sumsText;
	try {
		const info = await lstat(sumsPath);
		if (!info.isFile()) fail("SHA256SUMS must be a regular file");
		sumsText = await readFile(sumsPath, "utf8");
	} catch (error) {
		if (error instanceof PublishError) throw error;
		fail(`SHA256SUMS is required (${sumsPath}): ${error instanceof Error ? error.message : String(error)}`);
	}
	const sums = parseSha256Sums(sumsText);

	const objects = [];
	const files = [];
	const seenNames = new Set();
	for (const { platform, format, artifactPath } of selected) {
		const signed = signedArtifacts.get(artifactPath);
		if (!signed) fail(`installer ${artifactPath} is not an artifact of the signed release manifest`);
		const file = path.posix.basename(artifactPath);
		if (!FILE_NAME_RE.test(file)) fail(`installer file name ${file} is not portable`);
		if (seenNames.has(file)) fail(`installer file name ${file} is used by more than one installer`);
		seenNames.add(file);
		const listed = sums.get(artifactPath) ?? sums.get(file);
		if (!listed) fail(`SHA256SUMS has no entry for ${artifactPath}`);
		if (listed !== signed.sha256) fail(`SHA256SUMS digest for ${artifactPath} does not match the signed release manifest`);
		// Hash the exact bytes that will be uploaded (no re-read between check and upload).
		const bytes = await readFile(path.join(bundle.bundle, ...artifactPath.split("/")));
		if (sha256(bytes) !== signed.sha256 || bytes.byteLength !== signed.size) {
			fail(`installer ${artifactPath} changed after release verification`);
		}
		const [osName, arch] = platform.split("-");
		const objectPath = `${version}/${platform}/${file}`;
		files.push({
			platform,
			os: osName,
			arch,
			file,
			path: objectPath,
			size: bytes.byteLength,
			sha256: signed.sha256,
			minimum_os: minimumOs.get(platform) ?? DEFAULT_MINIMUM_OS[osName],
			format,
		});
		objects.push({ path: objectPath, bytes, contentType: "application/octet-stream", immutable: true });
	}

	const signatureRaw = signatureRecord.raw;
	const publishedAt = now.toISOString();
	const singleFormat = new Set(files.map((entry) => entry.platform)).size === files.length;
	const catalog = {
		schema_version: singleFormat ? SINGLE_FORMAT_SCHEMA : MULTI_FORMAT_SCHEMA,
		type: CATALOG_TYPE,
		product_id: releaseManifest.product_id,
		channel: releaseManifest.channel,
		version,
		published_at: publishedAt,
		release_notes_url: httpsUrl(options.releaseNotesUrl, "--release-notes-url"),
		release: {
			tag: releaseManifest.release_tag,
			git_sha: releaseManifest.git_sha,
			release_sequence: releaseManifest.release_sequence,
			manifest_path: `${version}/release/${RELEASE_MANIFEST_NAME}`,
			manifest_sha256: sha256(manifestRaw),
			signature_sha256: sha256(signatureRaw),
			signer_key_id: validated.keyId,
			signer_fingerprint: validated.fingerprint,
		},
		files,
	};
	const sumsOut = Buffer.from(files.map((entry) => `${entry.sha256}  ${entry.platform}/${entry.file}\n`).join(""), "utf8");
	objects.push(
		{ path: `${version}/SHA256SUMS`, bytes: sumsOut, contentType: "text/plain; charset=utf-8", immutable: true },
		{ path: catalog.release.manifest_path, bytes: manifestRaw, contentType: "application/json", immutable: true },
		{ path: `${version}/release/${RELEASE_SIGNATURE_NAME}`, bytes: signatureRaw, contentType: "application/json", immutable: true },
	);
	const catalogRaw = Buffer.from(`${JSON.stringify(catalog, null, 2)}\n`, "utf8");
	const latest = {
		schema_version: 1,
		type: LATEST_TYPE,
		product_id: catalog.product_id,
		version,
		release_sequence: catalog.release.release_sequence,
		manifest_path: `${version}/manifest.json`,
		manifest_sha256: sha256(catalogRaw),
		published_at: publishedAt,
	};
	const latestRaw = Buffer.from(`${JSON.stringify(latest, null, 2)}\n`, "utf8");

	let signing = null;
	if (options.signingKey) {
		if (!KEY_ID_RE.test(String(options.keyId ?? ""))) fail("installer catalog key id is missing or invalid");
		signing = await loadEd25519PrivateKey(options.signingKey, bundle.bundle);
	} else if (!options.dryRun) {
		fail("installer catalog signing key is required to publish (AIDR_INSTALLER_MANIFEST_SIGNING_KEY_PATH); nothing is published unsigned");
	}
	const envelope = (raw) => Buffer.from(`${JSON.stringify(signReleaseManifest(raw, signing.privateKey, options.keyId), null, 2)}\n`, "utf8");
	objects.push({ path: latest.manifest_path, bytes: catalogRaw, contentType: "application/json", immutable: true });
	if (signing) objects.push({ path: `${latest.manifest_path}.sig`, bytes: envelope(catalogRaw), contentType: "application/json", immutable: true });
	objects.push({ path: "latest.json", bytes: latestRaw, contentType: "application/json", immutable: false });
	if (signing) objects.push({ path: "latest.json.sig", bytes: envelope(latestRaw), contentType: "application/json", immutable: false });

	return {
		version,
		skipped,
		signed: Boolean(signing),
		signerFingerprint: signing?.fingerprint ?? null,
		catalog,
		latest,
		objects,
	};
}

function storageObjectUrl(base, bucket, objectPath, mode = "") {
	const encoded = objectPath.split("/").map(encodeURIComponent).join("/");
	return `${base}/storage/v1/object/${mode}${encodeURIComponent(bucket)}/${encoded}`;
}

function resolveUploadTarget(env) {
	const rawUrl = String(env.SUPABASE_URL ?? "").trim();
	const key = String(env.SUPABASE_SERVICE_ROLE_KEY ?? "").trim();
	const bucket = String(env.AIDR_INSTALLERS_BUCKET ?? DEFAULT_INSTALLERS_BUCKET).trim();
	if (!rawUrl || !key) fail("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required to publish");
	let url;
	try {
		url = new URL(rawUrl);
	} catch {
		fail("SUPABASE_URL is not a URL");
	}
	const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
	if (url.username || url.password || (url.protocol !== "https:" && !(loopback && url.protocol === "http:"))) {
		fail("SUPABASE_URL must be https (http only for loopback) and carry no credentials");
	}
	if (!BUCKET_RE.test(bucket)) fail("AIDR_INSTALLERS_BUCKET is not a valid bucket name");
	return { base: url.origin + url.pathname.replace(/\/+$/, ""), key, bucket };
}

async function fetchExisting(target, objectPath, fetchImpl) {
	const response = await fetchImpl(storageObjectUrl(target.base, target.bucket, objectPath, "authenticated/"), {
		method: "GET",
		headers: { Authorization: `Bearer ${target.key}`, apikey: target.key },
	});
	if (response.status === 404 || response.status === 400) return null;
	if (!response.ok) fail(`reading ${objectPath} failed with HTTP ${response.status}`);
	return Buffer.from(await response.arrayBuffer());
}

async function putObject(target, object, fetchImpl) {
	const response = await fetchImpl(storageObjectUrl(target.base, target.bucket, object.path), {
		method: "POST",
		headers: {
			Authorization: `Bearer ${target.key}`,
			apikey: target.key,
			"Content-Type": object.contentType,
			"Cache-Control": object.immutable ? "max-age=31536000, immutable" : "no-cache",
			"x-upsert": object.immutable ? "false" : "true",
		},
		body: object.bytes,
	});
	if (response.ok) return "uploaded";
	const text = await response.text().catch(() => "");
	const duplicate = response.status === 409 || (response.status === 400 && /duplicate|already exists/i.test(text));
	if (!object.immutable || !duplicate) fail(`uploading ${object.path} failed with HTTP ${response.status}`);
	const existing = await fetchExisting(target, object.path, fetchImpl);
	if (!existing || sha256(existing) !== sha256(object.bytes)) {
		fail(`${object.path} already exists with different bytes; published versions are immutable`);
	}
	return "unchanged";
}

/** Upload the assembled release; latest.json moves only forward and only last. */
export async function uploadInstallerRelease(release, env, fetchImpl = fetch, { allowDowngrade = false } = {}) {
	if (!release.signed) fail("refusing to upload an unsigned installer catalog");
	const target = resolveUploadTarget(env);
	const current = await fetchExisting(target, "latest.json", fetchImpl);
	if (current) {
		let pointer = null;
		try {
			pointer = JSON.parse(current.toString("utf8"));
		} catch {
			fail("the current latest.json is not JSON; repair the bucket before publishing");
		}
		const currentSequence = Number(pointer?.release_sequence);
		if (!Number.isSafeInteger(currentSequence)) fail("the current latest.json has no release_sequence");
		if (currentSequence > release.latest.release_sequence && !allowDowngrade) {
			fail(`latest.json points at release sequence ${currentSequence}; refusing to move it back to ${release.latest.release_sequence}`);
		}
	}
	const results = [];
	for (const object of release.objects) {
		results.push({ path: object.path, result: await putObject(target, object, fetchImpl) });
	}
	return { bucket: target.bucket, results };
}

export async function stageInstallerRelease(release, outDir) {
	for (const object of release.objects) {
		const destination = path.join(outDir, ...object.path.split("/"));
		await mkdir(path.dirname(destination), { recursive: true });
		await writeFile(destination, object.bytes, { flag: "wx" });
	}
}

/** Derive the public key a published catalog verifies with (for operators and tests). */
export function publicKeyB64FromPrivatePem(pem) {
	return createPublicKey(createPrivateKey(pem)).export({ type: "spki", format: "der" }).toString("base64");
}

function parseArguments(argv) {
	const options = { installers: [], minOs: [] };
	const valued = new Map([
		["--bundle", "bundle"],
		["--policy", "policy"],
		["--sha256sums", "sha256sums"],
		["--release-notes-url", "releaseNotesUrl"],
		["--signing-key", "signingKey"],
		["--key-id", "keyId"],
		["--out", "out"],
	]);
	for (let index = 0; index < argv.length; index += 1) {
		const flag = argv[index];
		if (flag === "--dry-run") options.dryRun = true;
		else if (flag === "--allow-downgrade") options.allowDowngrade = true;
		else if (flag === "--installer" || flag === "--min-os") {
			const value = argv[++index];
			if (!value) fail(`missing value for ${flag}`);
			(flag === "--installer" ? options.installers : options.minOs).push(value);
		} else if (valued.has(flag)) {
			const key = valued.get(flag);
			const value = argv[++index];
			if (!value || value.startsWith("--")) fail(`missing value for ${flag}`);
			if (options[key] !== undefined) fail(`duplicate option: ${flag}`);
			options[key] = value;
		} else fail(`unknown option: ${flag}`);
	}
	return options;
}

async function main() {
	const options = parseArguments(process.argv.slice(2));
	options.signingKey ??= process.env.AIDR_INSTALLER_MANIFEST_SIGNING_KEY_PATH || undefined;
	options.keyId ??= process.env.AIDR_INSTALLER_MANIFEST_KEY_ID || undefined;
	const release = await buildInstallerRelease(options);
	const summary = {
		version: release.version,
		signed: release.signed,
		signer_fingerprint: release.signerFingerprint,
		release_sequence: release.latest.release_sequence,
		catalog_schema_version: release.catalog.schema_version,
		files: release.catalog.files.map(({ platform, format, file, size, sha256: digest }) => ({ platform, format, file, size, sha256: digest })),
		// Signed files under installers/<platform>/ whose extension is not a published format.
		skipped: release.skipped,
	};
	if (options.dryRun) {
		const outDir = options.out ?? (await mkdtemp(path.join(os.tmpdir(), "aidr-installers-")));
		await stageInstallerRelease(release, outDir);
		console.log(JSON.stringify({ status: "dry-run", out: outDir, ...summary }, null, 2));
		return;
	}
	if (options.out) await stageInstallerRelease(release, options.out);
	const uploaded = await uploadInstallerRelease(release, process.env, fetch, { allowDowngrade: options.allowDowngrade });
	console.log(JSON.stringify({ status: "published", bucket: uploaded.bucket, ...summary, objects: uploaded.results }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	main().catch((error) => {
		console.error(`Installer publication failed: ${error instanceof Error ? error.message : String(error)}`);
		process.exit(1);
	});
}
