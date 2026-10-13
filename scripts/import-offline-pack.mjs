#!/usr/bin/env node
/**
 * Import a vendor-signed intel pack into an air-gapped installation.
 *
 * Input is either the signed pack directory produced by the vendor release
 * tooling (`manifest.json`, the `manifest.sig` written by
 * `scripts/sign-intel-pack-manifest.mjs`, and every file the manifest lists) or
 * a single-file `aidr-intel-pack-bundle-v1` JSON that carries those exact bytes
 * for transfer on removable media (`--export-bundle` writes one).
 *
 * Verification happens before anything is written, and it is the same contract
 * the endpoint loader enforces (`packages/core/src/intel/loader.ts`): the manifest
 * must match the core `IntelPackManifestSchema`, its exact bytes must carry a
 * valid Ed25519 signature from a key in the operator's trusted-keys file
 * (`{ "<key_id>": "<public PEM>" }`, the core loader format), every listed file
 * must be present with a matching SHA-256 (ciphertext SHA-256 for encrypted
 * files), unlisted files and unsafe paths are refused, an expired pack is
 * refused and a version older than the installed one is refused (rollback).
 *
 * License-bound updates: before a pack is installed or registered it must pass
 * the core `acceptPack` (packages/core/src/intel/acceptance.ts) against the
 * customer's license: a pack issued after the license's expires_at + grace_days
 * is refused, and a pack with a customer audience needs a license whose
 * customer_id is listed. `--license <file>` names the license (verified against
 * the registry embedded in the core build, or `--license-public-keys <file>`);
 * the local target uses the endpoint's applied license
 * (`~/.singularity-aidr/license.json`) when no `--license` is given and one is
 * installed. Only signed times are compared. Packs already installed keep
 * enforcing whatever the license state.
 *
 * Targets:
 *   --target local    install into a packs directory (`<packs>/<pack_id>/<version>/`)
 *                     and activate it, the layout the endpoint loader reads.
 *   --target storage  upload the verified bundle to the private `aidr-packs`
 *                     bucket of a self-hosted deployment (migration
 *                     20260924000013) and register it in `pack_versions`, so the
 *                     authenticated `packs-manifest` / `packs-download` functions
 *                     serve it to entitled tenants. Encrypted files must use
 *                     a key every tenant served the row holds: a shared pack
 *                     key ("aidr-shared-pack-*") for a shared row, or that
 *                     tenant's derived key for a --tenant-id row
 *                     (scripts/intel-pack-keys.mjs).
 *
 * Nothing here contacts the vendor or the internet.
 */
import { createHash, randomUUID } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { packKeyScope } from "./intel-pack-keys.mjs";

export const BUNDLE_FORMAT = "aidr-intel-pack-bundle-v1";
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_FILES = 256;
const RESERVED = new Set(["manifest.json", "manifest.sig"]);
const VERSION_FLOOR_NAME = ".trusted-version-floor.json";

export class PackImportError extends Error {
	constructor(message) {
		super(message);
		this.name = "PackImportError";
	}
}

/** Core verification primitives, loaded from the built core (bundled into the customer kit). */
async function loadCore() {
	try {
		const [schema, verify, semver, loader, acceptance, license] = await Promise.all([
			import("../packages/core/dist/intel/schema.js"),
			import("../packages/core/dist/intel/verify.js"),
			import("../packages/core/dist/intel/semver.js"),
			import("../packages/core/dist/intel/loader.js"),
			import("../packages/core/dist/intel/acceptance.js"),
			import("../packages/core/dist/license/index.js"),
		]);
		return {
			IntelPackManifestSchema: schema.IntelPackManifestSchema,
			verifyEd25519Signature: verify.verifyEd25519Signature,
			compareSemver: semver.compareSemver,
			activatePackVersion: loader.activatePackVersion,
			acceptPack: acceptance.acceptPack,
			verifyLicense: license.verifyLicense,
			parseLicensePublicKeyRegistry: license.parseLicensePublicKeyRegistry,
			readSignedDocumentFile: license.readSignedDocumentFile,
		};
	} catch (error) {
		throw new PackImportError(`the core intel verifier is unavailable (${error?.code ?? error?.message}); run "pnpm -C packages/core build" or use the customer-kit copy of this script`);
	}
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function safeRelativePath(path) {
	if (typeof path !== "string" || !path || path.length > 512 || path.includes("\\") || path.includes("\0")) return false;
	const parts = path.split("/");
	return parts.every((part) => SEGMENT.test(part)) && !RESERVED.has(path);
}

function regularFile(path, label) {
	let stats;
	try {
		stats = lstatSync(path);
	} catch {
		throw new PackImportError(`${label} is missing`);
	}
	if (stats.isSymbolicLink() || !stats.isFile()) throw new PackImportError(`${label} must be a regular, non-symlink file`);
	if (stats.size > MAX_FILE_BYTES) throw new PackImportError(`${label} exceeds ${MAX_FILE_BYTES} bytes`);
	return readFileSync(path);
}

function listFiles(root, prefix = "") {
	const out = [];
	for (const entry of readdirSync(join(root, prefix), { withFileTypes: true })) {
		const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
		if (entry.isSymbolicLink()) throw new PackImportError(`pack contains a symlink: ${rel}`);
		if (entry.isDirectory()) out.push(...listFiles(root, rel));
		else if (entry.isFile()) out.push(rel);
		else throw new PackImportError(`pack contains a non-regular entry: ${rel}`);
		if (out.length > MAX_FILES + 2) throw new PackImportError(`pack has more than ${MAX_FILES} files`);
	}
	return out;
}

/** Read a pack directory or bundle into `{ manifestBytes, signatureBase64, files: Map<path, Buffer> }`. */
export function readPackSource(source) {
	const path = resolve(source);
	let stats;
	try {
		stats = lstatSync(path);
	} catch {
		throw new PackImportError(`pack source ${path} does not exist`);
	}
	if (stats.isSymbolicLink()) throw new PackImportError("pack source must not be a symlink");
	if (stats.isDirectory()) {
		const manifestBytes = regularFile(join(path, "manifest.json"), "manifest.json");
		const signatureBase64 = regularFile(join(path, "manifest.sig"), "manifest.sig").toString("utf8").trim();
		const files = new Map();
		for (const rel of listFiles(path)) {
			if (RESERVED.has(rel)) continue;
			files.set(rel, regularFile(join(path, ...rel.split("/")), rel));
		}
		return { manifestBytes, signatureBase64, files };
	}
	const raw = regularFile(path, "pack bundle");
	let bundle;
	try {
		bundle = JSON.parse(raw.toString("utf8"));
	} catch {
		throw new PackImportError("pack bundle is not JSON");
	}
	if (!bundle || bundle.format !== BUNDLE_FORMAT || typeof bundle.manifest_b64 !== "string" || typeof bundle.manifest_sig_b64 !== "string" || !Array.isArray(bundle.files)) {
		throw new PackImportError(`pack bundle must be an ${BUNDLE_FORMAT} document`);
	}
	const files = new Map();
	for (const file of bundle.files) {
		if (!file || typeof file.path !== "string" || typeof file.content_b64 !== "string") throw new PackImportError("pack bundle file entries need path and content_b64");
		if (files.has(file.path)) throw new PackImportError(`pack bundle repeats ${file.path}`);
		files.set(file.path, Buffer.from(file.content_b64, "base64"));
	}
	return { manifestBytes: Buffer.from(bundle.manifest_b64, "base64"), signatureBase64: bundle.manifest_sig_b64.trim(), files };
}

/** Parse the core trusted-keys file (`{ key_id: public PEM }`). */
export function loadTrustedKeys(path) {
	const raw = regularFile(resolve(path), "trusted-keys file");
	let parsed;
	try {
		parsed = JSON.parse(raw.toString("utf8"));
	} catch {
		throw new PackImportError("trusted-keys file is not JSON");
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new PackImportError("trusted-keys file must map key ids to public PEM keys");
	const keys = new Map();
	for (const [keyId, pem] of Object.entries(parsed)) {
		if (typeof pem === "string" && keyId.trim() && pem.includes("PUBLIC KEY")) keys.set(keyId.trim(), pem);
	}
	if (keys.size === 0) throw new PackImportError("trusted-keys file contains no public keys; nothing can be verified");
	return keys;
}

/**
 * Verify a pack completely. Returns the parsed manifest and digests; throws a
 * PackImportError for any failure. No filesystem writes.
 */
export async function verifyOfflinePack(pack, { trustedKeys, revokedKeyIds = [], now = Date.now(), core } = {}) {
	const lib = core ?? (await loadCore());
	let manifestJson;
	try {
		manifestJson = JSON.parse(pack.manifestBytes.toString("utf8"));
	} catch {
		throw new PackImportError("manifest.json is not JSON");
	}
	const parsed = lib.IntelPackManifestSchema.safeParse(manifestJson);
	if (!parsed.success) throw new PackImportError("manifest.json does not match the intel pack manifest schema");
	const manifest = parsed.data;
	if (!SEGMENT.test(manifest.pack_id) || !SEGMENT.test(manifest.version)) throw new PackImportError("pack_id and version must be single path-safe segments");
	if (!Number.isFinite(Date.parse(manifest.issued_at))) throw new PackImportError("manifest issued_at is not a timestamp");

	const publicKeyPem = trustedKeys.get(manifest.key_id);
	if (!publicKeyPem) throw new PackImportError(`manifest key ${manifest.key_id} is not in the trusted-keys file`);
	if (revokedKeyIds.includes(manifest.key_id)) throw new PackImportError(`manifest key ${manifest.key_id} is revoked`);
	if (!lib.verifyEd25519Signature({ publicKeyPem, message: pack.manifestBytes, signatureBase64: pack.signatureBase64 })) {
		throw new PackImportError("manifest signature does not verify; the pack was altered or signed by another key");
	}
	if (manifest.expires_at !== undefined) {
		const expiresAt = Date.parse(manifest.expires_at);
		if (!Number.isFinite(expiresAt)) throw new PackImportError("manifest expires_at is not a timestamp");
		if (expiresAt <= now) throw new PackImportError(`pack ${manifest.pack_id}@${manifest.version} expired at ${manifest.expires_at}`);
	}

	if (manifest.files.length > MAX_FILES) throw new PackImportError(`pack lists more than ${MAX_FILES} files`);
	const listed = new Set();
	let total = 0;
	for (const file of manifest.files) {
		if (!safeRelativePath(file.path)) throw new PackImportError(`manifest lists an unsafe path: ${JSON.stringify(file.path)}`);
		if (listed.has(file.path)) throw new PackImportError(`manifest lists ${file.path} twice`);
		listed.add(file.path);
		const bytes = pack.files.get(file.path);
		if (!bytes) throw new PackImportError(`listed file ${file.path} is missing`);
		total += bytes.length;
		if (bytes.length > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES) throw new PackImportError("pack exceeds the size limit");
		if (file.encrypted) {
			if (file.cipher !== "aes-256-gcm" || !file.key_id || !file.ciphertext_sha256) {
				throw new PackImportError(`encrypted file ${file.path} needs cipher aes-256-gcm, key_id and ciphertext_sha256`);
			}
			if (sha256(bytes) !== file.ciphertext_sha256.toLowerCase()) throw new PackImportError(`ciphertext SHA-256 mismatch for ${file.path}`);
		} else {
			if (!file.sha256) throw new PackImportError(`file ${file.path} has no sha256`);
			if (sha256(bytes) !== file.sha256.toLowerCase()) throw new PackImportError(`SHA-256 mismatch for ${file.path}`);
		}
	}
	const unlisted = [...pack.files.keys()].filter((path) => !listed.has(path));
	if (unlisted.length) throw new PackImportError(`pack carries unlisted file(s): ${unlisted.join(", ")}`);
	return {
		manifest,
		manifestSha256: sha256(pack.manifestBytes),
		files: manifest.files.map((file) => file.path),
		bytes: total,
	};
}

/**
 * Read and verify a license file (fail closed). `publicKeysPath` overrides the
 * registry embedded in the core build. An expired license still verifies; what
 * it may still receive is decided by `assertPackAccepted`.
 */
export async function loadLicense(path, { publicKeysPath, now = Date.now(), core } = {}) {
	const lib = core ?? (await loadCore());
	try {
		const document = lib.readSignedDocumentFile(resolve(path), "license file");
		const registry = publicKeysPath === undefined ? undefined : lib.parseLicensePublicKeyRegistry(lib.readSignedDocumentFile(resolve(publicKeysPath), "license public-key registry"));
		return lib.verifyLicense(document, { registry, now });
	} catch (error) {
		throw new PackImportError(`license ${resolve(path)} is not valid: ${error instanceof Error ? error.message : "verification failed"}`);
	}
}

/** Refuse a pack the license does not entitle (core acceptPack; signed times only). */
export function assertPackAccepted(manifest, license, lib) {
	const decision = lib.acceptPack(manifest, license ?? null);
	if (!decision.accepted) throw new PackImportError(`${decision.code}: ${decision.message}`);
}

/** Serialize a (verified) pack into the single-file transfer bundle. */
export function createBundle(pack, manifest) {
	return Buffer.from(`${JSON.stringify({
		format: BUNDLE_FORMAT,
		pack_id: manifest.pack_id,
		version: manifest.version,
		manifest_b64: pack.manifestBytes.toString("base64"),
		manifest_sig_b64: pack.signatureBase64,
		files: manifest.files.map((file) => ({ path: file.path, content_b64: pack.files.get(file.path).toString("base64") })),
	}, null, 2)}\n`, "utf8");
}

function readVersionFloor(packsDir, packId) {
	const path = join(dirname(packsDir), VERSION_FLOOR_NAME);
	if (!existsSync(path)) return null;
	try {
		return JSON.parse(readFileSync(path, "utf8"))?.packs?.[packId]?.version ?? null;
	} catch {
		throw new PackImportError(`intel version floor ${path} is unreadable; refusing to guess the installed version`);
	}
}

function readActiveVersion(packRoot) {
	const path = join(packRoot, "active.json");
	if (!existsSync(path)) return null;
	try {
		return JSON.parse(readFileSync(path, "utf8")).version ?? null;
	} catch {
		throw new PackImportError(`${path} is unreadable`);
	}
}

/** Install a verified pack into `<packsDir>/<pack_id>/<version>/` and activate it. */
export async function installLocal(pack, verified, { packsDir, trustedKeys, license = null, now = Date.now(), core } = {}) {
	const lib = core ?? (await loadCore());
	const { manifest } = verified;
	assertPackAccepted(manifest, license, lib);
	const root = resolve(packsDir);
	const packRoot = join(root, manifest.pack_id);
	const target = join(packRoot, manifest.version);
	for (const installed of [readVersionFloor(root, manifest.pack_id), readActiveVersion(packRoot)]) {
		if (installed && lib.compareSemver(manifest.version, installed) < 0) {
			throw new PackImportError(`pack ${manifest.pack_id}@${manifest.version} is older than installed ${installed}; rollback refused`);
		}
	}
	if (existsSync(target)) {
		const existing = readPackSource(target);
		if (sha256(existing.manifestBytes) !== verified.manifestSha256) {
			throw new PackImportError(`a different ${manifest.pack_id}@${manifest.version} is already installed; version equivocation refused`);
		}
		await verifyOfflinePack(existing, { trustedKeys, now, core: lib });
		await lib.activatePackVersion({ packId: manifest.pack_id, version: manifest.version, packsDir: root });
		return { outcome: "already_installed", path: target };
	}
	mkdirSync(packRoot, { recursive: true, mode: 0o755 });
	const staging = join(packRoot, `.staging-${randomUUID()}`);
	try {
		mkdirSync(staging, { mode: 0o755 });
		writeFileSync(join(staging, "manifest.json"), pack.manifestBytes, { flag: "wx", mode: 0o644 });
		writeFileSync(join(staging, "manifest.sig"), `${pack.signatureBase64}\n`, { flag: "wx", mode: 0o644 });
		for (const file of manifest.files) {
			const destination = join(staging, ...file.path.split("/"));
			if (!destination.startsWith(`${staging}${sep}`) || relative(staging, destination).startsWith("..")) throw new PackImportError(`unsafe path ${file.path}`);
			mkdirSync(dirname(destination), { recursive: true, mode: 0o755 });
			writeFileSync(destination, pack.files.get(file.path), { flag: "wx", mode: 0o644 });
		}
		// Re-read what landed on disk and verify it again before it becomes visible.
		await verifyOfflinePack(readPackSource(staging), { trustedKeys, now, core: lib });
		renameSync(staging, target);
	} catch (error) {
		rmSync(staging, { recursive: true, force: true });
		throw error;
	}
	await lib.activatePackVersion({ packId: manifest.pack_id, version: manifest.version, packsDir: root });
	return { outcome: "installed", path: target };
}

function readDeployment(deploymentDir) {
	const dir = resolve(deploymentDir);
	const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
	if (manifest.mode !== "self-hosted") throw new PackImportError("storage import is only supported for self-hosted deployments");
	const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line)).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
	const base = new URL(manifest.supabase_url);
	if (base.protocol !== "https:" && !(manifest.development && ["localhost", "127.0.0.1"].includes(base.hostname))) throw new PackImportError("HTTPS required");
	if (!env.SERVICE_ROLE_KEY || env.SERVICE_ROLE_KEY.startsWith("REPLACE_")) throw new PackImportError("configure the deployment's service-role credential first");
	return { base, env };
}

/**
 * Refuse a registration whose encrypted files no tenant it is served to could
 * decrypt: a shared row (tenant_id IS NULL) reaches every premium tenant, so it
 * needs a shared pack key; a tenant row may use a shared key or that tenant's
 * own derived key. Unknown key ids (e.g. the retired per-tenant "aidr-pack-v1",
 * which named a different key on every tenant) are not deliverable.
 */
export function assertDeliverablePackKeys(manifest, tenantId = null) {
	for (const file of manifest.files) {
		if (!file.encrypted) continue;
		const scope = packKeyScope(file.key_id);
		const ok = scope && (scope.kind === "shared" || (tenantId !== null && scope.tenantId.toLowerCase() === tenantId.toLowerCase()));
		if (!ok) {
			throw new PackImportError(`${file.path} is encrypted with key ${JSON.stringify(file.key_id)}, which ${tenantId ? `tenant ${tenantId}` : "the tenants a shared pack is served to"} cannot hold; use a shared pack key${tenantId ? " or this tenant's pack key" : ""} (scripts/intel-pack-keys.mjs)`);
		}
	}
}

/**
 * Upload the verified bundle to the private `aidr-packs` bucket and register it
 * in `pack_versions`. Re-running after an interruption is safe: an identical
 * object or row is accepted, a different one is refused.
 */
export async function installStorage(pack, verified, { deploymentDir, tenantId = null, bucket = "aidr-packs", license = null, core } = {}) {
	const lib = core ?? (await loadCore());
	assertPackAccepted(verified.manifest, license, lib);
	if (tenantId !== null && !UUID.test(tenantId)) throw new PackImportError("--tenant-id must be a UUID");
	assertDeliverablePackKeys(verified.manifest, tenantId);
	const { base, env } = readDeployment(deploymentDir);
	const { manifest } = verified;
	const headers = { apikey: env.ANON_KEY ?? "", Authorization: `Bearer ${env.SERVICE_ROLE_KEY}` };
	const call = async (path, init = {}) => {
		const response = await fetch(new URL(path, base), { ...init, headers: { ...headers, ...(init.headers ?? {}) }, signal: AbortSignal.timeout(60_000) });
		return response;
	};
	const scope = tenantId ? `tenant_id=eq.${tenantId}` : "tenant_id=is.null";
	const existingResponse = await call(`/rest/v1/pack_versions?pack_id=eq.${encodeURIComponent(manifest.pack_id)}&${scope}&select=version,manifest_sig_b64,storage_path`);
	if (!existingResponse.ok) throw new PackImportError(`pack_versions lookup failed (HTTP ${existingResponse.status})`);
	const existingRows = await existingResponse.json();
	const sameVersion = existingRows.find((row) => row.version === manifest.version);
	if (sameVersion) {
		if (sameVersion.manifest_sig_b64 !== pack.signatureBase64) throw new PackImportError(`a different ${manifest.pack_id}@${manifest.version} is already registered; version equivocation refused`);
		return { outcome: "already_registered", storage_path: sameVersion.storage_path };
	}
	const newer = existingRows.find((row) => lib.compareSemver(row.version, manifest.version) > 0);
	if (newer) throw new PackImportError(`pack ${manifest.pack_id}@${manifest.version} is older than registered ${newer.version}; rollback refused`);

	const storagePath = `${tenantId ?? "shared"}/${manifest.pack_id}/${manifest.version}.aidrpack.json`;
	const objectPath = `/storage/v1/object/${bucket}/${storagePath}`;
	const bundle = createBundle(pack, manifest);
	const uploaded = await call(objectPath, { method: "POST", body: bundle, headers: { "Content-Type": "application/json", "x-upsert": "false" } });
	if (uploaded.status === 409 || uploaded.status === 400) {
		// An interrupted earlier run may have uploaded the object; accept only identical bytes.
		const current = await call(`/storage/v1/object/authenticated/${bucket}/${storagePath}`);
		const bytes = current.ok ? Buffer.from(await current.arrayBuffer()) : null;
		if (!bytes || sha256(bytes) !== sha256(bundle)) {
			throw new PackImportError(`private pack upload was refused (HTTP ${uploaded.status}) and no identical object exists at ${storagePath}`);
		}
	} else if (uploaded.status !== 200 && uploaded.status !== 201) {
		throw new PackImportError(`private pack upload failed (HTTP ${uploaded.status})`);
	}
	const row = {
		pack_id: manifest.pack_id,
		version: manifest.version,
		tenant_id: tenantId,
		storage_path: storagePath,
		manifest_json: JSON.parse(pack.manifestBytes.toString("utf8")),
		manifest_sig_b64: pack.signatureBase64,
		key_id: manifest.key_id,
		issued_at: manifest.issued_at,
		expires_at: manifest.expires_at ?? null,
	};
	const registered = await call("/rest/v1/pack_versions", { method: "POST", body: JSON.stringify(row), headers: { "Content-Type": "application/json", Prefer: "return=minimal" } });
	if (registered.status !== 201 && registered.status !== 204) {
		throw new PackImportError(`pack uploaded to ${storagePath} but pack_versions registration failed (HTTP ${registered.status}); re-run the same import to finish`);
	}
	return { outcome: "registered", storage_path: storagePath, bucket };
}

const USAGE = `Usage:
  node scripts/import-offline-pack.mjs --pack <pack-dir|bundle.json> --trusted-keys <trusted-keys.json> --target local [--packs-dir <dir>] [--license <license.json>]
  node scripts/import-offline-pack.mjs --pack <pack-dir|bundle.json> --trusted-keys <trusted-keys.json> --target storage --deployment <dir> [--tenant-id <uuid>] [--license <license.json>]
  (--license-public-keys <registry.json> overrides the license registry embedded in the core build)
  node scripts/import-offline-pack.mjs --pack <pack-dir> --trusted-keys <trusted-keys.json> --export-bundle <out.json>`;

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) {
	try {
		const { values } = parseArgs({
			strict: true,
			options: {
				help: { type: "boolean", short: "h" },
				pack: { type: "string" },
				"trusted-keys": { type: "string" },
				target: { type: "string" },
				"packs-dir": { type: "string" },
				deployment: { type: "string" },
				"tenant-id": { type: "string" },
				"revoked-key-id": { type: "string", multiple: true },
				"export-bundle": { type: "string" },
				license: { type: "string" },
				"license-public-keys": { type: "string" },
			},
		});
		if (values.help) {
			console.log(USAGE);
			process.exit(0);
		}
		if (!values.pack || !values["trusted-keys"] || (!values.target && !values["export-bundle"])) throw new PackImportError(USAGE);
		const core = await loadCore();
		const trustedKeys = loadTrustedKeys(values["trusted-keys"]);
		const pack = readPackSource(values.pack);
		const verified = await verifyOfflinePack(pack, { trustedKeys, revokedKeyIds: values["revoked-key-id"] ?? [], core });
		const home = process.env.HOME?.trim() || homedir();
		const installedLicense = join(home, ".singularity-aidr", "license.json");
		const licensePath = values.license ?? (values.target === "local" && existsSync(installedLicense) ? installedLicense : undefined);
		const license = licensePath === undefined ? null : await loadLicense(licensePath, { publicKeysPath: values["license-public-keys"], core });
		const summary = {
			pack_id: verified.manifest.pack_id,
			version: verified.manifest.version,
			key_id: verified.manifest.key_id,
			manifest_sha256: verified.manifestSha256,
			files: verified.files.length,
			bytes: verified.bytes,
			...(license ? { license: { license_id: license.payload.license_id, customer_id: license.payload.customer_id ?? null, state: license.state, updates_until: license.updatesUntil } } : {}),
		};
		if (values["export-bundle"]) {
			writeFileSync(resolve(values["export-bundle"]), createBundle(pack, verified.manifest), { flag: "wx", mode: 0o644 });
			console.log(JSON.stringify({ outcome: "bundle_written", bundle: resolve(values["export-bundle"]), ...summary }));
		}
		if (values.target === "local") {
			const packsDir = values["packs-dir"] ?? join(home, ".singularity-aidr", "intel", "packs");
			const result = await installLocal(pack, verified, { packsDir, trustedKeys, license, core });
			console.log(JSON.stringify({ ...result, target: "local", ...summary }));
		} else if (values.target === "storage") {
			if (!values.deployment) throw new PackImportError("--target storage requires --deployment <dir>");
			const result = await installStorage(pack, verified, { deploymentDir: values.deployment, tenantId: values["tenant-id"] ?? null, license, core });
			console.log(JSON.stringify({ ...result, target: "storage", ...summary }));
		} else if (values.target !== undefined) {
			throw new PackImportError("--target must be local or storage");
		}
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : "offline pack import failed"}`);
		process.exitCode = 1;
	}
}
