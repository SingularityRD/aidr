import {
	createHash,
	createPrivateKey,
	createPublicKey,
	randomBytes,
	sign as cryptoSign,
	verify as cryptoVerify,
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
	access,
	lstat,
	mkdir,
	open,
	readFile,
	readdir,
	rename,
	unlink,
	writeFile,
} from "node:fs/promises";
import path from "node:path";

export const RELEASE_MANIFEST_NAME = "aidr-release.manifest.json";
export const RELEASE_SIGNATURE_NAME = "aidr-release.manifest.sig";
export const RELEASE_METADATA_NAME = "release-metadata.json";
export const RELEASE_INVENTORY_NAME = "release-inventory.json";

const SHA256_RE = /^[0-9a-f]{64}$/;
const KEY_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const PRODUCT_ID_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const CHANNEL_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const VERSION_RE = /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}$/;
const TAG_RE = /^[0-9A-Za-z][0-9A-Za-z._/-]{0,255}$/;
const PRIVATE_KEY_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const CONTROL_FILES = new Set([
	RELEASE_MANIFEST_NAME,
	RELEASE_SIGNATURE_NAME,
	RELEASE_METADATA_NAME,
	RELEASE_INVENTORY_NAME,
]);

export function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

export function normalizeFingerprint(value, label = "signer fingerprint") {
	const normalized = String(value ?? "")
		.toLowerCase()
		.replace(/^sha256:/, "");
	if (!SHA256_RE.test(normalized)) throw new Error(`${label} must be SHA-256 hex`);
	return `sha256:${normalized}`;
}

export function parseInstant(value, label) {
	if (typeof value !== "string") throw new Error(`${label} must be an ISO-8601 timestamp`);
	const instant = new Date(value);
	if (!Number.isFinite(instant.getTime()) || instant.toISOString() !== value) {
		throw new Error(`${label} must be a canonical ISO-8601 timestamp`);
	}
	return instant;
}

export function normalizeSafePath(value, label = "artifact path") {
	if (typeof value !== "string" || value.length === 0 || value.length > 512) {
		throw new Error(`${label} is invalid`);
	}
	if (value.includes("\\") || value.includes(":") || value.includes("\0") || path.posix.isAbsolute(value)) {
		throw new Error(`${label} is unsafe: ${value}`);
	}
	const segments = value.split("/");
	if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
		throw new Error(`${label} is unsafe: ${value}`);
	}
	if (!/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value)) {
		throw new Error(`${label} contains unsupported characters: ${value}`);
	}
	if (CONTROL_FILES.has(path.posix.basename(value))) {
		throw new Error(`${label} collides with a release control file: ${value}`);
	}
	return value;
}

export function parsePositiveInteger(value, label) {
	const number = Number(value);
	if (!Number.isSafeInteger(number) || number < 1) throw new Error(`${label} must be a positive safe integer`);
	return number;
}

export function assertKeyId(value) {
	if (!KEY_ID_RE.test(String(value ?? ""))) throw new Error("key id is invalid");
	return String(value);
}

export function assertProductId(value) {
	if (!PRODUCT_ID_RE.test(String(value ?? ""))) throw new Error("product id is invalid");
	return String(value);
}

export function assertChannel(value) {
	if (!CHANNEL_RE.test(String(value ?? ""))) throw new Error("release channel is invalid");
	return String(value);
}

export async function readJsonFile(filePath, label) {
	const info = await lstat(filePath);
	if (!info.isFile() || info.isSymbolicLink()) throw new Error(`${label} must be a regular file`);
	const raw = await readFile(filePath);
	let value;
	try {
		value = JSON.parse(raw.toString("utf8"));
	} catch {
		throw new Error(`${label} is not valid JSON`);
	}
	return { raw, value };
}

export async function loadReleaseBundle(bundlePath, { allowSignedControlFiles = false } = {}) {
	const bundle = path.resolve(bundlePath);
	const bundleInfo = await lstat(bundle);
	if (!bundleInfo.isDirectory() || bundleInfo.isSymbolicLink()) {
		throw new Error("release bundle must be a regular directory");
	}

	const metadataRecord = await readJsonFile(path.join(bundle, RELEASE_METADATA_NAME), "release metadata");
	const inventoryRecord = await readJsonFile(path.join(bundle, RELEASE_INVENTORY_NAME), "release inventory");
	const metadata = validateMetadata(metadataRecord.value);
	const inventory = validateInventory(inventoryRecord.value);
	const metadataByPath = new Map(metadata.artifacts.map((entry) => [entry.path, entry]));
	const inventoryByPath = new Map(inventory.artifacts.map((entry) => [entry.staged_path, entry]));

	if (metadataByPath.size !== inventoryByPath.size) {
		throw new Error("release metadata and inventory contain different artifact sets");
	}
	for (const [artifactPath, metadataEntry] of metadataByPath) {
		const inventoryEntry = inventoryByPath.get(artifactPath);
		if (!inventoryEntry || inventoryEntry.sha256 !== metadataEntry.sha256) {
			throw new Error(`release metadata and inventory disagree for ${artifactPath}`);
		}
	}

	const artifacts = [];
	for (const artifactPath of [...inventoryByPath.keys()].sort(compareStrings)) {
		const fullPath = resolveWithin(bundle, artifactPath);
		const info = await lstat(fullPath);
		if (!info.isFile() || info.isSymbolicLink()) throw new Error(`release artifact must be a regular file: ${artifactPath}`);
		if (/\.(?:pem|key|p12|pfx|jks|keystore)$/i.test(artifactPath)) {
			throw new Error(`key material cannot be a release artifact: ${artifactPath}`);
		}
		const bytes = await readFile(fullPath);
		if (!bytes.includes(0) && PRIVATE_KEY_RE.test(bytes.toString("utf8"))) {
			throw new Error(`private key material found in release artifact: ${artifactPath}`);
		}
		const digest = sha256(bytes);
		const metadataEntry = metadataByPath.get(artifactPath);
		if (digest !== metadataEntry.sha256) throw new Error(`release artifact digest mismatch: ${artifactPath}`);
		if (bytes.byteLength !== metadataEntry.size) throw new Error(`release artifact size mismatch: ${artifactPath}`);
		artifacts.push({ path: artifactPath, size: bytes.byteLength, sha256: digest });
	}

	const expectedFiles = new Set([
		RELEASE_METADATA_NAME,
		RELEASE_INVENTORY_NAME,
		...artifacts.map((entry) => entry.path),
	]);
	if (allowSignedControlFiles) {
		expectedFiles.add(RELEASE_MANIFEST_NAME);
		expectedFiles.add(RELEASE_SIGNATURE_NAME);
	}
	const expectedDirectories = new Set();
	for (const file of expectedFiles) {
		let directory = path.posix.dirname(file);
		while (directory !== ".") {
			expectedDirectories.add(directory);
			directory = path.posix.dirname(directory);
		}
	}
	const { files: actualFiles, directories: actualDirectories } = await listBundleTree(bundle);
	for (const file of actualFiles) {
		if (!expectedFiles.has(file)) throw new Error(`untracked file in release bundle: ${file}`);
	}
	for (const directory of actualDirectories) {
		if (!expectedDirectories.has(directory)) throw new Error(`untracked directory in release bundle: ${directory}`);
	}
	for (const file of expectedFiles) {
		if (!actualFiles.includes(file)) throw new Error(`release bundle file is missing: ${file}`);
	}

	return {
		bundle,
		metadata,
		inventory,
		metadataRaw: metadataRecord.raw,
		inventoryRaw: inventoryRecord.raw,
		artifacts,
	};
}

export function createReleaseManifest(bundle, options) {
	const productId = assertProductId(options.productId);
	const channel = assertChannel(options.channel);
	const keyId = assertKeyId(options.keyId);
	const releaseSequence = parsePositiveInteger(options.releaseSequence, "release sequence");
	const issuedAt = parseInstant(options.issuedAt, "issued-at");
	const expiresAt = parseInstant(options.expiresAt, "expires-at");
	if (expiresAt <= issuedAt) throw new Error("expires-at must be after issued-at");

	return {
		schema_version: 1,
		type: "aidr-release",
		product_id: productId,
		channel,
		release_sequence: releaseSequence,
		release_tag: bundle.metadata.release_tag,
		release_version: bundle.metadata.release_version,
		git_sha: bundle.metadata.git_sha,
		issued_at: issuedAt.toISOString(),
		expires_at: expiresAt.toISOString(),
		signer: {
			key_id: keyId,
			fingerprint_sha256: normalizeFingerprint(options.fingerprint),
		},
		bindings: {
			release_metadata: {
				path: RELEASE_METADATA_NAME,
				sha256: sha256(bundle.metadataRaw),
			},
			release_inventory: {
				path: RELEASE_INVENTORY_NAME,
				sha256: sha256(bundle.inventoryRaw),
			},
		},
		artifacts: bundle.artifacts,
	};
}

export async function loadEd25519PrivateKey(privateKeyPath, bundlePath) {
	const resolvedKey = path.resolve(privateKeyPath);
	if (isWithin(resolvedKey, bundlePath)) throw new Error("private signing key must be outside the release bundle");
	const info = await lstat(resolvedKey);
	if (!info.isFile() || info.isSymbolicLink()) throw new Error("private signing key must be a regular file");
	const pem = await readFile(resolvedKey, "utf8");
	if (!PRIVATE_KEY_RE.test(pem)) throw new Error("private signing key is not PEM private key material");
	const privateKey = createPrivateKey(pem);
	if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("release signing key must be Ed25519");
	const publicKey = createPublicKey(privateKey);
	const fingerprint = `sha256:${sha256(publicKey.export({ type: "spki", format: "der" }))}`;
	return { privateKey, fingerprint };
}

export function signReleaseManifest(rawManifest, privateKey, keyId) {
	const signature = cryptoSign(null, rawManifest, privateKey);
	if (signature.byteLength !== 64) throw new Error("unexpected Ed25519 signature length");
	return {
		schema_version: 1,
		algorithm: "Ed25519",
		key_id: assertKeyId(keyId),
		signature_b64: signature.toString("base64"),
	};
}

export async function loadSignerPolicy(policyPath, bundlePath) {
	const resolvedPolicy = path.resolve(policyPath);
	if (isWithin(resolvedPolicy, bundlePath)) throw new Error("signer policy must be stored outside the release bundle");
	const { value: policy } = await readJsonFile(resolvedPolicy, "signer policy");
	if (!policy || policy.schema_version !== 1 || typeof policy.policy_id !== "string" || policy.policy_id.length < 1) {
		throw new Error("signer policy schema is invalid");
	}
	assertExactKeys(
		policy,
		[
			"schema_version",
			"policy_id",
			"product_id",
			"allowed_channels",
			"minimum_release_sequence",
			"maximum_signature_lifetime_seconds",
			"trusted_signers",
			"revoked_key_ids",
			"revoked_fingerprints",
		],
		"signer policy",
	);
	assertKeyId(policy.policy_id);
	assertProductId(policy.product_id);
	const allowedChannels = validateUniqueStrings(policy.allowed_channels, "allowed channel", assertChannel);
	const minimumReleaseSequence = parsePositiveInteger(policy.minimum_release_sequence, "minimum release sequence");
	const maximumSignatureLifetimeSeconds = parsePositiveInteger(
		policy.maximum_signature_lifetime_seconds,
		"maximum signature lifetime seconds",
	);
	const revokedKeyIds = new Set(validateUniqueStrings(policy.revoked_key_ids ?? [], "revoked key id", assertKeyId));
	const revokedFingerprints = new Set(
		validateUniqueStrings(policy.revoked_fingerprints ?? [], "revoked fingerprint", normalizeFingerprint),
	);
	if (!Array.isArray(policy.trusted_signers) || policy.trusted_signers.length === 0) {
		throw new Error("signer policy must contain trusted signers");
	}
	const trustedSigners = new Map();
	for (const value of policy.trusted_signers) {
		if (!value || typeof value !== "object") throw new Error("trusted signer entry is invalid");
		assertExactKeys(
			value,
			["key_id", "public_key_pem", "fingerprint_sha256", "valid_from", "valid_until"],
			"trusted signer",
		);
		const keyId = assertKeyId(value.key_id);
		if (trustedSigners.has(keyId)) throw new Error(`duplicate trusted signer key id: ${keyId}`);
		if (typeof value.public_key_pem !== "string" || PRIVATE_KEY_RE.test(value.public_key_pem)) {
			throw new Error(`trusted signer ${keyId} must contain only an Ed25519 public key`);
		}
		const publicKey = createPublicKey(value.public_key_pem);
		if (publicKey.asymmetricKeyType !== "ed25519") throw new Error(`trusted signer ${keyId} is not Ed25519`);
		const actualFingerprint = `sha256:${sha256(publicKey.export({ type: "spki", format: "der" }))}`;
		const configuredFingerprint = normalizeFingerprint(value.fingerprint_sha256);
		if (actualFingerprint !== configuredFingerprint) throw new Error(`trusted signer fingerprint mismatch: ${keyId}`);
		const validFrom = parseInstant(value.valid_from, `trusted signer ${keyId} valid_from`);
		const validUntil = parseInstant(value.valid_until, `trusted signer ${keyId} valid_until`);
		if (validUntil <= validFrom) throw new Error(`trusted signer validity window is invalid: ${keyId}`);
		trustedSigners.set(keyId, { keyId, publicKey, fingerprint: actualFingerprint, validFrom, validUntil });
	}
	return {
		policyId: policy.policy_id,
		productId: policy.product_id,
		allowedChannels: new Set(allowedChannels),
		minimumReleaseSequence,
		maximumSignatureLifetimeSeconds,
		revokedKeyIds,
		revokedFingerprints,
		trustedSigners,
	};
}

export function validateReleaseManifest(manifest, bundle, policy, now = new Date()) {
	if (!manifest || manifest.schema_version !== 1 || manifest.type !== "aidr-release") {
		throw new Error("release manifest schema is invalid");
	}
	assertExactKeys(
		manifest,
		[
			"schema_version",
			"type",
			"product_id",
			"channel",
			"release_sequence",
			"release_tag",
			"release_version",
			"git_sha",
			"issued_at",
			"expires_at",
			"signer",
			"bindings",
			"artifacts",
		],
		"release manifest",
	);
	if (!isPlainObject(manifest.signer) || !isPlainObject(manifest.bindings)) {
		throw new Error("release manifest signer or bindings are invalid");
	}
	assertExactKeys(manifest.signer, ["key_id", "fingerprint_sha256"], "release manifest signer");
	assertExactKeys(manifest.bindings, ["release_metadata", "release_inventory"], "release manifest bindings");
	for (const [name, binding] of Object.entries(manifest.bindings)) {
		if (!isPlainObject(binding)) throw new Error(`release manifest ${name} binding is invalid`);
		assertExactKeys(binding, ["path", "sha256"], `release manifest ${name} binding`);
	}
	const productId = assertProductId(manifest.product_id);
	const channel = assertChannel(manifest.channel);
	const releaseSequence = parsePositiveInteger(manifest.release_sequence, "release sequence");
	if (productId !== policy.productId) throw new Error("release product is not allowed by signer policy");
	if (!policy.allowedChannels.has(channel)) throw new Error("release channel is not allowed by signer policy");
	if (releaseSequence < policy.minimumReleaseSequence) throw new Error("release sequence is below the policy floor");
	if (manifest.release_tag !== bundle.metadata.release_tag || manifest.release_version !== bundle.metadata.release_version || manifest.git_sha !== bundle.metadata.git_sha) {
		throw new Error("release manifest provenance does not match release metadata");
	}
	const issuedAt = parseInstant(manifest.issued_at, "release issued_at");
	const expiresAt = parseInstant(manifest.expires_at, "release expires_at");
	if (expiresAt <= issuedAt) throw new Error("release validity window is invalid");
	if (issuedAt.getTime() > now.getTime()) throw new Error("release is not valid yet");
	if (expiresAt.getTime() <= now.getTime()) throw new Error("release manifest has expired");
	if ((expiresAt.getTime() - issuedAt.getTime()) / 1000 > policy.maximumSignatureLifetimeSeconds) {
		throw new Error("release validity exceeds signer policy maximum");
	}
	const keyId = assertKeyId(manifest.signer?.key_id);
	const fingerprint = normalizeFingerprint(manifest.signer?.fingerprint_sha256);
	if (policy.revokedKeyIds.has(keyId) || policy.revokedFingerprints.has(fingerprint)) {
		throw new Error("release signer is revoked");
	}
	const signer = policy.trustedSigners.get(keyId);
	if (!signer) throw new Error("release signer is not in the trusted allowlist");
	if (signer.fingerprint !== fingerprint) throw new Error("release signer fingerprint does not match policy");
	if (issuedAt < signer.validFrom || expiresAt > signer.validUntil) {
		throw new Error("release validity is outside the trusted signer window");
	}
	if (
		manifest.bindings?.release_metadata?.path !== RELEASE_METADATA_NAME ||
		manifest.bindings.release_metadata.sha256 !== sha256(bundle.metadataRaw)
	) {
		throw new Error("release metadata binding does not match");
	}
	if (
		manifest.bindings?.release_inventory?.path !== RELEASE_INVENTORY_NAME ||
		manifest.bindings.release_inventory.sha256 !== sha256(bundle.inventoryRaw)
	) {
		throw new Error("release inventory binding does not match");
	}
	if (JSON.stringify(manifest.artifacts) !== JSON.stringify(bundle.artifacts)) {
		throw new Error("signed artifact inventory does not match verified bundle artifacts");
	}
	return { productId, channel, releaseSequence, issuedAt, expiresAt, keyId, fingerprint, signer };
}

export function verifyManifestSignature(rawManifest, signatureEnvelope, validatedManifest) {
	if (
		!signatureEnvelope ||
		signatureEnvelope.schema_version !== 1 ||
		signatureEnvelope.algorithm !== "Ed25519" ||
		signatureEnvelope.key_id !== validatedManifest.keyId ||
		typeof signatureEnvelope.signature_b64 !== "string" ||
		!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureEnvelope.signature_b64)
	) {
		throw new Error("release signature envelope is invalid");
	}
	assertExactKeys(
		signatureEnvelope,
		["schema_version", "algorithm", "key_id", "signature_b64"],
		"release signature envelope",
	);
	const signature = Buffer.from(signatureEnvelope.signature_b64, "base64");
	if (signature.byteLength !== 64) throw new Error("release Ed25519 signature length is invalid");
	if (signature.toString("base64") !== signatureEnvelope.signature_b64) {
		throw new Error("release Ed25519 signature encoding is not canonical");
	}
	if (!cryptoVerify(null, rawManifest, validatedManifest.signer.publicKey, signature)) {
		throw new Error("release Ed25519 signature does not verify");
	}
}

export async function loadRollbackState(statePath, bundlePath) {
	const resolvedState = path.resolve(statePath);
	if (isWithin(resolvedState, bundlePath)) throw new Error("anti-rollback state must be stored outside the release bundle");
	try {
		await access(resolvedState, fsConstants.F_OK);
	} catch {
		return { path: resolvedState, value: { schema_version: 1, records: {} } };
	}
	const { value } = await readJsonFile(resolvedState, "anti-rollback state");
	if (!value || value.schema_version !== 1 || !isPlainObject(value.records)) {
		throw new Error("anti-rollback state schema is invalid");
	}
	for (const [key, record] of Object.entries(value.records)) {
		if (!/^[a-z0-9._-]+\/[a-z0-9._-]+$/.test(key) || !isPlainObject(record)) {
			throw new Error("anti-rollback state record is invalid");
		}
		parsePositiveInteger(record.highest_release_sequence, "anti-rollback sequence");
		if (!SHA256_RE.test(String(record.manifest_sha256 ?? ""))) throw new Error("anti-rollback manifest digest is invalid");
		parseInstant(record.recorded_at, "anti-rollback recorded_at");
	}
	return { path: resolvedState, value };
}

export function enforceRollbackState(state, manifest, manifestDigest) {
	const key = `${manifest.product_id}/${manifest.channel}`;
	const current = state.value.records[key];
	if (!current) return;
	if (manifest.release_sequence < current.highest_release_sequence) {
		throw new Error(`release rollback rejected: sequence ${manifest.release_sequence} is below installed sequence ${current.highest_release_sequence}`);
	}
	if (manifest.release_sequence === current.highest_release_sequence && manifestDigest !== current.manifest_sha256) {
		throw new Error("release equivocation rejected: sequence is already bound to a different signed manifest");
	}
}

export async function recordRollbackState(state, manifest, manifestDigest, recordedAt = new Date()) {
	const key = `${manifest.product_id}/${manifest.channel}`;
	const current = state.value.records[key];
	if (!current || manifest.release_sequence > current.highest_release_sequence) {
		state.value.records[key] = {
			highest_release_sequence: manifest.release_sequence,
			manifest_sha256: manifestDigest,
			release_version: manifest.release_version,
			recorded_at: recordedAt.toISOString(),
		};
	}
	await atomicJsonWrite(state.path, state.value, 0o600);
}

export async function acquireRollbackLock(statePath) {
	const resolvedState = path.resolve(statePath);
	const lockPath = `${resolvedState}.lock`;
	await mkdir(path.dirname(lockPath), { recursive: true });
	let handle;
	try {
		handle = await open(lockPath, "wx", 0o600);
		await handle.writeFile(
			`${JSON.stringify({ pid: process.pid, acquired_at: new Date().toISOString() })}\n`,
			"utf8",
		);
	} catch (error) {
		if (handle) await handle.close().catch(() => {});
		if (error?.code === "EEXIST") {
			throw new Error(`another release verification or installation holds the anti-rollback lock: ${lockPath}`);
		}
		throw error;
	}
	let released = false;
	return {
		path: lockPath,
		async release() {
			if (released) return;
			released = true;
			await handle.close();
			await unlink(lockPath);
		},
	};
}

export async function atomicJsonWrite(filePath, value, mode = 0o600) {
	const resolved = path.resolve(filePath);
	await mkdir(path.dirname(resolved), { recursive: true });
	const temporary = `${resolved}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
	await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode, flag: "wx" });
	await rename(temporary, resolved);
}

export async function writeExclusive(filePath, value, mode = 0o644) {
	await writeFile(filePath, value, { encoding: "utf8", mode, flag: "wx" });
}

export function resolveWithin(root, relativePath) {
	const resolvedRoot = path.resolve(root);
	const resolved = path.resolve(resolvedRoot, relativePath);
	if (resolved === resolvedRoot || !resolved.startsWith(`${resolvedRoot}${path.sep}`)) {
		throw new Error(`path escapes release bundle: ${relativePath}`);
	}
	return resolved;
}

export function isWithin(candidate, root) {
	const normalizeCase = (value) => (process.platform === "win32" ? value.toLowerCase() : value);
	const resolvedCandidate = normalizeCase(path.resolve(candidate));
	const resolvedRoot = normalizeCase(path.resolve(root));
	return resolvedCandidate === resolvedRoot || resolvedCandidate.startsWith(`${resolvedRoot}${path.sep}`);
}

async function listBundleTree(root) {
	const files = [];
	const directories = [];
	const stack = [{ absolute: root, relative: "" }];
	while (stack.length > 0) {
		const current = stack.pop();
		const entries = await readdir(current.absolute, { withFileTypes: true });
		entries.sort((left, right) => compareStrings(left.name, right.name));
		for (const entry of entries) {
			const absolute = path.join(current.absolute, entry.name);
			const relative = current.relative ? `${current.relative}/${entry.name}` : entry.name;
			const info = await lstat(absolute);
			if (info.isSymbolicLink()) throw new Error(`symbolic links are not allowed in release bundles: ${relative}`);
			if (info.isDirectory()) {
				directories.push(relative);
				stack.push({ absolute, relative });
			}
			else if (info.isFile()) files.push(relative);
			else throw new Error(`unsupported filesystem entry in release bundle: ${relative}`);
		}
	}
	return { files: files.sort(compareStrings), directories: directories.sort(compareStrings) };
}

function validateMetadata(value) {
	if (!value || value.schema_version !== 1 || !Array.isArray(value.artifacts) || value.artifacts.length === 0) {
		throw new Error("release metadata schema is invalid");
	}
	assertExactKeys(
		value,
		["schema_version", "release_tag", "release_version", "git_sha", "source_date_epoch", "artifacts"],
		"release metadata",
	);
	if (!TAG_RE.test(String(value.release_tag ?? ""))) throw new Error("release tag is invalid");
	if (!VERSION_RE.test(String(value.release_version ?? ""))) throw new Error("release version is invalid");
	if (!/^[0-9a-f]{40,64}$/i.test(String(value.git_sha ?? ""))) throw new Error("release git SHA is invalid");
	if (!Number.isSafeInteger(value.source_date_epoch) || value.source_date_epoch < 0) {
		throw new Error("release source date epoch is invalid");
	}
	const seen = new Set();
	for (const entry of value.artifacts) {
		if (!entry || typeof entry !== "object") throw new Error("release metadata artifact is invalid");
		assertExactKeys(entry, ["path", "size", "sha256"], "release metadata artifact");
		entry.path = normalizeSafePath(entry.path);
		if (seen.has(entry.path)) throw new Error(`duplicate release metadata artifact: ${entry.path}`);
		seen.add(entry.path);
		if (!Number.isSafeInteger(entry.size) || entry.size < 0) throw new Error(`release artifact size is invalid: ${entry.path}`);
		if (!SHA256_RE.test(String(entry.sha256 ?? ""))) throw new Error(`release artifact digest is invalid: ${entry.path}`);
	}
	return value;
}

function validateInventory(value) {
	if (!value || value.schema_version !== 1 || !Array.isArray(value.artifacts) || value.artifacts.length === 0) {
		throw new Error("release inventory schema is invalid");
	}
	assertExactKeys(value, ["schema_version", "artifacts"], "release inventory");
	const seen = new Set();
	for (const entry of value.artifacts) {
		if (!entry || typeof entry !== "object") throw new Error("release inventory artifact is invalid");
		assertExactKeys(entry, ["source_path", "staged_path", "kind", "sha256"], "release inventory artifact");
		const sourcePath = normalizeSafePath(entry.source_path, "release inventory source path");
		if (!sourcePath.startsWith("release-output/")) {
			throw new Error(`release inventory source path is outside release-output: ${sourcePath}`);
		}
		entry.staged_path = normalizeSafePath(entry.staged_path);
		if (sourcePath.slice("release-output/".length) !== entry.staged_path) {
			throw new Error(`release inventory source and staged paths disagree: ${entry.staged_path}`);
		}
		if (seen.has(entry.staged_path)) throw new Error(`duplicate release inventory artifact: ${entry.staged_path}`);
		seen.add(entry.staged_path);
		if (entry.kind !== "release-artifact") throw new Error(`release inventory kind is invalid: ${entry.staged_path}`);
		if (!SHA256_RE.test(String(entry.sha256 ?? ""))) throw new Error(`release inventory digest is invalid: ${entry.staged_path}`);
	}
	return value;
}

function validateUniqueStrings(values, label, validator) {
	if (!Array.isArray(values)) throw new Error(`${label} list is invalid`);
	const normalized = values.map((value) => validator(value));
	if (new Set(normalized).size !== normalized.length) throw new Error(`${label} list contains duplicates`);
	return normalized;
}

function isPlainObject(value) {
	return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, expected, label) {
	const actual = Object.keys(value).sort(compareStrings);
	const allowed = [...expected].sort(compareStrings);
	if (actual.length !== allowed.length || actual.some((key, index) => key !== allowed[index])) {
		throw new Error(`${label} contains unexpected or missing fields`);
	}
}

function compareStrings(left, right) {
	return left < right ? -1 : left > right ? 1 : 0;
}
