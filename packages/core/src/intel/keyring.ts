import { lstat } from "node:fs/promises";
import { dirname } from "node:path";

import { loadConfig, resolvePath } from "../config.js";
import { atomicWriteJson, getFileContent } from "../file-utils.js";
import { type EntitlementSnapshotV2, verifyEd25519SignedEntitlementSnapshot } from "../managed.js";
import { preparePrivateLocalDirectory, preparePrivateLocalFile } from "../private-local-file.js";

const DEFAULT_KEYRING_PATH = "~/.singularity-aidr/intel/keys.json";
const DEFAULT_ENTITLEMENT_PATH = "~/.singularity-aidr/entitlement.json";
const DEFAULT_MANAGED_STATE_PATH = "~/.singularity-aidr/managed.json";
const DEFAULT_RETAINED_KEYS_PATH = "~/.singularity-aidr/intel/retained/pack-keys.json";
const RETAINED_KEYS_SCHEMA_VERSION = 1;

function normalizeKeyMap(obj: unknown): Map<string, Uint8Array> {
	const map = new Map<string, Uint8Array>();
	if (!obj || typeof obj !== "object") return map;

	const root = obj as Record<string, unknown>;
	const record =
		("intel_keys" in root ? root.intel_keys : undefined) ??
		("keys" in root ? root.keys : undefined) ??
		obj;

	if (!record || typeof record !== "object") return map;

	for (const [keyId, b64] of Object.entries(record as Record<string, unknown>)) {
		if (typeof keyId !== "string" || typeof b64 !== "string") continue;
		const id = keyId.trim();
		if (!id) continue;
		const bytes = parseAes256Key(b64);
		if (bytes) map.set(id, bytes);
	}
	return map;
}

function parseAes256Key(value: string): Uint8Array | null {
	try {
		const bytes = Buffer.from(value.trim(), "base64");
		return bytes.length === 32 ? bytes : null;
	} catch {
		return null;
	}
}

async function readJsonFile(path: string): Promise<unknown | null> {
	try {
		const raw = await getFileContent(path, "utf-8");
		return JSON.parse(raw) as unknown;
	} catch {
		return null;
	}
}

function isManagedEntitlementFile(value: unknown): value is Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const root = value as Record<string, unknown>;
	return (
		root.managed === true || (typeof root.tenant_id === "string" && typeof root.serial === "string")
	);
}

function finiteTimestamp(value: unknown): number | null {
	if (typeof value !== "string") return null;
	const timestamp = Date.parse(value);
	return Number.isFinite(timestamp) ? timestamp : null;
}

async function matchingManagedPackKeys(
	file: Record<string, unknown>,
	expiresAt: number,
	managedStatePath: string,
): Promise<unknown[] | null> {
	// The derived keyring is not an independent grant. Require its current
	// managed-state snapshot to refer to the same signed serial; revocation or
	// replacement of that snapshot invalidates the old decrypted pack key.
	const state = await readJsonFile(managedStatePath);
	if (!state || typeof state !== "object" || Array.isArray(state)) return null;
	const managed = state as Record<string, unknown>;
	if (
		managed.sync_disabled_reason === "revoked" ||
		managed.entitlement_alg !== "ed25519" ||
		typeof managed.entitlement_sig !== "string" ||
		!managed.entitlement_sig
	)
		return null;
	const entitlement = managed.entitlement;
	if (!entitlement || typeof entitlement !== "object" || Array.isArray(entitlement)) return null;
	const snapshot = entitlement as Record<string, unknown>;
	if (
		snapshot.schema_version !== 2 ||
		snapshot.serial !== file.serial ||
		snapshot.tenant_id !== file.tenant_id ||
		snapshot.grace_until !== file.expires_at ||
		finiteTimestamp(snapshot.grace_until) !== expiresAt ||
		!Array.isArray(snapshot.pack_keys)
	)
		return null;
	const config = await loadConfig();
	if (
		config.licensing.public_keys_pem.length === 0 ||
		!verifyEd25519SignedEntitlementSnapshot({
			snapshot: snapshot as unknown as EntitlementSnapshotV2,
			sig_b64: managed.entitlement_sig,
			public_keys_pem: config.licensing.public_keys_pem,
		})
	)
		return null;
	return snapshot.pack_keys;
}

function matchesCurrentPackKey(
	candidate: unknown,
	keyId: string,
	key: Uint8Array,
	nowMs: number,
	entitlementExpiry: number,
): boolean {
	if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return false;
	const entry = candidate as Record<string, unknown>;
	const keyExpiry = finiteTimestamp(entry.expires_at);
	return (
		entry.key_id === keyId &&
		entry.key_b64 === Buffer.from(key).toString("base64") &&
		entry.alg === "aes-256-gcm" &&
		keyExpiry !== null &&
		keyExpiry > nowMs &&
		keyExpiry <= entitlementExpiry
	);
}

async function loadManagedEntitlementKeys(
	file: Record<string, unknown>,
	now: Date,
	managedStatePath: string,
): Promise<Map<string, Uint8Array>> {
	const empty = new Map<string, Uint8Array>();
	if (file.revoked === true) return empty;
	const issuedAt = finiteTimestamp(file.issued_at);
	const expiresAt = finiteTimestamp(file.expires_at);
	if (
		issuedAt === null ||
		expiresAt === null ||
		issuedAt > expiresAt ||
		now.getTime() < issuedAt ||
		now.getTime() >= expiresAt
	) {
		return empty;
	}

	const packKeys = await matchingManagedPackKeys(file, expiresAt, managedStatePath);
	if (!packKeys) return empty;

	const keys = normalizeKeyMap(file);
	const keyExpiries = file.key_expires_at;
	const expiryMap =
		keyExpiries && typeof keyExpiries === "object" && !Array.isArray(keyExpiries)
			? (keyExpiries as Record<string, unknown>)
			: null;
	for (const [keyId, key] of keys) {
		const signedKey = packKeys.some((candidate) =>
			matchesCurrentPackKey(candidate, keyId, key, now.getTime(), expiresAt),
		);
		const fileKeyExpiry = expiryMap ? finiteTimestamp(expiryMap[keyId]) : expiresAt;
		if (
			!signedKey ||
			fileKeyExpiry === null ||
			fileKeyExpiry <= now.getTime() ||
			fileKeyExpiry > expiresAt
		)
			keys.delete(keyId);
	}
	return keys;
}

export async function loadIntelKeyring(
	params: {
		keyringPath?: string;
		entitlementPath?: string;
		managedStatePath?: string;
		now?: Date;
	} = {},
): Promise<Map<string, Uint8Array>> {
	// Entitlement file has priority (control plane can refresh this).
	const entitlementPath = resolvePath(params.entitlementPath ?? DEFAULT_ENTITLEMENT_PATH);
	const keyringPath = resolvePath(params.keyringPath ?? DEFAULT_KEYRING_PATH);
	const managedStatePath = resolvePath(params.managedStatePath ?? DEFAULT_MANAGED_STATE_PATH);

	const entitlement = await readJsonFile(entitlementPath);
	if (isManagedEntitlementFile(entitlement)) {
		// A stale or revoked commercial keyring must not fall back to the
		// developer-supplied static keyring beneath it.
		return loadManagedEntitlementKeys(entitlement, params.now ?? new Date(), managedStatePath);
	}
	const state = await readJsonFile(managedStatePath);
	if (state && typeof state === "object" && !Array.isArray(state)) {
		const managed = state as Record<string, unknown>;
		if (managed.entitlement_alg === "ed25519" || managed.sync_disabled_reason === "revoked") {
			// A missing or corrupt derived file does not authorize falling back to
			// an unrelated static key while this installation is managed.
			return new Map<string, Uint8Array>();
		}
	}
	const fromEnt = normalizeKeyMap(entitlement);
	if (fromEnt.size > 0) return fromEnt;

	const keyring = await readJsonFile(keyringPath);
	return normalizeKeyMap(keyring);
}

/**
 * Decryption keys of pack versions that were already activated, by `pack@version`.
 *
 * The entitlement keyring above deliberately empties when the entitlement ends.
 * Without this store an encrypted pack that was installed and enforcing would
 * stop decrypting at that moment, i.e. detection would degrade because of
 * license state. The loader therefore records the keys an active pack version
 * decrypted with, owner-only, and falls back to them for that exact version
 * only. A NEW version never inherits a retained key, and a revoked key id is
 * still refused by the loader before any key is looked up.
 */
export type RetainedPackKeys = Map<string, Map<string, Uint8Array>>;

export function retainedPackKeyId(packId: string, version: string): string {
	return `${packId}@${version}`;
}

function retainedPackKeysPath(path?: string): string {
	return resolvePath(path ?? DEFAULT_RETAINED_KEYS_PATH);
}

export async function loadRetainedPackKeys(path?: string): Promise<RetainedPackKeys> {
	const resolved = retainedPackKeysPath(path);
	const out: RetainedPackKeys = new Map();
	try {
		const stats = await lstat(resolved);
		if (stats.isSymbolicLink() || !stats.isFile()) return out;
	} catch {
		return out;
	}
	const parsed = await readJsonFile(resolved);
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return out;
	const root = parsed as Record<string, unknown>;
	if (root.schema_version !== RETAINED_KEYS_SCHEMA_VERSION) return out;
	const versions = root.versions;
	if (!versions || typeof versions !== "object" || Array.isArray(versions)) return out;
	for (const [versionId, keys] of Object.entries(versions as Record<string, unknown>)) {
		const map = normalizeKeyMap({ keys });
		if (map.size > 0) out.set(versionId, map);
	}
	return out;
}

/**
 * Record the keys an activated pack version decrypted with. Owner-only file in a
 * private directory; returns false (no write) when nothing new would be stored.
 */
export async function retainPackKeys(params: {
	packId: string;
	version: string;
	keys: Map<string, Uint8Array>;
	path?: string;
}): Promise<boolean> {
	if (params.keys.size === 0) return false;
	const path = retainedPackKeysPath(params.path);
	const current = await loadRetainedPackKeys(path);
	const versionId = retainedPackKeyId(params.packId, params.version);
	const existing = current.get(versionId) ?? new Map<string, Uint8Array>();
	let changed = false;
	for (const [keyId, key] of params.keys) {
		const known = existing.get(keyId);
		if (known && Buffer.from(known).equals(Buffer.from(key))) continue;
		existing.set(keyId, key);
		changed = true;
	}
	if (!changed) return false;
	current.set(versionId, existing);
	const versions: Record<string, Record<string, string>> = {};
	for (const [id, keys] of current) {
		versions[id] = Object.fromEntries(
			[...keys].map(([keyId, key]) => [keyId, Buffer.from(key).toString("base64")]),
		);
	}
	preparePrivateLocalDirectory(dirname(path));
	await atomicWriteJson(
		path,
		{ schema_version: RETAINED_KEYS_SCHEMA_VERSION, versions },
		{ mode: 0o600 },
	);
	if (process.platform === "win32") preparePrivateLocalFile(path);
	return true;
}
