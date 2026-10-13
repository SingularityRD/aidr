#!/usr/bin/env node
/**
 * Publishing-side tooling for encrypted premium intel packs.
 *
 * Key model (the control plane side is supabase/functions/_shared/pack-keys.ts;
 * a Vitest contract keeps both derivations byte-identical):
 *
 *   Tenant pack key   HKDF-SHA256(AIDR_PACK_MASTER_KEY_B64, info
 *                     "aidr:packkey:v2:tenant:<tenant_id>"), key_id
 *                     "aidr-tenant-pack-v2.<tenant_id>.<master fingerprint>".
 *                     Encrypts packs registered for ONE tenant
 *                     (import-offline-pack --tenant-id <uuid>).
 *   Shared pack key   a random 32-byte key with key_id "aidr-shared-pack-<label>",
 *                     configured in AIDR_SHARED_PACK_KEYS and delivered to every
 *                     premium_intel tenant. Encrypts shared rows
 *                     (pack_versions.tenant_id IS NULL), including vendor packs:
 *                     the vendor generates the shared key, encrypts with it and
 *                     hands key_id=key to the customer with the premium licence.
 *
 * Commands:
 *   new-shared-key --label <label> --out <file>
 *       Write "aidr-shared-pack-<label>=<base64>" to a new 0600 file. Append that
 *       line to AIDR_SHARED_PACK_KEYS (comma-separated) in the functions Secret.
 *   tenant-key-id --tenant-id <uuid> [--master-key-file <file>]
 *       Print the key_id a tenant's endpoints hold (never the key).
 *   encrypt-pack --pack <dir> (--tenant-id <uuid> [--master-key-file <file>] | --shared-key-file <file>) [--file <path>]...
 *       Encrypt the listed manifest files (default: every file) in place with the
 *       AES-256-GCM envelope the core loader reads, and record encrypted, cipher,
 *       key_id, sha256 (plaintext) and ciphertext_sha256 in manifest.json. Sign
 *       the manifest afterwards with scripts/sign-intel-pack-manifest.mjs.
 *
 * The master key is read from --master-key-file or AIDR_PACK_MASTER_KEY_B64; it
 * is never printed.
 */
import { createCipheriv, createHash, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

export const TENANT_PACK_KEY_PREFIX = "aidr-tenant-pack-v2";
export const SHARED_PACK_KEY_PATTERN = /^aidr-shared-pack-[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const TENANT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const KEY_B64_PATTERN = /^(?:[A-Za-z0-9+/]{4}){10}[A-Za-z0-9+/]{3}=$/;

export class PackKeyError extends Error {
	constructor(message) {
		super(message);
		this.name = "PackKeyError";
	}
}

function keyBytes(b64, label) {
	const value = String(b64 ?? "").trim();
	if (!KEY_B64_PATTERN.test(value)) throw new PackKeyError(`${label} must be a base64 32-byte key`);
	return Buffer.from(value, "base64");
}

/** Tenant pack key ({ key_id, key_b64 }); identical to the control plane derivation. */
export function deriveTenantPackKey(masterB64, tenantId) {
	const master = keyBytes(masterB64, "the pack master key");
	if (!TENANT_ID_PATTERN.test(String(tenantId))) throw new PackKeyError("tenant id must be a UUID");
	const tenant = tenantId.toLowerCase();
	const key = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(0), `aidr:packkey:v2:tenant:${tenant}`, 32));
	const fingerprint = createHmac("sha256", master).update("aidr:packkey-id:v2").digest("hex").slice(0, 16);
	return { key_id: `${TENANT_PACK_KEY_PREFIX}.${tenant}.${fingerprint}`, key_b64: key.toString("base64") };
}

/** Parse "<key_id>=<base64>[,...]"; any malformed entry rejects the whole value. */
export function parseSharedPackKeys(raw) {
	const text = String(raw ?? "").trim();
	if (!text) return [];
	const seen = new Set();
	return text.split(",").map((entry) => {
		const separator = entry.indexOf("=");
		const keyId = separator > 0 ? entry.slice(0, separator).trim() : "";
		const keyB64 = separator > 0 ? entry.slice(separator + 1).trim() : "";
		if (!SHARED_PACK_KEY_PATTERN.test(keyId) || seen.has(keyId)) throw new PackKeyError(`invalid shared pack key id ${JSON.stringify(keyId)}`);
		keyBytes(keyB64, keyId);
		seen.add(keyId);
		return { key_id: keyId, key_b64: keyB64 };
	});
}

/**
 * Which endpoints can hold a key id: a shared key (every premium tenant) or one
 * tenant's derived key. Anything else (including the retired "aidr-pack-v1",
 * which named a different key on every tenant) is not deliverable.
 */
export function packKeyScope(keyId) {
	if (typeof keyId !== "string") return null;
	if (SHARED_PACK_KEY_PATTERN.test(keyId)) return { kind: "shared" };
	const match = keyId.match(/^aidr-tenant-pack-v2\.([0-9a-f-]{36})\.[0-9a-f]{16}$/);
	return match && TENANT_ID_PATTERN.test(match[1]) ? { kind: "tenant", tenantId: match[1] } : null;
}

/** The AES-256-GCM envelope (12-byte IV | ciphertext | 16-byte tag) the core loader decrypts. */
export function encryptEnvelope(plain, keyB64) {
	const iv = randomBytes(12);
	const cipher = createCipheriv("aes-256-gcm", keyBytes(keyB64, "pack key"), iv);
	return Buffer.concat([iv, cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function regularFile(path, label) {
	const stats = lstatSync(path, { throwIfNoEntry: false });
	if (!stats || stats.isSymbolicLink() || !stats.isFile()) throw new PackKeyError(`${label} must be an existing regular, non-symlink file`);
	return readFileSync(path);
}

/** Encrypt manifest files in place; returns the updated manifest. */
export function encryptPackDirectory(packDir, key, onlyPaths = []) {
	const dir = resolve(packDir);
	const manifestPath = join(dir, "manifest.json");
	const manifest = JSON.parse(regularFile(manifestPath, "manifest.json").toString("utf8"));
	if (!manifest || !Array.isArray(manifest.files)) throw new PackKeyError("manifest.json must list files");
	if (!packKeyScope(key.key_id)) throw new PackKeyError(`key id ${key.key_id} is not a deliverable pack key id`);
	const wanted = new Set(onlyPaths);
	for (const path of wanted) {
		if (!manifest.files.some((file) => file.path === path)) throw new PackKeyError(`${path} is not listed in manifest.json`);
	}
	for (const file of manifest.files) {
		if (wanted.size > 0 && !wanted.has(file.path)) continue;
		if (file.encrypted) throw new PackKeyError(`${file.path} is already encrypted`);
		if (typeof file.path !== "string" || file.path.split("/").some((part) => !part || part === "." || part === "..")) {
			throw new PackKeyError(`unsafe manifest path ${JSON.stringify(file.path)}`);
		}
		const target = join(dir, ...file.path.split("/"));
		const plain = regularFile(target, file.path);
		if (file.sha256 && sha256(plain) !== String(file.sha256).toLowerCase()) throw new PackKeyError(`plaintext SHA-256 mismatch for ${file.path}`);
		const envelope = encryptEnvelope(plain, key.key_b64);
		writeFileSync(target, envelope);
		Object.assign(file, { sha256: sha256(plain), encrypted: true, cipher: "aes-256-gcm", key_id: key.key_id, ciphertext_sha256: sha256(envelope) });
	}
	writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
	return manifest;
}

function masterKey(values) {
	const value = values["master-key-file"]
		? regularFile(resolve(values["master-key-file"]), "master key file").toString("utf8")
		: process.env.AIDR_PACK_MASTER_KEY_B64;
	if (!value?.trim()) throw new PackKeyError("set AIDR_PACK_MASTER_KEY_B64 or pass --master-key-file");
	return value.trim();
}

const USAGE = `Usage:
  node scripts/intel-pack-keys.mjs new-shared-key --label <label> --out <file>
  node scripts/intel-pack-keys.mjs tenant-key-id --tenant-id <uuid> [--master-key-file <file>]
  node scripts/intel-pack-keys.mjs encrypt-pack --pack <dir> (--tenant-id <uuid> [--master-key-file <file>] | --shared-key-file <file>) [--file <path>]...`;

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) {
	try {
		const { positionals, values } = parseArgs({
			allowPositionals: true,
			strict: true,
			options: {
				label: { type: "string" },
				out: { type: "string" },
				"tenant-id": { type: "string" },
				"master-key-file": { type: "string" },
				"shared-key-file": { type: "string" },
				pack: { type: "string" },
				file: { type: "string", multiple: true },
			},
		});
		const [command] = positionals;
		if (command === "new-shared-key") {
			const keyId = `aidr-shared-pack-${values.label ?? ""}`;
			if (!SHARED_PACK_KEY_PATTERN.test(keyId) || !values.out) throw new PackKeyError(USAGE);
			writeFileSync(resolve(values.out), `${keyId}=${randomBytes(32).toString("base64")}\n`, { flag: "wx", mode: 0o600 });
			console.log(JSON.stringify({ key_id: keyId, written: resolve(values.out) }));
		} else if (command === "tenant-key-id") {
			console.log(JSON.stringify({ key_id: deriveTenantPackKey(masterKey(values), values["tenant-id"] ?? "").key_id }));
		} else if (command === "encrypt-pack") {
			if (!values.pack || Boolean(values["tenant-id"]) === Boolean(values["shared-key-file"])) throw new PackKeyError(USAGE);
			const key = values["tenant-id"]
				? deriveTenantPackKey(masterKey(values), values["tenant-id"])
				: parseSharedPackKeys(regularFile(resolve(values["shared-key-file"]), "shared key file").toString("utf8").trim());
			const selected = Array.isArray(key) ? key : [key];
			if (selected.length !== 1) throw new PackKeyError("the shared key file must hold exactly one key_id=key line");
			const manifest = encryptPackDirectory(values.pack, selected[0], values.file ?? []);
			console.log(JSON.stringify({ pack_id: manifest.pack_id, version: manifest.version, key_id: selected[0].key_id, encrypted: manifest.files.filter((file) => file.encrypted).map((file) => file.path) }));
		} else {
			throw new PackKeyError(USAGE);
		}
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : "intel pack key operation failed"}`);
		process.exitCode = 1;
	}
}
