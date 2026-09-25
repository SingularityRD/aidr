// Managed-mode dashboard approval tokens (docs/contracts/dashboard-approvals.md).
//
// A token is `base64url(payload) + "." + base64url(signature)` where `payload`
// is the canonical JSON (recursively sorted keys, no whitespace) of
//   { v:1, tenant_id, iid, action_id, artifact_digest, tool, decision,
//     approver_id, issued_at, expires_at, nonce }
// and `signature` is Ed25519 over exactly those payload bytes. The signing
// key's id travels next to the token, and its public key is delivered to
// connectors inside the signed entitlement as
//   approval_public_keys: [{ key_id, public_key_spki_b64 }].
//
// Key custody follows the pack-key pattern (HKDF-SHA256 from an Edge secret)
// and never stores key material in the clear: each tenant's Ed25519 private
// key is sealed with AES-256-GCM under a per-tenant key-encryption key derived
// from AIDR_APPROVAL_SIGNING_WRAP_KEY_B64, with the tenant and key id bound as
// additional authenticated data. The database only ever holds ciphertext, and
// the unwrapped key exists only in the Edge Function's memory while signing.
//
// Only WebCrypto is used, so the same module runs in Deno and in the vitest
// contract suites.

const APPROVAL_TOKEN_VERSION = 1;
export const APPROVAL_TOKEN_TTL_MS = 15 * 60_000;
export const APPROVAL_REQUEST_MAX_TTL_MS = 30 * 60_000;
const APPROVAL_WRAP_KEY_VERSION = 1;
/** A retired key stays published while any token it signed can still be valid. */
export const RETIRED_KEY_PUBLICATION_MS = APPROVAL_TOKEN_TTL_MS + 5 * 60_000;

const APPROVAL_KEY_ID = /^apk_[a-f0-9]{32}$/;
const APPROVAL_SPKI_B64 = /^MCowBQYDK2VwAyEA[A-Za-z0-9+/]{43}=$/;

export type ApprovalDecision = "approve" | "deny";

export interface ApprovalTokenPayload {
	v: 1;
	tenant_id: string;
	iid: string;
	action_id: string;
	artifact_digest: string;
	tool: string;
	decision: ApprovalDecision;
	approver_id: string;
	issued_at: string;
	expires_at: string;
	nonce: string;
}

export interface SealedApprovalKey {
	keyId: string;
	publicKeySpkiB64: string;
	privateKeyCiphertextB64: string;
	privateKeyNonceB64: string;
	wrapKeyVersion: number;
}

export interface ApprovalPublicKey {
	key_id: string;
	public_key_spki_b64: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonicalize);
	if (!value || typeof value !== "object") return value;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(value as Record<string, unknown>).sort()) {
		out[key] = canonicalize((value as Record<string, unknown>)[key]);
	}
	return out;
}

function canonicalJson(value: unknown): string {
	return JSON.stringify(canonicalize(value));
}

function bytesToBase64(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
	return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function base64UrlEncode(bytes: Uint8Array): string {
	return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array {
	if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) throw new Error("invalid_base64url");
	const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
	return base64ToBytes(padded);
}

function buffer(bytes: Uint8Array): ArrayBuffer {
	return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/** Decode and length-check the wrap secret; null means misconfigured. */
export function parseWrapSecret(value: string | undefined | null): Uint8Array | null {
	if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value.trim())) return null;
	try {
		const bytes = base64ToBytes(value.trim());
		return bytes.length === 32 ? bytes : null;
	} catch {
		return null;
	}
}

async function tenantKeyEncryptionKey(
	wrapSecret: Uint8Array,
	tenantId: string,
	version: number,
): Promise<CryptoKey> {
	const master = await crypto.subtle.importKey("raw", buffer(wrapSecret), "HKDF", false, ["deriveKey"]);
	return crypto.subtle.deriveKey(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: new Uint8Array(),
			info: encoder.encode(`aidr:approval-signing-kek:v${version}:${tenantId}`),
		},
		master,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
}

function wrapAad(tenantId: string, keyId: string, version: number): Uint8Array {
	return encoder.encode(`aidr:approval-signing-key:v${version}:${tenantId}:${keyId}`);
}

function randomHex(bytes: number): string {
	return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (byte) =>
		byte.toString(16).padStart(2, "0"),
	).join("");
}

/** Generate a fresh tenant signing key and seal its private half. */
export async function generateSealedApprovalKey(
	wrapSecret: Uint8Array,
	tenantId: string,
): Promise<SealedApprovalKey> {
	const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
	const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
	const keyId = `apk_${randomHex(16)}`;
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const kek = await tenantKeyEncryptionKey(wrapSecret, tenantId, APPROVAL_WRAP_KEY_VERSION);
	const sealed = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(wrapAad(tenantId, keyId, APPROVAL_WRAP_KEY_VERSION)) },
			kek,
			pkcs8,
		),
	);
	pkcs8.fill(0);
	return {
		keyId,
		publicKeySpkiB64: bytesToBase64(spki),
		privateKeyCiphertextB64: bytesToBase64(sealed),
		privateKeyNonceB64: bytesToBase64(nonce),
		wrapKeyVersion: APPROVAL_WRAP_KEY_VERSION,
	};
}

/** Unseal a stored private key. Any mismatch (tenant, key id, secret) throws. */
export async function unsealApprovalKey(
	wrapSecret: Uint8Array,
	tenantId: string,
	stored: { key_id: string; private_key_ciphertext_b64: string; private_key_nonce_b64: string; wrap_key_version: number },
): Promise<CryptoKey> {
	const kek = await tenantKeyEncryptionKey(wrapSecret, tenantId, stored.wrap_key_version);
	const pkcs8 = new Uint8Array(
		await crypto.subtle.decrypt(
			{
				name: "AES-GCM",
				iv: buffer(base64ToBytes(stored.private_key_nonce_b64)),
				additionalData: buffer(wrapAad(tenantId, stored.key_id, stored.wrap_key_version)),
			},
			kek,
			buffer(base64ToBytes(stored.private_key_ciphertext_b64)),
		),
	);
	try {
		return await crypto.subtle.importKey("pkcs8", buffer(pkcs8), { name: "Ed25519" }, false, ["sign"]);
	} finally {
		pkcs8.fill(0);
	}
}

export function newApprovalNonce(): string {
	return base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
}

/** Sign a payload and return the compact token. */
export async function signApprovalToken(
	payload: ApprovalTokenPayload,
	privateKey: CryptoKey,
): Promise<string> {
	const bytes = encoder.encode(canonicalJson(payload));
	const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, bytes));
	return `${base64UrlEncode(bytes)}.${base64UrlEncode(signature)}`;
}

/**
 * Verify a token against a published SPKI key and return its payload, or null.
 * The Edge Function uses it as a self-check before persisting a token; the
 * connector-side verifier implements the same contract independently.
 */
export async function verifyApprovalToken(
	token: string,
	publicKeySpkiB64: string,
): Promise<ApprovalTokenPayload | null> {
	try {
		const [encodedPayload, encodedSignature, extra] = token.split(".");
		if (!encodedPayload || !encodedSignature || extra !== undefined) return null;
		const bytes = base64UrlDecode(encodedPayload);
		const key = await crypto.subtle.importKey(
			"spki",
			buffer(base64ToBytes(publicKeySpkiB64)),
			{ name: "Ed25519" },
			false,
			["verify"],
		);
		const valid = await crypto.subtle.verify(
			"Ed25519",
			key,
			buffer(base64UrlDecode(encodedSignature)),
			buffer(bytes),
		);
		if (!valid) return null;
		const text = decoder.decode(bytes);
		const payload = JSON.parse(text) as ApprovalTokenPayload;
		return canonicalJson(payload) === text && payload.v === APPROVAL_TOKEN_VERSION ? payload : null;
	} catch {
		return null;
	}
}

type KeyRow = {
	key_id?: unknown;
	public_key_spki_b64?: unknown;
	retired_at?: unknown;
	revoked_at?: unknown;
};

/**
 * Public keys a connector may trust right now: the active key plus a retired
 * key for as long as a token it signed can still be valid. Revoked keys are
 * never published. Malformed rows are dropped, never trusted.
 */
export function publishedApprovalKeys(rows: unknown, nowMs: number): ApprovalPublicKey[] {
	if (!Array.isArray(rows)) return [];
	const keys: ApprovalPublicKey[] = [];
	for (const row of rows as KeyRow[]) {
		if (!row || typeof row !== "object") continue;
		if (typeof row.key_id !== "string" || !APPROVAL_KEY_ID.test(row.key_id)) continue;
		if (typeof row.public_key_spki_b64 !== "string" || !APPROVAL_SPKI_B64.test(row.public_key_spki_b64)) continue;
		if (row.revoked_at !== null && row.revoked_at !== undefined) continue;
		if (row.retired_at !== null && row.retired_at !== undefined) {
			const retired = typeof row.retired_at === "string" ? Date.parse(row.retired_at) : Number.NaN;
			if (!Number.isFinite(retired) || retired + RETIRED_KEY_PUBLICATION_MS <= nowMs) continue;
		}
		keys.push({ key_id: row.key_id, public_key_spki_b64: row.public_key_spki_b64 });
	}
	return keys.sort((a, b) => a.key_id.localeCompare(b.key_id));
}

type KeyTableClient = {
	from(table: string): {
		select(columns: string): {
			eq(column: string, value: unknown): PromiseLike<{ data: unknown; error: unknown }>;
		};
	};
};

/**
 * Read a tenant's publishable approval keys for the signed entitlement. An
 * unreadable key table yields no keys: connectors then cannot verify any
 * dashboard approval, so the pending ask stays blocked (fail closed) while the
 * rest of the entitlement is still delivered.
 */
export async function loadApprovalPublicKeys(
	db: unknown,
	tenantId: string,
	nowMs: number,
): Promise<ApprovalPublicKey[]> {
	try {
		const result = await (db as KeyTableClient)
			.from("tenant_approval_signing_keys")
			.select("key_id,public_key_spki_b64,retired_at,revoked_at")
			.eq("tenant_id", tenantId);
		if (!result || typeof result !== "object" || result.error) return [];
		return publishedApprovalKeys(result.data, nowMs);
	} catch {
		return [];
	}
}
