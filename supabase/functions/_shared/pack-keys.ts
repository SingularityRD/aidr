// Premium intel pack keys delivered in the signed entitlement snapshot.
//
// Two key classes, each with its own key_id namespace, so a pack's key_id
// always names exactly one key on every endpoint that can open it:
//
//  * Tenant pack key: HKDF-SHA256(AIDR_PACK_MASTER_KEY_B64, info =
//    "aidr:packkey:v2:tenant:<tenant_id>"). key_id =
//    "aidr-tenant-pack-v2.<tenant_id>.<master fingerprint>". It opens only
//    pack_versions rows registered for that tenant. The derivation version, the
//    tenant and the master-key fingerprint are all in the key_id, so rotating
//    the master key changes the key_id instead of silently changing the bytes.
//  * Shared pack keys: AIDR_SHARED_PACK_KEYS, a comma-separated list of
//    "<key_id>=<base64 32-byte key>" with key ids "aidr-shared-pack-<label>".
//    They open the shared rows (pack_versions.tenant_id IS NULL), including
//    vendor packs whose key the vendor hands over with the premium licence, and
//    are delivered to every premium_intel tenant. Several may be configured
//    during a rotation.
//
// scripts/intel-pack-keys.mjs implements the same derivation for the
// publishing side (encryption, import scope checks); a Vitest contract keeps
// the two byte-identical.

export const TENANT_PACK_KEY_PREFIX = "aidr-tenant-pack-v2";
export const SHARED_PACK_KEY_PATTERN = /^aidr-shared-pack-[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const TENANT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const encoder = new TextEncoder();

export type PackKeyMaterial = { key_id: string; key_b64: string };

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> | null {
	if (!/^(?:[A-Za-z0-9+/]{4}){10}[A-Za-z0-9+/]{3}=$/.test(value)) return null;
	try {
		const bytes = Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
		return bytes.length === 32 ? bytes : null;
	} catch {
		return null;
	}
}

function bytesToBase64(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

function hex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Public, non-secret identifier of the master key (HMAC, not a hash of the key). */
async function masterFingerprint(master: Uint8Array<ArrayBuffer>): Promise<string> {
	const key = await crypto.subtle.importKey("raw", master, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const mac = await crypto.subtle.sign("HMAC", key, encoder.encode("aidr:packkey-id:v2"));
	return hex(new Uint8Array(mac)).slice(0, 16);
}

/** Tenant pack key and its key_id, or null without a valid master key or tenant id. */
export async function deriveTenantPackKey(masterB64: string, tenantId: string): Promise<PackKeyMaterial | null> {
	const master = base64ToBytes(masterB64.trim());
	if (!master || !TENANT_ID_PATTERN.test(tenantId)) return null;
	const tenant = tenantId.toLowerCase();
	const base = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
	const bits = await crypto.subtle.deriveBits(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: new Uint8Array(),
			info: encoder.encode(`aidr:packkey:v2:tenant:${tenant}`),
		},
		base,
		256,
	);
	return {
		key_id: `${TENANT_PACK_KEY_PREFIX}.${tenant}.${await masterFingerprint(master)}`,
		key_b64: bytesToBase64(new Uint8Array(bits)),
	};
}

/**
 * Parse AIDR_SHARED_PACK_KEYS. Any malformed entry rejects the whole value
 * (`invalid: true`, no keys) so a typo cannot deliver a half-configured set.
 */
export function parseSharedPackKeys(raw: string | null | undefined): { keys: PackKeyMaterial[]; invalid: boolean } {
	const text = (raw ?? "").trim();
	if (!text) return { keys: [], invalid: false };
	const keys: PackKeyMaterial[] = [];
	const seen = new Set<string>();
	for (const entry of text.split(",")) {
		const separator = entry.indexOf("=");
		const keyId = separator > 0 ? entry.slice(0, separator).trim() : "";
		const keyB64 = separator > 0 ? entry.slice(separator + 1).trim() : "";
		if (!SHARED_PACK_KEY_PATTERN.test(keyId) || seen.has(keyId) || !base64ToBytes(keyB64)) {
			return { keys: [], invalid: true };
		}
		seen.add(keyId);
		keys.push({ key_id: keyId, key_b64: keyB64 });
	}
	return { keys, invalid: false };
}

/** Every pack key a premium_intel tenant receives: its tenant key plus the shared keys. */
export async function entitledPackKeys(params: {
	masterB64: string;
	sharedKeys: string | null | undefined;
	tenantId: string;
}): Promise<PackKeyMaterial[]> {
	const out: PackKeyMaterial[] = [];
	if (params.masterB64.trim()) {
		const tenantKey = await deriveTenantPackKey(params.masterB64, params.tenantId).catch(() => null);
		if (tenantKey) out.push(tenantKey);
	}
	out.push(...parseSharedPackKeys(params.sharedKeys).keys);
	return out;
}
