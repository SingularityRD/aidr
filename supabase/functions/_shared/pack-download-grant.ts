export type PackDownloadGrant = {
	key_id: string;
	key_fingerprint: string;
	tenant_id: string;
	pack_id: string;
	version: string;
	expires_at: number;
};

const encoder = new TextEncoder();
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const hash = /^[a-f0-9]{64}$/;

function encode(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decode(value: string): ArrayBuffer {
	const bytes = Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0));
	if (encode(bytes) !== value) throw new Error("noncanonical_base64url");
	return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function validPackDownloadGrantSecret(secret: string): boolean {
	return encoder.encode(secret).byteLength >= 32;
}

async function hmacKey(secret: string): Promise<CryptoKey> {
	if (!validPackDownloadGrantSecret(secret)) throw new Error("invalid_pack_download_grant_secret");
	return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

function validGrant(value: unknown): value is PackDownloadGrant {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const grant = value as Record<string, unknown>;
	return grant.v === 1 &&
		typeof grant.key_id === "string" && uuid.test(grant.key_id) &&
		typeof grant.key_fingerprint === "string" && /^[A-Za-z0-9_-]{43}$/.test(grant.key_fingerprint) &&
		typeof grant.tenant_id === "string" && uuid.test(grant.tenant_id) &&
		typeof grant.pack_id === "string" && grant.pack_id.trim().length > 0 && grant.pack_id.length <= 256 &&
		typeof grant.version === "string" && grant.version.trim().length > 0 && grant.version.length <= 256 &&
		Number.isSafeInteger(grant.expires_at);
}

export async function packKeyFingerprint(keyHash: string, secret: string): Promise<string> {
	if (!hash.test(keyHash)) throw new Error("invalid_api_key_hash");
	const mac = await crypto.subtle.sign("HMAC", await hmacKey(secret), encoder.encode(`aidr-pack-key-fingerprint-v1:${keyHash}`));
	return encode(new Uint8Array(mac));
}

export async function verifyPackKeyFingerprint(keyHash: string, fingerprint: string, secret: string): Promise<boolean> {
	if (!hash.test(keyHash) || !/^[A-Za-z0-9_-]{43}$/.test(fingerprint)) return false;
	try {
		return await crypto.subtle.verify(
			"HMAC",
			await hmacKey(secret),
			decode(fingerprint),
			encoder.encode(`aidr-pack-key-fingerprint-v1:${keyHash}`),
		);
	} catch {
		return false;
	}
}

export async function signPackDownloadGrant(grant: PackDownloadGrant, secret: string): Promise<string> {
	if (!validGrant({ ...grant, v: 1 }) || !validPackDownloadGrantSecret(secret)) throw new Error("invalid_pack_download_grant");
	const payload = encode(encoder.encode(JSON.stringify({ v: 1, ...grant })));
	const mac = await crypto.subtle.sign("HMAC", await hmacKey(secret), encoder.encode(`aidr-pack-download-grant-v1:${payload}`));
	return `${payload}.${encode(new Uint8Array(mac))}`;
}

export async function readPackDownloadGrant(
	value: unknown,
	secret: string,
	nowSeconds = Math.floor(Date.now() / 1_000),
): Promise<PackDownloadGrant | null> {
	try {
		if (typeof value !== "string" || value.length > 2_048 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) return null;
		const [payload, signature] = value.split(".");
		if (!await crypto.subtle.verify(
			"HMAC",
			await hmacKey(secret),
			decode(signature),
			encoder.encode(`aidr-pack-download-grant-v1:${payload}`),
		)) return null;
		const parsed: unknown = JSON.parse(new TextDecoder().decode(decode(payload)));
		if (!validGrant(parsed)) return null;
		if (parsed.expires_at <= nowSeconds || parsed.expires_at > nowSeconds + 3_600) return null;
		return {
			key_id: parsed.key_id,
			key_fingerprint: parsed.key_fingerprint,
			tenant_id: parsed.tenant_id,
			pack_id: parsed.pack_id,
			version: parsed.version,
			expires_at: parsed.expires_at,
		};
	} catch {
		return null;
	}
}

export function packDownloadUrl(supabaseUrl: string, grant: string): string {
	const url = new URL("/functions/v1/packs-download", supabaseUrl);
	url.searchParams.set("grant", grant);
	return url.toString();
}

/** Never issue an agent-facing link to an internal service name or an untrusted Host header. */
export function publicPackDownloadOrigin(
	internalUrl: string,
	configuredOrigin: string | undefined,
	development = false,
): string | null {
	try {
		const url = new URL(configuredOrigin ?? internalUrl);
		if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) return null;
		const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
		if (url.protocol !== "https:" && !(development && loopback && url.protocol === "http:")) return null;
		return url.origin;
	} catch {
		return null;
	}
}
