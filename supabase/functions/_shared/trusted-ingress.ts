// Trusted-ingress client IP proof (single shared helper for every route).
//
// The reverse proxy (deploy/cloudflare/worker.mjs or deploy/ingress) owns the
// TCP peer: it removes any client-supplied x-aidr-client-* headers and adds a
// canonical remote IP, a Unix timestamp and an HMAC-SHA256 signature over
// `${context}\n${timestamp}\n${ip}`. Functions must never infer a client IP from
// x-forwarded-for, cf-connecting-ip or x-real-ip: a direct caller controls those
// headers and could mint a fresh rate-limit bucket per request. The per-route
// context domain-separates signatures, so a proof minted for one endpoint
// (device-start:v1, device-poll:v1, identity-security:v1, waitlist-signup:v1, …)
// cannot be replayed against another.

export const INGRESS_IP_HEADER = "x-aidr-client-ip";
export const INGRESS_TIMESTAMP_HEADER = "x-aidr-client-timestamp";
export const INGRESS_SIGNATURE_HEADER = "x-aidr-client-signature";
// Shared with device-start; the proxy uses one signing secret for all contexts.
export const INGRESS_SECRET_ENV = "AIDR_DEVICE_START_INGRESS_SECRET";
const MAX_CLOCK_SKEW_SECONDS = 60;
const MIN_SECRET_BYTES = 32;

/** Canonical dotted IPv4 or lower-case compressed IPv6; anything else is refused. */
export function canonicalIp(value: string | null): string | null {
	if (!value || value.length > 45 || value !== value.trim()) return null;
	if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) {
		const parts = value.split(".");
		if (parts.some((part) => Number(part) > 255 || (part.length > 1 && part.startsWith("0")))) return null;
		return value;
	}
	if (!value.includes(":") || !/^[0-9a-fA-F:]+$/.test(value)) return null;
	try {
		const hostname = new URL(`http://[${value}]/`).hostname;
		return hostname.slice(1, -1).toLowerCase();
	} catch {
		return null;
	}
}

/** A shared ingress secret must carry at least 256 bits of UTF-8 input. */
export function validIngressSecret(secret: string | null | undefined): secret is string {
	return typeof secret === "string" && new TextEncoder().encode(secret).length >= MIN_SECRET_BYTES;
}

function constantTimeHexEqual(actual: string, expected: string): boolean {
	if (!/^[a-f0-9]{64}$/.test(actual) || expected.length !== 64) return false;
	let difference = 0;
	for (let i = 0; i < 64; i++) difference |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
	return difference === 0;
}

/**
 * Returns the proxy-attested client IP, or null when the secret is too short or
 * the proof is absent, malformed, stale, bound to another context or signed with
 * another secret.
 */
export async function verifiedIngressIp(
	req: Request,
	secret: string,
	context: string,
	nowMs: number = Date.now(),
): Promise<string | null> {
	if (!validIngressSecret(secret)) return null;
	const ip = canonicalIp(req.headers.get(INGRESS_IP_HEADER));
	const timestamp = req.headers.get(INGRESS_TIMESTAMP_HEADER);
	const signature = req.headers.get(INGRESS_SIGNATURE_HEADER);
	if (!ip || !timestamp || !signature || !/^(0|[1-9]\d{0,15})$/.test(timestamp)) return null;
	const seconds = Number(timestamp);
	if (
		!Number.isSafeInteger(seconds) ||
		Math.abs(Math.floor(nowMs / 1000) - seconds) > MAX_CLOCK_SKEW_SECONDS
	) {
		return null;
	}
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const signed = await crypto.subtle.sign(
		"HMAC",
		key,
		new TextEncoder().encode(`${context}\n${timestamp}\n${ip}`),
	);
	const expected = Array.from(new Uint8Array(signed), (byte) => byte.toString(16).padStart(2, "0")).join("");
	return constantTimeHexEqual(signature, expected) ? ip : null;
}

/** Stable, non-reversible bucket component for a verified client IP. */
export async function ingressIpBucket(ip: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ip));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
