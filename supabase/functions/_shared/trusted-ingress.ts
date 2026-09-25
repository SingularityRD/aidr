// Signed client-IP proof from a trusted reverse proxy.
//
// Edge Functions must not infer a client IP from x-forwarded-for,
// cf-connecting-ip or x-real-ip: a direct caller controls those headers and
// could mint a fresh rate-limit bucket per request. A reverse proxy that owns
// the TCP peer instead strips any client-supplied x-aidr-client-* headers and
// adds the canonical remote IP, a Unix timestamp and an HMAC-SHA256 over
// `${context}\n${timestamp}\n${ip}`. The context binds a proof to one route, so
// a signature minted for one endpoint cannot be replayed against another.

const INGRESS_IP_HEADER = "x-aidr-client-ip";
const INGRESS_TIMESTAMP_HEADER = "x-aidr-client-timestamp";
const INGRESS_SIGNATURE_HEADER = "x-aidr-client-signature";
const INGRESS_MAX_CLOCK_SKEW_SECONDS = 60;
const INGRESS_MIN_SECRET_BYTES = 32;

/** A shared ingress secret must carry at least 256 bits of UTF-8 input. */
export function validIngressSecret(secret: string | null | undefined): secret is string {
	return typeof secret === "string" && new TextEncoder().encode(secret).length >= INGRESS_MIN_SECRET_BYTES;
}

/** Canonical dotted IPv4 or lower-case compressed IPv6; anything else is refused. */
function canonicalIp(value: string | null): string | null {
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

function constantTimeHexEqual(actual: string, expected: string): boolean {
	if (!/^[a-f0-9]{64}$/.test(actual) || expected.length !== 64) return false;
	let difference = 0;
	for (let i = 0; i < 64; i++) difference |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
	return difference === 0;
}

/**
 * Returns the proxy-attested client IP, or null when the proof is absent,
 * malformed, stale, bound to another context or signed with another secret.
 */
export async function verifiedIngressIp(
	req: Request,
	secret: string,
	context: string,
	nowMs: number = Date.now(),
): Promise<string | null> {
	const ip = canonicalIp(req.headers.get(INGRESS_IP_HEADER));
	const timestamp = req.headers.get(INGRESS_TIMESTAMP_HEADER);
	const signature = req.headers.get(INGRESS_SIGNATURE_HEADER);
	if (!ip || !timestamp || !signature || !/^(0|[1-9]\d{0,15})$/.test(timestamp)) return null;
	const seconds = Number(timestamp);
	if (
		!Number.isSafeInteger(seconds) ||
		Math.abs(Math.floor(nowMs / 1000) - seconds) > INGRESS_MAX_CLOCK_SKEW_SECONDS
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
