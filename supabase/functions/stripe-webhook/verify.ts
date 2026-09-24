// Stripe webhook signature verification (pure, dependency-free).
//
// Stripe signs the *raw* request body, so the caller MUST read the body as
// text before any JSON parsing. The signature header looks like:
//
//   Stripe-Signature: t=1700000000,v1=<hex>,v1=<hex>
//
// The HMAC-SHA256 is computed over `${t}.${rawBody}` with the endpoint secret
// and compared, in constant time, against every `v1` value in the header
// (Stripe sends more than one during secret rotation). The header may also
// carry unrelated keys (`v0`, `scheme`, ...); those are ignored.
//
// This module intentionally imports nothing Deno-, Node-, or SDK-specific so
// the exact code shipped inside the Edge Function is the code exercised by the
// vitest suite in ./__tests__.

/** Stripe's documented default replay tolerance. */
export const DEFAULT_TOLERANCE_SECONDS = 300;

/** Upper bound for a plausible unix-seconds timestamp (12 digits). */
const UNIX_SECONDS = /^\d{1,12}$/;

/** Lower-case hexadecimal of even length. */
const HEX = /^[0-9a-f]+$/;

type StripeSignatureFailure =
	| "missing_secret"
	| "missing_signature_header"
	| "malformed_signature_header"
	| "invalid_timestamp"
	| "timestamp_out_of_tolerance"
	| "signature_mismatch";

export type StripeSignatureVerification =
	| { ok: true; timestamp: number; matchedSignatures: number }
	| { ok: false; reason: StripeSignatureFailure };

export interface ParsedStripeSignatureHeader {
	/** Every `t=` value that parsed as unix seconds, in header order. */
	timestamps: number[];
	/** Every `v1=` value, lower-cased and de-duplicated, in header order. */
	signatures: string[];
}

/**
 * Resolve the configured replay tolerance.
 *
 * Anything that is not a finite, non-negative number falls back to
 * `DEFAULT_TOLERANCE_SECONDS`. This is the guard against the "NaN disables the
 * replay window" defect: `Number.isFinite` is checked explicitly instead of
 * relying on a NaN comparison, which is always false and would therefore skip
 * the freshness check entirely.
 */
export function resolveToleranceSeconds(value: unknown): number {
	if (typeof value === "number") {
		return Number.isFinite(value) && value >= 0
			? Math.floor(value)
			: DEFAULT_TOLERANCE_SECONDS;
	}
	if (typeof value === "string") {
		const trimmed = value.trim();
		// Strict parse: `Number("")` is 0 and `Number("300s")` is NaN, and a NaN
		// tolerance must never be allowed to disable the replay window.
		if (/^\d+(?:\.\d+)?$/.test(trimmed)) {
			const parsed = Number(trimmed);
			if (Number.isFinite(parsed) && parsed >= 0) return Math.floor(parsed);
		}
	}
	return DEFAULT_TOLERANCE_SECONDS;
}

/**
 * Parse a `Stripe-Signature` header.
 *
 * Returns `null` only when the header is absent or blank; a present-but-junk
 * header yields empty arrays so the caller can distinguish "no signature" from
 * "garbage signature".
 */
export function parseStripeSignatureHeader(
	raw: string | null | undefined,
): ParsedStripeSignatureHeader | null {
	if (typeof raw !== "string" || raw.trim() === "") return null;

	const timestamps: number[] = [];
	const signatures: string[] = [];

	for (const part of raw.split(",")) {
		const item = part.trim();
		if (!item) continue;
		const separator = item.indexOf("=");
		if (separator <= 0) continue;
		const key = item.slice(0, separator).trim().toLowerCase();
		const value = item.slice(separator + 1).trim();
		if (!value) continue;

		if (key === "t") {
			if (!UNIX_SECONDS.test(value)) continue;
			const parsed = Number(value);
			if (Number.isSafeInteger(parsed) && !timestamps.includes(parsed)) {
				timestamps.push(parsed);
			}
			continue;
		}

		if (key === "v1") {
			const lowered = value.toLowerCase();
			if (lowered.length % 2 !== 0 || !HEX.test(lowered)) continue;
			if (!signatures.includes(lowered)) signatures.push(lowered);
		}
	}

	return { timestamps, signatures };
}

export function hexToBytes(hex: string): Uint8Array | null {
	if (typeof hex !== "string") return null;
	const lowered = hex.toLowerCase();
	if (lowered.length === 0 || lowered.length % 2 !== 0 || !HEX.test(lowered)) return null;
	const bytes = new Uint8Array(lowered.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = Number.parseInt(lowered.slice(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
	let out = "";
	for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
	return out;
}

/**
 * Length-independent comparison of two byte strings.
 *
 * The XOR accumulator visits every byte so the running time does not depend on
 * the position of the first difference. A length mismatch returns early, which
 * leaks only the length of a value the caller already supplied.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
	return diff === 0;
}

/** HMAC-SHA256(`${timestamp}.${rawBody}`) as lower-case hex. */
export async function computeStripeSignatureHex(
	secret: string,
	timestamp: number | string,
	rawBody: string,
): Promise<string> {
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(`${timestamp}.${rawBody}`));
	return bytesToHex(new Uint8Array(mac));
}

export interface VerifyStripeWebhookSignatureInput {
	/** Raw request body, read as text and never re-serialised. */
	rawBody: string;
	/** Value of the `Stripe-Signature` header. */
	signatureHeader: string | null | undefined;
	/** Stripe endpoint secret (`whsec_...` / `STRIPE_WEBHOOK_SECRET`). */
	secret: string | null | undefined;
	/** Replay window in seconds. Invalid values fall back to 300. */
	toleranceSeconds?: unknown;
	/** Unix seconds; injectable so tests are deterministic. */
	nowSeconds?: number;
}

/**
 * Verify a Stripe webhook signature.
 *
 * A signature is accepted only when its own timestamp is inside the replay
 * window *and* the HMAC for that timestamp matches one of the supplied `v1`
 * values. Stale timestamps are rejected before any HMAC comparison, so a
 * captured request cannot be replayed later.
 */
export async function verifyStripeWebhookSignature(
	input: VerifyStripeWebhookSignatureInput,
): Promise<StripeSignatureVerification> {
	const secret = typeof input.secret === "string" ? input.secret.trim() : "";
	if (!secret) return { ok: false, reason: "missing_secret" };

	const parsed = parseStripeSignatureHeader(input.signatureHeader);
	if (parsed === null) return { ok: false, reason: "missing_signature_header" };
	if (parsed.signatures.length === 0) {
		return { ok: false, reason: "malformed_signature_header" };
	}
	if (parsed.timestamps.length === 0) return { ok: false, reason: "invalid_timestamp" };

	const tolerance = resolveToleranceSeconds(input.toleranceSeconds);
	const now = Number.isFinite(input.nowSeconds)
		? Math.floor(input.nowSeconds as number)
		: Math.floor(Date.now() / 1000);

	const provided = parsed.signatures
		.map((signature) => hexToBytes(signature))
		.filter((bytes): bytes is Uint8Array => bytes !== null);
	if (provided.length === 0) return { ok: false, reason: "malformed_signature_header" };

	let sawFreshTimestamp = false;

	for (const timestamp of parsed.timestamps) {
		// Freshness is enforced per candidate timestamp, before any HMAC work.
		if (Math.abs(now - timestamp) > tolerance) continue;
		sawFreshTimestamp = true;

		const expected = hexToBytes(await computeStripeSignatureHex(secret, timestamp, input.rawBody));
		if (expected === null) return { ok: false, reason: "signature_mismatch" };

		let matched = 0;
		for (const candidate of provided) {
			if (constantTimeEqual(expected, candidate)) matched++;
		}
		if (matched > 0) return { ok: true, timestamp, matchedSignatures: matched };
	}

	return {
		ok: false,
		reason: sawFreshTimestamp ? "signature_mismatch" : "timestamp_out_of_tolerance",
	};
}
