import { describe, expect, it } from "vitest";
import {
	computeStripeSignatureHex,
	constantTimeEqual,
	DEFAULT_TOLERANCE_SECONDS,
	hexToBytes,
	MAX_TOLERANCE_SECONDS,
	parseStripeSignatureHeader,
	resolveToleranceSeconds,
	verifyStripeWebhookSignature,
} from "../verify.ts";

// A placeholder endpoint secret. It is not a real Stripe secret and is only
// used to derive signatures inside this test process.
const SECRET = "whsec_test_placeholder_not_a_real_secret";
const OTHER_SECRET = "whsec_test_placeholder_other_secret";
const NOW = 1_760_000_000; // fixed unix seconds so the replay window is deterministic

const BODY = JSON.stringify({
	id: "evt_test_00000000000001",
	type: "customer.subscription.updated",
	data: { object: { id: "sub_test_1", status: "active" } },
});

async function signedHeader(
	body: string,
	options: { secret?: string; timestamp?: number; extraV1?: string[] } = {},
): Promise<string> {
	const secret = options.secret ?? SECRET;
	const timestamp = options.timestamp ?? NOW;
	const signature = await computeStripeSignatureHex(secret, timestamp, body);
	const parts = [`t=${timestamp}`, `v1=${signature}`];
	for (const extra of options.extraV1 ?? []) parts.push(`v1=${extra}`);
	return parts.join(",");
}

describe("stripe signature verification", () => {
	it("accepts a valid signature", async () => {
		const result = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: await signedHeader(BODY),
			secret: SECRET,
			nowSeconds: NOW,
		});

		expect(result).toEqual({ ok: true, timestamp: NOW, matchedSignatures: 1 });
	});

	it("accepts a valid signature inside the tolerance window", async () => {
		const result = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: await signedHeader(BODY, { timestamp: NOW - 299 }),
			secret: SECRET,
			nowSeconds: NOW,
		});

		expect(result.ok).toBe(true);
	});

	it("rejects a tampered body", async () => {
		const header = await signedHeader(BODY);
		const tampered = JSON.stringify({
			id: "evt_test_00000000000001",
			type: "customer.subscription.updated",
			data: { object: { id: "sub_test_1", status: "active", extra_agents: 99 } },
		});

		const result = await verifyStripeWebhookSignature({
			rawBody: tampered,
			signatureHeader: header,
			secret: SECRET,
			nowSeconds: NOW,
		});

		expect(result).toEqual({ ok: false, reason: "signature_mismatch" });
	});

	it("rejects a signature computed with the wrong secret", async () => {
		const result = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: await signedHeader(BODY, { secret: OTHER_SECRET }),
			secret: SECRET,
			nowSeconds: NOW,
		});

		expect(result).toEqual({ ok: false, reason: "signature_mismatch" });
	});

	it("rejects a missing signature header", async () => {
		for (const header of [null, undefined, "", "   "]) {
			const result = await verifyStripeWebhookSignature({
				rawBody: BODY,
				signatureHeader: header,
				secret: SECRET,
				nowSeconds: NOW,
			});
			expect(result).toEqual({ ok: false, reason: "missing_signature_header" });
		}
	});

	it("rejects a missing endpoint secret instead of trusting the payload", async () => {
		const result = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: await signedHeader(BODY),
			secret: "   ",
			nowSeconds: NOW,
		});

		expect(result).toEqual({ ok: false, reason: "missing_secret" });
	});

	it("rejects a stale timestamp outside the tolerance window", async () => {
		const result = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: await signedHeader(BODY, { timestamp: NOW - 301 }),
			secret: SECRET,
			nowSeconds: NOW,
		});

		expect(result).toEqual({ ok: false, reason: "timestamp_out_of_tolerance" });
	});

	it("rejects a future timestamp outside the tolerance window", async () => {
		const result = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: await signedHeader(BODY, { timestamp: NOW + 4000 }),
			secret: SECRET,
			nowSeconds: NOW,
		});

		expect(result).toEqual({ ok: false, reason: "timestamp_out_of_tolerance" });
	});

	it("honours a custom tolerance window", async () => {
		const header = await signedHeader(BODY, { timestamp: NOW - 600 });

		const strict = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: header,
			secret: SECRET,
			toleranceSeconds: 300,
			nowSeconds: NOW,
		});
		const relaxed = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: header,
			secret: SECRET,
			toleranceSeconds: 900,
			nowSeconds: NOW,
		});

		expect(strict.ok).toBe(false);
		expect(relaxed.ok).toBe(true);
	});

	it("treats a non-numeric tolerance as the 300s default instead of skipping the check", async () => {
		// Regression guard for the Paddle handler defect where a NaN tolerance
		// makes the freshness comparison false and silently disables the window.
		const stale = await signedHeader(BODY, { timestamp: NOW - 3600 });

		for (const tolerance of ["not-a-number", "", Number.NaN, undefined, null, -5, Number.POSITIVE_INFINITY]) {
			expect(resolveToleranceSeconds(tolerance)).toBe(DEFAULT_TOLERANCE_SECONDS);

			const result = await verifyStripeWebhookSignature({
				rawBody: BODY,
				signatureHeader: stale,
				secret: SECRET,
				toleranceSeconds: tolerance,
				nowSeconds: NOW,
			});
			expect(result).toEqual({ ok: false, reason: "timestamp_out_of_tolerance" });
		}
	});

	it("parses an explicit numeric tolerance", () => {
		expect(resolveToleranceSeconds("120")).toBe(120);
		expect(resolveToleranceSeconds(0)).toBe(0);
		expect(resolveToleranceSeconds("300")).toBe(300);
		expect(resolveToleranceSeconds("3600")).toBe(MAX_TOLERANCE_SECONDS);
		expect(resolveToleranceSeconds(3600)).toBe(3600);
	});

	it("refuses a tolerance above one hour instead of widening the replay window", async () => {
		const timestamp = NOW - 7200;
		const stale = `t=${timestamp},v1=${await computeStripeSignatureHex(SECRET, timestamp, BODY)}`;
		for (const tolerance of ["3601", 3601, "86400", 1e9, "999999999999"]) {
			expect(resolveToleranceSeconds(tolerance)).toBe(DEFAULT_TOLERANCE_SECONDS);
			const result = await verifyStripeWebhookSignature({
				rawBody: BODY,
				signatureHeader: stale,
				secret: SECRET,
				toleranceSeconds: tolerance,
				nowSeconds: NOW,
			});
			expect(result).toEqual({ ok: false, reason: "timestamp_out_of_tolerance" });
		}
	});

	it("accepts when one of several v1 signatures matches", async () => {
		const valid = await computeStripeSignatureHex(SECRET, NOW, BODY);
		const header = [
			`t=${NOW}`,
			"v1=0000000000000000000000000000000000000000000000000000000000000000",
			`v1=${valid}`,
			"v1=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		].join(",");

		const result = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: header,
			secret: SECRET,
			nowSeconds: NOW,
		});

		expect(result).toEqual({ ok: true, timestamp: NOW, matchedSignatures: 1 });
	});

	it("rejects when none of several v1 signatures match", async () => {
		const header = [
			`t=${NOW}`,
			"v1=1111111111111111111111111111111111111111111111111111111111111111",
			"v1=2222222222222222222222222222222222222222222222222222222222222222",
		].join(",");

		const result = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: header,
			secret: SECRET,
			nowSeconds: NOW,
		});

		expect(result).toEqual({ ok: false, reason: "signature_mismatch" });
	});

	it("accepts when one of several timestamps is fresh and matches", async () => {
		const staleSignature = await computeStripeSignatureHex(SECRET, NOW - 7200, BODY);
		const freshSignature = await computeStripeSignatureHex(SECRET, NOW, BODY);
		const header = `t=${NOW - 7200},v1=${staleSignature},t=${NOW},v1=${freshSignature}`;

		const result = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: header,
			secret: SECRET,
			nowSeconds: NOW,
		});

		expect(result).toEqual({ ok: true, timestamp: NOW, matchedSignatures: 1 });
	});

	it("ignores unrelated header keys and tolerates whitespace", async () => {
		const signature = await computeStripeSignatureHex(SECRET, NOW, BODY);
		const header = ` scheme=v1 , t=${NOW} , v0=deadbeef , v1=${signature} `;

		const result = await verifyStripeWebhookSignature({
			rawBody: BODY,
			signatureHeader: header,
			secret: SECRET,
			nowSeconds: NOW,
		});

		expect(result.ok).toBe(true);
	});

	it("rejects a malformed header with no usable v1 value", async () => {
		for (const header of ["t=1760000000", "garbage", "t=1760000000,v1=zzzz", "v1=abc"]) {
			const result = await verifyStripeWebhookSignature({
				rawBody: BODY,
				signatureHeader: header,
				secret: SECRET,
				nowSeconds: NOW,
			});
			expect(result.ok).toBe(false);
		}
	});
});

describe("stripe signature header parsing", () => {
	it("collects multiple v1 values in order", () => {
		const parsed = parseStripeSignatureHeader("t=1,v1=aa,v1=bb,v0=cc");
		expect(parsed).toEqual({ timestamps: [1], signatures: ["aa", "bb"] });
	});

	it("returns null for a missing header", () => {
		expect(parseStripeSignatureHeader(null)).toBeNull();
		expect(parseStripeSignatureHeader("")).toBeNull();
	});

	it("drops non-numeric timestamps", () => {
		expect(parseStripeSignatureHeader("t=abc,v1=aa")).toEqual({ timestamps: [], signatures: ["aa"] });
		expect(parseStripeSignatureHeader("t=1e9,v1=aa")).toEqual({ timestamps: [], signatures: ["aa"] });
	});

	it("lower-cases and de-duplicates signatures", () => {
		expect(parseStripeSignatureHeader("t=5,v1=AA,v1=aa")).toEqual({
			timestamps: [5],
			signatures: ["aa"],
		});
	});
});

describe("hex helpers", () => {
	it("round-trips bytes", () => {
		expect(hexToBytes("00ff10")).toEqual(new Uint8Array([0, 255, 16]));
		expect(hexToBytes("zz")).toBeNull();
		expect(hexToBytes("abc")).toBeNull();
	});

	it("compares bytes without leaking position through the result", () => {
		const a = new Uint8Array([1, 2, 3]);
		expect(constantTimeEqual(a, new Uint8Array([1, 2, 3]))).toBe(true);
		expect(constantTimeEqual(a, new Uint8Array([1, 2, 4]))).toBe(false);
		expect(constantTimeEqual(a, new Uint8Array([1, 2]))).toBe(false);
	});
});
