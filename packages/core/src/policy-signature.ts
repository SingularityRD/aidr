import { verifyEd25519CanonicalJson } from "./managed.js";

/**
 * Signed runtime policy envelope.
 *
 * Wire contract (produced by the landing control plane `signRuntimePolicyEnvelope`):
 *
 *   policy_signed: { alg: "ed25519", key_id, sig_b64, envelope }
 *
 * `sig_b64` is an Ed25519 signature over UTF-8 `canonicalJson(envelope)` (the same
 * recursive key-sorted JSON used for signed entitlements). The envelope binds the
 * policy digest, its version, a monotonic sequence and a validity window, and repeats
 * `key_id` inside the signed bytes so a key id cannot be relabelled to dodge revocation.
 */
type PolicyEnvelope = {
	schema_version: 1;
	key_id: string;
	policy_version: string;
	policy_sha256: string;
	sequence: number;
	issued_at: string;
	expires_at: string;
	tenant_id?: string;
};

type PolicySignatureFailure =
	| "missing_signature"
	| "malformed_signature"
	| "no_trusted_keys"
	| "bad_signature"
	| "key_revoked"
	| "binding_mismatch"
	| "not_yet_valid"
	| "expired"
	| "rollback";

export type PolicySignatureResult =
	| { ok: true; envelope: PolicyEnvelope }
	| { ok: false; reason: PolicySignatureFailure };

/** Highest policy previously accepted for this endpoint/token; used to refuse rollback and replay. */
export type PolicyHighWater = { sequence: number; policySha256: string };

const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
/** A signed policy may not claim a validity window longer than this. */
const MAX_VALIDITY_MS = 30 * 24 * 3_600_000;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const SHA256_HEX = /^[a-f0-9]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
	return !!value && typeof value === "object" && !Array.isArray(value);
}

function parseEnvelope(raw: unknown): PolicyEnvelope | null {
	if (!isRecord(raw) || raw.schema_version !== 1) return null;
	const { key_id, policy_version, policy_sha256, sequence, issued_at, expires_at, tenant_id } = raw;
	if (typeof key_id !== "string" || !key_id.trim()) return null;
	if (typeof policy_version !== "string" || !policy_version) return null;
	if (typeof policy_sha256 !== "string" || !SHA256_HEX.test(policy_sha256)) return null;
	if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) return null;
	if (
		typeof issued_at !== "string" ||
		!ISO_DATE.test(issued_at) ||
		!Number.isFinite(Date.parse(issued_at))
	)
		return null;
	if (
		typeof expires_at !== "string" ||
		!ISO_DATE.test(expires_at) ||
		!Number.isFinite(Date.parse(expires_at))
	)
		return null;
	if (tenant_id !== undefined && typeof tenant_id !== "string") return null;
	return raw as PolicyEnvelope;
}

/** Sequence of the signed envelope in a policy body, or null when unsigned/malformed (no signature check). */
export function policyBodySequence(
	body: Record<string, unknown> | undefined,
): PolicyHighWater | null {
	const signed = body?.policy_signed;
	if (!isRecord(signed) || !isRecord(signed.envelope)) return null;
	const { sequence, policy_sha256 } = signed.envelope;
	if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) return null;
	if (typeof policy_sha256 !== "string" || !SHA256_HEX.test(policy_sha256)) return null;
	return { sequence, policySha256: policy_sha256 };
}

/**
 * Verify a policy response body's `policy_signed` block. The caller must already have
 * validated `body.policy_sha256` against the canonical runtime policy; this binds that
 * digest, the version and the sequence to the signature.
 */
export function verifySignedPolicy(input: {
	body: Record<string, unknown> | undefined;
	publicKeysPem: string[];
	revokedKeyIds?: ReadonlySet<string>;
	now: number;
	/** Fetch-time anti-rollback check. Omit when re-validating an already accepted policy. */
	highWater?: PolicyHighWater | null;
}): PolicySignatureResult {
	if (input.publicKeysPem.length === 0) return { ok: false, reason: "no_trusted_keys" };
	const signed = input.body?.policy_signed;
	if (signed === undefined || signed === null) return { ok: false, reason: "missing_signature" };
	if (!isRecord(signed) || signed.alg !== "ed25519" || typeof signed.sig_b64 !== "string") {
		return { ok: false, reason: "malformed_signature" };
	}
	const envelope = parseEnvelope(signed.envelope);
	if (!envelope || signed.key_id !== envelope.key_id)
		return { ok: false, reason: "malformed_signature" };

	if (
		!verifyEd25519CanonicalJson({
			value: envelope,
			sig_b64: signed.sig_b64,
			public_keys_pem: input.publicKeysPem,
		})
	) {
		return { ok: false, reason: "bad_signature" };
	}
	if (input.revokedKeyIds?.has(envelope.key_id)) return { ok: false, reason: "key_revoked" };

	// Signature is authentic from here on; bind it to what the connector actually received.
	if (
		envelope.policy_sha256 !== input.body?.policy_sha256 ||
		envelope.policy_version !== input.body?.policy_version
	) {
		return { ok: false, reason: "binding_mismatch" };
	}
	const issuedAt = Date.parse(envelope.issued_at);
	const expiresAt = Date.parse(envelope.expires_at);
	if (expiresAt < issuedAt || expiresAt - issuedAt > MAX_VALIDITY_MS) {
		return { ok: false, reason: "malformed_signature" };
	}
	if (issuedAt > input.now + MAX_CLOCK_SKEW_MS) return { ok: false, reason: "not_yet_valid" };
	if (input.now >= expiresAt) return { ok: false, reason: "expired" };

	const high = input.highWater;
	if (high) {
		if (envelope.sequence < high.sequence) return { ok: false, reason: "rollback" };
		// Same sequence must be the same policy; a different digest is a conflicting replay.
		if (envelope.sequence === high.sequence && envelope.policy_sha256 !== high.policySha256) {
			return { ok: false, reason: "rollback" };
		}
	}
	return { ok: true, envelope };
}
