// Ed25519-signed runtime policy envelope for connectors.
//
// Wire contract (verified by `verifySignedPolicy` in packages/core/src/policy-signature.ts and
// produced identically by the landing control plane `signRuntimePolicyEnvelope`):
//
//   policy_signed: { alg: "ed25519", key_id, sig_b64, envelope }
//
// `sig_b64` is an Ed25519 signature over UTF-8 `canonicalJson(envelope)`. Edge Functions are
// deployed independently of the workspace packages and cannot import packages/core, so the
// canonicalisation is copied here; supabase/functions/__tests__/policy-signature.test.ts
// compares it with core over a corpus and runs the real core verifier on this module's output.
//
// Key provisioning mirrors the entitlement key: a dedicated policy key is recommended so a leaked
// policy key cannot mint entitlements. With no policy key the entitlement signing key is reused
// (matching the connector falling back from control_plane.policy_public_keys_pem to
// licensing.public_keys_pem). With neither the policy is served unsigned.
import { type EnvReader, isConfiguredValue } from "./config.ts";

export type PolicyEnvelope = {
	schema_version: 1;
	key_id: string;
	policy_version: string;
	policy_sha256: string;
	sequence: number;
	issued_at: string;
	expires_at: string;
	tenant_id: string;
};

export type SignedPolicy = {
	alg: "ed25519";
	key_id: string;
	sig_b64: string;
	envelope: PolicyEnvelope;
};

export type PolicySigningConfig = { keyId: string; pkcs8B64: string; ttlHours: number };

/** Stable machine-readable code for a half-configured or unusable signing setup (HTTP 503). */
export const POLICY_SIGNING_UNAVAILABLE = "policy_signing_unavailable";

/** Same recursive key-sorted form as `canonicalizeForSigning` in packages/core/src/managed.ts. */
function canonicalizeForSigning(value: unknown): unknown {
	if (Array.isArray(value)) return value.map((v) => canonicalizeForSigning(v));
	if (!value || typeof value !== "object") return value;
	const obj = value as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(obj).sort()) out[key] = canonicalizeForSigning(obj[key]);
	return out;
}

export function canonicalJson(value: unknown): string {
	return JSON.stringify(canonicalizeForSigning(value));
}

function parseTtlHours(env: EnvReader): number | null {
	const raw = (env("AIDR_POLICY_SIGNATURE_TTL_HOURS") ?? "").trim();
	const ttl = raw === "" ? 24 : /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
	return Number.isSafeInteger(ttl) && ttl >= 1 && ttl <= 720 ? ttl : null;
}

export type PolicySigningSetup =
	| { ok: true; config: PolicySigningConfig | null }
	| { ok: false; error: typeof POLICY_SIGNING_UNAVAILABLE };

/**
 * `config: null` means signing is not provisioned (serve unsigned). A half-configured pair
 * (policy or, when falling back, entitlement) or an invalid TTL fails closed.
 */
export function resolvePolicySigning(env: EnvReader): PolicySigningSetup {
	const keyId = (env("AIDR_POLICY_SIGNING_KEY_ID") ?? "").trim();
	const b64 = (env("AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64") ?? "").trim();
	const unavailable = { ok: false, error: POLICY_SIGNING_UNAVAILABLE } as const;
	let pair: { keyId: string; pkcs8B64: string } | null = null;
	if (keyId || b64) {
		if (!keyId || !b64) return unavailable;
		pair = { keyId, pkcs8B64: b64 };
	} else {
		const entKeyId = (env("AIDR_ENTITLEMENT_SIGNING_KEY_ID") ?? "").trim();
		const entB64 = (env("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64") ?? "").trim();
		if (isConfiguredValue(entKeyId) !== isConfiguredValue(entB64)) return unavailable;
		if (entKeyId && entB64) pair = { keyId: entKeyId, pkcs8B64: entB64 };
	}
	const ttlHours = parseTtlHours(env);
	if (ttlHours === null) return unavailable;
	return { ok: true, config: pair ? { ...pair, ttlHours } : null };
}

function bytesToBase64(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

/** Returns null when the key is unusable or the sequence is not a positive safe integer. */
export async function signRuntimePolicyEnvelope(
	input: { tenantId: string; policyVersion: string; policySha256: string; sequence: number; now: Date },
	config: PolicySigningConfig,
): Promise<SignedPolicy | null> {
	if (!Number.isSafeInteger(input.sequence) || input.sequence < 1) return null;
	const envelope: PolicyEnvelope = {
		schema_version: 1,
		key_id: config.keyId,
		policy_version: input.policyVersion,
		policy_sha256: input.policySha256,
		sequence: input.sequence,
		issued_at: input.now.toISOString(),
		expires_at: new Date(input.now.getTime() + config.ttlHours * 3_600_000).toISOString(),
		tenant_id: input.tenantId,
	};
	try {
		const pkcs8 = Uint8Array.from(atob(config.pkcs8B64), (c) => c.charCodeAt(0));
		const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
		const sig = await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(canonicalJson(envelope)));
		return { alg: "ed25519", key_id: config.keyId, sig_b64: bytesToBase64(new Uint8Array(sig)), envelope };
	} catch {
		return null;
	}
}

/** Latest of the given timestamps in epoch ms; null when none parse. */
export function policySequence(...timestamps: Array<string | null | undefined>): number | null {
	let best: number | null = null;
	for (const stamp of timestamps) {
		const ms = typeof stamp === "string" ? Date.parse(stamp) : Number.NaN;
		if (Number.isFinite(ms) && ms >= 1 && (best === null || ms > best)) best = ms;
	}
	return best;
}
