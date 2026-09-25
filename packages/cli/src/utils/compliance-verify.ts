import { createHash, createPublicKey, type KeyObject, verify } from "node:crypto";

/**
 * Offline verification of a Singularity AIDR compliance evidence report
 * (`aidr.compliance-report/v1`, see docs/compliance-report.md).
 *
 * The report's `integrity` block carries the SHA-256 of the canonical JSON of
 * everything except `integrity` itself and, when the issuing control plane has a
 * signing key, an Ed25519 signature over those same canonical bytes. This module
 * recomputes both with node:crypto only; it never contacts the control plane.
 *
 * A signature checked only against the key embedded in the report proves that
 * the report was not altered after signing by whoever holds that key. Pinning the
 * operator's published public key (`publicKeyPem`) additionally proves who issued it.
 */

const COMPLIANCE_REPORT_SCHEMA = "aidr.compliance-report/v1";
const COMPLIANCE_CANONICALIZATION = "aidr-canonical-json/v1";

type SignatureStatus = "valid" | "invalid" | "absent";

export interface ComplianceVerification {
	/** true only when every requested check passed. */
	ok: boolean;
	schema: string | null;
	reportId: string | null;
	tenantId: string | null;
	period: { from: string; to: string } | null;
	sha256: { recorded: string | null; computed: string | null; valid: boolean };
	signature: SignatureStatus;
	keyId: string | null;
	/** null when no public key was pinned; otherwise whether it matched the signer. */
	keyPinned: boolean | null;
	/** Static reason codes; never report content. */
	problems: string[];
}

export interface ComplianceVerifyOptions {
	/** PEM (SPKI) public key the report must be signed with. */
	publicKeyPem?: string;
	/** Fail when the report carries no signature. */
	requireSignature?: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function canonicalize(value: unknown): unknown {
	if (value === null || typeof value === "string" || typeof value === "boolean") return value;
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new Error("non_finite_number");
		return value;
	}
	if (Array.isArray(value)) return value.map(canonicalize);
	if (isRecord(value)) {
		const out: Record<string, unknown> = {};
		for (const key of Object.keys(value).sort()) out[key] = canonicalize(value[key]);
		return out;
	}
	throw new Error("unsupported_value");
}

/** aidr-canonical-json/v1: sorted keys at every level, arrays in order, no whitespace. */
export function canonicalJson(value: unknown): string {
	return JSON.stringify(canonicalize(value));
}

function stringOrNull(value: unknown): string | null {
	return typeof value === "string" ? value : null;
}

function spkiDer(key: KeyObject): Buffer {
	return key.export({ format: "der", type: "spki" });
}

/** Accept the bare report or the Edge Function response `{ ok, report }`. */
function unwrapComplianceReport(value: unknown): unknown {
	if (isRecord(value) && value.ok === true && isRecord(value.report) && !("integrity" in value)) {
		return value.report;
	}
	return value;
}

// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: each check records its own reason code
export function verifyComplianceReport(
	input: unknown,
	options: ComplianceVerifyOptions = {},
): ComplianceVerification {
	const problems: string[] = [];
	const report = unwrapComplianceReport(input);
	const result: ComplianceVerification = {
		ok: false,
		schema: null,
		reportId: null,
		tenantId: null,
		period: null,
		sha256: { recorded: null, computed: null, valid: false },
		signature: "absent",
		keyId: null,
		keyPinned: null,
		problems,
	};
	if (!isRecord(report)) {
		problems.push("not_a_report");
		return result;
	}
	result.schema = stringOrNull(report.schema);
	result.reportId = stringOrNull(report.report_id);
	const sections = isRecord(report.sections) ? report.sections : {};
	const profile = isRecord(sections.tenant_profile) ? sections.tenant_profile : {};
	result.tenantId = stringOrNull(profile.tenant_id);
	if (
		isRecord(report.period) &&
		typeof report.period.from === "string" &&
		typeof report.period.to === "string"
	) {
		result.period = { from: report.period.from, to: report.period.to };
	}
	if (result.schema !== COMPLIANCE_REPORT_SCHEMA) problems.push("unsupported_schema");

	const integrity = report.integrity;
	if (!isRecord(integrity)) {
		problems.push("missing_integrity");
		return result;
	}
	if (
		integrity.canonicalization !== COMPLIANCE_CANONICALIZATION ||
		integrity.hash_algorithm !== "sha256" ||
		integrity.hashed_scope !== "report_without_integrity"
	) {
		problems.push("unsupported_integrity_method");
	}
	result.sha256.recorded = stringOrNull(integrity.sha256);

	const { integrity: _omit, ...body } = report;
	let canonical: string;
	try {
		canonical = canonicalJson(body);
	} catch {
		problems.push("not_canonicalizable");
		return result;
	}
	const computed = createHash("sha256").update(canonical, "utf8").digest("hex");
	result.sha256.computed = computed;
	result.sha256.valid =
		typeof result.sha256.recorded === "string" && /^[a-f0-9]{64}$/.test(result.sha256.recorded)
			? result.sha256.recorded === computed
			: false;
	if (!result.sha256.valid) problems.push("hash_mismatch");

	let pinned: KeyObject | null = null;
	if (options.publicKeyPem !== undefined) {
		try {
			pinned = createPublicKey(options.publicKeyPem);
			if (pinned.asymmetricKeyType !== "ed25519") throw new Error("not_ed25519");
		} catch {
			problems.push("invalid_pinned_key");
			pinned = null;
			result.keyPinned = false;
		}
	}

	const signature = integrity.signature;
	if (signature === null || signature === undefined) {
		result.signature = "absent";
		if (options.requireSignature) problems.push("signature_required");
		if (options.publicKeyPem !== undefined) {
			result.keyPinned = false;
			problems.push("signature_required");
		}
	} else if (!isRecord(signature)) {
		result.signature = "invalid";
		problems.push("malformed_signature");
	} else {
		result.keyId = stringOrNull(signature.key_id);
		let embedded: KeyObject | null = null;
		try {
			if (
				signature.algorithm !== "ed25519" ||
				signature.signed_payload !== "canonical_json_utf8" ||
				typeof signature.public_key_spki_b64 !== "string" ||
				typeof signature.value_b64 !== "string"
			) {
				throw new Error("malformed");
			}
			embedded = createPublicKey({
				key: Buffer.from(signature.public_key_spki_b64, "base64"),
				format: "der",
				type: "spki",
			});
			if (embedded.asymmetricKeyType !== "ed25519") throw new Error("not_ed25519");
		} catch {
			embedded = null;
		}
		if (!embedded) {
			result.signature = "invalid";
			problems.push("malformed_signature");
		} else {
			if (pinned) {
				result.keyPinned = spkiDer(pinned).equals(spkiDer(embedded));
				if (!result.keyPinned) problems.push("signer_key_not_pinned_key");
			}
			// Verify with the pinned key when one is given, so a swapped embedded
			// key cannot vouch for itself.
			const key = pinned ?? embedded;
			const valid = verify(
				null,
				Buffer.from(canonical, "utf8"),
				key,
				Buffer.from(String(signature.value_b64), "base64"),
			);
			result.signature = valid ? "valid" : "invalid";
			if (!valid) problems.push("signature_invalid");
		}
	}

	result.ok = problems.length === 0;
	return result;
}
