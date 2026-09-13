import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { verifyIncidentSqliteStore } from "./persist.js";

export interface IncidentAnchorPayloadV1 {
	type: "aidr_incident_anchor_payload";
	schema_version: 1;
	scope: string;
	created_at: string;
	public_key_fingerprint_sha256: string;
	checked_incidents: number;
	checked_revisions: number;
	/** Absent on earlier local receipts, which used host-locale collation. */
	head_order?: "utf16";
	/** Aggregate digest over every ordered incident chain head, without incident identifiers. */
	heads_sha256: string;
}

export interface SignedIncidentAnchorReceiptV1 {
	type: "aidr_incident_anchor_receipt";
	schema_version: 1;
	algorithm: "Ed25519";
	payload_base64: string;
	signature_base64: string;
}

export interface WriteIncidentAnchorOptions {
	sqlite_path: string;
	receipt_path: string;
	/** PEM Ed25519 private key file. Keep it outside the incident database and receipt store. */
	private_key_path: string;
	/** Explicit tenant/deployment/candidate boundary included in the signature. */
	scope: string;
}

export interface VerifyIncidentAnchorOptions {
	sqlite_path: string;
	receipt_path: string;
	public_key_path: string;
	expected_scope: string;
}

export interface IncidentAnchorVerification {
	valid: boolean;
	code:
		| "valid"
		| "receipt_invalid"
		| "signature_invalid"
		| "scope_mismatch"
		| "key_mismatch"
		| "store_invalid"
		| "anchor_state_mismatch"
		| "unavailable";
	checked_incidents?: number;
	checked_revisions?: number;
}

function keyFingerprint(publicKey: ReturnType<typeof createPublicKey>): string {
	const der = publicKey.export({ format: "der", type: "spki" });
	return createHash("sha256").update(der).digest("hex");
}

function headsDigest(
	heads: Array<{ incident_id: string; revision_number: number; record_hash: string }>,
	order: "utf16" | "legacy_locale" = "utf16",
): string {
	const hash = createHash("sha256").update("aidr.incident.heads.v1\0");
	// Locale collation differs by host and ICU configuration. The signed digest
	// must use the same UTF-16 code-unit ordering on every verifier.
	for (const head of [...heads].sort((a, b) =>
		order === "legacy_locale"
			? a.incident_id.localeCompare(b.incident_id)
			: a.incident_id < b.incident_id
				? -1
				: a.incident_id > b.incident_id
					? 1
					: 0,
	))
		hash
			.update(JSON.stringify([head.incident_id, head.revision_number, head.record_hash]))
			.update("\n");
	return hash.digest("hex");
}

function nonEmptyScope(scope: string): boolean {
	return (
		scope.length > 0 && scope.length <= 256 && scope === scope.trim() && !/[\x00-\x1f]/.test(scope)
	);
}

function requireDistinctPaths(paths: string[]): void {
	const normalized = paths.map((path) => {
		const absolute = resolve(path);
		return process.platform === "win32" ? absolute.toLowerCase() : absolute;
	});
	if (new Set(normalized).size !== paths.length)
		throw new Error("Incident database, receipt, and key paths must be distinct");
}

function decodeCanonicalBase64(value: unknown): Buffer | null {
	if (typeof value !== "string" || value.length === 0 || value.length > 1_000_000) return null;
	const bytes = Buffer.from(value, "base64");
	return bytes.toString("base64") === value ? bytes : null;
}

function readPayload(bytes: Buffer): IncidentAnchorPayloadV1 | null {
	try {
		const payload = JSON.parse(bytes.toString("utf8")) as IncidentAnchorPayloadV1;
		if (
			payload.type !== "aidr_incident_anchor_payload" ||
			payload.schema_version !== 1 ||
			!nonEmptyScope(payload.scope) ||
			typeof payload.created_at !== "string" ||
			!Number.isFinite(Date.parse(payload.created_at)) ||
			!/^[a-f0-9]{64}$/.test(payload.public_key_fingerprint_sha256) ||
			!Number.isSafeInteger(payload.checked_incidents) ||
			payload.checked_incidents < 0 ||
			!Number.isSafeInteger(payload.checked_revisions) ||
			payload.checked_revisions < 0 ||
			(payload.head_order !== undefined && payload.head_order !== "utf16") ||
			!/^[a-f0-9]{64}$/.test(payload.heads_sha256)
		)
			return null;
		return payload;
	} catch {
		return null;
	}
}

function anchorStateMatches(
	payload: IncidentAnchorPayloadV1,
	local: Awaited<ReturnType<typeof verifyIncidentSqliteStore>>,
): boolean {
	const order = payload.head_order === "utf16" ? "utf16" : "legacy_locale";
	return (
		payload.checked_incidents === local.checked_incidents &&
		payload.checked_revisions === local.checked_revisions &&
		payload.heads_sha256 === headsDigest(local.heads, order)
	);
}

/**
 * Write a signed, immutable-on-create receipt beside—not inside—the database.
 * The private key is read from a separate PEM file and is never serialized.
 * The caller must retain the receipt and public key independently of the DB.
 */
export async function writeSignedIncidentAnchorReceipt(
	options: WriteIncidentAnchorOptions,
): Promise<SignedIncidentAnchorReceiptV1> {
	if (!nonEmptyScope(options.scope)) throw new Error("Incident anchor scope is invalid");
	requireDistinctPaths([options.sqlite_path, options.receipt_path, options.private_key_path]);
	const local = await verifyIncidentSqliteStore(options.sqlite_path);
	if (!local.valid) throw new Error("Incident store consistency verification failed");
	const privateKey = createPrivateKey(await readFile(options.private_key_path));
	if (privateKey.asymmetricKeyType !== "ed25519")
		throw new Error("Incident anchor key must be Ed25519");
	const publicKey = createPublicKey(privateKey);
	const payload: IncidentAnchorPayloadV1 = {
		type: "aidr_incident_anchor_payload",
		schema_version: 1,
		scope: options.scope,
		created_at: new Date().toISOString(),
		public_key_fingerprint_sha256: keyFingerprint(publicKey),
		checked_incidents: local.checked_incidents,
		checked_revisions: local.checked_revisions,
		head_order: "utf16",
		heads_sha256: headsDigest(local.heads),
	};
	const payloadBytes = Buffer.from(JSON.stringify(payload), "utf8");
	const receipt: SignedIncidentAnchorReceiptV1 = {
		type: "aidr_incident_anchor_receipt",
		schema_version: 1,
		algorithm: "Ed25519",
		payload_base64: payloadBytes.toString("base64"),
		signature_base64: sign(null, payloadBytes, privateKey).toString("base64"),
	};
	const handle = await open(options.receipt_path, "wx", 0o600);
	try {
		await handle.writeFile(`${JSON.stringify(receipt)}\n`, "utf8");
		await handle.sync();
	} finally {
		await handle.close();
	}
	return receipt;
}

/**
 * Verify a separately retained receipt using only the public key, then compare
 * its signed head digest to current SQLite state. Host time is not a trusted timestamp.
 */
export async function verifySignedIncidentAnchorReceipt(
	options: VerifyIncidentAnchorOptions,
): Promise<IncidentAnchorVerification> {
	try {
		if (!nonEmptyScope(options.expected_scope)) return { valid: false, code: "scope_mismatch" };
		let receipt: SignedIncidentAnchorReceiptV1;
		try {
			receipt = JSON.parse(
				await readFile(options.receipt_path, "utf8"),
			) as SignedIncidentAnchorReceiptV1;
		} catch {
			return { valid: false, code: "receipt_invalid" };
		}
		if (
			receipt?.type !== "aidr_incident_anchor_receipt" ||
			receipt.schema_version !== 1 ||
			receipt.algorithm !== "Ed25519"
		)
			return { valid: false, code: "receipt_invalid" };
		const payloadBytes = decodeCanonicalBase64(receipt.payload_base64);
		const signatureBytes = decodeCanonicalBase64(receipt.signature_base64);
		if (!payloadBytes || !signatureBytes || signatureBytes.length !== 64)
			return { valid: false, code: "receipt_invalid" };
		const publicKey = createPublicKey(await readFile(options.public_key_path));
		if (publicKey.asymmetricKeyType !== "ed25519") return { valid: false, code: "key_mismatch" };
		if (!verify(null, payloadBytes, publicKey, signatureBytes))
			return { valid: false, code: "signature_invalid" };
		const payload = readPayload(payloadBytes);
		if (!payload) return { valid: false, code: "receipt_invalid" };
		if (payload.scope !== options.expected_scope) return { valid: false, code: "scope_mismatch" };
		if (payload.public_key_fingerprint_sha256 !== keyFingerprint(publicKey))
			return { valid: false, code: "key_mismatch" };
		const local = await verifyIncidentSqliteStore(options.sqlite_path);
		if (!local.valid) return { valid: false, code: "store_invalid" };
		if (!anchorStateMatches(payload, local)) return { valid: false, code: "anchor_state_mismatch" };
		return {
			valid: true,
			code: "valid",
			checked_incidents: local.checked_incidents,
			checked_revisions: local.checked_revisions,
		};
	} catch {
		return { valid: false, code: "unavailable" };
	}
}
