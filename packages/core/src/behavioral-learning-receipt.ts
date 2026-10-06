import {
	createHash,
	createPrivateKey,
	createPublicKey,
	randomUUID,
	sign,
	verify,
} from "node:crypto";
import { z } from "zod";
import type { BehavioralBaselineObservation } from "./behavioral-baseline-store.js";
import { canonicalJson as canonicalDetectorPolicyPayload } from "./canonical-json.js";
import type { AgentRuntime } from "./types.js";

const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_INPUT_BYTES = 16_384;
const RECEIPT_TTL_MS = 24 * 60 * 60 * 1000;
const RETENTION_MS = 30 * RECEIPT_TTL_MS;
const Identifier = z
	.string()
	.min(1)
	.max(256)
	.regex(/^[^\u0000-\u001f\u007f]+$/);
const Digest = z.string().regex(/^[a-f0-9]{64}$/);
const DateTime = z.string().datetime({ offset: true });
const KeyId = z
	.string()
	.min(1)
	.max(128)
	.regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
const Keys = z.record(KeyId, z.string().min(1).max(4096));

export const LearningAuthorityKeyringSchema = z
	.object({ execution: Keys, approval: Keys })
	.strict();
export type LearningAuthorityKeyring = z.infer<typeof LearningAuthorityKeyringSchema>;

export interface LearningReceiptContext {
	tenantId: string;
	deviceId: string;
	agentRuntime: AgentRuntime;
	policyDigest: string;
	corpusDigest: string;
	modelVersion: string;
	entitlementSerial: string;
	revocationEpoch?: number;
	validFromMs: number;
	validUntilMs: number;
	authorities: LearningAuthorityKeyring;
	/** Current authenticated revocation feed; historical revoked grants cannot restore learning. */
	revokedEntitlementSerials?: readonly string[];
}

const Observation = z
	.object({
		toolName: Identifier,
		timestamp: z.number().int().nonnegative(),
		riskScore: z.literal(0),
		commandToken: z
			.string()
			.regex(/^command:sha256:[a-f0-9]{64}$/)
			.optional(),
		pathToken: z
			.string()
			.regex(/^path:sha256:[a-f0-9]{64}$/)
			.optional(),
		urlToken: z
			.string()
			.regex(/^url:sha256:[a-f0-9]{64}$/)
			.optional(),
		durationMs: z.number().int().nonnegative().max(RECEIPT_TTL_MS),
	})
	.strict();

const ExecutionPayloadSchema = z
	.object({
		kind: z.literal("aidr.behavioral.execution.v1"),
		schemaVersion: z.literal(1),
		executionId: z.string().uuid(),
		tenantId: Identifier,
		deviceId: Identifier,
		agentRuntime: Identifier,
		sessionId: Identifier,
		toolName: Identifier,
		inputDigest: Digest,
		policyDigest: Digest,
		corpusDigest: Digest,
		modelVersion: Identifier,
		entitlementSerial: Identifier,
		startedAt: DateTime,
		completedAt: DateTime,
		issuedAt: DateTime,
		expiresAt: DateTime,
		outcome: z.literal("success"),
		outputInspection: z.literal("clean"),
		observation: Observation,
		fingerprint: z.string().regex(/^event:sha256:[a-f0-9]{64}$/),
	})
	.strict();

const ApprovalPayloadSchema = z
	.object({
		kind: z.literal("aidr.behavioral.approval.v1"),
		schemaVersion: z.literal(1),
		approvalId: z.string().uuid(),
		executionDigest: Digest,
		benign: z.literal(true),
		consent: z.literal(true),
		issuedAt: DateTime,
		expiresAt: DateTime,
	})
	.strict();

const ExecutionEnvelopeSchema = z
	.object({
		alg: z.literal("ed25519"),
		keyId: KeyId,
		payload: ExecutionPayloadSchema,
		sigBase64: z.string().min(1).max(128),
	})
	.strict();
const ApprovalEnvelopeSchema = z
	.object({
		alg: z.literal("ed25519"),
		keyId: KeyId,
		payload: ApprovalPayloadSchema,
		sigBase64: z.string().min(1).max(128),
	})
	.strict();
const BundleSchema = z
	.object({ execution: ExecutionEnvelopeSchema, approval: ApprovalEnvelopeSchema })
	.strict();

export type LearningExecutionPayload = z.infer<typeof ExecutionPayloadSchema>;
export type SignedLearningExecutionReceipt = z.infer<typeof ExecutionEnvelopeSchema>;
export type SignedLearningApprovalReceipt = z.infer<typeof ApprovalEnvelopeSchema>;
export type LearningReceiptBundle = z.infer<typeof BundleSchema>;

export interface VerifiedLearningReceipt {
	executionId: string;
	approvalId: string;
	expiresAt: number;
	sessionId: string;
	toolName: string;
	inputDigest: string;
	observation: BehavioralBaselineObservation;
	fingerprint: string;
}

function bounded(value: unknown): void {
	if (Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_RECEIPT_BYTES) {
		throw new Error("Behavioral learning receipt exceeds its size limit");
	}
}

function authorityKey(raw: string) {
	const trimmed = raw.trim();
	const pem = trimmed.startsWith("-----BEGIN PUBLIC KEY-----");
	const bytes = Buffer.from(trimmed, "base64");
	const key = pem
		? createPublicKey(trimmed)
		: createPublicKey({ key: bytes, format: "der", type: "spki" });
	if (key.asymmetricKeyType !== "ed25519") throw new Error("Learning authority must use Ed25519");
	// Node accepts an otherwise valid key followed by private PEM or ASN.1 tail.
	// A declared-public authority is forwarded in the signed public handoff.
	const complete = pem
		? key.export({ type: "spki", format: "pem" }).toString().trim() ===
			trimmed.replace(/\r\n/g, "\n")
		: bytes.toString("base64") === trimmed &&
			key.export({ type: "spki", format: "der" }).equals(bytes);
	if (!complete) throw new Error("Learning authority must contain exactly one public key");
	return key;
}

function publicDigest(raw: string): string {
	return createHash("sha256")
		.update(authorityKey(raw).export({ type: "spki", format: "der" }))
		.digest("hex");
}

/** Separate IDs or references for the same private key do not establish independence. */
export function validateLearningAuthorities(value: unknown): LearningAuthorityKeyring {
	const authorities = LearningAuthorityKeyringSchema.parse(value);
	const fingerprints = new Set<string>();
	for (const role of ["execution", "approval"] as const) {
		const keys = Object.values(authorities[role]);
		if (keys.length < 1 || keys.length > 16)
			throw new Error("Learning authority keyring is empty or oversized");
		for (const key of keys) {
			const fingerprint = publicDigest(key);
			if (fingerprints.has(fingerprint))
				throw new Error("Learning authorities must use distinct keys");
			fingerprints.add(fingerprint);
		}
	}
	return authorities;
}

/** Canonical input is bounded and never included in a durable receipt. */
export function learningInputDigest(toolInput: Record<string, unknown>): string {
	const content = canonicalDetectorPolicyPayload(toolInput);
	if (Buffer.byteLength(content, "utf8") > MAX_INPUT_BYTES)
		throw new Error("Learning input exceeds its size limit");
	return createHash("sha256").update(content).digest("hex");
}

function receiptDigest(value: unknown): string {
	return createHash("sha256").update(canonicalDetectorPolicyPayload(value)).digest("hex");
}

function authorizedPrivateKey(privateKeyPem: string, trustedPublicKey: string) {
	const privateKey = createPrivateKey(privateKeyPem);
	if (privateKey.asymmetricKeyType !== "ed25519")
		throw new Error("Learning authority must use Ed25519");
	const actual = createPublicKey(privateKey).export({ type: "spki", format: "der" });
	const expected = authorityKey(trustedPublicKey).export({ type: "spki", format: "der" });
	if (!actual.equals(expected))
		throw new Error("Private key does not match the authorized learning role");
	return privateKey;
}

/** Validate the actual protected key before a broker executes any operation. */
export function assertLearningAuthorityPrivateKey(
	context: LearningReceiptContext,
	role: "execution" | "approval",
	keyId: string,
	privateKeyPem: string,
): void {
	currentContext(context, Date.now());
	const key = context.authorities[role][keyId];
	if (!key) throw new Error("Learning authority is not authorized by the tenant policy");
	authorizedPrivateKey(privateKeyPem, key);
}

function signature(payload: unknown, privateKeyPem: string, trustedPublicKey: string): string {
	return sign(
		null,
		Buffer.from(canonicalDetectorPolicyPayload(payload)),
		authorizedPrivateKey(privateKeyPem, trustedPublicKey),
	).toString("base64");
}

function verifiedSignature(
	payload: unknown,
	sigBase64: string,
	keyId: string,
	keys: Record<string, string>,
): void {
	const rawKey = keys[keyId];
	const bytes = Buffer.from(sigBase64, "base64");
	if (
		!rawKey ||
		bytes.length !== 64 ||
		bytes.toString("base64") !== sigBase64 ||
		!verify(null, Buffer.from(canonicalDetectorPolicyPayload(payload)), authorityKey(rawKey), bytes)
	) {
		throw new Error("Behavioral learning receipt signature is not authorized");
	}
}

function currentContext(context: LearningReceiptContext, now: number): void {
	validateLearningAuthorities(context.authorities);
	if (
		!Number.isFinite(now) ||
		!Number.isFinite(context.validFromMs) ||
		!Number.isFinite(context.validUntilMs) ||
		context.validFromMs > now ||
		context.validUntilMs <= now ||
		context.revokedEntitlementSerials?.includes(context.entitlementSerial)
	)
		throw new Error("Learning authority context is expired or unavailable");
}

function validateExecution(
	receipt: SignedLearningExecutionReceipt,
	context: LearningReceiptContext,
): void {
	const payload = receipt.payload;
	for (const name of [
		"tenantId",
		"deviceId",
		"agentRuntime",
		"policyDigest",
		"corpusDigest",
		"modelVersion",
		"entitlementSerial",
	] as const) {
		if (payload[name] !== context[name])
			throw new Error(`Behavioral learning receipt ${name} binding failed`);
	}
	verifiedSignature(payload, receipt.sigBase64, receipt.keyId, context.authorities.execution);
	const started = Date.parse(payload.startedAt);
	const completed = Date.parse(payload.completedAt);
	const issued = Date.parse(payload.issuedAt);
	const expires = Date.parse(payload.expiresAt);
	if (
		started < context.validFromMs ||
		started > completed ||
		completed > issued ||
		issued >= expires ||
		expires - issued > RECEIPT_TTL_MS ||
		completed - started > RECEIPT_TTL_MS ||
		expires > context.validUntilMs ||
		payload.observation.timestamp !== completed ||
		payload.observation.durationMs !== completed - started ||
		payload.observation.toolName !== payload.toolName
	)
		throw new Error("Behavioral learning execution timing or observation binding failed");
}

export function verifyLearningExecutionReceipt(
	value: unknown,
	context: LearningReceiptContext,
	now = Date.now(),
): SignedLearningExecutionReceipt {
	bounded(value);
	currentContext(context, now);
	const receipt = ExecutionEnvelopeSchema.parse(value);
	validateExecution(receipt, context);
	if (
		Date.parse(receipt.payload.issuedAt) > now + 60_000 ||
		Date.parse(receipt.payload.expiresAt) <= now
	) {
		throw new Error("Behavioral learning execution receipt is expired or future dated");
	}
	return receipt;
}

/** Called by a trusted execution authority only after its own actual success boundary. */
export function createLearningExecutionReceipt(
	payload: LearningExecutionPayload,
	privateKeyPem: string,
	keyId: string,
	context: LearningReceiptContext,
): SignedLearningExecutionReceipt {
	const parsed = ExecutionPayloadSchema.parse(payload);
	validateLearningAuthorities(context.authorities);
	const trusted = context.authorities.execution[keyId];
	if (!trusted) throw new Error("Execution authority is not authorized by the tenant policy");
	const receipt: SignedLearningExecutionReceipt = {
		alg: "ed25519",
		keyId,
		payload: parsed,
		sigBase64: signature(parsed, privateKeyPem, trusted),
	};
	return verifyLearningExecutionReceipt(receipt, context);
}

/** A separate operator makes the independent benign classification and consent assertion. */
export function createLearningApprovalReceipt(
	execution: SignedLearningExecutionReceipt,
	privateKeyPem: string,
	keyId: string,
	context: LearningReceiptContext,
): SignedLearningApprovalReceipt {
	verifyLearningExecutionReceipt(execution, context);
	const trusted = context.authorities.approval[keyId];
	if (!trusted) throw new Error("Approval authority is not authorized by the tenant policy");
	const now = Date.now();
	const payload = ApprovalPayloadSchema.parse({
		kind: "aidr.behavioral.approval.v1",
		schemaVersion: 1,
		approvalId: randomUUID(),
		executionDigest: receiptDigest(execution),
		benign: true,
		consent: true,
		issuedAt: new Date(now).toISOString(),
		expiresAt: execution.payload.expiresAt,
	});
	return { alg: "ed25519", keyId, payload, sigBase64: signature(payload, privateKeyPem, trusted) };
}

/** Reverify historical signed proofs before restoring any learned observation. */
export function verifyLearningReceiptBundle(
	value: unknown,
	context: LearningReceiptContext,
	options: {
		mode: "ingest" | "restore";
		now?: number;
		acceptedAt?: number;
		activation?: { entitlementSerial: string; validFromMs: number; validUntilMs: number };
	},
): VerifiedLearningReceipt {
	bounded(value);
	const now = options.now ?? Date.now();
	currentContext(context, now);
	const { execution, approval } = BundleSchema.parse(value);
	const historical = options.mode === "restore" ? options.activation : undefined;
	if (
		historical &&
		(!Number.isFinite(historical.validFromMs) ||
			!Number.isFinite(historical.validUntilMs) ||
			!Identifier.safeParse(historical.entitlementSerial).success ||
			historical.validFromMs >= historical.validUntilMs ||
			options.acceptedAt === undefined ||
			options.acceptedAt < historical.validFromMs ||
			options.acceptedAt >= historical.validUntilMs ||
			context.revokedEntitlementSerials?.includes(historical.entitlementSerial))
	) {
		throw new Error("Historical behavioral learning authority was revoked or invalid");
	}
	validateExecution(execution, historical ? { ...context, ...historical } : context);
	verifiedSignature(
		approval.payload,
		approval.sigBase64,
		approval.keyId,
		context.authorities.approval,
	);
	if (approval.payload.executionDigest !== receiptDigest(execution))
		throw new Error("Approval belongs to a different execution receipt");
	const executionIssued = Date.parse(execution.payload.issuedAt);
	const executionExpires = Date.parse(execution.payload.expiresAt);
	const approvalIssued = Date.parse(approval.payload.issuedAt);
	const approvalExpires = Date.parse(approval.payload.expiresAt);
	const acceptedAt = options.mode === "ingest" ? now : options.acceptedAt;
	if (
		acceptedAt === undefined ||
		!Number.isFinite(acceptedAt) ||
		acceptedAt > now + 60_000 ||
		executionIssued > acceptedAt ||
		approvalIssued < executionIssued ||
		approvalIssued > acceptedAt ||
		approvalExpires <= acceptedAt ||
		executionExpires <= acceptedAt ||
		approvalExpires - approvalIssued > RECEIPT_TTL_MS ||
		approvalExpires > executionExpires ||
		execution.payload.observation.timestamp < now - RETENTION_MS
	) {
		throw new Error(
			"Behavioral learning approval or accepted observation is outside its authorized window",
		);
	}
	return {
		executionId: execution.payload.executionId,
		approvalId: approval.payload.approvalId,
		expiresAt: Math.max(executionExpires, approvalExpires),
		sessionId: execution.payload.sessionId,
		toolName: execution.payload.toolName,
		inputDigest: execution.payload.inputDigest,
		observation: execution.payload.observation,
		fingerprint: execution.payload.fingerprint,
	};
}
