/**
 * Claude Code's short-lived hook has no trusted tenant in the tool payload.
 * Operator-delivered detector policy is accepted only when it is signed by a
 * configured entitlement key and bound to a verified managed entitlement.
 */
import { createPublicKey, verify } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type Config,
	createBehavioralDetectionOrchestrator,
	DlpPolicySchema,
	isEntitlementActive,
	loadConfig,
	loadManagedState,
	type ManagedState,
	managedStatePath,
	resolvePath,
	type ToolEvaluationContext,
} from "@singularityrd/aidr-core";
import { z } from "zod";

const MAX_BUNDLE_BYTES = 8 * 1024 * 1024;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const FEED_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DateTime = z.string().datetime({ offset: true });

const DetectorPolicyPayloadSchema = z
	.object({
		schema_version: z.literal(1),
		tenant_id: z.string().regex(ID),
		issued_at: DateTime,
		expires_at: DateTime,
		dlp: z
			.object({ enabled: z.literal(true), policy: DlpPolicySchema })
			.strict()
			.optional(),
		behavioral: z
			.object({
				enabled: z.literal(true),
				// The hook is a new process per call; learning here cannot form a
				// durable baseline and must not be advertised as operational.
				learning_allowed: z.literal(false).default(false),
			})
			.strict()
			.optional(),
		reputation_feed: z
			.object({
				feed_id: z.string().regex(FEED_ID),
				trusted_keys: z.record(z.string().min(1)),
				max_age_ms: z
					.number()
					.int()
					.positive()
					.max(7 * 24 * 60 * 60 * 1000)
					.optional(),
			})
			.strict()
			.optional(),
	})
	.strict()
	.refine((value) => value.dlp || value.behavioral || value.reputation_feed, {
		message: "At least one provisioned detector is required",
	});

const SignedDetectorPolicySchema = z
	.object({
		alg: z.literal("ed25519"),
		payload: DetectorPolicyPayloadSchema,
		sig_b64: z.string().min(1),
	})
	.strict();

type DetectorContext = Partial<Pick<ToolEvaluationContext, "runtimeDetectors" | "reputationFeed">>;
type SignedDetectorPolicy = z.infer<typeof SignedDetectorPolicySchema>;

/** Fixed, non-tool-selectable location under the local AIDR state directory. */
export function detectorPolicyPath(): string {
	return join(resolvePath("~/.singularity-aidr"), "detectors", "claude-code.json");
}

/** The publisher signs the canonical payload bytes, never the wrapper. */
export function canonicalDetectorPolicyPayload(value: unknown): string {
	if (value === null || typeof value === "string" || typeof value === "boolean") {
		return JSON.stringify(value);
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new Error("Invalid detector policy number");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) {
		return `[${value.map(canonicalDetectorPolicyPayload).join(",")}]`;
	}
	if (typeof value === "object") {
		const record = value as Record<string, unknown>;
		return `{${Object.keys(record)
			.sort()
			.map((key) => `${JSON.stringify(key)}:${canonicalDetectorPolicyPayload(record[key])}`)
			.join(",")}}`;
	}
	throw new Error("Invalid detector policy value");
}

function publicKey(raw: string) {
	const trimmed = raw.trim();
	if (trimmed.startsWith("-----BEGIN")) return createPublicKey(trimmed);
	const bytes = Buffer.from(trimmed, "base64");
	if (bytes.length === 0 || bytes.toString("base64") !== trimmed) {
		throw new Error("Invalid public key encoding");
	}
	return createPublicKey({ key: bytes, format: "der", type: "spki" });
}

function verifySignature(
	payload: unknown,
	signatureBase64: string,
	trustedKeys: string[],
): boolean {
	const signature = Buffer.from(signatureBase64, "base64");
	if (signature.length !== 64 || signature.toString("base64") !== signatureBase64) return false;
	const message = Buffer.from(canonicalDetectorPolicyPayload(payload), "utf8");
	return trustedKeys.some((keyText) => {
		try {
			const key = publicKey(keyText);
			return key.asymmetricKeyType === "ed25519" && verify(null, message, key, signature);
		} catch {
			return false;
		}
	});
}

/**
 * Returns no optional detectors when none were issued. Once a signed policy is
 * present, every validation failure blocks the tool call; it is never treated
 * as an empty policy. A future signed entitlement may mandate the bundle via
 * its `runtime_detectors` premium module.
 */
async function readInstalledPolicy(
	required: boolean,
): Promise<{ signed: SignedDetectorPolicy; rawPayload: unknown } | null> {
	const path = detectorPolicyPath();
	let raw: Buffer;
	try {
		const info = await lstat(path);
		if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_BUNDLE_BYTES) {
			throw new Error("Detector policy file is invalid");
		}
		raw = await readFile(path);
		if (raw.length > MAX_BUNDLE_BYTES) throw new Error("Detector policy exceeds size limit");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT" && !required) return null;
		throw new Error("Provisioned detector policy is unavailable");
	}

	try {
		const parsed: unknown = JSON.parse(raw.toString("utf8"));
		return {
			signed: SignedDetectorPolicySchema.parse(parsed),
			rawPayload: (parsed as { payload: unknown }).payload,
		};
	} catch {
		throw new Error("Provisioned detector policy is invalid");
	}
}

function validatePolicyTrust(
	config: Config,
	state: ManagedState,
	signed: SignedDetectorPolicy,
	rawPayload: unknown,
): void {
	const payload = signed.payload;
	const now = Date.now();
	if (
		config.mode !== "managed" ||
		config.licensing.public_keys_pem.length === 0 ||
		state.entitlement_alg !== "ed25519" ||
		!state.entitlement_sig ||
		state.entitlement?.schema_version !== 2 ||
		!isEntitlementActive(state) ||
		state.entitlement.tenant_id !== payload.tenant_id ||
		Date.parse(payload.issued_at) > now ||
		Date.parse(payload.expires_at) <= now ||
		Date.parse(payload.expires_at) <= Date.parse(payload.issued_at) ||
		!verifySignature(rawPayload, signed.sig_b64, config.licensing.public_keys_pem)
	) {
		throw new Error("Provisioned detector policy trust or tenant binding failed");
	}
	if (
		payload.dlp?.policy.tenantId !== undefined &&
		payload.dlp.policy.tenantId !== payload.tenant_id
	) {
		throw new Error("Provisioned DLP policy belongs to a different tenant");
	}
}

function validateFeedKeyring(feed: SignedDetectorPolicy["payload"]["reputation_feed"]): void {
	if (!feed) return;
	if (
		feed &&
		(Object.keys(feed.trusted_keys).length === 0 || Object.keys(feed.trusted_keys).length > 32)
	) {
		throw new Error("Provisioned reputation feed keyring is invalid");
	}
	if (
		feed &&
		Object.values(feed.trusted_keys).some((key) => {
			try {
				return publicKey(key).asymmetricKeyType !== "ed25519";
			} catch {
				return true;
			}
		})
	) {
		throw new Error("Provisioned reputation feed keyring is invalid");
	}
}

function detectorContext(payload: SignedDetectorPolicy["payload"]): DetectorContext {
	const context: DetectorContext = {};
	if (payload.dlp || payload.behavioral) {
		const runtimeDetectors: NonNullable<ToolEvaluationContext["runtimeDetectors"]> = {
			tenantId: payload.tenant_id,
		};
		if (payload.dlp) runtimeDetectors.dlp = { enabled: true, policy: payload.dlp.policy };
		if (payload.behavioral) {
			runtimeDetectors.behavioral = {
				enabled: true,
				orchestrator: createBehavioralDetectionOrchestrator(),
				learningAllowed: false,
			};
		}
		context.runtimeDetectors = runtimeDetectors;
	}
	const feed = payload.reputation_feed;
	if (feed) {
		context.reputationFeed = {
			storeDir: join(resolvePath("~/.singularity-aidr"), "reputation-feeds", feed.feed_id),
			feedId: feed.feed_id,
			trustedKeys: feed.trusted_keys,
			...(feed.max_age_ms ? { maxAgeMs: feed.max_age_ms } : {}),
		};
	}
	return context;
}

export async function loadProvisionedDetectorContext(): Promise<DetectorContext> {
	const config = await loadConfig();
	const state = await loadManagedState(managedStatePath(), {
		publicKeysPem: config.licensing.public_keys_pem,
	});
	const required =
		state.entitlement_alg === "ed25519" &&
		state.entitlement?.schema_version === 2 &&
		isEntitlementActive(state) &&
		state.entitlement.premium_modules.includes("runtime_detectors");
	const installed = await readInstalledPolicy(required);
	if (!installed) return {};
	validatePolicyTrust(config, state, installed.signed, installed.rawPayload);
	validateFeedKeyring(installed.signed.payload.reputation_feed);
	return detectorContext(installed.signed.payload);
}
