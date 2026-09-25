/**
 * Shared provisioning of the operator-delivered tenant detector policy.
 *
 * A connector's tool hook has no trusted tenant in the tool payload, so a
 * signature alone is not enough: the policy must also be bound to a verified
 * managed entitlement for the same tenant. This module is the single
 * implementation of that contract, and every connector consumes it.
 *
 * The policy location is fixed and non-tool-selectable: it lives under the
 * local AIDR state directory and is named after the reported agent runtime,
 * which is a closed union (`AgentRuntime`), never a caller-supplied path. An
 * installation with no provisioned policy (and no entitlement that requires
 * one) gets an empty context, so an unprovisioned connector behaves exactly as
 * it did before provisioning existed.
 */
import { createHash, createPublicKey, verify } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { createBehavioralBaselineStore } from "./behavioral-baseline-store.js";
import { BehavioralCorpusSchema, LOCAL_EMBEDDER_MODEL_VERSION } from "./behavioral-corpus.js";
import { createBehavioralDetectionOrchestrator } from "./behavioral-orchestrator.js";
import { loadConfig, resolvePath } from "./config.js";
import { DlpPolicySchema } from "./dlp/index.js";
import type { ToolEvaluationContext } from "./evaluator.js";
import { inspectLocalDlpPolicy } from "./local-dlp-policy.js";
import {
	isEntitlementActive,
	loadManagedState,
	type ManagedState,
	managedStatePath,
} from "./managed.js";
import { LocalEmbeddingModel } from "./ml-model.js";
import {
	type AgentRuntime,
	type Config,
	type Logger,
	PromptProtectionModeSchema,
} from "./types.js";

const MAX_BUNDLE_BYTES = 8 * 1024 * 1024;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const FEED_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DateTime = z.string().datetime({ offset: true });

const DetectorPolicyPayloadSchema = z
	.object({
		schema_version: z.union([z.literal(1), z.literal(2)]),
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
				// Old payloads remain no-learning. V2 opt-in needs an independently
				// verified entitlement capability as well as this signed declaration.
				learning_allowed: z.boolean().default(false),
				learning_capability: z.literal("durable_baseline_v1").optional(),
				// Missing or cold baseline is fail-closed unless the signed tenant policy
				// explicitly selects the degraded skip behavior.
				unavailable_action: z.enum(["ask", "deny", "skip"]).default("ask"),
				threat_corpus: BehavioralCorpusSchema.optional(),
			})
			.strict()
			.optional(),
		// Tenant floor for prompt jailbreak / content-safety actions. It can only
		// tighten the local `prompt_protection` settings (see prompt-safety.ts).
		prompt_safety: z
			.object({
				jailbreak: PromptProtectionModeSchema.optional(),
				content_safety: z
					.object({
						malware: PromptProtectionModeSchema.optional(),
						phishing_kit: PromptProtectionModeSchema.optional(),
						weapons_cbrn: PromptProtectionModeSchema.optional(),
						self_harm: PromptProtectionModeSchema.optional(),
						hate_harassment: PromptProtectionModeSchema.optional(),
						sexual_minors: PromptProtectionModeSchema.optional(),
					})
					.strict()
					.optional(),
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
	.refine(
		(value) => {
			const behavioral = value.behavioral;
			if (!behavioral) return true;
			if (value.schema_version === 1) {
				return (
					!behavioral.learning_allowed &&
					!behavioral.learning_capability &&
					behavioral.unavailable_action === "ask" &&
					!behavioral.threat_corpus
				);
			}
			return (
				!behavioral.learning_allowed || behavioral.learning_capability === "durable_baseline_v1"
			);
		},
		{ message: "Behavioral provisioning requires an explicit supported V2 workflow" },
	)
	.refine(
		(value) => value.dlp || value.behavioral || value.reputation_feed || value.prompt_safety,
		{
			message: "At least one provisioned detector is required",
		},
	);

const SignedDetectorPolicySchema = z
	.object({
		alg: z.literal("ed25519"),
		payload: DetectorPolicyPayloadSchema,
		sig_b64: z.string().min(1),
	})
	.strict();

export type DetectorProvisionedContext = Partial<
	Pick<ToolEvaluationContext, "runtimeDetectors" | "reputationFeed">
>;
type SignedDetectorPolicy = z.infer<typeof SignedDetectorPolicySchema>;

/**
 * The agent runtimes a detector policy may be provisioned for. `AgentRuntime`
 * is the source of truth; the `satisfies` clause refuses an entry that is not a
 * real runtime, and the runtime check below refuses anything else a JavaScript
 * caller (or a bundler-mangled payload) might pass as a path segment.
 */
const DETECTOR_PROVISIONING_RUNTIMES = [
	"claude-code",
	"cursor",
	"vscode",
	"openclaw",
	"opencode",
	"codex",
] as const satisfies readonly AgentRuntime[];

function assertDetectorProvisioningRuntime(value: string): AgentRuntime {
	if (!(DETECTOR_PROVISIONING_RUNTIMES as readonly string[]).includes(value)) {
		throw new Error("Detector provisioning agent runtime is not supported");
	}
	return value as AgentRuntime;
}

/**
 * Fixed, non-tool-selectable location under the local AIDR state directory.
 *
 * The only variable part is the reported agent runtime, which must be one of
 * the known connector identities — no caller (and therefore no tool payload)
 * can redirect the read to another file or directory.
 */
export function detectorPolicyPath(agentRuntime: AgentRuntime): string {
	const runtime = assertDetectorProvisioningRuntime(agentRuntime);
	return join(resolvePath("~/.singularity-aidr"), "detectors", `${runtime}.json`);
}

/**
 * Fixed, non-tool-selectable location for the durable behavioural baseline. The
 * hook is a new process per tool call, so the baseline must outlive the process
 * that accepted an observation. It is keyed by tenant and session inside the
 * store; the directory itself is per installation.
 */
export function behavioralBaselineDir(): string {
	return join(resolvePath("~/.singularity-aidr"), "behavioral-baseline");
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
	agentRuntime: AgentRuntime,
	required: boolean,
): Promise<{ signed: SignedDetectorPolicy; rawPayload: unknown } | null> {
	const path = detectorPolicyPath(agentRuntime);
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
		payload.behavioral?.learning_allowed &&
		!state.entitlement.premium_modules.includes("behavioral_learning_v1")
	) {
		throw new Error("Provisioned behavioral learning capability is unavailable");
	}
	const corpus = payload.behavioral?.threat_corpus;
	if (corpus) {
		const { sha256, ...content } = corpus;
		if (
			corpus.tenant_id !== payload.tenant_id ||
			createHash("sha256").update(canonicalDetectorPolicyPayload(content), "utf8").digest("hex") !==
				sha256
		) {
			throw new Error("Provisioned behavioral corpus digest or tenant binding failed");
		}
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

async function detectorContext(
	payload: SignedDetectorPolicy["payload"],
): Promise<DetectorProvisionedContext> {
	const context: DetectorProvisionedContext = {};
	if (payload.dlp || payload.behavioral || payload.prompt_safety) {
		const runtimeDetectors: NonNullable<ToolEvaluationContext["runtimeDetectors"]> = {
			tenantId: payload.tenant_id,
		};
		if (payload.dlp) runtimeDetectors.dlp = { enabled: true, policy: payload.dlp.policy };
		if (payload.prompt_safety) runtimeDetectors.promptSafety = payload.prompt_safety;
		if (payload.behavioral) {
			const corpus = payload.behavioral.threat_corpus;
			// Import only after signature, entitlement, tenant, digest and model
			// compatibility validation. Never fall back to a fabricated corpus.
			const mlModel = new LocalEmbeddingModel(LocalEmbeddingModel.createDefaultConfig());
			if (corpus) await mlModel.importThreatCorpus(corpus.entries);
			runtimeDetectors.behavioral = {
				enabled: true,
				learningAllowed: payload.behavioral.learning_allowed,
				unavailableAction: payload.behavioral.unavailable_action,
				orchestrator: createBehavioralDetectionOrchestrator(
					{ modelVersion: LOCAL_EMBEDDER_MODEL_VERSION },
					{
						mlModel,
						provisionedPolicy: {
							tenantId: payload.tenant_id,
							learningAllowed: payload.behavioral.learning_allowed,
						},
						// A different corpus/version must not inherit observations scored
						// against the prior corpus. A missing corpus cannot restore a baseline.
						baselineStore: corpus
							? createBehavioralBaselineStore({
									storeDir: behavioralBaselineDir(),
									corpusDigest: corpus.sha256,
								})
							: undefined,
					},
				),
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

/** Warn once per process and reason: hooks and plugins evaluate many calls. */
const reportedLocalPolicyWarnings = new Set<string>();

const stderrLogger: Logger = {
	debug() {},
	info() {},
	warn(message, data) {
		process.stderr.write(
			`[singularity-aidr] ${message}${data ? ` ${JSON.stringify(data)}` : ""}\n`,
		);
	},
	error(message, data) {
		process.stderr.write(
			`[singularity-aidr] ${message}${data ? ` ${JSON.stringify(data)}` : ""}\n`,
		);
	},
};

/**
 * Local-mode DLP: an optional, unsigned operator policy file. Missing means
 * off; invalid is skipped and logged (and reported by the health check), never
 * treated as an enforced policy.
 */
async function localDlpContext(logger: Logger): Promise<DetectorProvisionedContext> {
	const state = await inspectLocalDlpPolicy();
	if (state.status === "absent") return {};
	if (state.status === "invalid") {
		const key = `${state.path}\0${state.reason}`;
		if (!reportedLocalPolicyWarnings.has(key)) {
			reportedLocalPolicyWarnings.add(key);
			logger.warn("Local DLP policy is invalid and was skipped; local DLP is NOT enforced.", {
				path: state.path,
				reason: state.reason,
			});
		}
		return {};
	}
	return {
		runtimeDetectors: {
			tenantId: state.policy.tenantId,
			dlp: { enabled: true, policy: state.policy },
		},
	};
}

/**
 * Load the detector policy for one agent runtime.
 *
 * `agentRuntime` selects a fixed file for that runtime only. It must come from
 * the runtime the connector is actually serving — never from a tool payload.
 *
 * Managed mode accepts only the signed, entitlement-bound bundle. Local mode
 * additionally reads the optional unsigned `dlp-policy.json` when no signed
 * bundle is installed (see `local-dlp-policy.ts`).
 */
export async function loadProvisionedDetectorContext(
	agentRuntime: AgentRuntime,
	options: { logger?: Logger } = {},
): Promise<DetectorProvisionedContext> {
	const config = await loadConfig();
	const state = await loadManagedState(managedStatePath(), {
		publicKeysPem: config.licensing.public_keys_pem,
	});
	const required =
		state.entitlement_alg === "ed25519" &&
		state.entitlement?.schema_version === 2 &&
		isEntitlementActive(state) &&
		state.entitlement.premium_modules.includes("runtime_detectors");
	const installed = await readInstalledPolicy(agentRuntime, required);
	if (!installed) {
		return config.mode === "local" ? localDlpContext(options.logger ?? stderrLogger) : {};
	}
	validatePolicyTrust(config, state, installed.signed, installed.rawPayload);
	validateFeedKeyring(installed.signed.payload.reputation_feed);
	return detectorContext(installed.signed.payload);
}
