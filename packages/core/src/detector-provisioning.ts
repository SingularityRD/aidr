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
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { lstat, open, readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import {
	buildAgentProfileContext,
	inspectLocalAgentProfiles,
	localAgentProfileLayer,
	managedAgentProfileLayer,
} from "./agent-profile-loader.js";
import { FileAuthenticatedBehavioralBaselineStore } from "./authenticated-behavioral-baseline-store.js";
import { createBehavioralBaselineStore } from "./behavioral-baseline-store.js";
import { BehavioralCorpusSchema, LOCAL_EMBEDDER_MODEL_VERSION } from "./behavioral-corpus.js";
import {
	LearningAuthorityKeyringSchema,
	type LearningReceiptContext,
	validateLearningAuthorities,
} from "./behavioral-learning-receipt.js";
import { createBehavioralDetectionOrchestrator } from "./behavioral-orchestrator.js";
import { canonicalJson as canonicalDetectorPolicyPayload } from "./canonical-json.js";
import { isInvalidConfig, loadConfig, resolvePath } from "./config.js";
import { DlpPolicySchema } from "./dlp/index.js";
import type { ToolEvaluationContext } from "./evaluator.js";
import { getInstallationId } from "./installation-id.js";
import { inspectLocalDlpPolicy } from "./local-dlp-policy.js";
import {
	isEntitlementActive,
	loadManagedState,
	loadRevocationsCache,
	type ManagedState,
	managedStatePath,
	revocationBindingForState,
} from "./managed.js";
import { LocalEmbeddingModel } from "./ml-model.js";
import { preparePrivateLocalDirectory, preparePrivateLocalFile } from "./private-local-file.js";
import { resolveSecretStore } from "./secret-store.js";
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
				learning_authorities: LearningAuthorityKeyringSchema.optional(),
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
		// Agent permission profiles. Validated separately (after the signature
		// check) so a malformed section denies calls with a reason that names the
		// profile problem instead of failing the whole bundle generically.
		agent_profiles: z.unknown().optional(),
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
					!behavioral.learning_authorities &&
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
		(value) =>
			value.dlp ||
			value.behavioral ||
			value.reputation_feed ||
			value.prompt_safety ||
			value.agent_profiles !== undefined,
		{ message: "At least one provisioned detector is required" },
	);

const SignedDetectorPolicySchema = z
	.object({
		alg: z.literal("ed25519"),
		payload: DetectorPolicyPayloadSchema,
		sig_b64: z.string().min(1),
	})
	.strict();

export type DetectorProvisionedContext = Partial<
	Pick<ToolEvaluationContext, "runtimeDetectors" | "reputationFeed" | "agentProfiles">
>;
type SignedDetectorPolicy = z.infer<typeof SignedDetectorPolicySchema>;
interface DetectorPolicySources {
	config: string | null;
	managed: string | null;
	policy: string | null;
	revocations: string | null;
}

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
export { canonicalJson as canonicalDetectorPolicyPayload } from "./canonical-json.js";

function publicKey(raw: string) {
	const trimmed = raw.trim();
	if (trimmed.startsWith("-----BEGIN PUBLIC KEY-----")) {
		const key = createPublicKey(trimmed);
		if (
			key.export({ type: "spki", format: "pem" }).toString().trim() !==
			trimmed.replace(/\r\n/g, "\n")
		)
			throw new Error("Invalid public key encoding");
		return key;
	}
	const bytes = Buffer.from(trimmed, "base64");
	if (bytes.length === 0 || bytes.toString("base64") !== trimmed) {
		throw new Error("Invalid public key encoding");
	}
	const key = createPublicKey({ key: bytes, format: "der", type: "spki" });
	if (!key.export({ type: "spki", format: "der" }).equals(bytes))
		throw new Error("Invalid public key encoding");
	return key;
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
	source?: { raw: string | null },
): Promise<{ signed: SignedDetectorPolicy; rawPayload: unknown } | null> {
	const path = detectorPolicyPath(agentRuntime);
	let raw: Buffer;
	try {
		if (source?.raw === null) {
			if (!required) return null;
			throw new Error("Required detector policy is missing");
		}
		if (source) {
			raw = Buffer.from(source.raw as string, "utf8");
		} else {
			const info = await lstat(path);
			if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_BUNDLE_BYTES) {
				throw new Error("Detector policy file is invalid");
			}
			raw = await readFile(path);
		}
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
	if (payload.behavioral?.learning_authorities) {
		validateLearningAuthorities(payload.behavioral.learning_authorities);
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
	agentRuntime: AgentRuntime,
	learning?: { receiptContext: LearningReceiptContext; authenticationKey: Buffer },
): Promise<DetectorProvisionedContext> {
	const context: DetectorProvisionedContext = {};
	const authenticatedBaselineStore = learning
		? new FileAuthenticatedBehavioralBaselineStore({
				context: learning.receiptContext,
				storeDir: behavioralBaselineDir(),
				authenticationKey: learning.authenticationKey,
			})
		: undefined;
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
						authenticatedBaselineStore,
					},
				),
			};
		}
		context.runtimeDetectors = runtimeDetectors;
	}
	if (payload.agent_profiles !== undefined) {
		const layer = managedAgentProfileLayer(payload.agent_profiles, "signed tenant detector bundle");
		context.agentProfiles = buildAgentProfileContext(agentRuntime, [layer]);
	}
	const feed = payload.reputation_feed;
	if (feed) {
		context.reputationFeed = {
			storeDir: join(resolvePath("~/.singularity-aidr"), "reputation-feeds", feed.feed_id),
			feedId: feed.feed_id,
			trustedKeys: feed.trusted_keys,
			maxAgeMs: feed.max_age_ms,
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
 * The operator's local agent profile document. Valid: enforced in every mode
 * (it can only narrow a managed profile). Invalid: refused, warned once, and
 * reported by `aidr doctor` — never enforced as if it were valid.
 */
async function withLocalAgentProfiles(
	agentRuntime: AgentRuntime,
	context: DetectorProvisionedContext,
	logger: Logger,
): Promise<DetectorProvisionedContext> {
	const state = await inspectLocalAgentProfiles();
	if (state.status === "invalid") {
		const key = `profiles\0${state.path}\0${state.reason}`;
		if (!reportedLocalPolicyWarnings.has(key)) {
			reportedLocalPolicyWarnings.add(key);
			logger.warn(
				"Local agent permission profiles are invalid and were NOT loaded; run `aidr profile validate`.",
				{ path: state.path, reason: state.reason },
			);
		}
	}
	const local = localAgentProfileLayer(state);
	if (!local) return context;
	const agentProfiles = buildAgentProfileContext(agentRuntime, [
		...(context.agentProfiles?.layers ?? []),
		local,
	]);
	return { ...context, agentProfiles };
}

/**
 * Load the detector policy for one agent runtime.
 *
 * `agentRuntime` selects a fixed file for that runtime only. It must come from
 * the runtime the connector is actually serving — never from a tool payload.
 *
 * Managed mode accepts only the signed, entitlement-bound bundle. Local mode
 * additionally reads the optional unsigned `dlp-policy.json` when no signed
 * bundle is installed (see `local-dlp-policy.ts`). Agent permission profiles
 * come from the signed bundle's `agent_profiles` section and, in every mode,
 * from the local `agent-profiles.json` (see `agent-profile-loader.ts`).
 */
export async function loadProvisionedDetectorContext(
	agentRuntime: AgentRuntime,
	options: { logger?: Logger } = {},
): Promise<DetectorProvisionedContext> {
	const logger = options.logger ?? stderrLogger;
	const installed = await loadValidatedDetectorPolicy(agentRuntime);
	if (!installed) {
		// loadValidatedDetectorPolicy already refused an invalid configuration.
		const config = await loadConfig();
		const base = config.mode === "local" ? await localDlpContext(logger) : {};
		return withLocalAgentProfiles(agentRuntime, base, logger);
	}
	const receiptContext = await learningReceiptContext(installed, agentRuntime);
	const learning = receiptContext
		? { receiptContext, authenticationKey: await learningAuthenticationKey(receiptContext) }
		: undefined;
	return withLocalAgentProfiles(
		agentRuntime,
		await detectorContext(installed.signed.payload, agentRuntime, learning),
		logger,
	);
}

export interface ProvisionedLearningContext {
	receiptContext: LearningReceiptContext;
	orchestrator: NonNullable<
		NonNullable<DetectorProvisionedContext["runtimeDetectors"]>["behavioral"]
	>["orchestrator"];
	detectorContext: DetectorProvisionedContext;
}

/** Fixed installed tenant authority; neither tools nor receipts choose trust roots. */
export async function loadProvisionedLearningContext(
	agentRuntime: AgentRuntime,
): Promise<ProvisionedLearningContext> {
	const installed = await loadValidatedDetectorPolicy(agentRuntime);
	const receiptContext = installed ? await learningReceiptContext(installed, agentRuntime) : null;
	if (!installed || !receiptContext)
		throw new Error("Signed behavioral learning is not provisioned for this runtime");
	const context = await detectorContext(installed.signed.payload, agentRuntime, {
		receiptContext,
		authenticationKey: await learningAuthenticationKey(receiptContext),
	});
	const orchestrator = context.runtimeDetectors?.behavioral?.orchestrator;
	if (!orchestrator) throw new Error("Behavioral learning detector is unavailable");
	return { receiptContext, orchestrator, detectorContext: context };
}

/** Public signatures and classifier policy only; the policy can contain confidential matchers. */
export interface BrokerLearningAuthorityBundle {
	schemaVersion: 1;
	agentRuntime: AgentRuntime;
	deviceId: string;
	managed: Pick<
		ManagedState,
		"entitlement" | "entitlement_alg" | "entitlement_sig" | "entitlement_key_id"
	>;
	policy: { alg: "ed25519"; payload: unknown; sig_b64: string };
}

export async function exportBrokerLearningAuthority(
	agentRuntime: AgentRuntime,
): Promise<BrokerLearningAuthorityBundle> {
	const installed = await loadValidatedDetectorPolicy(agentRuntime);
	const context = installed ? await learningReceiptContext(installed, agentRuntime) : null;
	if (!installed || !context) throw new Error("Signed behavioral learning is not provisioned");
	const state = installed.state;
	return {
		schemaVersion: 1,
		agentRuntime,
		deviceId: context.deviceId,
		managed: {
			entitlement: state.entitlement,
			entitlement_alg: state.entitlement_alg,
			entitlement_sig: state.entitlement_sig,
			entitlement_key_id: state.entitlement_key_id,
		},
		policy: { alg: "ed25519", payload: installed.rawPayload, sig_b64: installed.signed.sig_b64 },
	};
}

/** An independent operator verifies the broker's signed public handoff against local issuer roots. */
export async function loadProvisionedLearningApprovalContext(
	agentRuntime: AgentRuntime,
	bundle: BrokerLearningAuthorityBundle,
): Promise<LearningReceiptContext> {
	if (
		bundle.schemaVersion !== 1 ||
		bundle.agentRuntime !== agentRuntime ||
		!z.string().uuid().safeParse(bundle.deviceId).success ||
		Object.keys(bundle).some(
			(key) => !["schemaVersion", "agentRuntime", "deviceId", "managed", "policy"].includes(key),
		) ||
		Object.keys(bundle.managed).some(
			(key) =>
				!["entitlement", "entitlement_alg", "entitlement_sig", "entitlement_key_id"].includes(key),
		)
	) {
		throw new Error("Broker learning authority handoff is invalid");
	}
	const configPath = resolvePath("~/.singularity-aidr/config.json");
	const config = await loadConfig();
	const revocations = await readFile(
		resolvePath(config.licensing.revocations_cache_path),
		"utf8",
	).catch((error: NodeJS.ErrnoException) => {
		if (error.code === "ENOENT") return null;
		throw error;
	});
	const installed = await loadValidatedDetectorPolicy(agentRuntime, {
		config: await readFile(configPath, "utf8"),
		managed: JSON.stringify(bundle.managed),
		policy: JSON.stringify(bundle.policy),
		revocations,
	});
	const context = installed
		? await learningReceiptContext(installed, agentRuntime, bundle.deviceId)
		: null;
	if (!context) throw new Error("Broker learning authority handoff is unavailable");
	return context;
}

async function learningReceiptContext(
	installed: NonNullable<Awaited<ReturnType<typeof loadValidatedDetectorPolicy>>>,
	agentRuntime: AgentRuntime,
	brokerDeviceId?: string,
): Promise<LearningReceiptContext | null> {
	const behavioral = installed.signed.payload.behavioral;
	const entitlement = installed.state.entitlement;
	if (
		!behavioral?.learning_allowed ||
		!behavioral.learning_authorities ||
		!behavioral.threat_corpus
	)
		return null;
	if (
		entitlement?.schema_version !== 2 ||
		!entitlement.premium_modules.includes("runtime_detectors") ||
		!entitlement.premium_modules.includes("behavioral_learning_v1")
	)
		throw new Error("Signed behavioral learning entitlement is unavailable");
	const deviceId = brokerDeviceId ?? (await getInstallationId());
	if (!z.string().uuid().safeParse(deviceId).success)
		throw new Error("Behavioral learning installation identity is unavailable");
	return {
		tenantId: installed.signed.payload.tenant_id,
		deviceId: deviceId as string,
		agentRuntime,
		policyDigest: createHash("sha256")
			.update(canonicalDetectorPolicyPayload(installed.rawPayload))
			.digest("hex"),
		corpusDigest: behavioral.threat_corpus.sha256,
		modelVersion: behavioral.threat_corpus.model_version,
		entitlementSerial: entitlement.serial,
		revocationEpoch: entitlement.revocation_epoch,
		validFromMs: installed.validFromMs,
		validUntilMs: installed.validUntilMs,
		authorities: validateLearningAuthorities(behavioral.learning_authorities),
		revokedEntitlementSerials: installed.revokedEntitlementSerials,
	};
}

async function learningAuthenticationKey(context: LearningReceiptContext): Promise<Buffer> {
	const store = resolveSecretStore();
	if (store.location !== "os-vault")
		throw new Error("Authenticated behavioral learning requires an OS vault");
	const id = `aidr-learning-${createHash("sha256").update(`${context.tenantId}\0${context.deviceId}\0${context.agentRuntime}`).digest("hex").slice(0, 40)}`;
	let raw = store.get(id);
	if (raw === null) {
		const root = join(behavioralBaselineDir(), "key-initialization");
		preparePrivateLocalDirectory(root);
		const lockPath = join(root, `${id}.lock`);
		// No stale-lock takeover: a crashed initializer needs explicit operator recovery.
		const lock = await open(lockPath, "wx", 0o600);
		try {
			preparePrivateLocalFile(lockPath);
			raw = store.get(id);
			if (raw === null) {
				const fresh = randomBytes(32).toString("base64");
				store.put(id, fresh);
				raw = store.get(id);
				if (raw !== fresh) throw new Error("Behavioral learning vault write could not be verified");
			}
		} finally {
			await lock.close();
			await unlink(lockPath);
		}
	}
	const bytes = Buffer.from(raw, "base64");
	if (bytes.length !== 32 || bytes.toString("base64") !== raw)
		throw new Error("Behavioral learning authentication key is invalid");
	return bytes;
}

/** Output hooks need DLP trust, without starting the behavioral model. */
export async function loadProvisionedDlpPolicy(
	agentRuntime: AgentRuntime,
	sources?: DetectorPolicySources,
): Promise<{
	tenantId: string;
	policy: z.infer<typeof DlpPolicySchema> | null;
	validFromMs: number;
	validUntilMs: number;
} | null> {
	const installed = await loadValidatedDetectorPolicy(agentRuntime, sources);
	if (!installed) return null;
	return {
		tenantId: installed.signed.payload.tenant_id,
		policy: installed.signed.payload.dlp?.policy ?? null,
		validFromMs: installed.validFromMs,
		validUntilMs: installed.validUntilMs,
	};
}

async function loadValidatedDetectorPolicy(
	agentRuntime: AgentRuntime,
	sources?: DetectorPolicySources,
) {
	const config = await loadConfig(
		undefined,
		undefined,
		undefined,
		sources ? { raw: sources.config } : undefined,
	);
	if (isInvalidConfig(config)) throw new Error("Detector configuration is unavailable");
	const state = await loadManagedState(managedStatePath(), {
		publicKeysPem: config.licensing.public_keys_pem,
		...(sources ? { source: { raw: sources.managed } } : {}),
	});
	const required =
		state.entitlement_alg === "ed25519" &&
		state.entitlement?.schema_version === 2 &&
		state.entitlement.premium_modules.includes("runtime_detectors");
	const installed = await readInstalledPolicy(
		agentRuntime,
		required,
		sources ? { raw: sources.policy } : undefined,
	);
	if (!installed) return null;
	let nextRevocationTransitionMs = Infinity;
	let revokedEntitlementSerials: readonly string[] = [];
	if (config.licensing.revocations_enabled && config.licensing.public_keys_pem.length > 0) {
		const revocations = await loadRevocationsCache(
			resolvePath(config.licensing.revocations_cache_path),
			config.licensing.public_keys_pem,
			revocationBindingForState(state),
			Date.now(),
			sources ? { raw: sources.revocations } : undefined,
		);
		revokedEntitlementSerials = revocations?.payload.revocations.entitlement_serials ?? [];
		if (
			revocations &&
			state.entitlement?.schema_version === 2 &&
			revocations.payload.revocations.entitlement_serials.includes(state.entitlement.serial)
		) {
			throw new Error("Provisioned detector entitlement was revoked");
		}
		if (sources?.revocations) {
			try {
				const issuedAt = Date.parse(JSON.parse(sources.revocations).payload?.issued_at);
				if (
					issuedAt > Date.now() &&
					(await loadRevocationsCache(
						resolvePath(config.licensing.revocations_cache_path),
						config.licensing.public_keys_pem,
						revocationBindingForState(state),
						issuedAt,
						{ raw: sources.revocations },
					))
				)
					nextRevocationTransitionMs = issuedAt;
			} catch {
				/* An unusable feed never grants authority. */
			}
		}
	}
	validatePolicyTrust(config, state, installed.signed, installed.rawPayload);
	validateFeedKeyring(installed.signed.payload.reputation_feed);
	const entitlement = state.entitlement;
	return {
		...installed,
		state,
		revokedEntitlementSerials,
		validFromMs: Math.max(
			Date.parse(installed.signed.payload.issued_at),
			Date.parse(entitlement?.issued_at ?? ""),
		),
		validUntilMs: Math.min(
			nextRevocationTransitionMs,
			Date.parse(installed.signed.payload.expires_at),
			entitlement?.schema_version === 2 ? Date.parse(entitlement.grace_until) : 0,
		),
	};
}
