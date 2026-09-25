/**
 * Shared runtime evaluation pipeline for hook entry points.
 * Hooks should normalize transport-specific payloads, then call this function.
 */

import { isAbsolute } from "node:path";
import {
	type AgentProfileContext,
	agentProfileFailureVerdict,
	agentProfileVerdict,
	evaluateAgentProfiles,
	mergeAgentProfileVerdict,
} from "./agent-profile.js";
import { loadTrustedModelSources, type TrustedModelSources } from "./ai-supply-chain.js";
import { isAllowlisted, loadAllowlist } from "./allowlist.js";
import {
	buildIncidentEntry,
	buildRuntimeVerdictEntry,
	getRecentEntries,
	logIncident,
	logVerdict,
} from "./audit-log.js";
import { BehavioralDetectionOrchestrator } from "./behavioral-orchestrator.js";
import { isCommercialBuild } from "./build-flavor.js";
import { VerdictCache } from "./cache.js";
import {
	CANARY_TRIGGERED_CATEGORY,
	CANARY_UNAVAILABLE_CATEGORY,
	type CanaryHit,
	type CanaryStage,
	canaryTriggeredVerdict,
	canaryUnavailableVerdict,
	inspectToolInputForCanaries,
} from "./canary/detect.js";
import { AmsiClient, isAmsiSupported } from "./clients/amsi.js";
import { ControlPlaneClient } from "./clients/control-plane.js";
import { UrlCheckClient } from "./clients/url-check.js";
import {
	applySecureCodeWarnings,
	type CodeGuardResult,
	CodeRuleSet,
	EMPTY_CODE_GUARD_RESULT,
	inspectToolCallCode,
} from "./code-guard.js";
import { isInvalidConfig, loadConfig, resolvePath } from "./config.js";
import {
	type DelegatedCredentialClaimsV1,
	type DelegatedCredentialErrorCode,
	type DelegatedCredentialVerificationContext,
	verifyDelegatedCredential,
} from "./delegated-credential.js";
import { DetectionLegUnavailableError } from "./detection-leg.js";
import type { DlpPolicy } from "./dlp/policy.js";
import { type DlpFinding, type DlpScanResult, scanDlpInput } from "./dlp/scanner.js";
import { DecisionEngine } from "./engine.js";
import {
	extractFromToolCall,
	extractFromUnknownTool,
	INPUT_NOT_FULLY_INSPECTED,
	type InspectionLimit,
	inspectionLimitsHit,
	MAX_ARTIFACT_SIZE,
} from "./extractors.js";
import { HeuristicsEngine } from "./heuristics.js";
import {
	correlateIncidents,
	normalizeAuditEntriesToSignals,
	persistIncidentRecords,
} from "./incidents/index.js";
import { getInstallationId } from "./installation-id.js";
import { getDegradedSafeModeReason, isDegradedSafeMode } from "./integrity/index.js";
import { loadMergedIntelFromDisk } from "./intel/loader.js";
import type { IntelMerged } from "./intel/types.js";
import { emptyIntelMerged } from "./intel/types.js";
import type { ManagedState, RevocationListV1 } from "./managed.js";
import {
	applyIngestResult,
	applyRevocationsToManagedState,
	getAuthToken,
	isEntitlementActive,
	isPremiumModuleEnabled,
	isSyncDisabled,
	loadManagedState,
	loadRevocationsCache,
	managedStatePath,
	parseSignedRevocationsFromControlPlaneBody,
	saveEntitlementKeyringFromState,
	saveManagedState,
	saveRevocationsCache,
	verifyEd25519SignedRevocationList,
} from "./managed.js";
import { PackageChecker } from "./package-checker.js";
import {
	extractPackagesFromCommand,
	extractPackagesFromManifest,
	hasDuplicateJsonObjectKeys,
	isDependencyManifestPath,
	isPackageJsonPath,
	isPackageManifestPath,
	type ParsedPackage,
} from "./package-extractor.js";
import { evaluateCommonPiiBaseline } from "./pii-baseline.js";
import { evaluatePolicy } from "./policy.js";
import type { TenantPromptSafetyPolicy } from "./prompt-safety.js";
import { syncRemoteRuntimePolicy } from "./remote-policy.js";
import type { ReputationFeedLoadOptions } from "./reputation-feed.js";
import { loadThreatsFromDirs } from "./threat-loader.js";
import { normalizeToolEvaluationRequest, readFileEditPayload } from "./tool-normalization.js";
import { applyToxicFlow } from "./toxic-flow.js";
import { loadTrustedDomains } from "./trusted-domains.js";
import type {
	AgentRuntime,
	AmsiCheckResult,
	Artifact,
	CachedVerdict,
	Config,
	DelegationLineage,
	Logger,
	PackageCheckResult,
	UrlCheckResult,
	Verdict,
} from "./types.js";
import { nullLogger } from "./types.js";
import { VERSION } from "./version.js";

type CachedIntelMerged = { loadedAt: number; tag: string; merged: IntelMerged };
let cachedPackageIntel: CachedIntelMerged | null = null;

function intelCacheTag(
	config: Config,
	managedState: ManagedState,
	revocations: RevocationListV1 | null,
): string {
	const packsDir = String(config.intel_packs?.packs_dir ?? "");
	const trustedKeys = String(config.intel_packs?.trusted_keys_path ?? "");
	const serial =
		managedState.entitlement?.schema_version === 2 ? managedState.entitlement.serial : "";
	const revEpoch = revocations ? String(revocations.revocation_epoch ?? 0) : "0";
	const requireRevocations =
		config.licensing.revocations_enabled && config.licensing.public_keys_pem.length > 0;
	const revocationIdentity = JSON.stringify(revocations);
	return `${packsDir}|${trustedKeys}|${serial}|${requireRevocations}|${revEpoch}|${revocationIdentity}`;
}

async function getPackageIntelMerged(
	config: Config,
	managedState: ManagedState,
	revocations: RevocationListV1 | null,
): Promise<IntelMerged | null> {
	const packsEnabled = config.intel_packs?.enabled === true || config.intel?.enabled === true;
	if (!packsEnabled) return null;

	// Commercial/managed: intel packs are a premium module; only enable when entitled.
	const enforcePremium = isCommercialBuild() || config.mode === "managed";
	if (enforcePremium && !isPremiumModuleEnabled(managedState, "intel_packs")) {
		cachedPackageIntel = null;
		return null;
	}

	const ttlMs = Math.max(0, Number(config.intel_packs?.cache_ttl_seconds ?? 60)) * 1000;
	const now = Date.now();
	const tag = intelCacheTag(config, managedState, revocations);
	if (
		cachedPackageIntel &&
		cachedPackageIntel.tag === tag &&
		now - cachedPackageIntel.loadedAt < ttlMs
	)
		return cachedPackageIntel.merged;

	try {
		const merged = await loadMergedIntelFromDisk({
			packsDir: config.intel_packs?.packs_dir,
			trustedKeysPath: config.intel_packs?.trusted_keys_path,
			verificationMode: "grace",
			graceHours: config.intel_packs?.expired_grace_hours ?? 72,
			requireRevocations:
				config.licensing.revocations_enabled && config.licensing.public_keys_pem.length > 0,
			revocations: revocations
				? {
						pack_ids: revocations.revocations?.pack_ids,
						key_ids: revocations.revocations?.key_ids,
					}
				: null,
		});
		cachedPackageIntel = { loadedAt: now, tag, merged };
		return merged;
	} catch {
		return {
			...emptyIntelMerged(),
			availability: "unavailable",
			detail: "signed intel-pack loading failed",
		};
	}
}

export interface ToolEvaluationRequest {
	sessionId: string;
	toolName: string;
	toolInput: Record<string, unknown>;
	artifacts: Artifact[];
}

/**
 * Delegated-credential context for a tool call.
 *
 * Supplying it is opt-in. A connector that holds no delegated credential keeps
 * calling the evaluator with an unchanged context, and a call that carries no
 * delegation context is never denied for that reason. The expected fields are
 * the verifier's own verification context, reusing its definition of what
 * "bound to this exact call" means instead of restating it here.
 */
export interface ToolDelegationContext extends DelegatedCredentialVerificationContext {
	/** Compact `aidr-delegation+jwt` credential presented with this tool call. */
	token: string;
	/** Trusted Ed25519 public keys (SPKI base64 or PEM) by key id. */
	publicKeysById: Readonly<Record<string, string>>;
}

export interface ToolEvaluationContext {
	threatsDir: string;
	allowlistsDir: string;
	configPath?: string;
	/** Soft-gated hosts block paranoid asks; record their enforced decision before audit/ingest. */
	promoteParanoidAsk?: boolean;
	userThreatsDir?: string;
	agentRuntime?: AgentRuntime;
	agentRuntimeVersion?: string;
	logger?: Logger;
	/** Trusted caller-owned detector policy. Tool payloads must never select their tenant. */
	runtimeDetectors?: {
		tenantId: string;
		dlp?: { enabled: boolean; policy: DlpPolicy; contentType?: string };
		/** Signed tenant floor for prompt jailbreak / content-safety actions (prompt hooks only). */
		promptSafety?: TenantPromptSafetyPolicy;
		behavioral?: {
			enabled: boolean;
			orchestrator: BehavioralDetectionOrchestrator;
			/** Only an operator-approved baseline workflow should set this to true. */
			learningAllowed?: boolean;
			/** Signed tenant choice for cold or unavailable baseline-dependent legs. */
			unavailableAction?: "ask" | "deny" | "skip";
		};
	};
	/** Verified, local signed feed configuration; absent means no feed claim. */
	reputationFeed?: ReputationFeedLoadOptions;
	/**
	 * The caller can execute the tool with `Verdict.transformedInput` in place of
	 * the original input. Only then may a DLP `redact` outcome become an allow
	 * carrying the redacted input; otherwise redaction is enforced as a deny,
	 * because passing the original payload through would disclose the value.
	 */
	supportsInputRewrite?: boolean;
	/**
	 * Delegated credential authorizing this exact call. Absent means the caller
	 * makes no delegation claim, and the call is evaluated exactly as before.
	 */
	delegation?: ToolDelegationContext;
	/**
	 * Trusted agent permission profiles for this connector (local document and,
	 * in managed mode, the signed tenant section). Absent means no profile
	 * restricts the call. Profiles only ever make a verdict stricter.
	 */
	agentProfiles?: AgentProfileContext;
	/**
	 * Host-reported absolute working directory of the agent session. Selects
	 * repository-scoped profiles and anchors `${workspace}` and relative paths.
	 * Defaults to the process working directory.
	 */
	workingDirectory?: string;
}

const DETECTOR_DECISION_RANK = { allow: 0, ask: 1, deny: 2 } as const;

function hostEffectiveVerdict(
	verdict: Verdict,
	config: Config,
	context: ToolEvaluationContext,
): Verdict {
	return context.promoteParanoidAsk &&
		config.sensitivity === "paranoid" &&
		verdict.decision === "ask"
		? { ...verdict, decision: "deny" }
		: verdict;
}

function detectorVerdict(
	decision: "ask" | "deny",
	category: string,
	source: string,
	reason: string,
	matchedThreatId: string | null = null,
): Verdict {
	return {
		decision,
		category,
		confidence: 1,
		severity: decision === "deny" ? "critical" : "warning",
		source,
		artifacts: [],
		matchedThreatId,
		reasons: [reason],
	};
}

function behavioralUnavailableVerdict(action: "ask" | "deny" | "skip", reason: string): Verdict {
	if (action === "skip") {
		return {
			...allowVerdict("behavioral"),
			category: "behavioral_unavailable",
			severity: "warning",
			reasons: [reason],
		};
	}
	return detectorVerdict(action, "behavioral_unavailable", "behavioral", reason);
}

function auditToolInputForVerdict(
	toolInput: Record<string, unknown>,
	verdict: Verdict,
	context: ToolEvaluationContext,
): Record<string, unknown> {
	// Tenant DLP matches can be arbitrary business secrets that the generic
	// credential redactor does not know. Never copy their raw payload into an
	// audit summary or remote event when the configured detector determined the
	// outcome (including unavailable inspection).
	// A canary trigger may carry the decoy token value itself; it never enters a
	// log or remote event (the verdict names the canary id instead).
	if (verdict.category === CANARY_TRIGGERED_CATEGORY) return { content_omitted: "canary trigger" };
	return context.runtimeDetectors?.dlp?.enabled === true ||
		verdict.source === "dlp" ||
		verdict.category === "behavioral_unavailable" ||
		verdict.source === "runtime_detectors"
		? { content_omitted: "runtime detector decision" }
		: toolInput;
}

function mergeDetectorVerdict(current: Verdict, candidate: Verdict | null, base: Verdict): Verdict {
	if (!candidate) return current;
	return DETECTOR_DECISION_RANK[candidate.decision] > DETECTOR_DECISION_RANK[current.decision] ||
		(candidate.decision === current.decision && current === base)
		? candidate
		: current;
}

function isUrlCheckResult(value: unknown): value is UrlCheckResult {
	if (!value || typeof value !== "object") return false;
	const result = value as Partial<UrlCheckResult>;
	return (
		typeof result.url === "string" &&
		typeof result.isMalicious === "boolean" &&
		Array.isArray(result.findings) &&
		Array.isArray(result.flags)
	);
}

type DlpDetectorContext = NonNullable<
	NonNullable<ToolEvaluationContext["runtimeDetectors"]>["dlp"]
>;

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sameKeys(left: Record<string, unknown>, right: Record<string, unknown>): boolean {
	const leftKeys = Object.keys(left).sort();
	const rightKeys = Object.keys(right).sort();
	return (
		leftKeys.length === rightKeys.length && leftKeys.every((key, index) => key === rightKeys[index])
	);
}

/**
 * Redact the connector's original tool input under the tenant policy.
 *
 * Returns the replacement input only when every check holds: the original
 * payload itself scans to `redact`, the redacted text is a JSON object with the
 * same top-level parameters (a rule may not rename or drop a parameter), and a
 * rescan of the result under the same policy finds nothing left to act on and
 * no common PII. Anything else returns null and the caller denies.
 */
function redactToolInput(
	detector: DlpDetectorContext,
	tenantId: string,
	original: Record<string, unknown>,
): Record<string, unknown> | null {
	const contentType = detector.contentType ?? "application/json";
	// The rewritten input is executed, so replacements must be inert words
	// (`REDACTED_EMAIL`), never display placeholders that a shell globs.
	const scan = scanDlpInput(detector.policy, {
		tenantId,
		content: JSON.stringify(original),
		contentType,
		replacementStyle: "shell_inert",
	});
	if (
		scan.status !== "inspected" ||
		scan.action !== "redact" ||
		typeof scan.transformedContent !== "string"
	) {
		return null;
	}
	const transformed: unknown = JSON.parse(scan.transformedContent);
	if (!isPlainObject(transformed) || !sameKeys(original, transformed)) return null;
	const recheckContent = JSON.stringify(transformed);
	const recheck = scanDlpInput(detector.policy, { tenantId, content: recheckContent, contentType });
	if (recheck.status !== "inspected" || recheck.action !== "allow") return null;
	if (evaluateCommonPiiBaseline(detector.policy, recheckContent).finding !== null) return null;
	return transformed;
}

function dlpRedactedVerdict(
	findings: DlpFinding[],
	transformedInput: Record<string, unknown>,
): Verdict {
	const ruleIds = [...new Set(findings.map((finding) => finding.ruleId))];
	const labels = [...new Set(findings.map((finding) => finding.labelName))];
	return {
		decision: "allow",
		category: "dlp_redacted",
		confidence: 1,
		severity: "warning",
		source: "dlp",
		artifacts: [],
		matchedThreatId: ruleIds[0] ?? null,
		reasons: [
			`DLP redaction applied: ${findings.length} value(s) matching ${labels.join(", ")} (rule ${ruleIds.join(", ")}) were replaced before the tool ran.`,
		],
		transformedInput,
	};
}

/**
 * The tenant rules' own outcome; null when the policy allows the content.
 *
 * `rewriteSource` is the connector's original tool input when the connector
 * executes a rewritten payload (`supportsInputRewrite`); otherwise null.
 */
function tenantDlpVerdict(
	dlp: DlpScanResult,
	detector: DlpDetectorContext,
	tenantId: string,
	rewriteSource: Record<string, unknown> | null,
): Verdict | null {
	if (dlp.status === "unavailable") {
		return detectorVerdict(
			dlp.action === "block" ? "deny" : "ask",
			"dlp_unavailable",
			"dlp",
			`DLP inspection unavailable: ${dlp.unavailable.reason}.`,
		);
	}
	if (dlp.action === "allow") return null;
	if (dlp.action === "redact") {
		// Only a connector that executes the rewritten payload may receive an
		// allow here. Passing a redact result through anywhere else would
		// disclose the original value, so it is enforced as a deny.
		const transformed = rewriteSource ? redactToolInput(detector, tenantId, rewriteSource) : null;
		if (transformed) return dlpRedactedVerdict(dlp.findings, transformed);
		return detectorVerdict(
			"deny",
			"dlp",
			"dlp",
			rewriteSource
				? "DLP redaction required, but a safe redacted tool input could not be produced; the call was blocked."
				: "DLP redaction required; this connector cannot rewrite tool input.",
			dlp.findings[0]?.ruleId ?? null,
		);
	}
	return detectorVerdict(
		dlp.action === "ask" ? "ask" : "deny",
		"dlp",
		"dlp",
		`DLP policy requires ${dlp.action}.`,
		dlp.findings[0]?.ruleId ?? null,
	);
}

function evaluateDlpDetector(
	detector: DlpDetectorContext,
	tenantId: string,
	content: string,
	rewriteSource: Record<string, unknown> | null,
): Verdict | null {
	try {
		const dlp = scanDlpInput(detector.policy, {
			tenantId,
			content,
			contentType: detector.contentType ?? "application/json",
		});
		// Built-in common-PII baseline, governed by the tenant policy's reserved
		// `pii-<type>` rules and exceptions (see pii-baseline.ts). Oversized input
		// is reported as unavailable rather than partially scanned.
		const baseline =
			dlp.status === "unavailable" && dlp.unavailable.reason === "oversize"
				? null
				: evaluateCommonPiiBaseline(detector.policy, content).finding;
		const baselineVerdict = baseline
			? detectorVerdict(
					baseline.decision,
					"dlp",
					"dlp",
					baseline.decision === "ask"
						? `Common PII (${baseline.type}) detected; tenant DLP policy requires approval.`
						: `Common PII (${baseline.type}) detected; original tool input was blocked.`,
					baseline.ruleId,
				)
			: null;
		if (baselineVerdict?.decision === "deny") return baselineVerdict;
		const tenantVerdict = tenantDlpVerdict(dlp, detector, tenantId, rewriteSource);
		return tenantVerdict?.decision === "deny" ? tenantVerdict : (baselineVerdict ?? tenantVerdict);
	} catch {
		return detectorVerdict(
			"deny",
			"dlp_unavailable",
			"dlp",
			"Configured DLP policy or tenant binding could not be validated.",
		);
	}
}

async function evaluateBehavioralDetector(
	detector: NonNullable<NonNullable<ToolEvaluationContext["runtimeDetectors"]>["behavioral"]>,
	request: ToolEvaluationRequest,
	tenantId: string,
	content: string,
	currentVerdict: Verdict,
): Promise<Verdict | null> {
	try {
		const input = request.toolInput;
		const behavioral = await detector.orchestrator.evaluate({
			tenantId,
			sessionId: request.sessionId,
			toolName: request.toolName,
			riskScore:
				currentVerdict.decision === "deny" ? 100 : currentVerdict.decision === "ask" ? 75 : 0,
			timestamp: Date.now(),
			command: typeof input.command === "string" ? input.command : undefined,
			path: typeof input.file_path === "string" ? input.file_path : undefined,
			url: typeof input.url === "string" ? input.url : undefined,
			classificationText: content,
			// No authenticated post-execution receipt reaches preflight. Keep learning
			// off until receipt verification is bound to baseline writes and restore.
			learningAllowed: false,
		});
		if (behavioral.outcome === "anomalous") {
			return detectorVerdict(
				"ask",
				"behavioral_anomaly",
				"behavioral",
				`Behavioral anomaly detected (score ${behavioral.anomalyScore ?? "unknown"}).`,
			);
		}
		if (behavioral.outcome === "learning" || behavioral.outcome === "unavailable") {
			const action = detector.unavailableAction ?? "ask";
			const reason =
				behavioral.outcome === "learning"
					? "Behavioral baseline-dependent legs are not ready; this call was not evaluated by those legs."
					: "Behavioral detection is unavailable; no clean result is available from that detector.";
			return behavioralUnavailableVerdict(action, reason);
		}
		return null;
	} catch {
		return detectorVerdict(
			"ask",
			"behavioral_unavailable",
			"behavioral",
			"Configured behavioral detection could not inspect this call.",
		);
	}
}

function lineageFromClaims(claims: DelegatedCredentialClaimsV1): DelegationLineage {
	return {
		issuer: claims.issuer,
		tenantId: claims.tenantId,
		subjectUserId: claims.subjectUserId,
		agentId: claims.agentId,
		tool: { serverId: claims.tool.serverId, name: claims.tool.name },
		resource: { type: claims.resource.type, id: claims.resource.id },
		audience: claims.audience,
		scopes: [...claims.scopes],
		tokenId: claims.tokenId,
		delegationDepth: claims.delegationDepth,
		expiresAt: claims.expiresAt,
		...(claims.parentTokenId === undefined ? {} : { parentTokenId: claims.parentTokenId }),
	};
}

/**
 * Verify the delegated credential bound to a call, without letting a refusal
 * fall through to the detectors.
 *
 * The verifier's machine-readable code is the reason prefix
 * (`delegation_denied:<code>`), so an operator - or a log pipeline - can tell
 * `audience_mismatch` from `scope_insufficient` from `token_expired` from
 * `delegation_escalation` without parsing prose. Only a credential that
 * verified against this exact call yields lineage; unauthorized claims are
 * never recorded as if they had been accepted.
 */
function evaluateDelegation(
	delegation: ToolDelegationContext,
	toolName: string,
): { verdict: Verdict } | { lineage: DelegationLineage } {
	const { token, publicKeysById, ...verificationContext } = delegation;
	let code: DelegatedCredentialErrorCode;
	try {
		const result = verifyDelegatedCredential({
			token,
			publicKeysById,
			// The caller may supply expected metadata, but the tool name must come
			// from the call being evaluated rather than that parallel metadata.
			context: { ...verificationContext, tool: { ...verificationContext.tool, name: toolName } },
		});
		if (result.ok) return { lineage: lineageFromClaims(result.claims) };
		code = result.code;
	} catch {
		// A verifier that throws must not become a pass.
		code = "invalid_context";
	}
	const refused = detectorVerdict(
		"deny",
		"delegation_denied",
		"delegation",
		`delegation_denied:${code}`,
	);
	return {
		verdict: {
			...refused,
			reasons: [
				...refused.reasons,
				`The delegated credential presented with this ${toolName} call was refused (${code}); the call was blocked instead of being forwarded.`,
			],
		},
	};
}

/**
 * Do not turn a configured inspection failure into a clean allow.
 *
 * A delegated credential is an authorization claim about this exact call, so it
 * is checked before any detector: a refusal is a hard DENY that no detector
 * outcome may soften, and it cannot be skipped merely because no other runtime
 * detector is configured. With no delegation context this is a pass-through, so
 * calls that carry no credential keep their previous behaviour exactly.
 */
async function applyRuntimeDetectors(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	config: Config,
	baseVerdict: Verdict,
	managedState: ManagedState,
	rewriteSource: Record<string, unknown> | null,
): Promise<Verdict> {
	const delegationOutcome = context.delegation
		? evaluateDelegation(context.delegation, request.toolName)
		: null;
	if (delegationOutcome && "verdict" in delegationOutcome) return delegationOutcome.verdict;
	const tenantScopedDetectorsEnabled =
		context.runtimeDetectors?.dlp?.enabled === true ||
		context.runtimeDetectors?.behavioral?.enabled === true;
	if (
		delegationOutcome &&
		tenantScopedDetectorsEnabled &&
		context.runtimeDetectors?.tenantId !== delegationOutcome.lineage.tenantId
	) {
		// The signed delegation lineage and tenant-scoped detector state must name
		// the same tenant. Otherwise one tenant's call could be evaluated against
		// another tenant's DLP policy or behavioral baseline, while its audit entry
		// attributes the call to the signed tenant.
		return {
			...detectorVerdict(
				"deny",
				"tenant_isolation",
				"runtime_detectors",
				"Delegated identity tenant does not match tenant-scoped detector context.",
			),
			delegation: delegationOutcome.lineage,
		};
	}

	const checked = await recheckRedactedInput(
		await applyConfiguredDetectors(request, context, baseVerdict, managedState, rewriteSource),
		request,
		context,
		config,
	);
	const canaryGap = canaryUnavailableByRequest.get(request);
	const verdict = canaryGap ? canaryUnavailableVerdict(checked, canaryGap) : checked;
	return delegationOutcome ? { ...verdict, delegation: delegationOutcome.lineage } : verdict;
}

/**
 * Requests whose canary check could not run, with the reason. Set by the early
 * canary check and read where every pipeline path settles its verdict
 * (`applyRuntimeDetectors`), so a skipped check is never reported as clean.
 */
const canaryUnavailableByRequest = new WeakMap<ToolEvaluationRequest, string>();

/**
 * Canary check, run before any other leg: a call that touches a decoy is
 * denied outright (no allowlist, approval or cached verdict applies), and no
 * reputation lookup ever receives the decoy value. Detection-internal failures
 * are skipped, logged and remembered for the final verdict.
 */
function checkToolCallCanaries(request: ToolEvaluationRequest, logger: Logger): Verdict | null {
	const inspection = inspectToolInputForCanaries(request.toolInput);
	if (inspection.status === "triggered") return canaryTriggeredVerdict(inspection.hits);
	if (inspection.status === "unavailable") {
		canaryUnavailableByRequest.set(request, inspection.reason);
		logger.warn("Canary credential check unavailable; signal skipped", {
			reason: inspection.reason,
		});
	}
	return null;
}

/**
 * Record a canary trigger seen outside the pre-execution tool check (tool
 * output after execution, a user prompt): audit entry, and in managed mode an
 * incident through the same path as a blocked tool call. Never throws; the
 * returned deny verdict is what the caller enforces.
 */
export async function recordCanaryTrigger(params: {
	sessionId: string;
	toolName: string;
	hits: readonly CanaryHit[];
	stage: Exclude<CanaryStage, "tool_input">;
	configPath?: string;
	logger?: Logger;
	agentRuntime?: AgentRuntime;
	agentRuntimeVersion?: string;
}): Promise<Verdict> {
	const verdict = canaryTriggeredVerdict(params.hits, params.stage);
	const logger = params.logger ?? nullLogger;
	try {
		const config = await loadConfig(params.configPath, logger);
		if (isInvalidConfig(config)) return verdict;
		await recordEarlyVerdict(
			{
				sessionId: params.sessionId,
				toolName: params.toolName,
				toolInput: { content_omitted: params.stage },
				artifacts: [],
			},
			{
				threatsDir: "",
				allowlistsDir: "",
				configPath: params.configPath,
				agentRuntime: params.agentRuntime,
				agentRuntimeVersion: params.agentRuntimeVersion,
				logger,
			},
			config,
			verdict,
			logger,
			performance.now(),
		);
	} catch {
		// Recording cannot change the enforced decision.
	}
	return verdict;
}

async function applyConfiguredDetectors(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	baseVerdict: Verdict,
	managedState: ManagedState,
	rewriteSource: Record<string, unknown> | null,
): Promise<Verdict> {
	const detectors = context.runtimeDetectors;
	if (!detectors || (detectors.dlp?.enabled !== true && detectors.behavioral?.enabled !== true)) {
		return baseVerdict;
	}

	const tenantId = detectors.tenantId;
	if (typeof tenantId !== "string" || tenantId.trim() === "" || tenantId.length > 128) {
		return detectorVerdict(
			"deny",
			"detection_unavailable",
			"runtime_detectors",
			"Detector tenant identity is missing or invalid.",
		);
	}
	if (
		managedState.entitlement?.schema_version === 2 &&
		managedState.entitlement.tenant_id !== tenantId
	) {
		return detectorVerdict(
			"deny",
			"tenant_isolation",
			"runtime_detectors",
			"Detector tenant does not match the signed managed entitlement.",
		);
	}

	let content: string;
	try {
		content = JSON.stringify(request.toolInput);
		if (typeof content !== "string") throw new Error("Tool input cannot be serialized");
	} catch {
		return detectorVerdict(
			"deny",
			"detection_unavailable",
			"runtime_detectors",
			"Tool input could not be serialized for configured inspection.",
		);
	}

	let result = baseVerdict;
	if (detectors.dlp?.enabled === true) {
		result = mergeDetectorVerdict(
			result,
			evaluateDlpDetector(detectors.dlp, tenantId, content, rewriteSource),
			baseVerdict,
		);
	}

	if (detectors.behavioral?.enabled === true) {
		result = mergeDetectorVerdict(
			result,
			await evaluateBehavioralDetector(detectors.behavioral, request, tenantId, content, result),
			baseVerdict,
		);
	}
	// Even when another detector has higher precedence, its artifact list may
	// contain a tenant-specific value that generic redaction cannot recognize.
	return detectors.dlp?.enabled === true && result.artifacts.length > 0
		? { ...result, artifacts: [] }
		: result;
}

async function recordEarlyVerdict(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	config: Config,
	verdict: Verdict,
	logger: Logger,
	startTime: number,
	allowlisted = false,
): Promise<void> {
	const durationMs = performance.now() - startTime;
	let incidentEntry: Record<string, unknown> | null = null;
	const auditInput = auditToolInputForVerdict(request.toolInput, verdict, context);
	if (
		config.mode === "managed" &&
		config.response.emit_incidents &&
		(verdict.decision === "ask" || verdict.decision === "deny")
	) {
		try {
			incidentEntry = buildIncidentEntry({
				incidentId: `inc_${request.sessionId}_${Date.now()}`,
				sessionId: request.sessionId,
				toolName: request.toolName,
				toolInput: auditInput,
				verdict,
				recommendedActions: verdict.decision === "deny" ? ["review", "block"] : ["review"],
			});
			await logIncident(config.logging, incidentEntry);
		} catch {
			incidentEntry = null;
		}
	}
	try {
		await logVerdict(
			config.logging,
			request.sessionId,
			request.toolName,
			auditInput,
			verdict,
			allowlisted,
			durationMs,
		);
	} catch {
		// An audit failure cannot erase the detector decision.
	}
	if (verdict.decision !== "allow") {
		try {
			await ingestToControlPlaneIfEnabled(
				request,
				context,
				config,
				verdict,
				incidentEntry,
				logger,
				durationMs,
			);
		} catch {
			// Telemetry failure cannot erase the local decision.
		}
	}
}

/**
 * Session toxic-flow detection (docs/toxic-flow.md), applied after every other
 * layer so it sees their decision: a deny is left alone and not recorded, an
 * allow or ask is recorded into the session and may be escalated when this
 * call completes a dangerous chain. It never throws; state failures come back
 * as a marked, non-clean verdict.
 */
function applySessionFlow(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	config: Config,
	verdict: Verdict,
	allowlisted = false,
): Promise<Verdict> {
	return applyToxicFlow(request, verdict, config, {
		agentRuntime: context.agentRuntime,
		logger: context.logger ?? nullLogger,
		allowlisted,
	});
}

export function allowVerdict(source = "none"): Verdict {
	return {
		decision: "allow",
		category: "none",
		confidence: 1.0,
		severity: "info",
		source,
		artifacts: [],
		matchedThreatId: null,
		reasons: [],
	};
}

export async function evaluateToolCall(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
): Promise<Verdict> {
	const normalizedRequest = normalizeToolEvaluationRequest(request);
	const startTime = performance.now();
	// Redaction must rewrite the payload the connector will actually execute,
	// not the alias-expanded copy the detectors inspect.
	const rewriteSource = context.supportsInputRewrite === true ? request.toolInput : null;
	return runEvaluationPipeline(normalizedRequest, context, startTime, rewriteSource);
}

function invalidConfigVerdict(): Verdict {
	return {
		...allowVerdict("config_invalid"),
		decision: "deny",
		category: "config_invalid",
		severity: "critical",
		reasons: ["Singularity AIDR configuration is invalid; this tool call was blocked."],
	};
}

function uninspectablePatchVerdict(): Verdict {
	return {
		decision: "deny",
		category: "file_write",
		confidence: 1,
		severity: "critical",
		source: "policy",
		artifacts: ["apply_patch"],
		matchedThreatId: "POL-FS-003",
		reasons: [
			"apply_patch targets or added content could not be fully parsed; execution was denied.",
		],
	};
}

function ambiguousToolInputVerdict(): Verdict {
	return {
		decision: "deny",
		category: "input_ambiguous",
		confidence: 1,
		severity: "critical",
		source: "policy",
		artifacts: [],
		matchedThreatId: "POL-INPUT-001",
		reasons: [
			"Conflicting connector input aliases could not be safely normalized; execution was denied.",
		],
	};
}

function malformedCommandVerdict(): Verdict {
	return {
		decision: "deny",
		category: "malformed_command",
		confidence: 1,
		severity: "critical",
		source: "policy",
		artifacts: [],
		matchedThreatId: "POL-INPUT-002",
		reasons: [
			"Shell command was neither a string nor a well-formed argv array, so the executed command could not be inspected; execution was denied.",
		],
	};
}

function truncatedCommandVerdict(): Verdict {
	return {
		decision: "deny",
		category: "input_truncated",
		confidence: 1,
		severity: "critical",
		source: "policy",
		artifacts: ["Bash"],
		matchedThreatId: null,
		reasons: [
			`Bash command exceeds the ${MAX_ARTIFACT_SIZE}-character inspection limit; execution was denied because trailing input was not inspected.`,
		],
	};
}

interface LoadedHeuristics {
	engine: HeuristicsEngine;
	threatsLoaded: number;
	/** The same rules, indexed for the code guard (`match_on: code:<language>`). */
	codeRules: CodeRuleSet;
	modelSources: TrustedModelSources;
}

/** The local threat rules this call is matched against, honouring `disabled_threats`. */
async function loadHeuristics(
	context: ToolEvaluationContext,
	config: Config,
	logger: Logger,
): Promise<LoadedHeuristics> {
	const userThreatsDir = context.userThreatsDir ?? resolvePath("~/.singularity-aidr/threats");
	let threats = await loadThreatsFromDirs([context.threatsDir, userThreatsDir], logger);
	if (config.disabled_threats.length > 0) {
		const disabledSet = new Set(config.disabled_threats);
		threats = threats.filter((t) => !disabledSet.has(t.id));
	}
	const trustedDomains = await loadTrustedDomains(context.allowlistsDir, logger);
	const modelSources = await loadTrustedModelSources(
		context.allowlistsDir,
		config.ai_supply_chain,
		logger,
	);
	return {
		engine: new HeuristicsEngine(threats, trustedDomains, modelSources),
		threatsLoaded: threats.length,
		codeRules: new CodeRuleSet(threats, config.disabled_threats),
		modelSources,
	};
}

/**
 * The code-guard leg (AI supply-chain and secure-code rules over the code this
 * call writes or runs). A failure here is a detection-internal failure: the
 * signal is skipped and logged, never reported as a clean inspection.
 */
function inspectCodeLeg(
	request: ToolEvaluationRequest,
	loaded: LoadedHeuristics,
	config: Config,
	logger: Logger,
): CodeGuardResult {
	try {
		return inspectToolCallCode(
			request.toolName,
			request.toolInput,
			loaded.codeRules,
			loaded.modelSources,
			config.secure_code,
		);
	} catch (error) {
		logger.warn("Code inspection leg did not run; model-loading and secure-code rules skipped", {
			errorType: error instanceof Error ? error.name : typeof error,
		});
		return EMPTY_CODE_GUARD_RESULT;
	}
}

/** Normalization flags that mean the tool input could not be read unambiguously. */
const UNINSPECTABLE_INPUT_FLAGS = [
	"__aidr_input_normalization_failed",
	"__aidr_malformed_command",
	"__aidr_patch_parse_failed",
] as const;

/**
 * DLP redaction changes what the tool executes, so the rewritten input is a new
 * tool call and must pass the threat rules itself: replacing a value can turn
 * a harmless argument into a dangerous one (a glob, a path traversal, a flag).
 * The rewritten input is denied when it cannot be fully inspected or when it
 * matches a threat rule the original input did not match and that match alone
 * would not be allowed. Any failure here denies, because the connector would
 * otherwise execute an input nothing inspected.
 */
async function recheckRedactedInput(
	verdict: Verdict,
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	config: Config,
): Promise<Verdict> {
	const transformed = verdict.transformedInput;
	if (verdict.decision !== "allow" || !transformed) return verdict;
	const unsafe = (reason: string, matchedThreatId: string | null = null): Verdict =>
		detectorVerdict(
			"deny",
			"dlp_redaction_unsafe",
			"dlp",
			`DLP redaction produced a tool input that ${reason}; the call was blocked.`,
			matchedThreatId,
		);
	try {
		const rewritten = normalizeToolEvaluationRequest({
			...request,
			toolInput: transformed,
			artifacts: extractFromToolCall(request.toolName, transformed),
		});
		if (
			UNINSPECTABLE_INPUT_FLAGS.some((flag) => rewritten.toolInput[flag] === true) ||
			inspectionLimitsHit(rewritten.artifacts).length > 0 ||
			rewritten.artifacts.some(
				(artifact) => artifact.type === "command" && artifact.value.length > MAX_ARTIFACT_SIZE,
			)
		) {
			return unsafe("could not be fully inspected");
		}
		if (!config.heuristics_enabled || rewritten.artifacts.length === 0) return verdict;
		const { engine, threatsLoaded } = await loadHeuristics(
			context,
			config,
			context.logger ?? nullLogger,
		);
		if (threatsLoaded === 0) return unsafe("could not be checked against any threat rule");
		const before = new Set(engine.match(request.artifacts).map((match) => match.threat.id));
		const introduced = engine
			.match(rewritten.artifacts)
			.filter((match) => !before.has(match.threat.id));
		if (introduced.length === 0) return verdict;
		const decided = await new DecisionEngine(config.sensitivity).decide({
			heuristicMatches: introduced,
			urlCheckResults: [],
		});
		if (decided.decision === "allow") return verdict;
		return unsafe(
			"matches a threat rule the original input did not",
			decided.matchedThreatId ?? introduced[0]?.threat.id ?? null,
		);
	} catch {
		return unsafe("could not be re-inspected");
	}
}

/**
 * The agent permission profile outcome for this call, or null when no profile
 * restricts it. An unexpected evaluation failure is a deny: the profile is a
 * security control and must not silently disappear.
 */
async function evaluateAgentProfileVerdict(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
): Promise<Verdict | null> {
	const profiles = context.agentProfiles;
	if (!profiles || profiles.layers.length === 0) return null;
	const reported = context.workingDirectory?.trim();
	const workingDirectory = reported && isAbsolute(reported) ? reported : process.cwd();
	try {
		const evaluation = await evaluateAgentProfiles(
			profiles,
			{ toolName: request.toolName, toolInput: request.toolInput, artifacts: request.artifacts },
			{ workingDirectory },
		);
		return agentProfileVerdict(evaluation);
	} catch {
		return agentProfileFailureVerdict();
	}
}

/** MCP calls reach the evaluator as `mcp__<server>__<tool>` or the host's generic `MCP` tool. */
function isMcpToolName(toolName: string): boolean {
	return toolName === "MCP" || toolName.startsWith("mcp__");
}

/**
 * Inspection limits the tool input exceeded. The extractor reports them as
 * marker artifacts; for MCP tools the input is additionally re-walked here, so
 * a connector that builds its own artifact list cannot drop the signal.
 */
function uninspectedInputLimits(request: ToolEvaluationRequest): InspectionLimit[] {
	const limits = new Set(inspectionLimitsHit(request.artifacts));
	if (isMcpToolName(request.toolName)) {
		const walked = extractFromUnknownTool(request.toolName, request.toolInput);
		for (const limit of inspectionLimitsHit(walked)) limits.add(limit);
	}
	return [...limits];
}

function inputNotFullyInspectedVerdict(limits: InspectionLimit[]): Verdict {
	return {
		decision: "deny",
		category: INPUT_NOT_FULLY_INSPECTED,
		confidence: 1,
		severity: "critical",
		source: "policy",
		artifacts: [],
		matchedThreatId: "POL-INPUT-003",
		reasons: [
			`${INPUT_NOT_FULLY_INSPECTED}: tool input exceeds the inspection limits (${limits.join(", ")}); execution was denied because part of the input was not inspected.`,
		],
	};
}

async function runEvaluationPipeline(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	startTime: number,
	rewriteSource: Record<string, unknown> | null,
): Promise<Verdict> {
	const logger = context.logger ?? nullLogger;
	let config: Config;
	try {
		config = await loadConfig(context.configPath, logger);
	} catch {
		return invalidConfigVerdict();
	}
	if (isInvalidConfig(config)) {
		const verdict = invalidConfigVerdict();
		await recordEarlyVerdict(request, context, config, verdict, logger, startTime);
		return verdict;
	}
	const canaryVerdict = checkToolCallCanaries(request, logger);
	if (canaryVerdict) {
		await recordEarlyVerdict(request, context, config, canaryVerdict, logger, startTime);
		return canaryVerdict;
	}
	if (request.toolInput.__aidr_input_normalization_failed === true) {
		const verdict = ambiguousToolInputVerdict();
		await recordEarlyVerdict(request, context, config, verdict, logger, startTime);
		return verdict;
	}
	if (request.toolInput.__aidr_malformed_command === true) {
		const verdict = malformedCommandVerdict();
		await recordEarlyVerdict(request, context, config, verdict, logger, startTime);
		return verdict;
	}
	if (request.toolInput.__aidr_patch_parse_failed === true) {
		const verdict = uninspectablePatchVerdict();
		await recordEarlyVerdict(request, context, config, verdict, logger, startTime);
		return verdict;
	}
	const rawBashCommand = request.toolName === "Bash" ? request.toolInput.command : undefined;
	if (
		(typeof rawBashCommand === "string" && rawBashCommand.length > MAX_ARTIFACT_SIZE) ||
		request.artifacts.some(
			(artifact) => artifact.type === "command" && artifact.value.length > MAX_ARTIFACT_SIZE,
		)
	) {
		const verdict = truncatedCommandVerdict();
		await recordEarlyVerdict(request, context, config, verdict, logger, startTime);
		return verdict;
	}
	const uninspected = uninspectedInputLimits(request);
	if (uninspected.length > 0) {
		const verdict = inputNotFullyInspectedVerdict(uninspected);
		await recordEarlyVerdict(request, context, config, verdict, logger, startTime);
		return verdict;
	}
	// A profile deny is final: nothing downstream can soften it. An ask (or an
	// allow) is merged into whatever detection decides, deny > ask > allow.
	const profileVerdict = await evaluateAgentProfileVerdict(request, context);
	if (profileVerdict?.decision === "deny") {
		await recordEarlyVerdict(request, context, config, profileVerdict, logger, startTime);
		return profileVerdict;
	}
	// Every exit below routes its verdict through here: tenant runtime
	// detectors, then session (toxic) flow, then the profile restriction,
	// then host promotion.
	const finalize = async (verdict: Verdict, allowlisted = false): Promise<Verdict> =>
		hostEffectiveVerdict(
			mergeAgentProfileVerdict(
				await applySessionFlow(
					request,
					context,
					config,
					await applyRuntimeDetectors(
						request,
						context,
						config,
						verdict,
						managedState,
						rewriteSource,
					),
					allowlisted,
				),
				profileVerdict,
			),
			config,
			context,
		);
	const commercial = isCommercialBuild();
	// Computed once: the same manifest edits decide whether this request has
	// anything for the package leg to inspect at all (see the empty-artifact
	// fast path below) and what that leg then checks.
	const manifestEdits = manifestEditInputs(request);

	// Managed-only commercial behavior: without a valid auth token + signed entitlement (or offline grace),
	// the runtime does not enforce and becomes inert (allow-only).
	const disabled = (reason: string): Verdict =>
		mergeAgentProfileVerdict(disabledVerdict(reason), profileVerdict);
	const disabledVerdict = (reason: string): Verdict => {
		if (commercial) {
			return {
				decision: "ask",
				category: "managed_disabled",
				confidence: 1.0,
				severity: "warning",
				source: "managed_disabled",
				artifacts: [],
				matchedThreatId: null,
				reasons: [reason],
			};
		}
		return {
			...allowVerdict("managed_disabled"),
			// Keep the category consistent with the source. A licensing disable is not a
			// clean inspection, and a caller that logs only `category` must be able to
			// tell the two apart.
			category: "managed_disabled",
			reasons: [reason],
		};
	};

	// Commercial gating: if runtime integrity is degraded, do not enable protections.
	if (commercial && isDegradedSafeMode()) {
		return disabled(
			`AIDR disabled: degraded safe mode (${getDegradedSafeModeReason() ?? "integrity"}).`,
		);
	}

	const managedOnly = commercial || config.mode === "managed";
	const aidrDir = resolvePath("~/.singularity-aidr");
	const managedPath = managedStatePath();

	let token = (config.auth.api_key ?? "").trim();
	let managedState: ManagedState = {};
	let revocationsForIntel: RevocationListV1 | null = null;
	// Set when a managed/commercial installation has not completed enrollment or
	// entitlement acquisition. Managed-only features (signed intel packs, remote
	// policy, control-plane sync, entitlement-enforced premium modules) stay
	// disabled, but local heuristics/policy/allowlist detection MUST still run.
	// Returning an allow verdict here would silently disable the product's core
	// protection, which is exactly the failure mode this flag exists to prevent.
	const unenrolledReason =
		"AIDR is not enrolled: running local detection only (managed features disabled).";

	if (managedOnly) {
		// Effective auth token can come from config (api_key/enrollment_token) or from managed state cache.
		token = getAuthToken(config.auth) ?? "";
		managedState = await loadManagedState(managedPath, {
			authToken: token || undefined,
			publicKeysPem: config.licensing.public_keys_pem,
			onSecurityEvent: (event) =>
				logger.warn(
					"Managed state verification failure",
					event as unknown as Record<string, unknown>,
				),
		});
		const cachedApiKey =
			typeof managedState.api_key === "string" ? managedState.api_key.trim() : "";

		const apiKey = (config.auth.api_key ?? "").trim() || cachedApiKey || "";
		const enrollToken = (config.auth.enrollment_token ?? "").trim();

		if (!apiKey && !enrollToken) {
			// No credentials yet. Do NOT disable detection: fall through to local
			// evaluation with managed features switched off, and surface the state.
			logger.warn(unenrolledReason);
		}

		// If only enrollment_token is present, try to exchange it for an api_key.
		if (!apiKey && enrollToken && config.control_plane.enabled) {
			const iid = await getInstallationId(aidrDir).catch(() => undefined);
			if (!iid) {
				logger.warn(`${unenrolledReason} (missing installation id)`);
			} else {
				try {
					const client = new ControlPlaneClient(config.control_plane, enrollToken, logger);
					const res = await client.enroll({
						iid,
						agent_runtime: context.agentRuntime,
						agent_runtime_version: context.agentRuntimeVersion,
					});
					const issued =
						typeof res.body?.api_key === "string" ? (res.body.api_key as string).trim() : "";
					if (res.ok && issued) {
						managedState = applyIngestResult(
							managedState,
							{ ok: true, status: res.status, body: res.body },
							config.control_plane.grace_period_hours,
							{ authToken: issued, publicKeysPem: config.licensing.public_keys_pem },
						);
						managedState.api_key = issued;
						await saveManagedState(managedPath, managedState);
						await saveEntitlementKeyringFromState(managedState);
					}
				} catch {
					// Ignore; handled below by entitlement gating.
				}
			}
		}

		// Refresh token after potential enrollment exchange.
		token =
			(config.auth.api_key ?? "").trim() ||
			(typeof managedState.api_key === "string" ? managedState.api_key.trim() : "");

		// Whether this installation actually holds managed credentials. Managed-only
		// hard gates (missing iid, control plane off, unsigned entitlement) describe
		// a *broken enrolled* installation. An installation that was never enrolled
		// cannot satisfy any of them by construction - it has no iid (that file is
		// created during enrollment) and no signed entitlement - so evaluating those
		// gates against it is meaningless and, before this flag existed, turned every
		// un-enrolled managed/commercial install into a blanket deny.
		const hasCredentials = token.length > 0;

		if (!hasCredentials) {
			// Enrollment did not produce a key (unreachable control plane, rejected
			// token, or no token). Keep enforcing locally instead of going inert.
			logger.warn(unenrolledReason);
		}

		// Ensure we have a signed entitlement (or offline grace) before enforcing.
		// If missing, attempt a best-effort heartbeat to fetch it.
		// Respect managed sync backoff to avoid repeated remote attempts when over-limit / abuse-throttled.
		//
		// The credential check is what keeps an un-enrolled install out of here: with
		// no token there is nothing to authenticate the heartbeat with, and the gates
		// below must not be evaluated against it.
		//
		// Note this DOES run for an installation holding a credential that has not
		// validated yet. An enrolled commercial install that cannot produce a signed
		// entitlement must fail closed (see the gates below) - that is a licensing
		// control, and it is deliberately not relaxed here.
		if (hasCredentials && !isEntitlementActive(managedState) && !isSyncDisabled(managedState)) {
			try {
				const iid = await getInstallationId(aidrDir).catch(() => undefined);
				if (!iid) return disabled("AIDR disabled: missing installation id (iid).");

				if (!config.control_plane.enabled) {
					return disabled("AIDR disabled: control_plane.enabled=false (managed-only build).");
				}
				const client = new ControlPlaneClient(config.control_plane, token, logger);
				const result = await client.ingest({
					iid,
					agent_runtime: context.agentRuntime,
					agent_runtime_version: context.agentRuntimeVersion,
					events: [],
				});
				const next = applyIngestResult(
					managedState,
					result,
					config.control_plane.grace_period_hours,
					{ authToken: token, publicKeysPem: config.licensing.public_keys_pem },
				);
				if (next !== managedState) {
					managedState = next;
					await saveManagedState(managedPath, managedState);
					await saveEntitlementKeyringFromState(managedState);
				}
			} catch {
				// Ignore.
			}
		}

		// Require server-signed entitlements when configured and keys are present; otherwise remain inert.
		// This is a licensing control and applies to any installation holding credentials.
		if (
			config.licensing.require_signed_entitlements &&
			config.licensing.public_keys_pem.length > 0
		) {
			if (managedState.entitlement_alg !== "ed25519" || !isEntitlementActive(managedState)) {
				return disabled("AIDR disabled: missing or invalid server-signed entitlement (ed25519).");
			}
		}

		// Credentials exist but no signed entitlement was obtained: a mistyped,
		// rotated or revoked api_key, or an unreachable endpoint. Managed features are
		// genuinely unavailable, so record that state. It must never be used to grant
		// managed features - only to describe why they are off.
		if (hasCredentials && !isEntitlementActive(managedState)) {
			logger.warn(
				`${unenrolledReason} (credentials present but not validated by the control plane)`,
			);
		}

		// Best-effort: refresh revocations cache and apply after entitlement gating (startup order).
		try {
			let signedRev =
				config.licensing.revocations_enabled && config.licensing.public_keys_pem.length > 0
					? await loadRevocationsCache(
							resolvePath(config.licensing.revocations_cache_path),
							config.licensing.public_keys_pem,
						)
					: null;
			if (
				!signedRev &&
				config.licensing.revocations_enabled &&
				config.licensing.public_keys_pem.length > 0
			) {
				const client = new ControlPlaneClient(config.control_plane, token, logger);
				const res = await client.fetchRevocations();
				if (res.ok) {
					const parsed = parseSignedRevocationsFromControlPlaneBody(res.body);
					if (
						parsed &&
						verifyEd25519SignedRevocationList({
							list: parsed.payload,
							sig_b64: parsed.sig_b64,
							public_keys_pem: config.licensing.public_keys_pem,
						})
					) {
						await saveRevocationsCache(
							resolvePath(config.licensing.revocations_cache_path),
							parsed,
						);
						signedRev = parsed;
					}
				}
			}

			revocationsForIntel = signedRev?.payload ?? null;

			if (signedRev?.payload) {
				const iid = await getInstallationId(aidrDir).catch(() => undefined);
				if (iid) {
					const next = applyRevocationsToManagedState({
						state: managedState,
						iid,
						revocations: signedRev.payload,
					});
					if (next !== managedState) {
						managedState = next;
						await saveManagedState(managedPath, managedState);
					}
				}
			}
		} catch {
			// Fail open.
		}

		// If revocations disabled sync or invalidated the entitlement, stay inert.
		//
		// This is safe for an installation that never enrolled: `loadManagedState`
		// only returns state whose signature verified against the configured public
		// keys, and such an installation has no keys and no token to sync with, so it
		// cannot be handed a forged revocation locally. Do NOT widen this to cover
		// "credentials present but unverified" - a routine seat-limit backoff sets the
		// same field, and that 24h backoff is explicitly documented as leaving local
		// protection running.
		if (isSyncDisabled(managedState)) {
			return disabled(
				`AIDR disabled: managed sync is disabled (${managedState.sync_disabled_reason ?? "unknown"}).`,
			);
		}
		// Both signed-entitlement gates require configured keys. Without a key there is
		// no way to verify an ed25519 entitlement, so "no entitlement" carries no
		// information about licensing - it only means this installation was never
		// enrolled. Requiring signed entitlements is a declaration of *how* to verify
		// one, not a claim that the operator already holds one; treating it as the
		// latter disarmed every default install, which is the same defect as the
		// missing-credential gate fixed above.
		if (
			config.licensing.require_signed_entitlements &&
			config.licensing.public_keys_pem.length > 0
		) {
			if (managedState.entitlement_alg !== "ed25519" || !isEntitlementActive(managedState)) {
				return disabled("AIDR disabled: entitlement revoked or no longer valid (ed25519).");
			}
		}
	}

	// Sync remote runtime policy if control plane is enabled and we have a token
	if (config.control_plane.enabled && token) {
		try {
			const merged = await syncRemoteRuntimePolicy(config, token, logger);
			if (merged !== config) {
				// Only assign if sync actually modified the config
				config = { ...config, ...merged };
			}
		} catch (error) {
			if (config.control_plane.remote_policy_required) {
				const verdict: Verdict = {
					...allowVerdict("remote_policy_unavailable"),
					decision: "deny",
					category: "remote_policy_unavailable",
					severity: "warning",
					reasons: [
						error instanceof Error ? error.message : "Required central policy is unavailable.",
					],
				};
				await recordEarlyVerdict(request, context, config, verdict, logger, startTime);
				return verdict;
			}
		}
	}

	// MCP policy can produce verdicts even without artifacts (e.g., denying unknown servers)
	if (request.artifacts.length === 0) {
		const isMcpTool = request.toolName.startsWith("mcp__") || request.toolName === "MCP";
		// A manifest edit is inspectable input even when the connector extracted
		// no artifacts for the tool name, so it may not take this fast path.
		if (!isMcpTool && manifestEdits.length === 0) {
			const verdict = await finalize(allowVerdict("no_artifacts"));
			if (
				verdict.decision !== "allow" ||
				verdict.category === "behavioral_unavailable" ||
				verdict.category === CANARY_UNAVAILABLE_CATEGORY ||
				verdict.category.startsWith("toxic_flow") ||
				verdict.transformedInput
			) {
				await recordEarlyVerdict(request, context, config, verdict, logger, startTime);
			}
			return verdict;
		}
	}

	// An explicit policy denial outranks a local false-positive exception.
	// Approval-required actions may still use the operator-managed approval path.
	const policyVerdict = await evaluatePolicy(
		request.toolName,
		request.artifacts,
		config,
		request.toolInput,
	);
	let allowlisted: Verdict | null = null;
	try {
		const allowlist = await loadAllowlist(config.allowlist, logger);
		if (isAllowlisted(allowlist, request.artifacts) && policyVerdict?.decision !== "deny") {
			allowlisted = allowVerdict("allowlisted");
		}
	} catch {
		// Fail open if allowlist loading fails.
	}

	if (allowlisted) {
		const finalVerdict = await finalize(allowlisted, true);
		await recordEarlyVerdict(
			request,
			context,
			config,
			finalVerdict,
			logger,
			startTime,
			finalVerdict.decision === "allow",
		);
		return finalVerdict;
	}

	if (policyVerdict) {
		const finalVerdict = await finalize(policyVerdict);
		const durationMs = performance.now() - startTime;
		const auditInput = auditToolInputForVerdict(request.toolInput, finalVerdict, context);
		let incidentEntry: Record<string, unknown> | null = null;
		if (
			config.mode === "managed" &&
			config.response.emit_incidents &&
			(finalVerdict.decision === "ask" || finalVerdict.decision === "deny")
		) {
			try {
				incidentEntry = buildIncidentEntry({
					incidentId: `inc_${request.sessionId}_${Date.now()}`,
					sessionId: request.sessionId,
					toolName: request.toolName,
					toolInput: auditInput,
					verdict: finalVerdict,
					recommendedActions: finalVerdict.decision === "deny" ? ["review", "block"] : ["review"],
				});
				await logIncident(config.logging, incidentEntry);
			} catch {
				incidentEntry = null;
			}
		}

		try {
			await logVerdict(
				config.logging,
				request.sessionId,
				request.toolName,
				auditInput,
				finalVerdict,
				false,
				durationMs,
			);
		} catch {
			// Fail open.
		}

		await ingestToControlPlaneIfEnabled(
			request,
			context,
			config,
			finalVerdict,
			incidentEntry,
			logger,
			durationMs,
		);
		return finalVerdict;
	}

	let cache: VerdictCache | null = null;
	try {
		cache = new VerdictCache(config.cache, logger, VERSION);
		await cache.load();
	} catch {
		cache = null;
	}

	const urls = request.artifacts
		.filter((artifact) => artifact.type === "url")
		.map((artifact) => artifact.value);
	// An older clean cache entry is not proof that a newly configured signed feed
	// was verified for this request.
	const { cachedUrlVerdicts, uncachedUrls } = context.reputationFeed
		? { cachedUrlVerdicts: new Map<string, CachedVerdict>(), uncachedUrls: urls }
		: partitionUrlsByCache(urls, cache);

	let heuristicMatches: ReturnType<HeuristicsEngine["match"]> = [];
	// Tracked so the degraded-detection guard below can tell "nothing matched"
	// apart from "no rules were loaded at all".
	let threatsLoaded = 0;
	let codeGuard: CodeGuardResult = EMPTY_CODE_GUARD_RESULT;
	if (config.heuristics_enabled) {
		const loaded = await loadHeuristics(context, config, logger);
		threatsLoaded = loaded.threatsLoaded;
		heuristicMatches = loaded.engine.match(request.artifacts);
		// Model-loading rules decide like any heuristic; secure-code findings
		// are advisory and folded in after the decision (see below).
		codeGuard = inspectCodeLeg(request, loaded, config, logger);
		heuristicMatches = [...heuristicMatches, ...codeGuard.heuristicMatches];
	}

	let urlCheckResults: Awaited<ReturnType<UrlCheckClient["checkUrls"]>> = [];
	// Any DetectionLegUnavailableError from the URL leg is a degradation, whether
	// or not a signed feed is configured: an endpoint that answered 401/5xx, an
	// unreachable endpoint, and an endpoint that answered without feed coverage
	// for some URLs are all "these URLs were NOT checked". Only the configured
	// signed-feed branch used to set this, so a first-party outage produced a
	// clean `allow`.
	let urlLegUnavailable = false;
	let urlLegUnavailableReason = "the URL reputation leg did not run";
	const urlsToCheck = cache ? uncachedUrls : urls;
	if (urlsToCheck.length > 0) {
		if (!config.url_check.enabled) {
			urlLegUnavailable = true;
			urlLegUnavailableReason = "disabled to avoid sending URLs to an external reputation provider";
		} else {
			try {
				const client = new UrlCheckClient(
					{ ...config.url_check, reputationFeed: context.reputationFeed },
					logger,
					token,
				);
				urlCheckResults = await client.checkUrls(urlsToCheck);
			} catch (error) {
				if (error instanceof DetectionLegUnavailableError && error.leg === "url_reputation") {
					urlLegUnavailable = true;
					urlLegUnavailableReason = error.reason;
					// Detections from the batches that did run are evidence; the
					// missing batches are the gap. Keep both.
					urlCheckResults = error.partialResults.filter(isUrlCheckResult);
					logger.warn("URL reputation leg did not provide complete inspection", {
						reason: error.reason,
						uncheckedCount: error.uncheckedCount,
					});
				} else if (context.reputationFeed) {
					// A configured signed feed must never be silently skipped, so any
					// other failure while it is configured is still an unavailable leg.
					urlLegUnavailable = true;
					urlLegUnavailableReason = error instanceof Error ? error.message : String(error);
					logger.warn("Configured signed URL feed did not provide complete inspection", {
						errorType: error instanceof Error ? error.name : typeof error,
					});
				}
			}
		}
	}

	const packageCheckResults = await checkPackages(
		request,
		manifestEdits,
		config,
		context.reputationFeed ? null : cache,
		logger,
		token,
		managedState,
		revocationsForIntel,
		context.reputationFeed,
	);

	// AMSI scan (Windows only)
	//
	// Every failure path here used to end in a bare `catch { /* Fail open */ }`,
	// so a Windows host with no working AMSI backend produced exactly the same
	// verdict as a host that scanned the content and found nothing. The leg state
	// is tracked instead and the post-engine guard below turns it into a blocking
	// review: `amsi_check` is enabled by default, and an enabled leg that did not
	// run is not a clean result.
	//
	// The leg is skipped entirely when the host does not support AMSI at all
	// (that is not an outage) and when the operator disabled `amsi_check` (an
	// explicit choice that must not degrade every verdict).
	const amsiScans: { content: string; name: string }[] = [];
	if (request.toolName === "Bash") {
		const command = (request.toolInput.command ?? "") as string;
		if (command) {
			amsiScans.push({ content: command, name: `Bash:command` });
		}
	} else if (request.toolName === "Write") {
		const filePath = (request.toolInput.file_path ?? "") as string;
		const content = (request.toolInput.content ?? "") as string;
		if (content) {
			amsiScans.push({ content, name: `Write:${filePath}` });
		}
	} else if (request.toolName === "Edit") {
		const editContents = request.artifacts.filter(
			(artifact) => artifact.type === "content" && artifact.context === "edit",
		);
		if (editContents.length > 0) {
			for (const [index, artifact] of editContents.entries()) {
				amsiScans.push({ content: artifact.value, name: `Edit:section-${index + 1}` });
			}
		} else {
			const filePath = (request.toolInput.file_path ?? "") as string;
			const newString = (request.toolInput.new_string ?? "") as string;
			if (newString) {
				amsiScans.push({ content: newString, name: `Edit:${filePath}` });
			}
		}
	}

	let amsiUnavailable = false;
	const amsiCheckResults: AmsiCheckResult[] = [];
	if (config.amsi_check.enabled && isAmsiSupported() && amsiScans.length > 0) {
		let amsiClient: AmsiClient | null = null;
		try {
			amsiClient = new AmsiClient(logger);
			await amsiClient.init();
			if (amsiClient.isAvailable) {
				for (const scan of amsiScans) {
					const result = await amsiClient.scanString(scan.content, scan.name);
					if (result) {
						amsiCheckResults.push(result);
					} else {
						// A scan that returned nothing is not a scan that passed.
						amsiUnavailable = true;
						logger.warn("AMSI scan did not complete; content was NOT scanned", {
							contentName: scan.name,
						});
					}
				}
			} else {
				// This host supports AMSI, so no usable backend is an outage of the
				// leg, not evidence that the content is clean.
				amsiUnavailable = true;
				logger.warn("AMSI leg unavailable: no working AMSI backend on this host", {
					backendKind: amsiClient.backendKind,
				});
			}
		} catch (error) {
			amsiUnavailable = true;
			logger.warn("AMSI scan leg did not run", {
				errorType: error instanceof Error ? error.name : typeof error,
			});
		} finally {
			amsiClient?.close();
		}
	}

	const engine = new DecisionEngine(config.sensitivity);
	let verdict = await engine.decide({
		heuristicMatches,
		urlCheckResults,
		packageCheckResults: packageCheckResults.length > 0 ? packageCheckResults : undefined,
		amsiCheckResults: amsiCheckResults.length > 0 ? amsiCheckResults : undefined,
	});

	if (cachedUrlVerdicts.size > 0 && verdict.decision === "allow") {
		for (const [url, cachedVerdict] of cachedUrlVerdicts) {
			if (cachedVerdict.verdict === "allow") {
				continue;
			}
			verdict = {
				decision: cachedVerdict.verdict,
				category: "network_egress",
				confidence: 1.0,
				severity: cachedVerdict.severity,
				source: `cache(${cachedVerdict.source})`,
				artifacts: [url],
				matchedThreatId: null,
				reasons: cachedVerdict.reasons,
			};
			break;
		}
	}
	// An enabled AMSI leg that did not run is a gap in coverage, not a clean
	// result. `amsi_check` is enabled by default, so on a Windows host where
	// koffi and the PowerShell fallback are both unusable this used to be
	// swallowed and the call was allowed as if AMSI had inspected it. The source
	// is "amsi" so an AMSI detection and an AMSI outage are grouped together.
	if (amsiUnavailable && verdict.decision === "allow") {
		verdict = detectorVerdict(
			"ask",
			"amsi_unavailable",
			"amsi",
			"AMSI malware scanning is enabled on this host but the scan did not run, so this content was NOT scanned.",
		);
	}

	//
	// If heuristics are enabled and there is something to inspect, but no rule
	// could be loaded, then the local detection layer is not running at all. An
	// `allow` here would be indistinguishable from a clean verdict and would
	// silently turn the product into a no-op (a typo in the threats path, an
	// incomplete install, or a renamed bundle is enough). Report it as
	// indeterminate instead: the call goes to a human rather than through.
	//
	// The check is deliberately narrow. It does NOT fire when:
	//   - heuristics are disabled by configuration, or
	//   - there are no artifacts to inspect (nothing was going to be matched).
	// The first is an explicit operator choice; the second is not a degradation.
	if (
		verdict.decision === "allow" &&
		config.heuristics_enabled &&
		threatsLoaded === 0 &&
		request.artifacts.length > 0
	) {
		verdict = {
			decision: "ask",
			category: "detection_unavailable",
			confidence: 1.0,
			severity: "warning",
			source: "detection_unavailable",
			artifacts: request.artifacts.map((a) => a.value),
			matchedThreatId: null,
			reasons: [
				`No local threat rules could be loaded from ${context.threatsDir ?? "(no threats directory supplied)"}, so this call was NOT inspected.`,
				"This is not a clean result. Check the threat-rule path and reinstall the connector bundle.",
			],
		};
		logger.warn("Local detection unavailable: no threat rules loaded", {
			threatsDir: context.threatsDir,
			artifacts: request.artifacts.length,
		});
	}

	// A URL leg that did not run or covered only part of the requested URLs is a
	// visible coverage gap, including when the operator chose not to share URLs
	// with a provider. Local heuristics still run on the original artifacts.
	//
	// This sits AFTER the degraded-detection guard on purpose: when the local
	// rule set is missing entirely, "this call was NOT inspected" is the more
	// accurate report, and both guards would only ever say `ask`.
	if (urlLegUnavailable && verdict.decision === "allow") {
		verdict = detectorVerdict(
			"ask",
			"url_reputation_unavailable",
			"url_check",
			`URL reputation lookup was unavailable (${urlLegUnavailableReason}), so the URLs in this call were NOT verified clean and require review.`,
		);
	}
	// Secure-code guardrails: a notice by default (`warn`), a review with
	// `secure_code.action: "ask"`. Never a deny on their own.
	verdict = applySecureCodeWarnings(verdict, codeGuard.warnings, config.secure_code);
	verdict = await finalize(verdict);
	const durationMs = performance.now() - startTime;
	const auditInput = auditToolInputForVerdict(request.toolInput, verdict, context);

	await cacheUrlResults(urlCheckResults, context.reputationFeed ? null : cache);

	try {
		await logVerdict(
			config.logging,
			request.sessionId,
			request.toolName,
			auditInput,
			verdict,
			false,
			durationMs,
		);
	} catch {
		// Fail open.
	}

	let incidentEntry: Record<string, unknown> | null = null;
	// Minimal incidenting: open an incident for ask/deny verdicts (commercial managed mode by default).
	if (
		config.mode === "managed" &&
		config.response.emit_incidents &&
		(verdict.decision === "ask" || verdict.decision === "deny")
	) {
		try {
			incidentEntry = buildIncidentEntry({
				incidentId: `inc_${request.sessionId}_${Date.now()}`,
				sessionId: request.sessionId,
				toolName: request.toolName,
				toolInput: auditInput,
				verdict,
				recommendedActions: verdict.decision === "deny" ? ["review", "block"] : ["review"],
			});
			await logIncident(config.logging, incidentEntry);
		} catch {
			// Fail open.
			incidentEntry = null;
		}
	}

	// Optional: lightweight local correlation (builds a derived incident view from recent audit entries).
	if (config.incident.enabled && config.incident.correlation_enabled) {
		try {
			const recent = await getRecentEntries(config.logging, 200);
			const signals = normalizeAuditEntriesToSignals(recent);
			const incidents = correlateIncidents(signals, { max_gap_ms: 5 * 60 * 1000 });
			await persistIncidentRecords(
				{ store: config.incident.store, logging: config.logging },
				incidents,
				{ recent_entries: recent },
			);
		} catch {
			// Fail open
		}
	}

	// Best-effort control plane telemetry (for dashboard/licensing). Never blocks verdict.
	await ingestToControlPlaneIfEnabled(
		request,
		context,
		config,
		verdict,
		incidentEntry,
		logger,
		durationMs,
	);

	return verdict;
}

async function ingestToControlPlaneIfEnabled(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	config: Config,
	verdict: Verdict,
	incidentEntry: Record<string, unknown> | null,
	logger: Logger,
	durationMs: number,
): Promise<void> {
	if (config.mode !== "managed") return;
	if (!config.control_plane.enabled) return;
	if (!config.control_plane.send_audit_logs) return;

	const rawToken = getAuthToken(config.auth);

	if (verdict.decision === "allow" && !config.control_plane.send_clean_verdicts) return;

	const managedPath = managedStatePath();
	const managedState = await loadManagedState(managedPath, {
		authToken: rawToken,
		publicKeysPem: config.licensing.public_keys_pem,
		onSecurityEvent: (event) =>
			logger.warn(
				"Managed state verification failure",
				event as unknown as Record<string, unknown>,
			),
	});
	const authToken =
		(config.auth.api_key ?? "").trim() ||
		(typeof managedState.api_key === "string" ? managedState.api_key.trim() : "") ||
		"";
	if (!authToken) return;
	if (isSyncDisabled(managedState)) return;

	let iid: string | undefined;
	try {
		iid = await getInstallationId(resolvePath("~/.singularity-aidr"));
	} catch {
		iid = undefined;
	}

	const entry = buildRuntimeVerdictEntry(
		request.sessionId,
		request.toolName,
		auditToolInputForVerdict(request.toolInput, verdict, context),
		verdict,
		false,
		durationMs,
	);

	try {
		const client = new ControlPlaneClient(config.control_plane, authToken, logger);
		const result = await client.ingest({
			iid,
			agent_runtime: context.agentRuntime,
			agent_runtime_version: context.agentRuntimeVersion,
			events:
				config.control_plane.sync_incidents && incidentEntry ? [entry, incidentEntry] : [entry],
		});

		const nextState = applyIngestResult(
			managedState,
			result,
			config.control_plane.grace_period_hours,
			{ authToken, publicKeysPem: config.licensing.public_keys_pem },
		);
		if (nextState !== managedState) {
			await saveManagedState(managedPath, nextState);
			await saveEntitlementKeyringFromState(nextState);
		}
	} catch {
		// Fail open
	}
}

function partitionUrlsByCache(
	urls: string[],
	cache: VerdictCache | null,
): { cachedUrlVerdicts: Map<string, CachedVerdict>; uncachedUrls: string[] } {
	const cachedUrlVerdicts = new Map<string, CachedVerdict>();
	let uncachedUrls: string[] = [];

	if (cache && urls.length > 0) {
		try {
			for (const url of urls) {
				const cached = cache.getUrl(url);
				if (cached !== null) {
					cachedUrlVerdicts.set(url, cached);
				} else {
					uncachedUrls.push(url);
				}
			}
		} catch {
			uncachedUrls = urls;
		}
	}

	return { cachedUrlVerdicts, uncachedUrls };
}

async function cacheUrlResults(
	urlCheckResults: UrlCheckResult[],
	cache: VerdictCache | null,
): Promise<void> {
	if (!cache) return;
	try {
		for (const result of urlCheckResults) {
			const isClean = !result.isMalicious && result.flags.length === 0;
			// A clean result without a source expiry cannot be safely cached: the
			// source row may already be near its freshness limit when this check runs.
			if (isClean && result.cacheValidUntil === undefined) continue;
			let cachedVerdict: CachedVerdict;
			if (result.isMalicious) {
				cachedVerdict = {
					verdict: "deny",
					severity: "critical",
					reasons: [
						`URL check: malicious (${result.findings
							.map((finding) => `${finding.severityName}/${finding.typeName}`)
							.join(", ")})`,
					],
					source: "url_check",
				};
			} else if (result.flags.length > 0) {
				cachedVerdict = {
					verdict: "ask",
					severity: "warning",
					reasons: [`URL check: suspicious (${result.flags.join(", ")})`],
					source: "url_check",
				};
			} else {
				cachedVerdict = {
					verdict: "allow",
					severity: "info",
					reasons: [],
					source: "url_check",
				};
			}
			cache.putUrl(result.url, cachedVerdict, result.isMalicious, result.cacheValidUntil);
		}
		await cache.save();
	} catch {
		// Fail open.
	}
}

/** Artifact contexts whose `content` is text a write/edit operation introduces. */
const EDIT_CONTENT_CONTEXTS = new Set(["write", "edit", "apply_patch"]);

/**
 * Canonical operations whose `content` is not an edit payload: `Bash` has its
 * own command leg, and `Read`/`Delete`/`WebFetch` observe or remove existing
 * bytes. Their package routing must stay exactly as it has always been — a
 * command is handled by `extractPackagesFromCommand`, and reading a manifest is
 * not a supply-chain event.
 */
const NON_EDIT_TOOL_NAMES = new Set(["Bash", "Read", "Delete", "WebFetch"]);

interface ManifestEditInput {
	filePath: string;
	content: string;
}

/**
 * Collect the package manifest edits a request carries, independent of its tool
 * name.
 *
 * Supply-chain inspection used to be selected with `toolName === "Bash"`,
 * `"Write"` or `"Edit"`, so a connector whose edit tool is named anything else
 * — Codex's `apply_patch`, or an alias core has never seen — carried a manifest
 * payload straight past the package leg. Routing is therefore decided from the
 * payload: a `content` artifact produced by a write/edit operation, or the
 * request's own edit fields, paired with a file path. Non-edit operations are
 * excluded so that reading a manifest is never mistaken for editing one.
 */
function manifestEditInputs(request: ToolEvaluationRequest): ManifestEditInput[] {
	if (NON_EDIT_TOOL_NAMES.has(request.toolName)) return [];

	const inputs: ManifestEditInput[] = [];
	const seen = new Set<string>();
	const add = (filePath: unknown, content: unknown): void => {
		if (typeof filePath !== "string" || typeof content !== "string") return;
		if (filePath.trim() === "" || content.trim() === "") return;
		const key = `${filePath}\u0000${content}`;
		if (seen.has(key)) return;
		seen.add(key);
		inputs.push({ filePath, content });
	};

	// Connectors may extract before field normalization, or use a path field
	// core does not know; prefer the request's own path, then any extracted one.
	const payload = readFileEditPayload(request.toolInput);
	if (payload.patch) {
		for (const edit of payload.edits ?? []) add(edit.filePath, edit.content);
		return inputs;
	}

	const pathFromArtifacts = request.artifacts.find(
		(artifact) => artifact.type === "file_path" && artifact.value.trim() !== "",
	)?.value;
	const filePath = payload.filePath ?? pathFromArtifacts;

	for (const artifact of request.artifacts) {
		if (artifact.type !== "content") continue;
		if (!EDIT_CONTENT_CONTEXTS.has(artifact.context ?? "")) continue;
		add(filePath, artifact.value);
	}

	// Artifacts are best-effort and a connector may omit them for an unfamiliar
	// alias, so the payload itself must also route (the canonical Write/Edit
	// case, widened to every non-observation tool name).
	add(payload.filePath, payload.content);
	return inputs;
}

async function checkPackages(
	request: ToolEvaluationRequest,
	manifestEdits: readonly ManifestEditInput[],
	config: Config,
	cache: VerdictCache | null,
	logger: Logger,
	apiKey: string,
	managedState: ManagedState,
	revocations: RevocationListV1 | null,
	reputationFeed?: ReputationFeedLoadOptions,
): Promise<PackageCheckResult[]> {
	const results: PackageCheckResult[] = [];

	let parsedPackages: ParsedPackage[] | undefined;
	try {
		if (request.toolName === "Bash") {
			const command = (request.toolInput.command ?? "") as string;
			parsedPackages = extractPackagesFromCommand(command);
		} else {
			// Payload-driven: the manifest edit is what selects this leg, not the
			// name the connector happens to give its edit tool.
			parsedPackages = [];
			for (const input of manifestEdits) {
				if (isDependencyManifestPath(input.filePath) && !isPackageManifestPath(input.filePath)) {
					parsedPackages.push(...extractPackagesFromManifest(input.filePath, input.content));
					continue;
				}
				if (isPackageJsonPath(input.filePath) && !isCompletePackageManifest(input.content)) {
					return [
						packageCheckUnavailableResult(
							input.filePath,
							"npm",
							"could not be reconstructed as a complete package manifest; no packages were verified",
						),
					];
				}
				parsedPackages.push(...extractPackagesFromManifest(input.filePath, input.content));
			}
		}
	} catch (error) {
		logger.warn("Package input extraction failed", {
			toolName: request.toolName,
			errorType: error instanceof Error ? error.name : typeof error,
		});
		return [packageCheckUnavailableResult("package operation", "npm")];
	}

	if (!parsedPackages) return results;
	results.push(
		...parsedPackages
			.filter((pkg) => pkg.unverifiedReason || pkg.registry === "unknown")
			.map((pkg) =>
				packageCheckUnavailableResult(
					pkg.name,
					pkg.registry,
					pkg.unverifiedReason ?? "uses an unsupported package ecosystem",
				),
			),
	);
	const checkablePackages = parsedPackages.filter(
		(pkg): pkg is ParsedPackage & { registry: "npm" | "pypi" } =>
			!pkg.unverifiedReason && pkg.registry !== "unknown",
	);
	if (checkablePackages.length === 0) return results;
	if (!config.package_check.enabled) {
		return [
			...results,
			...checkablePackages.map((pkg) =>
				packageCheckUnavailableResult(
					pkg.name,
					pkg.registry,
					"is disabled to avoid sharing package names with external providers",
				),
			),
		];
	}

	const intelMerged = await getPackageIntelMerged(config, managedState, revocations);
	const intelPacksEnabled = config.intel_packs?.enabled === true || config.intel?.enabled === true;
	const intelPacksEntitled =
		!(isCommercialBuild() || config.mode === "managed") ||
		isPremiumModuleEnabled(managedState, "intel_packs");
	const intelUnavailable =
		intelPacksEnabled && intelPacksEntitled && intelMerged?.availability !== "available";
	const uncached: (ParsedPackage & { registry: "npm" | "pypi" })[] = [];
	for (const pkg of checkablePackages) {
		const cacheKey = `${pkg.registry}:${pkg.name}${pkg.version ? `@${pkg.version}` : ""}`;
		let cached: CachedVerdict | null = null;
		try {
			cached = cache?.getPackage(cacheKey) ?? null;
		} catch (error) {
			logger.warn("Package verdict cache read failed; running a live check", {
				packageName: pkg.name,
				registry: pkg.registry,
				errorType: error instanceof Error ? error.name : typeof error,
			});
		}

		if (cached && cached.verdict !== "allow") {
			results.push({
				packageName: pkg.name,
				registry: pkg.registry,
				verdict: cached.verdict === "deny" ? "malicious" : "suspicious_age",
				confidence: 1.0,
				details: cached.reasons.join("; "),
			});
		} else if (intelUnavailable) {
			results.push(
				packageCheckUnavailableResult(
					pkg.name,
					pkg.registry,
					`required signed intel packs are unavailable${intelMerged?.detail ? ` (${intelMerged.detail})` : ""}`,
				),
			);
		} else {
			// Historical clean cache entries may have come from SEVERITY_UNKNOWN.
			// Recheck them until the provider has an affirmative benign verdict.
			uncached.push(pkg);
		}
	}

	if (uncached.length > 0) {
		let checked: PackageCheckResult[] = [];
		try {
			const checker = new PackageChecker(
				{
					registryTimeoutSeconds: config.package_check.timeout_seconds,
					fileCheckEndpoint: config.file_check.endpoint,
					fileCheckTimeoutSeconds: config.file_check.timeout_seconds,
					fileCheckEnabled: config.file_check.enabled,
					fileCheckAllowInsecureLoopback: config.file_check.allow_insecure_loopback,
					apiKey,
					intelPackageNameDeny: intelMerged?.packageNameDeny,
					intelPackageHashDeny: intelMerged?.packageHashDeny,
					reputationFeed,
				},
				logger,
			);
			const checkResults = await checker.checkPackages(uncached);
			checked = validatePackageCheckResults(checkResults, uncached);
		} catch (error) {
			logger.warn("Package checker unavailable; package operation requires review", {
				packageCount: uncached.length,
				errorType: error instanceof Error ? error.name : typeof error,
			});
		}

		results.push(...checked);
		const unchecked = findUncheckedPackages(uncached, checked);
		if (unchecked.length > 0) {
			logger.warn("Package checker returned incomplete coverage", {
				requested: uncached.length,
				checked: checked.length,
				unchecked: unchecked.length,
			});
			results.push(
				...unchecked.map((pkg) => packageCheckUnavailableResult(pkg.name, pkg.registry)),
			);
		}

		if (cache) {
			try {
				for (const result of checked) {
					const pkg = uncached.find((p) => p.name === result.packageName);
					const cacheKey = `${result.registry}:${result.packageName}${pkg?.version ? `@${pkg.version}` : ""}`;
					const isCritical = result.verdict === "malicious" || result.verdict === "not_found";
					cache.putPackage(
						cacheKey,
						{
							verdict: result.verdict === "clean" ? "allow" : isCritical ? "deny" : "ask",
							severity: isCritical ? "critical" : "warning",
							reasons: [result.details],
							source: "package_check",
						},
						result.ageDays ?? null,
					);
				}
			} catch (error) {
				logger.warn("Package verdict cache write failed", {
					errorType: error instanceof Error ? error.name : typeof error,
				});
			}
		}
	}

	return results;
}

function isCompletePackageManifest(content: string): boolean {
	try {
		const value: unknown = JSON.parse(content);
		if (!value || typeof value !== "object" || Array.isArray(value)) return false;
		if (hasDuplicateJsonObjectKeys(content)) return false;
		const manifest = value as Record<string, unknown>;
		return ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"].every(
			(key) => {
				const entries = manifest[key];
				return (
					entries === undefined ||
					(typeof entries === "object" &&
						entries !== null &&
						!Array.isArray(entries) &&
						Object.values(entries).every((version) => typeof version === "string"))
				);
			},
		);
	} catch {
		return false;
	}
}

function packageCheckUnavailableResult(
	packageName: string,
	registry: "npm" | "pypi" | "unknown",
	reason = "is unavailable",
): PackageCheckResult {
	return {
		packageName,
		registry,
		verdict: "unknown",
		confidence: 0.6,
		details: `Package check for '${packageName}' ${reason}; it was NOT verified clean and requires review`,
	};
}

function findUncheckedPackages(
	expected: ParsedPackage[],
	observed: PackageCheckResult[],
): ParsedPackage[] {
	const observedCounts = new Map<string, number>();
	for (const result of observed) {
		const key = `${result.registry}:${result.packageName}`;
		observedCounts.set(key, (observedCounts.get(key) ?? 0) + 1);
	}

	return expected.filter((pkg) => {
		const key = `${pkg.registry}:${pkg.name}`;
		const remaining = observedCounts.get(key) ?? 0;
		if (remaining === 0) return true;
		observedCounts.set(key, remaining - 1);
		return false;
	});
}

function validatePackageCheckResults(
	value: unknown,
	expected: ParsedPackage[],
): PackageCheckResult[] {
	if (!Array.isArray(value)) return [];
	const expectedCounts = new Map<string, number>();
	for (const pkg of expected) {
		const key = `${pkg.registry}:${pkg.name}`;
		expectedCounts.set(key, (expectedCounts.get(key) ?? 0) + 1);
	}

	const groupedResults = new Map<string, PackageCheckResult[]>();
	let malformed = false;
	for (const entry of value) {
		if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
			malformed = true;
			continue;
		}
		const row = entry as Record<string, unknown>;
		if (
			typeof row.packageName !== "string" ||
			!row.packageName ||
			(row.registry !== "npm" && row.registry !== "pypi") ||
			!(["malicious", "not_found", "suspicious_age", "unknown", "clean"] as unknown[]).includes(
				row.verdict,
			) ||
			typeof row.confidence !== "number" ||
			!Number.isFinite(row.confidence) ||
			row.confidence < 0 ||
			row.confidence > 1 ||
			typeof row.details !== "string"
		) {
			malformed = true;
			continue;
		}
		const result = row as unknown as PackageCheckResult;
		const key = `${result.registry}:${result.packageName}`;
		if (!expectedCounts.has(key)) continue;
		const rows = groupedResults.get(key) ?? [];
		rows.push(result);
		groupedResults.set(key, rows);
	}

	const results: PackageCheckResult[] = [];
	for (const [key, rows] of groupedResults) {
		const expectedCount = expectedCounts.get(key) ?? 0;
		if (malformed || rows.length > expectedCount) {
			// Ambiguous rows can never vouch for clean coverage. Preserve valid
			// explicit denials, while uncovered package occurrences become review results.
			results.push(
				...rows
					.filter((result) => result.verdict === "malicious" || result.verdict === "not_found")
					.slice(0, expectedCount),
			);
			continue;
		}
		results.push(...rows);
	}
	return results;
}
