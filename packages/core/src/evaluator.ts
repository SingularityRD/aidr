/**
 * Shared runtime evaluation pipeline for hook entry points.
 * Hooks should normalize transport-specific payloads, then call this function.
 */

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
import { AmsiClient, isAmsiSupported } from "./clients/amsi.js";
import { ControlPlaneClient } from "./clients/control-plane.js";
import { UrlCheckClient } from "./clients/url-check.js";
import { loadConfig, resolvePath } from "./config.js";
import {
	type DelegatedCredentialClaimsV1,
	type DelegatedCredentialErrorCode,
	type DelegatedCredentialVerificationContext,
	verifyDelegatedCredential,
} from "./delegated-credential.js";
import { DetectionLegUnavailableError } from "./detection-leg.js";
import type { DlpPolicy } from "./dlp/policy.js";
import { scanDlpInput } from "./dlp/scanner.js";
import { DecisionEngine } from "./engine.js";
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
	redactRemoteEvent,
	saveEntitlementKeyringFromState,
	saveManagedState,
	saveRevocationsCache,
	verifyEd25519SignedRevocationList,
} from "./managed.js";
import { PackageChecker } from "./package-checker.js";
import {
	extractPackagesFromCommand,
	extractPackagesFromManifest,
	type ParsedPackage,
} from "./package-extractor.js";
import { evaluatePolicy } from "./policy.js";
import { syncRemoteRuntimePolicy } from "./remote-policy.js";
import type { ReputationFeedLoadOptions } from "./reputation-feed.js";
import { loadThreatsFromDirs } from "./threat-loader.js";
import { normalizeToolEvaluationRequest } from "./tool-normalization.js";
import {
	initTracing,
	recordDetectionPhase,
	setSecurityDecisionAttributes,
	startActiveSpan,
} from "./tracing.js";
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
import { ConfigSchema, nullLogger } from "./types.js";
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
	return `${packsDir}|${trustedKeys}|${serial}|${revEpoch}`;
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
		return null;
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
	userThreatsDir?: string;
	agentRuntime?: AgentRuntime;
	agentRuntimeVersion?: string;
	logger?: Logger;
	/** Trusted caller-owned detector policy. Tool payloads must never select their tenant. */
	runtimeDetectors?: {
		tenantId: string;
		dlp?: { enabled: boolean; policy: DlpPolicy; contentType?: string };
		behavioral?: {
			enabled: boolean;
			orchestrator: BehavioralDetectionOrchestrator;
			/** Only an operator-approved baseline workflow should set this to true. */
			learningAllowed?: boolean;
		};
	};
	/** Verified, local signed feed configuration; absent means no feed claim. */
	reputationFeed?: ReputationFeedLoadOptions;
	/**
	 * Delegated credential authorizing this exact call. Absent means the caller
	 * makes no delegation claim, and the call is evaluated exactly as before.
	 */
	delegation?: ToolDelegationContext;
}

const DETECTOR_DECISION_RANK = { allow: 0, ask: 1, deny: 2 } as const;

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

function auditToolInputForVerdict(
	toolInput: Record<string, unknown>,
	verdict: Verdict,
	context: ToolEvaluationContext,
): Record<string, unknown> {
	// Tenant DLP matches can be arbitrary business secrets that the generic
	// credential redactor does not know. Never copy their raw payload into an
	// audit summary or remote event when the configured detector determined the
	// outcome (including unavailable inspection).
	return context.runtimeDetectors?.dlp?.enabled === true ||
		verdict.source === "dlp" ||
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

function evaluateDlpDetector(
	detector: NonNullable<NonNullable<ToolEvaluationContext["runtimeDetectors"]>["dlp"]>,
	tenantId: string,
	content: string,
): Verdict | null {
	try {
		const dlp = scanDlpInput(detector.policy, {
			tenantId,
			content,
			contentType: detector.contentType ?? "application/json",
		});
		if (dlp.status === "unavailable") {
			return detectorVerdict(
				dlp.action === "block" ? "deny" : "ask",
				"dlp_unavailable",
				"dlp",
				`DLP inspection unavailable: ${dlp.unavailable.reason}.`,
			);
		}
		if (dlp.action === "allow") return null;
		// A hook returns a verdict, not a rewritten tool payload. Passing a
		// redact result through would disclose the original value.
		return detectorVerdict(
			dlp.action === "ask" ? "ask" : "deny",
			"dlp",
			"dlp",
			dlp.action === "redact"
				? "DLP redaction required; this connector cannot rewrite tool input."
				: `DLP policy requires ${dlp.action}.`,
			dlp.findings[0]?.ruleId ?? null,
		);
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
			riskScore: currentVerdict.decision === "deny" ? 100 : currentVerdict.decision === "ask" ? 75 : 0,
			timestamp: Date.now(),
			command: typeof input.command === "string" ? input.command : undefined,
			path: typeof input.file_path === "string" ? input.file_path : undefined,
			url: typeof input.url === "string" ? input.url : undefined,
			classificationText: content,
			learningAllowed: detector.learningAllowed === true && currentVerdict.decision === "allow",
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
			return detectorVerdict(
				"ask",
				"behavioral_unavailable",
				"behavioral",
				`Behavioral detection ${behavioral.outcome}; no clean result available.`,
			);
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
			context: verificationContext,
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
	baseVerdict: Verdict,
	managedState: ManagedState,
): Promise<Verdict> {
	const delegationOutcome = context.delegation
		? evaluateDelegation(context.delegation, request.toolName)
		: null;
	if (delegationOutcome && "verdict" in delegationOutcome) return delegationOutcome.verdict;

	const verdict = await applyConfiguredDetectors(request, context, baseVerdict, managedState);
	return delegationOutcome ? { ...verdict, delegation: delegationOutcome.lineage } : verdict;
}

async function applyConfiguredDetectors(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	baseVerdict: Verdict,
	managedState: ManagedState,
): Promise<Verdict> {
	const detectors = context.runtimeDetectors;
	if (!detectors || (detectors.dlp?.enabled !== true && detectors.behavioral?.enabled !== true)) {
		return baseVerdict;
	}

	const tenantId = detectors.tenantId;
	if (typeof tenantId !== "string" || tenantId.trim() === "" || tenantId.length > 128) {
		return detectorVerdict("deny", "detection_unavailable", "runtime_detectors", "Detector tenant identity is missing or invalid.");
	}
	if (
		managedState.entitlement?.schema_version === 2 &&
		managedState.entitlement.tenant_id !== tenantId
	) {
		return detectorVerdict("deny", "tenant_isolation", "runtime_detectors", "Detector tenant does not match the signed managed entitlement.");
	}

	let content: string;
	try {
		content = JSON.stringify(request.toolInput);
		if (typeof content !== "string") throw new Error("Tool input cannot be serialized");
	} catch {
		return detectorVerdict("deny", "detection_unavailable", "runtime_detectors", "Tool input could not be serialized for configured inspection.");
	}

	let result = baseVerdict;
	if (detectors.dlp?.enabled === true) {
		result = mergeDetectorVerdict(result, evaluateDlpDetector(detectors.dlp, tenantId, content), baseVerdict);
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
	allowlisted = false,
): Promise<void> {
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
		await logVerdict(config.logging, request.sessionId, request.toolName, auditInput, verdict, allowlisted);
	} catch {
		// An audit failure cannot erase the detector decision.
	}
	if (verdict.decision !== "allow") {
		try {
			await ingestToControlPlaneIfEnabled(request, context, config, verdict, incidentEntry, logger);
		} catch {
			// Telemetry failure cannot erase the local decision.
		}
	}
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
	// Initialize tracing on first call if enabled
	initTracing();

	const startTime = performance.now();

	return startActiveSpan(
		"security_decision",
		async (mainSpan) => {
			mainSpan.setAttribute("aidr.session_id", normalizedRequest.sessionId);
			mainSpan.setAttribute("aidr.tool_name", normalizedRequest.toolName);

			const verdict = await runEvaluationPipeline(normalizedRequest, context, startTime);

			// Record final decision attributes
			const durationMs = performance.now() - startTime;
			setSecurityDecisionAttributes({
				toolName: normalizedRequest.toolName,
				sessionId: normalizedRequest.sessionId,
				decision: verdict.decision,
				category: verdict.category,
				confidence: verdict.confidence,
				severity: verdict.severity,
				artifactsCount: verdict.artifacts.length,
				matchedThreatId: verdict.matchedThreatId,
				reasons: verdict.reasons,
				durationMs,
			});

			mainSpan.setAttribute("aidr.decision", verdict.decision);
			mainSpan.setAttribute("aidr.duration_ms", durationMs);

			return verdict;
		},
		{ kind: 1 }, // SpanKind.INTERNAL
	) as Promise<Verdict>;
}

async function runEvaluationPipeline(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	_startTime: number,
): Promise<Verdict> {
	const logger = context.logger ?? nullLogger;
	let config = await loadConfig(context.configPath, logger).catch(() => ConfigSchema.parse({}));
	const commercial = isCommercialBuild();

	// Managed-only commercial behavior: without a valid auth token + signed entitlement (or offline grace),
	// the runtime does not enforce and becomes inert (allow-only).
	const disabled = (reason: string): Verdict => {
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
	let managedUnenrolled = false;
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
			managedUnenrolled = true;
			logger.warn(unenrolledReason);
		}

		// If only enrollment_token is present, try to exchange it for an api_key.
		if (!apiKey && enrollToken && config.control_plane.enabled) {
			const iid = await getInstallationId(aidrDir).catch(() => undefined);
			if (!iid) {
				managedUnenrolled = true;
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
			managedUnenrolled = true;
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
			managedUnenrolled = true;
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
				return { ...allowVerdict("remote_policy_unavailable"), decision: "deny", category: "remote_policy_unavailable", severity: "warning", reasons: [error instanceof Error ? error.message : "Required central policy is unavailable."] };
			}
		}
	}

	// MCP policy can produce verdicts even without artifacts (e.g., denying unknown servers)
	if (request.artifacts.length === 0) {
		const isMcpTool = request.toolName.startsWith("mcp__") || request.toolName === "MCP";
		if (!isMcpTool) {
			const verdict = await applyRuntimeDetectors(request, context, allowVerdict("no_artifacts"), managedState);
			if (verdict.decision !== "allow") {
				await recordEarlyVerdict(request, context, config, verdict, logger);
			}
			return verdict;
		}
	}

	// An explicit policy denial outranks a local false-positive exception.
	// Approval-required actions may still use the operator-managed approval path.
	const policyVerdict = await evaluatePolicy(request.toolName, request.artifacts, config, request.toolInput);
	// Allowlist check phase
	const allowlisted = await startActiveSpan("allowlist_check", async (allowlistSpan) => {
		const allowlistStart = performance.now();
		let isAllowlistedResult = false;
		try {
			const allowlist = await loadAllowlist(config.allowlist, logger);
			isAllowlistedResult = isAllowlisted(allowlist, request.artifacts);
			if (isAllowlistedResult && policyVerdict?.decision !== "deny") {
				const verdict = allowVerdict("allowlisted");
				allowlistSpan.setAttribute("aidr.allowlisted", true);
				allowlistSpan.end();
				return verdict;
			}
		} catch {
			// Fail open if allowlist loading fails.
		}
		const durationMs = performance.now() - allowlistStart;
		recordDetectionPhase({
			phase: "allowlist_check",
			artifactCount: request.artifacts.length,
			cacheHit: isAllowlistedResult,
			durationMs,
		});
		allowlistSpan.end();
		return null;
	});

	if (allowlisted) {
		const finalVerdict = await applyRuntimeDetectors(request, context, allowlisted, managedState);
		await recordEarlyVerdict(request, context, config, finalVerdict, logger, finalVerdict.decision === "allow");
		return finalVerdict;
	}

	if (policyVerdict) {
		const finalVerdict = await applyRuntimeDetectors(request, context, policyVerdict, managedState);
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
	if (config.heuristics_enabled) {
		const userThreatsDir = context.userThreatsDir ?? resolvePath("~/.singularity-aidr/threats");
		let threats = await loadThreatsFromDirs([context.threatsDir, userThreatsDir], logger);
		if (config.disabled_threats.length > 0) {
			const disabledSet = new Set(config.disabled_threats);
			threats = threats.filter((t) => !disabledSet.has(t.id));
		}
		threatsLoaded = threats.length;
		const trustedDomains = await loadTrustedDomains(context.allowlistsDir, logger);
		const heuristics = new HeuristicsEngine(threats, trustedDomains);
		heuristicMatches = heuristics.match(request.artifacts);
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
	if (urlsToCheck.length > 0 && config.url_check.enabled) {
		try {
			const client = new UrlCheckClient({ ...config.url_check, reputationFeed: context.reputationFeed }, logger, token);
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

	const packageCheckResults = await checkPackages(
		request,
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
		const filePath = (request.toolInput.file_path ?? "") as string;
		const newString = (request.toolInput.new_string ?? "") as string;
		if (newString) {
			amsiScans.push({ content: newString, name: `Edit:${filePath}` });
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

	// A URL leg that ran and produced results did not degrade; a leg that did not
	// run (or covered only part of the requested URLs) did. The guard is
	// deliberately narrow: it only fires while the leg is enabled, the engine
	// still says `allow`, and no broader degradation has already been reported.
	// An operator who disabled `url_check` is making an explicit choice, and that
	// choice must stay silent rather than degrade every call.
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
	verdict = await applyRuntimeDetectors(request, context, verdict, managedState);
	const auditInput = auditToolInputForVerdict(request.toolInput, verdict, context);

	await cacheUrlResults(urlCheckResults, context.reputationFeed ? null : cache);

	try {
		await logVerdict(
			config.logging,
			request.sessionId,
			request.toolName,
			auditInput,
			verdict,
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
	await ingestToControlPlaneIfEnabled(request, context, config, verdict, incidentEntry, logger);

	return verdict;
}

async function ingestToControlPlaneIfEnabled(
	request: ToolEvaluationRequest,
	context: ToolEvaluationContext,
	config: Config,
	verdict: Verdict,
	incidentEntry: Record<string, unknown> | null,
	logger: Logger,
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
	);

	try {
		const client = new ControlPlaneClient(config.control_plane, authToken, logger);
		const remoteEntry = redactRemoteEvent(entry, config.control_plane.redact_mode);
		const remoteIncident =
			config.control_plane.sync_incidents && incidentEntry
				? redactRemoteEvent(incidentEntry, config.control_plane.redact_mode)
				: null;
		const result = await client.ingest({
			iid,
			agent_runtime: context.agentRuntime,
			agent_runtime_version: context.agentRuntimeVersion,
			events: remoteIncident ? [remoteEntry, remoteIncident] : [remoteEntry],
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
			cache.putUrl(result.url, cachedVerdict, result.isMalicious);
		}
		await cache.save();
	} catch {
		// Fail open.
	}
}

async function checkPackages(
	request: ToolEvaluationRequest,
	config: Config,
	cache: VerdictCache | null,
	logger: Logger,
	apiKey: string,
	managedState: ManagedState,
	revocations: RevocationListV1 | null,
	reputationFeed?: ReputationFeedLoadOptions,
): Promise<PackageCheckResult[]> {
	const results: PackageCheckResult[] = [];
	if (!config.package_check.enabled) return results;

	let parsedPackages: ParsedPackage[] | undefined;
	try {
		if (request.toolName === "Bash") {
			const command = (request.toolInput.command ?? "") as string;
			parsedPackages = extractPackagesFromCommand(command);
		} else if (request.toolName === "Write" || request.toolName === "Edit") {
			const filePath = (request.toolInput.file_path ?? "") as string;
			const content = (request.toolInput.content ?? request.toolInput.new_string ?? "") as string;
			parsedPackages = extractPackagesFromManifest(filePath, content);
		}
	} catch (error) {
		logger.warn("Package input extraction failed", {
			toolName: request.toolName,
			errorType: error instanceof Error ? error.name : typeof error,
		});
		return [packageCheckUnavailableResult("package operation", "npm")];
	}

	if (!parsedPackages || parsedPackages.length === 0) return results;

	const intelMerged = await getPackageIntelMerged(config, managedState, revocations);
	const uncached: ParsedPackage[] = [];
	for (const pkg of parsedPackages) {
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
		} else if (!cached) {
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
					apiKey,
					intelPackageNameDeny: intelMerged?.packageNameDeny,
					intelPackageHashDeny: intelMerged?.packageHashDeny,
					reputationFeed,
				},
				logger,
			);
			const checkResults = await checker.checkPackages(uncached);
			if (Array.isArray(checkResults)) checked = checkResults;
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

function packageCheckUnavailableResult(
	packageName: string,
	registry: "npm" | "pypi",
): PackageCheckResult {
	return {
		packageName,
		registry,
		verdict: "unknown",
		confidence: 0.6,
		details: `Package check for '${packageName}' is unavailable; this package was NOT verified clean and requires review`,
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
