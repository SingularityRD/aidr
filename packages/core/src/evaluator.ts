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
import { isCommercialBuild } from "./build-flavor.js";
import { VerdictCache } from "./cache.js";
import { AmsiClient, isAmsiSupported } from "./clients/amsi.js";
import { ControlPlaneClient } from "./clients/control-plane.js";
import { UrlCheckClient } from "./clients/url-check.js";
import { loadConfig, resolvePath } from "./config.js";
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
import { loadThreatsFromDirs } from "./threat-loader.js";
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

export interface ToolEvaluationContext {
	threatsDir: string;
	allowlistsDir: string;
	configPath?: string;
	userThreatsDir?: string;
	agentRuntime?: AgentRuntime;
	agentRuntimeVersion?: string;
	logger?: Logger;
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
	// Initialize tracing on first call if enabled
	initTracing();

	const startTime = performance.now();

	return startActiveSpan(
		"security_decision",
		async (mainSpan) => {
			mainSpan.setAttribute("aidr.session_id", request.sessionId);
			mainSpan.setAttribute("aidr.tool_name", request.toolName);

			const verdict = await runEvaluationPipeline(request, context, startTime);

			// Record final decision attributes
			const durationMs = performance.now() - startTime;
			setSecurityDecisionAttributes({
				toolName: request.toolName,
				sessionId: request.sessionId,
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
		return { ...allowVerdict("managed_disabled"), reasons: [reason] };
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
			return disabled(
				"AIDR disabled: missing auth.api_key or auth.enrollment_token (managed-only build).",
			);
		}

		// If only enrollment_token is present, try to exchange it for an api_key.
		if (!apiKey && enrollToken && config.control_plane.enabled) {
			const iid = await getInstallationId(aidrDir).catch(() => undefined);
			if (!iid) return disabled("AIDR disabled: missing installation id (iid).");

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

		// Refresh token after potential enrollment exchange.
		token =
			(config.auth.api_key ?? "").trim() ||
			(typeof managedState.api_key === "string" ? managedState.api_key.trim() : "");
		if (!token) return disabled("AIDR disabled: enrollment did not produce an API key.");

		// Ensure we have a signed entitlement (or offline grace) before enforcing.
		// If missing, attempt a best-effort heartbeat to fetch it.
		// Respect managed sync backoff to avoid repeated remote attempts when over-limit / abuse-throttled.
		if (!isEntitlementActive(managedState) && !isSyncDisabled(managedState)) {
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
		if (
			config.licensing.require_signed_entitlements &&
			config.licensing.public_keys_pem.length > 0
		) {
			if (managedState.entitlement_alg !== "ed25519" || !isEntitlementActive(managedState)) {
				return disabled("AIDR disabled: missing or invalid server-signed entitlement (ed25519).");
			}
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
		if (isSyncDisabled(managedState)) {
			return disabled(
				`AIDR disabled: managed sync is disabled (${managedState.sync_disabled_reason ?? "unknown"}).`,
			);
		}
		if (config.licensing.require_signed_entitlements) {
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
		} catch {
			// Fail open if remote policy sync fails
		}
	}

	// MCP policy can produce verdicts even without artifacts (e.g., denying unknown servers)
	if (request.artifacts.length === 0) {
		const isMcpTool = request.toolName.startsWith("mcp__") || request.toolName === "MCP";
		if (!isMcpTool) {
			return allowVerdict("no_artifacts");
		}
	}

	// Allowlist check phase
	const allowlisted = await startActiveSpan("allowlist_check", async (allowlistSpan) => {
		const allowlistStart = performance.now();
		let isAllowlistedResult = false;
		try {
			const allowlist = await loadAllowlist(config.allowlist, logger);
			isAllowlistedResult = isAllowlisted(allowlist, request.artifacts);
			if (isAllowlistedResult) {
				const verdict = allowVerdict("allowlisted");
				await logVerdict(
					config.logging,
					request.sessionId,
					request.toolName,
					request.toolInput,
					verdict,
					true,
				);
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

	if (allowlisted) return allowlisted;

	const policyVerdict = await evaluatePolicy(
		request.toolName,
		request.artifacts,
		config,
		request.toolInput,
	);
	if (policyVerdict) {
		let incidentEntry: Record<string, unknown> | null = null;
		if (
			config.mode === "managed" &&
			config.response.emit_incidents &&
			(policyVerdict.decision === "ask" || policyVerdict.decision === "deny")
		) {
			try {
				incidentEntry = buildIncidentEntry({
					incidentId: `inc_${request.sessionId}_${Date.now()}`,
					sessionId: request.sessionId,
					toolName: request.toolName,
					toolInput: request.toolInput,
					verdict: policyVerdict,
					recommendedActions: policyVerdict.decision === "deny" ? ["review", "block"] : ["review"],
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
				request.toolInput,
				policyVerdict,
			);
		} catch {
			// Fail open.
		}

		await ingestToControlPlaneIfEnabled(
			request,
			context,
			config,
			policyVerdict,
			incidentEntry,
			logger,
		);
		return policyVerdict;
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
	const { cachedUrlVerdicts, uncachedUrls } = partitionUrlsByCache(urls, cache);

	let heuristicMatches: ReturnType<HeuristicsEngine["match"]> = [];
	if (config.heuristics_enabled) {
		const userThreatsDir = context.userThreatsDir ?? resolvePath("~/.singularity-aidr/threats");
		let threats = await loadThreatsFromDirs([context.threatsDir, userThreatsDir], logger);
		if (config.disabled_threats.length > 0) {
			const disabledSet = new Set(config.disabled_threats);
			threats = threats.filter((t) => !disabledSet.has(t.id));
		}
		const trustedDomains = await loadTrustedDomains(context.allowlistsDir, logger);
		const heuristics = new HeuristicsEngine(threats, trustedDomains);
		heuristicMatches = heuristics.match(request.artifacts);
	}

	let urlCheckResults: Awaited<ReturnType<UrlCheckClient["checkUrls"]>> = [];
	const urlsToCheck = cache ? uncachedUrls : urls;
	if (urlsToCheck.length > 0 && config.url_check.enabled) {
		try {
			const client = new UrlCheckClient(config.url_check, logger, token);
			urlCheckResults = await client.checkUrls(urlsToCheck);
		} catch {
			// Fail open.
		}
	}

	const packageCheckResults = await checkPackages(
		request,
		config,
		cache,
		logger,
		token,
		managedState,
		revocationsForIntel,
	);

	// AMSI scan (Windows only)
	const amsiCheckResults: AmsiCheckResult[] = [];
	if (config.amsi_check.enabled && isAmsiSupported()) {
		let amsiClient: AmsiClient | null = null;
		try {
			amsiClient = new AmsiClient(logger);
			await amsiClient.init();
			if (amsiClient.isAvailable) {
				const scans: { content: string; name: string }[] = [];

				if (request.toolName === "Bash") {
					const command = (request.toolInput.command ?? "") as string;
					if (command) {
						scans.push({ content: command, name: `Bash:command` });
					}
				} else if (request.toolName === "Write") {
					const filePath = (request.toolInput.file_path ?? "") as string;
					const content = (request.toolInput.content ?? "") as string;
					if (content) {
						scans.push({ content, name: `Write:${filePath}` });
					}
				} else if (request.toolName === "Edit") {
					const filePath = (request.toolInput.file_path ?? "") as string;
					const newString = (request.toolInput.new_string ?? "") as string;
					if (newString) {
						scans.push({ content: newString, name: `Edit:${filePath}` });
					}
				}

				for (const scan of scans) {
					const result = await amsiClient.scanString(scan.content, scan.name);
					if (result) {
						amsiCheckResults.push(result);
					}
				}
			}
		} catch {
			// Fail open
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

	await cacheUrlResults(urlCheckResults, cache);

	try {
		await logVerdict(
			config.logging,
			request.sessionId,
			request.toolName,
			request.toolInput,
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
				toolInput: request.toolInput,
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
		request.toolInput,
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
): Promise<PackageCheckResult[]> {
	const results: PackageCheckResult[] = [];
	if (!config.package_check.enabled) return results;

	try {
		const intelMerged = await getPackageIntelMerged(config, managedState, revocations);
		let parsedPackages: ParsedPackage[] | undefined;
		if (request.toolName === "Bash") {
			const command = (request.toolInput.command ?? "") as string;
			parsedPackages = extractPackagesFromCommand(command);
		} else if (request.toolName === "Write" || request.toolName === "Edit") {
			const filePath = (request.toolInput.file_path ?? "") as string;
			const content = (request.toolInput.content ?? request.toolInput.new_string ?? "") as string;
			parsedPackages = extractPackagesFromManifest(filePath, content);
		}

		if (!parsedPackages || parsedPackages.length === 0) return results;

		const uncached: ParsedPackage[] = [];
		for (const pkg of parsedPackages) {
			const cacheKey = `${pkg.registry}:${pkg.name}${pkg.version ? `@${pkg.version}` : ""}`;
			const cached = cache?.getPackage(cacheKey);
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
			const checker = new PackageChecker(
				{
					registryTimeoutSeconds: config.package_check.timeout_seconds,
					fileCheckEndpoint: config.file_check.endpoint,
					fileCheckTimeoutSeconds: config.file_check.timeout_seconds,
					fileCheckEnabled: config.file_check.enabled,
					apiKey,
					intelPackageNameDeny: intelMerged?.packageNameDeny,
					intelPackageHashDeny: intelMerged?.packageHashDeny,
				},
				logger,
			);
			const checked = await checker.checkPackages(uncached);
			results.push(...checked);

			if (cache) {
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
			}
		}
	} catch {
		// Fail open
	}

	return results;
}
