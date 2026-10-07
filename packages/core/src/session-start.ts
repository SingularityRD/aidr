/**
 * High-level session start orchestrator.
 * Combines plugin scanning, version check, and temp cleanup into a single call.
 */

import { inspectInfrastructurePolicy } from "./aig-policy.js";
import { isCommercialBuild } from "./build-flavor.js";
import { ControlPlaneClient } from "./clients/control-plane.js";
import { isInvalidConfig, loadConfig, resolvePath } from "./config.js";
import { pruneOrphanedTmpFiles } from "./file-utils.js";
import { getInstallationId } from "./installation-id.js";
import { getDegradedSafeModeReason, isDegradedSafeMode } from "./integrity/index.js";
import {
	applyIngestResult,
	applyRevocationsToManagedState,
	getAuthToken,
	getEffectiveManagedApiKey,
	isEntitlementActive,
	isSyncDisabled,
	loadManagedState,
	loadRevocationsCache,
	revocationBindingForState,
	managedStatePath,
	parseSignedRevocationsFromControlPlaneBody,
	saveEntitlementKeyringFromState,
	saveManagedState,
	saveRevocationsCache,
	verifyEd25519SignedRevocationList,
} from "./managed.js";
import {
	beginEnrollment,
	clearEnrollment,
	enrollManagedInstallation,
	enrollmentPending,
} from "./managed-enrollment.js";
import {
	discoverMcpServers,
	type McpDiscoveryAttestationOptions,
	type McpDiscoveryAttestationStatus,
	type McpDiscoveryServer,
} from "./mcp-discovery.js";
import type { McpInventoryCoverageStatus } from "./mcp-inventory.js";
import { inspectRemoteRuntimePolicyCache } from "./remote-policy.js";
import { runSessionStartScan } from "./session-start-scan.js";
import type { AgentRuntime, Logger, PluginInfo, PluginScanResult } from "./types.js";
import { nullLogger } from "./types.js";
import { checkForUpdate, type VersionCheckResult } from "./version-check.js";

export interface SessionStartContext {
	plugins: PluginInfo[];
	threatsDir: string;
	allowlistsDir: string;
	version: string;
	agentRuntime: AgentRuntime;
	logger?: Logger;
	configPath?: string;
	scanCachePath?: string;
	checkUrls?: boolean;
	checkFileHashes?: boolean;
	aidrDirPath?: string;
	agentRuntimeVersion?: string;
	/**
	 * Tenant MCP tool-manifest attestation inputs (keyring, signed manifests,
	 * recorded approval state). Trusted-publisher provisioning and signer key
	 * custody are external; when this is omitted every discovered server is
	 * reported as unverifiable rather than as a neutral inventory row.
	 */
	mcpAttestation?: McpDiscoveryAttestationOptions;
}

/**
 * A discovery coverage gap, not a threat finding: the server's tool definitions
 * could not be shown to be signed and operator-approved.
 */
export interface SessionStartCoverageFinding {
	kind: "mcp_tool_manifest_unverified";
	severity: "medium" | "high";
	/** Locally configured server name. */
	server: string;
	/** Configuration file the server was discovered in. */
	source: string;
	/** Discovery attestation status that produced this finding. */
	status: McpDiscoveryAttestationStatus;
	reason: string;
	detail: string;
	/** Toolset hash held in quarantine, when one exists. */
	quarantined_toolset_hash?: string;
}

export interface SessionStartResult {
	enabled: boolean;
	disabled_reason?: string;
	bootstrap?: {
		verification_url: string;
		user_code: string;
		expires_at?: string;
	};
	scanResults: PluginScanResult[];
	versionCheck: VersionCheckResult | null;
	posture?: {
		mcpServers: number;
		riskyMcpServers: number;
		unverifiedMcpServers: number;
		invalidSources: number;
		/** Aggregate readability of the MCP inventory sources; never claims a
		 * complete inventory when a configured source could not be read. */
		mcpCoverage: McpInventoryCoverageStatus;
		/** Server records visible in a readable source but not enumerable. */
		mcpServersNotEnumerated: number;
		/** Sources whose whole server list is unknown (unparseable files). */
		mcpSourcesNotEnumerated: number;
		infrastructure: string;
	};
	/**
	 * Coverage gaps from MCP discovery. An unverified server is a finding here,
	 * never a neutral count in `posture`.
	 */
	coverageFindings?: SessionStartCoverageFinding[];
}

/** Coverage gaps are visibility failures: verification could not be established. */
const COVERAGE_SEVERITY: Record<McpDiscoveryAttestationStatus, "medium" | "high"> = {
	approved: "medium",
	quarantined: "medium",
	unapproved: "medium",
	unsigned: "medium",
	unverifiable: "high",
	rejected: "high",
};

const COVERAGE_DETAIL: Record<string, string> = {
	no_keyring:
		"No MCP signing keyring is configured on this agent, so the tool manifest cannot be verified. Trusted-publisher provisioning is external to this agent.",
	no_signed_manifest:
		"No signed tool manifest was supplied for this server, so its tool definitions are unverified.",
	unknown_signer:
		"The manifest signer is not present in the tenant keyring, so the tool manifest cannot be verified.",
	invalid_public_key:
		"The tenant keyring entry for the manifest signer is not a usable Ed25519 public key.",
	approval_state_unavailable:
		"The signed tool manifest verified, but no readable attestation state was available, so operator approval cannot be established.",
	state_unavailable:
		"The signed tool manifest verified, but the recorded attestation state could not be read, so the toolset cannot be treated as approved.",
	not_approved:
		"The signed tool manifest verified, but no operator approval is recorded for this toolset.",
	quarantined_pending_operator_approval:
		"The signed tool manifest is quarantined pending an out-of-band operator approval.",
};

function mcpToolManifestCoverageFindings(
	servers: McpDiscoveryServer[],
): SessionStartCoverageFinding[] {
	const findings: SessionStartCoverageFinding[] = [];
	for (const server of servers) {
		const { attestation } = server;
		if (attestation.status === "approved") continue;
		const reason = attestation.reason ?? attestation.status;
		const fallback =
			attestation.status === "rejected"
				? `The tool manifest failed verification (${reason}); it is not trusted.`
				: `The tool manifest could not be verified (${reason}).`;
		findings.push({
			kind: "mcp_tool_manifest_unverified",
			severity: COVERAGE_SEVERITY[attestation.status],
			server: server.name,
			source: server.source,
			status: attestation.status,
			reason,
			detail: COVERAGE_DETAIL[reason] ?? fallback,
			...(attestation.quarantined_toolset_hash
				? { quarantined_toolset_hash: attestation.quarantined_toolset_hash }
				: {}),
		});
	}
	return findings;
}

export async function runSessionStart(ctx: SessionStartContext): Promise<SessionStartResult> {
	const logger = ctx.logger ?? nullLogger;
	const aidrDirPath = resolvePath(ctx.aidrDirPath ?? "~/.singularity-aidr");
	const config = await loadConfig(ctx.configPath, logger).catch(() => undefined);
	if (!config || isInvalidConfig(config)) {
		return {
			enabled: false,
			disabled_reason: "configuration_invalid",
			scanResults: [],
			versionCheck: null,
		};
	}
	if (config.privacy?.required === true) {
		return {
			enabled: false,
			disabled_reason: "mandatory_privacy_requires_owned_gateway",
			scanResults: [],
			versionCheck: null,
		};
	}
	const commercial = isCommercialBuild();
	const [inventory, infrastructure] = await Promise.all([
		discoverMcpServers(config.policy.mcp.inventory_paths, { attestation: ctx.mcpAttestation }),
		inspectInfrastructurePolicy(config),
	]);
	const coverageFindings = mcpToolManifestCoverageFindings(inventory.servers);
	const posture = {
		mcpServers: inventory.servers.length,
		riskyMcpServers: inventory.servers.filter((s) => s.risk_hints.length > 0).length,
		unverifiedMcpServers: coverageFindings.length,
		invalidSources: inventory.sources.filter((s) => s.status === "invalid").length,
		mcpCoverage: inventory.coverage.status,
		mcpServersNotEnumerated: inventory.coverage.servers_not_enumerated,
		mcpSourcesNotEnumerated: inventory.coverage.sources_not_enumerated,
		infrastructure: infrastructure.state,
	};

	if (commercial && config.mode !== "managed") {
		return {
			enabled: false,
			disabled_reason: "commercial_build_requires_managed_mode",
			scanResults: [],
			versionCheck: null,
		};
	}

	if (commercial && isDegradedSafeMode()) {
		return {
			enabled: false,
			disabled_reason: `degraded_safe_mode:${getDegradedSafeModeReason() ?? "integrity"}`,
			scanResults: [],
			versionCheck: null,
		};
	}

	// Fire-and-forget temp cleanup
	pruneOrphanedTmpFiles(aidrDirPath).catch(() => {});

	let token = getAuthToken(config.auth);
	const managedPath = managedStatePath();
	const enrollmentPendingPath = `${managedPath}.enrollment-pending`;
	const repairRequired = (): SessionStartResult => ({
		enabled: false,
		disabled_reason: "enrollment_repair_required",
		scanResults: [],
		versionCheck: null,
	});
	if (config.mode === "managed" && (await enrollmentPending(enrollmentPendingPath))) {
		return repairRequired();
	}
	// Do not generate a replacement installation identity while repair is pending.
	const iidPromise = getInstallationId(aidrDirPath).catch(() => undefined);

	// Allow managed state to persist an issued API key (from /v1/enroll).
	let managedState = await loadManagedState(managedPath, {
		authToken: token,
		publicKeysPem: config.licensing.public_keys_pem,
		onSecurityEvent: (event) =>
			logger.warn(
				"Managed state verification failure",
				event as unknown as Record<string, unknown>,
			),
	});
	const cachedApiKey = typeof managedState.api_key === "string" ? managedState.api_key.trim() : "";
	token = getEffectiveManagedApiKey(config.auth.api_key, managedState) || token;
	const loadCurrentState = () =>
		loadManagedState(managedPath, {
			authToken: token,
			publicKeysPem: config.licensing.public_keys_pem,
		});
	const useSavedCredential = (current: typeof managedState): boolean => {
		if (!current.api_key?.trim()) return false;
		managedState = current;
		token = getEffectiveManagedApiKey(config.auth.api_key, current);
		return true;
	};

	const enroll = async (
		enrollmentToken: string,
		iid: string,
	): Promise<"enrolled" | "retry" | "repair"> => {
		const result = await enrollManagedInstallation({
			managedPath,
			enrollmentToken,
			iid,
			config,
			logger,
			agentRuntime: ctx.agentRuntime,
			agentRuntimeVersion: ctx.agentRuntimeVersion,
		});
		if (result.outcome === "enrolled") {
			managedState = result.state;
			token = result.apiKey;
		}
		return result.outcome;
	};

	// Managed-only: if there's no auth token, start (or reuse) a device-code bootstrap session.
	// This must not block: create (or reuse) a short code + URL so the user can authorize in a browser.
	if (!token && config.mode === "managed" && config.control_plane.enabled) {
		let bootstrap:
			| {
					device_code: string;
					user_code: string;
					verification_url: string;
					expires_at?: string;
			  }
			| undefined;

		const expMs =
			typeof managedState.device_expires_at === "string"
				? Date.parse(managedState.device_expires_at)
				: Number.NaN;
		const stillValid = Number.isFinite(expMs) && Date.now() < expMs - 5000;
		if (
			stillValid &&
			typeof managedState.device_code === "string" &&
			typeof managedState.user_code === "string" &&
			typeof managedState.verification_url === "string"
		) {
			bootstrap = {
				device_code: managedState.device_code,
				user_code: managedState.user_code,
				verification_url: managedState.verification_url,
				expires_at: managedState.device_expires_at,
			};
		} else {
			try {
				const client = new ControlPlaneClient(config.control_plane, "", logger);
				const iid = await iidPromise;
				const res = await client.deviceStart({
					iid,
					agent_runtime: ctx.agentRuntime,
					agent_runtime_version: ctx.agentRuntimeVersion,
				});
				const body = res.body ?? {};
				const deviceCode =
					typeof body.device_code === "string" ? (body.device_code as string).trim() : "";
				const userCode =
					typeof body.user_code === "string" ? (body.user_code as string).trim() : "";
				const verifyUrl =
					typeof body.verification_url === "string" ? (body.verification_url as string).trim() : "";
				const expiresAt =
					typeof body.expires_at === "string" ? (body.expires_at as string).trim() : "";

				if (res.ok && deviceCode && userCode && verifyUrl) {
					// Serialize bootstrap writes with issuance too. A slow device-start
					// response must not replace a key saved by a faster startup.
					const attempt = await beginEnrollment(enrollmentPendingPath, iid ?? "unavailable");
					if (!attempt) return repairRequired();
					try {
						const current = await loadCurrentState();
						if (!useSavedCredential(current)) {
							managedState = {
								...current,
								device_code: deviceCode,
								user_code: userCode,
								verification_url: verifyUrl,
								device_expires_at: expiresAt || undefined,
								device_started_at: new Date().toISOString(),
							};
							await saveManagedState(managedPath, managedState, undefined, {
								requirePersistence: true,
							});
							bootstrap = {
								device_code: deviceCode,
								user_code: userCode,
								verification_url: verifyUrl,
								expires_at: expiresAt || undefined,
							};
						}
					} finally {
						// No enroll request has been sent by this bootstrap writer.
						await clearEnrollment(enrollmentPendingPath, attempt);
					}
				}
			} catch {
				// Ignore.
			}
		}

		// Best-effort: one-shot poll. If the user already authorized, we can enroll immediately.
		if (bootstrap) {
			try {
				const client = new ControlPlaneClient(config.control_plane, "", logger);
				const poll = await client.devicePoll({ device_code: bootstrap.device_code });
				const enrollToken =
					typeof poll.body?.enrollment_token === "string"
						? (poll.body.enrollment_token as string).trim()
						: "";
				if (poll.ok && enrollToken) {
					const iid = await iidPromise;
					if (iid) {
						if ((await enroll(enrollToken, iid)) === "repair") return repairRequired();
					}
				} else if (poll.error === "already_exchanged") {
					try {
						const attempt = await beginEnrollment(
							enrollmentPendingPath,
							(await iidPromise) ?? "unavailable",
						);
						if (!attempt || !useSavedCredential(await loadCurrentState())) return repairRequired();
						await clearEnrollment(enrollmentPendingPath, attempt);
					} catch {
						return repairRequired();
					}
				}
			} catch {
				// Ignore.
			}
		}

		// If we still don't have a token, return a bootstrap hint and keep protections disabled.
		if (!token) {
			return {
				enabled: false,
				disabled_reason: "auth_required",
				bootstrap: bootstrap
					? {
							verification_url: bootstrap.verification_url,
							user_code: bootstrap.user_code,
							expires_at: bootstrap.expires_at,
						}
					: undefined,
				scanResults: [],
				versionCheck: null,
			};
		}
	}

	// One-time enrollment exchange. A lost issuance response requires repair.
	if (!config.auth.api_key?.trim() && config.auth.enrollment_token?.trim() && !cachedApiKey) {
		const iid = await iidPromise;
		if (iid) {
			const outcome = await enroll(config.auth.enrollment_token.trim(), iid);
			if (outcome === "repair") return repairRequired();
			if (outcome === "retry")
				return {
					enabled: false,
					disabled_reason: "auth_required",
					scanResults: [],
					versionCheck: null,
				};
		}
	}

	// Ensure we have a valid entitlement before doing any protection-related startup work.
	if (
		config.control_plane.enabled &&
		(!isEntitlementActive(managedState) ||
			(config.licensing.require_signed_entitlements && managedState.entitlement_alg !== "ed25519"))
	) {
		try {
			const iid = await iidPromise;
			if (iid) {
				const client = new ControlPlaneClient(config.control_plane, token ?? "", logger, {
					telemetryQueueBinding: managedState.telemetry_queue,
				});
				const result = await client.ingest({
					iid,
					agent_runtime: ctx.agentRuntime,
					agent_runtime_version: ctx.agentRuntimeVersion,
					events: [],
				});
				const next = applyIngestResult(
					managedState,
					result,
					config.control_plane.grace_period_hours,
					{
						authToken: token,
						publicKeysPem: config.licensing.public_keys_pem,
						endpoint: config.control_plane.endpoint,
						iid,
					},
				);
				if (next !== managedState) {
					managedState = next;
					await saveManagedState(managedPath, managedState);
					await saveEntitlementKeyringFromState(managedState);
					token = getEffectiveManagedApiKey(config.auth.api_key, managedState) || token;
				}
			}
		} catch {
			// Ignore.
		}
	}

	if (config.licensing.require_signed_entitlements && config.licensing.public_keys_pem.length > 0) {
		if (managedState.entitlement_alg !== "ed25519" || !isEntitlementActive(managedState)) {
			return {
				enabled: false,
				disabled_reason: "missing_or_invalid_signed_entitlement",
				scanResults: [],
				versionCheck: null,
			};
		}
	}

	const managedHeartbeat =
		config.mode === "managed" && config.control_plane.enabled && token
			? async () => {
					const heartbeatToken = token;
					if (!heartbeatToken) return;
					const iid = await iidPromise;
					if (!iid) return;

					try {
						const client = new ControlPlaneClient(config.control_plane, heartbeatToken, logger, {
							telemetryQueueBinding: managedState.telemetry_queue,
						});

						// Revocation feed (best-effort): cached, verified, and applied to local premium unlock.
						let signedRev =
							config.licensing.revocations_enabled && config.licensing.public_keys_pem.length > 0
								? await loadRevocationsCache(
										resolvePath(config.licensing.revocations_cache_path),
										config.licensing.public_keys_pem,
										revocationBindingForState(managedState),
									)
								: null;
						const refreshMs =
							Math.max(0, config.licensing.revocations_refresh_seconds ?? 3600) * 1000;
						const shouldRefresh =
							!signedRev ||
							!Number.isFinite(Date.parse(signedRev.payload.issued_at)) ||
							Date.now() - Date.parse(signedRev.payload.issued_at) > refreshMs;
						if (
							shouldRefresh &&
							config.licensing.revocations_enabled &&
							config.licensing.public_keys_pem.length > 0
						) {
							const res = await client.fetchRevocations();
							if (res.ok) {
								const parsed = parseSignedRevocationsFromControlPlaneBody(
									res.body,
									revocationBindingForState(managedState),
								);
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

						const revokedState = applyRevocationsToManagedState({
							state: managedState,
							iid,
							revocations: signedRev?.payload ?? null,
						});
						if (revokedState !== managedState) {
							managedState = revokedState;
							await saveManagedState(managedPath, managedState);
						}

						if (isSyncDisabled(managedState)) return;

						const cacheStatus = await inspectRemoteRuntimePolicyCache(config, heartbeatToken).catch(
							() => undefined,
						);
						const events: Record<string, unknown>[] = [];
						if (cacheStatus && cacheStatus.present) {
							events.push({
								type: "runtime_policy_cache",
								verdict: "allow",
								severity: "info",
								runtime_policy_cache: {
									source: cacheStatus.source,
									usable: cacheStatus.usable,
									policy_version: cacheStatus.policyVersion,
								},
							});
						}

						const result = await client.ingest({
							iid,
							agent_runtime: ctx.agentRuntime,
							agent_runtime_version: ctx.agentRuntimeVersion,
							events,
						});
						const next = applyIngestResult(
							managedState,
							result,
							config.control_plane.grace_period_hours,
							{
								authToken: heartbeatToken,
								publicKeysPem: config.licensing.public_keys_pem,
								endpoint: config.control_plane.endpoint,
								iid,
							},
						);
						const nextWithRevocations = signedRev?.payload
							? applyRevocationsToManagedState({
									state: next,
									iid,
									revocations: signedRev.payload,
								})
							: next;
						if (nextWithRevocations !== managedState) {
							await saveManagedState(managedPath, nextWithRevocations);
							await saveEntitlementKeyringFromState(nextWithRevocations);
							managedState = nextWithRevocations;
							token = getEffectiveManagedApiKey(config.auth.api_key, managedState) || token;
						}
					} catch {
						// Fail open
					}
				}
			: async () => {};

	const heartbeatPromise = managedHeartbeat();

	const versionCheckPromise = config.version_check.enabled
		? iidPromise
				.then((iid) =>
					checkForUpdate(
						ctx.version,
						logger,
						undefined,
						{
							agentRuntime: ctx.agentRuntime,
							agentRuntimeVersion: ctx.agentRuntimeVersion,
							iid,
						},
						token,
					),
				)
				.catch(() => null)
		: Promise.resolve(null);

	// Commercial build: enforce strict startup order by waiting for managed heartbeat
	// (revocations + entitlement refresh) before scanning or loading packs.
	if (commercial) {
		await heartbeatPromise;
		const [scanResults, versionCheck] = await Promise.all([
			runSessionStartScan({
				plugins: ctx.plugins,
				threatsDir: ctx.threatsDir,
				allowlistsDir: ctx.allowlistsDir,
				aidrVersion: ctx.version,
				logger,
				configPath: ctx.configPath,
				scanCachePath: ctx.scanCachePath,
				checkUrls: ctx.checkUrls,
				checkFileHashes: ctx.checkFileHashes,
			}),
			versionCheckPromise,
		]);
		return { enabled: true, scanResults, versionCheck, posture, coverageFindings };
	}

	// Parallel: scan + version check + managed heartbeat
	const [scanResults, versionCheck] = await Promise.all([
		runSessionStartScan({
			plugins: ctx.plugins,
			threatsDir: ctx.threatsDir,
			allowlistsDir: ctx.allowlistsDir,
			aidrVersion: ctx.version,
			logger,
			configPath: ctx.configPath,
			scanCachePath: ctx.scanCachePath,
			checkUrls: ctx.checkUrls,
			checkFileHashes: ctx.checkFileHashes,
		}),
		versionCheckPromise,
		heartbeatPromise,
	]);

	return { enabled: true, scanResults, versionCheck, posture, coverageFindings };
}
