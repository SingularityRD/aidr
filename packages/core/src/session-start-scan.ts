/**
 * Shared SessionStart scanning pipeline for hook entry points.
 * Hooks provide transport-specific paths and output formatting.
 */

import { createHash } from "node:crypto";
import { logPluginScan } from "./audit-log.js";
import { isCommercialBuild } from "./build-flavor.js";
import { loadConfig, resolvePath } from "./config.js";
import { loadMergedIntelFromDisk } from "./intel/loader.js";
import {
	isPremiumModuleEnabled,
	loadManagedState,
	loadRevocationsCache,
	loadRevocationBinding,
	managedStatePath,
} from "./managed.js";
import {
	cacheKey,
	computeConfigHash,
	getCached,
	loadScanCache,
	saveScanCache,
	storeResult,
} from "./plugin-scan-cache.js";
import { canReusePluginScanCache, scanPlugin } from "./plugin-scanner.js";
import { loadThreats } from "./threat-loader.js";
import { loadTrustedDomains } from "./trusted-domains.js";
import type {
	Logger,
	PluginFinding,
	PluginFindingData,
	PluginInfo,
	PluginScanResult,
} from "./types.js";
import { ConfigSchema, nullLogger } from "./types.js";

export interface SessionStartScanContext {
	plugins: PluginInfo[];
	threatsDir: string;
	allowlistsDir: string;
	aidrVersion?: string;
	logger?: Logger;
	configPath?: string;
	scanCachePath?: string;
	checkUrls?: boolean;
	checkFileHashes?: boolean;
}

export function fromCachedFinding(finding: PluginFindingData): PluginFinding {
	return {
		threatId: finding.threat_id,
		title: finding.title,
		severity: finding.severity,
		confidence: finding.confidence,
		action: finding.action,
		artifact: finding.artifact,
		sourceFile: finding.source_file,
	};
}

export function toFindingData(finding: PluginFinding): PluginFindingData {
	return {
		threat_id: finding.threatId,
		title: finding.title,
		severity: finding.severity,
		confidence: finding.confidence,
		action: finding.action,
		artifact: finding.artifact,
		source_file: finding.sourceFile,
	};
}

export function toAuditFindingData(finding: PluginFinding): Record<string, unknown> {
	const { action: _, ...rest } = toFindingData(finding);
	return rest;
}

export async function runSessionStartScan(
	context: SessionStartScanContext,
): Promise<PluginScanResult[]> {
	const logger = context.logger ?? nullLogger;
	const config = await loadConfig(context.configPath, logger).catch(() => ConfigSchema.parse({}));

	const threats = await loadThreats(context.threatsDir, logger);
	const trustedDomains = await loadTrustedDomains(context.allowlistsDir, logger);

	const plugins = context.plugins;
	let intelMerged: Awaited<ReturnType<typeof loadMergedIntelFromDisk>> | null = null;
	let packAccessIdentity = "disabled";
	let revocationIdentity = "not-loaded";
	try {
		const packsEnabled = config.intel_packs?.enabled === true || config.intel?.enabled === true;
		if (packsEnabled) {
			const enforcePremium = isCommercialBuild() || config.mode === "managed";
			let mayLoadPacks = true;
			packAccessIdentity = enforcePremium ? "not-entitled" : "ungated";
			if (enforcePremium) {
				// Premium gating + revocation application (best-effort) for intel packs.
				const managed = await loadManagedState(managedStatePath(), {
					publicKeysPem: config.licensing.public_keys_pem,
					onSecurityEvent: (event) =>
						logger.warn(
							"Managed state verification failure during session scan",
							event as unknown as Record<string, unknown>,
						),
				});
				const premiumEnabled = isPremiumModuleEnabled(managed, "intel_packs");
				const entitlement = managed.entitlement;
				const entitlementIdentity = createHash("sha256")
					.update(
						JSON.stringify({
							premiumEnabled,
							algorithm: managed.entitlement_alg ?? "",
							serial: entitlement?.schema_version === 2 ? entitlement.serial : "",
							expiresAt: entitlement?.expires_at ?? "",
							graceUntil: entitlement?.schema_version === 2 ? entitlement.grace_until : "",
							revocationEpoch:
								entitlement?.schema_version === 2 ? entitlement.revocation_epoch : null,
							signature: managed.entitlement_sig ?? "",
						}),
					)
					.digest("hex");
				packAccessIdentity = `gated:${entitlementIdentity}`;
				if (!premiumEnabled) {
					mayLoadPacks = false;
				}
			}

			if (mayLoadPacks) {
				const requireRevocations =
					config.licensing.revocations_enabled && config.licensing.public_keys_pem.length > 0;
				const signedRev = requireRevocations
					? await loadRevocationsCache(
							resolvePath(config.licensing.revocations_cache_path),
							config.licensing.public_keys_pem,
							await loadRevocationBinding(config.licensing.public_keys_pem),
						)
					: null;
				revocationIdentity = createHash("sha256")
					.update(JSON.stringify(signedRev ?? null))
					.digest("hex");
				const rev = signedRev?.payload?.revocations
					? {
							pack_ids: signedRev.payload.revocations.pack_ids,
							key_ids: signedRev.payload.revocations.key_ids,
						}
					: null;

				intelMerged = await loadMergedIntelFromDisk({
					packsDir: config.intel_packs?.packs_dir,
					trustedKeysPath: config.intel_packs?.trusted_keys_path,
					verificationMode: "grace",
					graceHours: config.intel_packs?.expired_grace_hours ?? 72,
					requireRevocations,
					revocations: rev,
				});
			}
		}
	} catch {
		intelMerged = null;
		packAccessIdentity = "load-error";
		revocationIdentity = "load-error";
	}

	const checkUrls = context.checkUrls ?? config.url_check.enabled;
	const checkFileHashes = context.checkFileHashes ?? config.file_check.enabled;
	const includeQueryParameters = config.url_check.include_query_parameters;
	// Plugin scans consume only this intel set; including it prevents stale clean results after pack updates.
	const pluginIntelHash = createHash("sha256")
		.update(
			[...(intelMerged?.pluginSignatureDeny ?? [])]
				.map((value) => value.toLowerCase())
				.sort()
				.join("\n"),
		)
		.digest("hex");
	const configHash = await computeConfigHash(
		`${context.aidrVersion ?? ""}|plugin-scan-v2|urls=${checkUrls}|files=${checkFileHashes}|url-query=${includeQueryParameters}|plugin-intel=${pluginIntelHash}|packs=${packAccessIdentity}|revocations=${revocationIdentity}`,
		context.threatsDir,
		context.allowlistsDir,
	);
	const cache = await loadScanCache(configHash, context.scanCachePath, logger);
	if (plugins.length === 0) {
		await saveScanCache(cache, context.scanCachePath, logger);
		return [];
	}
	const resultsWithFindings: PluginScanResult[] = [];
	let cacheModified = false;

	for (const plugin of plugins) {
		const key = cacheKey(plugin.key, plugin.version, plugin.lastUpdated);
		const cached = getCached(cache, plugin.key, plugin.version, plugin.lastUpdated);
		const cacheTreeIsComplete = cached ? await canReusePluginScanCache(plugin, logger) : true;
		if (cached && !cacheTreeIsComplete) {
			delete cache.entries[key];
			cacheModified = true;
		}
		if (cached && cacheTreeIsComplete && cached.findings.length === 0) {
			continue;
		}

		if (cached && cacheTreeIsComplete && cached.findings.length > 0) {
			resultsWithFindings.push({
				plugin,
				findings: cached.findings.map(fromCachedFinding),
			});
			continue;
		}

		const result = await scanPlugin(plugin, threats, {
			checkUrls,
			checkFileHashes,
			includeQueryParameters,
			trustedDomains,
			intelMerged,
			logger,
		});

		if ((result.unavailableChecks?.length ?? 0) === 0) {
			storeResult(
				cache,
				plugin.key,
				plugin.version,
				plugin.lastUpdated,
				result.findings.map(toFindingData),
			);
			cacheModified = true;
		}

		if (result.findings.length > 0 || (result.unavailableChecks?.length ?? 0) > 0) {
			resultsWithFindings.push(result);
		}
	}

	if (cacheModified) {
		await saveScanCache(cache, context.scanCachePath, logger);
	}

	try {
		const aidrConfig = await loadConfig(context.configPath, logger);
		for (const result of resultsWithFindings) {
			await logPluginScan(
				aidrConfig.logging,
				result.plugin.key,
				result.plugin.version,
				result.findings.map(toAuditFindingData),
			);
		}
	} catch {
		// Logging must never crash the hook.
	}

	return resultsWithFindings;
}
