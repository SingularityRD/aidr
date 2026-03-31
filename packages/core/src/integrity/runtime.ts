import { logIncident } from "../audit-log.js";
import { loadConfig, resolvePath } from "../config.js";
import { loadRevocationsCache } from "../managed.js";
import type { Logger } from "../types.js";
import { ConfigSchema, nullLogger } from "../types.js";
import { enterDegradedSafeMode } from "./degraded-safe-mode.js";
import { type IntegrityCheckResult, verifyArtifactIntegrity } from "./verify.js";

export async function verifyArtifactIntegrityAndLog(params: {
	artifactDir: string;
	artifactId: string;
	logger?: Logger;
	configPath?: string;
}): Promise<IntegrityCheckResult> {
	const logger = params.logger ?? nullLogger;
	const config = await loadConfig(params.configPath, logger).catch(() => ConfigSchema.parse({}));

	if (!config.integrity.enabled) return { status: "skipped" };
	if (!config.integrity.verify_on_start) return { status: "skipped" };

	// Optional: apply revocations to prevent known-compromised artifacts from running in premium mode.
	try {
		if (config.licensing.revocations_enabled && config.licensing.public_keys_pem.length > 0) {
			const signed = await loadRevocationsCache(
				resolvePath(config.licensing.revocations_cache_path),
				config.licensing.public_keys_pem,
			);
			const revoked = signed?.payload?.revocations?.artifact_ids ?? [];
			if (Array.isArray(revoked) && revoked.includes(params.artifactId)) {
				enterDegradedSafeMode(`${params.artifactId}:revoked`);

				try {
					await logIncident(config.logging, {
						type: "incident",
						timestamp: new Date().toISOString(),
						incident_id: `inc_revoked_${Date.now()}`,
						status: "open",
						session_id: `revoked_${params.artifactId}`,
						tool_name: "Integrity",
						tool_input_summary: params.artifactId,
						artifacts: [params.artifactId],
						decision: "ask",
						severity: "critical",
						reasons: ["Artifact is revoked by control plane revocation feed"],
						source: "integrity",
						matched_threat_id: "REVOCATION-ARTIFACT-001",
						recommended_actions: ["review", "reinstall"],
					});
				} catch (e) {
					logger.debug("Revocation incident log failed (fail-open)", { error: String(e) });
				}

				return { status: "revoked", reason: "artifact_id_revoked" };
			}
		}
	} catch {
		// Fail open
	}

	const result = await verifyArtifactIntegrity({
		artifactDir: params.artifactDir,
		publicKeysPem: config.integrity.public_keys_pem ?? [],
		verifySignatures: (config.integrity.public_keys_pem ?? []).length > 0,
		expectedArtifactId: params.artifactId,
	});

	if (
		result.status === "ok" ||
		result.status === "missing_manifest" ||
		result.status === "no_public_keys"
	) {
		return result;
	}

	// Anything other than ok/skipped/missing-manifest/no-keys is treated as suspicious.
	enterDegradedSafeMode(`${params.artifactId}:${result.status}`);

	try {
		const mismatchedPaths = (result.mismatches ?? []).map((m) => m.path);
		const manifest = result.manifest as
			| (typeof result.manifest & { lineage?: { watermark_id?: string } })
			| undefined;
		const watermark = manifest?.lineage?.watermark_id;
		await logIncident(config.logging, {
			type: "incident",
			timestamp: new Date().toISOString(),
			incident_id: `inc_integrity_${Date.now()}`,
			status: "open",
			session_id: `integrity_${params.artifactId}`,
			tool_name: "Integrity",
			tool_input_summary: params.artifactId,
			artifacts: mismatchedPaths.length > 0 ? mismatchedPaths : [params.artifactId],
			decision: "ask",
			severity: "critical",
			reasons: [
				`Artifact integrity check failed: ${result.status}`,
				watermark ? `watermark_id: ${watermark}` : "",
				result.reason ?? "",
			].filter(Boolean),
			source: "integrity",
			matched_threat_id: "INTEGRITY-001",
			recommended_actions: ["review", "reinstall"],
		});
	} catch (e) {
		logger.debug("Integrity incident log failed (fail-open)", { error: String(e) });
	}

	return result;
}
