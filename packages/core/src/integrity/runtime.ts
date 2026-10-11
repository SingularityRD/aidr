import { logIncident } from "../audit-log.js";
import { isCommercialBuild } from "../build-flavor.js";
import { loadConfig, resolvePath } from "../config.js";
import { loadRevocationBinding, loadRevocationsCache } from "../managed.js";
import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";
import { enterDegradedSafeMode } from "./degraded-safe-mode.js";
import {
	hasWellFormedSignature,
	type IntegrityCheckResult,
	verifyArtifactIntegrity,
} from "./verify.js";

export class ArtifactIntegrityError extends Error {
	constructor(
		readonly artifactId: string,
		readonly result: IntegrityCheckResult,
	) {
		super(`Artifact integrity verification failed for ${artifactId}: ${result.status}`);
		this.name = "ArtifactIntegrityError";
	}
}

export async function verifyArtifactIntegrityAndLog(params: {
	artifactDir: string;
	artifactId: string;
	logger?: Logger;
	configPath?: string;
}): Promise<IntegrityCheckResult> {
	const logger = params.logger ?? nullLogger;
	const config = await loadConfig(params.configPath, logger);
	const commercial = isCommercialBuild();

	if (!commercial && !config.integrity.enabled) return { status: "skipped" };
	if (!commercial && !config.integrity.verify_on_start) return { status: "skipped" };

	// Optional: apply revocations to prevent known-compromised artifacts from running in premium mode.
	try {
		if (config.licensing.revocations_enabled && config.licensing.public_keys_pem.length > 0) {
			const signed = await loadRevocationsCache(
				resolvePath(config.licensing.revocations_cache_path),
				config.licensing.public_keys_pem,
				await loadRevocationBinding(config.licensing.public_keys_pem),
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

				const result = { status: "revoked", reason: "artifact_id_revoked" } as const;
				if (commercial) throw new ArtifactIntegrityError(params.artifactId, result);
				return result;
			}
		}
	} catch (error) {
		if (error instanceof ArtifactIntegrityError) throw error;
		// Fail open
	}

	const publicKeysPem = config.integrity.public_keys_pem ?? [];
	let result = await verifyArtifactIntegrity({
		artifactDir: params.artifactDir,
		publicKeysPem,
		verifySignatures: commercial || publicKeysPem.length > 0,
		expectedArtifactId: params.artifactId,
	});

	if (result.status === "ok") return result;

	// A commercial install that is not enrolled (or has not been provisioned with
	// the integrity trust keys yet, e.g. offline) has nothing to verify the
	// manifest signature against. That is a missing managed capability, not
	// evidence of tampering: refusing to start here turned every un-enrolled
	// commercial install into a blanket deny, contrary to the local-enforcement
	// default. The shipped bytes are still checked against the manifest digests
	// (including the closed resource directories); any mismatch is a genuine
	// local integrity failure and still fails closed below.
	//
	// That allowance covers a *signed* release only. An artifact that ships no
	// signature at all (a development or unsigned release-candidate build) has
	// no release provenance to fall back on, so it fails closed exactly as a
	// missing manifest does: digests computed by whoever built the bytes prove
	// nothing about where they came from.
	if (
		commercial &&
		result.status === "no_public_keys" &&
		!(await hasWellFormedSignature(params.artifactDir))
	) {
		result = { ...result, reason: "artifact_unsigned" };
	} else if (commercial && result.status === "no_public_keys") {
		const unsigned = await verifyArtifactIntegrity({
			artifactDir: params.artifactDir,
			publicKeysPem: [],
			verifySignatures: false,
			expectedArtifactId: params.artifactId,
		});
		if (unsigned.status === "ok") {
			logger.warn(
				"Artifact signature not verifiable: no integrity public keys are provisioned (managed status unavailable). File digests verified; local detection continues.",
				{ artifactId: params.artifactId },
			);
			return {
				status: "no_public_keys",
				manifest: unsigned.manifest,
				reason: "signature_unverified_digests_ok",
			};
		}
		result = unsigned;
	}
	if (!commercial && (result.status === "missing_manifest" || result.status === "no_public_keys"))
		return result;

	// Development tolerates absent release metadata; commercial artifacts tolerate nothing but ok.
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

	if (commercial) throw new ArtifactIntegrityError(params.artifactId, result);
	return result;
}
