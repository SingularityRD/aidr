import {
	domainFromUrlOrHost,
	lookupDomainRisk,
	matchPackageIntel,
	matchPluginIntel,
} from "./api.js";
import type { DomainRiskEntry, IntelMerged } from "./types.js";

export type ReputationVerdict = "allow" | "ask" | "deny" | "unknown";

export interface ReputationResult {
	verdict: ReputationVerdict;
	reason?: string;
	confidence?: number;
	severity?: "critical" | "high" | "medium" | "low";
}

/**
 * Normalized reputation provider interface for intel packs.
 * This is intentionally minimal so connectors/runtimes can call it without
 * pulling in policy engine semantics.
 */
export interface IntelReputationProvider {
	checkUrl(urlOrHost: string): ReputationResult;
	checkDomain(domainOrHost: string): ReputationResult;
	checkPackageName(name: string): ReputationResult;
	checkPackageHashSha256(sha256Hex: string): ReputationResult;
	checkPluginSignature(signature: string): ReputationResult;
}

function asSeverityForDomain(risk: DomainRiskEntry): ReputationResult["severity"] {
	return risk.severity;
}

export function createIntelReputationProvider(merged: IntelMerged): IntelReputationProvider {
	return {
		checkUrl(urlOrHost: string): ReputationResult {
			const host = domainFromUrlOrHost(urlOrHost);
			if (!host) return { verdict: "unknown" };

			// Allowlist wins at intel layer.
			if (merged.urlAllowHosts.has(host)) {
				return { verdict: "allow", reason: "Intel URL allowlist match", confidence: 1.0 };
			}
			if (merged.urlDenyHosts.has(host)) {
				return {
					verdict: "deny",
					reason: "Intel URL denylist match",
					confidence: 1.0,
					severity: "critical",
				};
			}

			const risk = lookupDomainRisk(merged, host);
			if (!risk) return { verdict: "unknown" };

			return {
				verdict: risk.action,
				reason: risk.reason ?? "Intel domain risk match",
				confidence: typeof risk.confidence === "number" ? risk.confidence : 0.9,
				severity: asSeverityForDomain(risk),
			};
		},

		checkDomain(domainOrHost: string): ReputationResult {
			const host = domainFromUrlOrHost(domainOrHost);
			if (!host) return { verdict: "unknown" };

			const risk = lookupDomainRisk(merged, host);
			if (!risk) return { verdict: "unknown" };

			return {
				verdict: risk.action,
				reason: risk.reason ?? "Intel domain risk match",
				confidence: typeof risk.confidence === "number" ? risk.confidence : 0.9,
				severity: asSeverityForDomain(risk),
			};
		},

		checkPackageName(name: string): ReputationResult {
			const hit = matchPackageIntel(merged, { name });
			if (!hit) return { verdict: "unknown" };
			return {
				verdict: hit.verdict,
				reason: hit.reason,
				confidence: hit.confidence,
				severity: "critical",
			};
		},

		checkPackageHashSha256(sha256Hex: string): ReputationResult {
			const hit = matchPackageIntel(merged, { sha256: sha256Hex });
			if (!hit) return { verdict: "unknown" };
			return {
				verdict: hit.verdict,
				reason: hit.reason,
				confidence: hit.confidence,
				severity: "critical",
			};
		},

		checkPluginSignature(signature: string): ReputationResult {
			const hit = matchPluginIntel(merged, { signature });
			if (!hit) return { verdict: "unknown" };
			return {
				verdict: hit.verdict,
				reason: hit.reason,
				confidence: hit.confidence,
				severity: "critical",
			};
		},
	};
}
