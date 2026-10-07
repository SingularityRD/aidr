/**
 * Shared visual formatting for Singularity AIDR alerts.
 * Plain text + Unicode only — no ANSI escape codes.
 */

import type { SessionStartCoverageFinding, SessionStartResult } from "./session-start.js";
import type { PluginScanResult, PluginScanUnavailableCheck } from "./types.js";
import type { VersionCheckResult } from "./version-check.js";

export interface RemotePolicyCacheInfo {
	enabled: boolean;
	path?: string;
	source?: "valid" | "expired" | "invalid" | "missing";
	usable?: boolean;
	present?: boolean;
	policyVersion?: string;
	ttlSeconds?: number;
	ageSeconds?: number;
}

export const PAD = 12;
export const SEPARATOR_WIDTH = 48;

export function severityEmoji(severity: string): string {
	const s = severity.toLowerCase();
	if (s === "critical" || s === "high") return "🚨";
	if (s === "medium" || s === "warn" || s === "warning") return "⚠️";
	return "ℹ️";
}

export function kv(key: string, value: string): string {
	return `   ${key.padEnd(PAD)}${value}`;
}

export function separatorLine(headerLength: number): string {
	return "━".repeat(headerLength);
}

export function formatUpdateNotice(result: VersionCheckResult): string {
	return `⬆️  Update available: v${result.currentVersion} → v${result.latestVersion} (https://github.com/singularityrd/aidr)`;
}

function formatRemotePolicyLine(cache?: RemotePolicyCacheInfo | null): string {
	if (!cache?.enabled || !cache?.present) return "";
	if (cache.source === "valid" && cache.ttlSeconds != null) {
		return `${cache.policyVersion ?? "policy"} cached, ${cache.ttlSeconds}s left`;
	}
	if (cache.source === "expired") {
		const suffix = cache.ageSeconds != null ? `, ${cache.ageSeconds}s old` : "";
		return `${cache.policyVersion ?? "policy"} cache expired${suffix}`;
	}
	if (cache.source === "invalid") {
		return "cache invalid";
	}
	return "";
}

export function formatStartupClean(
	version: string,
	versionCheck?: VersionCheckResult | null,
	remotePolicyCache?: RemotePolicyCacheInfo | null,
): string {
	let base = `🛡️ Singularity AIDR v${version} ✅ No threats found`;
	const policyLine = formatRemotePolicyLine(remotePolicyCache);
	if (policyLine) {
		base = `${base}\n${kv("Policy", policyLine)}`;
	}
	if (versionCheck?.updateAvailable) {
		return `${base}\n${formatUpdateNotice(versionCheck)}`;
	}
	return base;
}

export function formatStartupDisabled(version: string, reason: string): string {
	return `Singularity AIDR v${version} - Disabled (${reason})`;
}

/**
 * A managed/commercial installation that has not been enrolled still enforces
 * locally - the evaluator runs the full local detection layer. Reporting it as
 * "Disabled" is wrong and dangerous: it tells the operator there is no
 * protection while threats are in fact being blocked, and it was the message
 * that made the un-enrolled state look like a dead end.
 *
 * Used only for the reasons in LOCAL_ENFORCEMENT_ACTIVE_REASONS. Reasons that
 * genuinely stop enforcement (degraded integrity, a commercial build forced to
 * local mode, an unrecognised reason) use formatStartupDisabled instead.
 */
function formatStartupLocalOnly(version: string, reason: string): string {
	return `Singularity AIDR v${version} - Local protection ACTIVE (managed features unavailable: ${reason})`;
}

/**
 * The reasons for which the local detection layer still runs and therefore for
 * which this banner must NOT claim the product is switched off.
 *
 * This is an allow-list on purpose. The failure mode being guarded against is
 * over-claiming protection, so an unrecognised reason must fall back to
 * "Disabled" rather than to "protection is ACTIVE".
 */
const LOCAL_ENFORCEMENT_ACTIVE_REASONS = new Set<string>([
	// Managed/commercial installation that has not been enrolled. The evaluator
	// keeps running the full local layer; only managed features are unavailable.
	"auth_required",
	"enrollment_repair_required",
	"missing_or_invalid_signed_entitlement",
	"activation_required",
]);

function isEnforcementStopped(disabledReason: string | undefined): boolean {
	if (!disabledReason) return true;
	return !LOCAL_ENFORCEMENT_ACTIVE_REASONS.has(disabledReason);
}

/** Banner lines for one check that could not run (or ran on partial rules) for a plugin. */
function unavailableCheckLines(pluginKey: string, check: PluginScanUnavailableCheck): string[] {
	if (check.check === "threat_rules") {
		return [
			`⚠️ ${`Plugin`.padEnd(PAD)}${pluginKey}`,
			`⚠️ Threat rules incomplete — protection degraded (${check.uncheckedCount} rule file(s) missing or unverified).`,
			kv("Reason", check.reason),
		];
	}
	const label =
		check.check === "url_reputation"
			? "URL reputation"
			: check.check === "file_reputation"
				? "File reputation"
				: "Plugin file inspection";
	return [
		check.check === "plugin_files"
			? `⚠️ ${label} was incomplete for ${check.uncheckedCount} path(s).`
			: `⚠️ ${label} was not verified for ${check.uncheckedCount} item(s).`,
		kv("Reason", check.reason),
	];
}

export function formatThreatBanner(
	version: string,
	results: PluginScanResult[],
	versionCheck?: VersionCheckResult | null,
	remotePolicyCache?: RemotePolicyCacheInfo | null,
): string {
	const hasHighOrCriticalFinding = results.some((result) =>
		result.findings.some(
			(finding) => finding.severity === "critical" || finding.severity === "high",
		),
	);
	const hasUnavailableChecks = results.some(
		(result) => (result.unavailableChecks?.length ?? 0) > 0,
	);
	const headerLabel = hasHighOrCriticalFinding
		? "Threat Detected"
		: hasUnavailableChecks
			? "Review Required"
			: "Threat Detected";
	const header = `🛡️ Singularity AIDR v${version} — ${headerLabel}`;
	const lines: string[] = [" ", header, separatorLine(SEPARATOR_WIDTH)];

	const MAX_FINDINGS = 5;
	let first = true;

	for (const result of results) {
		const highCrit = result.findings.filter(
			(f) => f.severity === "critical" || f.severity === "high",
		);
		for (const f of highCrit.slice(0, MAX_FINDINGS)) {
			if (!first) lines.push("");
			first = false;

			const emoji = severityEmoji(f.severity);
			lines.push(`${emoji} ${`Plugin`.padEnd(PAD)}${result.plugin.key}`);
			lines.push(kv("Threat", f.title));
			lines.push(kv("Severity", f.severity.toUpperCase()));
			if (f.artifact) {
				lines.push(kv("Artifact", f.artifact));
			}
			lines.push(kv("Source", f.sourceFile));
			const actionLabel =
				f.action === "block"
					? "Block recommendation; review or disable this plugin"
					: "Review recommended";
			lines.push(kv("Finding", actionLabel));
		}

		const overflow = highCrit.length - MAX_FINDINGS;
		if (overflow > 0) {
			lines.push("");
			lines.push(`   ... and ${overflow} more findings`);
		}

		for (const check of result.unavailableChecks ?? []) {
			if (!first) lines.push("");
			first = false;
			lines.push(...unavailableCheckLines(result.plugin.key, check));
		}
	}

	const policyLine = formatRemotePolicyLine(remotePolicyCache);
	if (policyLine) {
		lines.push("");
		lines.push(kv("Policy", policyLine));
	}

	if (versionCheck?.updateAvailable) {
		lines.push("");
		lines.push(formatUpdateNotice(versionCheck));
	}

	return lines.join("\n");
}

/** Inventory counts, including how many servers have no verified tool manifest. */
function mcpInventorySection(posture: NonNullable<SessionStartResult["posture"]>): string {
	const {
		mcpServers,
		riskyMcpServers,
		unverifiedMcpServers,
		invalidSources,
		mcpCoverage,
		mcpServersNotEnumerated,
		mcpSourcesNotEnumerated,
	} = posture;
	// Coverage is stated out loud: an unreadable source must never be presented
	// as a complete inventory.
	const gapParts: string[] = [];
	if ((mcpServersNotEnumerated ?? 0) > 0) {
		gapParts.push(`${mcpServersNotEnumerated} server entries were unusable`);
	}
	if ((mcpSourcesNotEnumerated ?? 0) > 0) {
		gapParts.push(`${mcpSourcesNotEnumerated} source(s) could not be read at all`);
	}
	const coverageWarning =
		mcpCoverage && mcpCoverage !== "read"
			? ` Inventory coverage is ${mcpCoverage}, not complete.`
			: "";
	const gapNote = gapParts.length > 0 ? ` ${gapParts.join("; ")}.` : "";
	return `MCP inventory: ${mcpServers} configured, ${riskyMcpServers} with risk indicators, ${invalidSources} unreadable sources, ${unverifiedMcpServers ?? 0} with unverified tool manifests.${coverageWarning}${gapNote} Configuration discovery does not verify server trust.`;
}

/** Coverage gaps are rendered, never folded into the inventory counts. */
function mcpCoverageGapSection(findings: SessionStartCoverageFinding[]): string[] {
	const MAX_COVERAGE_FINDINGS = 5;
	const lines = ["MCP tool-manifest coverage gaps:"];
	for (const finding of findings.slice(0, MAX_COVERAGE_FINDINGS)) {
		lines.push(`  - ${finding.server} (${finding.status}, ${finding.reason}): ${finding.detail}`);
	}
	const overflow = findings.length - MAX_COVERAGE_FINDINGS;
	if (overflow > 0) lines.push(`  ... and ${overflow} more coverage gaps`);
	return lines;
}

/** The plugin-scan banner of an enabled session start. */
function scanHeadline(version: string, result: SessionStartResult): string {
	if (result.scanResults.length > 0) {
		return formatThreatBanner(version, result.scanResults, result.versionCheck);
	}
	if (!result.rulesIncomplete) return formatStartupClean(version, result.versionCheck);
	// Never "No threats found" when the rule set the scan used was partial.
	const headline = `🛡️ Singularity AIDR v${version} — Review Required`;
	return result.versionCheck?.updateAvailable
		? `${headline}\n${formatUpdateNotice(result.versionCheck)}`
		: headline;
}

export function formatSessionStartMessage(version: string, result: SessionStartResult): string {
	if (result.enabled === false) {
		const reason = result.disabled_reason ?? "disabled";
		// Only claim the product is off when it actually is. The managed-only
		// reasons below leave local detection running, so the banner must say so.
		const base = isEnforcementStopped(result.disabled_reason)
			? formatStartupDisabled(version, reason)
			: formatStartupLocalOnly(version, reason);
		if (reason === "enrollment_repair_required") {
			return `${base}\nEnrollment could not be confirmed locally. An operator must settle the enrollment outcome and revoke any affected key in the control plane, then start fresh pairing and approve it in the browser. Preserve the installation ID and tenant; do not reuse the previous authorization code.`;
		}
		if (!result.bootstrap) return base;

		const lines: string[] = [base, ""];
		lines.push("To activate Singularity AIDR:");
		lines.push(kv("Open", result.bootstrap.verification_url));
		lines.push(kv("Code", result.bootstrap.user_code));
		if (result.bootstrap.expires_at) {
			lines.push(kv("Expires", result.bootstrap.expires_at));
		}
		return lines.join("\n");
	}
	const sections: string[] = [];
	const message = scanHeadline(version, result);
	if (result.rulesIncomplete) {
		sections.push(`⚠️ Threat ${result.rulesIncomplete.message}. ${result.rulesIncomplete.reason}`);
	}
	if (result.posture) {
		sections.push(mcpInventorySection(result.posture));
		sections.push(`AI infrastructure policy assessment: ${result.posture.infrastructure}.`);
	}
	const coverage = result.coverageFindings ?? [];
	if (coverage.length > 0) sections.push(...mcpCoverageGapSection(coverage));
	if (sections.length === 0) return message;
	return `${message}\n${sections.join("\n")}`;
}
