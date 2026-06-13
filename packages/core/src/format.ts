/**
 * Shared visual formatting for Singularity AIDR alerts.
 * Plain text + Unicode only — no ANSI escape codes.
 */

import type { SessionStartResult } from "./session-start.js";
import type { PluginScanResult } from "./types.js";
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

export function formatThreatBanner(
	version: string,
	results: PluginScanResult[],
	versionCheck?: VersionCheckResult | null,
	remotePolicyCache?: RemotePolicyCacheInfo | null,
): string {
	const header = `🛡️ Singularity AIDR v${version} — Threat Detected`;
	const lines: string[] = [" ", header, separatorLine(SEPARATOR_WIDTH)];

	const MAX_FINDINGS = 5;
	let first = true;

	for (const result of results) {
		const highCrit = result.findings.filter(
			(f) => f.severity === "critical" || f.severity === "high",
		);
		if (highCrit.length === 0) continue;

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
			const actionLabel = f.action === "block" ? "Blocked" : "Flagged";
			lines.push(kv("Action", actionLabel));
		}

		const overflow = highCrit.length - MAX_FINDINGS;
		if (overflow > 0) {
			lines.push("");
			lines.push(`   ... and ${overflow} more findings`);
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

export function formatSessionStartMessage(version: string, result: SessionStartResult): string {
	if (result.enabled === false) {
		const base = formatStartupDisabled(version, result.disabled_reason ?? "disabled");
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
	if (result.scanResults.length > 0) {
		return formatThreatBanner(version, result.scanResults, result.versionCheck);
	}
	return formatStartupClean(version, result.versionCheck);
}
