/**
 * Shared visual formatting for Singularity AIDR alerts.
 * Plain text + Unicode only — no ANSI escape codes.
 */

import { displayReason } from "./i18n/display.js";
import { severityLabel, t, upperCaseFor } from "./i18n/index.js";
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
	const key =
		result.action === "installing"
			? "session.updateInstalling"
			: result.action === "aidr_update"
				? "session.updateAvailableInstaller"
				: "session.updateAvailable";
	return t(key, {
		current: result.currentVersion,
		latest: result.latestVersion,
	});
}

function formatRemotePolicyLine(cache?: RemotePolicyCacheInfo | null): string {
	if (!cache?.enabled || !cache?.present) return "";
	const policy = cache.policyVersion ?? t("session.policy.defaultName");
	if (cache.source === "valid" && cache.ttlSeconds != null) {
		return t("session.policy.cached", { policy, seconds: cache.ttlSeconds });
	}
	if (cache.source === "expired") {
		return cache.ageSeconds != null
			? t("session.policy.expiredAge", { policy, seconds: cache.ageSeconds })
			: t("session.policy.expired", { policy });
	}
	if (cache.source === "invalid") {
		return t("session.policy.invalid");
	}
	return "";
}

export function formatStartupClean(
	version: string,
	versionCheck?: VersionCheckResult | null,
	remotePolicyCache?: RemotePolicyCacheInfo | null,
): string {
	let base = t("session.clean", { version });
	const policyLine = formatRemotePolicyLine(remotePolicyCache);
	if (policyLine) {
		base = `${base}\n${kv(t("session.label.policy"), policyLine)}`;
	}
	if (versionCheck?.updateAvailable) {
		return `${base}\n${formatUpdateNotice(versionCheck)}`;
	}
	return base;
}

export function formatStartupDisabled(version: string, reason: string): string {
	return t("session.disabled", { version, reason });
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
	return t("session.localOnly", { version, reason });
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
			`⚠️ ${t("session.label.plugin").padEnd(PAD)}${pluginKey}`,
			t("session.rulesIncompleteBanner", { count: check.uncheckedCount }),
			kv(t("session.label.reason"), check.reason),
		];
	}
	const label =
		check.check === "url_reputation"
			? t("session.check.urlReputation")
			: check.check === "file_reputation"
				? t("session.check.fileReputation")
				: t("session.check.pluginFiles");
	return [
		check.check === "plugin_files"
			? t("session.check.incompletePaths", { label, count: check.uncheckedCount })
			: t("session.check.unverifiedItems", { label, count: check.uncheckedCount }),
		kv(t("session.label.reason"), check.reason),
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
	const headerLabel =
		!hasHighOrCriticalFinding && hasUnavailableChecks
			? t("session.header.reviewRequired")
			: t("session.header.threatDetected");
	const header = t("session.header", { version, label: headerLabel });
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
			lines.push(`${emoji} ${t("session.label.plugin").padEnd(PAD)}${result.plugin.key}`);
			lines.push(kv(t("session.label.threat"), displayReason(f.title)));
			lines.push(kv(t("session.label.severity"), upperCaseFor(severityLabel(f.severity))));
			if (f.artifact) {
				lines.push(kv(t("session.label.artifact"), f.artifact));
			}
			lines.push(kv(t("session.label.source"), f.sourceFile));
			const actionLabel =
				f.action === "block" ? t("session.finding.block") : t("session.finding.review");
			lines.push(kv(t("session.label.finding"), actionLabel));
		}

		const overflow = highCrit.length - MAX_FINDINGS;
		if (overflow > 0) {
			lines.push("");
			lines.push(t("session.moreFindings", { count: overflow }));
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
		lines.push(kv(t("session.label.policy"), policyLine));
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
		gapParts.push(t("session.mcp.unusableServers", { count: mcpServersNotEnumerated }));
	}
	if ((mcpSourcesNotEnumerated ?? 0) > 0) {
		gapParts.push(t("session.mcp.unreadableSources", { count: mcpSourcesNotEnumerated }));
	}
	const coverageWarning =
		mcpCoverage && mcpCoverage !== "read"
			? t("session.mcp.coverageWarning", { coverage: mcpCoverage })
			: "";
	const gapNote = gapParts.length > 0 ? ` ${gapParts.join("; ")}.` : "";
	return t("session.mcp.inventory", {
		servers: mcpServers,
		risky: riskyMcpServers,
		invalid: invalidSources,
		unverified: unverifiedMcpServers ?? 0,
		coverageWarning,
		gapNote,
	});
}

/** Coverage gaps are rendered, never folded into the inventory counts. */
function mcpCoverageGapSection(findings: SessionStartCoverageFinding[]): string[] {
	const MAX_COVERAGE_FINDINGS = 5;
	const lines = [t("session.mcp.coverageGaps")];
	for (const finding of findings.slice(0, MAX_COVERAGE_FINDINGS)) {
		lines.push(`  - ${finding.server} (${finding.status}, ${finding.reason}): ${finding.detail}`);
	}
	const overflow = findings.length - MAX_COVERAGE_FINDINGS;
	if (overflow > 0) lines.push(t("session.mcp.moreGaps", { count: overflow }));
	return lines;
}

/** The plugin-scan banner of an enabled session start. */
function scanHeadline(version: string, result: SessionStartResult): string {
	if (result.scanResults.length > 0) {
		return formatThreatBanner(version, result.scanResults, result.versionCheck);
	}
	if (!result.rulesIncomplete) return formatStartupClean(version, result.versionCheck);
	// Never "No threats found" when the rule set the scan used was partial.
	const headline = t("session.header", { version, label: t("session.header.reviewRequired") });
	return result.versionCheck?.updateAvailable
		? `${headline}\n${formatUpdateNotice(result.versionCheck)}`
		: headline;
}

/** `YYYY-MM-DD HH:MM` in the computer's local time zone. */
function localMinute(date: Date): string {
	const pad = (value: number) => String(value).padStart(2, "0");
	return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** What an unreachable control plane means for this session, per the install-time offline choice. */
export function formatOfflineNotice(
	notice: NonNullable<SessionStartResult["offline"]>,
	now = Date.now(),
): string {
	const blocksAt = notice.blocksAt ? Date.parse(notice.blocksAt) : Number.NaN;
	const line =
		notice.policy === "keep_enforcing_local"
			? t("session.offline.keepLocal")
			: Number.isFinite(blocksAt) && blocksAt > now
				? t("session.offline.blockAt", {
						time: localMinute(new Date(blocksAt)),
						minutes: Math.max(1, Math.ceil((blocksAt - now) / 60_000)),
					})
				: t("session.offline.blocked");
	return notice.supportContact
		? `${line}\n${t("session.offline.support", { contact: notice.supportContact })}`
		: line;
}

export function formatSessionStartMessage(version: string, result: SessionStartResult): string {
	const extra: string[] = [];
	if (result.unprotectedTools && result.unprotectedTools.length > 0) {
		extra.push(
			t("session.unprotectedTools", {
				tools: result.unprotectedTools.map((tool) => tool.label).join(", "),
			}),
		);
	}
	if (result.privacyNotice) extra.push(result.privacyNotice);
	const base = formatSessionStartBody(version, result);
	return extra.length > 0 ? `${base}\n${extra.join("\n")}` : base;
}

function formatSessionStartBody(version: string, result: SessionStartResult): string {
	if (result.enabled === false) {
		const reason = result.disabled_reason ?? "disabled";
		// Only claim the product is off when it actually is. The managed-only
		// reasons below leave local detection running, so the banner must say so.
		const base = isEnforcementStopped(result.disabled_reason)
			? formatStartupDisabled(version, reason)
			: formatStartupLocalOnly(version, reason);
		if (reason === "enrollment_repair_required") {
			return `${base}\n${t("session.enrollmentRepair")}`;
		}
		if (!result.bootstrap) return base;

		const lines: string[] = [base, ""];
		lines.push(t("session.activate"));
		lines.push(kv(t("session.label.open"), result.bootstrap.verification_url));
		lines.push(kv(t("session.label.code"), result.bootstrap.user_code));
		if (result.bootstrap.expires_at) {
			lines.push(kv(t("session.label.expires"), result.bootstrap.expires_at));
		}
		return lines.join("\n");
	}
	const sections: string[] = [];
	const message = scanHeadline(version, result);
	if (result.rulesIncomplete) {
		sections.push(
			t("session.rulesIncomplete", {
				message: result.rulesIncomplete.message,
				reason: result.rulesIncomplete.reason,
			}),
		);
	}
	if (result.posture) {
		sections.push(mcpInventorySection(result.posture));
		sections.push(t("session.infrastructure", { assessment: result.posture.infrastructure }));
	}
	const coverage = result.coverageFindings ?? [];
	if (coverage.length > 0) sections.push(...mcpCoverageGapSection(coverage));
	if (result.offline) sections.push(formatOfflineNotice(result.offline));
	if (sections.length === 0) return message;
	return `${message}\n${sections.join("\n")}`;
}
