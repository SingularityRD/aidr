import type { AigInfraScanSummary } from "./aig-infra-scan.js";
import { resolvePath } from "./config.js";
import { getFileContent } from "./file-utils.js";
import type { Artifact, Config, Verdict } from "./types.js";

function origin(value: string): string | null {
	try {
		const url = new URL(value);
		return ["http:", "https:"].includes(url.protocol) ? url.origin : null;
	} catch {
		return null;
	}
}

/**
 * Parse a saved `aidr scan --save-report` summary. Returns null for anything
 * that is not a well-formed report (oversized, future-dated, or with a target
 * or CVE entry of the wrong shape), so a damaged file is never read as clean.
 */
export function parseInfrastructureScanReport(
	text: string,
	now = Date.now(),
): AigInfraScanSummary | null {
	if (text.length > 4 * 1024 * 1024) return null;
	let report: AigInfraScanSummary;
	try {
		report = JSON.parse(text) as AigInfraScanSummary;
	} catch {
		return null;
	}
	if (!report || typeof report !== "object") return null;
	const scanned = Date.parse(report.scannedAt);
	if (!Number.isFinite(scanned) || scanned > now + 60_000 || !Array.isArray(report.targets))
		return null;
	if (
		report.targets.some(
			(target) =>
				!target ||
				typeof target.url !== "string" ||
				!origin(target.url) ||
				typeof target.reachable !== "boolean" ||
				!Array.isArray(target.matched) ||
				target.matched.some(
					(match) => !match || typeof match.product !== "string" || !match.product.trim(),
				) ||
				!Array.isArray(target.cves) ||
				(target.error !== null && typeof target.error !== "string") ||
				target.cves.some(
					(cve) =>
						!cve ||
						typeof cve.cveId !== "string" ||
						typeof cve.severity !== "string" ||
						typeof cve.evaluated !== "boolean",
				),
		)
	) {
		return null;
	}
	return report;
}

export async function inspectInfrastructurePolicy(config: Config, now = Date.now()) {
	const policy = config.policy.ai_infrastructure;
	if (!policy?.enabled) return { state: "disabled" as const, report: null };
	try {
		const report = parseInfrastructureScanReport(
			await getFileContent(resolvePath(policy.report_path)),
			now,
		);
		if (!report) return { state: "invalid" as const, report: null };
		if (now - Date.parse(report.scannedAt) > policy.max_age_seconds * 1000)
			return { state: "expired" as const, report: null };
		return { state: "current" as const, report };
	} catch {
		return { state: "unavailable" as const, report: null };
	}
}

/** Act only on explicitly protected origins and version-confirmed critical findings. */
export async function evaluateInfrastructurePolicy(
	artifacts: Artifact[],
	config: Config,
): Promise<Verdict | null> {
	const policy = config.policy.ai_infrastructure;
	if (!policy?.enabled) return null;
	const protectedOrigins = new Set(policy.targets.map(origin).filter(Boolean));
	const urls = artifacts.filter((a) => a.type === "url" && protectedOrigins.has(origin(a.value)));
	if (!urls.length) return null;
	const { state, report } = await inspectInfrastructurePolicy(config);
	let pending: Verdict | null = null;
	for (const artifact of urls) {
		const target = report?.targets.find((t) => origin(t.url) === origin(artifact.value));
		const critical =
			target?.cves?.filter(
				(cve) => cve.evaluated === true && cve.severity?.toLowerCase() === "critical",
			) ?? [];
		const unconfirmed =
			!target ||
			target.error ||
			!target.reachable ||
			!target.matched.length ||
			!Array.isArray(target.cves) ||
			target.cves.some((cve) => !cve.evaluated && cve.severity?.toLowerCase() === "critical");
		if (!critical.length && !unconfirmed) continue;
		const action = critical.length ? policy.critical_action : policy.unverified_action;
		if (action === "allow") continue;
		const verdict: Verdict = {
			decision: action === "block" ? "deny" : "ask",
			category: "vulnerable_ai_infrastructure",
			confidence: critical.length ? 1 : 0,
			severity: critical.length ? "critical" : "warning",
			source: "aig_infrastructure_policy",
			artifacts: [artifact.value],
			matchedThreatId: "AIG-INFRA-POLICY",
			reasons: critical.length
				? [
						`Version-confirmed critical AI infrastructure vulnerabilities: ${critical.map((cve) => cve.cveId).join(", ")}`,
					]
				: [
						`AI infrastructure assessment is ${state === "current" ? "incomplete or applicability is unconfirmed" : state}; operator review required`,
					],
		};
		if (verdict.decision === "deny") return verdict;
		pending = verdict;
	}
	return pending;
}
