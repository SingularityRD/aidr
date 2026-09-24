const VULNERABILITY_LEVELS = ["info", "low", "moderate", "high", "critical"];

export function assessProductionAuditReport(report, { status = 0, error = null, signal = null } = {}) {
	const failures = [];
	if (error) failures.push(`pnpm audit failed to start: ${error.message ?? String(error)}`);
	if (signal) failures.push(`pnpm audit was terminated by ${signal}`);
	if (status == null) failures.push("pnpm audit exited without a status");
	else if (status !== 0 && status !== 1) failures.push(`pnpm audit exited with unexpected status ${status}`);
	if (!report || typeof report !== "object" || Array.isArray(report)) {
		failures.push("invalid pnpm audit report");
		return { advisories: [], failures };
	}
	if (report.error != null) failures.push(`pnpm audit returned an error: ${JSON.stringify(report.error)}`);
	if (!report.advisories || typeof report.advisories !== "object" || Array.isArray(report.advisories)) {
		failures.push("pnpm audit report is missing its advisories object");
	}
	const vulnerabilities = report.metadata?.vulnerabilities;
	if (
		!vulnerabilities ||
		typeof vulnerabilities !== "object" ||
		VULNERABILITY_LEVELS.some((level) => !Number.isSafeInteger(vulnerabilities[level]) || vulnerabilities[level] < 0)
	) {
		failures.push("pnpm audit report is missing valid vulnerability counts");
	}
	if (!Number.isSafeInteger(report.metadata?.dependencies) || report.metadata.dependencies < 1) {
		failures.push("pnpm audit report is missing a nonempty dependency count");
	}
	const advisories = Object.values(report.advisories ?? {});
	if (status === 1 && advisories.length === 0) {
		failures.push("pnpm audit exited nonzero without reporting any advisories");
	}
	return { advisories, failures };
}
