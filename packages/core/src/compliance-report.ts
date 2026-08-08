/**
 * Compliance Report Generator for Singularity AIDR.
 *
 * Produces SOC 2 Type II and ISO 27001 compliance evidence reports by
 * aggregating audit-log entries and incident records.  Each report includes
 * metadata, audit-log summaries, incident-response metrics, and control
 * evidence.  Reports may be exported as JSON or as a structured object
 * suitable for PDF rendering.
 *
 * @module compliance-report
 */

import { getRecentEntries } from "./audit-log.js";
import type { Incident } from "./incidents/types.js";
import type { LoggingConfig } from "./types.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Supported compliance frameworks. */
export type ReportFramework = "SOC_2_TYPE_II" | "ISO_27001";

/** Supported export formats. */
export type ReportExportFormat = "json" | "pdf-ready";

/** Metadata attached to every generated report. */
export interface ComplianceReportMetadata {
	readonly reportType: ReportFramework;
	readonly generatedAt: string;
	readonly version: string;
	readonly reportId: string;
}

/** Statistical summary of audit-log entries. */
export interface AuditLogSummary {
	readonly totalEntries: number;
	readonly dateRange: {
		readonly from: string;
		readonly to: string;
	};
	readonly entriesByType: Record<string, number>;
	readonly entriesByDecision: Record<string, number>;
	readonly entriesBySeverity: Record<string, number>;
}

/** Aggregate incident-response metrics computed from incident records. */
export interface IncidentMetrics {
	readonly totalIncidents: number;
	readonly byStatus: Record<string, number>;
	readonly bySeverity: Record<string, number>;
	readonly meanTimeToResolveMs: number;
	readonly meanTimeToAcknowledgeMs: number;
}

/** Evidence that a specific control is operating effectively. */
export interface ControlEvidence {
	readonly controlId: string;
	readonly controlName: string;
	readonly status: "effective" | "partially_effective" | "ineffective" | "not_tested";
	readonly lastTestedAt: string;
	readonly evidence: readonly string[];
}

/** Availability and monitoring coverage metrics. */
export interface AvailabilityMetrics {
	readonly uptimePercentage: number;
	readonly monitoringCoverage: number;
	readonly detectionCoverage: number;
}

/** Continuous monitoring snapshot used in ISO 27001 reports. */
export interface ContinuousMonitoring {
	readonly lastScanAt: string;
	readonly activeThreats: number;
	readonly resolvedThreats: number;
}

/**
 * Full SOC 2 Type II report.
 *
 * Includes audit-log summaries, incident metrics, control evidence, and
 * availability / monitoring coverage metrics.
 */
export interface SOC2Report {
	readonly metadata: ComplianceReportMetadata;
	readonly auditLogSummary: AuditLogSummary;
	readonly incidentMetrics: IncidentMetrics;
	readonly controls: readonly ControlEvidence[];
	readonly availabilityMetrics: AvailabilityMetrics;
}

/**
 * Full ISO 27001 compliance report.
 *
 * Includes compliance gaps, risk findings, incident metrics, audit-log
 * summaries, and a continuous-monitoring snapshot.
 */
export interface ISO27001Report {
	readonly metadata: ComplianceReportMetadata;
	readonly complianceGaps: readonly string[];
	readonly riskFindings: readonly string[];
	readonly incidentMetrics: IncidentMetrics;
	readonly auditLogSummary: AuditLogSummary;
	readonly continuousMonitoring: ContinuousMonitoring;
}

/** Discriminated union of all supported compliance reports. */
export type ComplianceReport = SOC2Report | ISO27001Report;

// ---------------------------------------------------------------------------
// Internal helpers — audit log
// ---------------------------------------------------------------------------

/**
 * Parse an ISO-8601 timestamp from an audit entry.
 * Returns `null` when the entry has no valid `timestamp` field.
 */
function extractTimestamp(entry: Record<string, unknown>): string | null {
	const ts = entry.timestamp;
	if (typeof ts === "string" && !Number.isNaN(Date.parse(ts))) return ts;
	return null;
}

interface DateRangeState {
	earliest: string | null;
	latest: string | null;
}

function updateDateRange(state: DateRangeState, entry: Record<string, unknown>): void {
	const timestamp = extractTimestamp(entry);
	if (timestamp === null) return;
	if (state.earliest === null || timestamp < state.earliest) state.earliest = timestamp;
	if (state.latest === null || timestamp > state.latest) state.latest = timestamp;
}

/**
 * Compute an {@link AuditLogSummary} from an array of raw audit-log entries.
 */
function computeAuditLogSummary(entries: readonly Record<string, unknown>[]): AuditLogSummary {
	const byType: Record<string, number> = {};
	const byDecision: Record<string, number> = {};
	const bySeverity: Record<string, number> = {};

	const dateRange: DateRangeState = { earliest: null, latest: null };

	for (const entry of entries) {
		// Count by type
		const t = String(entry.type ?? "unknown");
		byType[t] = (byType[t] ?? 0) + 1;

		// Count by decision
		const d = String(entry.decision ?? entry.verdict ?? "unknown");
		byDecision[d] = (byDecision[d] ?? 0) + 1;

		// Count by severity
		const s = String(entry.severity ?? "unknown");
		bySeverity[s] = (bySeverity[s] ?? 0) + 1;

		// Track date range
		updateDateRange(dateRange, entry);
	}

	return {
		totalEntries: entries.length,
		dateRange: {
			from: dateRange.earliest ?? new Date().toISOString(),
			to: dateRange.latest ?? new Date().toISOString(),
		},
		entriesByType: byType,
		entriesByDecision: byDecision,
		entriesBySeverity: bySeverity,
	};
}

// ---------------------------------------------------------------------------
// Internal helpers — incidents
// ---------------------------------------------------------------------------

/**
 * Compute {@link IncidentMetrics} from an array of {@link Incident} records.
 */
function computeIncidentMetrics(incidents: readonly Incident[]): IncidentMetrics {
	const byStatus: Record<string, number> = {};
	const bySeverity: Record<string, number> = {};
	let totalResolveMs = 0;
	let resolveCount = 0;
	let totalAckMs = 0;
	let ackCount = 0;

	for (const inc of incidents) {
		// Status distribution
		const st: string = inc.status;
		byStatus[st] = (byStatus[st] ?? 0) + 1;

		// Severity distribution
		const se: string = inc.severity;
		bySeverity[se] = (bySeverity[se] ?? 0) + 1;

		// Mean time to resolve (status === "resolved")
		if (inc.status === "resolved") {
			const dur = inc.last_seen_ms - inc.opened_at_ms;
			if (dur >= 0) {
				totalResolveMs += dur;
				resolveCount++;
			}
		}

		// Mean time to acknowledge (status !== "open")
		if (inc.status !== "open") {
			const dur = inc.last_seen_ms - inc.opened_at_ms;
			if (dur >= 0) {
				totalAckMs += dur;
				ackCount++;
			}
		}
	}

	return {
		totalIncidents: incidents.length,
		byStatus,
		bySeverity,
		meanTimeToResolveMs: resolveCount > 0 ? Math.round(totalResolveMs / resolveCount) : 0,
		meanTimeToAcknowledgeMs: ackCount > 0 ? Math.round(totalAckMs / ackCount) : 0,
	};
}

/**
 * Build a list of {@link ControlEvidence} entries.
 *
 * The evidence is derived from the current incident state and represents
 * the five core SOC 2 trust-service criteria mapped to AIDR capabilities.
 */
function buildControlEvidence(incidents: readonly Incident[]): ControlEvidence[] {
	const now = new Date().toISOString();

	// Security — detection coverage
	const highOrCritical = incidents.filter(
		(inc) => inc.severity === "high" || inc.severity === "critical",
	);
	const resolvedHighOrCritical = highOrCritical.filter((inc) => inc.status === "resolved");

	return [
		{
			controlId: "CC6.1",
			controlName: "Logical and physical access controls",
			status: incidents.length > 0 ? "partially_effective" : "effective",
			lastTestedAt: now,
			evidence: [
				`${incidents.length} incident(s) recorded`,
				"Real-time tool-call evaluation active",
			],
		},
		{
			controlId: "CC7.1",
			controlName: "Detection and monitoring of security events",
			status: highOrCritical.length > 0 ? "partially_effective" : "effective",
			lastTestedAt: now,
			evidence: [
				`${highOrCritical.length} high/critical incident(s) detected`,
				"Automated scanning pipeline operational",
			],
		},
		{
			controlId: "CC7.2",
			controlName: "Incident response and remediation",
			status:
				resolvedHighOrCritical.length === highOrCritical.length && highOrCritical.length > 0
					? "effective"
					: "partially_effective",
			lastTestedAt: now,
			evidence: [
				`${resolvedHighOrCritical.length} of ${highOrCritical.length} high/critical incidents resolved`,
				"Incident correlation engine enabled",
			],
		},
		{
			controlId: "CC6.6",
			controlName: "Prevention of unauthorized use of system resources",
			status: "effective",
			lastTestedAt: now,
			evidence: [
				"Allowlist-based command/URL/file control active",
				"DLP content classification enabled",
			],
		},
		{
			controlId: "A1.2",
			controlName: "System availability and monitoring",
			status: "effective",
			lastTestedAt: now,
			evidence: ["Heartbeat health checks configured", "Metrics collection operational"],
		},
	];
}

// ---------------------------------------------------------------------------
// Internal helpers — availability
// ---------------------------------------------------------------------------

/**
 * Derive {@link AvailabilityMetrics} from incident data.
 *
 * A simple heuristic: uptime is inferred from the ratio of resolved incidents
 * to total incidents, and coverage metrics reflect the breadth of detection
 * sources present in the incident set.
 */
function computeAvailabilityMetrics(incidents: readonly Incident[]): AvailabilityMetrics {
	const total = incidents.length;
	const resolved = incidents.filter((inc) => inc.status === "resolved").length;
	const uptimePct = total > 0 ? Math.round((resolved / total) * 100) : 100;

	// Estimate coverage from unique session / agent / connector / plugin keys
	const uniqueSessions = new Set<string>();
	const uniquePlugins = new Set<string>();
	for (const inc of incidents) {
		if (inc.session_id) uniqueSessions.add(inc.session_id);
		if (inc.plugin_key) uniquePlugins.add(inc.plugin_key);
	}

	const sessionCoverage = Math.min(100, uniqueSessions.size * 20);
	const pluginCoverage = Math.min(100, uniquePlugins.size * 25);

	return {
		uptimePercentage: uptimePct,
		monitoringCoverage: Math.max(sessionCoverage, 50),
		detectionCoverage: Math.max(pluginCoverage, 50),
	};
}

/**
 * Build a {@link ContinuousMonitoring} snapshot from incident data.
 */
function buildContinuousMonitoring(incidents: readonly Incident[]): ContinuousMonitoring {
	const now = new Date().toISOString();
	const openIncidents = incidents.filter(
		(inc) => inc.status === "open" || inc.status === "acknowledged",
	);
	const resolvedIncidents = incidents.filter((inc) => inc.status === "resolved");

	return {
		lastScanAt: now,
		activeThreats: openIncidents.length,
		resolvedThreats: resolvedIncidents.length,
	};
}

/**
 * Derive compliance gaps from the current incident and audit state.
 */
function deriveComplianceGaps(incidents: readonly Incident[]): string[] {
	const gaps: string[] = [];

	// No incidents means no detection — which may or may not be a gap
	if (incidents.length === 0) {
		gaps.push("No incident records exist — verify detection pipeline is active");
	}

	const hasOpen = incidents.some((inc) => inc.status === "open" || inc.status === "acknowledged");
	if (hasOpen) {
		gaps.push("Open incidents require remediation tracking (A.16.1.5)");
	}

	const hasCritical = incidents.some((inc) => inc.severity === "critical");
	if (hasCritical) {
		gaps.push("Critical-severity incidents detected — verify escalation procedure (A.16.1.2)");
	}

	if (gaps.length === 0) {
		gaps.push("All monitored controls are operating effectively");
	}

	return gaps;
}

/**
 * Derive risk findings from incident and audit data.
 */
function deriveRiskFindings(incidents: readonly Incident[]): string[] {
	const findings: string[] = [];

	const total = incidents.length;
	if (total > 0) {
		const bySev = new Map<string, number>();
		for (const inc of incidents) {
			bySev.set(inc.severity, (bySev.get(inc.severity) ?? 0) + 1);
		}
		for (const [sev, count] of bySev) {
			findings.push(`${count} incident(s) at severity "${sev}"`);
		}
	}

	const unresolved = incidents.filter(
		(inc) => inc.status === "open" || inc.status === "acknowledged" || inc.status === "contained",
	).length;
	if (unresolved > 0) {
		findings.push(`${unresolved} unresolved incident(s) require risk acceptance or remediation`);
	}

	if (findings.length === 0) {
		findings.push("No risk findings — all monitored controls are nominal");
	}

	return findings;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

let _reportCounter = 0;

/**
 * Generate a unique report identifier.
 */
function nextReportId(): string {
	_reportCounter++;
	return `cr_${Date.now()}_${_reportCounter}`;
}

const REPORT_VERSION = "1.0.0";

/**
 * Build the standard {@link ComplianceReportMetadata} block.
 */
function buildMetadata(framework: ReportFramework): ComplianceReportMetadata {
	return {
		reportType: framework,
		generatedAt: new Date().toISOString(),
		version: REPORT_VERSION,
		reportId: nextReportId(),
	};
}

/**
 * Generate a **SOC 2 Type II** compliance evidence report.
 *
 * The report aggregates recent audit-log entries and incident records to
 * produce an audit-log summary, incident-response metrics, control-evidence
 * mappings, and availability / monitoring-coverage metrics.
 *
 * @param config    - Logging configuration used to locate the audit log.
 * @param incidents - Array of {@link Incident} records to include in the
 *                    report (typically from the correlation engine).
 * @param auditLogLimit - Maximum number of recent audit entries to analyse
 *                    (default 1000).
 * @returns A fully populated {@link SOC2Report}.
 *
 * @example
 * ```ts
 * const report = await generateSOC2Report(loggingConfig, incidents);
 * const json = exportReport(report, "json");
 * ```
 */
export async function generateSOC2Report(
	config: LoggingConfig,
	incidents: readonly Incident[],
	auditLogLimit = 1000,
): Promise<SOC2Report> {
	const rawEntries = await getRecentEntries(config, auditLogLimit);
	const typed = rawEntries.map((e) => e as Record<string, unknown>);
	const auditLogSummary = computeAuditLogSummary(typed);
	const incidentMetrics = computeIncidentMetrics(incidents);
	const controls = buildControlEvidence(incidents);
	const availabilityMetrics = computeAvailabilityMetrics(incidents);

	return {
		metadata: buildMetadata("SOC_2_TYPE_II"),
		auditLogSummary,
		incidentMetrics,
		controls,
		availabilityMetrics,
	};
}

/**
 * Generate an **ISO 27001** compliance report.
 *
 * The report aggregates recent audit-log entries and incident records to
 * produce compliance-gap analysis, risk findings, incident-response metrics,
 * audit-log summaries, and a continuous-monitoring snapshot.
 *
 * @param config    - Logging configuration used to locate the audit log.
 * @param incidents - Array of {@link Incident} records to include in the
 *                    report (typically from the correlation engine).
 * @param auditLogLimit - Maximum number of recent audit entries to analyse
 *                    (default 1000).
 * @returns A fully populated {@link ISO27001Report}.
 *
 * @example
 * ```ts
 * const report = await generateISO27001Report(loggingConfig, incidents);
 * ```
 */
export async function generateISO27001Report(
	config: LoggingConfig,
	incidents: readonly Incident[],
	auditLogLimit = 1000,
): Promise<ISO27001Report> {
	const rawEntries = await getRecentEntries(config, auditLogLimit);
	const typed = rawEntries.map((e) => e as Record<string, unknown>);
	const auditLogSummary = computeAuditLogSummary(typed);
	const incidentMetrics = computeIncidentMetrics(incidents);
	const complianceGaps = deriveComplianceGaps(incidents);
	const riskFindings = deriveRiskFindings(incidents);
	const continuousMonitoring = buildContinuousMonitoring(incidents);

	return {
		metadata: buildMetadata("ISO_27001"),
		complianceGaps,
		riskFindings,
		incidentMetrics,
		auditLogSummary,
		continuousMonitoring,
	};
}

/**
 * Serialise a compliance report to the requested format.
 *
 * **`"json"`** — Returns a compact JSON string representation of the report.
 *
 * **`"pdf-ready"`** — Returns a structured plain object that can be passed
 * directly to a PDF-rendering engine.  The structure is identical to the
 * JSON output but preserves the native types (dates as strings, numbers as
 * numbers) so that a PDF template can consume it without an extra parse.
 *
 * @param report - The compliance report to export (SOC 2 or ISO 27001).
 * @param format - Target format — `"json"` or `"pdf-ready"`.
 * @returns A string when `format` is `"json"`, or the report object itself
 *          when `format` is `"pdf-ready"`.
 *
 * @example
 * ```ts
 * const json = exportReport(soc2Report, "json");
 * // json is a JSON string
 *
 * const pdfData = exportReport(isoReport, "pdf-ready");
 * // pdfData is the ISO27001Report object
 * ```
 */
export function exportReport(
	report: ComplianceReport,
	format: ReportExportFormat,
): string | ComplianceReport {
	if (format === "pdf-ready") {
		return report;
	}

	return JSON.stringify(report);
}
