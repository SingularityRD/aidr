import assert from "node:assert/strict";
import test from "node:test";
import { assessProductionAuditReport } from "./audit-production-deps-report.mjs";

const cleanReport = {
	advisories: {},
	metadata: {
		dependencies: 185,
		vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
	},
};

test("accepts a complete clean pnpm audit report", () => {
	assert.deepEqual(assessProductionAuditReport(cleanReport), { advisories: [], failures: [] });
});

test("rejects a JSON error response that looks like an empty audit", () => {
	const result = assessProductionAuditReport({
		...cleanReport,
		error: { code: "ERR_PNPM_AUDIT_ENDPOINT", status: 503 },
	});
	assert.equal(result.advisories.length, 0);
	assert.match(result.failures.join(" "), /returned an error/);
});

test("rejects incomplete reports and nonzero exits without advisories", () => {
	assert.match(assessProductionAuditReport({ advisories: {} }).failures.join(" "), /vulnerability counts/);
	assert.match(assessProductionAuditReport(cleanReport, { status: 1 }).failures.join(" "), /without reporting any advisories/);
});

test("rejects spawn failures, signals, and unexpected exit statuses", () => {
	assert.match(assessProductionAuditReport(cleanReport, { error: new Error("registry offline") }).failures.join(" "), /failed to start/);
	assert.match(assessProductionAuditReport(cleanReport, { signal: "SIGTERM", status: null }).failures.join(" "), /terminated/);
	assert.match(assessProductionAuditReport(cleanReport, { status: 2 }).failures.join(" "), /unexpected status/);
});

test("retains advisory reports from pnpm's vulnerability exit status for policy evaluation", () => {
	const advisory = { id: 1124282, module_name: "react-router", severity: "high", findings: [] };
	const report = {
		advisories: { 1124282: advisory },
		metadata: {
			dependencies: 185,
			vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
		},
	};
	assert.deepEqual(assessProductionAuditReport(report, { status: 1 }), {
		advisories: [advisory],
		failures: [],
	});
});
