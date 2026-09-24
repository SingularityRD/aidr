import assert from "node:assert/strict";
import test from "node:test";
import { assessBuildAudit } from "./audit-build-deps.mjs";

const allowed = {
	id: 1120680,
	module_name: "esbuild",
	severity: "low",
	findings: [{ version: "0.27.7", paths: [".>vitest>vite>esbuild"] }],
};

test("accepts the exact non-listening Vitest development-server advisory", () => {
	assert.deepEqual(assessBuildAudit({ advisories: { 1120680: allowed } }), {
		allowed: ["1120680"],
		failures: [],
	});
});

test("fails closed when the allowed advisory changes scope", () => {
	const changed = structuredClone(allowed);
	changed.findings[0].paths = ["packages__dashboard>vite>esbuild"];
	assert.deepEqual(assessBuildAudit({ advisories: { 1120680: changed } }), {
		allowed: [],
		failures: ["1120680 esbuild (low)"],
	});
});

test("rejects every other advisory and invalid reports", () => {
	const other = { id: 99, module_name: "rollup", severity: "high", findings: [] };
	assert.deepEqual(assessBuildAudit({ advisories: { 99: other } }).failures, [
		"99 rollup (high)",
	]);
	assert.equal(assessBuildAudit({ error: "registry unavailable" }).failures.length, 1);
});
