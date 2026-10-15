import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { budgetViolations, percentile, summarize } from "./hook-latency.mjs";

const here = dirname(fileURLToPath(import.meta.url));

test("percentile uses the nearest rank", () => {
	const sorted = Array.from({ length: 20 }, (_, i) => i + 1);
	assert.equal(percentile(sorted, 50), 10);
	assert.equal(percentile(sorted, 95), 19);
	assert.equal(percentile(sorted, 100), 20);
	assert.equal(percentile([], 50), null);
});

test("summarize reports rounded order statistics", () => {
	assert.deepEqual(summarize([3.4, 1.2, 2.6]), { n: 3, p50: 3, p95: 3, p99: 3, max: 3, mean: 2 });
});

test("budget violations name the scenario, its p95 and its errors", () => {
	const budget = JSON.parse(readFileSync(join(here, "hook-latency-budget.json"), "utf8"));
	assert.equal(budget.format, "aidr-hook-latency-budget-v1");
	assert.ok(budget.ci_p95_ms >= budget.p95_ms.warm_benign);
	const scenarios = [
		{ scenario: "warm_benign", p95: budget.p95_ms.warm_benign + 1, errors: 0 },
		{ scenario: "cold_benign", p95: 1, errors: 2 },
		{ scenario: "warm_blocked", p95: 1, errors: 0 },
	];
	const violations = budgetViolations(scenarios, budget);
	assert.equal(violations.length, 2);
	assert.match(violations[0], /^warm_benign: p95 \d+ ms > budget \d+ ms$/);
	assert.match(violations[1], /^cold_benign: 2 error\(s\)$/);
});
