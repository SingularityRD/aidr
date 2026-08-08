import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

import {
	DEFAULT_MINIMUM_SCORE,
	SECURITY_OPERATOR_CHECKS,
	evaluateMutationReport,
	runMutationGate,
} from "./mutation-gate.mjs";

const temporaryDirectories = [];

afterEach(async () => {
	await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

test("mutation gate is seeded, deterministic, and checks security operators", async () => {
	const rootDir = await mkdtemp(path.join(os.tmpdir(), "aidr-mutation-gate-test-"));
	temporaryDirectories.push(rootDir);
	const runnerPath = path.join(rootDir, "runner.mjs");
	await writeFile(
		runnerPath,
		`import { writeFileSync } from "node:fs";
const checks = Object.fromEntries(process.env.AIDR_MUTATION_OPERATORS.split(",").map((id) => [id, { status: "passed" }]));
writeFileSync(process.env.AIDR_MUTATION_REPORT_PATH, JSON.stringify({ seed: Number(process.env.AIDR_MUTATION_SEED), score: 0.91, operator_checks: checks }));
`,
		"utf8",
	);

	const options = { rootDir, runner: [process.execPath, runnerPath], seed: 17 };
	const first = await runMutationGate(options);
	const second = await runMutationGate(options);

	assert.deepEqual(second, first);
	assert.equal(first.passed, true);
	assert.equal(first.seed, 17);
	assert.equal(first.reported_score, 0.91);
	assert.equal(first.score_source, "mutation-runner-report");
	assert.deepEqual(first.operator_checks.map(({ id }) => id), [...SECURITY_OPERATOR_CHECKS].sort());
});

test("mutation gate fails closed without a runner or a real score", async () => {
	await assert.rejects(runMutationGate({ runner: "aidr-runner-that-does-not-exist" }), /Mutation runner unavailable/);

	const result = evaluateMutationReport({ operator_checks: {} });
	assert.equal(result.passed, false);
	assert.ok(result.failures.includes("Mutation runner report has no numeric mutation score"));
	assert.equal(result.reported_score, null);
	assert.equal(result.score_source, null);
});

test("mutation threshold cannot be lowered", () => {
	assert.throws(() => evaluateMutationReport({}, { minimumScore: DEFAULT_MINIMUM_SCORE - 0.01 }), /cannot be reduced/);
});
