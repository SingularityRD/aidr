import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const manifest = JSON.parse(readFileSync(new URL("./e2e-release-manifest.json", import.meta.url), "utf8"));
const status = readFileSync(new URL("../docs/evidence/gate19-release-e2e-status.md", import.meta.url), "utf8");

test("release E2E pins the full bridge and control-plane assertion counts", () => {
	const bridge = manifest.suites.find((suite) => suite.id === "aig-bridge-contract");
	const controlPlane = manifest.suites.find((suite) => suite.id === "supabase-control-plane");
	assert.equal(bridge.expectedTests, 67);
	assert.ok(bridge.requiredEnv.includes("AIG_BRIDGE_TEST_POSTGRES_DSN"));
	assert.equal(controlPlane.expectedTests, 19);
});

test("Gate 19 status lists every current suite and exact assertion count", () => {
	assert.match(status, new RegExp(`${manifest.suites.length} suites and ${manifest.suites.reduce((total, suite) => total + suite.expectedTests, 0)} exact\\s+assertions`));
	for (const suite of manifest.suites) assert.ok(status.includes(`| \`${suite.id}\` | ${suite.expectedTests} |`), suite.id);
});
