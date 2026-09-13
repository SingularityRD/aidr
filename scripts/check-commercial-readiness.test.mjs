import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { validateCommercialReadiness } from "./check-commercial-readiness.mjs";

const [inventory, gaps, registry, releaseSource] = await Promise.all([
	readFile("FEATURE_INVENTORY.json", "utf8").then(JSON.parse),
	readFile("PRODUCTION_SALES_GAPS.json", "utf8").then(JSON.parse),
	readFile("docs/production-readiness/commercial-go-evidence-registry.json", "utf8").then(JSON.parse),
	readFile("scripts/release-artifact-manifests.mjs", "utf8"),
]);
const fixture = () => ({ inventory: structuredClone(inventory), gaps: structuredClone(gaps), registry: structuredClone(registry), releaseSource, now: new Date("2026-09-13T12:00:00Z") });

test("current commercial inventory matches the release scope", () => {
	assert.deepEqual(validateCommercialReadiness(fixture()), []);
});

test("omitting a release artifact fails the commercial check", () => {
	const input = fixture();
	input.registry.artifactRoots = input.registry.artifactRoots.filter((root) => root !== "packages/codex/dist");
	assert.match(validateCommercialReadiness(input).join("\n"), /missing release artifact root packages\/codex\/dist/);
});

test("adding a release target without registry coverage fails", () => {
	const input = fixture();
	input.releaseSource = input.releaseSource.replace(
		/const targets = \[/,
		'const targets = [\n\t{ pkg: "packages/new-connector/package.json", dir: "packages/new-connector/dist", artifactId: "new-connector/dist" },',
	);
	assert.match(validateCommercialReadiness(input).join("\n"), /missing release artifact root packages\/new-connector\/dist/);
});

test("feature and work-package counts cannot drift from their inventories", () => {
	const input = fixture();
	input.gaps.feature_status_counts.wired += 1;
	input.gaps.work_package_count -= 1;
	const failures = validateCommercialReadiness(input).join("\n");
	assert.match(failures, /gaps\.feature_status_counts\.wired/);
	assert.match(failures, /work package count differs/);
});

test("an expired Sales Approved claim is rejected", () => {
	const input = fixture();
	input.registry.releaseCandidate = "rc-test";
	Object.assign(input.registry.claims[0], {
		status: "closed",
		maturity: "approved",
		salesApproved: true,
		releaseCandidate: "rc-test",
		expiresAt: "2026-09-12",
	});
	assert.match(validateCommercialReadiness(input).join("\n"), /CLAIM-001: Sales Approved claim is expired/);
});
