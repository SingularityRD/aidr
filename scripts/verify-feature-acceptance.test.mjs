import assert from "node:assert/strict";
import { mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { verifyFeatureAcceptance } from "./verify-feature-acceptance.mjs";

const inventory = JSON.parse(readFileSync(new URL("../FEATURE_INVENTORY.json", import.meta.url), "utf8"));
const matrix = JSON.parse(readFileSync(new URL("../FEATURE_ACCEPTANCE.json", import.meta.url), "utf8"));

test("every inventory capability remains NO-GO even when a local test source exists", () => {
	assert.deepEqual(verifyFeatureAcceptance(inventory, matrix), {
		capabilities: 109,
		localTestPointers: 248,
		productionAccepted: 0,
		decision: "NO-GO",
	});
	const falsePass = structuredClone(matrix);
	falsePass.features["DET-01"].decision = "GO";
	assert.throws(() => verifyFeatureAcceptance(inventory, falsePass), /not acceptance evidence/);
});

test("source files and omitted capabilities cannot masquerade as test coverage", () => {
	const sourcePointer = structuredClone(matrix);
	sourcePointer.features["DET-01"].localTestSources = ["packages/core/src/extractors.ts"];
	assert.throws(() => verifyFeatureAcceptance(inventory, sourcePointer), /not a test source/);
	const missingCapability = structuredClone(matrix);
	delete missingCapability.features["DET-01"];
	assert.throws(() => verifyFeatureAcceptance(inventory, missingCapability), /cover exactly/);
});

test("absolute and symlink-escaped test pointers cannot inflate local coverage", (context) => {
	const absolutePointer = structuredClone(matrix);
	absolutePointer.features["DET-01"].localTestSources = [join(process.cwd(), "packages/core/src/__tests__/extractors.test.ts")];
	assert.throws(() => verifyFeatureAcceptance(inventory, absolutePointer), /repository-relative path/);

	const fixture = join(tmpdir(), `aidr-feature-acceptance-${process.pid}-${Date.now()}`);
	const root = join(fixture, "repo");
	const outsideDirectory = join(fixture, "outside");
	const outside = join(outsideDirectory, "outside.test.ts");
	const link = join(root, "external");
	mkdirSync(root, { recursive: true });
	mkdirSync(outsideDirectory, { recursive: true });
	writeFileSync(outside, "export {}\n");
	try {
		try {
			// Windows directory junctions do not require Developer Mode/admin rights.
			symlinkSync(outsideDirectory, link, "junction");
		} catch (error) {
			if (error?.code === "EPERM" || error?.code === "EACCES") {
				context.skip("this Windows host does not permit creating the symlink fixture");
				return;
			}
			throw error;
		}
		const escapedPointer = structuredClone(matrix);
		for (const feature of Object.values(escapedPointer.features)) feature.localTestSources = [];
		escapedPointer.features["DET-01"].localTestSources = ["external/outside.test.ts"];
		assert.throws(() => verifyFeatureAcceptance(inventory, escapedPointer, root), /outside the repository/);
	} finally {
		rmSync(fixture, { recursive: true, force: true });
	}
});
