import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { bindPypiLicenseEvidence, cycloneDxLicenses, parseSpdxExpression, resolvePypiLicense } from "./lib/pypi-license-data.mjs";
import { parseHashLockedRequirements } from "./lib/python-requirements-sbom.mjs";

const lockBytes = readFileSync(new URL("../services/aig-bridge/requirements-runtime.lock", import.meta.url));
const evidenceJson = readFileSync(new URL("../services/aig-bridge/pypi-runtime-licenses.json", import.meta.url), "utf8");
const lockDigest = createHash("sha256").update(lockBytes).digest("hex");
const locked = parseHashLockedRequirements(lockBytes.toString("utf8"));
const evidence = JSON.parse(evidenceJson);
const entry = (name) => structuredClone(evidence.packages.find((candidate) => candidate.name === name));

test("committed evidence is bound to the shipped lock and classifies every package", () => {
	const bound = bindPypiLicenseEvidence(evidenceJson, lockDigest, locked);
	assert.deepEqual(bound.problems, []);
	assert.equal(bound.byName.size, locked.length);
	const unresolved = [...bound.byName.values()].filter((item) => resolvePypiLicense(item).obligation === "unknown");
	assert.deepEqual(unresolved.map((item) => item.name), []);
});

test("evidence from another lock or another wheel is rejected, not trusted", () => {
	assert.match(bindPypiLicenseEvidence(evidenceJson, "0".repeat(64), locked).problems.join("\n"), /different requirements-runtime\.lock/);
	const tampered = structuredClone(evidence);
	tampered.packages[0].wheel_sha256 = "f".repeat(64);
	const result = bindPypiLicenseEvidence(JSON.stringify(tampered), lockDigest, locked);
	assert.match(result.problems.join("\n"), /not from a wheel pinned by the lock/);
	assert.equal(result.byName.has(tampered.packages[0].name), false);
	assert.match(bindPypiLicenseEvidence("", lockDigest, locked).problems[0], /missing or not valid/);
});

test("copyleft licences are classified precisely rather than collapsed to permissive", () => {
	assert.equal(resolvePypiLicense(entry("certifi")).obligation, "weak-copyleft");
	const psycopg = resolvePypiLicense(entry("psycopg"));
	assert.equal(psycopg.obligation, "weak-copyleft");
	assert.deepEqual(psycopg.spdx, [], "LGPLv3 does not say -only or -or-later, so no SPDX id is invented");
	assert.deepEqual(cycloneDxLicenses(psycopg), [{ license: { name: "GNU Lesser General Public License v3 (LGPLv3)" } }]);
	assert.equal(evidence.packages.some((candidate) => candidate.name === "psycopg-binary"), false);
	assert.equal(locked.some((candidate) => candidate.name === "psycopg-binary"), false);
	const bundledFixture = entry("psycopg");
	bundledFixture.bundled_native_libraries = ["fixture.libs/libpq.so"];
	assert.match(resolvePypiLicense(bundledFixture).flags[0], /bundles 1 native library/);
	assert.equal(resolvePypiLicense(entry("cryptography")).obligation, "permissive");
});

test("unrecognised or conflicting metadata stays unknown", () => {
	const unreviewedField = entry("pyyaml");
	unreviewedField.core_metadata.license_field = "Custom Vendor Terms";
	assert.equal(resolvePypiLicense(unreviewedField).obligation, "unknown");
	assert.equal(cycloneDxLicenses(resolvePypiLicense(unreviewedField)), undefined);

	const unreviewedExpression = entry("anyio");
	unreviewedExpression.core_metadata.license_expression = "MIT OR LicenseRef-Acme";
	assert.equal(resolvePypiLicense(unreviewedExpression).obligation, "unknown");

	const none = entry("pyyaml");
	none.core_metadata = { license_expression: null, license_field: null, license_classifiers: [], license_file_headers: [] };
	assert.equal(resolvePypiLicense(none).obligation, "unknown");

	const conflict = entry("pyyaml");
	conflict.core_metadata.license_classifiers = ["License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)"];
	assert.equal(resolvePypiLicense(conflict).obligation, "unknown");
});

test("the reviewed uvloop resolution is pinned to its licence-file digests", () => {
	const uvloop = entry("uvloop");
	const resolved = resolvePypiLicense(uvloop);
	assert.equal(resolved.obligation, "permissive");
	assert.deepEqual(resolved.spdx, ["Apache-2.0", "MIT"]);
	uvloop.license_files[0].sha256 = "a".repeat(64);
	assert.equal(resolvePypiLicense(uvloop).obligation, "unknown");
});

test("SPDX expressions respect AND/OR and reject unreviewed identifiers", () => {
	assert.equal(parseSpdxExpression("MIT OR GPL-3.0-only")?.obligation, "permissive");
	assert.equal(parseSpdxExpression("MIT AND GPL-3.0-only")?.obligation, "strong-copyleft");
	assert.equal(parseSpdxExpression("(Apache-2.0 OR BSD-3-Clause) AND MPL-2.0")?.obligation, "weak-copyleft");
	assert.equal(parseSpdxExpression("MIT WITH Classpath-exception-2.0"), null);
	assert.equal(parseSpdxExpression("Made-Up-1.0"), null);
});
