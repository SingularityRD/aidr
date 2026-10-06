import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { buildReport, classifyComponent, renderMarkdown } from "./generate-license-report.mjs";
import { cycloneDxLicenses, resolvePypiLicense } from "./lib/pypi-license-data.mjs";

const lib = (name, licenses) => ({ type: "library", name, version: "1.0.0", purl: `pkg:npm/${name}@1.0.0`, licenses });

test("missing licence is UNKNOWN, never permissive", () => {
	assert.equal(classifyComponent(lib("a", undefined)).category, "unknown");
	assert.equal(classifyComponent(lib("a", [])).category, "unknown");
});

test("classifies permissive, copyleft and OR expressions", () => {
	assert.equal(classifyComponent(lib("a", [{ license: { id: "MIT" } }])).category, "permissive");
	assert.equal(classifyComponent(lib("a", [{ license: { id: "LGPL-3.0-only" } }])).category, "review-required");
	assert.equal(classifyComponent(lib("a", [{ license: { expression: "(MIT OR GPL-3.0-only)" } }])).category, "permissive");
	assert.equal(classifyComponent(lib("a", [{ license: { expression: "MIT AND GPL-3.0-only" } }])).category, "review-required");
	assert.equal(classifyComponent(lib("a", [{ license: { name: "Custom EULA" } }])).category, "other");
});

test("report totals ignore applications and flag attention items", () => {
	const report = buildReport({
		components: [
			{ type: "application", name: "app", version: "1" },
			lib("a", [{ license: { id: "Apache-2.0" } }]),
			lib("b", undefined),
			lib("c", [{ license: { id: "GPL-2.0-only" } }]),
		],
	});
	assert.deepEqual(report.totals, { libraries: 3, permissive: 1, reviewRequired: 1, other: 0, unknown: 1 });
	assert.deepEqual(report.attention.map((c) => c.name), ["b", "c"]);
	assert.match(renderMarkdown(report), /UNKNOWN/);
});

test("OR branches preserve mandatory AND obligations and separate declarations", () => {
	const category = (expression) => classifyComponent(lib("a", [{ expression }])).category;
	assert.equal(category("(MIT OR Apache-2.0) AND GPL-3.0-only"), "review-required");
	assert.equal(category("MIT OR (Apache-2.0 AND GPL-3.0-only)"), "permissive");
	assert.equal(category("MIT OR LicenseRef-Unreviewed"), "other");
	assert.equal(category("MIT WITH Unreviewed-exception"), "other");
	assert.equal(category("(MIT OR Apache-2.0"), "other");
	assert.equal(classifyComponent(lib("a", [{ expression: "MIT OR GPL-3.0-only" }, { license: { id: "AGPL-3.0-only" } }])).category, "review-required");
});

test("exact runtime wheels retain copyleft obligations and bundled native-library flags", () => {
	const evidence = JSON.parse(readFileSync(new URL("../services/aig-bridge/pypi-runtime-licenses.json", import.meta.url), "utf8"));
	const report = buildReport({ components: evidence.packages.map((entry) => {
		const resolved = resolvePypiLicense(entry);
		return { ...lib(entry.name, cycloneDxLicenses(resolved)), properties: resolved.flags.map((value) => ({ name: "aidr:license-flags", value })) };
	}) });
	assert.deepEqual(report.totals, { libraries: 30, permissive: 28, reviewRequired: 2, other: 0, unknown: 0 });
	assert.deepEqual(report.attention.map((entry) => entry.name).sort(), ["certifi", "cryptography", "psycopg", "pydantic-core", "watchfiles"]);
	assert.equal(evidence.packages.some((entry) => entry.name === "psycopg-binary"), false);
	for (const name of ["cryptography", "pydantic-core", "watchfiles"]) {
		assert.equal(report.attention.find((entry) => entry.name === name).licenseFlags.length, 1);
		assert.match(report.attention.find((entry) => entry.name === name).licenseFlags[0], /bundles 1 native library/);
	}
	assert.match(renderMarkdown(report), /bundles 1 native library/);
	assert.match(report.legalStatus, /Counsel approval \(COM-002\) is not implied/);
});

test("strict CLI rejects review, unknown, unsupported expressions and native-library flags", (context) => {
	const dir = mkdtempSync(path.join(os.tmpdir(), "aidr-license-report-"));
	context.after(() => rmSync(dir, { recursive: true, force: true }));
	const script = fileURLToPath(new URL("./generate-license-report.mjs", import.meta.url));
	const cases = [
		{ component: lib("clean", [{ license: { id: "MIT" } }]), expected: 0 },
		{ component: lib("mixed", [{ expression: "(MIT OR Apache-2.0) AND GPL-3.0-only" }]), expected: 1 },
		{ component: lib("lgpl", [{ license: { name: "GNU Lesser General Public License v3 (LGPLv3)" } }]), expected: 1 },
		{ component: lib("unknown", undefined), expected: 1 },
		{ component: lib("unsupported", [{ expression: "MIT OR LicenseRef-Unreviewed" }]), expected: 1 },
		{ component: { ...lib("bundled", [{ license: { id: "MIT" } }]), properties: [{ name: "aidr:license-flags", value: "Bundled native library licence unresolved" }] }, expected: 1 },
	];
	for (const { component, expected } of cases) {
		const input = path.join(dir, "sbom.json");
		writeFileSync(input, JSON.stringify({ components: [component] }));
		const result = spawnSync(process.execPath, [script, "--sbom", input, "--output", path.join(dir, "report.json"), "--strict"], { encoding: "utf8" });
		assert.equal(result.status, expected, `${component.name}: ${result.stdout}${result.stderr}`);
	}
});
