import assert from "node:assert/strict";
import { test } from "node:test";
import { buildReport, classifyComponent, renderMarkdown } from "./generate-license-report.mjs";

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
