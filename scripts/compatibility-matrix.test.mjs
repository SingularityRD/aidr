/**
 * The published compatibility matrix is generated from the release records and must not drift.
 *
 *   node --test scripts/compatibility-matrix.test.mjs
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { acceptedRecords, loadInputs, OUTPUT_PATH, PREVIEW_LABEL, renderCompatibilityMatrix } from "./generate-compatibility-matrix.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const inputs = loadInputs(root);

const rowFor = (markdown, connectorName) => markdown.split("\n").find((line) => line.startsWith(`| ${connectorName} | `));

test("docs/compatibility-matrix.md matches the generator", () => {
	assert.equal(readFileSync(path.join(root, OUTPUT_PATH), "utf8"), renderCompatibilityMatrix(inputs), `${OUTPUT_PATH} is stale; run node scripts/generate-compatibility-matrix.mjs`);
});

test("every sold connector is listed, with the tested host version from its acceptance record", () => {
	const markdown = renderCompatibilityMatrix(inputs);
	for (const row of inputs.support.rows) {
		const records = acceptedRecords(row, inputs.evidence);
		const name = { "claude-code": "Claude Code", cursor: "Cursor", vscode: "VS Code", openclaw: "OpenClaw", opencode: "OpenCode", codex: "Codex CLI" }[row.connector];
		const line = rowFor(markdown, name);
		assert.ok(line, `${row.connector} is missing from the tested-host table`);
		if (records.length === 0) {
			assert.ok(line.includes(PREVIEW_LABEL), `${row.connector} has no real-host evidence and must be shown as a preview`);
		} else {
			assert.ok(!line.includes(PREVIEW_LABEL));
			for (const record of records) assert.ok(line.includes(record.host.version), `${row.connector}: tested version ${record.host.version} not shown`);
		}
	}
});

test("Cursor and VS Code stay preview while the support matrix records no evidence for them", () => {
	const markdown = renderCompatibilityMatrix(inputs);
	for (const [connector, name] of [
		["cursor", "Cursor"],
		["vscode", "VS Code"],
	]) {
		const row = inputs.support.rows.find((r) => r.connector === connector);
		if ((row.acceptanceEvidence ?? []).length === 0) assert.match(rowFor(markdown, name), /Preview — no real-host acceptance evidence yet/);
	}
});

test("a record whose digest does not match the support matrix does not count as evidence", () => {
	const support = structuredClone(inputs.support);
	const codex = support.rows.find((row) => row.connector === "codex");
	const evidence = structuredClone(inputs.evidence);
	for (const ref of codex.acceptanceEvidence) evidence[ref.path] = { ...evidence[ref.path], matches: false };
	const markdown = renderCompatibilityMatrix({ ...inputs, support, evidence });
	assert.ok(rowFor(markdown, "Codex CLI").includes(PREVIEW_LABEL), "an unverifiable record must not make a connector tested");
});

test("evidence added for a connector removes its preview label", () => {
	const support = structuredClone(inputs.support);
	const cursor = support.rows.find((row) => row.connector === "cursor");
	cursor.acceptanceEvidence = [{ path: "synthetic/cursor.json", sha256: "0".repeat(64) }];
	const evidence = {
		...inputs.evidence,
		"synthetic/cursor.json": {
			matches: true,
			record: { passed: true, host: { version: "Cursor 9.9.9" }, platform: "linux", architecture: "x64", recordedAtUtc: "2026-10-13T00:00:00Z", aidrArtifact: { buildFlavor: "development" }, proves: {}, limitations: [] },
		},
	};
	const line = rowFor(renderCompatibilityMatrix({ ...inputs, support, evidence }), "Cursor");
	assert.ok(!line.includes(PREVIEW_LABEL));
	assert.ok(line.includes("Cursor 9.9.9"));
});

test("the host failure section states what the host does when the hook cannot answer", () => {
	const markdown = renderCompatibilityMatrix(inputs);
	assert.match(markdown, /## Host failure behaviour/);
	assert.match(rowFor(markdown.slice(markdown.indexOf("## Host failure behaviour")), "Codex CLI"), /Call runs \(host fails open\)/);
	assert.match(markdown, /target scope, not tested support/);
});
