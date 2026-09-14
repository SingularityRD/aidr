import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { validateCommercialGateReceipts, validateReceiptRecord } from "./verify-commercial-gate-receipts.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RECEIPTS_FILE = "docs/production-readiness/commercial-gate-receipts.json";
const SCHEMA_FILE = "docs/production-readiness/commercial-gate-receipts.schema.json";

const [registry, receipts, schema] = await Promise.all([
	readFile(join(ROOT, "docs/production-readiness/commercial-go-evidence-registry.json"), "utf8").then(JSON.parse),
	readFile(join(ROOT, RECEIPTS_FILE), "utf8").then(JSON.parse),
	readFile(join(ROOT, SCHEMA_FILE), "utf8").then(JSON.parse),
]);

// The verifier binds closed receipts to the digest of the current
// release-inventory.json, which lives under gitignored .release-evidence/. The
// tests inject a deterministic inventory so they never depend on that
// pre-existing artefact.
const inventoryDir = mkdtempSync(join(tmpdir(), "aidr-gate-receipts-"));
const inventoryPath = join(inventoryDir, "release-inventory.json");
const inventoryBytes = `${JSON.stringify({ schema_version: 1, artifacts: [] }, null, 2)}\n`;
writeFileSync(inventoryPath, inventoryBytes, "utf8");
const candidateDigest = createHash("sha256").update(inventoryBytes).digest("hex");
const sha256OfFile = (path) => createHash("sha256").update(readFileSync(join(ROOT, path))).digest("hex");

const EVIDENCE_PATH = SCHEMA_FILE;

function fixture() {
	return {
		registry: structuredClone(registry),
		receipts: structuredClone(receipts),
		schema: structuredClone(schema),
		root: ROOT,
		releaseInventoryPath: inventoryPath,
	};
}

// Turn one real receipt into a fully backed closed receipt. The owner and
// reviewer strings are obviously synthetic fixture values: no test writes a
// receipt to disk and none of them is evidence about a real person.
function closeReceipt(input, gateId, overrides = {}) {
	const receipt = input.receipts.find((item) => item.gate_id === gateId);
	input.registry.hardGates.find((item) => item.id === gateId).status = "closed";
	Object.assign(
		receipt,
		{
			decision: "closed",
			owner_name: "fixture-owner",
			evidence_path: EVIDENCE_PATH,
			evidence_sha256: sha256OfFile(EVIDENCE_PATH),
			candidate_digest: candidateDigest,
			effective_version: "fixture-effective-version",
			recorded_at_utc: "2026-01-01T00:00:00.000Z",
			reviewer_name: "fixture-reviewer",
			reviewer_role: "Independent Reviewer",
		},
		overrides,
	);
	return receipt;
}

const failuresOf = (input) => validateCommercialGateReceipts(input).failures.join("\n");

test("a complete all-open receipt set passes", () => {
	assert.deepEqual(validateCommercialGateReceipts(fixture()).failures, []);
});

test("the shipped receipts cover every registry hard gate exactly once", () => {
	const ids = receipts.map((receipt) => receipt.gate_id);
	assert.equal(new Set(ids).size, ids.length);
	assert.deepEqual([...ids].sort(), registry.hardGates.map((gate) => gate.id).sort());
});

test("every shipped receipt records the registry owner role and stays open", () => {
	for (const gate of registry.hardGates) {
		const receipt = receipts.find((item) => item.gate_id === gate.id);
		assert.equal(receipt.owner_role, gate.ownerRole);
		assert.equal(receipt.decision, gate.status);
		assert.equal(receipt.candidate_digest, null);
		assert.equal(receipt.effective_version, null);
		assert.equal(receipt.recorded_at_utc, null);
		assert.equal(receipt.evidence_path, null);
		assert.equal(receipt.evidence_sha256, null);
		assert.ok(receipt.external_inputs.length > 0);
	}
});

test("a missing gate receipt fails", () => {
	const input = fixture();
	input.receipts = input.receipts.filter((receipt) => receipt.gate_id !== "COM-013");
	assert.match(failuresOf(input), /COM-013: no receipt exists for this registry hard gate/);
});

test("an extra unknown gate id fails", () => {
	const input = fixture();
	input.receipts.push({ ...structuredClone(input.receipts[0]), gate_id: "COM-999" });
	assert.match(failuresOf(input), /COM-999: receipt does not correspond to a registry hard gate/);
});

test("a duplicate receipt fails", () => {
	const input = fixture();
	input.receipts.push(structuredClone(input.receipts[0]));
	assert.match(failuresOf(input), /duplicate receipt for COM-001/);
});

test("a closed receipt with no reviewer fails", () => {
	const input = fixture();
	closeReceipt(input, "COM-001", { reviewer_name: "REQUIRED" });
	const failures = failuresOf(input);
	assert.match(failures, /COM-001: a closed receipt needs a named reviewer/);
	assert.doesNotMatch(failures, /COM-001: a closed receipt needs a named owner/);
});

test("a closed receipt reviewed by its own role fails", () => {
	const input = fixture();
	closeReceipt(input, "COM-001", { reviewer_role: "Commercial/Sales + Finance/Billing" });
	assert.match(failuresOf(input), /COM-001: reviewer_role must differ from owner_role/);
});

test("a closed receipt with a fabricated or non-matching evidence hash fails", () => {
	const mismatch = fixture();
	closeReceipt(mismatch, "COM-002", { evidence_sha256: "b".repeat(64) });
	assert.match(failuresOf(mismatch), /COM-002: evidence SHA-256 does not match/);

	const absent = fixture();
	closeReceipt(absent, "COM-002", { evidence_path: "docs/production-readiness/no-such-evidence.json" });
	assert.match(failuresOf(absent), /COM-002: evidence path does not exist on disk/);
});

test("a closed receipt whose candidate digest differs from the release inventory fails", () => {
	const input = fixture();
	closeReceipt(input, "COM-003", { candidate_digest: "c".repeat(64) });
	assert.match(failuresOf(input), /COM-003: candidate_digest does not match the current release-inventory digest/);
});

test("no release inventory means no gate can close", () => {
	const input = fixture();
	input.releaseInventoryPath = join(inventoryDir, "absent-release-inventory.json");
	closeReceipt(input, "COM-004");
	assert.match(failuresOf(input), /COM-004: no release inventory exists to bind a candidate digest/);
});

test("a registry/receipt status disagreement fails", () => {
	const input = fixture();
	input.registry.hardGates.find((gate) => gate.id === "COM-005").status = "in-review";
	assert.match(failuresOf(input), /COM-005: receipt decision open disagrees with registry status in-review/);
});

test("an owner role that drifts from the registry fails", () => {
	const input = fixture();
	input.receipts.find((receipt) => receipt.gate_id === "COM-010").owner_role = "Invented Role";
	assert.match(failuresOf(input), /COM-010: owner_role must be copied from the registry/);
});

test("a non-closed receipt may not carry evidence fields", () => {
	const input = fixture();
	const receipt = input.receipts.find((item) => item.gate_id === "POV-001");
	receipt.evidence_path = EVIDENCE_PATH;
	receipt.evidence_sha256 = sha256OfFile(EVIDENCE_PATH);
	assert.match(failuresOf(input), /POV-001: evidence_path and evidence_sha256 must be null while decision is open/);
});

test("the schema rejects a closed record with no reviewer, hash or candidate binding", () => {
	const backed = {
		...structuredClone(receipts[0]),
		decision: "closed",
		owner_name: "fixture-owner",
		evidence_path: EVIDENCE_PATH,
		evidence_sha256: sha256OfFile(EVIDENCE_PATH),
		candidate_digest: candidateDigest,
		effective_version: "fixture-effective-version",
		recorded_at_utc: "2026-01-01T00:00:00.000Z",
		reviewer_name: "fixture-reviewer",
		reviewer_role: "Independent Reviewer",
	};
	assert.deepEqual(validateReceiptRecord(backed, schema), []);
	assert.ok(
		validateReceiptRecord({ ...backed, reviewer_name: "REQUIRED", evidence_sha256: null, candidate_digest: "unknown" }, schema).length > 0,
	);
});
