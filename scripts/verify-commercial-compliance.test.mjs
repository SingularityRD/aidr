import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import {
	LICENSE_REGISTER_FILE,
	LICENSE_SCHEMA_FILE,
	PRIVACY_MATRIX_FILE,
	PRIVACY_SCHEMA_FILE,
	ROOT,
	readComplianceArtifacts,
	validateCommercialCompliance,
	validateLicenseExceptionRegister,
	validatePrivacyDataFlowMatrix,
} from "./verify-commercial-compliance.mjs";

const artifacts = readComplianceArtifacts({ root: ROOT });

function validLicenseRegister() {
	return {
		schema_version: 1,
		register_id: "aidr-license-exception-register",
		status: "closed",
		updated_at: "2026-01-02",
		entries: [{
			exception_id: "LIC-EX-101",
			component: "fixture-component",
			version: "1.2.3",
			declared_license: "Fixture-License",
			exception_type: "dependency_policy",
			scope: "fixture package only",
			reason: "fixture migration",
			risk: "fixture review risk",
			mitigations: ["fixture pin and removal task"],
			owner: "fixture-owner",
			approver: "fixture-approver",
			approved_at: "2026-01-01",
			expires_at: "2026-12-31",
			status: "approved",
			evidence: ["fixture-evidence.txt"],
			unknowns: [],
		}],
		unknowns: [],
		limitations: ["fixture data is not a production record"],
	};
}

function validPrivacyMatrix() {
	return {
		schema_version: 1,
		matrix_id: "aidr-privacy-data-flow-matrix",
		status: "accepted",
		updated_at: "2026-01-02",
		deployment_scope: "fixture deployment",
		flows: [{
			flow_id: "DF-101",
			data_class: "fixture diagnostics",
			fields: ["event name"],
			source: "fixture source",
			purpose: "fixture verification",
			trigger: "fixture event",
			destination: "fixture destination",
			destination_domain: "example.invalid",
			region: "fixture region",
			subprocessor: "none recorded",
			lawful_basis: "fixture record",
			retention: "fixture retention",
			deletion: "fixture deletion",
			access: "fixture operator",
			transfer_mechanism: "fixture transport",
			evidence: ["fixture capture"],
			status: "accepted",
			unknowns: [],
		}],
		unknowns: [],
		limitations: ["fixture data is not a production record"],
	};
}

test("shipped register and matrix are locally valid while remaining open", () => {
	const result = validateCommercialCompliance(artifacts);
	assert.deepEqual(result.failures, []);
	assert.equal(result.license.status, "open");
	assert.equal(result.privacy.status, "open");
	assert.ok(result.license.unknown_values > 0);
	assert.ok(result.privacy.unknown_values > 0);
	assert.equal(result.license.open_entries, 1);
	assert.equal(result.privacy.flows, 12);
	assert.equal(result.privacy.open_flows, 12);
});

test("the shipped paths and schemas are the documented local artifacts", async () => {
	const paths = [LICENSE_REGISTER_FILE, LICENSE_SCHEMA_FILE, PRIVACY_MATRIX_FILE, PRIVACY_SCHEMA_FILE];
	for (const path of paths) {
		const contents = await readFile(join(ROOT, path), "utf8");
		assert.doesNotThrow(() => JSON.parse(contents), path);
	}
	assert.equal(artifacts.licenseSchema.$id, "https://singularityrd.dev/schemas/license-exception-register.schema.json");
	assert.equal(artifacts.privacySchema.$id, "https://singularityrd.dev/schemas/privacy-data-flow-matrix.schema.json");
});

test("a license exception must declare expires_at", () => {
	const register = validLicenseRegister();
	delete register.entries[0].expires_at;
	const result = validateLicenseExceptionRegister(register, artifacts.licenseSchema, { now: new Date("2026-01-02T00:00:00Z") });
	assert.match(result.failures.join("\n"), /expires_at/);
});

test("approved license exceptions need a future expiry and known evidence", () => {
	const expired = validLicenseRegister();
	expired.entries[0].expires_at = "2025-12-31";
	assert.match(
		validateLicenseExceptionRegister(expired, artifacts.licenseSchema, { now: new Date("2026-01-02T00:00:00Z") }).failures.join("\n"),
		/expires_at must be in the future/,
	);

	const unknownEvidence = validLicenseRegister();
	unknownEvidence.entries[0].evidence = ["unknown"];
	unknownEvidence.entries[0].unknowns = ["evidence[0]"];
	assert.match(
		validateLicenseExceptionRegister(unknownEvidence, artifacts.licenseSchema, { now: new Date("2026-01-02T00:00:00Z") }).failures.join("\n"),
		/non-unknown evidence/,
	);
});

test("expired entries are explicit and do not silently remain active", () => {
	const register = validLicenseRegister();
	register.status = "open";
	register.entries[0].status = "expired";
	register.entries[0].expires_at = "2025-12-31";
	assert.deepEqual(validateLicenseExceptionRegister(register, artifacts.licenseSchema, { now: new Date("2026-01-02T00:00:00Z") }).failures, []);

	register.entries[0].status = "open";
	assert.match(
		validateLicenseExceptionRegister(register, artifacts.licenseSchema, { now: new Date("2026-01-02T00:00:00Z") }).failures.join("\n"),
		/expires_at has passed/,
	);
});

test("duplicate license exception identifiers fail closed", () => {
	const register = validLicenseRegister();
	register.entries.push(structuredClone(register.entries[0]));
	assert.match(
		validateLicenseExceptionRegister(register, artifacts.licenseSchema).failures.join("\n"),
		/duplicate exception_id/,
	);
});

test("privacy matrix requires an explicit declaration for every unknown field", () => {
	const matrix = validPrivacyMatrix();
	matrix.status = "open";
	matrix.flows[0].status = "inventory";
	matrix.flows[0].destination = "unknown";
	matrix.flows[0].unknowns = [];
	const result = validatePrivacyDataFlowMatrix(matrix, artifacts.privacySchema);
	assert.match(result.failures.join("\n"), /unknown value at destination must be listed/);
});

test("accepted privacy matrices cannot contain unknown values", () => {
	const matrix = validPrivacyMatrix();
	matrix.flows[0].destination = "unknown";
	matrix.flows[0].unknowns = ["destination"];
	assert.match(
		validatePrivacyDataFlowMatrix(matrix, artifacts.privacySchema).failures.join("\n"),
		/accepted flow cannot retain unresolved unknowns|accepted status cannot contain unresolved unknowns/,
	);
});

test("a complete privacy matrix can be accepted without inventing values", () => {
	const result = validatePrivacyDataFlowMatrix(validPrivacyMatrix(), artifacts.privacySchema);
	assert.deepEqual(result.failures, []);
	assert.equal(result.summary.status, "accepted");
	assert.equal(result.summary.unknown_values, 0);
	assert.equal(result.summary.open_flows, 0);
});

test("blank and informal placeholder values are rejected", () => {
	const register = validLicenseRegister();
	register.entries[0].component = "TBD";
	assert.match(validateLicenseExceptionRegister(register, artifacts.licenseSchema).failures.join("\n"), /explicit 'unknown' sentinel/);

	const matrix = validPrivacyMatrix();
	matrix.flows[0].destination_domain = " ";
	assert.match(validatePrivacyDataFlowMatrix(matrix, artifacts.privacySchema).failures.join("\n"), /blank string/);
});
