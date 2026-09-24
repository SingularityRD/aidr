#!/usr/bin/env node

/**
 * Commercial hard-gate evidence receipt gate.
 *
 * This gate is deliberately dependency-free and does NOT decide whether a hard
 * gate may close. It proves only that the receipt set in
 * docs/production-readiness/commercial-gate-receipts.json is complete, honest
 * and structurally bound to the commercial evidence registry:
 *
 *   * exactly one receipt per registry hard gate, no extras, no duplicates;
 *   * every record validates against commercial-gate-receipts.schema.json;
 *   * the schema's decision vocabulary and gate-id enum cannot drift from the
 *     registry, and the schema's closed branch covers every clause in
 *     registry.policy.closedRequires;
 *   * any receipt that claims a closed decision carries a named owner, a
 *     reviewer whose role differs from the owner's, an on-disk evidence path
 *     whose SHA-256 matches, an effective version and a candidate digest equal
 *     to the current release-inventory digest;
 *   * the registry's own hardGates[].status and the receipt decision agree.
 *
 * All 13 gates are legitimately "open" today, so a complete and honest all-open
 * run exits 0. `node docs/scripts/claim-check.mjs --mode=gate` is the gate that
 * fails while gates are open; this one fails only on dishonesty or drift.
 *
 * Usage:
 *   node scripts/verify-commercial-gate-receipts.mjs
 *   node scripts/verify-commercial-gate-receipts.mjs --help
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { HELD, readInvestorMetricDictionary, validateMetricDictionary } from "./validate-investor-metric-dictionary.mjs";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REGISTRY_FILE = "docs/production-readiness/commercial-go-evidence-registry.json";
export const RECEIPTS_FILE = "docs/production-readiness/commercial-gate-receipts.json";
export const SCHEMA_FILE = "docs/production-readiness/commercial-gate-receipts.schema.json";
// Mirrors CANDIDATE_DIGEST_SOURCE in scripts/generate-v8-evidence-index.mjs so a
// closed receipt binds to the same release inventory the v8 index hashes. The
// path lives under gitignored .release-evidence/, so a fresh checkout has no
// candidate and no gate may close.
export const RELEASE_INVENTORY_FILE = ".release-evidence/customer-release-v8-local-20260913/release-inventory.json";
export const RELEASE_INVENTORY_ENV = "AIDR_COMMERCIAL_RELEASE_INVENTORY";

// Registry policy.acceptedStatuses values that assert closure. Mirroring
// docs/scripts/claim-check.mjs, every other status counts as still open.
export const CLOSED_DECISIONS = Object.freeze(["closed"]);

// Every registry.policy.closedRequires clause mapped to the receipt fields that
// satisfy it. A clause with no mapping, or a mapped field missing from the
// schema's closed branch, fails verification: the mirror must stay exact.
export const CLOSED_REQUIREMENT_FIELDS = Object.freeze({
	"named owner": ["owner_name"],
	"Release Candidate or effective version": ["effective_version", "candidate_digest"],
	"immutable evidence path and SHA-256": ["evidence_path", "evidence_sha256"],
	"reviewer or approver": ["reviewer_name", "reviewer_role"],
	"recorded date": ["recorded_at_utc"],
});

// The minimum field set the receipt schema must require. Kept explicit so a
// schema edit that drops a field fails here instead of silently weakening every
// record.
export const MINIMUM_RECEIPT_FIELDS = Object.freeze([
	"gate_id",
	"decision",
	"owner_name",
	"owner_role",
	"evidence_path",
	"evidence_sha256",
	"candidate_digest",
	"effective_version",
	"recorded_at_utc",
	"reviewer_name",
	"reviewer_role",
	"scope",
	"limitations",
	"external_inputs",
]);

export const REQUIRED_SENTINEL = "REQUIRED";
export const UNKNOWN = "unknown";
const REQUIRED_ASSESSMENT_SCOPE = ["tenant", "identity", "runtime", "distribution", "secrets"];
const SHA256 = /^[0-9a-f]{64}$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const ANNOTATION_KEYWORDS = new Set(["$schema", "$id", "$defs", "title", "description", "$comment", "examples", "default"]);
const SUPPORTED_KEYWORDS = new Set([
	...ANNOTATION_KEYWORDS,
	"$ref",
	"type",
	"enum",
	"const",
	"required",
	"properties",
	"additionalProperties",
	"items",
	"minItems",
	"uniqueItems",
	"minLength",
	"pattern",
	"oneOf",
	"allOf",
	"not",
	"if",
	"then",
	"else",
]);

export function sha256File(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function toRepoPath(value) {
	return String(value).replaceAll("\\", "/");
}

function typeMatches(value, type) {
	switch (type) {
		case "object":
			return value !== null && typeof value === "object" && !Array.isArray(value);
		case "array":
			return Array.isArray(value);
		case "string":
			return typeof value === "string";
		case "number":
			return typeof value === "number" && Number.isFinite(value);
		case "integer":
			return Number.isInteger(value);
		case "boolean":
			return typeof value === "boolean";
		case "null":
			return value === null;
		default:
			throw new Error(`unsupported schema type: ${type}`);
	}
}

function deepEqual(left, right) {
	if (left === right) return true;
	if (typeof left !== typeof right) return false;
	if (left === null || right === null || typeof left !== "object") return false;
	if (Array.isArray(left) !== Array.isArray(right)) return false;
	const leftKeys = Object.keys(left);
	const rightKeys = Object.keys(right);
	if (leftKeys.length !== rightKeys.length) return false;
	return leftKeys.every((key) => deepEqual(left[key], right[key]));
}

function resolveRef(ref, rootSchema) {
	if (typeof ref !== "string" || !ref.startsWith("#/")) {
		throw new Error(`unsupported $ref: ${JSON.stringify(ref)}`);
	}
	let node = rootSchema;
	for (const rawKey of ref.slice(2).split("/")) {
		const key = rawKey.replaceAll("~1", "/").replaceAll("~0", "~");
		if (node === null || typeof node !== "object" || !Object.hasOwn(node, key)) {
			throw new Error(`unresolvable $ref: ${ref}`);
		}
		node = node[key];
	}
	return node;
}

function assertKnownKeywords(schema, path) {
	for (const keyword of Object.keys(schema)) {
		if (!SUPPORTED_KEYWORDS.has(keyword)) {
			// Fail closed: an unsupported keyword could hide a constraint and turn a
			// dishonest receipt into a pass.
			throw new Error(`${path}: unsupported JSON Schema keyword ${keyword}`);
		}
	}
}

function subErrors(instance, schema, rootSchema, path) {
	const errors = [];
	collectErrors(instance, schema, rootSchema, path, errors);
	return errors;
}

function collectErrors(instance, schema, rootSchema, path, errors) {
	if (schema === null || typeof schema !== "object") return;
	if (schema.$ref !== undefined) {
		collectErrors(instance, resolveRef(schema.$ref, rootSchema), rootSchema, path, errors);
		return;
	}
	assertKnownKeywords(schema, path);
	if (schema.type !== undefined) {
		const types = Array.isArray(schema.type) ? schema.type : [schema.type];
		if (!types.some((type) => typeMatches(instance, type))) {
			errors.push(`${path}: expected ${types.join(" or ")}`);
			return;
		}
	}
	if (Array.isArray(schema.enum) && !schema.enum.some((value) => deepEqual(value, instance))) {
		errors.push(`${path}: ${JSON.stringify(instance)} is not one of ${JSON.stringify(schema.enum)}`);
	}
	if (Object.hasOwn(schema, "const") && !deepEqual(schema.const, instance)) {
		errors.push(`${path}: must equal ${JSON.stringify(schema.const)}`);
	}
	if (typeof instance === "string") {
		if (typeof schema.minLength === "number" && instance.length < schema.minLength) {
			errors.push(`${path}: needs at least ${schema.minLength} character(s)`);
		}
		if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(instance)) {
			errors.push(`${path}: does not match ${schema.pattern}`);
		}
	}
	if (Array.isArray(instance)) {
		if (typeof schema.minItems === "number" && instance.length < schema.minItems) {
			errors.push(`${path}: needs at least ${schema.minItems} item(s)`);
		}
		if (schema.uniqueItems === true && new Set(instance.map((item) => JSON.stringify(item))).size !== instance.length) {
			errors.push(`${path}: items must be unique`);
		}
		if (schema.items !== undefined) {
			instance.forEach((item, index) => collectErrors(item, schema.items, rootSchema, `${path}[${index}]`, errors));
		}
	}
	if (schema.not !== undefined && subErrors(instance, schema.not, rootSchema, path).length === 0) {
		errors.push(`${path}: matches a forbidden shape ${JSON.stringify(schema.not)}`);
	}
	if (Array.isArray(schema.oneOf)) {
		const matched = schema.oneOf.filter((branch) => subErrors(instance, branch, rootSchema, path).length === 0).length;
		if (matched !== 1) errors.push(`${path}: must match exactly one alternative, matched ${matched}`);
	}
	if (Array.isArray(schema.allOf)) {
		for (const branch of schema.allOf) collectErrors(instance, branch, rootSchema, path, errors);
	}
	if (schema.if !== undefined) {
		if (subErrors(instance, schema.if, rootSchema, path).length === 0) {
			if (schema.then !== undefined) collectErrors(instance, schema.then, rootSchema, path, errors);
		} else if (schema.else !== undefined) {
			collectErrors(instance, schema.else, rootSchema, path, errors);
		}
	}
	const isObject = instance !== null && typeof instance === "object" && !Array.isArray(instance);
	if (isObject && (Array.isArray(schema.required) || schema.properties !== undefined || schema.additionalProperties === false)) {
		for (const name of schema.required ?? []) {
			if (!Object.hasOwn(instance, name)) errors.push(`${path}: missing required property ${name}`);
		}
		for (const [name, value] of Object.entries(instance)) {
			const child = schema.properties?.[name];
			if (child !== undefined) collectErrors(value, child, rootSchema, `${path}.${name}`, errors);
			else if (schema.additionalProperties === false) errors.push(`${path}.${name}: additional property is not allowed`);
		}
	}
}

/** Validate one receipt record against the receipt schema. Returns error strings. */
export function validateReceiptRecord(receipt, schema) {
	return subErrors(receipt, schema, schema, "receipt");
}

function sameStringSet(left, right) {
	const a = new Set(left ?? []);
	const b = new Set(right ?? []);
	if (a.size !== b.size) return false;
	for (const value of a) if (!b.has(value)) return false;
	return true;
}

function describeDifference(label, expected, actual) {
	const expectedSet = new Set(expected ?? []);
	const actualSet = new Set(actual ?? []);
	const missing = [...expectedSet].filter((value) => !actualSet.has(value));
	const extra = [...actualSet].filter((value) => !expectedSet.has(value));
	const parts = [];
	if (missing.length > 0) parts.push(`missing ${JSON.stringify(missing)}`);
	if (extra.length > 0) parts.push(`unexpected ${JSON.stringify(extra)}`);
	return `${label} differs from the registry (${parts.join(", ")})`;
}

/**
 * A synthetic all-"REQUIRED" closed record. It is built in memory only and is
 * never written to disk: the schema must reject it, which is what proves a
 * closed decision cannot be represented without real backing.
 */
function unbackedClosedReceipt(gateId, ownerRole) {
	return {
		gate_id: gateId,
		decision: "closed",
		owner_name: REQUIRED_SENTINEL,
		owner_role: ownerRole,
		evidence_path: null,
		evidence_sha256: null,
		candidate_digest: UNKNOWN,
		effective_version: null,
		recorded_at_utc: null,
		reviewer_name: REQUIRED_SENTINEL,
		reviewer_role: REQUIRED_SENTINEL,
		scope: "synthetic schema self-test record",
		limitations: ["synthetic schema self-test record"],
		external_inputs: ["synthetic schema self-test record"],
	};
}

/** A synthetic fully backed closed record: the closure path the schema allows. */
function backedClosedReceipt(gateId, ownerRole) {
	return {
		...unbackedClosedReceipt(gateId, ownerRole),
		owner_name: "fixture-owner",
		evidence_path: "docs/production-readiness/commercial-go-evidence-registry.json",
		evidence_sha256: "0".repeat(64),
		candidate_digest: "0".repeat(64),
		effective_version: "fixture-effective-version",
		recorded_at_utc: "2026-01-01T00:00:00.000Z",
		reviewer_name: "fixture-reviewer",
		reviewer_role: "Fixture Reviewer Role",
	};
}

function validateSchemaAgainstRegistry(registry, schema, failures) {
	if (schema?.$schema !== "https://json-schema.org/draft/2020-12/schema") {
		failures.push(`receipt schema must declare the JSON Schema draft 2020-12 dialect`);
	}
	if (schema?.type !== "object" || schema?.additionalProperties !== false) {
		failures.push("receipt schema must be an object schema with additionalProperties: false");
	}
	const required = schema?.required;
	if (!Array.isArray(required)) {
		failures.push("receipt schema must declare a required array");
	} else {
		for (const field of MINIMUM_RECEIPT_FIELDS) {
			if (!required.includes(field)) failures.push(`receipt schema must require ${field}`);
		}
	}
	const gateIds = (registry?.hardGates ?? []).map((gate) => gate.id);
	const acceptedStatuses = registry?.policy?.acceptedStatuses ?? [];
	const receiptProperties = schema?.properties ?? {};
	if (!sameStringSet(receiptProperties.gate_id?.enum ?? [], gateIds)) {
		failures.push(describeDifference("receipt schema gate_id enum", gateIds, receiptProperties.gate_id?.enum));
	}
	if (!sameStringSet(receiptProperties.decision?.enum ?? [], acceptedStatuses)) {
		failures.push(describeDifference("receipt schema decision enum", acceptedStatuses, receiptProperties.decision?.enum));
	}

	const closedBranches = (schema?.allOf ?? []).filter(
		(branch) => branch?.if?.properties?.decision?.const === "closed" && branch?.then,
	);
	if (closedBranches.length !== 1) {
		failures.push(`receipt schema must contain exactly one closed-decision branch, found ${closedBranches.length}`);
		return;
	}
	const closedThen = closedBranches[0].then;
	const closedRequired = closedThen.required ?? [];
	for (const clause of registry?.policy?.closedRequires ?? []) {
		const fields = CLOSED_REQUIREMENT_FIELDS[clause];
		if (!fields) {
			failures.push(`no receipt field mapping for registry.policy.closedRequires entry: ${clause}`);
			continue;
		}
		for (const field of fields) {
			if (!closedRequired.includes(field)) {
				failures.push(`closed-decision branch must require ${field} for registry.policy.closedRequires entry: ${clause}`);
			}
		}
	}

	const sampleGateId = gateIds[0];
	const sampleOwnerRole = registry?.hardGates?.[0]?.ownerRole ?? "unknown";
	if (validateReceiptRecord(unbackedClosedReceipt(sampleGateId, sampleOwnerRole), schema).length === 0) {
		failures.push("receipt schema accepts a closed record with no owner, reviewer, hash or candidate binding");
	}
	if (validateReceiptRecord(backedClosedReceipt(sampleGateId, sampleOwnerRole), schema).length > 0) {
		failures.push("receipt schema rejects a fully backed closed record");
	}
}

function checkClosedReceipt(receipt, { root, digest }) {
	const failures = [];
	const gate = receipt.gate_id;
	if (typeof receipt.owner_name !== "string" || receipt.owner_name === REQUIRED_SENTINEL) {
		failures.push(`${gate}: a closed receipt needs a named owner`);
	}
	if (typeof receipt.reviewer_name !== "string" || receipt.reviewer_name === REQUIRED_SENTINEL) {
		failures.push(`${gate}: a closed receipt needs a named reviewer`);
	}
	if (typeof receipt.reviewer_role !== "string" || receipt.reviewer_role === REQUIRED_SENTINEL) {
		failures.push(`${gate}: a closed receipt needs a reviewer role`);
	} else if (receipt.reviewer_role === receipt.owner_role) {
		failures.push(`${gate}: reviewer_role must differ from owner_role`);
	}
	if (typeof receipt.effective_version !== "string" || receipt.effective_version.length === 0) {
		failures.push(`${gate}: a closed receipt needs an effective version or Release Candidate`);
	}
	if (typeof receipt.recorded_at_utc !== "string" || receipt.recorded_at_utc.length === 0) {
		failures.push(`${gate}: a closed receipt needs a recorded date`);
	}
	if (typeof receipt.evidence_path !== "string" || receipt.evidence_path.length === 0) {
		failures.push(`${gate}: a closed receipt needs an evidence path`);
	} else {
		const evidencePath = isAbsolute(receipt.evidence_path) ? receipt.evidence_path : resolve(root, receipt.evidence_path);
		const inside = relative(root, evidencePath);
		if (inside.startsWith("..") || isAbsolute(inside)) {
			failures.push(`${gate}: evidence path must stay inside the repository (${receipt.evidence_path})`);
		} else if (!existsSync(evidencePath) || !statSync(evidencePath).isFile()) {
			failures.push(`${gate}: evidence path does not exist on disk (${receipt.evidence_path})`);
		} else {
			const actual = sha256File(evidencePath);
			if (actual !== receipt.evidence_sha256) {
				failures.push(`${gate}: evidence SHA-256 does not match ${receipt.evidence_path} (recorded ${receipt.evidence_sha256}, actual ${actual})`);
			}
		}
	}
	if (digest === UNKNOWN) {
		failures.push(`${gate}: no release inventory exists to bind a candidate digest, so the gate must stay open`);
	} else if (receipt.candidate_digest !== digest) {
		failures.push(`${gate}: candidate_digest does not match the current release-inventory digest`);
	}
	if (gate === "INV-001") {
		try {
			const loaded = readInvestorMetricDictionary({ root });
			const result = validateMetricDictionary(loaded);
			if (
				result.failures.length > 0 ||
				loaded.dictionary.status !== HELD ||
				loaded.dictionary.metrics.some((metric) => metric.status !== HELD || metric.candidate_digest !== digest)
			) {
				failures.push(`${gate}: investor metric dictionary must validate with every metric HELD and bound to this release candidate`);
			}
		} catch {
			failures.push(`${gate}: investor metric dictionary could not be validated`);
		}
	}
	return failures;
}

function validUtc(value) {
	return typeof value === "string" && UTC_TIMESTAMP.test(value) && !Number.isNaN(Date.parse(value))
		&& new Date(value).toISOString() === value;
}

function checkAssessmentArtifact(root, artifact, label, failures) {
	if (!artifact || typeof artifact.path !== "string" || !SHA256.test(artifact.sha256 ?? "")) {
		failures.push(`SEC-EXT-001: ${label} needs a repository-local path and SHA-256`);
		return;
	}
	const path = resolve(root, artifact.path);
	if (!existsSync(path) || !statSync(path).isFile()) {
		failures.push(`SEC-EXT-001: ${label} file is absent`);
		return;
	}
	const inside = relative(realpathSync(root), realpathSync(path));
	if (inside.startsWith("..") || isAbsolute(inside)) {
		failures.push(`SEC-EXT-001: ${label} must stay inside the evidence root`);
	} else if (sha256File(path) !== artifact.sha256) {
		failures.push(`SEC-EXT-001: ${label} SHA-256 mismatch`);
	}
}

function checkIndependentAssessment(receipt, { root, digest, now }) {
	const failures = [];
	let assessment;
	try {
		const path = resolve(root, receipt.evidence_path);
		const inside = relative(realpathSync(root), realpathSync(path));
		if (inside.startsWith("..") || isAbsolute(inside)) throw new Error("out-of-root assessment");
		assessment = JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return ["SEC-EXT-001: evidence must be a readable assessment JSON manifest"];
	}
	if (assessment?.schema_version !== 1 || assessment.candidate_digest !== digest) {
		failures.push("SEC-EXT-001: assessment manifest version or candidate digest mismatch");
	}
	if (typeof assessment?.assessor_name !== "string" || !assessment.assessor_name.trim() || assessment.assessor_name === REQUIRED_SENTINEL) {
		failures.push("SEC-EXT-001: independent assessor name is missing");
	}
	for (const scope of REQUIRED_ASSESSMENT_SCOPE) {
		if (!Array.isArray(assessment?.scope) || !assessment.scope.includes(scope)) {
			failures.push(`SEC-EXT-001: assessment scope omits ${scope}`);
		}
	}
	const dates = ["started_at_utc", "completed_at_utc", "retest_at_utc", "valid_until_utc"];
	for (const field of dates) if (!validUtc(assessment?.[field])) failures.push(`SEC-EXT-001: invalid ${field}`);
	if (dates.every((field) => validUtc(assessment?.[field]))) {
		const [started, completed, retest, expires] = dates.map((field) => Date.parse(assessment[field]));
		if (!(started <= completed && completed <= retest && retest <= now.getTime() && now.getTime() < expires)) {
			failures.push("SEC-EXT-001: assessment/retest chronology is invalid or evidence has expired");
		}
		if (!validUtc(receipt.recorded_at_utc) || Date.parse(receipt.recorded_at_utc) < retest || Date.parse(receipt.recorded_at_utc) > now.getTime()) {
			failures.push("SEC-EXT-001: receipt must be recorded after retest and no later than now");
		}
	}
	if (assessment?.unresolved_critical !== 0 || assessment?.unresolved_high !== 0) {
		failures.push("SEC-EXT-001: unresolved critical/high findings prevent closure");
	}
	if (assessment?.signed_report?.path === assessment?.retest_letter?.path) {
		failures.push("SEC-EXT-001: report and retest letter must be distinct artifacts");
	}
	checkAssessmentArtifact(root, assessment?.signed_report, "signed report", failures);
	checkAssessmentArtifact(root, assessment?.retest_letter, "retest letter", failures);
	return failures;
}

/**
 * Validate the receipt set against the registry and the schema.
 * Returns { failures, summary }; failures is empty for a complete, honest,
 * all-open set.
 */
export function validateCommercialGateReceipts({
	registry,
	receipts,
	schema,
	root = ROOT,
	receiptsPath = RECEIPTS_FILE,
	schemaPath = SCHEMA_FILE,
	releaseInventoryPath = RELEASE_INVENTORY_FILE,
	now = new Date(),
} = {}) {
	const failures = [];
	const gates = Array.isArray(registry?.hardGates) ? registry.hardGates : [];
	if (gates.length === 0) failures.push("registry hardGates must be a non-empty array");
	if (!Array.isArray(registry?.policy?.acceptedStatuses) || registry.policy.acceptedStatuses.length === 0) {
		failures.push("registry policy.acceptedStatuses must be a non-empty array");
	}
	if (!Array.isArray(registry?.policy?.closedRequires) || registry.policy.closedRequires.length === 0) {
		failures.push("registry policy.closedRequires must be a non-empty array");
	}

	validateSchemaAgainstRegistry(registry, schema, failures);

	const inventoryFullPath = isAbsolute(releaseInventoryPath) ? releaseInventoryPath : resolve(root, releaseInventoryPath);
	const digest = existsSync(inventoryFullPath) && statSync(inventoryFullPath).isFile() ? sha256File(inventoryFullPath) : UNKNOWN;

	const declaredReceipts = registry?.hardGateReceipts?.receiptsPath;
	const declaredSchema = registry?.hardGateReceipts?.schemaPath;
	if (declaredReceipts !== undefined && toRepoPath(declaredReceipts) !== toRepoPath(receiptsPath)) {
		failures.push(`registry hardGateReceipts.receiptsPath points at ${declaredReceipts} but receipts were read from ${toRepoPath(receiptsPath)}`);
	}
	if (declaredSchema !== undefined && toRepoPath(declaredSchema) !== toRepoPath(schemaPath)) {
		failures.push(`registry hardGateReceipts.schemaPath points at ${declaredSchema} but the schema was read from ${toRepoPath(schemaPath)}`);
	}

	if (!Array.isArray(receipts)) {
		failures.push("receipts file must be a JSON array with one record per hard gate");
		return {
			failures,
			summary: {
				hardGateCount: gates.length,
				receiptCount: 0,
				decisions: {},
				digest,
				digestSource: toRepoPath(releaseInventoryPath),
				digestSourceExists: digest !== UNKNOWN,
				receiptsPath: toRepoPath(receiptsPath),
				schemaPath: toRepoPath(schemaPath),
				gateReceipts: [],
			},
		};
	}

	const gateById = new Map(gates.map((gate) => [gate.id, gate]));
	const seen = new Map();
	const decisions = {};
	for (const [index, receipt] of receipts.entries()) {
		const label = typeof receipt?.gate_id === "string" ? receipt.gate_id : `receipt[${index}]`;
		for (const error of validateReceiptRecord(receipt, schema)) {
			failures.push(`${label}: ${error}`);
		}
		if (typeof receipt?.gate_id !== "string" || receipt.gate_id.length === 0) continue;
		if (seen.has(receipt.gate_id)) failures.push(`duplicate receipt for ${receipt.gate_id}`);
		seen.set(receipt.gate_id, receipt);
		decisions[receipt.decision] = (decisions[receipt.decision] ?? 0) + 1;

		const gate = gateById.get(receipt.gate_id);
		if (!gate) {
			failures.push(`${receipt.gate_id}: receipt does not correspond to a registry hard gate`);
			continue;
		}
		if (receipt.owner_role !== gate.ownerRole) {
			failures.push(`${receipt.gate_id}: owner_role must be copied from the registry (${gate.ownerRole})`);
		}
		if (receipt.decision !== gate.status) {
			failures.push(`${receipt.gate_id}: receipt decision ${receipt.decision} disagrees with registry status ${gate.status}`);
		}
		if (gate.receiptPath !== undefined && toRepoPath(gate.receiptPath) !== toRepoPath(receiptsPath)) {
			failures.push(`${receipt.gate_id}: registry receiptPath ${gate.receiptPath} does not point at ${toRepoPath(receiptsPath)}`);
		}
		if (receipt.evidence_path !== null || receipt.evidence_sha256 !== null) {
			if (!CLOSED_DECISIONS.includes(receipt.decision)) {
				failures.push(`${receipt.gate_id}: evidence_path and evidence_sha256 must be null while decision is ${receipt.decision}`);
			}
		}
		if (receipt.candidate_digest !== null && receipt.candidate_digest !== UNKNOWN && receipt.candidate_digest !== digest) {
			failures.push(`${receipt.gate_id}: candidate_digest does not match the current release-inventory digest`);
		}
		if (CLOSED_DECISIONS.includes(receipt.decision)) {
			failures.push(...checkClosedReceipt(receipt, { root, digest }));
			if (receipt.gate_id === "SEC-EXT-001" && typeof receipt.evidence_path === "string") {
				failures.push(...checkIndependentAssessment(receipt, { root, digest, now }));
			}
		}
	}

	for (const gate of gates) {
		if (!seen.has(gate.id)) failures.push(`${gate.id}: no receipt exists for this registry hard gate`);
	}

	return {
		failures,
		summary: {
			hardGateCount: gates.length,
			receiptCount: receipts.length,
			decisions,
			digest,
			digestSource: toRepoPath(releaseInventoryPath),
			digestSourceExists: digest !== UNKNOWN,
			receiptsPath: toRepoPath(receiptsPath),
			schemaPath: toRepoPath(schemaPath),
			gateReceipts: receipts.map((receipt) => ({
				gate_id: receipt?.gate_id ?? null,
				decision: receipt?.decision ?? null,
				external_inputs: Array.isArray(receipt?.external_inputs) ? receipt.external_inputs.length : 0,
			})),
		},
	};
}

export function readRegistryAndReceipts({ root = ROOT, registryPath = REGISTRY_FILE, env = process.env } = {}) {
	const registry = JSON.parse(readFileSync(resolve(root, registryPath), "utf8"));
	const receiptsPath = registry?.hardGateReceipts?.receiptsPath ?? RECEIPTS_FILE;
	const schemaPath = registry?.hardGateReceipts?.schemaPath ?? SCHEMA_FILE;
	return {
		registry,
		registryPath: toRepoPath(registryPath),
		schema: JSON.parse(readFileSync(resolve(root, schemaPath), "utf8")),
		schemaPath: toRepoPath(schemaPath),
		receipts: JSON.parse(readFileSync(resolve(root, receiptsPath), "utf8")),
		receiptsPath: toRepoPath(receiptsPath),
		releaseInventoryPath: env?.[RELEASE_INVENTORY_ENV] ?? RELEASE_INVENTORY_FILE,
	};
}

function report(result) {
	const { failures, summary } = result;
	const status = failures.length === 0 ? "PASS" : "FAIL";
	console.log(`Commercial receipt registry validation: ${status} (not a production GO decision)`);
	console.log(`Receipts: ${summary.receiptsPath} (${summary.receiptCount}/${summary.hardGateCount} hard gates)`);
	console.log(`Schema: ${summary.schemaPath}`);
	const decisions = Object.entries(summary.decisions ?? {})
		.map(([decision, count]) => `${decision}=${count}`)
		.join(", ");
	console.log(`Decisions: ${decisions || "none"}`);
	console.log(
		`Candidate digest: ${summary.digest} from ${summary.digestSource} (${summary.digestSourceExists ? "present" : "absent, so no gate may close"})`,
	);
	for (const gate of summary.gateReceipts ?? []) {
		console.log(`- ${gate.gate_id}: ${gate.decision} (${gate.external_inputs} external input(s) required)`);
	}
	if (failures.length > 0) {
		console.error(`${failures.length} receipt failure(s):`);
		for (const failure of failures) console.error(`- ${failure}`);
	}
}

export function main(argv = process.argv.slice(2)) {
	if (argv.includes("--help") || argv.includes("-h")) {
		console.log("Usage: node scripts/verify-commercial-gate-receipts.mjs");
		return 0;
	}
	const unknown = argv.filter((arg) => arg !== "--");
	if (unknown.length > 0) {
		console.error(`Unknown argument: ${unknown[0]}`);
		return 2;
	}
	const loaded = readRegistryAndReceipts();
	const result = validateCommercialGateReceipts(loaded);
	report(result);
	return result.failures.length === 0 ? 0 : 1;
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
	try {
		process.exitCode = main();
	} catch (error) {
		console.error(`Commercial gate receipt verification error: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 2;
	}
}
