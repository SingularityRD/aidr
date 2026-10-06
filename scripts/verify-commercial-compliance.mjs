#!/usr/bin/env node

/**
 * Local validator for the commercial compliance templates.
 *
 * This command intentionally validates two different things:
 *
 *   1. the license exception register has a required expiry field and cannot
 *      silently turn an expired or unbacked exception into an active approval;
 *   2. the privacy data-flow matrix has the fields needed to describe each
 *      flow and keeps unavailable facts as the explicit `unknown` sentinel.
 *
 * A structurally valid template may still be open. Open/unknown records are
 * reported in the summary and are not converted into a completed decision.
 * The validator is dependency-free so it can run from a source checkout.
 */

import { readFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const LICENSE_REGISTER_FILE = "docs/production-readiness/license-exception-register.json";
export const LICENSE_SCHEMA_FILE = "docs/production-readiness/license-exception-register.schema.json";
export const PRIVACY_MATRIX_FILE = "docs/production-readiness/privacy-data-flow-matrix.json";
export const PRIVACY_SCHEMA_FILE = "docs/production-readiness/privacy-data-flow-matrix.schema.json";

// Descriptive aliases keep the names explicit for callers that prefer the full
// artifact name over the shorter register/matrix constants.
export const LICENSE_EXCEPTION_REGISTER_FILE = LICENSE_REGISTER_FILE;
export const LICENSE_EXCEPTION_REGISTER_SCHEMA_FILE = LICENSE_SCHEMA_FILE;
export const PRIVACY_DATA_FLOW_MATRIX_FILE = PRIVACY_MATRIX_FILE;
export const PRIVACY_DATA_FLOW_MATRIX_SCHEMA_FILE = PRIVACY_SCHEMA_FILE;

export const UNKNOWN = "unknown";
export const JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema";

const STATUS_OPEN = "open";
const LICENSE_CLOSED_STATUSES = new Set(["approved", "expired", "revoked"]);
const PLACEHOLDER_VALUE = /^(?:tbd|to be determined|not known|n\/a|na|not held)$/iu;
const SKIPPED_METADATA_KEYS = new Set(["unknowns", "limitations"]);

// ---------------------------------------------------------------------------
// Small JSON Schema 2020-12 subset
// ---------------------------------------------------------------------------

function typeOf(value) {
	if (value === null) return "null";
	if (Array.isArray(value)) return "array";
	if (Number.isInteger(value)) return "integer";
	if (typeof value === "number") return "number";
	return typeof value;
}

function matchesType(value, expected) {
	const actual = typeOf(value);
	const expectedTypes = Array.isArray(expected) ? expected : [expected];
	return expectedTypes.some((type) => type === "number" ? actual === "number" || actual === "integer" : actual === type);
}

function deepEqual(left, right) {
	if (left === right) return true;
	if (typeof left !== typeof right || left === null || right === null) return false;
	if (typeof left !== "object") return false;
	if (Array.isArray(left) !== Array.isArray(right)) return false;
	const leftKeys = Object.keys(left);
	const rightKeys = Object.keys(right);
	if (leftKeys.length !== rightKeys.length) return false;
	return leftKeys.every((key) => Object.hasOwn(right, key) && deepEqual(left[key], right[key]));
}

function resolveRef(ref, rootSchema) {
	if (typeof ref !== "string" || !ref.startsWith("#/")) {
		throw new Error(`unsupported schema reference ${JSON.stringify(ref)}`);
	}
	let node = rootSchema;
	for (const segment of ref.slice(2).split("/")) {
		const key = segment.replaceAll("~1", "/").replaceAll("~0", "~");
		if (node === null || typeof node !== "object" || !Object.hasOwn(node, key)) {
			throw new Error(`unresolvable schema reference ${ref}`);
		}
		node = node[key];
	}
	return node;
}

function validateCollect(value, schema, rootSchema, path) {
	const errors = [];
	validateNode(value, schema, rootSchema, path, errors);
	return errors;
}

function validateNode(value, schema, rootSchema, path, errors) {
	if (schema === null || typeof schema !== "object") {
		errors.push(`${path}: schema node is not an object`);
		return;
	}
	if (schema.$ref !== undefined) {
		validateNode(value, resolveRef(schema.$ref, rootSchema), rootSchema, path, errors);
		return;
	}
	if (schema.type !== undefined && !matchesType(value, schema.type)) {
		errors.push(`${path}: expected type ${Array.isArray(schema.type) ? schema.type.join(" or ") : schema.type}, got ${typeOf(value)}`);
		return;
	}
	if (Object.hasOwn(schema, "const") && !deepEqual(value, schema.const)) {
		errors.push(`${path}: expected ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`);
	}
	if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => deepEqual(candidate, value))) {
		errors.push(`${path}: value ${JSON.stringify(value)} is not in the declared enum`);
	}
	if (typeof value === "string") {
		if (typeof schema.minLength === "number" && value.length < schema.minLength) {
			errors.push(`${path}: string is shorter than minLength ${schema.minLength}`);
		}
		if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) {
			errors.push(`${path}: value ${JSON.stringify(value)} does not match ${schema.pattern}`);
		}
	}
	if (typeof value === "number" && typeof schema.minimum === "number" && value < schema.minimum) {
		errors.push(`${path}: value ${value} is below minimum ${schema.minimum}`);
	}
	if (Array.isArray(value)) {
		if (typeof schema.minItems === "number" && value.length < schema.minItems) {
			errors.push(`${path}: array has ${value.length} item(s), below minItems ${schema.minItems}`);
		}
		if (schema.uniqueItems === true && new Set(value.map((item) => JSON.stringify(item))).size !== value.length) {
			errors.push(`${path}: array items must be unique`);
		}
		if (schema.items !== undefined) {
			value.forEach((item, index) => validateNode(item, schema.items, rootSchema, `${path}[${index}]`, errors));
		}
	}
	if (schema.oneOf !== undefined) {
		const matched = schema.oneOf.filter((candidate) => validateCollect(value, candidate, rootSchema, path).length === 0);
		if (matched.length !== 1) errors.push(`${path}: expected exactly one oneOf branch, matched ${matched.length}`);
	}
	if (schema.anyOf !== undefined) {
		const matched = schema.anyOf.some((candidate) => validateCollect(value, candidate, rootSchema, path).length === 0);
		if (!matched) errors.push(`${path}: no anyOf branch matched`);
	}
	if (Array.isArray(schema.allOf)) {
		for (const branch of schema.allOf) validateNode(value, branch, rootSchema, path, errors);
	}
	if (schema.not !== undefined && validateCollect(value, schema.not, rootSchema, path).length === 0) {
		errors.push(`${path}: value matches a forbidden schema branch`);
	}
	if (schema.if !== undefined) {
		const conditionMatched = validateCollect(value, schema.if, rootSchema, path).length === 0;
		if (conditionMatched && schema.then !== undefined) validateNode(value, schema.then, rootSchema, path, errors);
		if (!conditionMatched && schema.else !== undefined) validateNode(value, schema.else, rootSchema, path, errors);
	}

	const isObject = value !== null && typeof value === "object" && !Array.isArray(value);
	if (!isObject || (schema.properties === undefined && schema.required === undefined && schema.additionalProperties === undefined)) return;
	for (const key of schema.required ?? []) {
		if (!Object.hasOwn(value, key)) errors.push(`${path}: missing required property '${key}'`);
	}
	for (const [key, child] of Object.entries(value)) {
		const propertySchema = schema.properties?.[key];
		if (propertySchema !== undefined) {
			validateNode(child, propertySchema, rootSchema, `${path}.${key}`, errors);
		} else if (schema.additionalProperties === false) {
			errors.push(`${path}: additional property '${key}' is not allowed`);
		} else if (schema.additionalProperties !== undefined && typeof schema.additionalProperties === "object") {
			validateNode(child, schema.additionalProperties, rootSchema, `${path}.${key}`, errors);
		}
	}
}

/** Validate a JSON value against a local JSON Schema and return error strings. */
export function validateAgainstSchema(value, schema) {
	if (schema === null || typeof schema !== "object") return ["$: schema must be an object"];
	const errors = [];
	validateNode(value, schema, schema, "$", errors);
	return errors;
}

// ---------------------------------------------------------------------------
// Shared template checks
// ---------------------------------------------------------------------------

function isRecord(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function collectUnknownPaths(value, path = "", found = [], skipKeys = SKIPPED_METADATA_KEYS) {
	if (value === UNKNOWN) {
		found.push(path || "$self");
		return found;
	}
	if (Array.isArray(value)) {
		value.forEach((item, index) => collectUnknownPaths(item, `${path}[${index}]`, found, skipKeys));
		return found;
	}
	if (!isRecord(value)) return found;
	for (const [key, child] of Object.entries(value)) {
		if (skipKeys.has(key)) continue;
		collectUnknownPaths(child, path ? `${path}.${key}` : key, found, skipKeys);
	}
	return found;
}

function findBlankStrings(value, path = "$", found = []) {
	if (typeof value === "string") {
		if (value.trim().length === 0) found.push(`${path}: blank string`);
		return found;
	}
	if (Array.isArray(value)) {
		value.forEach((item, index) => findBlankStrings(item, `${path}[${index}]`, found));
		return found;
	}
	if (!isRecord(value)) return found;
	for (const [key, child] of Object.entries(value)) findBlankStrings(child, `${path}.${key}`, found);
	return found;
}

function findImplicitPlaceholders(value, path = "$", found = [], skipKeys = SKIPPED_METADATA_KEYS) {
	if (typeof value === "string") {
		if (value !== UNKNOWN && PLACEHOLDER_VALUE.test(value.trim())) found.push(`${path}: use the explicit '${UNKNOWN}' sentinel instead of ${JSON.stringify(value)}`);
		return found;
	}
	if (Array.isArray(value)) {
		value.forEach((item, index) => findImplicitPlaceholders(item, `${path}[${index}]`, found, skipKeys));
		return found;
	}
	if (!isRecord(value)) return found;
	for (const [key, child] of Object.entries(value)) {
		if (skipKeys.has(key)) continue;
		findImplicitPlaceholders(child, `${path}.${key}`, found, skipKeys);
	}
	return found;
}

function declarationsCover(declarations, unknownPath) {
	if (!Array.isArray(declarations)) return false;
	const normalized = unknownPath.replace(/^\$\.?/u, "");
	return declarations.some((declaration) => {
		if (typeof declaration !== "string") return false;
		const candidate = declaration.trim().replace(/^\$\.?/u, "");
		return candidate === normalized || candidate === unknownPath;
	});
}

function validateUnknownDeclarations(record, label, unknownPaths) {
	const failures = [];
	const declarations = record?.unknowns;
	for (const unknownPath of unknownPaths) {
		if (!declarationsCover(declarations, unknownPath)) {
			failures.push(`${label}: unknown value at ${unknownPath} must be listed in that record's unknowns`);
		}
	}
	return failures;
}

function parseDateOnly(value) {
	if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/u.test(value)) return null;
	const [year, month, day] = value.split("-").map(Number);
	if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) return null;
	const date = new Date(Date.UTC(year, month - 1, day));
	if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null;
	return date;
}

function startOfUtcDay(now = new Date()) {
	const date = now instanceof Date ? new Date(now.getTime()) : new Date(now);
	if (Number.isNaN(date.getTime())) return null;
	return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

function requireKnownValue(record, field, label, failures) {
	if (record?.[field] === UNKNOWN || typeof record?.[field] !== "string" || record[field].trim().length === 0) {
		failures.push(`${label}: approved exception needs a known ${field}`);
	}
}

function validateSchemaIdentity(schema, expectedId, label, failures) {
	if (schema?.$schema !== JSON_SCHEMA_DIALECT) failures.push(`${label}: schema must declare JSON Schema draft 2020-12`);
	if (schema?.$id !== expectedId) failures.push(`${label}: schema has an unexpected $id`);
	if (schema?.type !== "object" || schema?.additionalProperties !== false) {
		failures.push(`${label}: schema must be an object with additionalProperties:false`);
	}
}

// ---------------------------------------------------------------------------
// License exception register
// ---------------------------------------------------------------------------

const LICENSE_SCHEMA_ID = "https://singularityrd.dev/schemas/license-exception-register.schema.json";

/** Validate one local license exception register. */
export function validateLicenseExceptionRegister(register, schema, { now = new Date() } = {}) {
	const failures = [];
	const effectiveSchema = schema ?? readJson(resolve(ROOT, LICENSE_SCHEMA_FILE));
	validateSchemaIdentity(effectiveSchema, LICENSE_SCHEMA_ID, "license exception schema", failures);
	failures.push(...validateAgainstSchema(register, effectiveSchema));
	failures.push(...findBlankStrings(register));
	failures.push(...findImplicitPlaceholders(register));
	if (!isRecord(register)) {
		return { failures, summary: { status: null, entries: 0, unknown_values: 0, open_entries: 0 } };
	}

	const topUnknowns = collectUnknownPaths(register, "", [], new Set([...SKIPPED_METADATA_KEYS, "entries"]));
	failures.push(...validateUnknownDeclarations(register, "license register", topUnknowns));
	const entries = Array.isArray(register.entries) ? register.entries : [];
	const seen = new Set();
	const today = startOfUtcDay(now);
	let openEntries = 0;
	let unknownValues = topUnknowns.length;

	for (const [index, entry] of entries.entries()) {
		const label = typeof entry?.exception_id === "string" ? entry.exception_id : `entries[${index}]`;
		if (!isRecord(entry)) continue;
		if (typeof entry.exception_id === "string") {
			if (seen.has(entry.exception_id)) failures.push(`${label}: duplicate exception_id`);
			seen.add(entry.exception_id);
		}
		const unknownPaths = collectUnknownPaths(entry);
		unknownValues += unknownPaths.length;
		failures.push(...validateUnknownDeclarations(entry, label, unknownPaths));
		if (entry.status === STATUS_OPEN || entry.status === "in_review" || entry.status === UNKNOWN) openEntries += 1;

		const expiry = entry.expires_at === UNKNOWN ? null : parseDateOnly(entry.expires_at);
		if (entry.expires_at !== UNKNOWN && expiry === null) {
			failures.push(`${label}: expires_at must be a real YYYY-MM-DD date or '${UNKNOWN}'`);
		}
		if (today !== null && expiry !== null && expiry.getTime() <= today.getTime() && !["expired", "revoked"].includes(entry.status)) {
			failures.push(`${label}: expires_at has passed; mark the entry expired/revoked or record a future expiry`);
		}
		if (entry.status === "expired") {
			if (expiry === null) failures.push(`${label}: expired entry needs a concrete expires_at date`);
			else if (today !== null && expiry.getTime() > today.getTime()) failures.push(`${label}: expired entry has a future expires_at date`);
		}
		if (entry.status === "approved") {
			for (const field of ["component", "version", "declared_license", "scope", "reason", "risk", "owner", "approver"]) {
				requireKnownValue(entry, field, label, failures);
			}
			if (entry.exception_type === UNKNOWN) failures.push(`${label}: approved exception needs a known exception_type`);
			if (entry.unknowns?.length > 0 || unknownPaths.length > 0) failures.push(`${label}: approved exception cannot retain unknown values`);
			if (entry.approved_at === UNKNOWN || parseDateOnly(entry.approved_at) === null) {
				failures.push(`${label}: approved exception needs a concrete approved_at date`);
			} else if (today !== null && parseDateOnly(entry.approved_at).getTime() > today.getTime()) {
				failures.push(`${label}: approved_at cannot be in the future`);
			}
			if (expiry === null) failures.push(`${label}: approved exception needs a concrete expires_at date`);
			else if (today !== null && expiry.getTime() <= today.getTime()) failures.push(`${label}: approved exception expires_at must be in the future`);
			if (!Array.isArray(entry.evidence) || entry.evidence.length === 0 || entry.evidence.some((item) => item === UNKNOWN)) {
				failures.push(`${label}: approved exception needs non-unknown evidence`);
			}
		}
	}

	if (register.status === "closed") {
		if (entries.length === 0) failures.push("license register: closed status needs at least one entry");
		if (topUnknowns.length > 0 || register.unknowns?.length > 0 || entries.some((entry) => entry?.unknowns?.length > 0)) {
			failures.push("license register: closed status cannot contain unresolved unknowns");
		}
		for (const [index, entry] of entries.entries()) {
			if (!LICENSE_CLOSED_STATUSES.has(entry?.status)) failures.push(`entries[${index}]: closed register entries must be approved, expired, or revoked`);
		}
	}

	return {
		failures,
		summary: {
			status: register.status ?? null,
			entries: entries.length,
			unknown_values: unknownValues,
			open_entries: openEntries,
		},
	};
}

// ---------------------------------------------------------------------------
// Privacy data-flow matrix
// ---------------------------------------------------------------------------

const PRIVACY_SCHEMA_ID = "https://singularityrd.dev/schemas/privacy-data-flow-matrix.schema.json";

/** Validate one local privacy data-flow matrix. */
export function validatePrivacyDataFlowMatrix(matrix, schema, { now = new Date() } = {}) {
	// `now` is accepted for a common validator call shape; matrix dates are
	// intentionally not interpreted as proof of a deployed measurement.
	void now;
	const failures = [];
	const effectiveSchema = schema ?? readJson(resolve(ROOT, PRIVACY_SCHEMA_FILE));
	validateSchemaIdentity(effectiveSchema, PRIVACY_SCHEMA_ID, "privacy matrix schema", failures);
	failures.push(...validateAgainstSchema(matrix, effectiveSchema));
	failures.push(...findBlankStrings(matrix));
	failures.push(...findImplicitPlaceholders(matrix));
	if (!isRecord(matrix)) {
		return { failures, summary: { status: null, flows: 0, unknown_values: 0, open_flows: 0 } };
	}

	const topUnknowns = collectUnknownPaths(matrix, "", [], new Set([...SKIPPED_METADATA_KEYS, "flows"]));
	failures.push(...validateUnknownDeclarations(matrix, "privacy matrix", topUnknowns));
	const flows = Array.isArray(matrix.flows) ? matrix.flows : [];
	const seen = new Set();
	let unknownValues = topUnknowns.length;
	let openFlows = 0;

	for (const [index, flow] of flows.entries()) {
		const label = typeof flow?.flow_id === "string" ? flow.flow_id : `flows[${index}]`;
		if (!isRecord(flow)) continue;
		if (typeof flow.flow_id === "string") {
			if (seen.has(flow.flow_id)) failures.push(`${label}: duplicate flow_id`);
			seen.add(flow.flow_id);
		}
		const unknownPaths = collectUnknownPaths(flow);
		unknownValues += unknownPaths.length;
		failures.push(...validateUnknownDeclarations(flow, label, unknownPaths));
		if (flow.status === UNKNOWN || flow.status === "inventory") openFlows += 1;
		if (["measured", "accepted"].includes(flow.status) && (unknownPaths.length > 0 || flow.unknowns?.length > 0)) {
			failures.push(`${label}: ${flow.status} flow cannot retain unresolved unknowns`);
		}
		if (["measured", "accepted"].includes(flow.status) && Array.isArray(flow.evidence) && flow.evidence.every(evidence => /^Source inspection only:/u.test(evidence))) {
			failures.push(`${label}: source inspection alone cannot establish a ${flow.status} deployment flow`);
		}
	}

	if (matrix.status === "accepted") {
		if (topUnknowns.length > 0 || matrix.unknowns?.length > 0) failures.push("privacy matrix: accepted status cannot contain unresolved unknowns");
		for (const [index, flow] of flows.entries()) {
			if (flow?.status !== "accepted") failures.push(`flows[${index}]: accepted matrix requires every flow to be accepted`);
		}
	}

	return {
		failures,
		summary: {
			status: matrix.status ?? null,
			flows: flows.length,
			unknown_values: unknownValues,
			open_flows: openFlows,
		},
	};
}

// ---------------------------------------------------------------------------
// Combined load/validate/CLI helpers
// ---------------------------------------------------------------------------

function readJson(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

function resolveArtifactPath(root, value) {
	return isAbsolute(value) ? value : resolve(root, value);
}

export function readComplianceArtifacts({
	root = ROOT,
	licenseRegisterPath = LICENSE_REGISTER_FILE,
	licenseSchemaPath = LICENSE_SCHEMA_FILE,
	privacyMatrixPath = PRIVACY_MATRIX_FILE,
	privacySchemaPath = PRIVACY_SCHEMA_FILE,
} = {}) {
	const paths = {
		licenseRegisterPath: resolveArtifactPath(root, licenseRegisterPath),
		licenseSchemaPath: resolveArtifactPath(root, licenseSchemaPath),
		privacyMatrixPath: resolveArtifactPath(root, privacyMatrixPath),
		privacySchemaPath: resolveArtifactPath(root, privacySchemaPath),
	};
	return {
		root,
		paths,
		licenseRegister: readJson(paths.licenseRegisterPath),
		licenseSchema: readJson(paths.licenseSchemaPath),
		privacyMatrix: readJson(paths.privacyMatrixPath),
		privacySchema: readJson(paths.privacySchemaPath),
	};
}

/** Validate both shipped local templates and return one deterministic summary. */
export function validateCommercialCompliance(input = {}) {
	const loaded = input.licenseRegister === undefined || input.privacyMatrix === undefined
		? readComplianceArtifacts(input)
		: input;
	const license = validateLicenseExceptionRegister(loaded.licenseRegister, loaded.licenseSchema, input);
	const privacy = validatePrivacyDataFlowMatrix(loaded.privacyMatrix, loaded.privacySchema, input);
	return {
		failures: [...license.failures.map((failure) => `license: ${failure}`), ...privacy.failures.map((failure) => `privacy: ${failure}`)],
		license: license.summary,
		privacy: privacy.summary,
	};
}

function takeOption(argv, index, name) {
	const value = argv[index];
	if (value === `${name}=`) return { value: "", next: index };
	if (value?.startsWith(`${name}=`)) return { value: value.slice(name.length + 1), next: index };
	if (value === name) return { value: argv[index + 1], next: index + 1 };
	return null;
}

function printReport(result, asJson = false) {
	if (asJson) {
		console.log(JSON.stringify({ status: result.failures.length === 0 ? "VALID_OPEN_OR_COMPLETE" : "INVALID", ...result }, null, 2));
		return;
	}
	const status = result.failures.length === 0 ? "VALID_OPEN_OR_COMPLETE" : "INVALID";
	console.log(`Commercial compliance templates: ${status}`);
	console.log(`- license exceptions: ${result.license.entries} entr(y/ies), ${result.license.unknown_values} unknown value(s), ${result.license.open_entries} open entr(y/ies)`);
	console.log(`- privacy data flows: ${result.privacy.flows} flow(s), ${result.privacy.unknown_values} unknown value(s), ${result.privacy.open_flows} open flow(s)`);
	if (result.failures.length > 0) {
		console.error(`${result.failures.length} validation failure(s):`);
		for (const failure of result.failures) console.error(`- ${failure}`);
	}
	if (result.failures.length === 0 && (result.license.unknown_values > 0 || result.privacy.unknown_values > 0)) {
		console.log("Unknown values remain explicit; this run does not infer completion or external acceptance.");
	}
}

export function main(argv = process.argv.slice(2)) {
	if (argv.includes("--help") || argv.includes("-h")) {
		console.log("Usage: node scripts/verify-commercial-compliance.mjs [--root DIR] [--license-register FILE] [--privacy-matrix FILE]");
		console.log("       Optional: --license-schema FILE --privacy-schema FILE --json");
		return 0;
	}
	const options = { root: ROOT };
	let asJson = false;
	for (let index = 0; index < argv.length; index += 1) {
		if (argv[index] === "--json") {
			asJson = true;
			continue;
		}
		let option = null;
		for (const name of ["--root", "--license-register", "--license-schema", "--privacy-matrix", "--privacy-schema"]) {
			option = takeOption(argv, index, name);
			if (!option) continue;
			if (typeof option.value !== "string" || option.value.length === 0) {
				console.error(`${name} needs a non-empty path`);
				return 2;
			}
			const key = name.slice(2).replaceAll("-", "");
			const keys = {
				root: "root",
				licenseregister: "licenseRegisterPath",
				licenseschema: "licenseSchemaPath",
				privacymatrix: "privacyMatrixPath",
				privacyschema: "privacySchemaPath",
			};
			options[keys[key]] = option.value;
			index = option.next;
			break;
		}
		if (option) continue;
		console.error(`Unknown argument: ${argv[index]}`);
		return 2;
	}
	try {
		const result = validateCommercialCompliance(options);
		printReport(result, asJson);
		return result.failures.length === 0 ? 0 : 1;
	} catch (error) {
		console.error(`Commercial compliance validation error: ${error instanceof Error ? error.message : String(error)}`);
		return 2;
	}
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (invokedDirectly) process.exitCode = main();
