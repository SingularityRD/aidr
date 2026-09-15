#!/usr/bin/env node

/**
 * Validate the investor metric dictionary without manufacturing evidence.
 *
 * The dictionary is a definition and evidence-status record, not a source of
 * measurements. A metric may be incomplete, but every missing required field
 * must be the exact sentinel "unknown" and the metric must remain NOT_HELD.
 * A held metric must have all required fields, an independent reviewer, and an
 * existing repository evidence file whose SHA-256 matches.
 *
 * Usage:
 *   node scripts/validate-investor-metric-dictionary.mjs
 *   node scripts/validate-investor-metric-dictionary.mjs --help
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DICTIONARY_FILE = "docs/production-readiness/investor-metric-dictionary.json";
export const SCHEMA_FILE = "docs/production-readiness/investor-metric-dictionary.schema.json";
export const TEMPLATE_FILE = "docs/production-readiness/investor-metric-dictionary-template.md";

export const UNKNOWN = "unknown";
export const NOT_HELD = "NOT_HELD";
export const HELD = "HELD";
export const STATUS_VOCABULARY = Object.freeze([NOT_HELD, HELD]);

export const METRIC_REQUIRED_FIELDS = Object.freeze([
	"metric_id",
	"name",
	"formula",
	"denominator",
	"source",
	"source_query",
	"candidate",
	"candidate_digest",
	"candidate_ref",
	"environment",
	"fixture_version",
	"window",
	"sample_size",
	"target_actual_status",
	"confidence",
	"owner",
	"reviewer",
	"evidence_ref",
	"evidence_sha256",
	"reviewed_at_utc",
	"limitations",
	"status",
]);

// These are the fields that establish whether a definition is sufficiently
// backed to be held. `limitations` is validated separately as a non-empty list.
export const COMPLETENESS_FIELDS = Object.freeze([
	"formula",
	"denominator",
	"source",
	"source_query",
	"candidate",
	"candidate_digest",
	"candidate_ref",
	"environment",
	"fixture_version",
	"window",
	"sample_size",
	"target_actual_status",
	"confidence",
	"owner",
	"reviewer",
	"evidence_ref",
	"evidence_sha256",
	"reviewed_at_utc",
]);

const SHA256 = /^[0-9a-f]{64}$/u;
const UTC_TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const TARGET_ACTUAL_STATUSES = new Set(["target_not_set", "target_met", "target_missed"]);

const PLACEHOLDER_VALUES = new Set([
	"UNKNOWN",
	"TBD",
	"TODO",
	"REQUIRED",
	"N/A",
	"NA",
	"NONE",
	"NOT HELD",
	"NOT_HELD",
	"NOT AVAILABLE",
	"UNAVAILABLE",
	"MISSING",
	"PENDING",
]);

const SUPPORTED_SCHEMA_KEYWORDS = new Set([
	"$schema",
	"$id",
	"$defs",
	"$ref",
	"title",
	"description",
	"type",
	"enum",
	"const",
	"required",
	"properties",
	"additionalProperties",
	"items",
	"minItems",
	"minLength",
	"minimum",
	"pattern",
	"oneOf",
	"allOf",
	"not",
	"if",
	"then",
	"else",
]);

function typeOf(value) {
	if (value === null) return "null";
	if (Array.isArray(value)) return "array";
	if (Number.isInteger(value)) return "integer";
	if (typeof value === "number") return "number";
	return typeof value;
}

function matchesType(value, expected) {
	const actual = typeOf(value);
	if (expected === "number") return actual === "number" || actual === "integer";
	return actual === expected;
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
		throw new Error(`unsupported $ref ${JSON.stringify(ref)}`);
	}
	let node = rootSchema;
	for (const segment of ref.slice(2).split("/")) {
		const key = segment.replaceAll("~1", "/").replaceAll("~0", "~");
		if (node === null || typeof node !== "object" || !Object.hasOwn(node, key)) {
			throw new Error(`unresolvable $ref ${ref}`);
		}
		node = node[key];
	}
	return node;
}

function validateSchemaKeywords(schema, path) {
	if (schema === null || typeof schema !== "object" || Array.isArray(schema)) return [];
	return Object.keys(schema)
		.filter((keyword) => !SUPPORTED_SCHEMA_KEYWORDS.has(keyword))
		.map((keyword) => `${path}: unsupported JSON Schema keyword ${keyword}`);
}

function collectSchemaErrors(value, schema, rootSchema, path, errors) {
	if (schema === null || typeof schema !== "object" || Array.isArray(schema)) {
		errors.push(`${path}: schema node must be an object`);
		return;
	}
	if (schema.$ref !== undefined) {
		collectSchemaErrors(value, resolveRef(schema.$ref, rootSchema), rootSchema, path, errors);
		return;
	}
	errors.push(...validateSchemaKeywords(schema, path));
	if (schema.type !== undefined) {
		const types = Array.isArray(schema.type) ? schema.type : [schema.type];
		if (!types.some((type) => matchesType(value, type))) {
			errors.push(`${path}: expected type ${types.join(" or ")}, got ${typeOf(value)}`);
			return;
		}
	}
	if (schema.const !== undefined && !deepEqual(schema.const, value)) {
		errors.push(`${path}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`);
	}
	if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => deepEqual(candidate, value))) {
		errors.push(`${path}: value ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
	}
	if (typeof value === "string") {
		if (typeof schema.minLength === "number" && value.length < schema.minLength) {
			errors.push(`${path}: string is shorter than minLength ${schema.minLength}`);
		}
		if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) {
			errors.push(`${path}: value ${JSON.stringify(value)} does not match pattern ${schema.pattern}`);
		}
	}
	if (typeof value === "number" && typeof schema.minimum === "number" && value < schema.minimum) {
		errors.push(`${path}: value ${value} is below minimum ${schema.minimum}`);
	}
	if (Array.isArray(value)) {
		if (typeof schema.minItems === "number" && value.length < schema.minItems) {
			errors.push(`${path}: array has ${value.length} item(s), below minItems ${schema.minItems}`);
		}
		if (schema.items !== undefined) {
			value.forEach((item, index) => collectSchemaErrors(item, schema.items, rootSchema, `${path}[${index}]`, errors));
		}
	}
	if (schema.not !== undefined && collectSchemaErrorsFor(value, schema.not, rootSchema, path).length === 0) {
		errors.push(`${path}: matches a forbidden schema shape`);
	}
	if (Array.isArray(schema.oneOf)) {
		const matches = schema.oneOf.filter((candidate) => collectSchemaErrorsFor(value, candidate, rootSchema, path).length === 0);
		if (matches.length !== 1) {
			errors.push(`${path}: expected exactly one oneOf subschema to match, ${matches.length} matched`);
		}
	}
	if (Array.isArray(schema.allOf)) {
		for (const branch of schema.allOf) collectSchemaErrors(value, branch, rootSchema, path, errors);
	}
	if (schema.if !== undefined) {
		if (collectSchemaErrorsFor(value, schema.if, rootSchema, path).length === 0) {
			if (schema.then !== undefined) collectSchemaErrors(value, schema.then, rootSchema, path, errors);
		} else if (schema.else !== undefined) {
			collectSchemaErrors(value, schema.else, rootSchema, path, errors);
		}
	}
	const objectValue = value !== null && typeof value === "object" && !Array.isArray(value);
	if (objectValue && (schema.properties !== undefined || schema.required !== undefined || schema.additionalProperties !== undefined)) {
		for (const key of schema.required ?? []) {
			if (!Object.hasOwn(value, key)) errors.push(`${path}: missing required property '${key}'`);
		}
		for (const [key, child] of Object.entries(value)) {
			const propertySchema = schema.properties?.[key];
			if (propertySchema !== undefined) {
				collectSchemaErrors(child, propertySchema, rootSchema, `${path}.${key}`, errors);
			} else if (schema.additionalProperties === false) {
				errors.push(`${path}: additional property '${key}' is not allowed`);
			} else if (schema.additionalProperties !== undefined && typeof schema.additionalProperties === "object") {
				collectSchemaErrors(child, schema.additionalProperties, rootSchema, `${path}.${key}`, errors);
			}
		}
	}
}

function collectSchemaErrorsFor(value, schema, rootSchema, path) {
	const errors = [];
	collectSchemaErrors(value, schema, rootSchema, path, errors);
	return errors;
}

/** Validate a value against the local JSON Schema subset used by this record. */
export function validateAgainstSchema(value, schema) {
	return collectSchemaErrorsFor(value, schema, schema, "$");
}

function isUnknown(value) {
	return value === UNKNOWN;
}

function isKnown(value) {
	return typeof value === "string" && value.trim().length > 0 && !PLACEHOLDER_VALUES.has(value.trim().toUpperCase());
}

function hasKnownValue(field, value) {
	switch (field) {
		case "candidate_digest":
		case "evidence_sha256":
			return typeof value === "string" && SHA256.test(value);
		case "sample_size":
			return Number.isInteger(value) && value >= 1;
		case "target_actual_status":
			return typeof value === "string" && TARGET_ACTUAL_STATUSES.has(value);
		case "reviewed_at_utc":
			return typeof value === "string" && UTC_TIMESTAMP.test(value);
		default:
			return isKnown(value);
	}
}

function hasUsableLimitations(value) {
	return Array.isArray(value) && value.length > 0 && value.every((item) => isKnown(item));
}

/** Return the missing evidence fields without changing the metric. */
export function metricCompleteness(metric) {
	const missing = COMPLETENESS_FIELDS.filter((field) => !hasKnownValue(field, metric?.[field]));
	if (!hasUsableLimitations(metric?.limitations)) missing.push("limitations");
	return {
		complete: missing.length === 0,
		missing,
	};
}

function sameStringSet(left, right) {
	const a = new Set(left ?? []);
	const b = new Set(right ?? []);
	if (a.size !== b.size) return false;
	for (const value of a) if (!b.has(value)) return false;
	return true;
}

function difference(label, expected, actual) {
	const expectedSet = new Set(expected ?? []);
	const actualSet = new Set(actual ?? []);
	const missing = [...expectedSet].filter((value) => !actualSet.has(value));
	const extra = [...actualSet].filter((value) => !expectedSet.has(value));
	const detail = [];
	if (missing.length > 0) detail.push(`missing ${JSON.stringify(missing)}`);
	if (extra.length > 0) detail.push(`unexpected ${JSON.stringify(extra)}`);
	return `${label} differs (${detail.join(", ")})`;
}

function validateSchemaContract(schema, failures) {
	if (schema?.$schema !== "https://json-schema.org/draft/2020-12/schema") {
		failures.push("metric dictionary schema must declare the JSON Schema draft 2020-12 dialect");
	}
	if (schema?.type !== "object" || schema?.additionalProperties !== false) {
		failures.push("metric dictionary schema must be an object schema with additionalProperties: false");
	}
	const topRequired = schema?.required;
	if (!Array.isArray(topRequired)) {
		failures.push("metric dictionary schema must declare a required array");
	} else {
		for (const field of ["schema_version", "status", "metrics"]) {
			if (!topRequired.includes(field)) failures.push(`metric dictionary schema must require ${field}`);
		}
	}
	const statusEnum = schema?.properties?.status?.enum;
	if (!sameStringSet(statusEnum, STATUS_VOCABULARY)) {
		failures.push(difference("metric dictionary schema status vocabulary", STATUS_VOCABULARY, statusEnum));
	}
	const metricSchema = schema?.$defs?.metric;
	if (metricSchema?.type !== "object" || metricSchema?.additionalProperties !== false) {
		failures.push("metric dictionary schema must define $defs.metric as a closed object schema");
		return;
	}
	if (!Array.isArray(metricSchema.required)) {
		failures.push("metric dictionary $defs.metric must declare a required array");
	} else {
		for (const field of METRIC_REQUIRED_FIELDS) {
			if (!metricSchema.required.includes(field)) failures.push(`metric dictionary schema must require ${field} per metric`);
		}
	}
	for (const field of METRIC_REQUIRED_FIELDS) {
		if (metricSchema.properties?.[field] === undefined) failures.push(`metric dictionary schema must define ${field} per metric`);
	}
}

const TEMPLATE_COLUMNS = Object.freeze([
	"ID",
	"Name",
	"Formula",
	"Denominator",
	"Source",
	"Candidate",
	"Environment",
	"Window",
	"Owner",
	"Reviewer",
	"Limitations",
	"Status",
]);

const TEMPLATE_COMPARE_FIELDS = Object.freeze([
	"name",
	"formula",
	"denominator",
	"source",
	"candidate",
	"environment",
	"window",
	"owner",
	"reviewer",
	"limitations",
	"status",
]);

function markdownCells(line) {
	const trimmed = line.trim();
	if (!trimmed.startsWith("|") || !trimmed.endsWith("|")) return null;
	return trimmed
		.slice(1, -1)
		.split("|")
		.map((cell) => cell.trim().replaceAll("\\|", "|"));
}

/** Parse the structured metric table used by the human dictionary mirror. */
export function parseTemplateMetricRows(markdown) {
	if (typeof markdown !== "string") return [];
	const lines = markdown.split(/\r?\n/u);
	const headerIndex = lines.findIndex((line) => {
		const cells = markdownCells(line);
		return cells?.length === TEMPLATE_COLUMNS.length && cells.every((cell, index) => cell === TEMPLATE_COLUMNS[index]);
	});
	if (headerIndex < 0) return [];
	const rows = [];
	for (const line of lines.slice(headerIndex + 1)) {
		const cells = markdownCells(line);
		if (cells === null) break;
		if (cells.length > 0 && cells.every((cell) => /^:?-{3,}:?$/u.test(cell))) continue;
		if (cells.length !== TEMPLATE_COLUMNS.length) {
			rows.push({ parse_error: `expected ${TEMPLATE_COLUMNS.length} columns, found ${cells.length}` });
			continue;
		}
		const [metric_id, name, formula, denominator, source, candidate, environment, window, owner, reviewer, limitations, status] = cells;
		rows.push({ metric_id, name, formula, denominator, source, candidate, environment, window, owner, reviewer, limitations, status });
	}
	return rows;
}

function validateTemplateCoverage(templateInput, metricIds, metrics, failures, templatePath) {
	if (templateInput === null) {
		failures.push(`investor metric dictionary template ${templatePath} could not be read`);
		return;
	}
	if (!Array.isArray(templateInput)) return;
	if (templateInput.length === 0) {
		failures.push("investor metric dictionary template contains no metric rows");
		return;
	}
	const templateRows = templateInput.map((item) => (typeof item === "string" ? { metric_id: item } : item));
	const templateIds = templateRows.map((row) => row?.metric_id);
	if (new Set(templateIds).size !== templateIds.length) {
		failures.push("investor metric dictionary template contains duplicate metric IDs");
	}
	if (!sameStringSet(templateIds, metricIds)) {
		failures.push(difference("dictionary metric IDs and template metric IDs", templateIds, metricIds));
	}
	const metricById = new Map(metrics.map((metric) => [metric?.metric_id, metric]));
	for (const row of templateRows) {
		if (row?.parse_error) {
			failures.push(`investor metric dictionary template: ${row.parse_error}`);
			continue;
		}
		const metric = metricById.get(row?.metric_id);
		if (!metric || typeof row !== "object") continue;
		for (const field of TEMPLATE_COMPARE_FIELDS) {
			const expected = row[field];
			const actual = field === "limitations" ? metric.limitations?.join("; ") : metric[field];
			if (expected !== actual) failures.push(`${row.metric_id}: template ${field} differs from dictionary`);
		}
	}
}

function sha256File(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function validateHeldBinding(metric, { root }, referenceField, hashField, label, failures) {
	if (metric?.status !== HELD || !isKnown(metric?.[referenceField]) || !SHA256.test(metric?.[hashField] ?? "")) return;
	if (isAbsolute(metric[referenceField])) {
		failures.push(`${label}: ${referenceField} must be a repository-relative path`);
		return;
	}
	const artifactPath = resolve(root, metric[referenceField]);
	const inside = relative(root, artifactPath);
	if (inside.startsWith("..") || isAbsolute(inside)) {
		failures.push(`${label}: ${referenceField} must stay inside the repository`);
		return;
	}
	if (!existsSync(artifactPath) || !statSync(artifactPath).isFile()) {
		failures.push(`${label}: ${referenceField} does not exist on disk (${metric[referenceField]})`);
		return;
	}
	const actual = sha256File(artifactPath);
	if (actual !== metric[hashField]) {
		failures.push(`${label}: ${hashField} does not match ${metric[referenceField]}`);
	}
}

function validateHeldBindings(metric, { root }, failures) {
	const label = metric.metric_id;
	validateHeldBinding(metric, { root }, "candidate_ref", "candidate_digest", label, failures);
	validateHeldBinding(metric, { root }, "evidence_ref", "evidence_sha256", label, failures);
}

/**
 * Validate the dictionary and return a stable summary. Incomplete records are
 * valid only when they explicitly remain NOT_HELD and use `unknown` for every
 * incomplete scalar field; incompleteness itself is not silently promoted to a
 * passing or held metric.
 */
export function validateMetricDictionary({ dictionary, schema, templateIds, templateMetrics, templatePath = TEMPLATE_FILE, root = ROOT } = {}) {
	const failures = [];
	validateSchemaContract(schema, failures);
	failures.push(...validateAgainstSchema(dictionary, schema));

	const metrics = Array.isArray(dictionary?.metrics) ? dictionary.metrics : [];
	const metricIds = [];
	const seen = new Set();
	const statuses = {};
	const completeMetrics = [];
	const incompleteMetrics = [];

	for (const [index, metric] of metrics.entries()) {
		const label = typeof metric?.metric_id === "string" ? metric.metric_id : `metrics[${index}]`;
		if (typeof metric?.metric_id === "string") {
			metricIds.push(metric.metric_id);
			if (seen.has(metric.metric_id)) failures.push(`${label}: duplicate metric_id`);
			seen.add(metric.metric_id);
		}
		if (typeof metric?.status === "string") statuses[metric.status] = (statuses[metric.status] ?? 0) + 1;

		const completeness = metricCompleteness(metric);
		if (completeness.complete) {
			completeMetrics.push(label);
		} else {
			incompleteMetrics.push({
				metric_id: label,
				missing: completeness.missing,
			});
			if (metric?.status !== NOT_HELD) {
				failures.push(`${label}: incomplete metric must remain ${NOT_HELD}`);
			}
			for (const field of completeness.missing.filter((name) => name !== "limitations")) {
				if (!isUnknown(metric?.[field])) {
					failures.push(`${label}: incomplete ${field} must be exactly ${JSON.stringify(UNKNOWN)}`);
				}
			}
		}

		if (metric?.status === HELD) {
			if (!completeness.complete) {
				failures.push(`${label}: ${HELD} metric has incomplete required fields (${completeness.missing.join(", ")})`);
			}
			if (isKnown(metric?.owner) && isKnown(metric?.reviewer) && metric.owner === metric.reviewer) {
				failures.push(`${label}: owner and reviewer must be different for a ${HELD} metric`);
			}
			validateHeldBindings(metric, { root }, failures);
		}
	}

	const templateInput = templateMetrics !== undefined ? templateMetrics : templateIds;
	validateTemplateCoverage(templateInput, metricIds, metrics, failures, templatePath);
	if (metrics.length > 0 && incompleteMetrics.length > 0 && dictionary?.status !== NOT_HELD) {
		failures.push(`dictionary with incomplete metrics must remain ${NOT_HELD}`);
	}
	if (dictionary?.status === HELD && metrics.some((metric) => metric?.status !== HELD)) {
		failures.push(`dictionary status ${HELD} requires every metric status to be ${HELD}`);
	}
	if (dictionary?.status === NOT_HELD && metrics.length > 0 && incompleteMetrics.length === 0 && metrics.every((metric) => metric?.status === HELD)) {
		failures.push(`dictionary status ${NOT_HELD} disagrees with all metrics being ${HELD}`);
	}

	return {
		failures,
		summary: {
			metricCount: metrics.length,
			completeCount: completeMetrics.length,
			incompleteCount: incompleteMetrics.length,
			statuses,
			incompleteMetrics,
			templateMetricCount: Array.isArray(templateInput) ? templateInput.length : null,
		},
	};
}

export function parseTemplateMetricIds(markdown) {
	return parseTemplateMetricRows(markdown).map((row) => row.metric_id).filter(Boolean);
}

export function readInvestorMetricDictionary({
	root = ROOT,
	dictionaryPath = DICTIONARY_FILE,
	schemaPath = SCHEMA_FILE,
	templatePath = TEMPLATE_FILE,
} = {}) {
	const readJson = (path) => JSON.parse(readFileSync(resolve(root, path), "utf8"));
	const fullTemplatePath = resolve(root, templatePath);
	const templateMetrics = existsSync(fullTemplatePath) && statSync(fullTemplatePath).isFile()
		? parseTemplateMetricRows(readFileSync(fullTemplatePath, "utf8"))
		: null;
	return {
		root,
		dictionary: readJson(dictionaryPath),
		schema: readJson(schemaPath),
		dictionaryPath: String(dictionaryPath).replaceAll("\\", "/"),
		schemaPath: String(schemaPath).replaceAll("\\", "/"),
		templatePath: String(templatePath).replaceAll("\\", "/"),
		templateMetrics,
		templateIds: Array.isArray(templateMetrics) ? templateMetrics.map((row) => row.metric_id) : null,
	};
}

export function report(result, paths = {}) {
	const { failures, summary } = result;
	console.log(`Investor metric dictionary: ${failures.length === 0 ? "PASS" : "FAIL"}`);
	console.log(`Dictionary: ${paths.dictionaryPath ?? DICTIONARY_FILE}`);
	console.log(`Schema: ${paths.schemaPath ?? SCHEMA_FILE}`);
	console.log(`Metrics: ${summary.metricCount} (complete=${summary.completeCount}, incomplete=${summary.incompleteCount})`);
	const statuses = Object.entries(summary.statuses).map(([status, count]) => `${status}=${count}`).join(", ");
	console.log(`Statuses: ${statuses || "none"}`);
	for (const metric of summary.incompleteMetrics) {
		console.log(`- ${metric.metric_id}: ${NOT_HELD}; unknown fields: ${metric.missing.join(", ")}`);
	}
	if (failures.length > 0) {
		console.error(`${failures.length} investor metric dictionary failure(s):`);
		for (const failure of failures) console.error(`- ${failure}`);
	}
}

export function main(argv = process.argv.slice(2)) {
	if (argv.includes("--help") || argv.includes("-h")) {
		console.log("Usage: node scripts/validate-investor-metric-dictionary.mjs");
		return 0;
	}
	if (argv.length > 0) {
		console.error(`Unknown argument: ${argv[0]}`);
		return 2;
	}
	const loaded = readInvestorMetricDictionary();
	const result = validateMetricDictionary(loaded);
	report(result, loaded);
	return result.failures.length === 0 ? 0 : 1;
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
	try {
		process.exitCode = main();
	} catch (error) {
		console.error(`Investor metric dictionary validation error: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 2;
	}
}
