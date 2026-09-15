#!/usr/bin/env node
// Analyze evaluator-controlled benchmark records. This does not run AIDR or certify a release.
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HEX_256 = /^[a-f0-9]{64}$/i;
const ACTIONS = new Set(["block", "approval", "allow", "unsupported", "timeout", "error"]);
const PARTITIONS = new Set(["development", "holdout"]);
const PHASES = new Set(["cold_local", "warm_local", "remote_reputation", "policy_refresh", "output_inspection"]);
// The three dimensions a corpus must declare against the sold scope. The corpus scope field and
// the per-case field are named separately because they deliberately differ in this schema.
const SCOPE_DIMENSIONS = [
	{ dimension: "attack_family", scopeField: "required_attack_families", caseField: "family", label: "attack family" },
	{ dimension: "connector", scopeField: "required_connectors", caseField: "connector", label: "connector" },
	{ dimension: "surface", scopeField: "required_surfaces", caseField: "surface", label: "surface" },
];
const SCOPE_POSTURES = new Set(["enforce", "observe", "unsupported"]);
const COMPARISON_UNKNOWN_REASONS = new Set(["not_authorized", "not_available", "budget_blocked", "missing_measurements", "unsupported_product"]);
const TRUSTED_KEY_ROLES = new Set(["independent_evaluator", "duty_separation_authority", "customer_authority", "budget_authority"]);
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
export const MAX_ANALYSIS_MATRIX_CELLS = 1_000_000;
const MAX_SAFE_NONNEGATIVE = Number.MAX_SAFE_INTEGER;
const MEASUREMENT_BUDGET_REFUSAL = "authorization_not_verified";
// Exactly one of these may appear on a case. They name the case it was derived from.
const DERIVATION_FIELDS = ["derived_from_case_id", "development_derived_from"];
const RESOURCE_FIELDS = ["cpu_percent", "rss_mb"];

// These constants are the normative required-field contract. The JSON Schemas are descriptive
// mirrors and the schema-drift test requires their `required` arrays to match these exports.
export const CORPUS_REQUIRED_FIELDS = ["schema_version", "corpus_id", "version", "rule_author_id", "oracle_reviewer_id", "scope", "cases"];
export const CORPUS_CASE_REQUIRED_FIELDS = ["case_id", "partition", "oracle", "family", "connector", "surface", "content_sha256"];
export const OBSERVATIONS_REQUIRED_FIELDS = ["schema_version", "workload_id", "environment", "trials_per_case", "candidate_product_id", "products", "measurements"];
export const OBSERVATION_PRODUCT_REQUIRED_FIELDS = ["product_id", "version", "artifact_sha256"];
export const MEASUREMENT_REQUIRED_FIELDS = ["case_id", "product_id", "trial", "action", "phase", "latency_ms", "raw_evidence_file", "raw_evidence_sha256"];
export const ATTESTATION_REQUIRED_FIELDS = ["schema_version", "payload", "signature_base64"];
export const ATTESTATION_PAYLOAD_REQUIRED_FIELDS = ["protocol_version", "corpus_sha256", "observations_sha256", "candidate_artifact_sha256", "rule_author_id", "evaluator_id", "evaluator_role", "completed_at"];
export const TRUSTED_KEY_REQUIRED_FIELDS = ["key_id", "evaluator_id", "public_key_sha256", "roles"];
export const DUTY_SEPARATION_RECEIPT_PAYLOAD_REQUIRED_FIELDS = ["corpus_sha256", "rule_author_id", "oracle_reviewer_id", "evaluator_id", "authority_id", "signing_key_id"];
export const REPORT_REQUIRED_FIELDS = ["schema_version", "kind", "claim_status", "production_accepted", "corpus", "observations_sha256", "workload_id", "environment", "attestation", "coverage", "gates", "canonical_report_sha256"];

function requireFields(value, fields, label) {
	for (const field of fields) if (!(field in value)) fail(`${label}.${field} is required`);
}

function fail(message) {
	throw new Error(message);
}

// Holdout-contamination failures carry a stable reason token and the offending subject so a
// reader (or a CI job) can tell exactly which guard refused the corpus.
function guardFail(reason, subject, detail) {
	fail(`holdout guard failed [${reason}] ${subject}: ${detail}`);
}

// Sold-scope failures use the same shape as the holdout guard: a stable reason token, the
// dimension item that is missing or short, and the requirement it fails.
function scopeFail(reason, subject, detail) {
	fail(`sold scope check failed [${reason}] ${subject}: ${detail}`);
}

function budgetFail(reason, detail) {
	fail(`measurement budget refused [${reason}] ${detail}`);
}

function analysisCapFail(detail) {
	fail(`analysis matrix exceeds hard safety cap of ${MAX_ANALYSIS_MATRIX_CELLS} case/product/trial cells [analysis_matrix_cap_exceeded] ${detail}`);
}

function object(value, label) {
	if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
	return value;
}

function nonempty(value, label) {
	if (typeof value !== "string" || !value.trim()) fail(`${label} must be a nonempty string`);
	return value.trim();
}

function safeId(value, label) {
	const id = nonempty(value, label);
	if (value !== id || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id)) fail(`${label} must be an opaque ASCII identifier`);
	return id;
}

function digest(bytes) {
	return createHash("sha256").update(bytes).digest("hex");
}

function strictBase64(value, label, expectedBytes) {
	const message = `${label} must be canonical base64 encoding of exactly ${expectedBytes} bytes`;
	const expectedLength = Math.ceil(expectedBytes / 3) * 4;
	if (typeof value !== "string" || value.length !== expectedLength || !CANONICAL_BASE64.test(value)) fail(message);
	const decoded = Buffer.from(value, "base64");
	if (decoded.length !== expectedBytes || decoded.toString("base64") !== value) fail(message);
	return decoded;
}

export function canonicalJson(value) {
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
	return JSON.stringify(value);
}

function measuredMetric(value, observations) {
	return { measured: observations > 0, value: observations > 0 ? value : null, observations };
}

function jsonFile(path) {
	const bytes = readFileSync(path);
	return { bytes, value: JSON.parse(bytes.toString("utf8")) };
}

function assertSha(value, label) {
	if (typeof value !== "string" || !HEX_256.test(value)) fail(`${label} must be a SHA-256 hex digest`);
	return value.toLowerCase();
}

function finiteNonnegative(value, label) {
	if (typeof value !== "number" || !Number.isFinite(value) || value < 0) fail(`${label} must be a finite nonnegative number`);
	return value;
}

function positiveInteger(value, label) {
	if (!Number.isSafeInteger(value) || value < 1) fail(`${label} must be a positive integer`);
	return value;
}

function safeBudgetNumber(value, label, reason = "measurement_budget_number_invalid") {
	if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > MAX_SAFE_NONNEGATIVE)
		budgetFail(reason, `${label} must be a finite nonnegative number no greater than ${MAX_SAFE_NONNEGATIVE}`);
	return value;
}

function safeBudgetInteger(value, label, reason = "measurement_budget_integer_invalid") {
	if (!Number.isSafeInteger(value) || value < 1)
		budgetFail(reason, `${label} must be a positive safe integer`);
	return value;
}

function safeMultiply(left, right, label) {
	if (!Number.isSafeInteger(left) || !Number.isSafeInteger(right) || left < 0 || right < 0)
		analysisCapFail(`${label} is not a nonnegative safe integer product`);
	if (left !== 0 && right > Math.floor(MAX_ANALYSIS_MATRIX_CELLS / left))
		analysisCapFail(`${label} would exceed the cap before analysis loops begin`);
	return left * right;
}

function safeAdd(left, right, label) {
	if (!Number.isSafeInteger(left) || !Number.isSafeInteger(right) || left < 0 || right < 0)
		analysisCapFail(`${label} is not a nonnegative safe integer sum`);
	if (right > MAX_ANALYSIS_MATRIX_CELLS - left)
		analysisCapFail(`${label} would exceed the cap before analysis loops begin`);
	return left + right;
}

// Resource fields are optional per measurement. Absence is recorded as unmeasured, never as zero.
function optionalNonnegative(value, label) {
	if (value === undefined || value === null) return null;
	return finiteNonnegative(value, label);
}

// Case content is compared in a normalized form so line-ending or surrounding-whitespace
// differences cannot hide a holdout case that is a copy of a development case.
function normalizeContent(value) {
	return value.replace(/\r\n?/g, "\n").trim();
}

function percentile(values, percentileValue) {
	if (values.length === 0) return null;
	const sorted = [...values].sort((a, b) => a - b);
	return sorted[Math.max(0, Math.ceil((percentileValue / 100) * sorted.length) - 1)];
}

function stats(values) {
	return {
		observations: values.length,
		p50_ms: percentile(values, 50),
		p95_ms: percentile(values, 95),
		p99_ms: percentile(values, 99),
	};
}

// No value is invented for an unmeasured statistic: the count is 0 and every statistic is null.
function resourceStats(values) {
	let peak = null;
	for (const value of values) if (peak === null || value > peak) peak = value;
	return { measured: values.length > 0, observations: values.length, p50: percentile(values, 50), p95: percentile(values, 95), peak };
}

function resourceRollup(rows) {
	const values = { cpu_percent: [], rss_mb: [] };
	for (const row of rows) for (const field of RESOURCE_FIELDS) if (typeof row[field] === "number") values[field].push(row[field]);
	return Object.fromEntries(RESOURCE_FIELDS.map((field) => [field, resourceStats(values[field])]));
}

function declaredPartitionTrials(value, label) {
	object(value, label);
	for (const key of Object.keys(value)) if (!PARTITIONS.has(key)) fail(`${label}.${key} is not a declared partition`);
	const trials = {};
	for (const partition of PARTITIONS) {
		if (!Number.isSafeInteger(value[partition]) || value[partition] < 1) fail(`${label}.${partition} must be a positive integer`);
		trials[partition] = value[partition];
	}
	return trials;
}

function caseContentSha(entry) {
	const id = entry.case_id;
	const declared = assertSha(entry.content_sha256, `content_sha256 for ${id}`);
	if (entry.content === undefined) return declared;
	if (typeof entry.content !== "string" || !entry.content.trim()) fail(`content for ${id} must be a nonempty string`);
	const recomputed = digest(Buffer.from(normalizeContent(entry.content), "utf8"));
	if (recomputed !== declared)
		guardFail("content_sha256_mismatch", `case ${id}`, `declared content_sha256 ${declared} does not match the normalized content digest ${recomputed}`);
	return declared;
}

function derivationReference(entry) {
	const id = entry.case_id;
	const declared = DERIVATION_FIELDS.filter((field) => entry[field] !== undefined && entry[field] !== null);
	if (declared.length === 0) return null;
	if (declared.length > 1) guardFail("duplicate_derivation_field", `case ${id}`, `declares both ${declared.join(" and ")}; use exactly one derivation reference`);
	return safeId(entry[declared[0]], `${declared[0]} for ${id}`);
}

function wilson(successes, total) {
	if (total === 0) return null;
	const z = 1.959963984540054;
	const p = successes / total;
	const denominator = 1 + (z * z) / total;
	const center = (p + (z * z) / (2 * total)) / denominator;
	const halfWidth = (z * Math.sqrt((p * (1 - p)) / total + (z * z) / (4 * total * total))) / denominator;
	return { low: Math.max(0, center - halfWidth), high: Math.min(1, center + halfWidth), method: "Wilson 95%" };
}

// Structural validation never looks at cases, so the committed scaffold in
// scripts/benchmarks/corpus.template.json can be proven structurally valid - and checked against
// the sold scope - before an independent evaluator has authored a single case.
export function validateCorpusStructure(corpus) {
	object(corpus, "corpus");
	requireFields(corpus, CORPUS_REQUIRED_FIELDS, "corpus");
	if (corpus.schema_version !== 1) fail("unsupported corpus schema_version");
	if (corpus.provenance !== undefined && !["synthetic_open", "customer_supplied"].includes(corpus.provenance)) fail("corpus.provenance must be synthetic_open or customer_supplied");
	nonempty(corpus.corpus_id, "corpus_id");
	nonempty(corpus.version, "corpus.version");
	nonempty(corpus.rule_author_id, "rule_author_id");
	nonempty(corpus.oracle_reviewer_id, "oracle_reviewer_id");
	if (corpus.rule_author_id === corpus.oracle_reviewer_id) fail("oracle reviewer must differ from rule author");
	const scope = object(corpus.scope, "corpus.scope");
	for (const field of ["required_attack_families", "required_connectors", "required_surfaces"]) {
		if (!Array.isArray(scope[field]) || scope[field].length === 0) fail(`scope.${field} must be a nonempty array`);
		const values = scope[field].map((value) => nonempty(value, `scope.${field} entry`));
		if (new Set(values).size !== values.length) fail(`scope.${field} contains duplicates`);
	}
	if (!Array.isArray(corpus.cases)) fail("corpus.cases must be an array");
	return scope;
}

export function validateCorpus(corpus) {
	const scope = validateCorpusStructure(corpus);
	if (!Array.isArray(corpus.cases) || corpus.cases.length === 0) fail("corpus.cases must be nonempty");
	if (corpus.cases.length > MAX_ANALYSIS_MATRIX_CELLS)
		analysisCapFail(`corpus declares ${corpus.cases.length} cases before analysis loops begin`);
	const declaredTrials = corpus.trials_per_case_by_partition === undefined ? null : declaredPartitionTrials(corpus.trials_per_case_by_partition, "corpus.trials_per_case_by_partition");
	const cases = new Map();
	const caseCounts = { development: 0, holdout: 0 };
	const contentShaById = new Map();
	const contentOwner = new Map();
	const derivedById = new Map();
	for (const entry of corpus.cases) {
		object(entry, "corpus case");
		requireFields(entry, CORPUS_CASE_REQUIRED_FIELDS.filter((field) => field !== "content_sha256"), "corpus case");
		const id = safeId(entry.case_id, "case_id");
		if (cases.has(id)) {
			const existing = cases.get(id);
			if (existing.partition !== entry.partition)
				guardFail("case_id_in_multiple_partitions", `case ${id}`, `the same case_id is declared in partition ${existing.partition} and partition ${entry.partition}`);
			fail(`duplicate case_id: ${id}`);
		}
		if (!PARTITIONS.has(entry.partition)) fail(`invalid partition for ${id}`);
		if (!(["malicious", "benign"].includes(entry.oracle))) fail(`invalid oracle for ${id}`);
		nonempty(entry.family, `family for ${id}`);
		nonempty(entry.connector, `connector for ${id}`);
		nonempty(entry.surface, `surface for ${id}`);
		const contentSha = caseContentSha(entry);
		const owner = contentOwner.get(contentSha);
		if (!owner) contentOwner.set(contentSha, { case_id: id, partition: entry.partition });
		else if (owner.partition !== entry.partition)
			guardFail("duplicate_case_content", `case ${id}`, `normalized content is identical to case ${owner.case_id} in partition ${owner.partition}`);
		contentShaById.set(id, contentSha);
		derivedById.set(id, derivationReference(entry));
		cases.set(id, entry);
		caseCounts[entry.partition] += 1;
	}
	// Recompute overlap and derivation from the raw case list so the reported gates stay honest
	// even if a rejection above is ever relaxed.
	const contamination = { cross_partition_case_id: [], cross_partition_content: [], cross_partition_derivation: [] };
	const seenIds = new Map();
	const seenContent = new Map();
	for (const entry of corpus.cases) {
		const id = entry.case_id;
		if (seenIds.has(id) && seenIds.get(id) !== entry.partition) contamination.cross_partition_case_id.push(id);
		if (!seenIds.has(id)) seenIds.set(id, entry.partition);
		const contentSha = contentShaById.get(id);
		if (contentSha === undefined) continue;
		const owner = seenContent.get(contentSha);
		if (owner === undefined) seenContent.set(contentSha, { partition: entry.partition });
		else if (owner.partition !== entry.partition) contamination.cross_partition_content.push(id);
	}
	for (const [id, reference] of derivedById) {
		if (reference === null) continue;
		if (reference === id) guardFail("self_derivation_reference", `case ${id}`, "a case cannot be derived from itself");
		const source = cases.get(reference);
		if (!source) guardFail("unknown_derivation_reference", `case ${id}`, `references undeclared case ${reference}`);
		if (source.partition === cases.get(id).partition) continue;
		contamination.cross_partition_derivation.push(id);
		guardFail("cross_partition_derivation", `case ${id}`, `partition ${cases.get(id).partition} derives from case ${reference} in partition ${source.partition}`);
	}
	const holdout = [...cases.values()].filter((entry) => entry.partition === "holdout");
	if (holdout.length === 0) guardFail("holdout_partition_empty", "partition holdout", "the corpus declares no holdout case, so no blind partition exists");
	for (const oracle of ["malicious", "benign"])
		if (!holdout.some((entry) => entry.oracle === oracle)) guardFail("holdout_single_oracle_class", "partition holdout", `the holdout contains no ${oracle} case`);
	return {
		cases,
		caseCounts,
		declaredTrials,
		contamination,
		holdoutBlind: {
			holdout_nonempty: holdout.length > 0,
			holdout_both_oracles: ["malicious", "benign"].every((oracle) => holdout.some((entry) => entry.oracle === oracle)),
		},
	};
}

// The sold scope is the machine-readable denominator of what the product actually sells:
// scripts/benchmarks/sold-scope.json. Loading it validates its own shape so a malformed
// denominator fails before it can be used to accept a corpus.
export function validateSoldScope(value) {
	object(value, "sold scope");
	if (value.schema_version !== 1) fail("unsupported sold scope schema_version");
	const scopeId = nonempty(value.scope_id, "sold scope scope_id");
	const idsOf = (entries, field) => {
		if (!Array.isArray(entries) || entries.length === 0) fail(`sold scope ${field} must be a nonempty array`);
		const ids = entries.map((entry) => {
			object(entry, `sold scope ${field} entry`);
			nonempty(entry.source, `sold scope ${field} entry source`);
			return nonempty(entry.id, `sold scope ${field} entry id`);
		});
		if (new Set(ids).size !== ids.length) fail(`sold scope ${field} contains duplicate ids`);
		return ids;
	};
	const requiredAttackFamilies = idsOf(value.attack_families, "attack_families");
	const requiredConnectors = idsOf(value.connectors, "connectors");
	const surfaceIds = idsOf(value.surfaces, "surfaces");
	for (const entry of value.surfaces) {
		if (typeof entry.required !== "boolean") fail(`sold scope surface ${entry.id} must declare a boolean required`);
		if (!SCOPE_POSTURES.has(entry.posture)) fail(`sold scope surface ${entry.id} has an unknown posture`);
	}
	const requiredSurfaces = value.surfaces.filter((entry) => entry.required).map((entry) => entry.id);
	if (requiredSurfaces.length === 0) fail("sold scope declares no required surface");
	const declared = object(value.required_scenarios_per_family, "sold scope required_scenarios_per_family");
	const minimums = {
		malicious: positiveInteger(declared.minimum_malicious_cases, "sold scope minimum_malicious_cases"),
		benign: positiveInteger(declared.minimum_benign_twins, "sold scope minimum_benign_twins"),
	};
	const overrides = declared.overrides === undefined ? {} : object(declared.overrides, "sold scope required_scenarios_per_family.overrides");
	const known = {
		attack_family: new Set(requiredAttackFamilies),
		connector: new Set(requiredConnectors),
		surface: new Set(surfaceIds),
	};
	for (const [key, override] of Object.entries(overrides)) {
		const separator = key.indexOf(":");
		const dimension = separator === -1 ? "" : key.slice(0, separator);
		const id = separator === -1 ? "" : key.slice(separator + 1);
		if (!known[dimension] || !known[dimension].has(id)) fail(`sold scope override ${key} does not name a declared ${dimension || "item"}`);
		object(override, `sold scope override ${key}`);
		if (override.minimum_malicious_cases !== undefined) positiveInteger(override.minimum_malicious_cases, `sold scope override ${key} minimum_malicious_cases`);
		if (override.minimum_benign_twins !== undefined) positiveInteger(override.minimum_benign_twins, `sold scope override ${key} minimum_benign_twins`);
	}
	if (!Array.isArray(value.out_of_scope_with_reason)) fail("sold scope out_of_scope_with_reason must be an array");
	for (const entry of value.out_of_scope_with_reason) {
		object(entry, "sold scope out_of_scope_with_reason entry");
		nonempty(entry.id, "sold scope out_of_scope_with_reason entry id");
		nonempty(entry.dimension, `sold scope out_of_scope_with_reason dimension for ${entry.id}`);
		nonempty(entry.reason, `sold scope out_of_scope_with_reason reason for ${entry.id}`);
		nonempty(entry.source, `sold scope out_of_scope_with_reason source for ${entry.id}`);
	}
	return { scopeId, requiredAttackFamilies, requiredConnectors, requiredSurfaces, minimums, overrides };
}

function scopeMinimums(soldScope, dimension, id) {
	const override = soldScope.overrides[`${dimension}:${id}`] ?? {};
	return {
		malicious: override.minimum_malicious_cases ?? soldScope.minimums.malicious,
		benign: override.minimum_benign_twins ?? soldScope.minimums.benign,
	};
}

// A corpus is in scope only when it declares exactly the sold dimensions - no omissions so a
// family cannot be quietly dropped, no extras so the corpus cannot claim credit for a dimension
// the product does not sell - and carries the declared minimum of malicious cases plus matching
// benign twins for every item. The first failure is fatal and names the item.
function checkSoldScopeCoverage(scope, cases, soldScope) {
	const declared = {
		attack_family: scope.required_attack_families,
		connector: scope.required_connectors,
		surface: scope.required_surfaces,
	};
	const required = {
		attack_family: soldScope.requiredAttackFamilies,
		connector: soldScope.requiredConnectors,
		surface: soldScope.requiredSurfaces,
	};
	for (const { dimension, scopeField, label } of SCOPE_DIMENSIONS) {
		for (const id of required[dimension]) if (!declared[dimension].includes(id))
			scopeFail(`scope_${dimension}_missing`, `${label} "${id}"`, `the sold scope "${soldScope.scopeId}" requires it but corpus.scope.${scopeField} does not declare it`);
		for (const id of declared[dimension]) if (!required[dimension].includes(id))
			scopeFail(`scope_${dimension}_extra`, `${label} "${id}"`, `corpus.scope.${scopeField} declares it but the sold scope does not`);
	}
	for (const { dimension, caseField, label } of SCOPE_DIMENSIONS) {
		for (const id of required[dimension]) {
			const minimums = scopeMinimums(soldScope, dimension, id);
			const malicious = cases.filter((entry) => entry !== null && typeof entry === "object" && entry[caseField] === id && entry.oracle === "malicious").length;
			if (malicious < minimums.malicious)
				scopeFail(`scope_${dimension}_minimum_not_met`, `${label} "${id}"`, `the corpus declares ${malicious} malicious case(s) but the sold scope requires at least ${minimums.malicious}`);
			const benign = cases.filter((entry) => entry !== null && typeof entry === "object" && entry[caseField] === id && entry.oracle === "benign").length;
			if (benign < minimums.benign)
				scopeFail(`scope_${dimension}_benign_twin_missing`, `${label} "${id}"`, `the corpus declares ${benign} benign twin(s) but the sold scope requires at least ${minimums.benign}`);
		}
	}
}

// soldScope is the validated form returned by validateSoldScope, never the raw JSON.
export function assertSoldScopeCoverage(corpus, soldScope) {
	const scope = validateCorpusStructure(corpus);
	checkSoldScopeCoverage(scope, corpus.cases, soldScope);
	return scope;
}

function validateMeasurementBudget(value) {
	const budget = object(value, "measurement_budget");
	if (typeof budget.authorization_ref !== "string" || !budget.authorization_ref.trim())
		budgetFail("measurement_budget_authorization_ref_missing", "measurement_budget.authorization_ref is required");
	const authorizationRef = budget.authorization_ref.trim();
	if (authorizationRef !== budget.authorization_ref || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(authorizationRef))
		budgetFail("measurement_budget_authorization_ref_invalid", "measurement_budget.authorization_ref must be an opaque ASCII identifier");
	if (typeof budget.currency !== "string" || !budget.currency.trim())
		budgetFail("measurement_budget_currency_invalid", "measurement_budget.currency must be a nonempty string");
	const currency = budget.currency.trim();
	if (currency !== budget.currency) budgetFail("measurement_budget_currency_invalid", "measurement_budget.currency must not have surrounding whitespace");

	const hasAmount = budget.amount !== undefined;
	const hasLegacyCeiling = budget.ceiling !== undefined;
	if (!hasAmount && !hasLegacyCeiling)
		budgetFail("measurement_budget_amount_missing", "measurement_budget.amount is required");
	const amount = safeBudgetNumber(hasAmount ? budget.amount : budget.ceiling, "measurement_budget.amount", "measurement_budget_amount_invalid");
	const ceiling = hasLegacyCeiling
		? safeBudgetNumber(budget.ceiling, "measurement_budget.ceiling", "measurement_budget_ceiling_invalid")
		: amount;
	if (hasAmount && hasLegacyCeiling && amount !== ceiling)
		budgetFail("measurement_budget_amount_mismatch", "measurement_budget.amount and measurement_budget.ceiling must agree");
	const spent = budget.spent === undefined || budget.spent === null
		? null
		: safeBudgetNumber(budget.spent, "measurement_budget.spent", "measurement_budget_spent_invalid");
	if (spent !== null && spent > amount)
		fail("measurement budget spent exceeds ceiling [measurement_budget_spent_exceeds_ceiling]");

	const hasNewCeilings = hasAmount || budget.trials !== undefined || budget.host_minutes !== undefined;
	const trials = budget.trials === undefined
		? null
		: safeBudgetInteger(budget.trials, "measurement_budget.trials", "measurement_budget_trials_invalid");
	const hostMinutes = budget.host_minutes === undefined
		? null
		: safeBudgetNumber(budget.host_minutes, "measurement_budget.host_minutes", "measurement_budget_host_minutes_invalid");
	if (hasNewCeilings && trials === null)
		budgetFail("measurement_budget_trials_missing", "measurement_budget.trials is required with amount and host_minutes");
	if (hasNewCeilings && hostMinutes === null)
		budgetFail("measurement_budget_host_minutes_missing", "measurement_budget.host_minutes is required with amount and trials");
	return {
		authorization_ref: authorizationRef,
		currency,
		amount,
		trials,
		host_minutes: hostMinutes,
		// Legacy names remain in the normalized report for reproducibility with v1 records.
		ceiling,
		spent,
	};
}

function validateObservations(observations, cases, caseCounts, declaredTrials) {
	object(observations, "observations");
	requireFields(observations, OBSERVATIONS_REQUIRED_FIELDS, "observations");
	if (observations.schema_version !== 1) fail("unsupported observations schema_version");
	nonempty(observations.workload_id, "workload_id");
	const environment = object(observations.environment, "environment");
	for (const field of ["environment_id", "os", "hardware", "runtime", "region", "concurrency", "workload_description"])
		nonempty(environment[field], `environment.${field}`);
	if (!Number.isSafeInteger(observations.trials_per_case) || observations.trials_per_case < 1) fail("trials_per_case must be a positive integer");
	const measurementBudget = observations.measurement_budget === undefined ? null : validateMeasurementBudget(observations.measurement_budget);
	const trialsByPartition = observations.trials_per_case_by_partition === undefined
		? { development: observations.trials_per_case, holdout: observations.trials_per_case }
		: declaredPartitionTrials(observations.trials_per_case_by_partition, "observations.trials_per_case_by_partition");
	if (trialsByPartition.development !== trialsByPartition.holdout && declaredTrials === null)
		guardFail("undeclared_partition_trial_difference", "partition trials", `observations use development=${trialsByPartition.development} and holdout=${trialsByPartition.holdout} trials but the corpus does not declare trials_per_case_by_partition`);
	let partitionTrialsDeclared = trialsByPartition.development === trialsByPartition.holdout;
	if (declaredTrials !== null) {
		partitionTrialsDeclared = true;
		for (const partition of PARTITIONS) if (declaredTrials[partition] !== trialsByPartition[partition]) {
			partitionTrialsDeclared = false;
			guardFail("declared_partition_trials_mismatch", `partition ${partition}`, `the corpus declares ${declaredTrials[partition]} trials but observations use ${trialsByPartition[partition]}`);
		}
	}
	if (!Array.isArray(observations.products) || observations.products.length === 0) fail("products must be nonempty");
	if (measurementBudget !== null && measurementBudget.trials !== null)
		for (const partition of PARTITIONS)
			if (trialsByPartition[partition] > measurementBudget.trials)
				budgetFail("measurement_budget_trials_exceeds_ceiling", `partition ${partition} uses ${trialsByPartition[partition]} trials but the authorized ceiling is ${measurementBudget.trials}`);
	const potentialPerCaseCells = {
		development: safeMultiply(trialsByPartition.development, observations.products.length, "development trials/products"),
		holdout: safeMultiply(trialsByPartition.holdout, observations.products.length, "holdout trials/products"),
	};
	safeAdd(
		safeMultiply(caseCounts.development, potentialPerCaseCells.development, "development cases/trials/products"),
		safeMultiply(caseCounts.holdout, potentialPerCaseCells.holdout, "holdout cases/trials/products"),
		"potential analysis matrix",
	);
	const products = new Map();
	for (const product of observations.products) {
		object(product, "product");
		requireFields(product, OBSERVATION_PRODUCT_REQUIRED_FIELDS, "product");
		const id = safeId(product.product_id, "product_id");
		if (products.has(id)) fail(`duplicate product_id: ${id}`);
		if (product.comparison_unknown_reason !== undefined && !COMPARISON_UNKNOWN_REASONS.has(product.comparison_unknown_reason)) fail(`invalid comparison_unknown_reason for ${id}`);
		nonempty(product.version, `version for ${id}`);
		assertSha(product.artifact_sha256, `artifact_sha256 for ${id}`);
		products.set(id, product);
	}
	const candidateId = safeId(observations.candidate_product_id, "candidate_product_id");
	if (!products.has(candidateId)) fail("candidate_product_id is not in products");
	const perCaseCells = {
		development: safeMultiply(trialsByPartition.development, products.size, "development trials/products"),
		holdout: safeMultiply(trialsByPartition.holdout, products.size, "holdout trials/products"),
	};
	const matrixCells = safeAdd(
		safeMultiply(caseCounts.development, perCaseCells.development, "development cases/trials/products"),
		safeMultiply(caseCounts.holdout, perCaseCells.holdout, "holdout cases/trials/products"),
		"total analysis matrix",
	);
	if (measurementBudget !== null && measurementBudget.trials !== null && matrixCells > measurementBudget.trials)
		budgetFail("measurement_budget_trials_exceeds_ceiling", `analysis requires ${matrixCells} trial cells but the authorized ceiling is ${measurementBudget.trials}`);
	if (!Array.isArray(observations.measurements)) fail("measurements must be an array");
	if (observations.measurements.length > matrixCells)
		analysisCapFail(`observations contain ${observations.measurements.length} rows for a ${matrixCells}-cell matrix`);
	const records = new Map();
	for (const row of observations.measurements) {
		object(row, "measurement");
		requireFields(row, MEASUREMENT_REQUIRED_FIELDS, "measurement");
		const caseId = safeId(row.case_id, "measurement.case_id");
		const productId = safeId(row.product_id, "measurement.product_id");
		if (!cases.has(caseId) || !products.has(productId)) fail(`unknown case/product: ${caseId}/${productId}`);
		if (!Number.isSafeInteger(row.trial) || row.trial < 1 || row.trial > trialsByPartition[cases.get(caseId).partition]) fail(`invalid trial for ${caseId}/${productId}`);
		if (!ACTIONS.has(row.action)) fail(`invalid action for ${caseId}/${productId}`);
		if (!PHASES.has(row.phase)) fail(`invalid phase for ${caseId}/${productId}`);
		if (row.latency_ms !== null) finiteNonnegative(row.latency_ms, `latency_ms for ${caseId}/${productId}`);
		if (["block", "approval", "allow"].includes(row.action) && row.latency_ms === null) fail(`missing decision latency for ${caseId}/${productId}`);
		if (cases.get(caseId).oracle === "malicious" && ["block", "approval", "allow"].includes(row.action) && typeof row.side_effect_occurred !== "boolean")
			fail(`side_effect_occurred must be observed for ${caseId}/${productId}`);
		optionalNonnegative(row.cpu_percent, `cpu_percent for ${caseId}/${productId}`);
		optionalNonnegative(row.rss_mb, `rss_mb for ${caseId}/${productId}`);
		if (row.score !== undefined && (typeof row.score !== "number" || !Number.isFinite(row.score) || row.score < 0 || row.score > 1)) fail(`score for ${caseId}/${productId} must be between 0 and 1`);
		assertSha(row.raw_evidence_sha256, `raw_evidence_sha256 for ${caseId}/${productId}`);
		nonempty(row.raw_evidence_file, `raw_evidence_file for ${caseId}/${productId}`);
		const key = `${caseId}\u0000${productId}\u0000${row.trial}`;
		if (records.has(key)) fail(`duplicate measurement: ${caseId}/${productId}/${row.trial}`);
		records.set(key, row);
	}
	return { products, candidateId, records, trialsByPartition, partitionTrialsDeclared, measurementBudget };
}

// A resource gate is true only when every completed candidate decision was measured for both fields.
function candidateResourceMeasured(observations, candidateId) {
	let decisions = 0;
	for (const row of observations.measurements) {
		if (row.product_id !== candidateId || !["block", "approval", "allow"].includes(row.action)) continue;
		decisions += 1;
		if (RESOURCE_FIELDS.some((field) => typeof row[field] !== "number")) return false;
	}
	return decisions > 0;
}

function verifyEvidenceFiles(observations, observationsPath) {
	const base = realpathSync(dirname(observationsPath));
	const seen = new Set();
	for (const row of observations.measurements) {
		if (isAbsolute(row.raw_evidence_file)) fail("raw evidence paths must be relative");
		const path = realpathSync(resolve(base, row.raw_evidence_file));
		const within = relative(base, path);
		if (within === ".." || within.startsWith(`..${sep}`) || isAbsolute(within)) fail("raw evidence escapes observation directory");
		if (!statSync(path).isFile()) fail("raw evidence must be a regular file");
		if (seen.has(path)) fail("each measurement requires a distinct raw evidence file");
		seen.add(path);
		if (digest(readFileSync(path)) !== row.raw_evidence_sha256.toLowerCase()) fail(`raw evidence hash mismatch for ${row.case_id}/${row.product_id}/${row.trial}`);
	}
}

function validateTrustedKeys(value) {
	object(value, "trusted keys");
	if (value.schema_version !== 1 || !Array.isArray(value.keys)) fail("trusted keys must have schema_version 1 and a keys array");
	const keys = new Map();
	for (const entry of value.keys) {
		object(entry, "trusted key");
		requireFields(entry, TRUSTED_KEY_REQUIRED_FIELDS, "trusted key");
		const id = safeId(entry.key_id, "trusted key key_id");
		if (keys.has(id)) fail(`duplicate trusted key_id: ${id}`);
		const evaluatorId = safeId(entry.evaluator_id, `trusted key evaluator_id for ${id}`);
		if (!Array.isArray(entry.roles) || entry.roles.length === 0 || entry.roles.some((role) => !TRUSTED_KEY_ROLES.has(role)) || new Set(entry.roles).size !== entry.roles.length)
			fail(`trusted key ${id} must declare recognized roles without duplicates`);
		keys.set(id, {
			sha256: assertSha(entry.public_key_sha256, `public_key_sha256 for trusted key ${id}`),
			evaluatorId,
			roles: new Set(entry.roles),
		});
	}
	return keys;
}

function verifySplitManifest(splitManifest, splitManifestBytes, corpus, payload) {
	if (splitManifest === null) return false;
	object(splitManifest, "split manifest");
	if (splitManifest.schema_version !== 1 || !Array.isArray(splitManifest.assignments)) fail("split manifest must have schema_version 1 and assignments");
	const manifestSha = digest(splitManifestBytes);
	if (assertSha(payload.split_manifest_sha256, "attested split_manifest_sha256") !== manifestSha) fail("split manifest hash differs from signed attestation");
	const expectedCorpus = digest(Buffer.from(canonicalJson({ ...corpus, cases: corpus.cases.map(({ partition: _partition, ...entry }) => entry) }), "utf8"));
	if (assertSha(splitManifest.source_corpus_sha256, "split manifest source_corpus_sha256") !== expectedCorpus) fail("split manifest is not bound to corpus content");
	const assignments = new Map();
	for (const entry of splitManifest.assignments) {
		const contentSha = assertSha(entry.content_sha256, "split manifest content_sha256");
		if (!PARTITIONS.has(entry.partition) || assignments.has(contentSha)) fail("split manifest has an invalid or duplicate assignment");
		assignments.set(contentSha, entry.partition);
	}
	for (const entry of corpus.cases) if (assignments.get(entry.content_sha256.toLowerCase()) !== entry.partition) fail(`split manifest partition mismatch for ${entry.case_id}`);
	if (assignments.size !== new Set(corpus.cases.map((entry) => entry.content_sha256.toLowerCase())).size) fail("split manifest assignment count differs from unique corpus content");
	return true;
}

function verifyAttestation(attestation, publicKeyPem, corpusBytes, observationBytes, corpus, observations, trustedKeys = null) {
	object(attestation, "attestation");
	requireFields(attestation, ATTESTATION_REQUIRED_FIELDS, "attestation");
	if (attestation.schema_version !== 1) fail("unsupported attestation schema_version");
	const payload = object(attestation.payload, "attestation.payload");
	requireFields(payload, ATTESTATION_PAYLOAD_REQUIRED_FIELDS, "attestation.payload");
	if (payload.protocol_version !== 1) fail("unsupported benchmark protocol_version");
	if (assertSha(payload.corpus_sha256, "attested corpus_sha256") !== digest(corpusBytes)) fail("corpus hash differs from signed attestation");
	if (assertSha(payload.observations_sha256, "attested observations_sha256") !== digest(observationBytes)) fail("observations hash differs from signed attestation");
	if (assertSha(payload.candidate_artifact_sha256, "attested candidate_artifact_sha256") !== observations.products.find((p) => p.product_id === observations.candidate_product_id).artifact_sha256.toLowerCase())
		fail("candidate artifact differs from signed attestation");
	if (nonempty(payload.rule_author_id, "attested rule_author_id") !== corpus.rule_author_id) fail("rule author mismatch");
	const evaluatorId = safeId(payload.evaluator_id, "evaluator_id");
	if (evaluatorId === corpus.rule_author_id || evaluatorId === corpus.oracle_reviewer_id) fail("evaluator must differ from rule author and oracle reviewer");
	if (payload.evaluator_role !== "independent_evaluator") fail("evaluator_role must be independent_evaluator");
	const time = nonempty(payload.completed_at, "completed_at");
	if (!/^\d{4}-\d{2}-\d{2}T/.test(time) || Number.isNaN(Date.parse(time))) fail("completed_at must be an ISO timestamp");
	const signature = strictBase64(attestation.signature_base64, "attestation signature", 64);
	const key = createPublicKey(publicKeyPem);
	if (key.asymmetricKeyType !== "ed25519") fail("attestation key must be Ed25519");
	const fingerprint = digest(key.export({ type: "spki", format: "der" }));
	const signingKeyId = payload.signing_key_id === undefined ? null : safeId(payload.signing_key_id, "attested signing_key_id");
	let trusted = false;
	if (trustedKeys !== null) {
		const keys = validateTrustedKeys(trustedKeys);
		if (signingKeyId === null) fail("trusted attestation requires signing_key_id");
		const trustedKey = keys.get(signingKeyId);
		if (!trustedKey || trustedKey.sha256 !== fingerprint || trustedKey.evaluatorId !== evaluatorId || !trustedKey.roles.has("independent_evaluator"))
			fail(`unknown, mismatched, or unauthorized attestation signing key: ${signingKeyId}`);
		trusted = true;
	}
	if (!verify(null, Buffer.from(JSON.stringify(payload)), key, signature)) fail("invalid evaluator signature");
	return { evaluator_id: evaluatorId, completed_at: time, public_key_sha256: fingerprint, signing_key_id: signingKeyId, trusted };
}

function classificationMetrics(rows, caseMap, allowRoc) {
	const matrix = { true_positive: 0, false_positive: 0, true_negative: 0, false_negative: 0, indeterminate: 0 };
	const scored = [];
	let determinate = 0;
	for (const row of rows) {
		const oracle = caseMap.get(row.case_id).oracle;
		if (!["block", "approval", "allow"].includes(row.action)) {
			matrix.indeterminate += 1;
			continue;
		}
		determinate += 1;
		const intervention = ["block", "approval"].includes(row.action);
		const positive = oracle === "malicious" ? intervention && row.side_effect_occurred !== true : intervention;
		if (oracle === "malicious") matrix[positive ? "true_positive" : "false_negative"] += 1;
		else matrix[positive ? "false_positive" : "true_negative"] += 1;
		if (typeof row.score === "number") scored.push({ malicious: oracle === "malicious", score: row.score });
	}
	const precisionDenominator = matrix.true_positive + matrix.false_positive;
	const recallDenominator = matrix.true_positive + matrix.false_negative;
	const precision = precisionDenominator ? matrix.true_positive / precisionDenominator : null;
	const recall = recallDenominator ? matrix.true_positive / recallDenominator : null;
	const f1 = precision !== null && recall !== null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null;
	const positives = scored.filter((entry) => entry.malicious);
	const negatives = scored.filter((entry) => !entry.malicious);
	let auc = null;
	let roc = null;
	if (allowRoc && scored.length === determinate && positives.length > 0 && negatives.length > 0) {
		let credit = 0;
		for (const positive of positives) for (const negative of negatives) credit += positive.score > negative.score ? 1 : positive.score === negative.score ? 0.5 : 0;
		auc = credit / (positives.length * negatives.length);
		roc = [...new Set(scored.map((entry) => entry.score))].sort((a, b) => b - a).map((threshold) => ({
			threshold,
			true_positive_rate: positives.filter((entry) => entry.score >= threshold).length / positives.length,
			false_positive_rate: negatives.filter((entry) => entry.score >= threshold).length / negatives.length,
		}));
	}
	const rocObservations = auc === null ? 0 : scored.length;
	return {
		confusion_matrix: matrix,
		precision: measuredMetric(precision, precision === null ? 0 : precisionDenominator),
		recall: measuredMetric(recall, recall === null ? 0 : recallDenominator),
		f1: measuredMetric(f1, f1 === null ? 0 : precisionDenominator + recallDenominator),
		roc: measuredMetric(roc, rocObservations),
		roc_auc: measuredMetric(auc, rocObservations),
	};
}

function summarizeRows(rows, caseMap, allowRoc = false) {
	const counts = {
		total: rows.length, malicious: 0, benign: 0, prevented: 0, held_for_approval: 0,
		malicious_allowed_or_effect: 0, malicious_side_effect_occurred: 0,
		malicious_side_effect_unknown: 0, benign_allowed: 0, false_blocks: 0,
		false_approvals: 0, unsupported: 0, timeout: 0, error: 0, missing: 0,
	};
	const latency = new Map();
	const resources = new Map();
	const decisionResources = [];
	for (const row of rows) {
		const { case_id: caseId, action, side_effect_occurred: effect, phase, latency_ms: ms } = row;
		const entry = caseMap.get(caseId);
		counts[entry.oracle] += 1;
		if (entry.oracle === "malicious") {
			if (effect === true) counts.malicious_side_effect_occurred += 1;
			else if (effect !== false) counts.malicious_side_effect_unknown += 1;
		}
		if (action === "missing" || action === "unsupported" || action === "timeout" || action === "error") counts[action] += 1;
		else if (entry.oracle === "malicious") {
			if (action === "block" && effect === false) counts.prevented += 1;
			else if (action === "approval" && effect === false) counts.held_for_approval += 1;
			else counts.malicious_allowed_or_effect += 1;
		} else if (action === "block") counts.false_blocks += 1;
		else if (action === "approval") counts.false_approvals += 1;
		else counts.benign_allowed += 1;
		if (["block", "approval", "allow"].includes(action)) {
			if (!latency.has(phase)) latency.set(phase, []);
			latency.get(phase).push(ms);
			if (!resources.has(phase)) resources.set(phase, []);
			resources.get(phase).push(row);
			decisionResources.push(row);
		}
	}
	return {
		counts,
		denominators: { malicious: counts.malicious, benign: counts.benign, all: counts.total },
		classification: classificationMetrics(rows, caseMap, allowRoc),
		 rates: {
			malicious_prevention: counts.malicious ? counts.prevented / counts.malicious : null,
			malicious_intervention: counts.malicious ? (counts.prevented + counts.held_for_approval) / counts.malicious : null,
			benign_false_block: counts.benign ? counts.false_blocks / counts.benign : null,
			benign_false_approval: counts.benign ? counts.false_approvals / counts.benign : null,
		},
		confidence_intervals: {
			malicious_prevention: wilson(counts.prevented, counts.malicious),
			benign_false_block: wilson(counts.false_blocks, counts.benign),
			benign_false_approval: wilson(counts.false_approvals, counts.benign),
		},
		latency_by_phase: Object.fromEntries([...latency].sort(([a], [b]) => a.localeCompare(b)).map(([phase, values]) => [phase, stats(values)])),
		resources: resourceRollup(decisionResources),
		resources_by_phase: Object.fromEntries([...resources].sort(([a], [b]) => a.localeCompare(b)).map(([phase, phaseRows]) => [phase, resourceRollup(phaseRows)])),
	};
}

// soldScope is the validated sold scope from validateSoldScope, or null when no --scope-file was
// supplied. Passing it asserts declared coverage and the per-item minimums before any report
// exists; it never changes how an observation is scored.
export function evaluateBenchmark({ corpus, observations, attestation, publicKeyPem, corpusBytes, observationBytes, observationsPath, soldScope = null, trustedKeys = null, splitManifest = null, splitManifestBytes = null, dutySeparationReceipt = null, dutySeparationReceiptBytes = null }) {
	if (soldScope !== null) assertSoldScopeCoverage(corpus, soldScope);
	const { cases, caseCounts, declaredTrials, contamination, holdoutBlind } = validateCorpus(corpus);
	const { products, candidateId, records, trialsByPartition, partitionTrialsDeclared, measurementBudget } = validateObservations(observations, cases, caseCounts, declaredTrials);
	const signer = verifyAttestation(attestation, publicKeyPem, corpusBytes, observationBytes, corpus, observations, trustedKeys);
	const holdoutFrozen = verifySplitManifest(splitManifest, splitManifestBytes, corpus, attestation.payload);
	verifyEvidenceFiles(observations, observationsPath);
	// An evaluator cannot authorize its own spend. Budget authorization requires a separate
	// externally verified budget-authority receipt, which is deliberately outside local execution.
	const budgetAuthorized = false;
	let dutySeparationBound = false;
	if (dutySeparationReceipt !== null) {
		object(dutySeparationReceipt, "duty separation receipt");
		if (!signer.trusted || trustedKeys === null) fail("duty separation receipt requires trusted evaluator and authority keys");
		if (!Buffer.isBuffer(dutySeparationReceiptBytes)) fail("duty separation receipt bytes are required");
		if (assertSha(attestation.payload.duty_separation_receipt_sha256, "attested duty_separation_receipt_sha256") !== digest(dutySeparationReceiptBytes)) fail("duty separation receipt differs from signed attestation");
		const receiptPayload = object(dutySeparationReceipt.payload, "duty separation receipt payload");
		requireFields(receiptPayload, DUTY_SEPARATION_RECEIPT_PAYLOAD_REQUIRED_FIELDS, "duty separation receipt payload");
		const receiptRuleAuthorId = safeId(receiptPayload.rule_author_id, "duty separation rule_author_id");
		const receiptOracleReviewerId = safeId(receiptPayload.oracle_reviewer_id, "duty separation oracle_reviewer_id");
		const receiptEvaluatorId = safeId(receiptPayload.evaluator_id, "duty separation evaluator_id");
		const receiptAuthorityId = safeId(receiptPayload.authority_id, "duty separation authority_id");
		const dutyIds = [receiptRuleAuthorId, receiptOracleReviewerId, receiptEvaluatorId, receiptAuthorityId];
		if (new Set(dutyIds).size !== dutyIds.length) fail("duty separation receipt duty identities must be pairwise distinct");
		if (assertSha(receiptPayload.corpus_sha256, "duty separation corpus_sha256") !== digest(corpusBytes) || receiptRuleAuthorId !== corpus.rule_author_id || receiptOracleReviewerId !== corpus.oracle_reviewer_id || receiptEvaluatorId !== signer.evaluator_id)
			fail("duty separation receipt identities or corpus do not match benchmark inputs");
		const receiptSignature = strictBase64(dutySeparationReceipt.signature_base64, "duty separation receipt signature", 64);
		const authorityKey = createPublicKey(nonempty(dutySeparationReceipt.public_key_pem, "duty separation receipt public_key_pem"));
		if (authorityKey.asymmetricKeyType !== "ed25519") fail("duty separation receipt key must be Ed25519");
		const authorityFingerprint = digest(authorityKey.export({ type: "spki", format: "der" }));
		const receiptSigningKeyId = safeId(receiptPayload.signing_key_id, "duty separation signing_key_id");
		const authority = validateTrustedKeys(trustedKeys).get(receiptSigningKeyId);
		if (!authority || authority.sha256 !== authorityFingerprint || authority.evaluatorId !== receiptAuthorityId || !authority.roles.has("duty_separation_authority") || authorityFingerprint === signer.public_key_sha256)
			fail("duty separation receipt key is not an independent trusted authority");
		if (!verify(null, Buffer.from(JSON.stringify(receiptPayload)), authorityKey, receiptSignature)) fail("invalid duty separation receipt signature");
		dutySeparationBound = true;
	}
	const operatingPoint = attestation.payload.frozen_operating_point;
	if (operatingPoint !== undefined && (operatingPoint?.frozen !== true || typeof operatingPoint.threshold !== "number" || !Number.isFinite(operatingPoint.threshold) || operatingPoint.threshold < 0 || operatingPoint.threshold > 1)) fail("frozen operating point must declare frozen true and a threshold between 0 and 1");
	const frozenOperatingPoint = holdoutFrozen && operatingPoint !== undefined;
	const report = {
		schema_version: 1,
		kind: "aidr_independent_benchmark_analysis",
		claim_status: "EVIDENCE_REVIEW_REQUIRED",
		production_accepted: false,
		corpus: { id: corpus.corpus_id, version: corpus.version, provenance: corpus.provenance ?? null, sha256: digest(corpusBytes), cases: cases.size, partitions: [...new Set([...cases.values()].map((c) => c.partition))].sort() },
		scope: {
			required_attack_families: corpus.scope.required_attack_families,
			required_connectors: corpus.scope.required_connectors,
			required_surfaces: corpus.scope.required_surfaces,
			uncovered_attack_families: corpus.scope.required_attack_families.filter((family) => ![...cases.values()].some((entry) => entry.oracle === "malicious" && entry.family === family)),
			uncovered_connectors: corpus.scope.required_connectors.filter((connector) => ![...cases.values()].some((entry) => entry.connector === connector)),
			uncovered_surfaces: corpus.scope.required_surfaces.filter((surface) => ![...cases.values()].some((entry) => entry.surface === surface)),
		},
		observations_sha256: digest(observationBytes),
		workload_id: observations.workload_id,
		environment: Object.fromEntries(["environment_id", "os", "hardware", "runtime", "region", "concurrency", "workload_description"].map((field) => [field, observations.environment[field]])),
		trials_per_case: observations.trials_per_case,
		trials_per_case_by_partition: trialsByPartition,
		attestation: signer,
		measurement_budget: measurementBudget === null
			? { status: "BLOCKED_EXTERNAL", refusal_reason: MEASUREMENT_BUDGET_REFUSAL, measured: false, authorized: false, authorization_ref: null, authorization_verified: false, amount: null, trials: null, host_minutes: null, ceiling: null, spent: null, currency: null }
			: { status: "BLOCKED_EXTERNAL", refusal_reason: MEASUREMENT_BUDGET_REFUSAL, measured: true, authorized: budgetAuthorized, authorization_ref: measurementBudget.authorization_ref, authorization_verified: false, amount: measurementBudget.amount, trials: measurementBudget.trials, host_minutes: measurementBudget.host_minutes, ceiling: measurementBudget.ceiling, spent: measurementBudget.spent, currency: measurementBudget.currency },
		duty_separation: { receipt_present: dutySeparationReceipt !== null, signed_and_bound: dutySeparationBound, independent: dutySeparationBound },
		comparison: Object.create(null),
		coverage: Object.create(null),
		limitations: [
			"A valid signature proves control of the evaluator key and input integrity; organizational independence and oracle quality require external review.",
			"The tool verifies raw artifact hashes but cannot independently prove protected side effects, equal test conditions, or customer deployment acceptance.",
			"Missing, unsupported, error, and timeout observations remain in denominators and never count as prevention.",
			"cpu_percent and rss_mb are optional per measurement; an absent value is reported as unmeasured (measured false, observations 0, null statistics) and is never reported as zero.",
			"The holdout guard is fail-closed: a corpus with one case_id in both partitions, repeated normalized case content, a cross-partition derivation reference, an empty or single-oracle holdout, or an undeclared per-partition trial difference is rejected before any report exists.",
			"Measurement-budget authorization is an external boundary: authorization_ref is opaque evidence only, authorization_verified and production_accepted remain false, and the declared amount, trials, and host_minutes ceilings do not constitute customer approval.",
		],
	};
	// Recorded only when a sold scope was supplied. `covered: true` means the declared coverage
	// denominator and its per-item minimums were satisfied - it is a scope statement, not a result.
	report.sold_scope = soldScope === null
		? null
		: {
				scope_id: soldScope.scopeId,
				required_attack_families: soldScope.requiredAttackFamilies,
				required_connectors: soldScope.requiredConnectors,
				required_surfaces: soldScope.requiredSurfaces,
				minimum_malicious_cases: soldScope.minimums.malicious,
				minimum_benign_twins: soldScope.minimums.benign,
				covered: true,
			};
	if (soldScope !== null)
		report.limitations.push(
			"The sold-scope check proves only that the corpus declares the sold attack families, connectors and surfaces and carries the declared malicious and benign case minimums; it measures nothing and does not show that any case was detected.",
		);
	for (const [productId, product] of products) {
		const rows = [];
		for (const [caseId, entry] of cases) for (let trial = 1; trial <= trialsByPartition[entry.partition]; trial++) {
			rows.push(records.get(`${caseId}\u0000${productId}\u0000${trial}`) ?? { case_id: caseId, action: "missing", phase: null, latency_ms: null });
		}
		const byDimension = (field) => Object.fromEntries([...new Set([...cases.values()].map((c) => c[field]))].sort().map((name) => [name, summarizeRows(rows.filter((row) => cases.get(row.case_id)[field] === name), cases, field === "partition" ? name === "development" || frozenOperatingPoint : frozenOperatingPoint)]));
		report.coverage[productId] = {
			version: product.version,
			artifact_sha256: product.artifact_sha256.toLowerCase(),
			overall: summarizeRows(rows, cases, frozenOperatingPoint),
			by_partition: byDimension("partition"),
			by_family: byDimension("family"),
			by_connector: byDimension("connector"),
			by_surface: byDimension("surface"),
		};
		if (productId !== candidateId) {
			const missing = report.coverage[productId].overall.counts.missing;
			const reason = product.comparison_unknown_reason ?? (missing > 0 ? "missing_measurements" : null);
			report.comparison[productId] = reason === null
				? { status: "measured", malicious_prevention: { status: "measured", value: report.coverage[productId].overall.rates.malicious_prevention } }
				: { status: "unknown", malicious_prevention: { status: "unknown", value: null, reason } };
		}
	}
	report.gates = {
		development_and_holdout_present: report.corpus.partitions.includes("development") && report.corpus.partitions.includes("holdout"),
		both_classes_in_each_partition: ["development", "holdout"].every((partition) => ["malicious", "benign"].every((oracle) => [...cases.values()].some((entry) => entry.partition === partition && entry.oracle === oracle))),
		declared_scope_covered: report.scope.uncovered_attack_families.length === 0 && report.scope.uncovered_connectors.length === 0 && report.scope.uncovered_surfaces.length === 0,
		// True means the sold-scope check ran and passed for this report; it is not a measurement.
		sold_scope_checked: soldScope !== null,
		competitor_in_same_record: products.size > 1,
		complete_matrix: Object.values(report.coverage).every((p) => p.overall.counts.missing === 0),
		candidate_1000_measured_benign_calls_per_connector: [...new Set([...cases.values()].map((entry) => entry.connector))].every((connector) => {
			let measured = 0;
			for (const entry of cases.values()) if (entry.connector === connector && entry.oracle === "benign")
				for (let trial = 1; trial <= trialsByPartition[entry.partition]; trial++) {
					const action = records.get(`${entry.case_id}\u0000${candidateId}\u0000${trial}`)?.action;
					if (["allow", "block", "approval"].includes(action)) measured += 1;
				}
			return measured >= 1000;
		}),
		holdout_partition_blind: holdoutBlind.holdout_nonempty && holdoutBlind.holdout_both_oracles && contamination.cross_partition_derivation.length === 0 && partitionTrialsDeclared,
		holdout_no_case_overlap: contamination.cross_partition_case_id.length === 0 && contamination.cross_partition_content.length === 0,
		holdout_frozen: holdoutFrozen,
		attestation_trusted: signer.trusted,
		measurement_budget_authorized: budgetAuthorized,
		// Evaluator self-attestation is not customer authorization; a separate customer-authority
		// receipt remains an external boundary, so local evaluation cannot set this gate.
		customer_corpus_authorized: false,
		duty_separation_signed_and_bound: dutySeparationBound,
		resource_measured: candidateResourceMeasured(observations, candidateId),
		candidate_id: candidateId,
		independent_acceptance: false,
	};
	report.canonical_report_sha256 = digest(Buffer.from(canonicalJson(report), "utf8"));
	return report;
}

function argsFromCli(argv) {
	const args = {};
	const valued = new Set(["--corpus", "--observations", "--attestation", "--public-key", "--scope-file", "--trusted-keys", "--split-manifest", "--duty-separation-receipt", "--reproduce", "--output"]);
	for (let index = 0; index < argv.length; index += 1) {
		const key = argv[index];
		if (key === "--force") {
			if (args[key]) fail("duplicate --force");
			args[key] = true;
			continue;
		}
		if (!valued.has(key) || !argv[index + 1] || args[key]) fail("usage: node scripts/benchmarks/evaluate.mjs --corpus PATH --observations PATH --attestation PATH --public-key PATH [--scope-file PATH] [--trusted-keys PATH] [--split-manifest PATH] [--duty-separation-receipt PATH] [--reproduce REPORT] [--output PATH] [--force]");
		args[key] = argv[++index];
	}
	if (!args["--corpus"]) fail("missing --corpus");
	// With --scope-file the coverage verdict is reported before the signed inputs are needed, so a
	// corpus that does not cover the sold scope fails with its real reason instead of "cases must
	// be nonempty". Without --scope-file every flag behaves exactly as before.
	if (!args["--scope-file"]) for (const key of ["--observations", "--attestation", "--public-key"]) if (!args[key]) fail(`missing ${key}`);
	return args;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		const args = argsFromCli(process.argv.slice(2));
		const corpusPath = resolve(args["--corpus"]);
		const corpus = jsonFile(corpusPath);
		let soldScope = null;
		if (args["--scope-file"]) {
			soldScope = validateSoldScope(jsonFile(resolve(args["--scope-file"])).value);
			// Coverage is asserted before anything else is read, so an empty or partial corpus
			// fails closed naming the item it misses rather than reporting a structural error.
			assertSoldScopeCoverage(corpus.value, soldScope);
			for (const key of ["--observations", "--attestation", "--public-key"]) if (!args[key]) fail(`missing ${key}`);
		}
		const observationsPath = resolve(args["--observations"]);
		const observations = jsonFile(observationsPath);
		const attestation = jsonFile(resolve(args["--attestation"])).value;
		const split = args["--split-manifest"] ? jsonFile(resolve(args["--split-manifest"])) : null;
		const receipt = args["--duty-separation-receipt"] ? jsonFile(resolve(args["--duty-separation-receipt"])) : null;
		const report = evaluateBenchmark({
			corpus: corpus.value, observations: observations.value, attestation,
			publicKeyPem: readFileSync(resolve(args["--public-key"]), "utf8"),
			corpusBytes: corpus.bytes, observationBytes: observations.bytes, observationsPath, soldScope,
			trustedKeys: args["--trusted-keys"] ? jsonFile(resolve(args["--trusted-keys"])).value : null,
			splitManifest: split?.value ?? null, splitManifestBytes: split?.bytes ?? null,
			dutySeparationReceipt: receipt?.value ?? null, dutySeparationReceiptBytes: receipt?.bytes ?? null,
		});
		const output = `${JSON.stringify(report, null, 2)}\n`;
		if (args["--reproduce"]) {
			const expected = readFileSync(resolve(args["--reproduce"]), "utf8");
			if (expected !== output) fail("reproduced report bytes differ");
		}
		if (args["--output"]) writeFileSync(resolve(args["--output"]), output, { flag: args["--force"] ? "w" : "wx" });
		else process.stdout.write(output);
	} catch (error) {
		process.stderr.write(`benchmark analysis failed: ${error.message}\n`);
		process.exitCode = 1;
	}
}
