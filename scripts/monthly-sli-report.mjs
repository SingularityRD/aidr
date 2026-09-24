#!/usr/bin/env node
/**
 * Generate and validate a local, time-based monthly availability report.
 *
 * This module intentionally accepts only local JSON input. It does not probe a
 * service, infer missing observations as success, or turn a load-test result
 * into a contractual SLI. Missing intervals are recorded as NOT_RUN and
 * ambiguous observations remain unknown.
 */

import { createHash } from "node:crypto";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const SCHEMA_VERSION = 1;
export const KIND = "aidr_monthly_sli_error_budget_report";
export const INPUT_KIND = "aidr_monthly_sli_observations";
export const INPUT_SCHEMA_URL = "https://singularity.example/schemas/aidr-monthly-sli-observations-v1.json";
export const GENERATOR = "scripts/monthly-sli-report.mjs";
export const REPORT_SCHEMA_URL = "https://singularity.example/schemas/aidr-monthly-sli-report-v1.json";
export const STATUS_PASS = "PASS";
export const STATUS_FAIL = "FAIL";
export const STATUS_NOT_RUN = "NOT_RUN";
export const STATUS_UNKNOWN = "unknown";
export const STATUS_VOCABULARY = Object.freeze([
	STATUS_PASS,
	STATUS_FAIL,
	STATUS_NOT_RUN,
	STATUS_UNKNOWN,
]);

const OBSERVATION_STATUSES = new Set(["good", "unavailable", STATUS_UNKNOWN, STATUS_NOT_RUN, "excluded"]);
const INTERVAL_STATUSES = new Set(["good", "unavailable", STATUS_UNKNOWN, STATUS_NOT_RUN, "excluded"]);
const EXCLUSION_CATEGORIES = new Set(["approved_maintenance", "customer_caused"]);
const INCIDENT_CLASSES = new Set(["unavailable", "approved_maintenance", "customer_caused", "unknown"]);
const INCIDENT_EVIDENCE_STATUSES = new Set(["observed", STATUS_UNKNOWN, STATUS_NOT_RUN]);
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MONTH_PATTERN = /^\d{4}-(?:0[1-9]|1[0-2])$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const ISO_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const EPSILON = 0.000001;
const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const MAX_REPORT_BYTES = 64 * 1024 * 1024;
const MAX_ENDPOINTS = 100;
const MAX_REGIONS = 100;
const MAX_SERIES = 1000;
const MAX_OBSERVATIONS = 100_000;
const MAX_EXCLUSIONS = 10_000;
const MAX_INCIDENTS = 10_000;
const MAX_LIMITATIONS = 100;
const MAX_INTERVALS_PER_SERIES = 220_001;

const DEFAULT_OBJECTIVE_RATIO = 0.999;
const DEFAULT_LIMITATIONS = Object.freeze([
	"This is a local observation report; it has no external probe, independent monitor, or provider evidence.",
	"The report is not a contractual SLA, service-credit record, or 99.9% availability claim.",
	"Load-test results remain workload observations and are not substituted for this monthly SLI.",
]);
const MAX_REPORT_LIMITATIONS = MAX_LIMITATIONS + DEFAULT_LIMITATIONS.length;

function isPlainObject(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOwn(value, key) {
	return isPlainObject(value) && Object.hasOwn(value, key);
}

function isFiniteNumber(value) {
	return typeof value === "number" && Number.isFinite(value);
}

function isNonNegativeNumber(value) {
	return isFiniteNumber(value) && value >= 0;
}

function isInteger(value) {
	return Number.isSafeInteger(value);
}

function isIsoTimestamp(value) {
	if (typeof value !== "string" || !ISO_PATTERN.test(value)) return false;
	const parsed = Date.parse(value);
	if (!Number.isFinite(parsed)) return false;
	// Accept the common UTC forms with or without .000 milliseconds, while
	// rejecting calendar values that Date.parse would otherwise normalize.
	return new Date(parsed).toISOString().slice(0, 10) === value.slice(0, 10);
}

function timestampMillis(value, label, failures) {
	if (!isIsoTimestamp(value)) {
		failures.push(`${label} must be a canonical UTC ISO-8601 timestamp`);
		return null;
	}
	return Date.parse(value);
}

function addUnknownPath(failures, path, value) {
	if (typeof value !== "string" || value.trim() === "") failures.push(`${path} must be a non-empty string`);
}

function roundNumber(value) {
	if (!isFiniteNumber(value)) return value;
	return Math.round((value + Number.EPSILON) * 1_000_000) / 1_000_000;
}

function approximatelyEqual(actual, expected, tolerance = EPSILON) {
	return isFiniteNumber(actual) && isFiniteNumber(expected) && Math.abs(actual - expected) <= tolerance;
}

function ratio(numerator, denominator) {
	return denominator > 0 ? roundNumber(numerator / denominator) : null;
}

function percentage(value) {
	return value === null ? null : roundNumber(value * 100);
}

function seriesKey(endpoint, region) {
	return `${endpoint}\u0000${region}`;
}

function seriesId(endpoint, region) {
	return `${endpoint}@${region}`;
}

function intervalKey(endpoint, region, start, end) {
	return `${seriesKey(endpoint, region)}\u0000${start}\u0000${end}`;
}

function safeBasename(value) {
	return basename(String(value).replaceAll("\\", "/"));
}

function reportStatus({ good, unavailable, excluded = 0, unknown, notRun, objectiveRatio }) {
	if (good + unavailable === 0 && excluded === 0 && unknown === 0 && notRun > 0) return STATUS_NOT_RUN;
	if (unknown > 0 || notRun > 0) return STATUS_UNKNOWN;
	if (good + unavailable === 0) return STATUS_UNKNOWN;
	return good / (good + unavailable) >= objectiveRatio ? STATUS_PASS : STATUS_FAIL;
}

function overallStatusForSeries(series, totals, objectiveRatio) {
	if (series.length > 0 && series.every((entry) => entry.status === STATUS_NOT_RUN)) return STATUS_NOT_RUN;
	if (series.some((entry) => entry.status === STATUS_UNKNOWN || entry.status === STATUS_NOT_RUN)) return STATUS_UNKNOWN;
	if (series.some((entry) => entry.status === STATUS_FAIL)) return STATUS_FAIL;
	return reportStatus({
		good: totals.good_seconds ?? totals.good,
		unavailable: totals.unavailable_seconds ?? totals.unavailable,
		excluded: totals.excluded_seconds ?? totals.excluded,
		unknown: totals.unknown_seconds ?? totals.unknown,
		notRun: totals.not_run_seconds ?? totals.notRun,
		objectiveRatio,
	});
}

function exactKeys(value, allowed, label, failures) {
	if (!isPlainObject(value)) {
		failures.push(`${label} must be an object`);
		return;
	}
	const allowedSet = new Set(allowed);
	for (const key of Object.keys(value)) {
		if (!allowedSet.has(key)) failures.push(`${label} has unexpected property ${key}`);
	}
}

function validateIdentifier(value, label, failures) {
	if (typeof value !== "string" || !ID_PATTERN.test(value)) failures.push(`${label} must be an identifier matching ${ID_PATTERN}`);
}

function validateMonth(value, label, failures) {
	if (typeof value !== "string" || !MONTH_PATTERN.test(value)) failures.push(`${label} must be YYYY-MM`);
}

function isFullCalendarMonth(window, month) {
	if (!isPlainObject(window) || typeof month !== "string" || !MONTH_PATTERN.test(month)) return false;
	const start = Date.parse(`${month}-01T00:00:00.000Z`);
	const end = new Date(start);
	end.setUTCMonth(end.getUTCMonth() + 1);
	return Date.parse(window.start_at) === start && Date.parse(window.end_at) === end.getTime();
}

function validateObjective(objective, failures, label = "objective") {
	if (!isPlainObject(objective)) {
		failures.push(`${label} must be an object`);
		return DEFAULT_OBJECTIVE_RATIO;
	}
	exactKeys(objective, ["availability_ratio", "contractual", "label"], label, failures);
	const value = objective.availability_ratio;
	if (!isFiniteNumber(value) || value < 0 || value > 1) failures.push(`${label}.availability_ratio must be between 0 and 1`);
	if (objective.contractual !== false) failures.push(`${label}.contractual must be false; contractual SLA claims are not produced locally`);
	if (objective.label !== "internal_reference_only") failures.push(`${label}.label must be internal_reference_only`);
	return isFiniteNumber(value) && value >= 0 && value <= 1 ? value : DEFAULT_OBJECTIVE_RATIO;
}

function validateScope(scope, failures) {
	if (!isPlainObject(scope)) {
		failures.push("scope must be an object");
		return { service: "", endpoints: [], regions: [] };
	}
	exactKeys(scope, ["service", "endpoints", "regions"], "scope", failures);
	if (typeof scope.service !== "string" || scope.service.trim() === "") failures.push("scope.service must be a non-empty string");
	if (!Array.isArray(scope.endpoints) || scope.endpoints.length === 0) failures.push("scope.endpoints must be a non-empty array");
	if (!Array.isArray(scope.regions) || scope.regions.length === 0) failures.push("scope.regions must be a non-empty array");
	const endpoints = Array.isArray(scope.endpoints) ? scope.endpoints : [];
	const regions = Array.isArray(scope.regions) ? scope.regions : [];
	if (endpoints.length > MAX_ENDPOINTS) failures.push(`scope.endpoints may contain at most ${MAX_ENDPOINTS} entries`);
	if (regions.length > MAX_REGIONS) failures.push(`scope.regions may contain at most ${MAX_REGIONS} entries`);
	if (endpoints.length * regions.length > MAX_SERIES) failures.push(`scope endpoint-region series may contain at most ${MAX_SERIES} entries`);
	for (const [index, endpoint] of endpoints.entries()) validateIdentifier(endpoint, `scope.endpoints[${index}]`, failures);
	for (const [index, region] of regions.entries()) validateIdentifier(region, `scope.regions[${index}]`, failures);
	if (new Set(endpoints).size !== endpoints.length) failures.push("scope.endpoints must not contain duplicates");
	if (new Set(regions).size !== regions.length) failures.push("scope.regions must not contain duplicates");
	return { service: scope.service, endpoints, regions };
}

function validateWindow(window, month, failures, label = "observation_window", reportShape = false) {
	if (!isPlainObject(window)) {
		failures.push(`${label} must be an object`);
		return { start: null, end: null, durationSeconds: 0 };
	}
	exactKeys(window, reportShape ? ["start_at", "end_at", "duration_seconds", "series_count"] : ["start_at", "end_at"], label, failures);
	const start = timestampMillis(window.start_at, `${label}.start_at`, failures);
	const end = timestampMillis(window.end_at, `${label}.end_at`, failures);
	if (start !== null && end !== null && end <= start) failures.push(`${label}.end_at must be after start_at`);
	if (start !== null && month && new Date(start).toISOString().slice(0, 7) !== month) {
		failures.push(`${label}.start_at must be within month ${month}`);
	}
	if (end !== null && start !== null && end - start > 366 * 86400 * 1000) failures.push(`${label} cannot exceed 366 days`);
	return {
		start,
		end,
		durationSeconds: start !== null && end !== null && end > start ? (end - start) / 1000 : 0,
	};
}

function validateInputObservation(observation, index, scope, window, failures) {
	const label = `observations[${index}]`;
	if (!isPlainObject(observation)) {
		failures.push(`${label} must be an object`);
		return null;
	}
	exactKeys(observation, ["endpoint", "region", "start_at", "end_at", "status", "reason"], label, failures);
	validateIdentifier(observation.endpoint, `${label}.endpoint`, failures);
	validateIdentifier(observation.region, `${label}.region`, failures);
	if (!scope.endpoints.includes(observation.endpoint)) failures.push(`${label}.endpoint is outside scope`);
	if (!scope.regions.includes(observation.region)) failures.push(`${label}.region is outside scope`);
	if (!OBSERVATION_STATUSES.has(observation.status)) failures.push(`${label}.status must be one of ${[...OBSERVATION_STATUSES].join(", ")}`);
	if (hasOwn(observation, "reason")) addUnknownPath(failures, `${label}.reason`, observation.reason);
	const start = timestampMillis(observation.start_at, `${label}.start_at`, failures);
	const end = timestampMillis(observation.end_at, `${label}.end_at`, failures);
	if (start !== null && end !== null && end <= start) failures.push(`${label}.end_at must be after start_at`);
	if (start !== null && window.start !== null && start < window.start) failures.push(`${label}.start_at is before the observation window`);
	if (end !== null && window.end !== null && end > window.end) failures.push(`${label}.end_at is after the observation window`);
	if (start === null || end === null || end <= start) return null;
	return { ...observation, start, end };
}

function validateExclusion(exclusion, index, scope, window, failures) {
	const label = `exclusions[${index}]`;
	if (!isPlainObject(exclusion)) {
		failures.push(`${label} must be an object`);
		return null;
	}
	exactKeys(exclusion, ["endpoint", "region", "start_at", "end_at", "category", "approved", "reference"], label, failures);
	validateIdentifier(exclusion.endpoint, `${label}.endpoint`, failures);
	validateIdentifier(exclusion.region, `${label}.region`, failures);
	if (!scope.endpoints.includes(exclusion.endpoint)) failures.push(`${label}.endpoint is outside scope`);
	if (!scope.regions.includes(exclusion.region)) failures.push(`${label}.region is outside scope`);
	if (!EXCLUSION_CATEGORIES.has(exclusion.category)) failures.push(`${label}.category must be approved_maintenance or customer_caused`);
	if (exclusion.approved !== true) failures.push(`${label}.approved must be true; unapproved exclusions are not silently removed from the denominator`);
	addUnknownPath(failures, `${label}.reference`, exclusion.reference);
	const start = timestampMillis(exclusion.start_at, `${label}.start_at`, failures);
	const end = timestampMillis(exclusion.end_at, `${label}.end_at`, failures);
	if (start !== null && end !== null && end <= start) failures.push(`${label}.end_at must be after start_at`);
	if (start !== null && window.start !== null && start < window.start) failures.push(`${label}.start_at is before the observation window`);
	if (end !== null && window.end !== null && end > window.end) failures.push(`${label}.end_at is after the observation window`);
	if (start === null || end === null || end <= start) return null;
	return { ...exclusion, start, end };
}

function validateUniqueIncidentIds(incidents, failures, label = "incidents") {
	const seen = new Set();
	for (const [index, incident] of incidents.entries()) {
		if (!isPlainObject(incident) || typeof incident.id !== "string") continue;
		if (seen.has(incident.id)) failures.push(`${label}[${index}].id duplicates incident ${incident.id}`);
		seen.add(incident.id);
	}
}

function validateIncident(incident, index, window, failures) {
	const label = `incidents[${index}]`;
	if (!isPlainObject(incident)) {
		failures.push(`${label} must be an object`);
		return null;
	}
	exactKeys(incident, ["id", "start_at", "end_at", "classification", "evidence_status", "reference"], label, failures);
	validateIdentifier(incident.id, `${label}.id`, failures);
	if (!INCIDENT_CLASSES.has(incident.classification)) failures.push(`${label}.classification is invalid`);
	if (!INCIDENT_EVIDENCE_STATUSES.has(incident.evidence_status)) failures.push(`${label}.evidence_status is invalid`);
	addUnknownPath(failures, `${label}.reference`, incident.reference);
	const start = timestampMillis(incident.start_at, `${label}.start_at`, failures);
	const end = timestampMillis(incident.end_at, `${label}.end_at`, failures);
	if (start !== null && end !== null && end <= start) failures.push(`${label}.end_at must be after start_at`);
	if (start !== null && window.start !== null && start < window.start) failures.push(`${label}.start_at is before the observation window`);
	if (end !== null && window.end !== null && end > window.end) failures.push(`${label}.end_at is after the observation window`);
	if (start === null || end === null || end <= start) return null;
	return { ...incident, start, end };
}

/**
 * Validate the local observations accepted by the generator.
 *
 * The returned array is deliberately suitable for CLI output and tests. An
 * empty array is the only valid result.
 */
export function validateMonthlyInput(input) {
	const failures = [];
	if (!isPlainObject(input)) return ["input must be an object"];
	exactKeys(input, ["$schema", "schema_version", "kind", "month", "scope", "observation_window", "objective", "observations", "exclusions", "incidents", "limitations"], "input", failures);
	if (hasOwn(input, "$schema") && input.$schema !== INPUT_SCHEMA_URL) failures.push(`input.$schema must be ${INPUT_SCHEMA_URL}`);
	if (input.schema_version !== SCHEMA_VERSION) failures.push(`input.schema_version must be ${SCHEMA_VERSION}`);
	if (input.kind !== INPUT_KIND) failures.push(`input.kind must be ${INPUT_KIND}`);
	validateMonth(input.month, "input.month", failures);
	const scope = validateScope(input.scope, failures);
	const window = validateWindow(input.observation_window, input.month, failures);
	if (input.objective !== undefined) validateObjective(input.objective, failures);
	if (input.observations !== undefined && !Array.isArray(input.observations)) failures.push("observations must be an array");
	if (input.exclusions !== undefined && !Array.isArray(input.exclusions)) failures.push("exclusions must be an array");
	if (input.incidents !== undefined && !Array.isArray(input.incidents)) failures.push("incidents must be an array");
	if (Array.isArray(input.observations) && input.observations.length > MAX_OBSERVATIONS) failures.push(`observations may contain at most ${MAX_OBSERVATIONS} entries`);
	if (Array.isArray(input.exclusions) && input.exclusions.length > MAX_EXCLUSIONS) failures.push(`exclusions may contain at most ${MAX_EXCLUSIONS} entries`);
	if (Array.isArray(input.incidents) && input.incidents.length > MAX_INCIDENTS) failures.push(`incidents may contain at most ${MAX_INCIDENTS} entries`);
	if (hasOwn(input, "limitations")) {
		if (!Array.isArray(input.limitations) || input.limitations.length > MAX_LIMITATIONS || input.limitations.some((value) => typeof value !== "string" || value.trim() === "")) {
			failures.push(`limitations must contain at most ${MAX_LIMITATIONS} non-empty strings`);
		}
	}

	const observations = Array.isArray(input.observations) && input.observations.length <= MAX_OBSERVATIONS
		? input.observations.map((entry, index) => validateInputObservation(entry, index, scope, window, failures)).filter(Boolean)
		: [];
	const exclusions = Array.isArray(input.exclusions) && input.exclusions.length <= MAX_EXCLUSIONS
		? input.exclusions.map((entry, index) => validateExclusion(entry, index, scope, window, failures)).filter(Boolean)
		: [];
	const incidents = Array.isArray(input.incidents) && input.incidents.length <= MAX_INCIDENTS
		? input.incidents.map((entry, index) => validateIncident(entry, index, window, failures)).filter(Boolean)
		: [];
	validateUniqueIncidentIds(incidents, failures);

	const intervalsBySeries = new Map();
	for (const entry of [...observations.map((value) => ({ ...value, type: "observation" })), ...exclusions.map((value) => ({ ...value, type: "exclusion" }))]) {
		const key = seriesKey(entry.endpoint, entry.region);
		const intervals = intervalsBySeries.get(key) ?? [];
		intervals.push(entry);
		intervalsBySeries.set(key, intervals);
	}
	for (const intervals of intervalsBySeries.values()) {
		if (intervals.length > MAX_INTERVALS_PER_SERIES) failures.push(`a series may contain at most ${MAX_INTERVALS_PER_SERIES} intervals`);
		intervals.sort((left, right) => left.start - right.start || left.end - right.end);
		for (let index = 1; index < intervals.length; index += 1) {
			const previous = intervals[index - 1];
			const entry = intervals[index];
			const sameExcludedInterval = entry.type !== previous.type && entry.start === previous.start && entry.end === previous.end && (entry.status === "excluded" || previous.status === "excluded");
			if (!sameExcludedInterval && entry.start < previous.end) failures.push(`${entry.type} ${entry.endpoint}@${entry.region} overlaps another interval`);
		}
	}

	const exclusionKeys = new Set(exclusions.map((exclusion) => intervalKey(exclusion.endpoint, exclusion.region, exclusion.start, exclusion.end)));
	for (const entry of observations) {
		if (entry.status !== "excluded") continue;
		const matching = exclusionKeys.has(intervalKey(entry.endpoint, entry.region, entry.start, entry.end));
		if (!matching) failures.push(`observations ${entry.endpoint}@${entry.region} status excluded must match an approved exclusion`);
	}
	return failures;
}

function normalizedInput(input) {
	return {
		...input,
		objective: {
			availability_ratio: input.objective?.availability_ratio ?? DEFAULT_OBJECTIVE_RATIO,
			contractual: false,
			label: "internal_reference_only",
		},
		observations: (input.observations ?? []).map((entry) => ({ ...entry })),
		exclusions: (input.exclusions ?? []).map((entry) => ({ ...entry })),
		incidents: (input.incidents ?? []).map((entry) => ({ ...entry })),
	};
}

function makeSegments(input, start, end) {
	const segmentsBySeries = new Map();
	for (const endpoint of input.scope.endpoints) {
		for (const region of input.scope.regions) {
			segmentsBySeries.set(seriesKey(endpoint, region), []);
		}
	}
	for (const observation of input.observations) {
		const segments = segmentsBySeries.get(seriesKey(observation.endpoint, observation.region));
		segments.push({ start: observation.start_at, end: observation.end_at, status: observation.status, reason: observation.reason ?? null });
	}
	const excludedObservationKeys = new Set(input.observations
		.filter((observation) => observation.status === "excluded")
		.map((observation) => intervalKey(observation.endpoint, observation.region, Date.parse(observation.start_at), Date.parse(observation.end_at))));
	for (const exclusion of input.exclusions) {
		if (excludedObservationKeys.has(intervalKey(exclusion.endpoint, exclusion.region, Date.parse(exclusion.start_at), Date.parse(exclusion.end_at)))) continue;
		const segments = segmentsBySeries.get(seriesKey(exclusion.endpoint, exclusion.region));
		segments.push({ start: exclusion.start_at, end: exclusion.end_at, status: "excluded", reason: exclusion.reference });
	}

	const result = [];
	for (const endpoint of input.scope.endpoints) {
		for (const region of input.scope.regions) {
			const key = seriesKey(endpoint, region);
			const source = (segmentsBySeries.get(key) ?? [])
				.map((segment) => ({ ...segment, startMs: Date.parse(segment.start), endMs: Date.parse(segment.end) }))
				.sort((left, right) => left.startMs - right.startMs);
			const segments = [];
			let cursor = start;
			for (const segment of source) {
				if (segment.startMs > cursor) {
					segments.push({ startMs: cursor, endMs: segment.startMs, status: STATUS_NOT_RUN, reason: "no local observation was recorded" });
				}
				segments.push({ startMs: segment.startMs, endMs: segment.endMs, status: segment.status, reason: segment.reason });
				cursor = segment.endMs;
				if (cursor > end) break;
			}
			if (cursor < end) segments.push({ startMs: cursor, endMs: end, status: STATUS_NOT_RUN, reason: "no local observation was recorded" });
			result.push({ endpoint, region, segments });
		}
	}
	return result;
}

function aggregateSegments(segments, objectiveRatio) {
	const totals = { good: 0, unavailable: 0, excluded: 0, unknown: 0, notRun: 0 };
	for (const segment of segments) {
		const seconds = (segment.endMs - segment.startMs) / 1000;
		if (segment.status === "good") totals.good += seconds;
		else if (segment.status === "unavailable") totals.unavailable += seconds;
		else if (segment.status === "excluded") totals.excluded += seconds;
		else if (segment.status === STATUS_UNKNOWN) totals.unknown += seconds;
		else if (segment.status === STATUS_NOT_RUN) totals.notRun += seconds;
	}
	for (const key of Object.keys(totals)) totals[key] = roundNumber(totals[key]);
	const eligible = roundNumber(totals.good + totals.unavailable);
	const status = reportStatus({ ...totals, objectiveRatio });
	return {
		expected_seconds: roundNumber(segments.reduce((sum, segment) => sum + (segment.endMs - segment.startMs) / 1000, 0)),
		good_seconds: totals.good,
		unavailable_seconds: totals.unavailable,
		excluded_seconds: totals.excluded,
		unknown_seconds: totals.unknown,
		not_run_seconds: totals.notRun,
		eligible_seconds: eligible,
		availability_ratio: ratio(totals.good, eligible),
		availability_percent: percentage(ratio(totals.good, eligible)),
		status,
	};
}

function normalizeIntervalsForReport(segments) {
	return segments.map((segment) => ({
		start_at: new Date(segment.startMs).toISOString(),
		end_at: new Date(segment.endMs).toISOString(),
		status: segment.status,
		...(segment.reason ? { reason: segment.reason } : {}),
	}));
}

function inputLimitations(input) {
	const supplied = Array.isArray(input.limitations) ? input.limitations.filter((value) => typeof value === "string" && value.trim() !== "") : [];
	return [...new Set([...DEFAULT_LIMITATIONS, ...supplied])];
}

/**
 * Generate a report from already-collected local observations.
 *
 * `sourceSha256` and `sourceFile` are supplied by the CLI after reading the
 * input file. Direct callers may leave them out; the resulting evidence state
 * is then explicitly "unknown" rather than an invented digest.
 */
export function generateMonthlyReport(input, options = {}) {
	options ??= {};
	const failures = validateMonthlyInput(input);
	if (failures.length > 0) throw new Error(`invalid monthly SLI input: ${failures.join("; ")}`);
	const normalized = normalizedInput(input);
	const start = Date.parse(normalized.observation_window.start_at);
	const end = Date.parse(normalized.observation_window.end_at);
	const objectiveRatio = normalized.objective.availability_ratio;
	const seriesSegments = makeSegments(normalized, start, end);
	const series = seriesSegments.map(({ endpoint, region, segments }) => ({
		id: seriesId(endpoint, region),
		endpoint,
		region,
		...aggregateSegments(segments, objectiveRatio),
		intervals: normalizeIntervalsForReport(segments),
	}));
	const totals = series.reduce((aggregate, entry) => {
		for (const key of ["expected_seconds", "good_seconds", "unavailable_seconds", "excluded_seconds", "unknown_seconds", "not_run_seconds", "eligible_seconds"]) aggregate[key] += entry[key];
		return aggregate;
	}, { expected_seconds: 0, good_seconds: 0, unavailable_seconds: 0, excluded_seconds: 0, unknown_seconds: 0, not_run_seconds: 0, eligible_seconds: 0 });
	for (const key of Object.keys(totals)) totals[key] = roundNumber(totals[key]);
	const overallStatus = overallStatusForSeries(series, totals, objectiveRatio);
	const availabilityRatio = ratio(totals.good_seconds, totals.eligible_seconds);
	const complete = overallStatus === STATUS_PASS || overallStatus === STATUS_FAIL;
	const targetErrorRatio = 1 - objectiveRatio;
	const allowedErrorSeconds = complete ? roundNumber(totals.eligible_seconds * targetErrorRatio) : null;
	const consumedErrorSeconds = complete ? totals.unavailable_seconds : null;
	const remainingErrorSeconds = complete ? roundNumber(allowedErrorSeconds - consumedErrorSeconds) : null;
	const consumedRatio = complete && allowedErrorSeconds > 0 ? ratio(consumedErrorSeconds, allowedErrorSeconds) : null;
	const sourceSha256 = typeof options.sourceSha256 === "string" && (SHA256_PATTERN.test(options.sourceSha256) || options.sourceSha256 === STATUS_UNKNOWN)
		? options.sourceSha256
		: STATUS_UNKNOWN;
	const sourceFile = typeof options.sourceFile === "string" && options.sourceFile.trim() !== "" ? safeBasename(options.sourceFile) : STATUS_UNKNOWN;
	const generatedAt = options.generatedAt ?? new Date().toISOString();
	if (!isIsoTimestamp(generatedAt)) throw new Error("generatedAt must be a canonical UTC ISO-8601 timestamp");

	const report = {
		$schema: REPORT_SCHEMA_URL,
		schema_version: SCHEMA_VERSION,
		kind: KIND,
		generator: { name: GENERATOR, version: SCHEMA_VERSION },
		generated_at: generatedAt,
		month: normalized.month,
		scope: normalized.scope,
		observation_window: {
			start_at: normalized.observation_window.start_at,
			end_at: normalized.observation_window.end_at,
			duration_seconds: roundNumber((end - start) / 1000),
			series_count: series.length,
		},
		target: {
			availability_ratio: objectiveRatio,
			contractual: false,
			label: "internal_reference_only",
		},
		status: overallStatus,
		coverage: {
			expected_seconds: totals.expected_seconds,
			observed_seconds: roundNumber(totals.expected_seconds - totals.not_run_seconds),
			measured_seconds: roundNumber(totals.good_seconds + totals.unavailable_seconds),
			excluded_seconds: totals.excluded_seconds,
			unknown_seconds: totals.unknown_seconds,
			not_run_seconds: totals.not_run_seconds,
			coverage_ratio: ratio(totals.expected_seconds - totals.not_run_seconds, totals.expected_seconds),
			complete,
			status: overallStatus,
		},
		sli: {
			name: "availability",
			unit: "ratio",
			good_seconds: totals.good_seconds,
			unavailable_seconds: totals.unavailable_seconds,
			eligible_seconds: totals.eligible_seconds,
			excluded_seconds: totals.excluded_seconds,
			unknown_seconds: totals.unknown_seconds,
			not_run_seconds: totals.not_run_seconds,
			availability_ratio: availabilityRatio,
			availability_percent: percentage(availabilityRatio),
			status: overallStatus,
		},
		error_budget: {
			objective_ratio: objectiveRatio,
			allowed_error_ratio: targetErrorRatio,
			allowed_error_seconds: allowedErrorSeconds,
			consumed_error_seconds: consumedErrorSeconds,
			remaining_error_seconds: remainingErrorSeconds,
			consumed_ratio: consumedRatio,
			status: overallStatus,
			basis: "eligible_seconds",
		},
		series,
		exclusions: normalized.exclusions.map(({ endpoint, region, start_at, end_at, category, approved, reference }) => ({ endpoint, region, start_at, end_at, category, approved, reference })),
		incidents: normalized.incidents.map(({ id, start_at, end_at, classification, evidence_status, reference }) => ({ id, start_at, end_at, classification, evidence_status, reference })),
		evidence: {
			source_file: sourceFile,
			source_sha256: sourceSha256,
			collection: "local_file",
		},
		limitations: inputLimitations(normalized),
		claims: {
			contractual_99_9_claim: false,
			contractual_sla_claim: false,
			production_sla_proven: false,
			production_accepted: false,
		},
	};
	assertValidMonthlyReport(report);
	return report;
}

function validateReportSeries(entry, index, objectiveRatio, window, failures) {
	const label = `series[${index}]`;
	if (!isPlainObject(entry)) {
		failures.push(`${label} must be an object`);
		return null;
	}
	exactKeys(entry, ["id", "endpoint", "region", "expected_seconds", "good_seconds", "unavailable_seconds", "excluded_seconds", "unknown_seconds", "not_run_seconds", "eligible_seconds", "availability_ratio", "availability_percent", "status", "intervals"], label, failures);
	validateIdentifier(entry.endpoint, `${label}.endpoint`, failures);
	validateIdentifier(entry.region, `${label}.region`, failures);
	if (entry.id !== seriesId(entry.endpoint, entry.region)) failures.push(`${label}.id does not match endpoint@region`);
	if (!isNonNegativeNumber(entry.expected_seconds) || !isNonNegativeNumber(entry.good_seconds) || !isNonNegativeNumber(entry.unavailable_seconds) || !isNonNegativeNumber(entry.excluded_seconds) || !isNonNegativeNumber(entry.unknown_seconds) || !isNonNegativeNumber(entry.not_run_seconds) || !isNonNegativeNumber(entry.eligible_seconds)) failures.push(`${label} duration fields must be non-negative finite numbers`);
	if (!STATUS_VOCABULARY.includes(entry.status)) failures.push(`${label}.status is invalid`);
	if (entry.availability_ratio !== null && (!isFiniteNumber(entry.availability_ratio) || entry.availability_ratio < 0 || entry.availability_ratio > 1)) failures.push(`${label}.availability_ratio must be null or between 0 and 1`);
	if (entry.availability_percent !== null && (!isFiniteNumber(entry.availability_percent) || entry.availability_percent < 0 || entry.availability_percent > 100)) failures.push(`${label}.availability_percent must be null or between 0 and 100`);
	if (!Array.isArray(entry.intervals) || entry.intervals.length === 0) failures.push(`${label}.intervals must be a non-empty array`);
	if (Array.isArray(entry.intervals) && entry.intervals.length > MAX_INTERVALS_PER_SERIES) failures.push(`${label}.intervals may contain at most ${MAX_INTERVALS_PER_SERIES} entries`);
	if (!approximatelyEqual(entry.expected_seconds, window.durationSeconds)) failures.push(`${label}.expected_seconds does not match the report window duration`);
	if (!approximatelyEqual(entry.eligible_seconds, entry.good_seconds + entry.unavailable_seconds)) failures.push(`${label}.eligible_seconds does not match good plus unavailable seconds`);
	const computedRatio = ratio(entry.good_seconds, entry.eligible_seconds);
	if (computedRatio === null ? entry.availability_ratio !== null : !approximatelyEqual(computedRatio, entry.availability_ratio)) failures.push(`${label}.availability_ratio does not match its counters`);
	if (entry.availability_ratio === null ? entry.availability_percent !== null : !approximatelyEqual(percentage(entry.availability_ratio), entry.availability_percent)) failures.push(`${label}.availability_percent does not match availability_ratio`);
	const sum = entry.good_seconds + entry.unavailable_seconds + entry.excluded_seconds + entry.unknown_seconds + entry.not_run_seconds;
	if (!approximatelyEqual(sum, entry.expected_seconds)) failures.push(`${label} counters do not cover expected_seconds`);
	const expectedStatus = reportStatus({ good: entry.good_seconds, unavailable: entry.unavailable_seconds, excluded: entry.excluded_seconds, unknown: entry.unknown_seconds, notRun: entry.not_run_seconds, objectiveRatio });
	if (entry.status !== expectedStatus) failures.push(`${label}.status ${entry.status} does not match the counters (${expectedStatus})`);
	if (Array.isArray(entry.intervals) && entry.intervals.length <= MAX_INTERVALS_PER_SERIES) {
		let cursor = null;
		let intervalSeconds = 0;
		const intervalTotals = { good: 0, unavailable: 0, excluded: 0, unknown: 0, notRun: 0 };
		for (const [intervalIndex, interval] of entry.intervals.entries()) {
			const intervalLabel = `${label}.intervals[${intervalIndex}]`;
			if (!isPlainObject(interval)) {
				failures.push(`${intervalLabel} must be an object`);
				continue;
			}
			exactKeys(interval, ["start_at", "end_at", "status", "reason"], intervalLabel, failures);
			if (hasOwn(interval, "reason")) addUnknownPath(failures, `${intervalLabel}.reason`, interval.reason);
			const start = timestampMillis(interval.start_at, `${intervalLabel}.start_at`, failures);
			const end = timestampMillis(interval.end_at, `${intervalLabel}.end_at`, failures);
			if (!INTERVAL_STATUSES.has(interval.status)) failures.push(`${intervalLabel}.status must be one of good, unavailable, excluded, NOT_RUN, unknown`);
			if (start !== null && end !== null && end <= start) failures.push(`${intervalLabel}.end_at must be after start_at`);
			if (start !== null && cursor !== null && start !== cursor) failures.push(`${intervalLabel} intervals must be contiguous and non-overlapping`);
			if (start !== null && end !== null && end > start) {
				cursor = end;
				const seconds = (end - start) / 1000;
				intervalSeconds += seconds;
				const counter = interval.status === "NOT_RUN" ? "notRun" : interval.status;
				if (Object.hasOwn(intervalTotals, counter)) intervalTotals[counter] += seconds;
			}
		}
		if (!approximatelyEqual(intervalSeconds, entry.expected_seconds)) failures.push(`${label}.intervals do not cover expected_seconds`);
		for (const [counter, field] of [["good", "good_seconds"], ["unavailable", "unavailable_seconds"], ["excluded", "excluded_seconds"], ["unknown", "unknown_seconds"], ["notRun", "not_run_seconds"]]) {
			if (!approximatelyEqual(roundNumber(intervalTotals[counter]), entry[field])) failures.push(`${label}.${field} does not match interval statuses`);
		}
		const firstInterval = entry.intervals[0];
		const lastInterval = entry.intervals.at(-1);
		if (isPlainObject(firstInterval) && entry.intervals.length > 0 && window.start !== null && isIsoTimestamp(firstInterval.start_at) && Date.parse(firstInterval.start_at) !== window.start) failures.push(`${label}.intervals must start at the report window start`);
		if (isPlainObject(lastInterval) && window.end !== null && isIsoTimestamp(lastInterval.end_at) && Date.parse(lastInterval.end_at) !== window.end) failures.push(`${label}.intervals must end at the report window end`);
	}
	return entry;
}

function validateReportExclusion(entry, index, scope, window, failures) {
	const label = `exclusions[${index}]`;
	if (!isPlainObject(entry)) {
		failures.push(`${label} must be an object`);
		return;
	}
	exactKeys(entry, ["endpoint", "region", "start_at", "end_at", "category", "approved", "reference"], label, failures);
	validateIdentifier(entry.endpoint, `${label}.endpoint`, failures);
	validateIdentifier(entry.region, `${label}.region`, failures);
	if (!scope.endpoints.includes(entry.endpoint)) failures.push(`${label}.endpoint is outside scope`);
	if (!scope.regions.includes(entry.region)) failures.push(`${label}.region is outside scope`);
	if (!EXCLUSION_CATEGORIES.has(entry.category)) failures.push(`${label}.category is invalid`);
	if (entry.approved !== true) failures.push(`${label}.approved must be true`);
	addUnknownPath(failures, `${label}.reference`, entry.reference);
	const start = timestampMillis(entry.start_at, `${label}.start_at`, failures);
	const end = timestampMillis(entry.end_at, `${label}.end_at`, failures);
	if (start !== null && end !== null && end <= start) failures.push(`${label}.end_at must be after start_at`);
	if (start !== null && window.start !== null && start < window.start) failures.push(`${label}.start_at is before the report window`);
	if (end !== null && window.end !== null && end > window.end) failures.push(`${label}.end_at is after the report window`);
}

function validateReportIncident(entry, index, window, failures) {
	const label = `incidents[${index}]`;
	if (!isPlainObject(entry)) {
		failures.push(`${label} must be an object`);
		return;
	}
	exactKeys(entry, ["id", "start_at", "end_at", "classification", "evidence_status", "reference"], label, failures);
	validateIdentifier(entry.id, `${label}.id`, failures);
	if (!INCIDENT_CLASSES.has(entry.classification)) failures.push(`${label}.classification is invalid`);
	if (!INCIDENT_EVIDENCE_STATUSES.has(entry.evidence_status)) failures.push(`${label}.evidence_status is invalid`);
	addUnknownPath(failures, `${label}.reference`, entry.reference);
	const start = timestampMillis(entry.start_at, `${label}.start_at`, failures);
	const end = timestampMillis(entry.end_at, `${label}.end_at`, failures);
	if (start !== null && end !== null && end <= start) failures.push(`${label}.end_at must be after start_at`);
	if (start !== null && window.start !== null && start < window.start) failures.push(`${label}.start_at is before the report window`);
	if (end !== null && window.end !== null && end > window.end) failures.push(`${label}.end_at is after the report window`);
}

function validateReportClaims(claims, failures) {
	if (!isPlainObject(claims)) {
		failures.push("claims must be an object");
		return;
	}
	exactKeys(claims, ["contractual_99_9_claim", "contractual_sla_claim", "production_sla_proven", "production_accepted"], "claims", failures);
	for (const key of ["contractual_99_9_claim", "contractual_sla_claim", "production_sla_proven", "production_accepted"]) {
		if (claims[key] !== false) failures.push(`claims.${key} must be false`);
	}
}

/**
 * Validate a generated report, including counter arithmetic and status
 * semantics. A structurally valid NOT_RUN or unknown report returns valid=true;
 * those statuses are evidence of absence, not failures in the validator.
 */
export function validateMonthlyReport(report, options = {}) {
	options ??= {};
	const failures = [];
	if (!isPlainObject(report)) return { valid: false, status: STATUS_UNKNOWN, errors: ["report must be an object"] };
	exactKeys(report, ["$schema", "schema_version", "kind", "generator", "generated_at", "month", "scope", "observation_window", "target", "status", "coverage", "sli", "error_budget", "series", "exclusions", "incidents", "evidence", "limitations", "claims"], "report", failures);
	if (hasOwn(report, "$schema") && report.$schema !== REPORT_SCHEMA_URL) failures.push(`report.$schema must be ${REPORT_SCHEMA_URL}`);
	if (report.schema_version !== SCHEMA_VERSION) failures.push(`report.schema_version must be ${SCHEMA_VERSION}`);
	if (report.kind !== KIND) failures.push(`report.kind must be ${KIND}`);
	if (!isPlainObject(report.generator)) failures.push("generator must be an object");
	else {
		exactKeys(report.generator, ["name", "version"], "generator", failures);
		if (report.generator.name !== GENERATOR) failures.push(`generator.name must be ${GENERATOR}`);
		if (report.generator.version !== SCHEMA_VERSION) failures.push(`generator.version must be ${SCHEMA_VERSION}`);
	}
	if (!isIsoTimestamp(report.generated_at)) failures.push("generated_at must be a canonical UTC ISO-8601 timestamp");
	validateMonth(report.month, "month", failures);
	const scope = validateScope(report.scope, failures);
	const window = validateWindow(report.observation_window, report.month, failures, "observation_window", true);
	if (isPlainObject(report.observation_window)) {
		if (!isNonNegativeNumber(report.observation_window.duration_seconds) || !approximatelyEqual(report.observation_window.duration_seconds, window.durationSeconds)) failures.push("observation_window.duration_seconds does not match its timestamps");
		if (!isInteger(report.observation_window.series_count) || report.observation_window.series_count < 1) failures.push("observation_window.series_count must be a positive integer");
	}
	const objectiveRatio = validateObjective(report.target, failures, "target");
	if (!STATUS_VOCABULARY.includes(report.status)) failures.push(`report.status must be one of ${STATUS_VOCABULARY.join(", ")}`);
	if (report.status === STATUS_PASS && !isFullCalendarMonth(report.observation_window, report.month)) {
		failures.push("PASS requires observations covering the full named UTC calendar month");
	}

	if (!isPlainObject(report.coverage)) failures.push("coverage must be an object");
	else {
		exactKeys(report.coverage, ["expected_seconds", "observed_seconds", "measured_seconds", "excluded_seconds", "unknown_seconds", "not_run_seconds", "coverage_ratio", "complete", "status"], "coverage", failures);
		for (const key of ["expected_seconds", "observed_seconds", "measured_seconds", "excluded_seconds", "unknown_seconds", "not_run_seconds"]) if (!isNonNegativeNumber(report.coverage[key])) failures.push(`coverage.${key} must be a non-negative finite number`);
		if (report.coverage.coverage_ratio !== null && (!isFiniteNumber(report.coverage.coverage_ratio) || report.coverage.coverage_ratio < 0 || report.coverage.coverage_ratio > 1)) failures.push("coverage.coverage_ratio must be null or between 0 and 1");
		if (typeof report.coverage.complete !== "boolean") failures.push("coverage.complete must be a boolean");
		if (!STATUS_VOCABULARY.includes(report.coverage.status)) failures.push("coverage.status is invalid");
	}

	if (!isPlainObject(report.sli)) failures.push("sli must be an object");
	else {
		exactKeys(report.sli, ["name", "unit", "good_seconds", "unavailable_seconds", "eligible_seconds", "excluded_seconds", "unknown_seconds", "not_run_seconds", "availability_ratio", "availability_percent", "status"], "sli", failures);
		if (report.sli.name !== "availability" || report.sli.unit !== "ratio") failures.push("sli must describe availability as a ratio");
		for (const key of ["good_seconds", "unavailable_seconds", "eligible_seconds", "excluded_seconds", "unknown_seconds", "not_run_seconds"]) if (!isNonNegativeNumber(report.sli[key])) failures.push(`sli.${key} must be a non-negative finite number`);
		if (report.sli.availability_ratio !== null && (!isFiniteNumber(report.sli.availability_ratio) || report.sli.availability_ratio < 0 || report.sli.availability_ratio > 1)) failures.push("sli.availability_ratio must be null or between 0 and 1");
		if (report.sli.availability_percent !== null && (!isFiniteNumber(report.sli.availability_percent) || report.sli.availability_percent < 0 || report.sli.availability_percent > 100)) failures.push("sli.availability_percent must be null or between 0 and 100");
		if (!STATUS_VOCABULARY.includes(report.sli.status)) failures.push("sli.status is invalid");
	}

	if (!isPlainObject(report.error_budget)) failures.push("error_budget must be an object");
	else {
		exactKeys(report.error_budget, ["objective_ratio", "allowed_error_ratio", "allowed_error_seconds", "consumed_error_seconds", "remaining_error_seconds", "consumed_ratio", "status", "basis"], "error_budget", failures);
		if (!approximatelyEqual(report.error_budget.objective_ratio, objectiveRatio)) failures.push("error_budget.objective_ratio must match target.availability_ratio");
		if (!isFiniteNumber(report.error_budget.allowed_error_ratio) || report.error_budget.allowed_error_ratio < 0 || report.error_budget.allowed_error_ratio > 1) failures.push("error_budget.allowed_error_ratio is invalid");
		for (const key of ["allowed_error_seconds", "consumed_error_seconds", "consumed_ratio"]) if (report.error_budget[key] !== null && !isNonNegativeNumber(report.error_budget[key])) failures.push(`error_budget.${key} must be null or non-negative`);
		if (report.error_budget.remaining_error_seconds !== null && !isFiniteNumber(report.error_budget.remaining_error_seconds)) failures.push("error_budget.remaining_error_seconds must be null or finite");
		if (report.error_budget.basis !== "eligible_seconds") failures.push("error_budget.basis must be eligible_seconds");
		if (!STATUS_VOCABULARY.includes(report.error_budget.status)) failures.push("error_budget.status is invalid");
	}

	const series = Array.isArray(report.series) && report.series.length <= MAX_SERIES ? report.series.map((entry, index) => validateReportSeries(entry, index, objectiveRatio, window, failures)).filter(Boolean) : [];
	if (!Array.isArray(report.series) || report.series.length === 0) failures.push("series must be a non-empty array");
	if (Array.isArray(report.series) && report.series.length > MAX_SERIES) failures.push(`series may contain at most ${MAX_SERIES} entries`);
	if (Array.isArray(report.series) && report.series.length <= MAX_SERIES) {
		const seen = new Set();
		for (const entry of series) {
			const key = seriesKey(entry.endpoint, entry.region);
			if (seen.has(key)) failures.push(`series contains duplicate ${entry.id}`);
			seen.add(key);
			if (!scope.endpoints.includes(entry.endpoint) || !scope.regions.includes(entry.region)) failures.push(`series ${entry.id} is outside scope`);
		}
		const expectedSeriesCount = scope.endpoints.length * scope.regions.length;
		if (report.series.length !== expectedSeriesCount) failures.push(`series must contain exactly ${expectedSeriesCount} endpoint-region series`);
		if (isPlainObject(report.observation_window) && report.observation_window.series_count !== expectedSeriesCount) failures.push(`observation_window.series_count must be ${expectedSeriesCount}`);
	}

	if (!Array.isArray(report.exclusions)) failures.push("exclusions must be an array");
	else if (report.exclusions.length > MAX_EXCLUSIONS) failures.push(`exclusions may contain at most ${MAX_EXCLUSIONS} entries`);
	else {
		report.exclusions.forEach((entry, index) => validateReportExclusion(entry, index, scope, window, failures));
		const exclusionIntervals = report.exclusions
			.filter((entry) => isPlainObject(entry) && isIsoTimestamp(entry.start_at) && isIsoTimestamp(entry.end_at))
			.map((entry) => ({ ...entry, start: Date.parse(entry.start_at), end: Date.parse(entry.end_at) }));
		const exclusionsBySeries = new Map();
		const approvedExclusionCounts = new Map();
		for (const exclusion of exclusionIntervals) {
			const seriesKeyValue = seriesKey(exclusion.endpoint, exclusion.region);
			const entries = exclusionsBySeries.get(seriesKeyValue) ?? [];
			entries.push(exclusion);
			exclusionsBySeries.set(seriesKeyValue, entries);
			const key = intervalKey(exclusion.endpoint, exclusion.region, exclusion.start, exclusion.end);
			approvedExclusionCounts.set(key, (approvedExclusionCounts.get(key) ?? 0) + 1);
		}
		for (const [seriesKeyValue, entries] of exclusionsBySeries) {
			entries.sort((left, right) => left.start - right.start || left.end - right.end);
			for (let index = 1; index < entries.length; index += 1) {
				if (entries[index].start < entries[index - 1].end) failures.push(`exclusions ${seriesKeyValue.replace(/\u0000/g, "@")} overlap`);
			}
		}
		const excludedIntervalCounts = new Map();
		for (const entry of series) {
			if (!Array.isArray(entry.intervals)) continue;
			for (const interval of entry.intervals) {
				if (!isPlainObject(interval) || interval.status !== "excluded" || !isIsoTimestamp(interval.start_at) || !isIsoTimestamp(interval.end_at)) continue;
				const key = intervalKey(entry.endpoint, entry.region, Date.parse(interval.start_at), Date.parse(interval.end_at));
				excludedIntervalCounts.set(key, (excludedIntervalCounts.get(key) ?? 0) + 1);
			}
		}
		for (const [index, exclusion] of report.exclusions.entries()) {
			if (!isPlainObject(exclusion) || !isIsoTimestamp(exclusion.start_at) || !isIsoTimestamp(exclusion.end_at)) continue;
			const key = intervalKey(exclusion.endpoint, exclusion.region, Date.parse(exclusion.start_at), Date.parse(exclusion.end_at));
			if (excludedIntervalCounts.get(key) !== 1) failures.push(`exclusions[${index}] must link to exactly one excluded interval in its scoped series`);
		}
		for (const [key, count] of excludedIntervalCounts) {
			if (approvedExclusionCounts.get(key) !== 1 || count !== 1) failures.push("excluded interval must have exactly one matching approved exclusion");
		}
	}
	if (!Array.isArray(report.incidents)) failures.push("incidents must be an array");
	else if (report.incidents.length > MAX_INCIDENTS) failures.push(`incidents may contain at most ${MAX_INCIDENTS} entries`);
	else {
		report.incidents.forEach((entry, index) => validateReportIncident(entry, index, window, failures));
		validateUniqueIncidentIds(report.incidents, failures);
	}
	if (!isPlainObject(report.evidence)) failures.push("evidence must be an object");
	else {
		exactKeys(report.evidence, ["source_file", "source_sha256", "collection"], "evidence", failures);
		if (typeof report.evidence.source_file !== "string" || report.evidence.source_file.trim() === "") failures.push("evidence.source_file must be non-empty or unknown");
		if (typeof report.evidence.source_file === "string" && report.evidence.source_file !== STATUS_UNKNOWN && safeBasename(report.evidence.source_file) !== report.evidence.source_file) failures.push("evidence.source_file must be a basename, not an absolute or nested path");
		if (report.evidence.source_sha256 !== STATUS_UNKNOWN && !SHA256_PATTERN.test(report.evidence.source_sha256)) failures.push("evidence.source_sha256 must be a SHA-256 digest or unknown");
		if (report.evidence.collection !== "local_file") failures.push("evidence.collection must be local_file");
		if (options.sourceSha256 !== undefined && report.evidence.source_sha256 !== options.sourceSha256) failures.push("evidence.source_sha256 does not match the supplied source file");
		if (options.sourceFile !== undefined && report.evidence.source_file !== safeBasename(options.sourceFile)) failures.push("evidence.source_file does not match the supplied source file");
	}
	if (!Array.isArray(report.limitations) || report.limitations.length < 3 || report.limitations.length > MAX_REPORT_LIMITATIONS || report.limitations.some((value) => typeof value !== "string" || value.trim() === "")) failures.push(`limitations must contain between 3 and ${MAX_REPORT_LIMITATIONS} non-empty strings`);
	validateReportClaims(report.claims, failures);

	if (series.length > 0 && isPlainObject(report.sli) && isPlainObject(report.coverage) && isPlainObject(report.error_budget)) {
		const totals = series.reduce((aggregate, entry) => {
			for (const key of ["expected_seconds", "good_seconds", "unavailable_seconds", "excluded_seconds", "unknown_seconds", "not_run_seconds", "eligible_seconds"]) aggregate[key] += entry[key];
			return aggregate;
		}, { expected_seconds: 0, good_seconds: 0, unavailable_seconds: 0, excluded_seconds: 0, unknown_seconds: 0, not_run_seconds: 0, eligible_seconds: 0 });
		for (const key of Object.keys(totals)) totals[key] = roundNumber(totals[key]);
		for (const key of ["good_seconds", "unavailable_seconds", "eligible_seconds", "excluded_seconds", "unknown_seconds", "not_run_seconds"]) if (!approximatelyEqual(report.sli[key], totals[key])) failures.push(`sli.${key} does not match series totals`);
		if (!approximatelyEqual(report.coverage.expected_seconds, totals.expected_seconds)) failures.push("coverage.expected_seconds does not match series totals");
		if (!approximatelyEqual(report.coverage.observed_seconds, totals.expected_seconds - totals.not_run_seconds)) failures.push("coverage.observed_seconds does not match series totals");
		if (!approximatelyEqual(report.coverage.measured_seconds, totals.good_seconds + totals.unavailable_seconds)) failures.push("coverage.measured_seconds does not match series totals");
		if (!approximatelyEqual(report.coverage.excluded_seconds, totals.excluded_seconds) || !approximatelyEqual(report.coverage.unknown_seconds, totals.unknown_seconds) || !approximatelyEqual(report.coverage.not_run_seconds, totals.not_run_seconds)) failures.push("coverage counters do not match series totals");
		const computedRatio = ratio(totals.good_seconds, totals.eligible_seconds);
		if (computedRatio === null ? report.sli.availability_ratio !== null : !approximatelyEqual(computedRatio, report.sli.availability_ratio)) failures.push("sli.availability_ratio does not match series totals");
		if (computedRatio === null ? report.sli.availability_percent !== null : !approximatelyEqual(percentage(computedRatio), report.sli.availability_percent)) failures.push("sli.availability_percent does not match series totals");
		const expectedStatus = overallStatusForSeries(series, totals, objectiveRatio);
		if (report.status !== expectedStatus || report.coverage.status !== expectedStatus || report.sli.status !== expectedStatus || report.error_budget.status !== expectedStatus) failures.push(`report status fields do not match the counters (${expectedStatus})`);
		const complete = expectedStatus === STATUS_PASS || expectedStatus === STATUS_FAIL;
		if (report.coverage.complete !== complete) failures.push("coverage.complete does not match report status");
		const coverageRatio = ratio(totals.expected_seconds - totals.not_run_seconds, totals.expected_seconds);
		if (coverageRatio === null ? report.coverage.coverage_ratio !== null : !approximatelyEqual(coverageRatio, report.coverage.coverage_ratio)) failures.push("coverage.coverage_ratio does not match counters");
		const allowedErrorRatio = 1 - objectiveRatio;
		const allowed = complete ? roundNumber(totals.eligible_seconds * allowedErrorRatio) : null;
		const consumed = complete ? totals.unavailable_seconds : null;
		const remaining = complete ? roundNumber(allowed - consumed) : null;
		const consumedShare = complete && allowed > 0 ? ratio(consumed, allowed) : null;
		if (complete) {
			if (!approximatelyEqual(report.error_budget.allowed_error_seconds, allowed) || !approximatelyEqual(report.error_budget.consumed_error_seconds, consumed) || !approximatelyEqual(report.error_budget.remaining_error_seconds, remaining)) failures.push("error budget counters do not match SLI counters");
		} else if (report.error_budget.allowed_error_seconds !== null || report.error_budget.consumed_error_seconds !== null || report.error_budget.remaining_error_seconds !== null) {
			failures.push("incomplete reports must not publish an error-budget duration");
		}
		if (consumedShare === null ? report.error_budget.consumed_ratio !== null : !approximatelyEqual(consumedShare, report.error_budget.consumed_ratio)) failures.push("error_budget.consumed_ratio does not match counters");
		if (!approximatelyEqual(report.error_budget.allowed_error_ratio, allowedErrorRatio)) failures.push("error_budget.allowed_error_ratio does not match target");
	}
	return { valid: failures.length === 0, status: report.status ?? STATUS_UNKNOWN, errors: failures };
}

export function assertValidMonthlyReport(report) {
	const result = validateMonthlyReport(report);
	if (!result.valid) throw new Error(`invalid monthly SLI report: ${result.errors.join("; ")}`);
	return report;
}

export function sha256(bytes) {
	return createHash("sha256").update(bytes).digest("hex");
}

function readBoundedFile(path, label, maxBytes = MAX_INPUT_BYTES) {
	const stats = statSync(path);
	if (!stats.isFile()) throw new Error(`${label} must be a regular file`);
	if (stats.size > maxBytes) throw new Error(`${label} exceeds the ${maxBytes}-byte local input limit`);
	return readFileSync(path);
}

function usage() {
	return [
		"Usage:",
		"  node scripts/monthly-sli-report.mjs [generate] --input OBSERVATIONS.json [--output REPORT.json] [--force] [--generated-at ISO]",
		"  node scripts/monthly-sli-report.mjs validate --report REPORT.json [--input OBSERVATIONS.json]",
		"  node scripts/monthly-sli-report.mjs --validate REPORT.json [--input OBSERVATIONS.json]",
	].join("\n");
}

function parseCliArguments(argv) {
	const options = { mode: null, input: null, output: "-", report: null, force: false, generatedAt: null, help: false };
	for (let index = 0; index < argv.length; index += 1) {
		const argument = argv[index];
		if (argument === "--help" || argument === "-h") {
			options.help = true;
			continue;
		}
		if (argument === "generate") {
			if (options.mode && options.mode !== "generate") throw new Error("only one mode may be selected");
			options.mode = "generate";
			continue;
		}
		if (argument === "validate") {
			if (options.mode && options.mode !== "validate") throw new Error("only one mode may be selected");
			options.mode = "validate";
			continue;
		}
		if (argument === "--force") {
			options.force = true;
			continue;
		}
		if (argument === "--validate") {
			options.mode = "validate";
			const value = argv[index + 1];
			if (value && !value.startsWith("-")) {
				options.report = value;
				index += 1;
			}
			continue;
		}
		if (argument === "--input" || argument === "--output" || argument === "--report" || argument === "--generated-at") {
			const value = argv[index + 1];
			if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value`);
			index += 1;
			if (argument === "--input") options.input = value;
			else if (argument === "--output") options.output = value;
			else if (argument === "--report") {
				options.report = value;
				options.mode = "validate";
			} else options.generatedAt = value;
			continue;
		}
		if (argument.startsWith("-")) throw new Error(`unknown option ${argument}`);
		if (options.mode === "validate") {
			if (options.report === null) options.report = argument;
			else throw new Error(`unexpected argument ${argument}`);
		} else if (options.input === null) options.input = argument;
		else if (options.output === "-") options.output = argument;
		else throw new Error(`unexpected argument ${argument}`);
	}
	if (!options.mode) options.mode = options.report ? "validate" : "generate";
	return options;
}

export function runCli(argv = process.argv.slice(2)) {
	const options = parseCliArguments(argv);
	if (options.help) {
		console.log(usage());
		return 0;
	}
	if (options.mode === "generate") {
		if (!options.input) throw new Error("generate mode requires --input");
		const inputPath = resolve(options.input);
		const bytes = readBoundedFile(inputPath, "input file");
		const input = JSON.parse(bytes.toString("utf8"));
		const report = generateMonthlyReport(input, {
			sourceFile: options.input,
			sourceSha256: sha256(bytes),
			generatedAt: options.generatedAt ?? undefined,
		});
		const output = options.output === "-" ? null : resolve(options.output);
		const serialized = `${JSON.stringify(report, null, 2)}\n`;
		if (output) {
			writeFileSync(output, serialized, { flag: options.force ? "w" : "wx" });
			console.log(JSON.stringify({ status: "generated", report_status: report.status, month: report.month, output: options.output }));
		} else {
			process.stdout.write(serialized);
		}
		return 0;
	}
	if (!options.report) throw new Error("validate mode requires --report");
	const reportPath = resolve(options.report);
	const report = JSON.parse(readBoundedFile(reportPath, "report file", MAX_REPORT_BYTES).toString("utf8"));
	const sourceOptions = options.input
		? (() => {
			const sourcePath = resolve(options.input);
			const bytes = readBoundedFile(sourcePath, "source file");
			return { sourceFile: options.input, sourceSha256: sha256(bytes) };
		})()
		: {};
	const result = validateMonthlyReport(report, sourceOptions);
	if (!result.valid) {
		for (const failure of result.errors) console.error(`- ${failure}`);
		console.error(`Monthly SLI report: INVALID (${result.errors.length} error(s))`);
		return 1;
	}
	console.log(JSON.stringify({ status: "validated", report_status: result.status, month: report.month, report: options.report }));
	return 0;
}

export {
	generateMonthlyReport as generateReport,
	generateMonthlyReport as generateMonthlySliReport,
	validateMonthlyReport as validateReport,
	validateMonthlyReport as validateMonthlySliReport,
};

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
	try {
		process.exitCode = runCli();
	} catch (error) {
		console.error(`Monthly SLI error: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 2;
	}
}
