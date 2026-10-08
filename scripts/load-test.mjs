#!/usr/bin/env node
import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";

const RESULT_KIND = "aidr_load_test_result";
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function fail(message, code = 1) {
	console.error(message);
	process.exit(code);
}

function parseArgs(argv) {
	const args = { allowedHosts: [] };
	for (let i = 0; i < argv.length; i += 1) {
		const token = argv[i];
		if (token === "--profile") args.profile = argv[++i];
		else if (token === "--output") args.output = argv[++i];
		else if (token === "--allow-host") args.allowedHosts.push(argv[++i]);
		else if (token === "--overwrite") args.overwrite = true;
		else if (token === "--dry-run") args.dryRun = true;
		else if (token === "--help" || token === "-h") args.help = true;
		else fail(`Unknown argument: ${token}`);
	}
	return args;
}

function usage() {
	console.log(`Usage:
  node scripts/load-test.mjs --profile FILE --output FILE [--allow-host HOST] [--overwrite]
  node scripts/load-test.mjs --profile FILE --output FILE --dry-run

Only loopback targets are allowed by default. Repeat --allow-host for an explicitly
authorized non-loopback target. The runner never executes infrastructure fault
commands; fault windows are observation periods for an operator-controlled drill.`);
}

function boundedNumber(value, label, minimum, maximum) {
	if (!Number.isFinite(value) || value < minimum || value > maximum) {
		fail(`${label} must be between ${minimum} and ${maximum}`);
	}
	return value;
}

function boundedInteger(value, label, minimum, maximum) {
	if (!Number.isInteger(value)) fail(`${label} must be an integer`);
	return boundedNumber(value, label, minimum, maximum);
}

function validateProfile(profile) {
	if (!profile || typeof profile !== "object" || Array.isArray(profile)) fail("Profile must be a JSON object");
	if (profile.schema_version !== 1) fail("Profile schema_version must be 1");
	if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$/.test(profile.workload_id ?? "")) fail("Invalid workload_id");
	if (!["load", "soak", "failover", "noisy_neighbor"].includes(profile.workload_class)) fail("Invalid workload_class");
	if (!/^[A-Z][A-Z0-9_]{2,127}$/.test(profile.base_url_env ?? "")) fail("base_url_env must name an environment variable");
	boundedNumber(profile.duration_seconds, "duration_seconds", 0.2, 604800);
	boundedNumber(profile.rate_per_second, "rate_per_second", 0.1, 10000);
	boundedInteger(profile.max_in_flight, "max_in_flight", 1, 10000);
	boundedInteger(profile.request_timeout_ms ?? 10000, "request_timeout_ms", 100, 120000);
	boundedInteger(profile.max_response_bytes ?? 1048576, "max_response_bytes", 0, 16777216);
	boundedInteger(profile.max_latency_samples ?? 250000, "max_latency_samples", 100, 1000000);
	boundedInteger(profile.max_fault_event_samples ?? 250000, "max_fault_event_samples", 100, 1000000);
	const validateThresholds = (thresholds, label) => {
		if (!thresholds || typeof thresholds !== "object" || Array.isArray(thresholds)) fail(`${label} must be an object`);
		const allowed = new Set(["min_requests", "max_error_ratio", "max_loss_ratio", "min_availability_ratio", "max_p95_ms", "max_p99_ms"]);
		for (const key of Object.keys(thresholds)) if (!allowed.has(key)) fail(`Unknown ${label} field: ${key}`);
		if (thresholds.min_requests !== undefined && (!Number.isInteger(thresholds.min_requests) || thresholds.min_requests < 0)) fail(`${label}.min_requests must be a non-negative integer`);
		for (const key of ["max_error_ratio", "max_loss_ratio", "min_availability_ratio"]) if (thresholds[key] !== undefined) boundedNumber(thresholds[key], `${label}.${key}`, 0, 1);
		for (const key of ["max_p95_ms", "max_p99_ms"]) if (thresholds[key] !== undefined) boundedNumber(thresholds[key], `${label}.${key}`, 0, 120000);
		if (thresholds.min_requests === undefined || !["max_loss_ratio", "min_availability_ratio"].some((key) => thresholds[key] !== undefined)) fail(`${label} requires min_requests and a generator-loss or end-to-end availability bound`);
	};
	validateThresholds(profile.thresholds, "thresholds");
	if (!Array.isArray(profile.scenarios) || profile.scenarios.length === 0 || profile.scenarios.length > 100) fail("scenarios must contain 1..100 entries");
	const names = new Set();
	for (const scenario of profile.scenarios) {
		if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(scenario.name ?? "") || names.has(scenario.name)) fail("Scenario names must be unique identifiers");
		names.add(scenario.name);
		if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(scenario.cohort ?? "")) fail(`Invalid cohort for ${scenario.name}`);
		if (typeof scenario.path !== "string" || !scenario.path.startsWith("/") || scenario.path.startsWith("//")) fail(`Scenario ${scenario.name} path must be relative to base URL`);
		if (!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].includes(scenario.method)) fail(`Invalid method for ${scenario.name}`);
		boundedInteger(scenario.weight, `${scenario.name}.weight`, 1, 1000);
		if (!Array.isArray(scenario.expected_statuses) || scenario.expected_statuses.length === 0 || scenario.expected_statuses.some((status) => !Number.isInteger(status) || status < 100 || status > 599)) fail(`Invalid expected_statuses for ${scenario.name}`);
		for (const [header, envName] of Object.entries(scenario.headers_env ?? {})) {
			if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(header) || !/^[A-Z][A-Z0-9_]{2,127}$/.test(envName)) fail(`Invalid environment-backed header for ${scenario.name}`);
		}
		if (["GET", "HEAD"].includes(scenario.method) && scenario.body_json !== undefined) fail(`${scenario.name} cannot attach body_json to ${scenario.method}`);
		if (scenario.thresholds !== undefined) validateThresholds(scenario.thresholds, `${scenario.name}.thresholds`);
	}
	const windows = profile.fault_windows ?? [];
	if (!Array.isArray(windows) || windows.length > 20) fail("fault_windows must be an array with at most 20 entries");
	if (profile.workload_class === "failover" && windows.length === 0) fail("failover workloads require at least one fault window");
	const windowNames = new Set();
	for (const window of windows) {
		if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(window.name ?? "") || windowNames.has(window.name)) fail("Fault window names must be unique identifiers");
		windowNames.add(window.name);
		if (typeof window.target !== "string" || !window.target.trim()) fail(`${window.name}.target must identify the fault target`);
		if (!Array.isArray(window.scenario_names) || window.scenario_names.length === 0 || window.scenario_names.some((name) => !names.has(name))) fail(`${window.name}.scenario_names must identify at least one declared scenario`);
		boundedNumber(window.start_seconds, `${window.name}.start_seconds`, 0, profile.duration_seconds);
		boundedNumber(window.end_seconds, `${window.name}.end_seconds`, window.start_seconds, profile.duration_seconds);
		if (window.end_seconds === window.start_seconds) fail(`${window.name}.end_seconds must be after start_seconds`);
		boundedInteger(window.recovery_confirmation_successes ?? 5, `${window.name}.recovery_confirmation_successes`, 1, 1000);
		if (window.require_fault_observed !== undefined && typeof window.require_fault_observed !== "boolean") fail(`${window.name}.require_fault_observed must be a boolean`);
		if (profile.workload_class === "failover" && window.require_fault_observed !== true) fail(`${window.name}.require_fault_observed must be true for failover workloads`);
		if (window.max_rto_ms !== undefined) boundedNumber(window.max_rto_ms, `${window.name}.max_rto_ms`, 0, 604800000);
	}
	return profile;
}

function resolveTemplate(value, sequence) {
	if (Array.isArray(value)) return value.map((item) => resolveTemplate(item, sequence));
	if (!value || typeof value !== "object") return value;
	const keys = Object.keys(value);
	if (keys.length === 1 && keys[0] === "$env") {
		const envName = value.$env;
		if (typeof envName !== "string" || !process.env[envName]) fail(`Required body environment variable is missing: ${envName}`);
		return process.env[envName];
	}
	if (keys.length === 1 && keys[0] === "$sequence") return sequence;
	if (keys.length === 1 && keys[0] === "$request_id") return randomUUID();
	if (keys.length === 1 && keys[0] === "$timestamp") return new Date().toISOString();
	return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, resolveTemplate(item, sequence)]));
}

function resolveRequest(scenario, sequence) {
	const headers = {};
	for (const [header, envName] of Object.entries(scenario.headers_env ?? {})) {
		const value = process.env[envName];
		if (!value) fail(`Required header environment variable is missing: ${envName}`);
		headers[header] = value;
	}
	let body;
	if (scenario.body_json !== undefined) {
		headers["content-type"] ??= "application/json";
		body = JSON.stringify(resolveTemplate(scenario.body_json, sequence));
	}
	return { headers, body };
}

class Aggregate {
	constructor(maxSamples) {
		this.maxSamples = maxSamples;
		this.scheduled = 0;
		this.started = 0;
		this.completed = 0;
		this.expected = 0;
		this.unexpected = 0;
		this.transportErrors = 0;
		this.dropped = 0;
		this.latencies = [];
		this.latencyCount = 0;
		this.latencyMax = 0;
		this.statusCounts = new Map();
		this.failureClasses = new Map();
	}

	schedule() { this.scheduled += 1; }
		drop() { this.dropped += 1; }
	start() { this.started += 1; }
	complete(durationMs, expected, status, failureClass) {
		this.completed += 1;
		if (expected) this.expected += 1;
		else if (status === null || (failureClass && failureClass !== "unexpected_status")) this.transportErrors += 1;
		else this.unexpected += 1;
		this.latencyCount += 1;
		this.latencyMax = Math.max(this.latencyMax, durationMs);
		if (this.latencies.length < this.maxSamples) this.latencies.push(durationMs);
		else {
			const slot = Math.floor(Math.random() * this.latencyCount);
			if (slot < this.maxSamples) this.latencies[slot] = durationMs;
		}
		const key = status === null ? "transport_error" : String(status);
		this.statusCounts.set(key, (this.statusCounts.get(key) ?? 0) + 1);
		if (failureClass) this.failureClasses.set(failureClass, (this.failureClasses.get(failureClass) ?? 0) + 1);
	}

	snapshot() {
		const sorted = [...this.latencies].sort((a, b) => a - b);
		const percentile = (fraction) => sorted.length ? sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)] : null;
		const failed = this.unexpected + this.transportErrors;
		return {
			scheduled: this.scheduled,
			started: this.started,
			completed: this.completed,
			expected_responses: this.expected,
			unexpected_responses: this.unexpected,
			transport_errors: this.transportErrors,
			dropped_requests: this.dropped,
			availability_ratio: this.scheduled ? this.expected / this.scheduled : 0,
			error_ratio: this.started ? failed / this.started : 1,
			loss_ratio: this.scheduled ? this.dropped / this.scheduled : 0,
			latency_ms: {
				p50: percentile(0.5),
				p95: percentile(0.95),
				p99: percentile(0.99),
				max: this.latencyCount ? this.latencyMax : null,
				samples: sorted.length,
				observations: this.latencyCount,
				sampling: sorted.length < this.latencyCount ? "reservoir" : "complete",
			},
			status_counts: Object.fromEntries([...this.statusCounts].sort(([a], [b]) => a.localeCompare(b))),
		};
	}
}

class SampleSeries {
	constructor(maxSamples) {
		this.maxSamples = maxSamples;
		this.values = [];
		this.count = 0;
		this.maximum = 0;
	}

	observe(value) {
		this.count += 1;
		this.maximum = Math.max(this.maximum, value);
		if (this.values.length < this.maxSamples) this.values.push(value);
		else {
			const slot = Math.floor(Math.random() * this.count);
			if (slot < this.maxSamples) this.values[slot] = value;
		}
	}

	snapshot() {
		const sorted = [...this.values].sort((a, b) => a - b);
		const percentile = (fraction) => sorted.length ? sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)] : null;
		return {
			p50: percentile(0.5),
			p95: percentile(0.95),
			p99: percentile(0.99),
			max: this.count ? this.maximum : null,
			samples: sorted.length,
			observations: this.count,
			sampling: sorted.length < this.count ? "reservoir" : "complete",
		};
	}
}

function classifyError(error) {
	if (error?.message === "response_body_limit_exceeded") return "response_body_limit";
	if (error?.name === "TimeoutError" || error?.name === "AbortError") return "timeout";
	if (error instanceof TypeError) return error.cause ? "network" : "client_error";
	return "other";
}

async function consumeResponse(response, maxBytes) {
	if (!response.body) return;
	const reader = response.body.getReader();
	let received = 0;
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) return;
			received += value.byteLength;
			if (received > maxBytes) {
				await reader.cancel("response_body_limit_exceeded");
				throw new Error("response_body_limit_exceeded");
			}
		}
	} finally {
		reader.releaseLock();
	}
}

function evaluateThresholds(label, metrics, thresholds = {}) {
	const checks = [];
	const add = (metric, operator, actual, expected, passed) => checks.push({ label, metric, operator, actual, expected, passed });
	if (thresholds.min_requests !== undefined) add("completed", ">=", metrics.completed, thresholds.min_requests, metrics.completed >= thresholds.min_requests);
	if (thresholds.max_error_ratio !== undefined) add("error_ratio", "<=", metrics.error_ratio, thresholds.max_error_ratio, metrics.error_ratio <= thresholds.max_error_ratio);
	if (thresholds.max_loss_ratio !== undefined) add("loss_ratio", "<=", metrics.loss_ratio, thresholds.max_loss_ratio, metrics.loss_ratio <= thresholds.max_loss_ratio);
	if (thresholds.min_availability_ratio !== undefined) add("availability_ratio", ">=", metrics.availability_ratio, thresholds.min_availability_ratio, metrics.availability_ratio >= thresholds.min_availability_ratio);
	if (thresholds.max_p95_ms !== undefined) add("latency_ms.p95", "<=", metrics.latency_ms.p95, thresholds.max_p95_ms, metrics.latency_ms.p95 !== null && metrics.latency_ms.p95 <= thresholds.max_p95_ms);
	if (thresholds.max_p99_ms !== undefined) add("latency_ms.p99", "<=", metrics.latency_ms.p99, thresholds.max_p99_ms, metrics.latency_ms.p99 !== null && metrics.latency_ms.p99 <= thresholds.max_p99_ms);
	return checks;
}

function faultObservations(profile, events, truncated) {
	return (profile.fault_windows ?? []).map((window) => {
		if (truncated) return { name: window.name, target: window.target, scenario_names: window.scenario_names, status: "insufficient_samples", fault_observed: false, estimated_rto_ms: null };
		const startMs = window.start_seconds * 1000;
		const endMs = window.end_seconds * 1000;
		const scopedEvents = events.filter((event) => window.scenario_names.includes(event.scenario));
		const windowEvents = scopedEvents.filter((event) => event.completed_at_ms >= startMs && event.completed_at_ms <= endMs);
		const firstFailure = windowEvents.find((event) => !event.expected);
		if (window.scenario_names.some((name) => !windowEvents.some((event) => event.scenario === name))) {
			return { name: window.name, target: window.target, scenario_names: window.scenario_names, status: "insufficient_samples", fault_observed: Boolean(firstFailure), estimated_rto_ms: null };
		}
		if (!firstFailure) return { name: window.name, target: window.target, scenario_names: window.scenario_names, status: "fault_not_observed", fault_observed: false, estimated_rto_ms: null };
		const confirmation = window.recovery_confirmation_successes ?? 5;
		const failedScenarios = [...new Set(windowEvents.filter((event) => !event.expected).map((event) => event.scenario))];
		const recoveryTimes = failedScenarios.map((name) => {
			const scenarioEvents = scopedEvents.filter((event) => event.scenario === name && event.completed_at_ms >= firstFailure.completed_at_ms);
			const lastFailureAt = scenarioEvents.findLastIndex((event) => !event.expected);
			let run = 0;
			for (const event of scenarioEvents.slice(lastFailureAt + 1)) {
				if (++run >= confirmation) return event.completed_at_ms;
			}
			return null;
		});
		const recoveredAt = recoveryTimes.includes(null) ? null : Math.max(...recoveryTimes);
		return {
			name: window.name,
			target: window.target,
			scenario_names: window.scenario_names,
			status: recoveredAt === null ? "not_recovered" : "recovered",
			fault_observed: true,
			first_failure_at_ms: firstFailure.completed_at_ms,
			recovered_at_ms: recoveredAt,
			estimated_rto_ms: recoveredAt === null ? null : recoveredAt - startMs,
			recovery_confirmation_successes: confirmation,
		};
	});
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
	usage();
	process.exit(0);
}
if (!args.profile || !args.output) {
	usage();
	fail("--profile and --output are required");
}
const profilePath = resolve(args.profile);
const outputPath = resolve(args.output);
if (existsSync(outputPath) && !args.overwrite) fail(`Output already exists: ${outputPath}`);
const profileBytes = readFileSync(profilePath);
const profile = validateProfile(JSON.parse(profileBytes.toString("utf8")));
const baseUrlValue = process.env[profile.base_url_env];
if (!baseUrlValue) fail(`Required base URL environment variable is missing: ${profile.base_url_env}`);
let baseUrl;
try { baseUrl = new URL(baseUrlValue); } catch { fail(`${profile.base_url_env} is not a valid URL`); }
if (!["http:", "https:"].includes(baseUrl.protocol) || baseUrl.username || baseUrl.password || baseUrl.pathname !== "/" || baseUrl.search || baseUrl.hash) fail("Base URL must be an HTTP(S) origin without credentials, query, fragment or path");
const allowedHosts = new Set([...LOOPBACK_HOSTS, ...args.allowedHosts.map((host) => String(host).toLowerCase())]);
if (!allowedHosts.has(baseUrl.hostname)) fail(`Target host ${baseUrl.hostname} is not authorized; pass --allow-host ${baseUrl.hostname} after approval`);
for (const scenario of profile.scenarios) {
	let target;
	try { target = new URL(scenario.path, baseUrl); } catch { fail(`Scenario ${scenario.name} path is not a valid URL path`); }
	if (target.origin !== baseUrl.origin || target.username || target.password || target.hash) fail(`Scenario ${scenario.name} path escapes the authorized origin or contains a fragment`);
	resolveRequest(scenario, 0);
}

if (args.dryRun) {
	console.log(JSON.stringify({ valid: true, workload_id: profile.workload_id, workload_class: profile.workload_class, target_origin: baseUrl.origin, duration_seconds: profile.duration_seconds, rate_per_second: profile.rate_per_second, scenarios: profile.scenarios.map(({ name, cohort, method, path, weight }) => ({ name, cohort, method, path, weight })), claims: { production_sla_proven: false, ha_proven: false } }, null, 2));
	process.exit(0);
}

const startedAt = new Date();
const clockStart = performance.now();
const maxSamples = profile.max_latency_samples ?? 250000;
const overall = new Aggregate(maxSamples);
const scenarios = new Map(profile.scenarios.map((scenario) => [scenario.name, new Aggregate(maxSamples)]));
const cohorts = new Map([...new Set(profile.scenarios.map((scenario) => scenario.cohort))].map((cohort) => [cohort, new Aggregate(maxSamples)]));
const scheduleLag = new SampleSeries(maxSamples);
const eventLimit = profile.max_fault_event_samples ?? 250000;
const events = [];
let eventsTruncated = false;
const weighted = profile.scenarios.flatMap((scenario) => Array.from({ length: scenario.weight }, () => scenario));
const inFlight = new Set();
let sequence = 0;
let peakInFlight = 0;
let scheduleFinishedAtMs = 0;

function aggregateFor(scenario) { return [overall, scenarios.get(scenario.name), cohorts.get(scenario.cohort)]; }

async function dispatch(scenario, number) {
	const requestStart = performance.now();
	for (const aggregate of aggregateFor(scenario)) aggregate.start();
	let status = null;
	let expected = false;
	let failureClass = null;
	try {
		const request = resolveRequest(scenario, number);
		const response = await fetch(new URL(scenario.path, baseUrl), { method: scenario.method, headers: request.headers, body: request.body, signal: AbortSignal.timeout(profile.request_timeout_ms ?? 10000), redirect: "manual" });
		status = response.status;
		await consumeResponse(response, profile.max_response_bytes ?? 1048576);
		expected = scenario.expected_statuses.includes(status);
		if (!expected) failureClass = "unexpected_status";
	} catch (error) {
		failureClass = classifyError(error);
		expected = false;
	}
	const durationMs = performance.now() - requestStart;
	for (const aggregate of aggregateFor(scenario)) aggregate.complete(durationMs, expected, status, failureClass);
	if (profile.fault_windows?.length) {
		if (events.length < eventLimit) events.push({ completed_at_ms: performance.now() - clockStart, expected, scenario: scenario.name });
		else eventsTruncated = true;
	}
}

const intervalMs = 1000 / profile.rate_per_second;
let nextAt = 0;
while (nextAt < profile.duration_seconds * 1000) {
	const waitMs = nextAt - (performance.now() - clockStart);
	if (waitMs > 0) await new Promise((done) => setTimeout(done, waitMs));
	scheduleLag.observe(Math.max(0, performance.now() - clockStart - nextAt));
	const scenario = weighted[sequence % weighted.length];
	sequence += 1;
	for (const aggregate of aggregateFor(scenario)) aggregate.schedule();
	if (inFlight.size >= profile.max_in_flight) {
		for (const aggregate of aggregateFor(scenario)) aggregate.drop();
	} else {
		const promise = dispatch(scenario, sequence).finally(() => inFlight.delete(promise));
		inFlight.add(promise);
		peakInFlight = Math.max(peakInFlight, inFlight.size);
	}
	nextAt += intervalMs;
}
// setTimeout rounds a fractional delay and can fire up to a millisecond early,
// so wait until the declared window has really elapsed instead of trusting one sleep.
for (let remainingWindowMs = profile.duration_seconds * 1000 - (performance.now() - clockStart); remainingWindowMs > 0; remainingWindowMs = profile.duration_seconds * 1000 - (performance.now() - clockStart)) {
	await new Promise((done) => setTimeout(done, Math.ceil(remainingWindowMs)));
}
scheduleFinishedAtMs = performance.now() - clockStart;
await Promise.allSettled([...inFlight]);
const drainFinishedAtMs = performance.now() - clockStart;

const overallMetrics = overall.snapshot();
const scenarioMetrics = Object.fromEntries([...scenarios].map(([name, aggregate]) => [name, aggregate.snapshot()]));
const cohortMetrics = Object.fromEntries([...cohorts].map(([name, aggregate]) => [name, aggregate.snapshot()]));
const lagMetrics = scheduleLag.snapshot();
const failureCounts = (aggregate) => Object.fromEntries([...aggregate.failureClasses].sort(([a], [b]) => a.localeCompare(b)));
const diagnostics = {
	generator: {
		schedule_lag_ms: lagMetrics,
		peak_in_flight: peakInFlight,
		schedule_finished_at_ms: scheduleFinishedAtMs,
		drain_finished_at_ms: drainFinishedAtMs,
		completed_rate_per_second: drainFinishedAtMs > 0 ? overallMetrics.completed / (drainFinishedAtMs / 1000) : 0,
	},
	failure_classes: {
		overall: failureCounts(overall),
		scenarios: Object.fromEntries([...scenarios].map(([name, aggregate]) => [name, failureCounts(aggregate)])),
		cohorts: Object.fromEntries([...cohorts].map(([name, aggregate]) => [name, failureCounts(aggregate)])),
	},
};
const faultResults = faultObservations(profile, events.sort((a, b) => a.completed_at_ms - b.completed_at_ms), eventsTruncated);
const thresholdChecks = [
	...evaluateThresholds("overall", overallMetrics, profile.thresholds),
	...profile.scenarios.flatMap((scenario) => evaluateThresholds(`scenario:${scenario.name}`, scenarioMetrics[scenario.name], scenario.thresholds)),
];
// A delayed generator can burst late requests and falsely pass service thresholds.
// These generous fixed guards reject an invalid load run without changing profile v1.
const p95LagLimitMs = Math.max(100, 2 * intervalMs);
const maxLagLimitMs = Math.max(1000, 10 * intervalMs);
thresholdChecks.push({ label: "generator", metric: "schedule_lag_ms.p95", operator: "<=", actual: lagMetrics.p95, expected: p95LagLimitMs, passed: lagMetrics.p95 !== null && lagMetrics.p95 <= p95LagLimitMs });
thresholdChecks.push({ label: "generator", metric: "schedule_lag_ms.max", operator: "<=", actual: lagMetrics.max, expected: maxLagLimitMs, passed: lagMetrics.max !== null && lagMetrics.max <= maxLagLimitMs });
for (const window of profile.fault_windows ?? []) {
	const result = faultResults.find((item) => item.name === window.name);
	const observationComplete = result.status === "recovered" || result.status === "fault_not_observed";
	thresholdChecks.push({ label: `fault:${window.name}`, metric: "observation_complete", operator: "=", actual: observationComplete, expected: true, passed: observationComplete });
	if (window.require_fault_observed) thresholdChecks.push({ label: `fault:${window.name}`, metric: "fault_observed", operator: "=", actual: result.fault_observed, expected: true, passed: result.fault_observed });
	if (window.max_rto_ms !== undefined) thresholdChecks.push({ label: `fault:${window.name}`, metric: "estimated_rto_ms", operator: "<=", actual: result.estimated_rto_ms, expected: window.max_rto_ms, passed: result.estimated_rto_ms !== null && result.estimated_rto_ms <= window.max_rto_ms });
}
const thresholdsPassed = thresholdChecks.every((check) => check.passed);
const result = {
	schema_version: 1,
	kind: RESULT_KIND,
	passed: thresholdsPassed,
	started_at: startedAt.toISOString(),
	completed_at: new Date().toISOString(),
	workload: {
		id: profile.workload_id,
		class: profile.workload_class,
		profile_sha256: createHash("sha256").update(profileBytes).digest("hex"),
		duration_seconds: profile.duration_seconds,
		rate_per_second: profile.rate_per_second,
		max_in_flight: profile.max_in_flight,
		target_origin: baseUrl.origin,
		environment_label: profile.environment_label ?? "unspecified",
		candidate_id: profile.candidate_id ?? null,
	},
	metrics: { overall: overallMetrics, scenarios: scenarioMetrics, cohorts: cohortMetrics },
	diagnostics,
	fault_observations: faultResults,
	threshold_checks: thresholdChecks,
	limitations: [
		"A passing run applies only to this target, candidate, workload and observation window.",
		"Fault observations require an independently controlled infrastructure fault during the declared window.",
		"This artifact does not establish a monthly availability SLI or contractual SLA.",
	],
	claims: { production_accepted: false, production_sla_proven: false, ha_proven: false },
};
mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`, { flag: args.overwrite ? "w" : "wx" });
console.log(`${result.passed ? "PASS" : "FAIL"}: ${overallMetrics.completed} completed, ${overallMetrics.dropped_requests} dropped. Evidence: ${outputPath}`);
if (!result.passed) process.exitCode = 2;
