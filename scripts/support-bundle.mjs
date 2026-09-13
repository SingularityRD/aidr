#!/usr/bin/env node
import { createHash } from "node:crypto";
import {
	existsSync,
	lstatSync,
	mkdirSync,
	readFileSync,
	realpathSync,
	writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";

const COLLECTOR_VERSION = 1;
const DEFAULT_MAX_BYTES = 256 * 1024;
const MAX_INPUT_BYTES = 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/;
const REVISION = /^[a-f0-9]{7,64}$/;
const CONSENT_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$/;

const { values } = parseArgs({
	options: {
		deployment: { type: "string", default: ".aidr-deploy" },
		output: { type: "string", default: ".aidr-support-bundle" },
		"customer-consent": { type: "boolean", default: false },
		"consent-reference": { type: "string" },
		"consent-recorded-at": { type: "string" },
		"collected-at": { type: "string" },
		"max-bytes": { type: "string", default: String(DEFAULT_MAX_BYTES) },
	},
});

function fail(message) {
	throw new Error(message);
}

function normalizeTimestamp(value, label) {
	const parsed = new Date(value);
	if (!value || Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
		fail(`${label} must be an ISO-8601 UTC timestamp such as 2026-09-12T10:00:00.000Z`);
	}
	return parsed.toISOString();
}

function isWithin(parent, child) {
	const path = relative(parent, child);
	return path === "" || (!path.startsWith("..") && !isAbsolute(path));
}

function safeRelativePath(value) {
	return (
		typeof value === "string" &&
		value.length <= 240 &&
		/^[A-Za-z0-9_.@+-]+(?:\/[A-Za-z0-9_.@+-]+)*$/.test(value) &&
		value.split("/").every((segment) => segment !== "." && segment !== "..")
	);
}

function compareText(left, right) {
	return left < right ? -1 : left > right ? 1 : 0;
}

function readAllowedJson(root, name, required) {
	const path = join(root, name);
	if (!existsSync(path)) {
		if (required) fail(`Required diagnostic source is missing: ${name}`);
		return null;
	}
	const entry = lstatSync(path);
	if (entry.isSymbolicLink() || !entry.isFile()) fail(`Diagnostic source must be a regular file: ${name}`);
	const real = realpathSync(path);
	if (!isWithin(root, real)) fail(`Diagnostic source escapes the deployment directory: ${name}`);
	if (entry.size > MAX_INPUT_BYTES) fail(`Diagnostic source exceeds the 1 MiB input limit: ${name}`);
	try {
		return JSON.parse(readFileSync(real, "utf8"));
	} catch {
		fail(`Diagnostic source is not valid JSON: ${name}`);
	}
}

function object(value, label) {
	if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
	return value;
}

function boolean(value, label) {
	if (typeof value !== "boolean") fail(`${label} must be a boolean`);
	return value;
}

function revision(value, label, nullable = false) {
	if (nullable && value === null) return null;
	if (typeof value !== "string" || !REVISION.test(value)) fail(`${label} is not a valid source revision`);
	return value;
}

function mode(value, label) {
	if (!['self-hosted', 'cloud'].includes(value)) fail(`${label} must be self-hosted or cloud`);
	return value;
}

function digestInventory(rows, pathField, label) {
	if (!Array.isArray(rows) || rows.length > 100_000) fail(`${label} must be a bounded array`);
	const normalized = rows.map((item) => {
		object(item, `${label} entry`);
		const path = item[pathField];
		if (!safeRelativePath(path)) fail(`${label} contains an unsafe path`);
		if (typeof item.sha256 !== "string" || !SHA256.test(item.sha256)) {
			fail(`${label} contains an invalid SHA-256 digest`);
		}
		return { path, sha256: item.sha256 };
	});
	normalized.sort((a, b) => compareText(a.path, b.path));
	for (let index = 1; index < normalized.length; index += 1) {
		if (normalized[index - 1].path === normalized[index].path) fail(`${label} contains duplicate paths`);
	}
	return {
		count: normalized.length,
		sha256: createHash("sha256").update(JSON.stringify(normalized)).digest("hex"),
	};
}

function summarizeDeployment(value) {
	const source = object(value, "deployment.json");
	if (source.schema_version !== 1) fail("Unsupported deployment manifest version");
	const deploymentMode = mode(source.mode, "deployment.json mode");
	const migrations = digestInventory(source.migrations, "name", "deployment migrations");
	const artifacts = digestInventory(source.artifacts, "path", "deployment artifacts");
	return {
		schema_version: source.schema_version,
		mode: deploymentMode,
		development: boolean(source.development, "deployment.json development"),
		source_revision: revision(source.source_commit, "deployment.json source_commit"),
		source_has_changes: boolean(source.source_has_changes, "deployment.json source_has_changes"),
		upstream_revision: revision(
			source.upstream_sha,
			"deployment.json upstream_sha",
			deploymentMode === "cloud",
		),
		migration_inventory: migrations,
		artifact_inventory: artifacts,
	};
}

function diagnosticCode(label) {
	if (typeof label !== "string") return "unclassified-redacted";
	if (/^migration \d{14}_[a-z0-9_]+\.sql$/.test(label)) return "migration-integrity";
	if (/^HTTPS origin or isolated development:/.test(label)) return "transport-origin-policy";
	const exact = new Map([
		["Node 24 or newer", "runtime-version"],
		["selected project's public and private keys configured", "deployment-credentials-present"],
		["public signup disabled", "public-signup-disabled"],
		[
			"S3 protocol credential is private and differs from the upstream demonstration secret",
			"object-storage-credential-policy",
		],
		["Docker Compose configuration resolves", "compose-configuration"],
		["all required deployment services running and healthy", "service-health"],
		["dashboard health", "dashboard-health"],
		["authentication health", "authentication-health"],
		["authentication settings reachable", "authentication-settings"],
		["authentication service confirms signup is disabled", "authentication-signup-policy"],
	]);
	return exact.get(label) ?? "unclassified-redacted";
}

function summarizeCodes(values, label) {
	if (!Array.isArray(values) || values.length > 10_000) fail(`${label} must be a bounded array`);
	const counts = new Map();
	for (const value of values) {
		const code = diagnosticCode(value);
		counts.set(code, (counts.get(code) ?? 0) + 1);
	}
	return [...counts.entries()]
		.sort(([left], [right]) => compareText(left, right))
		.map(([code, count]) => ({ code, count }));
}

function summarizeDoctor(value, deploymentMode) {
	if (value === null) return { present: false };
	const source = object(value, "doctor-evidence.json");
	const doctorMode = mode(source.mode, "doctor-evidence.json mode");
	if (doctorMode !== deploymentMode) fail("Doctor evidence mode does not match deployment mode");
	const checkedAt = normalizeTimestamp(source.checked_at, "doctor-evidence.json checked_at");
	return {
		present: true,
		checked_at: checkedAt,
		passed: boolean(source.passed, "doctor-evidence.json passed"),
		mode: doctorMode,
		online: boolean(source.online, "doctor-evidence.json online"),
		check_codes: summarizeCodes(source.checks, "doctor-evidence.json checks"),
		failure_codes: summarizeCodes(source.failures, "doctor-evidence.json failures"),
	};
}

function json(value) {
	return `${JSON.stringify(value, null, 2)}\n`;
}

const deploymentInput = resolve(values.deployment);
if (!existsSync(deploymentInput)) fail("Deployment directory does not exist");
if (lstatSync(deploymentInput).isSymbolicLink() || !lstatSync(deploymentInput).isDirectory()) {
	fail("Deployment source must be a real directory, not a symbolic link");
}
const deploymentRoot = realpathSync(deploymentInput);
const output = resolve(values.output);
if (existsSync(output)) fail("Support bundle output already exists; choose a new directory");
if (isWithin(deploymentRoot, output)) fail("Support bundle output cannot be inside the deployment directory");
if (!values["customer-consent"]) fail("--customer-consent is required before collecting diagnostics");
if (!values["consent-reference"] || !CONSENT_REFERENCE.test(values["consent-reference"])) {
	fail("--consent-reference must be a 6-64 character opaque ticket ID without names or email addresses");
}
const maxBytes = Number(values["max-bytes"]);
if (!Number.isSafeInteger(maxBytes) || maxBytes < 512 || maxBytes > 5 * 1024 * 1024) {
	fail("--max-bytes must be an integer between 512 and 5242880");
}
const collectedAt = normalizeTimestamp(values["collected-at"] ?? new Date().toISOString(), "--collected-at");
const consentRecordedAt = normalizeTimestamp(
	values["consent-recorded-at"] ?? collectedAt,
	"--consent-recorded-at",
);
if (consentRecordedAt > collectedAt) fail("Consent must be recorded before diagnostic collection");

const deployment = summarizeDeployment(readAllowedJson(deploymentRoot, "deployment.json", true));
const doctor = summarizeDoctor(
	readAllowedJson(deploymentRoot, "doctor-evidence.json", false),
	deployment.mode,
);
const payloads = new Map([
	[
		"consent-manifest.json",
		json({
			schema_version: 1,
			customer_consent: true,
			consent_reference: values["consent-reference"],
			consent_recorded_at: consentRecordedAt,
			collected_at: collectedAt,
			purpose: "vendor-support-diagnostics",
			included_sources: ["deployment.json:selected-fields", "doctor-evidence.json:selected-fields"],
			excluded_data_classes: [
				"credentials-and-environment-files",
				"logs-and-free-form-event-content",
				"database-and-storage-content",
				"customer-identities-hostnames-and-absolute-paths",
			],
			operator_attestations: [
				"The operator attests that the customer approved collection for the stated support purpose.",
				"The operator attests that the consent reference is an opaque ticket identifier without personal data.",
			],
			transfer_requirements: [
				"Transfer remains forbidden until the generated inventory is reviewed through the approved support process.",
				"Transfer and deletion must use the customer-approved channel and ticket retention policy.",
			],
		}),
	],
	[
		"diagnostic-summary.json",
		json({
			schema_version: 1,
			collector_version: COLLECTOR_VERSION,
			deployment,
			doctor,
			boundary:
				"Allowlisted structural diagnostics only. No environment file, log, database row, storage object, URL, hostname, user identity or absolute path was collected.",
		}),
	],
]);

const inventoryRows = [...payloads.entries()]
	.map(([path, content]) => ({
		path,
		bytes: Buffer.byteLength(content),
		sha256: createHash("sha256").update(content).digest("hex"),
	}))
	.sort((left, right) => compareText(left.path, right.path));
payloads.set("inventory.json", json({ schema_version: 1, files: inventoryRows }));
const checksums = [...payloads.entries()]
	.map(([path, content]) => ({ path, sha256: createHash("sha256").update(content).digest("hex") }))
	.sort((left, right) => compareText(left.path, right.path))
	.map((entry) => `${entry.sha256}  ${entry.path}`)
	.join("\n") + "\n";
payloads.set("SHA256SUMS", checksums);
const totalBytes = [...payloads.values()].reduce((total, content) => total + Buffer.byteLength(content), 0);
if (totalBytes > maxBytes) fail(`Generated support bundle exceeds --max-bytes (${totalBytes} > ${maxBytes})`);
const outputText = [...payloads.values()].join("\n");
for (const [label, pattern] of [
	["email address", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i],
	["URL", /https?:\/\//i],
	["Windows absolute path", /\b[A-Za-z]:[\\/]/],
	["home directory", /\/(?:Users|home)\//],
	["PEM key", /-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----/],
	["JWT", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/],
	[
		"credential assignment",
		/(?:authorization|password|private[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*["']?[^\s,"'}]{6,}/i,
	],
]) {
	if (pattern.test(outputText)) fail(`Generated support bundle contains a prohibited ${label}`);
}

mkdirSync(output, { recursive: false, mode: 0o700 });
for (const [name, content] of [...payloads.entries()].sort(([left], [right]) => compareText(left, right))) {
	writeFileSync(join(output, name), content, { encoding: "utf8", mode: 0o600, flag: "wx" });
}
console.log(
	`Support bundle created: ${payloads.size} files, ${totalBytes} bytes. Review inventory.json before customer-approved transfer.`,
);
