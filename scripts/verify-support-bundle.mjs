#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
	copyFileSync,
	existsSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const EXPECTED_FILES = new Set([
	"SHA256SUMS",
	"consent-manifest.json",
	"diagnostic-summary.json",
	"inventory.json",
]);
const INVENTORIED_FILES = new Set([
	"consent-manifest.json",
	"diagnostic-summary.json",
	"inventory.json",
]);
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const SHA256 = /^[a-f0-9]{64}$/;
const checks = [];
const generator = resolve(fileURLToPath(new URL("support-bundle.mjs", import.meta.url)));

function exactKeys(value, expected, label) {
	assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
	assert.deepEqual(new Set(Object.keys(value)), new Set(expected), `${label} has undeclared fields`);
}

function parseJson(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

function validateBundle(path) {
	const root = resolve(path);
	assert.ok(existsSync(root), "support bundle does not exist");
	const rootEntry = lstatSync(root);
	assert.ok(rootEntry.isDirectory() && !rootEntry.isSymbolicLink(), "bundle root must be a real directory");
	const names = readdirSync(root).sort();
	assert.deepEqual(new Set(names), EXPECTED_FILES, "bundle has missing or extra files");
	for (const name of names) {
		assert.match(name, SAFE_NAME);
		const entry = lstatSync(join(root, name));
		assert.ok(entry.isFile() && !entry.isSymbolicLink(), `${name} must be a regular file`);
	}

	const checksumRows = readFileSync(join(root, "SHA256SUMS"), "utf8")
		.trim()
		.split(/\r?\n/)
		.map((line) => {
			const match = line.match(/^([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$/);
			assert.ok(match, "invalid checksum row");
			return { sha256: match[1], path: match[2] };
		});
	assert.deepEqual(new Set(checksumRows.map((row) => row.path)), INVENTORIED_FILES);
	assert.equal(new Set(checksumRows.map((row) => row.path)).size, checksumRows.length);
	assert.deepEqual(
		checksumRows.map((row) => row.path),
		[...checksumRows.map((row) => row.path)].sort(),
		"checksum inventory must be sorted",
	);
	for (const row of checksumRows) {
		assert.equal(
			createHash("sha256").update(readFileSync(join(root, row.path))).digest("hex"),
			row.sha256,
			`${row.path} checksum mismatch`,
		);
	}

	const inventory = parseJson(join(root, "inventory.json"));
	exactKeys(inventory, ["schema_version", "files"], "inventory");
	assert.equal(inventory.schema_version, 1);
	assert.ok(Array.isArray(inventory.files));
	assert.deepEqual(new Set(inventory.files.map((row) => row.path)), new Set(["consent-manifest.json", "diagnostic-summary.json"]));
	assert.deepEqual(
		inventory.files.map((row) => row.path),
		[...inventory.files.map((row) => row.path)].sort(),
		"JSON inventory must be sorted",
	);
	for (const row of inventory.files) {
		exactKeys(row, ["path", "bytes", "sha256"], "inventory row");
		assert.match(row.path, SAFE_NAME);
		assert.ok(Number.isSafeInteger(row.bytes) && row.bytes >= 0);
		assert.match(row.sha256, SHA256);
		const content = readFileSync(join(root, row.path));
		assert.equal(content.length, row.bytes);
		assert.equal(createHash("sha256").update(content).digest("hex"), row.sha256);
	}

	const consent = parseJson(join(root, "consent-manifest.json"));
	exactKeys(
		consent,
		[
			"schema_version",
			"customer_consent",
			"consent_reference",
			"consent_recorded_at",
			"collected_at",
			"purpose",
			"included_sources",
			"excluded_data_classes",
			"operator_attestations",
			"transfer_requirements",
		],
		"consent manifest",
	);
	assert.equal(consent.schema_version, 1);
	assert.equal(consent.customer_consent, true);
	assert.match(consent.consent_reference, /^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$/);
	assert.equal(consent.purpose, "vendor-support-diagnostics");
	assert.equal(new Date(consent.consent_recorded_at).toISOString(), consent.consent_recorded_at);
	assert.equal(new Date(consent.collected_at).toISOString(), consent.collected_at);
	assert.ok(consent.consent_recorded_at <= consent.collected_at);
	assert.ok(Array.isArray(consent.included_sources) && consent.included_sources.length === 2);
	assert.ok(Array.isArray(consent.excluded_data_classes) && consent.excluded_data_classes.length > 0);
	assert.ok(Array.isArray(consent.operator_attestations) && consent.operator_attestations.length > 0);
	assert.ok(Array.isArray(consent.transfer_requirements) && consent.transfer_requirements.length > 0);

	const diagnostic = parseJson(join(root, "diagnostic-summary.json"));
	exactKeys(diagnostic, ["schema_version", "collector_version", "deployment", "doctor", "boundary"], "diagnostic summary");
	assert.equal(diagnostic.schema_version, 1);
	assert.equal(diagnostic.collector_version, 1);
	assert.equal(typeof diagnostic.boundary, "string");
	exactKeys(
		diagnostic.deployment,
		[
			"schema_version",
			"mode",
			"development",
			"source_revision",
			"source_has_changes",
			"upstream_revision",
			"migration_inventory",
			"artifact_inventory",
		],
		"deployment summary",
	);
	assert.ok(["self-hosted", "cloud"].includes(diagnostic.deployment.mode));
	assert.equal(diagnostic.deployment.schema_version, 1);
	assert.equal(typeof diagnostic.deployment.development, "boolean");
	assert.match(diagnostic.deployment.source_revision, /^[a-f0-9]{7,64}$/);
	assert.equal(typeof diagnostic.deployment.source_has_changes, "boolean");
	if (diagnostic.deployment.mode === "self-hosted") {
		assert.match(diagnostic.deployment.upstream_revision, /^[a-f0-9]{7,64}$/);
	} else {
		assert.equal(diagnostic.deployment.upstream_revision, null);
	}
	for (const value of [diagnostic.deployment.migration_inventory, diagnostic.deployment.artifact_inventory]) {
		exactKeys(value, ["count", "sha256"], "structural inventory");
		assert.ok(Number.isSafeInteger(value.count) && value.count >= 0);
		assert.match(value.sha256, SHA256);
	}
	if (diagnostic.doctor.present) {
		exactKeys(
			diagnostic.doctor,
			["present", "checked_at", "passed", "mode", "online", "check_codes", "failure_codes"],
			"doctor summary",
		);
		assert.equal(typeof diagnostic.doctor.passed, "boolean");
		assert.equal(typeof diagnostic.doctor.online, "boolean");
		assert.equal(diagnostic.doctor.mode, diagnostic.deployment.mode);
		assert.equal(new Date(diagnostic.doctor.checked_at).toISOString(), diagnostic.doctor.checked_at);
		for (const rows of [diagnostic.doctor.check_codes, diagnostic.doctor.failure_codes]) {
			assert.ok(Array.isArray(rows));
			for (const row of rows) {
				exactKeys(row, ["code", "count"], "doctor code");
				assert.match(row.code, /^[a-z][a-z0-9-]+$/);
				assert.ok(Number.isSafeInteger(row.count) && row.count > 0);
			}
		}
	} else {
		exactKeys(diagnostic.doctor, ["present"], "doctor summary");
	}

	const raw = names.map((name) => readFileSync(join(root, name), "utf8")).join("\n");
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
		assert.doesNotMatch(raw, pattern, `bundle contains ${label}`);
	}
	return { files: names.length, bytes: names.reduce((total, name) => total + lstatSync(join(root, name)).size, 0) };
}

function runGenerator(args, success = true) {
	const result = spawnSync(process.execPath, [generator, ...args], {
		encoding: "utf8",
		timeout: 30_000,
	});
	assert.equal(result.status === 0, success, result.stderr || result.stdout);
	return result;
}

function createFixture(path) {
	mkdirSync(path, { recursive: true });
	writeFileSync(
		join(path, "deployment.json"),
		JSON.stringify({
			schema_version: 1,
			project_name: "customer-secret-project",
			mode: "self-hosted",
			development: false,
			prepared_at: "2026-09-12T09:00:00.000Z",
			source_commit: "a".repeat(40),
			source_has_changes: false,
			upstream_sha: "b".repeat(40),
			dashboard_url: "https://private.customer.example",
			supabase_url: "https://alice@example.com/private",
			migrations: [{ name: "20260912000000_safe.sql", sha256: "c".repeat(64) }],
			artifacts: [
				{ path: "dashboard/index.html", sha256: "d".repeat(64), bearer_token: "fixture-bearer-secret" },
			],
			note: "C:\\Users\\Alice\\private token=fixture-token-secret",
		}),
	);
	writeFileSync(
		join(path, "doctor-evidence.json"),
		JSON.stringify({
			checked_at: "2026-09-12T10:00:00.000Z",
			passed: false,
			mode: "self-hosted",
			online: true,
			checks: ["Node 24 or newer", "HTTPS origin or isolated development: https://private.customer.example"],
			failures: ["alice@example.com C:\\Users\\Alice password=fixture-password-secret"],
			scope: "Bearer fixture-bearer-secret",
		}),
	);
	writeFileSync(
		join(path, ".env"),
		"SERVICE_ROLE_KEY=fixture-service-role-secret\nPASSWORD=fixture-password-secret\n",
	);
}

function copyFlatDirectory(source, destination) {
	mkdirSync(destination, { recursive: true });
	for (const name of readdirSync(source)) {
		const entry = lstatSync(join(source, name));
		assert.ok(entry.isFile() && !entry.isSymbolicLink(), "test fixture must contain regular files");
		copyFileSync(join(source, name), join(destination, name));
	}
}

function selfTest() {
	const root = mkdtempSync(resolve(".release-evidence/support-bundle-"));
	const fixture = join(root, "deployment");
	createFixture(fixture);
	const fixed = [
		"--deployment",
		fixture,
		"--customer-consent",
		"--consent-reference",
		"CASE-123456",
		"--consent-recorded-at",
		"2026-09-12T10:01:00.000Z",
		"--collected-at",
		"2026-09-12T10:02:00.000Z",
	];
	const first = join(root, "bundle-a");
	runGenerator([...fixed, "--output", first]);
	const validation = validateBundle(first);
	checks.push(`${validation.files} allowlisted bundle files validate with exact fields and checksums`);
	const raw = readdirSync(first).map((name) => readFileSync(join(first, name), "utf8")).join("\n");
	for (const canary of [
		"fixture-service-role-secret",
		"fixture-password-secret",
		"fixture-bearer-secret",
		"private.customer.example",
		"alice@example.com",
		"C:\\Users\\Alice",
	]) assert.ok(!raw.includes(canary), `private canary leaked: ${canary}`);
	checks.push("environment, free-form secret, identity, hostname and absolute-path canaries are absent");

	const second = join(root, "bundle-b");
	runGenerator([...fixed, "--output", second]);
	for (const name of [...EXPECTED_FILES]) {
		assert.ok(readFileSync(join(first, name)).equals(readFileSync(join(second, name))), `${name} is not deterministic`);
	}
	checks.push("fixed inputs and timestamps produce deterministic files and sorted SHA-256 inventory");

	runGenerator(["--deployment", fixture, "--output", join(root, "no-consent"), "--consent-reference", "CASE-123456"], false);
	checks.push("collection fails closed without explicit customer consent");
	runGenerator([
		"--deployment",
		fixture,
		"--output",
		join(root, "pii-consent"),
		"--customer-consent",
		"--consent-reference",
		"alice@example.com",
	], false);
	checks.push("consent references reject email addresses and require opaque ticket identifiers");
	const lateConsent = [...fixed];
	lateConsent[lateConsent.indexOf("--consent-recorded-at") + 1] = "2026-09-12T10:03:00.000Z";
	runGenerator([...lateConsent, "--output", join(root, "late-consent")], false);
	checks.push("collection rejects consent timestamps recorded after collection");
	runGenerator([...fixed, "--output", join(fixture, "nested-output")], false);
	checks.push("output paths inside the diagnostic source are rejected");
	runGenerator([...fixed, "--output", first], false);
	checks.push("existing output directories cannot be overwritten");
	runGenerator([...fixed, "--output", join(root, "too-small"), "--max-bytes", "512"], false);
	checks.push("configured output byte limit fails closed before creating an oversized bundle");

	const traversal = join(root, "traversal");
	createFixture(traversal);
	const traversalManifest = parseJson(join(traversal, "deployment.json"));
	traversalManifest.artifacts[0].path = "../private.env";
	writeFileSync(join(traversal, "deployment.json"), JSON.stringify(traversalManifest));
	runGenerator([...fixed.slice(0, 1), traversal, ...fixed.slice(2), "--output", join(root, "traversal-output")], false);
	checks.push("path traversal in allowlisted manifest inventories is rejected");

	const linkedRoot = join(root, "linked-deployment");
	let linked = false;
	try {
		symlinkSync(fixture, linkedRoot, process.platform === "win32" ? "junction" : "dir");
		linked = true;
	} catch {
		// The source-file symlink case below still proves the same boundary where junctions are unavailable.
	}
	if (linked) {
		runGenerator([...fixed.slice(0, 1), linkedRoot, ...fixed.slice(2), "--output", join(root, "linked-output")], false);
	} else {
		const linkedFileRoot = join(root, "linked-file-deployment");
		mkdirSync(linkedFileRoot);
		symlinkSync(join(fixture, "deployment.json"), join(linkedFileRoot, "deployment.json"), "file");
		runGenerator([...fixed.slice(0, 1), linkedFileRoot, ...fixed.slice(2), "--output", join(root, "linked-output")], false);
	}
	checks.push("symbolic-link diagnostic sources are rejected");

	const extra = join(root, "extra-file-bundle");
	copyFlatDirectory(first, extra);
	writeFileSync(join(extra, "debug.log"), "fixture-service-role-secret");
	assert.throws(() => validateBundle(extra));
	checks.push("verification rejects undeclared files");
	const tampered = join(root, "tampered-bundle");
	copyFlatDirectory(first, tampered);
	writeFileSync(join(tampered, "diagnostic-summary.json"), "{}\n");
	assert.throws(() => validateBundle(tampered));
	checks.push("verification rejects changed bundle content");

	const evidence = {
		passed: true,
		checked_at: new Date().toISOString(),
		checks,
		scope:
			"Local support-bundle boundary verification. Customer consent validity and external transfer authorization remain operational responsibilities.",
	};
	writeFileSync(join(root, "verification.json"), `${JSON.stringify(evidence, null, 2)}\n`);
	console.log(JSON.stringify({ passed: true, checks: checks.length, evidence_path: join(root, "verification.json") }));
}

if (process.argv[2] === "--self-test") {
	selfTest();
} else {
	const result = validateBundle(process.argv[2] ?? ".aidr-support-bundle");
	console.log(JSON.stringify({ passed: true, ...result }));
}
