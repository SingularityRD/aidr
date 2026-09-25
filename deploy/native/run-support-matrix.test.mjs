import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
	CONNECTOR_HOST_IDS,
	EVIDENCE_ALLOWED_FIELDS,
	EVIDENCE_REQUIRED_FIELDS,
	EVIDENCE_SHA256_PATTERN,
	HOST_BINARY_ENV_PATTERN,
	MATRIX_ALLOWED_FIELDS,
	MATRIX_DECISION,
	MATRIX_KIND,
	MATRIX_REQUIRED_FIELDS,
	MATRIX_REVIEWED_AT_PATTERN,
	MATRIX_SCHEMA_VERSION,
	NON_EMPTY_STRING_PATTERN,
	RESIDUAL_ALLOWED_FIELDS,
	RESIDUAL_REQUIRED_FIELDS,
	ROW_ALLOWED_FIELDS,
	ROW_ARRAY_FIELDS,
	ROW_OPTIONAL_FIELDS,
	ROW_REQUIRED_FIELDS,
	ROW_STRING_ARRAY_FIELDS,
	SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE,
	SCENARIOS_OPEN,
	SUPPORTED_ARCHITECTURES,
	SUPPORTED_CONTEXTS,
	SUPPORTED_PLATFORMS,
	buildRecord,
	verifierReportShowsLocalCompletion,
	validateMatrix,
} from "./run-support-matrix.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const RUNNER = join(HERE, "run-support-matrix.mjs");
const GATE = resolve(HERE, "..", "..", "scripts", "verify-native-host-matrix-v6.mjs");
const SUPPORT_MATRIX_PATH = join(HERE, "support-matrix.json");
const SCHEMA_PATH = join(HERE, "support-matrix.schema.json");
const TEMPLATE_PATH = join(HERE, "scenarios", "TEMPLATE.json");
/** The row override the fixtures point at a binary that exists on every machine. */
const PRESENT_HOST_ENV = "AIDR_NATIVE_TEST_PRESENT_HOST";
const ISOLATED_HOST_ENV_KEYS = ["PATH", "LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)", "AIDR_CURSOR_PATH", "AIDR_VSCODE_PATH", "OPENCODE_E2E_BIN", PRESENT_HOST_ENV];

function isolatedHostEnv(dir, extra = {}) {
	return {
		...process.env,
		PATH: dirname(process.execPath),
		LOCALAPPDATA: dir,
		ProgramFiles: dir,
		"ProgramFiles(x86)": dir,
		AIDR_CURSOR_PATH: "",
		AIDR_VSCODE_PATH: "",
		OPENCODE_E2E_BIN: "",
		...extra,
	};
}

async function withTempDir(fn) {
	const dir = mkdtempSync(join(tmpdir(), "aidr-support-matrix-test-"));
	try {
		return await fn(dir);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

const committedMatrix = () => JSON.parse(readFileSync(SUPPORT_MATRIX_PATH, "utf8"));
const sorted = (values) => [...values].sort();

test("Claude support claim matches the disabled-hook and crashed-hook host boundaries", () => {
	const claude = committedMatrix().rows.find((row) => row.connector === "claude-code");
	const interception = JSON.parse(readFileSync(join(HERE, "interception-matrix.json"), "utf8"));
	const outcome = (condition) =>
		interception.failureConditions.find((row) => row.connector === "claude-code" && row.condition === condition)?.outcome;
	assert.equal(outcome("disabled-hook"), "fail-open");
	assert.match(claude?.tamperResistance ?? "", /disabled hook is fail-open/u);
	// Observed by the real-host tier (docs/evidence/real-host/claude-code.json).
	assert.equal(outcome("crashed-hook"), "fail-open");
	assert.match(claude?.tamperResistance ?? "", /killed before it writes a verdict is fail-open/u);
});

/**
 * A minimal structurally valid support matrix: one codex row, no acceptance
 * evidence, no residual entries. Fixture only — it is never written into the
 * repository, and it records no host observation.
 */
function fixtureMatrix({ binary = null, envOverride = null } = {}) {
	return {
		schemaVersion: 1,
		kind: MATRIX_KIND,
		reviewedAt: "2026-09-13",
		decision: MATRIX_DECISION,
		decisionMeaning: "fixture: advertised scope only, no row carries acceptance",
		soldConnectorScope: ["codex"],
		soldPlatformScope: [...SUPPORTED_PLATFORMS],
		soldArchitectureScope: [...SUPPORTED_ARCHITECTURES],
		soldDeploymentProfiles: ["customer-self-hosted-control-plane"],
		interceptionPointVocabulary: ["pre-tool-call", "none"],
		rows: [
			{
				connector: "codex",
				hostBinary: binary,
				hostBinaryEnvOverride: envOverride,
				interceptionPoint: "pre-tool-call",
				outputInterceptionPoint: "none",
				tamperResistance: "fixture: no host was exercised",
				supportedPlatforms: [...SUPPORTED_PLATFORMS],
				supportedArchitectures: [...SUPPORTED_ARCHITECTURES],
				supportedContexts: ["user"],
				installPath: ["fixture"],
				uninstallPath: ["fixture"],
				supportOwnerRole: "Endpoint Engineering",
				knownBypasses: [],
				unobservedActions: ["fixture: no host run produced this matrix"],
				acceptanceEvidence: [],
			},
		],
		residual: [],
	};
}

/** A well-formed codex manifest that declares no acceptance record. */
function fixtureScenarioManifest() {
	return {
		schema_version: 1,
		hosts: {
			codex: {
				binary: process.execPath,
				version_args: ["--version"],
				cases: [
					{
						id: "denied_side_effect",
						argv: ["{host_binary}", "-e", "console.log('HOST_ATTEMPT')"],
						attempt: { source: "stdout", contains: "HOST_ATTEMPT" },
						hook: { source: "file", path: "{receipt}", contains: "AIDR_HOOK_INVOKED" },
					},
				],
			},
		},
	};
}

function writeFixture(dir, { matrix = fixtureMatrix(), scenario = null } = {}) {
	const matrixPath = join(dir, "support-matrix.json");
	writeFileSync(matrixPath, JSON.stringify(matrix, null, 2));
	let scenarioPath = null;
	if (scenario !== null) {
		scenarioPath = join(dir, "codex.json");
		writeFileSync(scenarioPath, typeof scenario === "string" ? scenario : JSON.stringify(scenario, null, 2));
	}
	return { matrixPath, scenarioPath };
}

/**
 * Build a record with the row override pointing at a binary that exists and a
 * PATH that only holds the Node runtime, so no host installed on the machine
 * under test can change the outcome.
 */
async function presentHostRecord(dir, options) {
	const previous = new Map(ISOLATED_HOST_ENV_KEYS.map((key) => [key, process.env[key]]));
	const isolated = isolatedHostEnv(dir, { [PRESENT_HOST_ENV]: process.execPath });
	for (const key of ISOLATED_HOST_ENV_KEYS) process.env[key] = isolated[key];
	try {
		return await buildRecord({ outputDir: join(dir, "evidence"), ...options });
	} finally {
		for (const [key, value] of previous) {
			if (value === undefined) delete process.env[key];
			else process.env[key] = value;
		}
	}
}

test("the support-matrix schema exists and agrees with the validator constants", () => {
	assert.ok(existsSync(SCHEMA_PATH), "deploy/native/support-matrix.schema.json must exist");
	const manifest = committedMatrix();
	assert.equal(manifest.$schema, "./support-matrix.schema.json");
	assert.ok(
		existsSync(resolve(dirname(SUPPORT_MATRIX_PATH), manifest.$schema)),
		"the $schema the manifest declares must resolve next to it",
	);
	const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));
	assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
	assert.equal(schema.type, "object");
	assert.equal(schema.additionalProperties, false);

	assert.deepEqual(sorted(schema.required), sorted(MATRIX_REQUIRED_FIELDS));
	assert.deepEqual(sorted(Object.keys(schema.properties)), sorted(MATRIX_ALLOWED_FIELDS));
	for (const field of MATRIX_REQUIRED_FIELDS) {
		assert.ok(Object.hasOwn(schema.properties, field), `schema.properties must describe ${field}`);
	}
	for (const field of ROW_OPTIONAL_FIELDS) {
		assert.ok(Object.hasOwn(schema.$defs.row.properties, field), `schema row properties must describe optional ${field}`);
	}
	// additionalProperties:false means the committed manifest must be describable
	// by its own published contract, key by key.
	for (const key of Object.keys(manifest)) {
		assert.ok(Object.hasOwn(schema.properties, key), `schema.properties is missing committed root field ${key}`);
	}
	assert.equal(schema.properties.schemaVersion.const, MATRIX_SCHEMA_VERSION);
	assert.equal(schema.properties.kind.const, MATRIX_KIND);
	assert.equal(schema.properties.decision.const, MATRIX_DECISION);
	assert.equal(schema.properties.reviewedAt.pattern, MATRIX_REVIEWED_AT_PATTERN);
	assert.equal(schema.properties.decisionMeaning.pattern, NON_EMPTY_STRING_PATTERN);
	assert.deepEqual(schema.properties.soldPlatformScope.items.enum, SUPPORTED_PLATFORMS);
	assert.deepEqual(schema.properties.soldArchitectureScope.items.enum, SUPPORTED_ARCHITECTURES);
	assert.equal(schema.$defs.sha256.pattern, EVIDENCE_SHA256_PATTERN);

	const row = schema.$defs.row;
	assert.equal(row.additionalProperties, false);
	assert.deepEqual(sorted(Object.keys(row.properties)), sorted(ROW_ALLOWED_FIELDS));
	assert.equal(schema.properties.rows.items.$ref, "#/$defs/row");
	assert.deepEqual(sorted(row.required), sorted(ROW_REQUIRED_FIELDS));
	for (const field of ROW_REQUIRED_FIELDS) {
		assert.ok(Object.hasOwn(row.properties, field), `schema.$defs.row.properties must describe ${field}`);
	}
	for (const key of Object.keys(manifest.rows[0])) {
		assert.ok(Object.hasOwn(row.properties, key), `schema.$defs.row.properties is missing committed row field ${key}`);
	}
	for (const field of ROW_ARRAY_FIELDS) {
		assert.equal(row.properties[field].type, "array", `schema.$defs.row.properties.${field} must be an array`);
	}
	for (const field of ROW_STRING_ARRAY_FIELDS) {
		assert.equal(row.properties[field].items.pattern, NON_EMPTY_STRING_PATTERN, `schema.$defs.row.properties.${field} must reject whitespace-only items`);
	}
	assert.deepEqual(row.properties.supportedPlatforms.items.enum, SUPPORTED_PLATFORMS);
	assert.deepEqual(row.properties.supportedArchitectures.items.enum, SUPPORTED_ARCHITECTURES);
	assert.deepEqual(row.properties.supportedContexts.items.enum, SUPPORTED_CONTEXTS);
	assert.equal(row.properties.hostBinaryEnvOverride.oneOf[0].pattern, HOST_BINARY_ENV_PATTERN);
	assert.equal(row.properties.versionArgs.minItems, 1);
	assert.equal(row.properties.versionArgs.items.pattern, NON_EMPTY_STRING_PATTERN);
	assert.equal(row.properties.acceptanceEvidence.items.$ref, "#/$defs/evidence");
	assert.deepEqual(schema.$defs.evidence.required, EVIDENCE_REQUIRED_FIELDS);
	assert.equal(schema.$defs.evidence.additionalProperties, false);
	assert.deepEqual(sorted(Object.keys(schema.$defs.evidence.properties)), sorted(EVIDENCE_ALLOWED_FIELDS));
	assert.equal(schema.$defs.evidence.properties.path.pattern, NON_EMPTY_STRING_PATTERN);
	assert.equal(schema.$defs.evidence.properties.sha256.$ref, "#/$defs/sha256");

	const residual = schema.$defs.residual;
	assert.equal(residual.additionalProperties, false);
	assert.deepEqual(sorted(Object.keys(residual.properties)), sorted(RESIDUAL_ALLOWED_FIELDS));
	assert.deepEqual(sorted(residual.required), sorted(RESIDUAL_REQUIRED_FIELDS));
	for (const key of Object.keys(manifest.residual[0])) {
		assert.ok(Object.hasOwn(residual.properties, key), `schema.$defs.residual.properties is missing committed residual field ${key}`);
	}

	// The exported constants are the validator's, not decoration: dropping any
	// field they declare required must be a hard validation error.
	for (const field of MATRIX_REQUIRED_FIELDS) {
		const broken = committedMatrix();
		delete broken[field];
		assert.throws(
			() => validateMatrix(broken),
			new RegExp(`support matrix: ${field} is required`, "u"),
			`removing root field ${field} must fail validation`,
		);
	}
	for (const field of ROW_REQUIRED_FIELDS) {
		const broken = committedMatrix();
		delete broken.rows[0][field];
		assert.throws(
			() => validateMatrix(broken),
			new RegExp(`support matrix: row .+ is missing ${field}$`, "u"),
			`removing row field ${field} must fail validation`,
		);
	}
	for (const field of RESIDUAL_REQUIRED_FIELDS) {
		const broken = committedMatrix();
		delete broken.residual[0][field];
		assert.throws(
			() => validateMatrix(broken),
			new RegExp(`support matrix: residual .+ is missing ${field}$`, "u"),
			`removing residual field ${field} must fail validation`,
		);
	}

	// Every sold connector needs a host id so an explicit scenario manifest can
	// be matched to its row.
	for (const connector of manifest.soldConnectorScope) {
		assert.ok(Object.hasOwn(CONNECTOR_HOST_IDS, connector), `no scenario host id is declared for ${connector}`);
	}
	assert.equal(validateMatrix(committedMatrix()).rows.length, 6);
});

test("the validator rejects schema-disallowed and malformed matrix fields", () => {
	const unknownRoot = fixtureMatrix();
	unknownRoot.extra = true;
	assert.throws(() => validateMatrix(unknownRoot), /support matrix: root has unknown field extra/u);

	const unknownRow = fixtureMatrix();
	unknownRow.rows[0].extra = true;
	assert.throws(() => validateMatrix(unknownRow), /support matrix: row codex has unknown field extra/u);

	const unknownConnector = fixtureMatrix();
	unknownConnector.soldConnectorScope = ["future-host"];
	unknownConnector.rows[0].connector = "future-host";
	assert.throws(() => validateMatrix(unknownConnector), /support matrix: row future-host has no scenario host id/u);

	const unknownEvidence = committedMatrix();
	unknownEvidence.rows[0].acceptanceEvidence = [{ extra: true }];
	assert.throws(() => validateMatrix(unknownEvidence), /support matrix: row claude-code\.acceptanceEvidence\[0\] has unknown field extra/u);

	const unknownResidual = fixtureMatrix();
	unknownResidual.residual = [{
		id: "fixture",
		description: "fixture",
		ownerRole: "QA",
		requiredInput: "fixture",
		acceptanceCommand: "fixture",
		acceptanceEvidence: [],
		extra: true,
	}];
	assert.throws(() => validateMatrix(unknownResidual), /support matrix: residual fixture has unknown field extra/u);

	const badSchemaPointer = fixtureMatrix();
	badSchemaPointer.$schema = 42;
	assert.throws(() => validateMatrix(badSchemaPointer), /support matrix: \$schema must be a string/u);

	const withVersionArgs = fixtureMatrix();
	withVersionArgs.rows[0].versionArgs = ["--version"];
	assert.equal(validateMatrix(withVersionArgs).rows[0].versionArgs[0], "--version");
	const badVersionArgs = fixtureMatrix();
	badVersionArgs.rows[0].versionArgs = [""];
	assert.throws(() => validateMatrix(badVersionArgs), /versionArgs entries must be non-empty strings/u);

	for (const field of ["installPath", "uninstallPath", "knownBypasses", "unobservedActions"]) {
		const broken = fixtureMatrix();
		broken.rows[0][field] = [""];
		assert.throws(() => validateMatrix(broken), new RegExp(`row codex\\.${field} entries must be non-empty strings`, "u"));
	}

	const badResidualEvidence = fixtureMatrix();
	badResidualEvidence.residual = [{
		id: "fixture",
		description: "fixture",
		ownerRole: "QA",
		requiredInput: "fixture",
		acceptanceCommand: "fixture",
		acceptanceEvidence: [{}],
	}];
	assert.throws(() => validateMatrix(badResidualEvidence), /residual fixture\.acceptanceEvidence\[0\] is missing path/u);
});

test("a manifest that copies the template's placeholders is refused", async () => {
	await withTempDir(async (dir) => {
		const templateCopy = readFileSync(TEMPLATE_PATH, "utf8");
		const { matrixPath, scenarioPath } = writeFixture(dir, {
			matrix: fixtureMatrix({ envOverride: PRESENT_HOST_ENV }),
			scenario: templateCopy,
		});
		const record = await presentHostRecord(dir, { matrixPath, scenarioFile: scenarioPath });
		const host = record.hosts.find((entry) => entry.connector === "codex");
		assert.equal(host.status, "HOST_ACCEPTANCE_OPEN");
		assert.equal(host.scenarios.status, SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE);
		assert.equal(host.scenarios.validation.template, true);
		assert.ok(host.scenarios.validation.placeholder_count > 0);
		assert.ok(host.scenarios.validation.unreplaced_placeholder_count > 0);
		assert.equal(host.scenarios.outputPath, undefined, "a refused manifest is never launched");
		assert.equal(record.decision, "NO-GO");
		assert.ok(record.blockers.includes("codex:NATIVE_SCENARIOS_OPEN"), record.blockers.join("; "));
		assert.ok(
			record.blockers.includes(`codex:${SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE}`),
			record.blockers.join("; "),
		);

		// Deleting the template markers is the bypass the README documents: it
		// changes the severity of every placeholder, not their presence, so the
		// same refusal code must still be produced.
		const stripped = JSON.parse(templateCopy);
		delete stripped.template;
		delete stripped.kind;
		writeFileSync(scenarioPath, JSON.stringify(stripped, null, 2));
		const second = await presentHostRecord(dir, { matrixPath, scenarioFile: scenarioPath });
		const secondHost = second.hosts.find((entry) => entry.connector === "codex");
		assert.equal(secondHost.scenarios.status, SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE);
		assert.equal(secondHost.scenarios.validation.template, false);
		assert.equal(secondHost.scenarios.validation.placeholder_count, 0);
		assert.ok(secondHost.scenarios.validation.unreplaced_placeholder_count > 0);
		assert.equal(secondHost.scenarios.exitCode, undefined);
		assert.ok(second.blockers.includes(`codex:${SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE}`));
		assert.equal(second.decision, "NO-GO");
	});
});

test("a well-formed manifest without an acceptance record stays HOST_ACCEPTANCE_OPEN", async () => {
	await withTempDir(async (dir) => {
		const { matrixPath, scenarioPath } = writeFixture(dir, {
			matrix: fixtureMatrix({ envOverride: PRESENT_HOST_ENV }),
			scenario: fixtureScenarioManifest(),
		});
		const record = await presentHostRecord(dir, { matrixPath, scenarioFile: scenarioPath });
		const host = record.hosts.find((entry) => entry.connector === "codex");
		assert.equal(host.acceptance, "open");
		assert.equal(host.status, "HOST_ACCEPTANCE_OPEN");
		assert.notEqual(host.status, "SCENARIOS_PASSED_REVIEW_OPEN");
		assert.notEqual(host.scenarios.status, SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE);
		assert.equal(host.scenarios.status, SCENARIOS_OPEN, host.scenarios.stderr);
		assert.ok(record.blockers.includes("codex:MISSING_NAMED_ACCEPTANCE_EVIDENCE"), record.blockers.join("; "));
		assert.ok(record.blockers.includes("codex:NATIVE_SCENARIOS_OPEN"), record.blockers.join("; "));
		assert.equal(record.decision, "NO-GO");
	});
});

test("synthetic and missing-host reports cannot masquerade as completed host scenarios", () => {
	const syntheticFixture = {
		kind: "aidr_native_host_matrix_v6",
		gate: "NO_GO",
		scenario_manifest_present: true,
		scenario_manifest_sha256: "a".repeat(64),
		manifest_validation: { ok: true, template: false, error_count: 0, placeholder_count: 0 },
		hosts: [{ id: "codex", status: "LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN" }],
	};
	assert.equal(
		verifierReportShowsLocalCompletion(syntheticFixture, "codex", "a".repeat(64)),
		false,
		"a short fixture report cannot masquerade as completed host scenarios",
	);
	assert.equal(
		verifierReportShowsLocalCompletion(
			{ ...syntheticFixture, hosts: [{ id: "codex", status: "HOST_UNAVAILABLE" }] },
			"codex",
			"a".repeat(64),
		),
		false,
		"a missing host cannot be counted as completed",
	);
});

test("an absent host binary is still HOST_UNAVAILABLE", async () => {
	await withTempDir(async (dir) => {
		const { matrixPath } = writeFixture(dir, { matrix: fixtureMatrix({ binary: "aidr-native-host-absent-0000" }) });
		const record = await buildRecord({ matrixPath, probeOnly: true });
		const host = record.hosts.find((entry) => entry.connector === "codex");
		assert.equal(host.binary, null);
		assert.equal(host.scenarios, null);
		assert.equal(host.status, "HOST_UNAVAILABLE");
		assert.equal(host.reason, "host binary is not installed on this machine");
		assert.ok(record.blockers.includes("codex:HOST_UNAVAILABLE"), record.blockers.join("; "));
		assert.equal(record.decision, "NO-GO");
	});
});

test("a missing default scenario is a machine-readable row blocker", async () => {
	await withTempDir(async (dir) => {
		const { matrixPath } = writeFixture(dir, { matrix: fixtureMatrix({ envOverride: PRESENT_HOST_ENV }) });
		const record = await presentHostRecord(dir, { matrixPath });
		const host = record.hosts.find((entry) => entry.connector === "codex");
		assert.equal(record.matrixPath, resolve(matrixPath));
		assert.equal(host.status, "HOST_ACCEPTANCE_OPEN");
		assert.equal(host.scenarios.status, "SCENARIO_MANIFEST_MISSING");
		assert.ok(record.blockers.includes("codex:SCENARIO_MANIFEST_MISSING"), record.blockers.join("; "));
		assert.equal(record.decision, "NO-GO");
	});
});

test("a scenario cannot exercise a different binary from the probed host", async () => {
	await withTempDir(async (dir) => {
		const scenario = fixtureScenarioManifest();
		scenario.hosts.codex.binary = join(dir, "not-the-installed-host.exe");
		const { matrixPath, scenarioPath } = writeFixture(dir, {
			matrix: fixtureMatrix({ envOverride: PRESENT_HOST_ENV }),
			scenario,
		});
		const record = await presentHostRecord(dir, { matrixPath, scenarioFile: scenarioPath });
		const host = record.hosts.find((entry) => entry.connector === "codex");
		assert.equal(host.status, "HOST_ACCEPTANCE_OPEN");
		assert.equal(host.scenarios.status, "SCENARIO_HOST_BINARY_MISMATCH");
		assert.equal(host.scenarios.outputPath, undefined, "the mismatched host must never launch");
		assert.ok(record.blockers.includes("codex:SCENARIO_HOST_BINARY_MISMATCH"));
	});
});

test("an explicit unreadable scenario file produces a record and never launches a host", async () => {
	await withTempDir(async (dir) => {
		const scenarioPath = join(dir, "codex.json");
		writeFileSync(scenarioPath, "{not-json");
		const { matrixPath } = writeFixture(dir, { matrix: fixtureMatrix({ envOverride: PRESENT_HOST_ENV }) });
		const record = await presentHostRecord(dir, { matrixPath, scenarioFile: scenarioPath });
		const host = record.hosts.find((entry) => entry.connector === "codex");
		assert.equal(host.status, "HOST_ACCEPTANCE_OPEN");
		assert.equal(host.scenarios.status, "SCENARIO_MANIFEST_UNREADABLE");
		assert.equal(host.scenarios.scenarioPath, resolve(scenarioPath));
		assert.equal(host.scenarios.outputPath, undefined);
		assert.ok(record.blockers.includes(`SCENARIO_MANIFEST_UNREADABLE:${resolve(scenarioPath)}`), record.blockers.join("; "));
		assert.ok(record.blockers.includes("codex:SCENARIO_MANIFEST_UNREADABLE"), record.blockers.join("; "));
		assert.equal(record.scenarioFile.issue.status, "SCENARIO_MANIFEST_UNREADABLE");
		assert.equal(record.decision, "NO-GO");
	});
});

test("a missing explicit scenario file produces a machine-readable record", async () => {
	await withTempDir(async (dir) => {
		const scenarioPath = join(dir, "missing.json");
		const { matrixPath } = writeFixture(dir, { matrix: fixtureMatrix({ envOverride: PRESENT_HOST_ENV }) });
		const record = await presentHostRecord(dir, { matrixPath, scenarioFile: scenarioPath });
		const host = record.hosts.find((entry) => entry.connector === "codex");
		assert.equal(host.status, "HOST_ACCEPTANCE_OPEN");
		assert.equal(host.scenarios.status, "SCENARIO_MANIFEST_MISSING");
		assert.equal(host.scenarios.scenarioPath, resolve(scenarioPath));
		assert.ok(record.blockers.includes(`SCENARIO_MANIFEST_MISSING:${resolve(scenarioPath)}`), record.blockers.join("; "));
		assert.ok(record.blockers.includes("codex:SCENARIO_MANIFEST_MISSING"), record.blockers.join("; "));
		assert.equal(record.scenarioFile.issue.status, "SCENARIO_MANIFEST_MISSING");
		assert.equal(record.decision, "NO-GO");
	});
});

test("an explicit scenario file with no advertised host is a machine-readable blocker", async () => {
	await withTempDir(async (dir) => {
		const scenarioPath = join(dir, "empty.json");
		writeFileSync(scenarioPath, JSON.stringify({ schema_version: 1, hosts: {} }));
		const { matrixPath } = writeFixture(dir, { matrix: fixtureMatrix({ envOverride: PRESENT_HOST_ENV }) });
		const record = await presentHostRecord(dir, { matrixPath, scenarioFile: scenarioPath });
		const host = record.hosts.find((entry) => entry.connector === "codex");
		assert.equal(host.status, "HOST_ACCEPTANCE_OPEN");
		assert.equal(host.scenarios.status, "SCENARIO_MANIFEST_NO_MATCH");
		assert.ok(record.blockers.includes(`SCENARIO_MANIFEST_NO_MATCH:${resolve(scenarioPath)}`), record.blockers.join("; "));
		assert.ok(record.scenarioFile.issue.validation.failures.some((failure) => failure.code === "HOSTS_EMPTY"));
		assert.equal(record.decision, "NO-GO");
	});
});

test("the CLI refuses a template copy with the documented reason code", async () => {
	await withTempDir(async (dir) => {
		const { matrixPath, scenarioPath } = writeFixture(dir, {
			matrix: fixtureMatrix({ envOverride: PRESENT_HOST_ENV }),
			scenario: readFileSync(TEMPLATE_PATH, "utf8"),
		});
		const outputPath = join(dir, "nested", "record.json");
		const result = spawnSync(
			process.execPath,
			[RUNNER, "--matrix", matrixPath, "--scenario-file", scenarioPath, "--output", outputPath],
			{ encoding: "utf8", timeout: 120_000, env: isolatedHostEnv(dir, { [PRESENT_HOST_ENV]: process.execPath }) },
		);
		assert.equal(result.status, 1, result.stderr);
		assert.ok(existsSync(outputPath), "the runner must still write its record");
		const record = JSON.parse(readFileSync(outputPath, "utf8"));
		const host = record.hosts.find((entry) => entry.connector === "codex");
		assert.equal(host.status, "HOST_ACCEPTANCE_OPEN");
		assert.equal(host.scenarios.status, SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE);
		assert.ok(record.blockers.includes(`codex:${SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE}`));
		assert.equal(record.decision, "NO-GO");
	});
});

test("the support runner refuses to overwrite a matrix input", async () => {
	await withTempDir(async (dir) => {
		const { matrixPath } = writeFixture(dir);
		const before = readFileSync(matrixPath, "utf8");
		const result = spawnSync(process.execPath, [RUNNER, "--matrix", matrixPath, "--probe-only", "--output", matrixPath], {
			encoding: "utf8",
			timeout: 120_000,
		});
		assert.equal(result.status, 2);
		assert.match(result.stderr, /Refusing to overwrite native input manifest/u);
		assert.equal(readFileSync(matrixPath, "utf8"), before);
	});
});

test("the native-host gate refuses a placeholder manifest without template markers", async () => {
	await withTempDir(async (dir) => {
		const stripped = JSON.parse(readFileSync(TEMPLATE_PATH, "utf8"));
		delete stripped.template;
		delete stripped.kind;
		const scenarioPath = join(dir, "codex.json");
		const outputPath = join(dir, "gate.json");
		writeFileSync(scenarioPath, JSON.stringify(stripped, null, 2));
		const result = spawnSync(process.execPath, [GATE, "--scenario-file", scenarioPath, "--output", outputPath], {
			encoding: "utf8",
			timeout: 120_000,
			env: isolatedHostEnv(dir),
		});
		assert.equal(result.status, 1, result.stderr);
		const report = JSON.parse(readFileSync(outputPath, "utf8"));
		assert.equal(report.gate, "NO_GO");
		assert.equal(report.manifest_validation.template, false);
		assert.ok(
			report.manifest_validation.failures.some((failure) => failure.code === "PLACEHOLDER_VALUE_UNREPLACED"),
			JSON.stringify(report.manifest_validation.failures.slice(0, 5)),
		);
		assert.ok(report.blockers.includes(SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE), report.blockers.join("; "));
		// The structural finding is still reported next to the refusal.
		assert.ok(
			report.blockers.some((blocker) => blocker.startsWith("SCENARIO_MANIFEST_INVALID:PLACEHOLDER_VALUE_UNREPLACED")),
			report.blockers.join("; "),
		);
	});
});
