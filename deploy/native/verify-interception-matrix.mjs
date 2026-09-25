#!/usr/bin/env node
/**
 * MKT-03 interception-matrix gate.
 *
 * Reads `deploy/native/interception-matrix.json` and `deploy/native/support-matrix.json`
 * and checks three different things:
 *
 *   1. Structure: fixed point/status/tamper/condition vocabularies, exactly one
 *      row per sold connector and point, unique rows, and an explicit
 *      `evidence`/`limitations` pair on every row.
 *   2. Source truth: every row that claims a point is *available* must point at
 *      a file that really exists inside that connector's own source root and
 *      must contain the guard marker it claims. A row that claims a point the
 *      connector source does not implement fails the gate.
 *   3. Agreement with the sold support matrix: a point the support matrix
 *      advertises for a connector may not be `unsupported` here, output-side
 *      points may not be claimed where the support matrix declares `none`, and
 *      nothing may be `enforced` that is not part of the sold matrix.
 *
 * `enforced` additionally requires a named real-host acceptance record in the
 * row evidence, so a row can never round up to enforced on source code alone.
 * An acceptance record is a JSON file under `docs/evidence/real-host/` written by
 * `pnpm test:e2e:real-host` (scripts/real-host-e2e/run.mjs): the gate parses it
 * and requires that it names the row's connector, passed, and proves exactly the
 * point (or observed exactly the failure-condition outcome) the row cites it for.
 *
 * A structurally valid matrix that is still NO-GO (open points, unobserved
 * conditions) passes this gate: validity and readiness are reported separately.
 *
 * Usage:
 *   node deploy/native/verify-interception-matrix.mjs [--matrix <path>]
 *     [--support-matrix <path>] [--json] [--require-enforced]
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const DEFAULT_MATRIX_PATH = join(HERE, "interception-matrix.json");
const DEFAULT_SUPPORT_MATRIX_PATH = join(HERE, "support-matrix.json");

export const INTERCEPTION_POINTS = [
	"pre-prompt",
	"pre-tool",
	"post-tool-output",
	"pre-delivery-response",
	"model-stream",
	"network",
];
export const ROW_STATUSES = ["enforced", "declared-not-proven", "tamper-evident-only", "unsupported"];
export const TAMPER_POSTURES = [
	"tamper-evident-only",
	"fail-closed-on-tamper",
	"no-artifact-integrity-check",
];
export const FAILURE_CONDITIONS = [
	"disabled-hook",
	"crashed-hook",
	"offline",
	"large-binary-response",
];
export const CONDITION_OUTCOMES = [
	"fail-closed",
	"explicitly-unsupported",
	"fail-open",
	"unobserved",
];
export const OUTPUT_SIDE_POINTS = ["post-tool-output", "pre-delivery-response", "model-stream"];

/** The guard a row must be able to point at for each interception point. */
export const POINT_EVIDENCE_KIND = {
	"pre-prompt": "prompt-boundary",
	"pre-tool": "hook-registration",
	"post-tool-output": "output-inspection",
	"pre-delivery-response": "output-inspection",
	"model-stream": "stream-interception",
	network: "network-boundary",
};

export const ALLOWED_EVIDENCE_KINDS = [
	...new Set([
		...Object.values(POINT_EVIDENCE_KIND),
		"failure-policy",
		"tamper-evidence",
		"host-capability-record",
		"test",
		"acceptance-record",
	]),
];

/**
 * A connector row may only cite its own source. A point claimed for one
 * connector cannot be "proven" by another connector's module.
 */
export const CONNECTOR_SOURCE_ROOTS = {
	"claude-code": ["packages/claude-code/", "hooks/"],
	cursor: ["packages/extension/"],
	vscode: ["packages/extension/"],
	openclaw: ["packages/openclaw/"],
	opencode: ["packages/opencode/"],
	codex: ["packages/codex/"],
};

/**
 * The bridge between the sold support matrix's interception vocabulary and this
 * matrix's five points. Both files must agree on it; the gate re-derives it
 * from the support matrix so a drifted copy cannot silence the comparison.
 */
export const SUPPORT_MATRIX_MAPPING = {
	interceptionPoint: {
		"pre-tool-call": ["pre-tool"],
		"pre-prompt": ["pre-prompt"],
		"network-egress": ["network"],
		none: [],
	},
	outputInterceptionPoint: {
		"post-tool-output": ["post-tool-output"],
		"pre-delivery-response": ["pre-delivery-response"],
		"tool-output-inspection": ["post-tool-output"],
		"post-tool-call": ["post-tool-output"],
		none: [],
	},
};

/**
 * Real-host acceptance records are not connector source, so they live in one
 * shared evidence directory instead of a connector's source root. A record is
 * only accepted from here.
 */
export const ACCEPTANCE_RECORD_ROOT = "docs/evidence/real-host/";
export const ACCEPTANCE_RECORD_KIND = "aidr-real-host-acceptance";

const STATUS_OUTCOMES_REQUIRING_EVIDENCE = new Set(["fail-closed", "explicitly-unsupported"]);
const TAMPER_POSTURES_REQUIRING_EVIDENCE = new Set(["tamper-evident-only", "fail-closed-on-tamper"]);

function digest(value) {
	return createHash("sha256").update(value).digest("hex");
}

function sameStringArray(value, expected) {
	return (
		Array.isArray(value) &&
		value.length === expected.length &&
		value.every((item, index) => item === expected[index])
	);
}

function deepEqual(left, right) {
	if (left === right) return true;
	if (Array.isArray(left) || Array.isArray(right)) {
		return (
			Array.isArray(left) &&
			Array.isArray(right) &&
			left.length === right.length &&
			left.every((item, index) => deepEqual(item, right[index]))
		);
	}
	if (left && right && typeof left === "object" && typeof right === "object") {
		const leftKeys = Object.keys(left).sort();
		const rightKeys = Object.keys(right).sort();
		return (
			leftKeys.length === rightKeys.length &&
			leftKeys.every((key, index) => key === rightKeys[index]) &&
			leftKeys.every((key) => deepEqual(left[key], right[key]))
		);
	}
	return false;
}

function readJson(path) {
	try {
		const raw = readFileSync(path, "utf8");
		return { ok: true, raw, value: JSON.parse(raw) };
	} catch (error) {
		return { ok: false, error: error instanceof Error ? error.message : String(error) };
	}
}

function normalizedRelative(repoRoot, path) {
	return relative(repoRoot, resolve(repoRoot, path)).replaceAll("\\", "/");
}

function report(options = {}) {
	const failures = [];
	const add = (code, connector, point, detail) => {
		failures.push({ code, connector, point, detail });
	};
	return {
		failures,
		add,
		...options,
	};
}

/**
 * Validate one evidence entry. Returns the number of usable entries so callers
 * can require "at least one entry of the expected kind".
 */
function checkEvidence(entry, context) {
	const { state, connector, point, repoRoot, label } = context;
	const acceptance = entry?.kind === "acceptance-record";
	const roots = acceptance ? [ACCEPTANCE_RECORD_ROOT] : context.roots;
	if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
		state.add("EVIDENCE_NOT_OBJECT", connector, point, label);
		return;
	}
	if (typeof entry.kind !== "string" || !ALLOWED_EVIDENCE_KINDS.includes(entry.kind)) {
		state.add("EVIDENCE_UNKNOWN_KIND", connector, point, `${label}:${String(entry.kind)}`);
		return;
	}
	if (typeof entry.path !== "string" || entry.path.trim().length === 0) {
		state.add("EVIDENCE_MISSING_PATH", connector, point, label);
		return;
	}
	const resolved = resolve(repoRoot, entry.path);
	if (!existsSync(resolved)) {
		state.add("EVIDENCE_PATH_MISSING", connector, point, entry.path);
		return;
	}
	if (Array.isArray(roots) && roots.length > 0) {
		const relativePath = normalizedRelative(repoRoot, entry.path);
		if (!roots.some((root) => relativePath.startsWith(root))) {
			state.add("EVIDENCE_OUTSIDE_CONNECTOR_ROOT", connector, point, `${entry.path} not under ${roots.join("|")}`);
			return;
		}
	}
	if (!Array.isArray(entry.contains) || entry.contains.length === 0) {
		state.add("EVIDENCE_MISSING_MARKERS", connector, point, entry.path);
		return;
	}
	let content;
	try {
		content = readFileSync(resolved, "utf8");
	} catch (error) {
		state.add("EVIDENCE_READ_FAILED", connector, point, `${entry.path}: ${error instanceof Error ? error.message : String(error)}`);
		return;
	}
	for (const marker of entry.contains) {
		if (typeof marker !== "string" || marker.length === 0) {
			state.add("EVIDENCE_INVALID_MARKER", connector, point, entry.path);
			continue;
		}
		if (!content.includes(marker)) {
			state.add("EVIDENCE_MARKER_MISSING", connector, point, `${entry.path} lacks ${JSON.stringify(marker)}`);
		}
	}
	if (acceptance) checkAcceptanceRecord(content, { ...context, path: entry.path });
}

/**
 * An acceptance record must be evidence for the claim that cites it: the same
 * connector, an overall pass, and either the cited point proven (`passed`) or the
 * cited failure condition observed with the outcome the row declares.
 */
function checkAcceptanceRecord(content, { state, connector, point, path, claim }) {
	let record;
	try {
		record = JSON.parse(content);
	} catch (error) {
		state.add("ACCEPTANCE_RECORD_INVALID", connector, point, `${path}: ${error instanceof Error ? error.message : String(error)}`);
		return;
	}
	if (record?.kind !== ACCEPTANCE_RECORD_KIND || record?.schemaVersion !== 1) {
		state.add("ACCEPTANCE_RECORD_INVALID", connector, point, `${path} is not an ${ACCEPTANCE_RECORD_KIND} v1 record`);
		return;
	}
	if (record.connector !== connector) {
		state.add("ACCEPTANCE_RECORD_CONNECTOR_MISMATCH", connector, point, `${path} records ${String(record.connector)}`);
		return;
	}
	if (record.passed !== true) {
		state.add("ACCEPTANCE_RECORD_NOT_PASSED", connector, point, path);
		return;
	}
	if (claim?.type === "point" && record.proves?.points?.[claim.point] !== "passed") {
		state.add("ACCEPTANCE_RECORD_DOES_NOT_PROVE", connector, point, `${path} does not prove ${claim.point}`);
	}
	if (claim?.type === "condition" && record.proves?.conditions?.[claim.condition] !== claim.outcome) {
		state.add(
			"ACCEPTANCE_RECORD_DOES_NOT_PROVE",
			connector,
			point,
			`${path} observed ${claim.condition}=${String(record.proves?.conditions?.[claim.condition])}, row declares ${claim.outcome}`,
		);
	}
}

export function verifyInterceptionMatrix(options = {}) {
	const repoRoot = resolve(options.repoRoot ?? REPO_ROOT);
	const matrixPath = options.matrixPath ? resolve(options.matrixPath) : DEFAULT_MATRIX_PATH;
	const supportMatrixPath = options.supportMatrixPath
		? resolve(options.supportMatrixPath)
		: DEFAULT_SUPPORT_MATRIX_PATH;
	const state = report({ matrixPath, supportMatrixPath, repoRoot });

	const matrixFile = readJson(matrixPath);
	if (!matrixFile.ok) {
		state.add("MATRIX_UNREADABLE", null, null, `${matrixPath}: ${matrixFile.error}`);
		return finish(state, null, null, null);
	}
	const supportFile = readJson(supportMatrixPath);
	if (!supportFile.ok) {
		state.add("SUPPORT_MATRIX_UNREADABLE", null, null, `${supportMatrixPath}: ${supportFile.error}`);
		return finish(state, matrixFile, null, null);
	}
	const matrix = matrixFile.value;
	const support = supportFile.value;

	if (matrix?.schemaVersion !== 1) state.add("MATRIX_SCHEMA_VERSION", null, null, String(matrix?.schemaVersion));
	if (matrix?.kind !== "aidr-interception-matrix") state.add("MATRIX_KIND", null, null, String(matrix?.kind));
	for (const [field, expected] of [
		["pointVocabulary", INTERCEPTION_POINTS],
		["statusVocabulary", ROW_STATUSES],
		["tamperPostureVocabulary", TAMPER_POSTURES],
		["conditionVocabulary", FAILURE_CONDITIONS],
		["conditionOutcomeVocabulary", CONDITION_OUTCOMES],
		["outputSidePoints", OUTPUT_SIDE_POINTS],
	]) {
		if (!sameStringArray(matrix?.[field], expected)) state.add("VOCABULARY_MISMATCH", null, null, field);
	}
	if (!deepEqual(matrix?.supportMatrixMapping, SUPPORT_MATRIX_MAPPING)) {
		state.add("SUPPORT_MATRIX_MAPPING_MISMATCH", null, null, "supportMatrixMapping");
	}

	const soldConnectors = Array.isArray(support?.soldConnectorScope) ? support.soldConnectorScope : [];
	if (soldConnectors.length === 0) {
		state.add("SUPPORT_MATRIX_SCOPE_MISSING", null, null, "soldConnectorScope");
		return finish(state, matrixFile, supportFile, null);
	}
	const soldSet = new Set(soldConnectors);

	if (!Array.isArray(matrix?.rows)) {
		state.add("ROWS_NOT_ARRAY", null, null, null);
		return finish(state, matrixFile, supportFile, null);
	}

	const byConnectorPoint = new Map();
	for (const [index, row] of matrix.rows.entries()) {
		const label = `rows[${index}]`;
		if (!row || typeof row !== "object" || Array.isArray(row)) {
			state.add("ROW_NOT_OBJECT", null, null, label);
			continue;
		}
		const connector = row.connector;
		const point = row.point;
		if (typeof connector !== "string" || connector.length === 0) {
			state.add("MISSING_CONNECTOR", null, null, label);
			continue;
		}
		if (!soldSet.has(connector)) {
			state.add("UNKNOWN_CONNECTOR", connector, null, label);
			continue;
		}
		if (typeof point !== "string" || !INTERCEPTION_POINTS.includes(point)) {
			state.add("UNKNOWN_POINT", connector, typeof point === "string" ? point : null, label);
			continue;
		}
		const key = `${connector}/${point}`;
		if (byConnectorPoint.has(key)) {
			state.add("DUPLICATE_ROW", connector, point, label);
			continue;
		}
		byConnectorPoint.set(key, row);

		if (typeof row.status !== "string" || !ROW_STATUSES.includes(row.status)) {
			state.add("UNKNOWN_STATUS", connector, point, String(row.status));
			continue;
		}
		if (!Array.isArray(row.limitations) || !row.limitations.every((item) => typeof item === "string" && item.trim())) {
			state.add("INVALID_LIMITATIONS", connector, point, label);
		} else if (row.limitations.length === 0 && row.status !== "unsupported") {
			state.add("MISSING_LIMITATIONS", connector, point, label);
		}
		if (!Array.isArray(row.evidence)) {
			state.add("EVIDENCE_NOT_ARRAY", connector, point, label);
			continue;
		}

		const roots = CONNECTOR_SOURCE_ROOTS[connector] ?? [];
		const requiredKind = POINT_EVIDENCE_KIND[point];
		let matching = 0;
		for (const entry of row.evidence) {
			if (entry && typeof entry === "object" && entry.kind === requiredKind) matching += 1;
			checkEvidence(entry, {
				state,
				connector,
				point,
				repoRoot,
				roots,
				label: `${key} evidence`,
				claim: { type: "point", point },
			});
		}

		if (row.status === "unsupported") {
			if (typeof row.reason !== "string" || row.reason.trim().length < 10) {
				state.add("MISSING_UNSUPPORTED_REASON", connector, point, label);
			}
		} else {
			if (row.evidence.length === 0 || matching === 0) {
				state.add("MISSING_POINT_GUARD", connector, point, `${key} needs a ${requiredKind} entry`);
			}
			if (row.reason !== null && typeof row.reason !== "string") {
				state.add("INVALID_REASON", connector, point, label);
			}
			if (typeof row.hostBoundary !== "string" || row.hostBoundary.trim().length === 0) {
				state.add("MISSING_HOST_BOUNDARY", connector, point, label);
			}
			if (row.status === "enforced" && !row.evidence.some((entry) => entry?.kind === "acceptance-record")) {
				state.add("ENFORCED_WITHOUT_ACCEPTANCE_RECORD", connector, point, label);
			}
		}
	}

	for (const connector of soldConnectors) {
		for (const point of INTERCEPTION_POINTS) {
			if (!byConnectorPoint.has(`${connector}/${point}`)) {
				state.add("MISSING_POINT_ROW", connector, point, null);
			}
		}
	}

	checkTamperPosture(matrix, soldConnectors, soldSet, repoRoot, state);
	checkFailureConditions(matrix, soldConnectors, soldSet, repoRoot, state);
	checkSupportMatrixAgreement({
		matrix,
		support,
		soldConnectors,
		byConnectorPoint,
		state,
	});

	return finish(state, matrixFile, supportFile, byConnectorPoint);
}

function checkTamperPosture(matrix, soldConnectors, soldSet, repoRoot, state) {
	if (!Array.isArray(matrix?.tamperPosture)) {
		state.add("TAMPER_POSTURE_NOT_ARRAY", null, null, null);
		return;
	}
	const seen = new Set();
	for (const [index, row] of matrix.tamperPosture.entries()) {
		const label = `tamperPosture[${index}]`;
		if (!row || typeof row !== "object" || Array.isArray(row)) {
			state.add("TAMPER_POSTURE_NOT_OBJECT", null, null, label);
			continue;
		}
		const connector = row.connector;
		if (typeof connector !== "string" || !soldSet.has(connector)) {
			state.add("UNKNOWN_TAMPER_CONNECTOR", typeof connector === "string" ? connector : null, null, label);
			continue;
		}
		if (seen.has(connector)) {
			state.add("DUPLICATE_TAMPER_POSTURE", connector, null, label);
			continue;
		}
		seen.add(connector);
		if (typeof row.status !== "string" || !TAMPER_POSTURES.includes(row.status)) {
			state.add("UNKNOWN_TAMPER_STATUS", connector, null, String(row.status));
			continue;
		}
		if (typeof row.reason !== "string" || row.reason.trim().length < 10) {
			state.add("MISSING_TAMPER_REASON", connector, null, label);
		}
		if (!Array.isArray(row.limitations)) {
			state.add("INVALID_TAMPER_LIMITATIONS", connector, null, label);
		}
		if (!Array.isArray(row.evidence)) {
			state.add("TAMPER_EVIDENCE_NOT_ARRAY", connector, null, label);
			continue;
		}
		let matching = 0;
		for (const entry of row.evidence) {
			if (entry && typeof entry === "object" && entry.kind === "tamper-evidence") matching += 1;
			checkEvidence(entry, {
				state,
				connector,
				point: "tamper",
				repoRoot,
				roots: CONNECTOR_SOURCE_ROOTS[connector] ?? [],
				label: `${connector} tamper evidence`,
			});
		}
		if (TAMPER_POSTURES_REQUIRING_EVIDENCE.has(row.status) && (row.evidence.length === 0 || matching === 0)) {
			state.add("MISSING_TAMPER_EVIDENCE", connector, null, label);
		}
	}
	for (const connector of soldConnectors) {
		if (!seen.has(connector)) state.add("MISSING_TAMPER_POSTURE", connector, null, null);
	}
}

function checkFailureConditions(matrix, soldConnectors, soldSet, repoRoot, state) {
	if (!Array.isArray(matrix?.failureConditions)) {
		state.add("FAILURE_CONDITIONS_NOT_ARRAY", null, null, null);
		return;
	}
	const seen = new Set();
	for (const [index, row] of matrix.failureConditions.entries()) {
		const label = `failureConditions[${index}]`;
		if (!row || typeof row !== "object" || Array.isArray(row)) {
			state.add("FAILURE_CONDITION_NOT_OBJECT", null, null, label);
			continue;
		}
		const connector = row.connector;
		const condition = row.condition;
		if (typeof connector !== "string" || !soldSet.has(connector)) {
			state.add("UNKNOWN_FAILURE_CONNECTOR", typeof connector === "string" ? connector : null, null, label);
			continue;
		}
		if (typeof condition !== "string" || !FAILURE_CONDITIONS.includes(condition)) {
			state.add("UNKNOWN_FAILURE_CONDITION", connector, typeof condition === "string" ? condition : null, label);
			continue;
		}
		const key = `${connector}/${condition}`;
		if (seen.has(key)) {
			state.add("DUPLICATE_FAILURE_CONDITION", connector, condition, label);
			continue;
		}
		seen.add(key);
		if (typeof row.outcome !== "string" || !CONDITION_OUTCOMES.includes(row.outcome)) {
			state.add("UNKNOWN_FAILURE_OUTCOME", connector, condition, String(row.outcome));
			continue;
		}
		if (typeof row.reason !== "string" || row.reason.trim().length < 10) {
			state.add("MISSING_FAILURE_REASON", connector, condition, label);
		}
		if (!Array.isArray(row.limitations)) {
			state.add("INVALID_FAILURE_LIMITATIONS", connector, condition, label);
		}
		if (!Array.isArray(row.evidence)) {
			state.add("FAILURE_EVIDENCE_NOT_ARRAY", connector, condition, label);
			continue;
		}
		let matching = 0;
		for (const entry of row.evidence) {
			if (entry && typeof entry === "object" && entry.kind === "failure-policy") matching += 1;
			checkEvidence(entry, {
				state,
				connector,
				point: condition,
				repoRoot,
				roots: null,
				label: `${key} evidence`,
				claim: { type: "condition", condition, outcome: row.outcome },
			});
		}
		if (STATUS_OUTCOMES_REQUIRING_EVIDENCE.has(row.outcome) && (row.evidence.length === 0 || matching === 0)) {
			state.add("MISSING_FAILURE_EVIDENCE", connector, condition, label);
		}
	}
	for (const connector of soldConnectors) {
		for (const condition of FAILURE_CONDITIONS) {
			if (!seen.has(`${connector}/${condition}`)) {
				state.add("MISSING_FAILURE_CONDITION", connector, condition, null);
			}
		}
	}
}

function checkSupportMatrixAgreement({ matrix, support, soldConnectors, byConnectorPoint, state }) {
	const supportRows = Array.isArray(support?.rows) ? support.rows : [];
	const supportByConnector = new Map();
	for (const row of supportRows) {
		if (row && typeof row === "object" && typeof row.connector === "string") {
			supportByConnector.set(row.connector, row);
		}
	}
	for (const connector of soldConnectors) {
		if (!supportByConnector.has(connector)) {
			state.add("SUPPORT_MATRIX_ROW_MISSING", connector, null, null);
		}
	}
	for (const connector of supportByConnector.keys()) {
		if (!soldConnectors.includes(connector)) {
			state.add("SUPPORT_MATRIX_ROW_OUTSIDE_SCOPE", connector, null, null);
		}
	}

	for (const [connector, supportRow] of supportByConnector) {
		const declared = [];
		for (const [field, mapping] of Object.entries(SUPPORT_MATRIX_MAPPING)) {
			const value = supportRow[field];
			if (value === null || value === undefined) continue;
			if (!Object.hasOwn(mapping, value)) {
				state.add("UNMAPPED_SUPPORT_MATRIX_POINT", connector, null, `${field}=${String(value)}`);
				continue;
			}
			const mapped = mapping[value];
			if (mapped.length === 0 && field === "outputInterceptionPoint") {
				for (const point of OUTPUT_SIDE_POINTS) {
					const row = byConnectorPoint.get(`${connector}/${point}`);
					if (row && row.status !== "unsupported") {
						state.add("SUPPORT_MATRIX_OUTPUT_NONE", connector, point, `support matrix declares ${field}=${value}`);
					}
				}
			}
			for (const point of mapped) declared.push(point);
		}

		for (const point of declared) {
			const row = byConnectorPoint.get(`${connector}/${point}`);
			if (row && row.status === "unsupported") {
				state.add("SUPPORT_MATRIX_REQUIRES_POINT", connector, point, "sold as available but declared unsupported");
			}
		}
		for (const row of byConnectorPoint.values()) {
			if (row.connector !== connector) continue;
			if (row.status === "enforced" && !declared.includes(row.point)) {
				state.add("ENFORCED_OUTSIDE_SOLD_MATRIX", connector, row.point, null);
			}
			if (
				row.status === "enforced" &&
				(!Array.isArray(supportRow.acceptanceEvidence) || supportRow.acceptanceEvidence.length === 0)
			) {
				state.add("ENFORCED_WITHOUT_SUPPORT_MATRIX_ACCEPTANCE", connector, row.point, null);
			}
		}
		if (Array.isArray(supportRow.acceptanceEvidence) && supportRow.acceptanceEvidence.length === 0) {
			state.withheldAcceptance = (state.withheldAcceptance ?? 0) + 1;
		}
	}
}

function finish(state, matrixFile, supportFile, byConnectorPoint) {
	const rows = byConnectorPoint ? [...byConnectorPoint.values()] : [];
	const byStatus = {};
	for (const status of ROW_STATUSES) byStatus[status] = rows.filter((row) => row.status === status).length;
	const openPoints = rows
		.filter((row) => row.status !== "enforced")
		.map((row) => ({ connector: row.connector, point: row.point, status: row.status }));

	const failureReasons = state.failures.map((failure) => {
		const scope = failure.connector ? `:${failure.connector}${failure.point ? `/${failure.point}` : ""}` : "";
		return `${failure.code}${scope}${failure.detail ? ` (${failure.detail})` : ""}`;
	});

	return {
		schemaVersion: 1,
		kind: "aidr-interception-matrix-gate",
		ok: state.failures.length === 0,
		decision: state.failures.length === 0 && byStatus.enforced === rows.length && rows.length > 0 ? "GO" : "NO-GO",
		matrixPath: state.matrixPath,
		matrixSha256: matrixFile?.ok ? digest(matrixFile.raw) : null,
		supportMatrixPath: state.supportMatrixPath,
		supportMatrixSha256: supportFile?.ok ? digest(supportFile.raw) : null,
		counts: {
			rows: rows.length,
			connectors: new Set(rows.map((row) => row.connector)).size,
			byStatus,
		},
		connectorsWithoutNamedAcceptance: state.withheldAcceptance ?? 0,
		openPointCount: openPoints.length,
		openPoints,
		failures: state.failures,
		failureReasons,
		limitations: [
			"A structurally valid matrix is not host acceptance: every non-enforced row stays open until a named real-host record exists.",
			"Source markers prove that the guard is declared in the repository, not that a host loaded, trusted or honoured it.",
			"An `enforced` row rests on a real-host acceptance record for the recorded host version and platform only; the records in docs/evidence/real-host/ drive the real host binary with a scripted mock model.",
		],
	};
}

function formatCounts(counts) {
	return Object.entries(counts)
		.map(([key, value]) => `${key}=${value}`)
		.join(" ");
}

function printReport(report) {
	console.log("MKT-03 interception matrix gate");
	console.log(`matrix   ${report.matrixPath} sha256=${(report.matrixSha256 ?? "unavailable").slice(0, 16)}`);
	console.log(`support  ${report.supportMatrixPath} sha256=${(report.supportMatrixSha256 ?? "unavailable").slice(0, 16)}`);
	console.log(`validity ${report.ok ? "PASS" : "FAIL"}  readiness ${report.decision}`);
	console.log(
		`connectors ${report.counts.connectors}  rows ${report.counts.rows}  ${formatCounts(report.counts.byStatus)}`,
	);
	const byConnector = new Map();
	for (const item of report.openPoints) {
		if (!byConnector.has(item.connector)) byConnector.set(item.connector, []);
		byConnector.get(item.connector).push(`${item.point}=${item.status}`);
	}
	for (const [connector, points] of byConnector) {
		console.log(`  ${connector}: ${points.join(" ")}`);
	}
	console.log(`open points ${report.openPointCount} (use --require-enforced to fail closed on them)`);
	console.log(`connectors without a named real-host acceptance record ${report.connectorsWithoutNamedAcceptance}`);
	if (report.failures.length === 0) {
		console.log("failures 0");
		return;
	}
	console.log(`failures ${report.failures.length}`);
	for (const reason of report.failureReasons) console.log(`  ${reason}`);
}

async function main(argv) {
	const { values } = parseArgs({
		args: argv,
		options: {
			matrix: { type: "string" },
			"support-matrix": { type: "string" },
			json: { type: "boolean" },
			"require-enforced": { type: "boolean" },
		},
		strict: true,
	});
	const report = verifyInterceptionMatrix({
		matrixPath: values.matrix ? resolve(values.matrix) : undefined,
		supportMatrixPath: values["support-matrix"] ? resolve(values["support-matrix"]) : undefined,
	});
	if (values.json === true) {
		console.log(JSON.stringify(report, null, 2));
	} else {
		printReport(report);
	}
	if (!report.ok) process.exitCode = 1;
	else if (values["require-enforced"] === true && report.decision !== "GO") process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		await main(process.argv.slice(2));
	} catch (error) {
		console.error(`Interception matrix error: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 2;
	}
}
