import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { verifyInterceptionMatrix } from "./verify-interception-matrix.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, "verify-interception-matrix.mjs");
const MATRIX_PATH = join(HERE, "interception-matrix.json");
const SUPPORT_MATRIX_PATH = join(HERE, "support-matrix.json");
const REPO_ROOT = resolve(HERE, "..", "..");
const SUPPORT_MATRIX_RAW = readFileSync(SUPPORT_MATRIX_PATH, "utf8");

function committedMatrix() {
	return JSON.parse(readFileSync(MATRIX_PATH, "utf8"));
}

function mutate(mutator) {
	const matrix = committedMatrix();
	mutator(matrix);
	return matrix;
}

function withTempDir(fn) {
	const dir = mkdtempSync(join(tmpdir(), "aidr-interception-matrix-test-"));
	try {
		return fn(dir);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

/** Drive the exported gate function against a candidate matrix. */
function verify(matrix, options = {}) {
	return withTempDir((dir) => {
		const matrixPath = join(dir, "interception-matrix.json");
		writeFileSync(matrixPath, JSON.stringify(matrix, null, 2));
		let supportMatrixPath = options.supportMatrixPath ?? SUPPORT_MATRIX_PATH;
		if (options.mutateSupport) {
			const support = JSON.parse(SUPPORT_MATRIX_RAW);
			options.mutateSupport(support);
			supportMatrixPath = join(dir, "support-matrix.json");
			writeFileSync(supportMatrixPath, JSON.stringify(support, null, 2));
		}
		return verifyInterceptionMatrix({ matrixPath, supportMatrixPath, repoRoot: REPO_ROOT });
	});
}

function codes(report) {
	return report.failures.map((failure) => failure.code);
}

function row(matrix, connector, point) {
	const found = matrix.rows.find((entry) => entry.connector === connector && entry.point === point);
	assert.ok(found, `missing fixture row ${connector}/${point}`);
	return found;
}

test("the committed matrix is structurally valid, source-grounded and honestly open", () => {
	const report = verifyInterceptionMatrix({
		matrixPath: MATRIX_PATH,
		supportMatrixPath: SUPPORT_MATRIX_PATH,
		repoRoot: REPO_ROOT,
	});
	assert.equal(report.ok, true, report.failureReasons.join("; "));
	assert.deepEqual(report.failures, []);
	// Validity and readiness are separate: only rows backed by a real-host
	// acceptance record (docs/evidence/real-host/) are enforced, the rest stay
	// open, so the matrix stays NO-GO.
	assert.equal(report.decision, "NO-GO");
	assert.equal(report.counts.connectors, 6);
	assert.equal(report.counts.rows, 36);
	assert.equal(report.counts.byStatus.enforced, 11);
	assert.deepEqual(
		committedMatrix()
			.rows.filter((entry) => entry.status === "enforced")
			.map((entry) => `${entry.connector}/${entry.point}`)
			.sort(),
		[
			"claude-code/post-tool-output",
			"claude-code/pre-prompt",
			"claude-code/pre-tool",
			"codex/pre-prompt",
			"codex/pre-tool",
			"openclaw/post-tool-output",
			"openclaw/pre-prompt",
			"openclaw/pre-tool",
			"opencode/post-tool-output",
			"opencode/pre-prompt",
			"opencode/pre-tool",
		],
	);
	// Cursor and VS Code have no real-host record.
	assert.equal(report.connectorsWithoutNamedAcceptance, 2);
	assert.equal(report.openPointCount, 25);
	assert.equal(report.matrixSha256.length, 64);
});

test("OpenClaw opaque binary remains uninspected and is not host-accepted with a binary result", () => {
	const matrix = committedMatrix();
	const binary = matrix.failureConditions.find(
		(entry) => entry.connector === "openclaw" && entry.condition === "large-binary-response",
	);
	assert.ok(binary, "missing OpenClaw large-binary-response condition");
	assert.equal(binary.outcome, "explicitly-unsupported");
	assert.match(binary.reason, /not decoded or inspected; it is marked incomplete/iu);
	assert.match(binary.reason, /not host-accepted with a binary result/iu);
	const report = verifyInterceptionMatrix({
		matrixPath: MATRIX_PATH,
		supportMatrixPath: SUPPORT_MATRIX_PATH,
		repoRoot: REPO_ROOT,
	});
	assert.equal(report.ok, true, report.failureReasons.join("; "));
});

test("an unknown status fails the gate", () => {
	const report = verify(
		mutate((matrix) => {
			row(matrix, "claude-code", "pre-tool").status = "totally-made-up";
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("UNKNOWN_STATUS"), report.failureReasons.join("; "));
});

test("an unknown interception point fails the gate", () => {
	const report = verify(
		mutate((matrix) => {
			row(matrix, "claude-code", "pre-tool").point = "post-tool";
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("UNKNOWN_POINT"), report.failureReasons.join("; "));
});

test("an unknown connector fails the gate", () => {
	const report = verify(
		mutate((matrix) => {
			row(matrix, "claude-code", "pre-tool").connector = "some-other-agent";
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("UNKNOWN_CONNECTOR"), report.failureReasons.join("; "));
	assert.ok(codes(report).includes("MISSING_POINT_ROW"), report.failureReasons.join("; "));
});

test("a sold connector with no rows fails the gate", () => {
	const report = verify(
		mutate((matrix) => {
			matrix.rows = matrix.rows.filter((entry) => entry.connector !== "codex");
			matrix.tamperPosture = matrix.tamperPosture.filter((entry) => entry.connector !== "codex");
			matrix.failureConditions = matrix.failureConditions.filter((entry) => entry.connector !== "codex");
		}),
	);
	assert.equal(report.ok, false);
	const missing = report.failures.filter(
		(failure) => failure.code === "MISSING_POINT_ROW" && failure.connector === "codex",
	);
	assert.equal(missing.length, 6);
	assert.ok(codes(report).includes("MISSING_TAMPER_POSTURE"), report.failureReasons.join("; "));
	assert.ok(codes(report).includes("MISSING_FAILURE_CONDITION"), report.failureReasons.join("; "));
});

test("a row claiming an implemented point the connector source lacks fails the gate", () => {
	const report = verify(
		mutate((matrix) => {
			row(matrix, "codex", "pre-tool").evidence = [
				{
					kind: "hook-registration",
					path: "packages/codex/src/cli.ts",
					contains: ["before_tool_call"],
				},
			];
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("EVIDENCE_MARKER_MISSING"), report.failureReasons.join("; "));
});

test("a row cannot borrow another connector's module as its guard", () => {
	const report = verify(
		mutate((matrix) => {
			row(matrix, "codex", "pre-tool").evidence = [
				{
					kind: "hook-registration",
					path: "packages/openclaw/src/index.ts",
					contains: ["before_tool_call"],
				},
			];
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("EVIDENCE_OUTSIDE_CONNECTOR_ROOT"), report.failureReasons.join("; "));
});

test("a row claiming an unsupported point as available fails the gate", () => {
	const report = verify(
		mutate((matrix) => {
			const target = row(matrix, "codex", "post-tool-output");
			target.status = "declared-not-proven";
			target.hostBoundary = "PostToolUse";
			target.reason = null;
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("MISSING_POINT_GUARD"), report.failureReasons.join("; "));
	assert.ok(codes(report).includes("SUPPORT_MATRIX_OUTPUT_NONE"), report.failureReasons.join("; "));
});

test("a row with a non-existent source path fails the gate", () => {
	const report = verify(
		mutate((matrix) => {
			row(matrix, "claude-code", "pre-tool").evidence[0].path = "packages/claude-code/src/does-not-exist.ts";
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("EVIDENCE_PATH_MISSING"), report.failureReasons.join("; "));
});

test("an unsupported row with a reason passes, and one without a reason fails", () => {
	const target = committedMatrix().rows.find(
		(entry) => entry.connector === "claude-code" && entry.point === "network",
	);
	assert.equal(target.status, "unsupported");
	assert.ok(target.reason.length > 10);
	const passing = verify(committedMatrix());
	assert.equal(passing.ok, true, passing.failureReasons.join("; "));

	const failing = verify(
		mutate((matrix) => {
			row(matrix, "claude-code", "network").reason = "";
		}),
	);
	assert.equal(failing.ok, false);
	assert.ok(codes(failing).includes("MISSING_UNSUPPORTED_REASON"), failing.failureReasons.join("; "));
});

test("marking a row enforced without a named real-host acceptance record fails the gate", () => {
	const report = verify(
		mutate((matrix) => {
			row(matrix, "cursor", "pre-tool").status = "enforced";
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("ENFORCED_WITHOUT_ACCEPTANCE_RECORD"), report.failureReasons.join("; "));
	assert.ok(codes(report).includes("ENFORCED_WITHOUT_SUPPORT_MATRIX_ACCEPTANCE"), report.failureReasons.join("; "));
});

test("an enforced row loses its status when its acceptance record is removed", () => {
	const report = verify(
		mutate((matrix) => {
			const target = row(matrix, "claude-code", "pre-tool");
			target.evidence = target.evidence.filter((entry) => entry.kind !== "acceptance-record");
		}),
	);
	assert.equal(report.ok, false);
	assert.deepEqual(codes(report), ["ENFORCED_WITHOUT_ACCEPTANCE_RECORD"]);
});

test("an acceptance record must live in the shared real-host evidence directory", () => {
	const report = verify(
		mutate((matrix) => {
			const record = row(matrix, "codex", "pre-tool").evidence.find((entry) => entry.kind === "acceptance-record");
			record.path = "docs/evidence/model-interception-live.json";
			record.contains = ["codex-cli"];
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("EVIDENCE_OUTSIDE_CONNECTOR_ROOT"), report.failureReasons.join("; "));
});

test("another connector's acceptance record cannot prove a row", () => {
	const report = verify(
		mutate((matrix) => {
			const record = row(matrix, "claude-code", "pre-tool").evidence.find((entry) => entry.kind === "acceptance-record");
			record.path = "docs/evidence/real-host/codex.json";
			record.contains = ['"pre-tool": "passed"'];
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("ACCEPTANCE_RECORD_CONNECTOR_MISMATCH"), report.failureReasons.join("; "));
});

test("an acceptance record that does not prove the cited point fails the gate", () => {
	const report = verify(
		mutate((matrix) => {
			// `agent --local` never delivers through a channel, so the OpenClaw record does
			// not prove pre-delivery-response; it cannot back an enforced row.
			const target = row(matrix, "openclaw", "pre-delivery-response");
			target.status = "enforced";
			target.evidence.push({
				kind: "acceptance-record",
				path: "docs/evidence/real-host/openclaw.json",
				contains: ['"connector": "openclaw"'],
			});
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("ACCEPTANCE_RECORD_DOES_NOT_PROVE"), report.failureReasons.join("; "));
});

test("a point the record proves stays unenforced when the support matrix does not sell it", () => {
	// OpenClaw's record proves post-tool-output; without the sold additional point the
	// enforced row is outside the sold matrix even though the record proves it.
	const record = JSON.parse(readFileSync(resolve(REPO_ROOT, "docs/evidence/real-host/openclaw.json"), "utf8"));
	assert.equal(record.proves.points["post-tool-output"], "passed");
	assert.equal(row(committedMatrix(), "openclaw", "post-tool-output").status, "enforced");
	const report = verify(committedMatrix(), {
		mutateSupport: (support) => {
			const openclaw = support.rows.find((entry) => entry.connector === "openclaw");
			openclaw.additionalInterceptionPoints = ["pre-prompt"];
		},
	});
	assert.equal(report.ok, false);
	assert.deepEqual(
		report.failures.map((failure) => `${failure.code}:${failure.connector}/${failure.point}`),
		["ENFORCED_OUTSIDE_SOLD_MATRIX:openclaw/post-tool-output"],
	);
});

test("an additional sold point must be enforced on a real-host record", () => {
	// Cursor's pre-prompt hook exists in source but has no real-host record, so the
	// sold scope cannot grow to include it.
	const cursor = verify(committedMatrix(), {
		mutateSupport: (support) => {
			support.rows.find((entry) => entry.connector === "cursor").additionalInterceptionPoints = ["pre-prompt"];
		},
	});
	assert.equal(cursor.ok, false);
	assert.deepEqual(
		cursor.failures.map((failure) => `${failure.code}:${failure.connector}/${failure.point}`),
		["ADDITIONAL_POINT_NOT_ENFORCED:cursor/pre-prompt"],
	);

	// Dropping the acceptance record from a sold additional point fails twice over.
	const withoutRecord = verify(
		mutate((matrix) => {
			const prompt = row(matrix, "codex", "pre-prompt");
			prompt.evidence = prompt.evidence.filter((entry) => entry.kind !== "acceptance-record");
		}),
	);
	assert.equal(withoutRecord.ok, false);
	assert.ok(codes(withoutRecord).includes("ENFORCED_WITHOUT_ACCEPTANCE_RECORD"), withoutRecord.failureReasons.join("; "));

	// Downgrading a sold additional point is refused instead of silently narrowing the claim.
	const downgraded = verify(
		mutate((matrix) => {
			row(matrix, "claude-code", "pre-prompt").status = "declared-not-proven";
		}),
	);
	assert.equal(downgraded.ok, false);
	assert.deepEqual(codes(downgraded), ["ADDITIONAL_POINT_NOT_ENFORCED"]);
});

test("additionalInterceptionPoints must be a list of mapped points", () => {
	const scalar = verify(committedMatrix(), {
		mutateSupport: (support) => {
			support.rows.find((entry) => entry.connector === "codex").additionalInterceptionPoints = "pre-prompt";
		},
	});
	assert.equal(scalar.ok, false);
	assert.ok(codes(scalar).includes("UNMAPPED_SUPPORT_MATRIX_POINT"), scalar.failureReasons.join("; "));

	const unmapped = verify(committedMatrix(), {
		mutateSupport: (support) => {
			support.rows.find((entry) => entry.connector === "codex").additionalInterceptionPoints = ["model-stream"];
		},
	});
	assert.equal(unmapped.ok, false);
	assert.ok(codes(unmapped).includes("UNMAPPED_SUPPORT_MATRIX_POINT"), unmapped.failureReasons.join("; "));

	// Codex declares no output point, so an additional output point contradicts it.
	const contradicts = verify(committedMatrix(), {
		mutateSupport: (support) => {
			support.rows.find((entry) => entry.connector === "codex").additionalInterceptionPoints = [
				"pre-prompt",
				"post-tool-output",
			];
		},
	});
	assert.equal(contradicts.ok, false);
	assert.ok(codes(contradicts).includes("ADDITIONAL_POINT_NOT_ENFORCED"), contradicts.failureReasons.join("; "));
	assert.ok(codes(contradicts).includes("SUPPORT_MATRIX_REQUIRES_POINT"), contradicts.failureReasons.join("; "));
});

test("a failure condition must match the outcome its acceptance record observed", () => {
	const report = verify(
		mutate((matrix) => {
			const crashed = matrix.failureConditions.find(
				(entry) => entry.connector === "claude-code" && entry.condition === "crashed-hook",
			);
			assert.equal(crashed.outcome, "fail-open");
			crashed.outcome = "fail-closed";
			crashed.evidence.push({
				kind: "failure-policy",
				path: "packages/claude-code/src/pre-tool-use.ts",
				contains: ["writeInspectionFailure"],
			});
		}),
	);
	assert.equal(report.ok, false);
	assert.deepEqual(codes(report), ["ACCEPTANCE_RECORD_DOES_NOT_PROVE"]);
});

test("a point declared unsupported while the support matrix sells it fails the gate", () => {
	const report = verify(committedMatrix(), {
		mutateSupport: (support) => {
			const codex = support.rows.find((entry) => entry.connector === "codex");
			codex.outputInterceptionPoint = "post-tool-output";
		},
	});
	assert.equal(report.ok, false);
	const failing = report.failures.filter((failure) => failure.code === "SUPPORT_MATRIX_REQUIRES_POINT");
	assert.deepEqual(
		failing.map((failure) => `${failure.connector}/${failure.point}`),
		["codex/post-tool-output"],
	);
});

test("claiming an output point the support matrix declares none for fails the gate", () => {
	const report = verify(committedMatrix(), {
		mutateSupport: (support) => {
			const claude = support.rows.find((entry) => entry.connector === "claude-code");
			claude.outputInterceptionPoint = "none";
		},
	});
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("SUPPORT_MATRIX_OUTPUT_NONE"), report.failureReasons.join("; "));
});

test("the support-matrix point bridge is part of the checked contract", () => {
	const report = verify(
		mutate((matrix) => {
			matrix.supportMatrixMapping.outputInterceptionPoint["tool-output-inspection"] = [];
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("SUPPORT_MATRIX_MAPPING_MISMATCH"), report.failureReasons.join("; "));
});

test("a vocabulary drift is rejected instead of silently narrowing the gate", () => {
	const report = verify(
		mutate((matrix) => {
			matrix.statusVocabulary = ["enforced", "declared-not-proven", "unsupported", "totally-made-up"];
		}),
	);
	assert.equal(report.ok, false);
	assert.ok(codes(report).includes("VOCABULARY_MISMATCH"), report.failureReasons.join("; "));
});

test("the CLI reports the committed matrix and exits 0 while keeping readiness NO-GO", () => {
	const result = spawnSync(process.execPath, [SCRIPT], { encoding: "utf8", timeout: 120_000 });
	assert.equal(result.status, 0, result.stderr);
	assert.match(result.stdout, /validity PASS {2}readiness NO-GO/u);
	assert.match(result.stdout, /failures 0/u);
	assert.match(result.stdout, /enforced=11/u);
});

test("the CLI fails closed on a validation failure and on --require-enforced", () => {
	const broken = withTempDir((dir) => {
		const path = join(dir, "interception-matrix.json");
		const matrix = mutate((candidate) => {
			row(candidate, "vscode", "pre-tool").status = "totally-made-up";
		});
		writeFileSync(path, JSON.stringify(matrix, null, 2));
		const result = spawnSync(process.execPath, [SCRIPT, "--matrix", path], { encoding: "utf8", timeout: 120_000 });
		assert.equal(result.status, 1, result.stdout);
		assert.match(result.stdout, /validity FAIL/u);
		assert.match(result.stdout, /UNKNOWN_STATUS/u);
		return result;
	});
	assert.equal(broken.status, 1);

	const gated = spawnSync(process.execPath, [SCRIPT, "--require-enforced"], {
		encoding: "utf8",
		timeout: 120_000,
	});
	assert.equal(gated.status, 1, gated.stdout);
	assert.match(gated.stdout, /validity PASS/u);

	const json = spawnSync(process.execPath, [SCRIPT, "--json"], { encoding: "utf8", timeout: 120_000 });
	assert.equal(json.status, 0, json.stderr);
	const parsed = JSON.parse(json.stdout);
	assert.equal(parsed.kind, "aidr-interception-matrix-gate");
	assert.equal(parsed.ok, true);
});
