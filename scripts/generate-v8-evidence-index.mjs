#!/usr/bin/env node
// Machine-readable evidence index for the Singularity AIDR v8 release candidate.
//
// This generator derives every value from artefacts that already exist on disk.
// It never invents a measurement, host, timestamp or customer fact:
//
//   * exit status   <- a provenance-bound machine-readable result file (written
//                      by `--run` or `--record`), else a decisive terminal marker
//                      inside the captured log, else "unknown" (fail closed).
//                      A stale/unbound result file can never create a PASS.
//   * timing        <- a captured start marker plus the log mtime, else "unknown".
//   * digests       <- SHA-256 of the log and of a declared artifact, else "unknown".
//   * test counts   <- parsed from the log when the log format is known, else "unknown".
//   * a gate with no log at all is emitted with status "NOT_RUN"; a declared gate
//     is never omitted from the index.
//
// Usage:
//   node scripts/generate-v8-evidence-index.mjs                 # write the index
//   node scripts/generate-v8-evidence-index.mjs --verify        # validate the index
//   node scripts/generate-v8-evidence-index.mjs --run <gate_id> # run a gate and capture
//   node scripts/generate-v8-evidence-index.mjs --record <gate_id> --exit-code <n> \
//        [--started-at <iso>] [--ended-at <iso>]                # record a gate run
//   node scripts/generate-v8-evidence-index.mjs --help

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const LOG_DIR = ".release-evidence/v8-logs";
export const INDEX_FILE = "docs/production-readiness/v8-evidence-index.json";
export const SCHEMA_FILE = "docs/production-readiness/v8-evidence-index.schema.json";
export const CANDIDATE_RELEASE_DIR = ".release-evidence/customer-release-v8-local-20260916-r9";
/** Candidate tag (e.g. `v8-local-20260916-r9`) used to name the kit and envelope. */
export const CANDIDATE_SUFFIX = CANDIDATE_RELEASE_DIR.split("/").pop()?.replace(/^customer-release-/, "") ?? "";
export const CANDIDATE_DIGEST_SOURCE = `${CANDIDATE_RELEASE_DIR}/release-inventory.json`;
export const GENERATOR_ID = "scripts/generate-v8-evidence-index.mjs";
export const RESULT_PROVENANCE_VERSION = 1;

export const UNKNOWN = "unknown";
export const UNAVAILABLE = "unavailable";
export const STATUS_PASS = "PASS";
export const STATUS_FAIL = "FAIL";
export const STATUS_NOT_RUN = "NOT_RUN";
export const STATUS_UNKNOWN = "unknown";
export const STATUS_VOCABULARY = Object.freeze([STATUS_PASS, STATUS_FAIL, STATUS_NOT_RUN, STATUS_UNKNOWN]);
// A status that asserts the gate succeeded. Its exit code must be exactly 0.
export const PASS_LIKE_STATUSES = Object.freeze([STATUS_PASS]);

// Evidence levels, ordered from weakest to strongest. A lower level must never
// be recorded in place of a higher one: a passing unit suite is not native-host
// acceptance and a local packaged run is not customer observation.
export const EVIDENCE_LEVELS = Object.freeze([
	"source_inspection",
	"unit_contract",
	"packaged_consumer",
	"isolated_integration",
	"native_host",
	"deployed_environment",
	"customer_observed",
	"externally_approved",
]);
export const EVIDENCE_LEVEL_FLOOR = EVIDENCE_LEVELS[0];

export function evidenceLevelRank(level) {
	return EVIDENCE_LEVELS.indexOf(level);
}

export function isEvidenceLevel(level) {
	return evidenceLevelRank(level) >= 0;
}

function assertEvidenceLevel(level, label) {
	if (!isEvidenceLevel(level)) {
		throw new Error(`${label}: unknown evidence level ${JSON.stringify(level)}`);
	}
}

// True when `lower` is being used where `higher` is claimed: the substitution
// this module exists to prevent.
export function levelsAreSubstituted(lower, higher) {
	assertEvidenceLevel(lower, "lower");
	assertEvidenceLevel(higher, "higher");
	return evidenceLevelRank(lower) < evidenceLevelRank(higher);
}

// Returns the only level that may be recorded for the pair. A claim above what
// the artefacts substantiate collapses to the substantiated level (fail closed);
// a deliberately weaker claim is preserved as-is.
export function failClosedEvidenceLevel(claimed, substantiated) {
	assertEvidenceLevel(claimed, "claimed");
	assertEvidenceLevel(substantiated, "substantiated");
	return evidenceLevelRank(claimed) <= evidenceLevelRank(substantiated) ? claimed : substantiated;
}

// ---------------------------------------------------------------------------
// Terminal markers. Every pattern below is declared from the gate's own source
// and was checked to appear exactly once in the captured log.
// ---------------------------------------------------------------------------

const CASES_PASS = /ALL PASS - (\d+)\/(\d+) cases behaved correctly/;
const CASES_FAIL = /(\d+) FAILURE\(S\) - (\d+)\/(\d+) cases behaved correctly/;
// Line-anchored patterns deliberately use [ \t] rather than \s for indentation:
// \s also matches newlines, which would let a pattern match across an empty line
// and report that empty line as the decisive marker.
const VITEST_FILES_SUMMARY = /^[ \t]*Test Files[ \t]+(.+?)\((\d+)\)[ \t]*$/m;
const VITEST_TESTS_SUMMARY = /^[ \t]*Tests[ \t]+(.+?)\((\d+)\)[ \t]*$/m;
const VITEST_TESTS_PASS = /^[ \t]*Tests[ \t]+\d+ passed(?: \| \d+ skipped)? \(\d+\)[ \t]*$/m;
const VITEST_FAILED = /^[ \t]*(?:Test Files|Tests)[ \t]+\d+ failed\b/m;
const NODE_TEST_TOTAL = /^ℹ tests (\d+)$/m;
const NODE_TEST_PASS = /^ℹ pass (\d+)$/m;
const NODE_TEST_FAIL = /^ℹ fail (\d+)$/m;
const NODE_TEST_SKIPPED = /^ℹ skipped (\d+)$/m;
const START_MARKER = /^\[aidr-gate\] started_at_utc=(\S+)/m;
// pnpm prints the failing command's own exit status. This is the only generic
// exit-status report available for the pnpm-driven gates, so it is used as a
// declared fallback: it can only ever downgrade a record to FAIL, never to PASS.
const PNPM_LIFECYCLE_FAILURE = /ELIFECYCLE\s+Command failed with exit code (\d+)/;
const PYTEST_PASS = /^\d+ passed(?:, \d+ \w+)* in \d+\.\d+s$/m;
const PYTEST_FAIL = /^\d+ (?:failed|error[s]?)(?:, \d+ \w+)* in \d+\.\d+s$/m;

// ---------------------------------------------------------------------------
// Gate registry. Every declared verification gate of the v8 execution prompt
// appears here exactly once; a gate can never be dropped from the index.
// task_ids / feature_ids are gate-level bindings to the T-ids and capability
// ids of docs/production-readiness/next-agent-execution-prompt-v8.md.
// ---------------------------------------------------------------------------

function gate(entry) {
	return Object.freeze({
		command: UNKNOWN,
		log: null,
		artifact: null,
		counts: "none",
		pass: null,
		fail: null,
		evidence_level: EVIDENCE_LEVEL_FLOOR,
		evidence_level_ceiling: EVIDENCE_LEVEL_FLOOR,
		limitations: [],
		...entry,
	});
}

export const GATES = Object.freeze([
	gate({
		gate_id: "01-git-diff-check",
		command: "git diff --check",
		log: "01-git-diff-check.log",
		task_ids: ["T34", "T35"],
		feature_ids: ["EVAL-01", "EVAL-02"],
		owner: "release-engineering",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"Worktree-hygiene gate: it proves absence of whitespace errors and conflict markers in the working tree, not product behaviour.",
		],
	}),
	gate({
		gate_id: "02-feature-inventory",
		command: "node scripts/generate-feature-inventory.mjs",
		log: "02-feature-inventory.log",
		artifact: "FEATURE_INVENTORY.json",
		pass: /^Validated \d+ capability records: /m,
		task_ids: ["T34", "T35"],
		feature_ids: ["EVAL-01", "EVAL-02", "EVAL-03", "DEP-05"],
		owner: "release-engineering",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"The generator's completion line proves the inventory was regenerated from declared sources; it is not production acceptance of any capability.",
			"Capability statuses remain wired/partial/missing/external and the recorded decision stays NO-GO.",
		],
	}),
	gate({
		gate_id: "03-sales-gap-audit",
		command: "node scripts/generate-production-sales-gap-audit.mjs",
		log: "03-sales-gap-audit.log",
		artifact: "PRODUCTION_SALES_GAPS.json",
		pass: /^\{"work_packages":\d+,"features":\d+,"profile_gates":/m,
		task_ids: ["T34", "T41"],
		feature_ids: ["EVAL-02", "EVAL-03", "BIL-01"],
		owner: "commercial-operations",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"Counts open work packages and external gates; it does not close any of them.",
			"Commercial, legal and customer evidence stays external and is not produced by this gate.",
		],
	}),
	gate({
		gate_id: "04-next-agent-prompt",
		command: "node scripts/verify-next-agent-execution-prompt.mjs",
		log: "04-next-agent-prompt.log",
		artifact: "docs/production-readiness/next-agent-execution-prompt-v8.md",
		pass: /^\{"passed":true,/m,
		fail: /^Next-agent prompt verification failed:/m,
		task_ids: ["T34"],
		feature_ids: ["EVAL-02", "EVAL-03", "DEP-05"],
		owner: "release-engineering",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"Validates that the execution prompt still carries every required section and task id; it does not execute the prompt's gates.",
		],
	}),
	gate({
		gate_id: "06-quality-static",
		command: "pnpm quality:static",
		log: "06-quality-static.log",
		pass: /^Demo preflight: PASS \(static-only controlled evaluation surface\)$/m,
		fail: /^Demo preflight: NO-GO$/m,
		task_ids: ["T34", "T35", "T41"],
		feature_ids: ["EVAL-01", "EVAL-02", "BIL-01", "CLI-01"],
		owner: "quality-engineering",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"Composite `&&` chain: the PASS marker is emitted by the final command (node scripts/demo-preflight.mjs --static), which can only be reached when every earlier chained command exited 0.",
			"Biome reported 156 warnings and knip reported review debt (files=220, exports=131, duplicates=1); a warning-only lint result is not a clean static surface.",
			"demo-preflight warns that no sales URL/email, no DASHBOARD_SMOKE_BASE_URL and no DEMO_USER_* credentials are configured, so only the local static demo route is verified.",
		],
	}),
	gate({
		gate_id: "07-audit-prod",
		command: "pnpm audit:prod",
		log: "07-audit-prod.log",
		artifact: ".release-evidence/dependency-audit.json",
		pass: /^Production dependency audit: \d+ advisory\(ies\); /m,
		fail: /^Production dependency audit failed:$/m,
		task_ids: ["T35", "T40"],
		feature_ids: ["DEP-05", "OBS-05", "EVAL-01"],
		owner: "security-engineering",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"Advisory counts come from the local audit feed at run time; feed freshness and provider provenance are not recorded in the log.",
			"The summary line is printed before the failure check, so success is derived from the summary plus the absence of the explicit failure marker.",
		],
	}),
	gate({
		gate_id: "08-supabase-check",
		command: "pnpm supabase:check",
		log: "08-supabase-check.log",
		pass: /^Supabase migration contract passed \(\d+ migrations/m,
		fail: /^Supabase migration contract failed:$/m,
		task_ids: ["T31", "T42"],
		feature_ids: ["DEP-03", "TEN-01"],
		owner: "platform-engineering",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"Static contract over migration text (ordering, uniqueness, critical grants); no database instance is contacted and no migration is applied.",
		],
	}),
	gate({
		gate_id: "09-verify-enforcement",
		command: "pnpm verify:enforcement",
		log: "09-verify-enforcement.log",
		pass: CASES_PASS,
		fail: CASES_FAIL,
		counts: "cases",
		task_ids: ["T01", "T35"],
		feature_ids: ["RSP-01", "CON-01", "CON-05", "EVAL-01"],
		owner: "security-engineering",
		evidence_level: "packaged_consumer",
		evidence_level_ceiling: "packaged_consumer",
		limitations: [
			"Drives locally built bundles through connector entry points with fixture tool calls; it does not observe a native host intercepting a real agent process.",
			"Deny paths are asserted from the emitted verdict, not from a verified absence of file/process/network side effects on a host.",
		],
	}),
	gate({
		gate_id: "10-verify-codex",
		command: "pnpm verify:codex",
		log: "10-verify-codex.log",
		pass: CASES_PASS,
		fail: CASES_FAIL,
		counts: "cases",
		task_ids: ["T01", "T35"],
		feature_ids: ["CON-05", "RSP-01", "EVAL-01"],
		owner: "security-engineering",
		evidence_level: "packaged_consumer",
		evidence_level_ceiling: "packaged_consumer",
		limitations: [
			"Contract test over the locally built Codex hook bundle for a named codex-cli version; real Codex host acceptance remains external.",
		],
	}),
	gate({
		gate_id: "11-test-ci-final",
		command: "pnpm test:ci",
		log: "11-test-ci-final.log",
		artifact: "coverage/test-results.json",
		pass: VITEST_TESTS_PASS,
		fail: VITEST_FAILED,
		counts: "vitest",
		task_ids: ["T35"],
		feature_ids: ["EVAL-01", "CON-05"],
		owner: "quality-engineering",
		evidence_level: "unit_contract",
		evidence_level_ceiling: "isolated_integration",
		limitations: [
			"Vitest exit status is derived from the suite summary (0 failed => exit 0); the wrapper scripts/run-tests-ci.mjs exits with the suite's status.",
			"Two skipped tests are recorded as skipped, not as passes.",
			"The declared artifact coverage/test-results.json is not present on disk, so artifact_sha256 is unknown.",
		],
	}),
	gate({
		gate_id: "12-test-coverage",
		command: "pnpm test:coverage",
		log: "12-test-coverage.log",
		pass: null,
		fail: VITEST_FAILED,
		counts: "vitest",
		task_ids: ["T35", "T39"],
		feature_ids: ["EVAL-01"],
		owner: "quality-engineering",
		evidence_level: "unit_contract",
		evidence_level_ceiling: "isolated_integration",
		limitations: [
			"The captured log ends after a passing test line with no Vitest summary block, so the coverage run did not complete in this log; no coverage threshold result exists.",
			"Individually observed passing tests are not a coverage measurement and are not reported as one.",
		],
	}),
	gate({
		gate_id: "13-build-release",
		command: "pnpm build:release",
		log: "13-build-release.log",
		artifact: ".release-evidence/aidr-sbom.cdx.json",
		pass: null,
		fail: null,
		task_ids: ["T29", "T31", "T35"],
		feature_ids: ["DEP-04", "DEP-05", "DEP-08", "OBS-05"],
		owner: "release-engineering",
		evidence_level: "packaged_consumer",
		evidence_level_ceiling: "packaged_consumer",
		limitations: [
			"Composite `&&` chain whose final two commands (scripts/check-no-sourcemaps.mjs, scripts/check-no-leaky-paths.mjs) emit no success marker, so the chain's exit status cannot be proven from this log.",
			"The log does show the build, artifact manifests, package contracts and 10 package consumer smokes completing; that is partial, not a verdict.",
			"Re-run this gate through `--run 13-build-release` (or `--record`) to capture an authoritative exit code.",
		],
	}),
	gate({
		gate_id: "14-node-contracts",
		command:
			"node --test scripts/endpoint-install.test.mjs scripts/deployment-prepare.test.mjs scripts/load-test.test.mjs scripts/release-signing.test.mjs scripts/run-e2e-release.test.mjs scripts/deployment-offboarding.test.mjs scripts/deployment-backup-offsite.test.mjs deploy/ingress/device-start.test.mjs deploy/monitoring/monitoring.test.mjs scripts/benchmarks/evaluate.test.mjs",
		log: "14-node-contracts.log",
		pass: NODE_TEST_PASS,
		fail: /^ℹ fail ([1-9]\d*)$/m,
		counts: "node_test",
		task_ids: ["T01", "T27", "T30", "T31", "T39", "T40", "T45"],
		feature_ids: ["DEP-03", "DEP-04", "DEP-05", "DEP-06", "DEP-07", "TEN-05", "EVAL-01"],
		owner: "quality-engineering",
		evidence_level: "unit_contract",
		evidence_level_ceiling: "unit_contract",
		limitations: [
			"node --test contract suites for scripts, device-start ingress and monitoring; they run on this host against local fixtures.",
			"Failures are derived from `ℹ fail <n>`; a log without that summary stays unknown.",
		],
	}),
	gate({
		gate_id: "15-aig-pytest",
		// The interpreter is `AIDR_AIG_PYTHON` when set (an isolated pinned venv),
		// otherwise the documented `python`. A bare `python` without the pinned
		// test dependencies fails at pytest collection, which is a missing
		// prerequisite rather than a product failure.
		command: "${AIDR_AIG_PYTHON:-python} -m pytest services/aig-bridge/tests -q",
		log: "15-aig-pytest.log",
		pass: PYTEST_PASS,
		fail: PYTEST_FAIL,
		task_ids: ["T06", "T39"],
		feature_ids: ["INF-01", "INF-02"],
		owner: "ai-infrastructure-engineering",
		evidence_level: "unit_contract",
		evidence_level_ceiling: "isolated_integration",
		limitations: [
			"Requires an isolated pinned venv built from services/aig-bridge/requirements-test.txt; the vendored AI-Infra-Guard submodule commit and dirty state must be recorded with the run.",
			"Dataset freshness and fingerprint coverage limits remain after a passing suite.",
			"Test counts are only accepted from pytest's own summary line; any other log shape stays unknown.",
		],
	}),
	gate({
		gate_id: "16-support-bundle",
		command: "node scripts/verify-support-bundle.mjs --self-test && node scripts/privacy-verify.mjs",
		log: "16-support-bundle.log",
		pass: /^Privacy evidence: .+ \(LOCAL_PASS\)$/m,
		fail: /^Privacy evidence: .+ \((?!LOCAL_PASS\))/m,
		task_ids: ["T37", "T40"],
		feature_ids: ["DEP-05", "OBS-05", "OBS-03"],
		owner: "support-operations",
		evidence_level: "unit_contract",
		evidence_level_ceiling: "isolated_integration",
		limitations: [
			"Self-test and privacy canary cover the allowlist and identity/secret patterns; they do not prove a real customer bundle content review.",
			"The declared command is an `&&` chain of two verifiers; both halves must appear in the captured log before an exit status can be derived.",
		],
	}),
	gate({
		gate_id: "17-claim-inventory",
		command: "node docs/scripts/claim-check.mjs --mode=inventory --json",
		log: "17-claim-inventory.log",
		task_ids: ["T34"],
		feature_ids: ["EVAL-02", "EVAL-03", "DEP-05"],
		owner: "commercial-operations",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"`--mode=gate` is expected to FAIL while external gates are open and must not be bypassed; an inventory PASS is not an approved-claim result.",
		],
	}),
	gate({
		gate_id: "18-native-host",
		command: "pnpm verify:native-host",
		log: "18-native-host.log",
		pass: /"gate": "GO"/m,
		fail: /"gate": "NO_GO"/m,
		task_ids: ["T01", "T12"],
		feature_ids: ["CON-01", "CON-02", "CON-03", "CON-04", "CON-05", "CON-06", "RSP-04", "RSP-06"],
		owner: "platform-engineering",
		evidence_level: "native_host",
		evidence_level_ceiling: "native_host",
		limitations: [
			"A missing or unnamed host must be reported as HOST_UNAVAILABLE and NO-GO; skipping an absent host is not acceptable evidence.",
			"Protected status requires observing that a deny actually prevented the file/process/network side effect on the host.",
		],
	}),
	gate({
		gate_id: "19-release-e2e",
		command: "pnpm test:e2e",
		log: "19-release-e2e.log",
		pass: /^Release E2E gate passed; evidence: /m,
		fail: /^Release E2E gate failed closed:$/m,
		task_ids: ["T01", "T29", "T35"],
		feature_ids: ["CON-01", "CON-02", "CON-03", "CON-04", "CON-05", "DEP-05", "EVAL-01"],
		owner: "quality-engineering",
		evidence_level: "native_host",
		evidence_level_ceiling: "native_host",
		limitations: [
			"Requires AIDR_E2E_RC_DIGEST bound to the release-inventory digest; without external receipts/hosts the fail-closed result must be preserved.",
			"Runs the real local CLIs and editor hosts on this workstation, which is not a customer environment.",
			"A fail-closed result caused by absent prerequisites is recorded as FAIL for this declared command; it is never rewritten into a pass.",
		],
	}),
	gate({
		gate_id: "20-release-bundle",
		command: "node .github/scripts/build-release-bundle.mjs",
		log: "20-release-bundle.log",
		artifact: `${CANDIDATE_RELEASE_DIR}/release-inventory.json`,
		pass: /^Release bundle assembled in .+ \(\d+ artifacts\)$/m,
		task_ids: ["T29", "T34"],
		feature_ids: ["DEP-05", "DEP-08", "OBS-05"],
		owner: "release-engineering",
		evidence_level: "packaged_consumer",
		evidence_level_ceiling: "packaged_consumer",
		limitations: [
			"Assembles 15 local artifacts, including an unsigned offline-verifiable provenance statement; without official publisher key custody and private registry publication the candidate stays unsigned (publisher_authenticated=false).",
			"Checksums prove content, not publisher identity.",
		],
	}),
	gate({
		gate_id: "20-customer-kit",
		// The kit needs a release bundle, an upstream checkout and a destination,
		// none of which the bare script name supplies; running it without them
		// fails on argument parsing before it can prove anything. Derive every
		// path from the candidate this index is bound to so the gate reproduces
		// exactly what the index records.
		command: `node scripts/customer-kit.mjs --output .release-evidence/aidr-customer-kit-${CANDIDATE_SUFFIX} --upstream-dir deploy/upstream --release-dir ${CANDIDATE_RELEASE_DIR} --envelope-output .release-evidence/aidr-envelope-${CANDIDATE_SUFFIX}`,
		log: "20-customer-kit.log",
		artifact: `.release-evidence/aidr-envelope-${CANDIDATE_SUFFIX}/release-inventory.json`,
		pass: /^Portable candidate assembled: \d+ files\./m,
		task_ids: ["T36", "T41"],
		feature_ids: ["DEP-08", "EVAL-02", "EVAL-03", "BIL-01"],
		owner: "release-engineering",
		evidence_level: "packaged_consumer",
		evidence_level_ceiling: "packaged_consumer",
		limitations: [
			"Portable candidate assembly only; the release envelope is unsigned and no customer host has installed it.",
			"Customer onboarding, empty-PATH installation and support workflows are separate gates and remain NOT_RUN.",
		],
	}),
	gate({
		gate_id: "21-aig-verify",
		command: "pnpm aig:verify",
		log: "21-aig-verify.log",
		pass: /^\{"source":\{"commit":/m,
		fail: /^\[aig\] /m,
		task_ids: ["T06", "T39"],
		feature_ids: ["INF-01", "INF-02", "EVAL-01"],
		owner: "ai-infrastructure-engineering",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"Verifies the vendored AI-Infra-Guard source pin and corpus on the same commit as the isolated Python suite; submodule dirty state must be captured in the evidence.",
		],
	}),
	gate({
		gate_id: "22-e2e-negative",
		command: "pnpm test:e2e:negative",
		log: "22-e2e-negative.log",
		// The runner classifies every scenario (PASS / FAIL / HOST_UNAVAILABLE /
		// BLOCKED_EXTERNAL / UNSUPPORTED / SETUP_FAILURE) and prints one decision
		// line. `product_failures=0` with an explicit NO-GO/blocked decision is a
		// pass for THIS gate: a host that is not installed is not a product
		// defect, and a wrong-accept would have set product_failures above zero.
		pass: /\[e2e-negative\] decision=\S+ status=\S+ exit_code=\d+ product_failures=0 /m,
		fail: /product_failures=[1-9]|Negative credential E2E control failed:$/m,
		task_ids: ["T21", "T35", "T42"],
		feature_ids: ["TEN-01", "TEN-06", "DET-10", "DET-11", "EVAL-01"],
		owner: "security-engineering",
		evidence_level: "isolated_integration",
		evidence_level_ceiling: "isolated_integration",
		limitations: [
			"Exercises missing/wrong credentials, wrong tenant, replay and unavailable-dependency paths against local fixtures.",
		],
	}),
	gate({
		gate_id: "23-fleet",
		command: "pnpm verify:fleet:windows && pnpm verify:fleet:unix",
		log: "23-fleet.log",
		pass: /"scope":"Offline template and local lifecycle verification/,
		fail: /"passed":\s*false/,
		task_ids: ["T12", "T17"],
		feature_ids: ["CLI-04", "RSP-04", "RSP-06"],
		owner: "platform-engineering",
		evidence_level: "isolated_integration",
		evidence_level_ceiling: "isolated_integration",
		limitations: [
			"The verifiers' own declared scope is offline template and local lifecycle verification; no Jamf/MDM or host execution acceptance is claimed.",
			"An absent OS or MDM host must not be counted as a success; real Intune/SCCM/Jamf execution and publisher signing remain external.",
		],
	}),
	gate({
		gate_id: "24-monitoring-and-upgrade",
		command:
			"pnpm verify:monitoring && pnpm verify:upgrade && pnpm verify:support-bundle && pnpm verify:load && pnpm verify:release-signing && pnpm verify:backup-offsite && pnpm verify:offboarding",
		log: "24-monitoring-and-upgrade.log",
		pass: null,
		fail: null,
		counts: "none",
		task_ids: ["T26", "T27", "T29", "T30", "T31", "T32", "T40"],
		feature_ids: ["DEP-03", "DEP-06", "DEP-07", "DEP-05", "OBS-05", "OBS-06"],
		owner: "platform-engineering",
		evidence_level: "isolated_integration",
		evidence_level_ceiling: "isolated_integration",
		limitations: [
			"Local readiness/upgrade/backup/offboarding drills; real offsite provider, independent-host recovery and agreed RPO/RTO remain external.",
			"Seven chained commands whose success markers overlap (two of them are node --test runs), so no exit status is inferred from a combined log; run it with `--run` or `--record` to capture one authoritatively.",
		],
	}),
	gate({
		gate_id: "25-customer-onboarding",
		// The verifier needs an installed deployment directory and refuses to
		// guess one, which is the right default but means the bare script name can
		// only ever report CUSTOMER_DEPLOYMENT_REQUIRED. Point it at the local
		// rehearsal installation this repository prepares, and fail closed with the
		// same operator-facing message when that installation is absent.
		//
		// Pass the directory as an argument rather than relying on
		// AIDR_DEPLOYMENT_DIR: the demo suite that follows inherits this
		// environment, and a deployment directory in it changes test behaviour in
		// unrelated packages.
		command: `node -e "const fs=require('fs');const d='.release-evidence/aidr-local-deployment-r9';if(!fs.existsSync(d+'/deployment.json')){console.error('BLOCKED CUSTOMER_DEPLOYMENT_REQUIRED: prepare a local installation with node scripts/deployment-prepare.mjs --development --supabase-url http://127.0.0.1:8000 --dashboard-url http://127.0.0.1:8080 --region self-hosted --tenant-region self-hosted; then start it and apply migrations');process.exit(3)}" && pnpm verify:customer-onboarding --deployment .release-evidence/aidr-local-deployment-r9 && pnpm test:customer-demo`,
		log: "25-customer-onboarding.log",
		task_ids: ["T20", "T36", "T37"],
		feature_ids: ["TEN-03", "TEN-05", "TEN-07", "CLI-01", "OBS-03"],
		owner: "release-engineering",
		evidence_level: "isolated_integration",
		evidence_level_ceiling: "isolated_integration",
		limitations: [
			"This declared command is a local rehearsal (verify:customer-onboarding plus the local customer demo); it cannot produce customer_observed evidence.",
			"Real customer observation requires a named customer on a real host and is not produced by this gate.",
		],
	}),
	gate({
		gate_id: "26-generator-determinism",
		command:
			"git diff --exit-code -- FEATURE_INVENTORY.json FEATURE_INVENTORY.md PRODUCTION_SALES_GAPS.json PRODUCTION_SALES_GAPS.md READINESS_BACKLOG.json",
		log: "26-generator-determinism.log",
		task_ids: ["T34"],
		feature_ids: ["EVAL-02", "EVAL-03", "DEP-05"],
		owner: "release-engineering",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"Proves the four generators are byte-stable across two runs; it does not prove the generated content is correct or complete.",
		],
	}),
	gate({
		gate_id: "27-empty-path-package-install",
		command: "pnpm verify:package-install",
		log: "27-empty-path-package-install.log",
		task_ids: ["T17", "T29"],
		feature_ids: ["CLI-01", "CLI-03", "CLI-04", "DEP-08"],
		owner: "release-engineering",
		evidence_level: "packaged_consumer",
		evidence_level_ceiling: "packaged_consumer",
		limitations: [
			"Requires a release-built dist: against a development dist the gate fails closed with SOURCE_MAP_PRESENT and TEST_DIRECTORY_PRESENT.",
			"A package whose entry point needs an unbundled runtime dependency (for example `yaml`, `@opencode-ai/plugin`, `commander`, or the first-party core) is reported SKIPPED_WITH_REASON when a fresh offline resolve cannot complete; a skip is never counted as a pass.",
			"The extension host (`vscode`) cannot exist in a Node-only consumer process, so that package's runtime entry is UNSUPPORTED and only its syntax and shipped assets are checked.",
		],
	}),
	gate({
		gate_id: "28-interception-matrix",
		command: "pnpm verify:interception-matrix",
		log: "28-interception-matrix.log",
		task_ids: ["T01", "T04", "T10"],
		feature_ids: ["CON-01", "CON-02", "CON-03", "CON-04", "CON-05", "CON-06", "MCP-07", "DET-06"],
		owner: "endpoint-engineering",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"Validity PASS with readiness NO-GO: every declared interception point is `declared-not-proven` or `unsupported` until a named real-host acceptance record exists, and the gate refuses an `enforced` row without one.",
			"Cross-checks each row against the connector's own source tree, so a row cannot claim a point the source does not implement or borrow another connector's module.",
		],
	}),
	gate({
		gate_id: "29-repo-hygiene",
		command: "pnpm verify:repo-hygiene",
		log: "29-repo-hygiene.log",
		artifact: "READINESS_BACKLOG.json",
		task_ids: ["T34", "T35"],
		feature_ids: ["EVAL-01", "EVAL-02"],
		owner: "release-engineering",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"Enforces the AIDR-012 acceptance criteria over tracked files: no tracked root scratch output, and no personal absolute host path outside an explicitly reasoned allowlist.",
			"A bare Windows UNC rule is deliberately out of scope because `\\\\\\\\` is the normal spelling of a regex escape in tracked source; the script documents that decision.",
		],
	}),
	gate({
		gate_id: "30-commercial-gates",
		command: "pnpm verify:commercial-gates",
		log: "30-commercial-gates.log",
		artifact: "docs/production-readiness/commercial-gate-receipts.json",
		task_ids: ["T34", "T41"],
		feature_ids: ["EVAL-02", "EVAL-03", "BIL-01"],
		owner: "commercial-operations",
		evidence_level: "source_inspection",
		evidence_level_ceiling: "source_inspection",
		limitations: [
			"Structural and consistency gate only: it exits 0 when all 13 hard gates are recorded as honestly open with their required external inputs named.",
			"It cannot close a gate. `node docs/scripts/claim-check.mjs --mode=gate` remains the gate that fails while any of them is open, and it is expected to fail.",
		],
	}),
]);

// ---------------------------------------------------------------------------
// Derivation helpers
// ---------------------------------------------------------------------------

const DECLARED_LOG_NAMES = new Set(GATES.map((entry) => entry.log).filter((name) => name !== null));

// Files that belong to the same gate number but are not this gate's declared
// log. They are never consumed silently: a filename mismatch must be visible in
// the record instead of being reported as "no evidence exists".
export function siblingLogFiles(gateEntry, root = ROOT) {
	if (gateEntry.log === null) return [];
	const directory = resolve(root, LOG_DIR);
	if (!existsSync(directory)) return [];
	const prefix = `${gateEntry.log.slice(0, gateEntry.log.indexOf("-") + 1)}`;
	return readdirSync(directory)
		.filter((name) => name.startsWith(prefix))
		.filter((name) => name !== gateEntry.log && !name.endsWith(".result.json"))
		.filter((name) => !DECLARED_LOG_NAMES.has(name))
		.filter((name) => statSync(resolve(directory, name)).isFile())
		.sort();
}

export function sha256Hex(buffer) {
	return createHash("sha256").update(buffer).digest("hex");
}

export function sha256File(absolutePath) {
	try {
		return sha256Hex(readFileSync(absolutePath));
	} catch {
		return UNKNOWN;
	}
}

// The gate logs are produced by different capture paths: PowerShell Tee-Object
// writes UTF-16LE with a BOM on Windows PowerShell, `--run` writes UTF-8, and a
// redirected stream can carry a UTF-8 BOM. Decode what is actually on disk
// instead of assuming one encoding.
export function decodeText(buffer) {
	if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) {
		return buffer.subarray(2).toString("utf16le");
	}
	if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
		const swapped = Buffer.from(buffer.subarray(2));
		swapped.swap16();
		return swapped.toString("utf16le");
	}
	if (buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
		return buffer.subarray(3).toString("utf8");
	}
	return buffer.toString("utf8");
}

export function readLogFile(absolutePath) {
	const bytes = readFileSync(absolutePath);
	return { text: decodeText(bytes), sha256: sha256Hex(bytes), byte_length: bytes.length };
}

export function gitCommitSha(root = ROOT) {
	const result = spawnSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8", timeout: 30000 });
	const sha = (result.stdout ?? "").trim();
	return /^[0-9a-f]{40}$/.test(sha) ? sha : UNKNOWN;
}

export function candidateDigest(root = ROOT) {
	const source = resolve(root, CANDIDATE_DIGEST_SOURCE);
	const digest = existsSync(source) ? sha256File(source) : UNKNOWN;
	return { source: CANDIDATE_DIGEST_SOURCE, digest_source_exists: existsSync(source), digest };
}

function declaredArtifactDigest(gateEntry, root = ROOT) {
	return gateEntry.artifact == null ? UNKNOWN : sha256File(resolve(root, gateEntry.artifact));
}

export function readEnvironment() {
	return {
		platform: process.platform,
		arch: process.arch,
		os_type: os.type(),
		os_release: os.release(),
		hostname: os.hostname(),
		// The gate logs carry no host identity, so the host behind each log cannot
		// be attested. This field says so instead of implying the generator host.
		gate_host_provenance: UNKNOWN,
	};
}

function toolVersion(commands) {
	for (const command of commands) {
		const result = spawnSync(command, { encoding: "utf8", shell: true, timeout: 30000 });
		const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
		if (!result.error && result.status === 0 && output) return output;
	}
	return UNAVAILABLE;
}

export function readToolVersions() {
	return {
		node: toolVersion(["node --version"]),
		pnpm: toolVersion(["pnpm --version"]),
		python: toolVersion(["python --version", "python3 --version"]),
		docker: toolVersion(["docker --version"]),
		os: `${os.type()} ${os.release()} (${process.arch})`,
	};
}

function integerOrUnknown(value) {
	return Number.isInteger(value) && value >= 0 ? value : UNKNOWN;
}

function tally({ total, passed, failed, skipped = UNKNOWN, files_total, files_passed }) {
	const counts = {
		total: integerOrUnknown(total),
		passed: integerOrUnknown(passed),
		failed: integerOrUnknown(failed),
		skipped: skipped === UNKNOWN ? UNKNOWN : integerOrUnknown(skipped),
	};
	if (files_total !== undefined || files_passed !== undefined) {
		counts.files_total = integerOrUnknown(files_total);
		counts.files_passed = integerOrUnknown(files_passed);
	}
	return counts;
}

export function parseTestCounts(kind, text) {
	if (kind === "cases") {
		const failed = CASES_FAIL.exec(text);
		if (failed) return tally({ total: Number(failed[3]), passed: Number(failed[2]), failed: Number(failed[1]) });
		const passed = CASES_PASS.exec(text);
		if (passed) return tally({ total: Number(passed[2]), passed: Number(passed[1]), failed: 0 });
		return UNKNOWN;
	}
	if (kind === "vitest") {
		const tests = VITEST_TESTS_SUMMARY.exec(text);
		if (!tests) return UNKNOWN;
		const segments = parseVitestSegments(tests[1]);
		const files = VITEST_FILES_SUMMARY.exec(text);
		const fileSegments = files ? parseVitestSegments(files[1]) : null;
		return tally({
			total: Number(tests[2]),
			passed: segments.passed,
			failed: segments.failed,
			skipped: segments.skipped,
			files_total: files ? Number(files[2]) : UNKNOWN,
			files_passed: fileSegments ? fileSegments.passed : UNKNOWN,
		});
	}
	if (kind === "node_test") {
		const total = NODE_TEST_TOTAL.exec(text);
		const passed = NODE_TEST_PASS.exec(text);
		const failed = NODE_TEST_FAIL.exec(text);
		if (!total || !passed || !failed) return UNKNOWN;
		const skipped = NODE_TEST_SKIPPED.exec(text);
		return tally({
			total: Number(total[1]),
			passed: Number(passed[1]),
			failed: Number(failed[1]),
			skipped: skipped ? Number(skipped[1]) : 0,
		});
	}
	return UNKNOWN;
}

// Vitest renders its summary as "<n> passed | <n> failed | <n> skipped (total)".
function parseVitestSegments(segment) {
	const counts = { passed: 0, failed: 0, skipped: 0 };
	for (const match of segment.matchAll(/(\d+)[ \t]+([a-z]+)/g)) {
		if (match[2] in counts) counts[match[2]] = Number(match[1]);
	}
	return counts;
}

function lastNonEmptyLine(text) {
	const lines = text.split(/\r?\n/).filter((line) => line.trim().length > 0);
	return lines.length > 0 ? lines[lines.length - 1].trim() : "";
}

function clip(text, limit = 320) {
	const flat = text.replace(/\s+/g, " ").trim();
	return flat.length <= limit ? flat : `${flat.slice(0, limit - 3)}...`;
}

function isoUtc(value) {
	if (value === UNKNOWN) return UNKNOWN;
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? UNKNOWN : date.toISOString();
}

function readResultFile(absolutePath) {
	if (!existsSync(absolutePath)) return null;
	try {
		const parsed = JSON.parse(readFileSync(absolutePath, "utf8"));
		return typeof parsed === "object" && parsed !== null ? parsed : null;
	} catch {
		return null;
	}
}

function normalizedFingerprint(value) {
	return typeof value === "string" ? value.trim().toLowerCase() : value;
}

/**
 * A result sidecar is only authoritative when it describes the exact artefacts
 * currently being indexed. The log hash catches a rewritten log; the declared
 * artifact hash catches a generated output being replaced; the source commit
 * and candidate digest keep a result from another checkout/release from
 * producing a PASS in this index. Missing bindings are unprovable, not legacy
 * compatibility.
 */
export function resultBindingFailures({
	gateEntry,
	resultFile,
	logBytes,
	artifact_sha256,
	commit_sha,
	candidate_digest,
}) {
	const failures = [];
	if (resultFile === null || typeof resultFile !== "object") {
		failures.push("result file is missing or is not valid JSON");
		return failures;
	}
	if (resultFile.gate_id !== gateEntry.gate_id) {
		failures.push(`gate_id ${JSON.stringify(resultFile.gate_id)} does not match ${gateEntry.gate_id}`);
	}
	if (resultFile.command !== gateEntry.command) {
		failures.push("declared command does not match the result file command");
	}
	if (resultFile.provenance_version !== undefined && resultFile.provenance_version !== RESULT_PROVENANCE_VERSION) {
		failures.push(`unsupported result provenance version ${JSON.stringify(resultFile.provenance_version)}`);
	}
	if (!Number.isInteger(resultFile.exit_code) || resultFile.exit_code < 0) {
		failures.push("result file has no usable non-negative integer exit_code");
	}

	const recordedCommit = resultFile.commit_sha ?? resultFile.source_commit;
	if (!/^[0-9a-f]{40}$/.test(normalizedFingerprint(commit_sha ?? ""))) {
		failures.push("current source commit is unknown, so the result cannot be source-bound");
	} else if (!/^[0-9a-f]{40}$/.test(normalizedFingerprint(recordedCommit ?? ""))) {
		failures.push("result file has no valid source commit binding");
	} else if (normalizedFingerprint(recordedCommit) !== normalizedFingerprint(commit_sha)) {
		failures.push(`result source commit ${recordedCommit} does not match current commit ${commit_sha}`);
	}
	if (resultFile.commit_sha !== undefined && resultFile.source_commit !== undefined && normalizedFingerprint(resultFile.commit_sha) !== normalizedFingerprint(resultFile.source_commit)) {
		failures.push("result commit_sha and source_commit bindings disagree");
	}

	if (!/^[0-9a-f]{64}$/.test(normalizedFingerprint(candidate_digest ?? ""))) {
		failures.push("current candidate digest is unknown, so the result cannot be candidate-bound");
	} else if (!/^[0-9a-f]{64}$/.test(normalizedFingerprint(resultFile.candidate_digest ?? ""))) {
		failures.push("result file has no valid candidate digest binding");
	} else if (normalizedFingerprint(resultFile.candidate_digest) !== normalizedFingerprint(candidate_digest)) {
		failures.push(`result candidate digest ${resultFile.candidate_digest} does not match current candidate digest ${candidate_digest}`);
	}
	if (typeof resultFile.candidate_digest_source !== "string" || resultFile.candidate_digest_source.trim().length === 0) {
		failures.push("result file has no candidate_digest_source binding");
	} else if (resultFile.candidate_digest_source !== CANDIDATE_DIGEST_SOURCE) {
		failures.push(`result candidate digest source ${JSON.stringify(resultFile.candidate_digest_source)} does not match ${CANDIDATE_DIGEST_SOURCE}`);
	}

	const recordedLog = normalizedFingerprint(resultFile.log_sha256);
	if (logBytes === null) {
		if (recordedLog !== UNKNOWN) failures.push("result file claims a log digest but the declared log is missing");
	} else if (!/^[0-9a-f]{64}$/.test(recordedLog)) {
		failures.push("result file has no valid log_sha256 binding");
	} else if (recordedLog !== logBytes.sha256) {
		failures.push(`result log_sha256 ${resultFile.log_sha256} does not match the current log ${logBytes.sha256}`);
	}

	const recordedArtifact = normalizedFingerprint(resultFile.artifact_sha256);
	if (!/^[0-9a-f]{64}$/.test(recordedArtifact) && recordedArtifact !== UNKNOWN) {
		failures.push("result file has no valid artifact_sha256 binding");
	} else if (recordedArtifact !== artifact_sha256) {
		failures.push(`result artifact_sha256 ${resultFile.artifact_sha256 ?? "missing"} does not match the current declared artifact ${artifact_sha256}`);
	}
	return failures;
}

function lineAt(text, index) {
	const start = text.lastIndexOf("\n", index) + 1;
	const end = text.indexOf("\n", index);
	const line = text.slice(start, end === -1 ? text.length : end).trim();
	if (line.length > 0) return line;
	// Defensive: a match landing on a line boundary must still report the
	// decisive line instead of an empty string.
	const forward = text
		.slice(index)
		.split("\n")
		.find((candidate) => candidate.trim().length > 0);
	return forward === undefined ? text.slice(index, index + 80).trim() : forward.trim();
}

function deriveExit(gateEntry, logText, resultFile, resultFilePresent, bindingFailures) {
	if (resultFile && bindingFailures.length === 0) {
		return { exit_code: resultFile.exit_code, basis: "result_file", marker: null };
	}
	if (logText !== null) {
		if (gateEntry.fail && gateEntry.fail.test(logText)) {
			const match = gateEntry.fail.exec(logText);
			return {
				exit_code: 1,
				basis: "log_marker",
				marker: match ? lineAt(logText, match.index) : gateEntry.fail.source,
			};
		}
		const lifeCycle = PNPM_LIFECYCLE_FAILURE.exec(logText);
		if (lifeCycle) {
			return { exit_code: Number(lifeCycle[1]), basis: "pnpm_lifecycle", marker: lifeCycle[0].trim() };
		}
		// A stale or malformed sidecar must never be allowed to turn a current
		// log's incidental PASS marker into trusted evidence. Fail closed instead.
		if (resultFilePresent) {
			return {
				exit_code: UNKNOWN,
				basis: "stale_result",
				marker: bindingFailures.join("; "),
			};
		}
		if (gateEntry.pass && gateEntry.pass.test(logText)) {
			const match = gateEntry.pass.exec(logText);
			return {
				exit_code: 0,
				basis: "log_marker",
				marker: match ? lineAt(logText, match.index) : gateEntry.pass.source,
			};
		}
	}
	if (resultFilePresent) {
		return { exit_code: UNKNOWN, basis: "stale_result", marker: bindingFailures.join("; ") };
	}
	return { exit_code: UNKNOWN, basis: "underivable", marker: null };
}

function statusFor(exitCode, logExists, resultFilePresent = false) {
	if (!logExists && exitCode === UNKNOWN) return resultFilePresent ? STATUS_UNKNOWN : STATUS_NOT_RUN;
	if (exitCode === 0) return STATUS_PASS;
	if (exitCode === UNKNOWN) return STATUS_UNKNOWN;
	return STATUS_FAIL;
}

// ---------------------------------------------------------------------------
// Record and index construction
// ---------------------------------------------------------------------------

export function buildGateRecord(gateEntry, context) {
	const { root, commit_sha, candidate_digest: digest, environment, tool_versions } = context;
	const logRelative = gateEntry.log === null ? null : `${LOG_DIR}/${gateEntry.log}`;
	const logAbsolute = logRelative === null ? null : resolve(root, logRelative);
	const resultRelative = logRelative === null ? null : `${logRelative}.result.json`;
	const resultAbsolute = logAbsolute === null ? null : `${logAbsolute}.result.json`;

	const logExists = logAbsolute !== null && existsSync(logAbsolute);
	const logBytes = logExists ? readLogFile(logAbsolute) : null;
	const logText = logBytes === null ? null : logBytes.text;
	const resultFileExists = resultAbsolute !== null && existsSync(resultAbsolute);
	const resultFile = resultFileExists ? readResultFile(resultAbsolute) : null;
	const artifact_sha256 = declaredArtifactDigest(gateEntry, root);
	const bindingFailures = resultFileExists
		? resultBindingFailures({
				gateEntry,
				resultFile,
				logBytes,
				artifact_sha256,
				commit_sha,
				candidate_digest: digest,
			})
		: [];
	const trustedResultFile = resultFile !== null && bindingFailures.length === 0 ? resultFile : null;
	const { exit_code, basis, marker } = deriveExit(gateEntry, logText, trustedResultFile, resultFileExists, bindingFailures);
	const status = statusFor(exit_code, logExists, resultFileExists);

	let started_at_utc = UNKNOWN;
	let ended_at_utc = UNKNOWN;
	let duration_ms = UNKNOWN;
	if (trustedResultFile && typeof trustedResultFile.started_at_utc === "string" && typeof trustedResultFile.ended_at_utc === "string") {
		started_at_utc = isoUtc(trustedResultFile.started_at_utc);
		ended_at_utc = isoUtc(trustedResultFile.ended_at_utc);
		duration_ms = Number.isFinite(trustedResultFile.duration_ms) && trustedResultFile.duration_ms >= 0 ? trustedResultFile.duration_ms : UNKNOWN;
	} else if (logText !== null) {
		const start = START_MARKER.exec(logText);
		if (start) {
			const started = new Date(start[1]);
			const ended = statSync(logAbsolute).mtime;
			if (!Number.isNaN(started.getTime())) {
				started_at_utc = started.toISOString();
				ended_at_utc = ended.toISOString();
				duration_ms = Math.max(0, ended.getTime() - started.getTime());
			}
		}
	}

	const test_counts = logText === null ? UNKNOWN : parseTestCounts(gateEntry.counts, logText);

	const observed_effect = describeEffect({
		gateEntry,
		logExists,
		logRelative,
		logText,
		basis,
		marker,
		status,
		exit_code,
		counts: test_counts,
		resultRelative,
		resultFileExists,
		bindingFailures,
	});

	const substantiated = logExists || trustedResultFile !== null ? gateEntry.evidence_level : EVIDENCE_LEVEL_FLOOR;
	const evidence_level = failClosedEvidenceLevel(substantiated, gateEntry.evidence_level_ceiling);

	return {
		gate_id: gateEntry.gate_id,
		task_ids: [...gateEntry.task_ids],
		feature_ids: [...gateEntry.feature_ids],
		status,
		command: gateEntry.command,
		exit_code,
		started_at_utc,
		ended_at_utc,
		duration_ms,
		commit_sha,
		candidate_digest: digest,
		environment: { ...environment },
		tool_versions: { ...tool_versions },
		test_counts,
		observed_effect,
		log_sha256: logBytes === null ? UNKNOWN : logBytes.sha256,
		artifact_sha256,
		limitations: buildLimitations({
			gateEntry,
			logRelative,
			resultRelative,
			logExists,
			resultFileExists,
			hasTrustedResult: trustedResultFile !== null,
			bindingFailures,
			basis,
			status,
			commit_sha,
			digest,
			siblings: siblingLogFiles(gateEntry, root),
		}),
		owner: gateEntry.owner,
		evidence_level,
		evidence_level_ceiling: gateEntry.evidence_level_ceiling,
	};
}

function describeEffect({
	gateEntry,
	logExists,
	logRelative,
	logText,
	basis,
	marker,
	status,
	exit_code,
	counts,
	resultRelative,
	resultFileExists,
	bindingFailures,
}) {
	if (!logExists && basis === "result_file") {
		return `Machine-readable result file recorded exit_code=${exit_code} for: ${gateEntry.command}; no log exists at ${logRelative}, so no log content was inspected.`;
	}
	if (!logExists) {
		const resultNote = resultRelative === null
			? ""
			: resultFileExists
				? `, but its result file at ${resultRelative} was ignored as stale or unprovable (${clip(bindingFailures.join("; "))})`
				: ` and no result file at ${resultRelative}`;
		return `none observed: no log at ${logRelative}${resultNote}, so this gate produced no evidence for this candidate (status ${status}, exit_code ${exit_code}).`;
	}
	const parts = [];
	if (basis === "result_file") {
		parts.push(`Machine-readable result file recorded exit_code=${exit_code} for: ${gateEntry.command}`);
	} else if (basis === "log_marker") {
		parts.push(`Terminal log marker for exit_code=${exit_code}: ${clip(marker ?? "")}`);
	} else if (basis === "pnpm_lifecycle") {
		parts.push(`pnpm reported the failing command's own exit status, so exit_code=${exit_code}: ${clip(marker ?? "")}`);
	} else if (basis === "stale_result") {
		parts.push(`A result file was ignored as stale or unprovable (${clip(bindingFailures.join("; "))}); no PASS was derived from the log.`);
	} else {
		parts.push(`No decisive terminal marker was found for exit_code; status is ${status} (fail closed).`);
	}
	if (counts !== UNKNOWN) {
		parts.push(`Parsed test counts: ${JSON.stringify(counts)}.`);
	}
	parts.push(`Last non-empty log line: ${clip(lastNonEmptyLine(logText ?? ""))}`);
	return parts.join(" ");
}

function buildLimitations({
	gateEntry,
	logRelative,
	resultRelative,
	logExists,
	resultFileExists,
	hasTrustedResult,
	bindingFailures,
	basis,
	status,
	commit_sha,
	digest,
	siblings,
}) {
	const limitations = [...gateEntry.limitations];
	if (!logExists && !resultFileExists) {
		limitations.push(
			`Declared gate has no log at ${logRelative} and no result file at ${resultRelative}; status=NOT_RUN and exit_code=unknown are the honest recorded result.`,
		);
		limitations.push(
			"evidence_level is the vocabulary floor because no evidence was substantiated for this gate; it is not a claim that source inspection happened.",
		);
	} else if (resultFileExists && !hasTrustedResult) {
		limitations.push(
			`The machine-readable result file ${resultRelative} was ignored because it is stale or unprovable: ${clip(bindingFailures.join("; "))}. It cannot supply an exit code or timing.`,
		);
	} else if (!logExists && hasTrustedResult) {
		limitations.push(
			`A machine-readable result file exists at ${resultRelative} but the log ${logRelative} is missing, so log_sha256 is unknown and no log content could be inspected.`,
		);
	} else if (basis === "result_file") {
		limitations.push(
			`exit_code and timing were read from the machine-readable result file ${resultRelative}; its source commit, candidate digest, log digest and declared-artifact digest match this index context.`,
		);
	} else if (basis === "log_marker") {
		limitations.push(
			"exit_code and status were derived from the gate's own decisive terminal log marker; no current, provenance-bound result file supplied an exit status.",
		);
	} else if (basis === "pnpm_lifecycle") {
		limitations.push(
			"exit_code was taken from pnpm's own lifecycle report of the failing command's exit status; it is a failure signal only and can never produce a PASS.",
		);
	} else if (basis === "stale_result") {
		limitations.push(
			"The result sidecar was present but not current; the generator refused to infer PASS from a stale or unprovable result and recorded unknown (fail closed).",
		);
	} else {
		limitations.push(
			"A log exists but no machine-readable result file and no decisive terminal marker were found, so exit_code and status are 'unknown' (fail closed).",
		);
	}
	if (basis !== "result_file") {
		limitations.push(
			`The log does not embed a commit SHA or candidate digest, so its correspondence to commit ${commit_sha} and candidate digest ${digest} is not proven.`,
		);
	}
	limitations.push(
		"environment and tool_versions describe the host that generated this index, not necessarily the host that produced this log; see environment.gate_host_provenance.",
	);
	limitations.push(
		"task_ids and feature_ids are gate-level bindings declared in scripts/generate-v8-evidence-index.mjs from the verification steps and related-feature lines of docs/production-readiness/next-agent-execution-prompt-v8.md; they are not per-artifact proof.",
	);
	limitations.push(
		"owner is a declared accountability role for the gate, not a named individual attestation.",
	);
	if (siblings.length > 0) {
		limitations.push(
			`Other files for the same gate number exist under ${LOG_DIR} but are not this gate's declared log and are not consumed by this record: ${siblings.join(", ")}. Re-run the gate with \`--run ${gateEntry.gate_id}\` to write ${gateEntry.log} plus its machine-readable result file.`,
		);
	}
	if (status === STATUS_NOT_RUN) {
		limitations.push("This gate must be run before it can support any release claim.");
	}
	if (status !== STATUS_PASS) {
		limitations.push(
			`evidence_level is the highest level this gate's artefacts substantiate (the vocabulary floor when nothing was substantiated) and evidence_level_ceiling is the most this gate can ever support; status ${status} means no passing evidence at that level may be counted.`,
		);
	}
	return limitations;
}

export function buildEvidenceIndex(options = {}) {
	const root = options.root ?? ROOT;
	const digest = candidateDigest(root);
	const commit_sha = gitCommitSha(root);
	const environment = readEnvironment();
	const tool_versions = readToolVersions();
	const context = { root, commit_sha, candidate_digest: digest.digest, environment, tool_versions };
	const gates = GATES.map((gateEntry) => buildGateRecord(gateEntry, context));

	const status_counts = countStatuses(gates);

	return {
		schema_version: 1,
		generator: GENERATOR_ID,
		generator_version: 1,
		candidate: {
			release_dir: CANDIDATE_RELEASE_DIR,
			digest_source: digest.source,
			digest_source_exists: digest.digest_source_exists,
		},
		commit_sha,
		candidate_digest: digest.digest,
		environment,
		tool_versions,
		evidence_levels: {
			vocabulary: [...EVIDENCE_LEVELS],
			floor: EVIDENCE_LEVEL_FLOOR,
			semantics:
				"Ordered weakest to strongest. evidence_level is the highest level the gate's artefacts substantiate and can never exceed evidence_level_ceiling, which is the most the gate's own command can ever support; a lower level must never stand in for a higher one. Gates with no captured log substantiate nothing and report the vocabulary floor. A level only counts as substantiated evidence when the record's status is PASS; FAIL, NOT_RUN and unknown records keep the level for context but must never be aggregated as evidence at that level.",
		},
		status_vocabulary: [...STATUS_VOCABULARY],
		status_semantics: {
			PASS: "The gate's own exit status is 0.",
			FAIL: "The gate failed with a non-zero exit status.",
			NOT_RUN: "No log and no result file exist; the gate was not run for this candidate.",
			unknown: "Evidence exists but the exit status could not be derived or a result file was stale/unprovable; never read as success.",
		},
		determinism:
			"This index contains no generation timestamp: per-gate timing comes only from captured start markers and log modification times, so repeated runs over unchanged artefacts are byte-identical.",
		methodology:
			"Every field is derived from artefacts on disk: a result file supplies an exit status only when its gate id, command, source commit, candidate digest, log SHA-256 and declared-artifact SHA-256 bind to the current index context; otherwise stale or unprovable result files are ignored and a PASS marker is never inferred from that log. Without a trusted result file, exit status comes from a decisive terminal log marker, timing from a captured start marker plus the log mtime, digests from SHA-256 of the log and of a declared artifact, and test counts from the log when the format is known. Any value that could not be derived is the explicit string 'unknown' and any gate without a log is reported as NOT_RUN; no gate is ever omitted and no measurement, host, timestamp or customer fact is invented.",
		status_counts,
		gate_count: gates.length,
		gates,
	};
}

export function serializeIndex(index) {
	return `${JSON.stringify(index, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Minimal JSON Schema (2020-12 subset) validator.
// Supports the keywords this index's schema actually uses: type, const, enum,
// pattern, minLength, minimum, minItems, required, properties,
// additionalProperties:false, items, oneOf, anyOf and local $ref.
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
	if (expected === "number") return actual === "number" || actual === "integer";
	return actual === expected;
}

function resolveRef(ref, rootSchema) {
	if (!ref.startsWith("#/")) throw new Error(`unsupported $ref ${ref}`);
	let node = rootSchema;
	for (const segment of ref.slice(2).split("/")) {
		node = node?.[segment.replace(/~1/g, "/").replace(/~0/g, "~")];
	}
	if (node === undefined) throw new Error(`unresolvable $ref ${ref}`);
	return node;
}

function validateNode(value, schema, rootSchema, path, errors) {
	if (schema.$ref) {
		validateNode(value, resolveRef(schema.$ref, rootSchema), rootSchema, path, errors);
		return;
	}
	if (schema.type && !matchesType(value, schema.type)) {
		errors.push(`${path}: expected type ${schema.type}, got ${typeOf(value)}`);
		return;
	}
	if (schema.const !== undefined && value !== schema.const) {
		errors.push(`${path}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`);
	}
	if (schema.enum && !schema.enum.includes(value)) {
		errors.push(`${path}: value ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
	}
	if (schema.minLength !== undefined && typeof value === "string" && value.length < schema.minLength) {
		errors.push(`${path}: string is shorter than minLength ${schema.minLength}`);
	}
	if (schema.pattern !== undefined && typeof value === "string" && !new RegExp(schema.pattern).test(value)) {
		errors.push(`${path}: value ${JSON.stringify(value)} does not match pattern ${schema.pattern}`);
	}
	if (schema.minimum !== undefined && typeof value === "number" && value < schema.minimum) {
		errors.push(`${path}: value ${value} is below minimum ${schema.minimum}`);
	}
	if (schema.minItems !== undefined && Array.isArray(value) && value.length < schema.minItems) {
		errors.push(`${path}: array has ${value.length} item(s), below minItems ${schema.minItems}`);
	}
	if (schema.oneOf) {
		const matched = schema.oneOf.filter((candidate) => validateCollect(value, candidate, rootSchema, path).length === 0);
		if (matched.length !== 1) {
			errors.push(`${path}: expected exactly one oneOf subschema to match, ${matched.length} matched`);
		}
	}
	if (schema.anyOf) {
		const matched = schema.anyOf.some((candidate) => validateCollect(value, candidate, rootSchema, path).length === 0);
		if (!matched) errors.push(`${path}: no anyOf subschema matched`);
	}
	if (Array.isArray(value) && schema.items) {
		value.forEach((item, index) => validateNode(item, schema.items, rootSchema, `${path}[${index}]`, errors));
	}
	if (typeOf(value) === "object" && (schema.properties || schema.required || schema.additionalProperties !== undefined)) {
		for (const key of schema.required ?? []) {
			if (!Object.hasOwn(value, key)) errors.push(`${path}: missing required property '${key}'`);
		}
		for (const [key, child] of Object.entries(value)) {
			const propertySchema = schema.properties?.[key];
			if (propertySchema) {
				validateNode(child, propertySchema, rootSchema, `${path}.${key}`, errors);
				continue;
			}
			if (schema.additionalProperties === false) {
				errors.push(`${path}: additional property '${key}' is not allowed`);
			} else if (typeof schema.additionalProperties === "object") {
				validateNode(child, schema.additionalProperties, rootSchema, `${path}.${key}`, errors);
			}
		}
	}
}

function validateCollect(value, schema, rootSchema, path) {
	const errors = [];
	validateNode(value, schema, rootSchema, path, errors);
	return errors;
}

export function validateAgainstSchema(value, schema) {
	const errors = [];
	validateNode(value, schema, schema, "$", errors);
	return errors;
}

export function findEmptyStrings(value, path = "$", found = []) {
	if (typeof value === "string") {
		if (value.trim().length === 0) found.push(`${path}: empty string`);
		return found;
	}
	if (Array.isArray(value)) {
		value.forEach((item, index) => findEmptyStrings(item, `${path}[${index}]`, found));
		return found;
	}
	if (value !== null && typeof value === "object") {
		for (const [key, child] of Object.entries(value)) findEmptyStrings(child, `${path}.${key}`, found);
	}
	return found;
}

export function countStatuses(gates) {
	const counts = Object.fromEntries(STATUS_VOCABULARY.map((status) => [status, 0]));
	for (const record of gates) {
		if (record !== null && typeof record === "object" && Object.hasOwn(counts, record.status)) {
			counts[record.status] += 1;
		}
	}
	return counts;
}

export function verifyEvidenceIndex(index, schema) {
	const errors = [];
	errors.push(...validateAgainstSchema(index, schema));
	errors.push(...findEmptyStrings(index).map((entry) => `empty-string value at ${entry}`));

	if (!Array.isArray(index?.gates)) {
		errors.push("$.gates: index has no gates array");
		return { ok: false, errors };
	}
	const seen = new Set();
	for (const [position, record] of index.gates.entries()) {
		const path = `$.gates[${position}]`;
		if (record === null || typeof record !== "object") {
			errors.push(`${path}: record is not an object`);
			continue;
		}
		const gateId = record.gate_id;
		if (typeof gateId !== "string" || gateId.length === 0) {
			errors.push(`${path}: record has no usable gate_id`);
			continue;
		}
		if (seen.has(gateId)) errors.push(`${path}: duplicate gate_id ${gateId}`);
		seen.add(gateId);
		if (record.commit_sha !== index.commit_sha) {
			errors.push(`${path} (${gateId}): commit_sha ${JSON.stringify(record.commit_sha)} does not match index commit_sha ${JSON.stringify(index.commit_sha)}`);
		}
		if (record.candidate_digest !== index.candidate_digest) {
			errors.push(`${path} (${gateId}): candidate_digest ${JSON.stringify(record.candidate_digest)} does not match index candidate_digest ${JSON.stringify(index.candidate_digest)}`);
		}
		if (PASS_LIKE_STATUSES.includes(record.status) && record.exit_code !== 0) {
			errors.push(
				`${path} (${gateId}): status ${record.status} is pass-like but exit_code is ${JSON.stringify(record.exit_code)}`,
			);
		}
		if (record.status === STATUS_NOT_RUN && record.exit_code !== UNKNOWN) {
			errors.push(`${path} (${gateId}): status NOT_RUN must not carry exit_code ${JSON.stringify(record.exit_code)}`);
		}
		if (record.status === STATUS_NOT_RUN && record.log_sha256 !== UNKNOWN) {
			errors.push(`${path} (${gateId}): status NOT_RUN must not carry log_sha256 ${JSON.stringify(record.log_sha256)}`);
		}
		if (isEvidenceLevel(record.evidence_level) && isEvidenceLevel(record.evidence_level_ceiling)) {
			if (levelsAreSubstituted(record.evidence_level_ceiling, record.evidence_level)) {
				errors.push(
					`${path} (${gateId}): evidence_level ${record.evidence_level} exceeds its ceiling ${record.evidence_level_ceiling}`,
				);
			}
		}
	}
	const declared = GATES.map((entry) => entry.gate_id);
	for (const gateId of declared) {
		if (!seen.has(gateId)) errors.push(`$.gates: declared gate ${gateId} is missing from the index`);
	}
	// The summary must not be able to disagree with the records it summarises.
	if (index.gate_count !== index.gates.length) {
		errors.push(`$.gate_count: ${JSON.stringify(index.gate_count)} does not match ${index.gates.length} record(s)`);
	}
	const recomputed = countStatuses(index.gates);
	if (JSON.stringify(recomputed) !== JSON.stringify(index.status_counts)) {
		errors.push(
			`$.status_counts: ${JSON.stringify(index.status_counts)} does not match the records ${JSON.stringify(recomputed)}`,
		);
	}
	return { ok: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// Result-file capture (`--run` / `--record`)
// ---------------------------------------------------------------------------

function resultFilePath(gateId) {
	const gateEntry = GATES.find((entry) => entry.gate_id === gateId);
	if (!gateEntry) throw new Error(`unknown gate_id: ${gateId}`);
	return { gateEntry, absolute: resolve(ROOT, `${LOG_DIR}/${gateEntry.log}`) };
}

export function resultProvenance(gateEntry, root = ROOT, logAbsolute = null) {
	const commit = gitCommitSha(root);
	const candidate = candidateDigest(root);
	return {
		provenance_version: RESULT_PROVENANCE_VERSION,
		commit_sha: commit,
		source_commit: commit,
		candidate_digest: candidate.digest,
		candidate_digest_source: candidate.source,
		log_sha256: logAbsolute !== null && existsSync(logAbsolute) ? sha256File(logAbsolute) : UNKNOWN,
		artifact_sha256: declaredArtifactDigest(gateEntry, root),
	};
}

export function writeResultFile({ gateEntry, absolute }, payload, { root = ROOT } = {}) {
	const body = {
		gate_id: gateEntry.gate_id,
		command: gateEntry.command,
		recorded_by: GENERATOR_ID,
		...payload,
		// These bindings are derived at write time and deliberately override any
		// caller-supplied copies. A result file must not be able to self-assert a
		// different source, candidate, log or declared-artifact identity.
		...resultProvenance(gateEntry, root, absolute),
	};
	writeFileSync(`${absolute}.result.json`, `${JSON.stringify(body, null, 2)}\n`);
	return body;
}

/**
 * Expand `${NAME:-default}` in a declared gate command.
 *
 * A gate whose interpreter must be pinned (the Python suites need an isolated
 * venv built from `requirements-test.txt`) declares the variable and a
 * documented default. The default keeps CI behaviour unchanged; an operator
 * points it at the pinned environment. The substitution is applied here so the
 * command actually executed is the one recorded in the log header.
 */
export function expandGateCommand(command, env = process.env) {
	return command.replace(/\$\{([A-Z][A-Z0-9_]*):-([^}]*)\}/g, (_match, name, fallback) => {
		const value = String(env[name] ?? "").trim();
		return value || fallback;
	});
}

function runGate(gateId) {
	const target = resultFilePath(gateId);
	if (target.gateEntry.command === UNKNOWN) {
		throw new Error(`${gateId} declares no command; declare one before running it`);
	}
	const command = expandGateCommand(target.gateEntry.command);
	const started = new Date();
	// The index trusts the captured result file, not this timeout; the hour cap
	// exists only so a hung gate cannot block the capture forever.
	const result = spawnSync(command, {
		cwd: ROOT,
		encoding: "utf8",
		shell: true,
		timeout: 60 * 60 * 1000,
		maxBuffer: 64 * 1024 * 1024,
	});
	const ended = new Date();
	const exitCode = Number.isInteger(result.status) ? result.status : 1;
	mkdirSync(dirname(target.absolute), { recursive: true });
	const log = [
		`[aidr-gate] started_at_utc=${started.toISOString()} command=${command}`,
		"",
		result.stdout ?? "",
		result.stderr ?? "",
		`[aidr-gate] ended_at_utc=${ended.toISOString()} exit_code=${exitCode}`,
		"",
	].join("\n");
	writeFileSync(target.absolute, log);
	const payload = {
		exit_code: exitCode,
		started_at_utc: started.toISOString(),
		ended_at_utc: ended.toISOString(),
		duration_ms: ended.getTime() - started.getTime(),
		log_path: `${LOG_DIR}/${target.gateEntry.log}`,
		log_sha256: sha256File(target.absolute),
		captured_by: "run",
	};
	writeResultFile(target, payload);
	return { gate_id: gateId, ...payload };
}

function recordGate(gateId, options) {
	const target = resultFilePath(gateId);
	const exitCode = Number(options["exit-code"]);
	if (!Number.isInteger(exitCode)) throw new Error("--record requires an integer --exit-code");
	mkdirSync(dirname(target.absolute), { recursive: true });
	const log = `${LOG_DIR}/${target.gateEntry.log}`;
	const absoluteLog = target.absolute;
	const started = options["started-at"] ? new Date(options["started-at"]) : null;
	let duration = UNKNOWN;
	let ended = options["ended-at"] ? isoUtc(options["ended-at"]) : null;
	if (existsSync(absoluteLog)) {
		const text = readLogFile(absoluteLog).text;
		const marker = START_MARKER.exec(text);
		if (!started && marker) options["started-at"] = marker[1];
		if (!ended) ended = statSync(absoluteLog).mtime.toISOString();
	}
	const startedIso = options["started-at"] ? isoUtc(options["started-at"]) : UNKNOWN;
	if (startedIso !== UNKNOWN && ended !== null && ended !== UNKNOWN) {
		duration = Math.max(0, new Date(ended).getTime() - new Date(startedIso).getTime());
	}
	return writeResultFile(target, {
		exit_code: exitCode,
		started_at_utc: startedIso,
		ended_at_utc: ended ?? UNKNOWN,
		duration_ms: duration,
		log_path: existsSync(absoluteLog) ? log : UNKNOWN,
		log_sha256: existsSync(absoluteLog) ? sha256File(absoluteLog) : UNKNOWN,
		captured_by: "record",
	});
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
	const options = {};
	const positional = [];
	for (let index = 0; index < argv.length; index += 1) {
		const arg = argv[index];
		if (arg.startsWith("--")) {
			const [key, inline] = arg.slice(2).split("=");
			if (inline !== undefined) {
				options[key] = inline;
			} else if (["verify", "help", "json"].includes(key)) {
				options[key] = true;
			} else {
				options[key] = argv[index + 1];
				index += 1;
			}
			continue;
		}
		positional.push(arg);
	}
	return { options, positional };
}

function usage() {
	return [
		"Usage:",
		"  node scripts/generate-v8-evidence-index.mjs [--out <path>]",
		"  node scripts/generate-v8-evidence-index.mjs --verify [--index <path>] [--schema <path>]",
		"  node scripts/generate-v8-evidence-index.mjs --run <gate_id>",
		"  node scripts/generate-v8-evidence-index.mjs --record <gate_id> --exit-code <n> [--started-at <iso>] [--ended-at <iso>]",
		"",
		"Declared gates:",
		...GATES.map((entry) => `  ${entry.gate_id.padEnd(34)} ${entry.command}`),
	].join("\n");
}

function main(argv) {
	const { options, positional } = parseArgs(argv);
	const indexFile = options.index ?? INDEX_FILE;
	const schemaFile = options.schema ?? SCHEMA_FILE;

	if (options.help) {
		console.log(usage());
		return 0;
	}
	if (options.verify) {
		const schema = JSON.parse(readFileSync(resolve(ROOT, schemaFile), "utf8"));
		const index = JSON.parse(readFileSync(resolve(ROOT, indexFile), "utf8"));
		const { ok, errors } = verifyEvidenceIndex(index, schema);
		if (ok) {
			console.log(`${indexFile}: ${index.gates.length} gate record(s) validated against ${schemaFile}.`);
			console.log(`status counts: ${JSON.stringify(index.status_counts)}`);
			return 0;
		}
		console.error(`${indexFile}: ${errors.length} validation error(s)`);
		for (const error of errors) console.error(`- ${error}`);
		return 1;
	}
	const gateId = options.run ?? options.record ?? positional[0];
	if (options.run) {
		const result = runGate(gateId);
		console.log(`Captured ${result.gate_id}: exit_code=${result.exit_code}, log_sha256=${result.log_sha256}`);
		return 0;
	}
	if (options.record) {
		const result = recordGate(gateId, options);
		console.log(`Recorded ${result.gate_id}: exit_code=${result.exit_code}, log_sha256=${result.log_sha256}`);
		return 0;
	}

	const index = buildEvidenceIndex();
	const output = resolve(ROOT, options.out ?? INDEX_FILE);
	mkdirSync(dirname(output), { recursive: true });
	const serialized = serializeIndex(index);
	writeFileSync(output, serialized);
	console.log(`Wrote ${options.out ?? INDEX_FILE} (${index.gate_count} gates, sha256=${sha256Hex(serialized)})`);
	console.log(`status counts: ${JSON.stringify(index.status_counts)}`);
	return 0;
}

const invokedDirectly =
	process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
	try {
		process.exitCode = main(process.argv.slice(2));
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
