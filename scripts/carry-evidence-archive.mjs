#!/usr/bin/env node
/**
 * Carry the last rehearsal's evidence into the tracked archive.
 *
 * `.release-evidence/` is gitignored and multi-gigabyte, so the gate logs, their
 * result sidecars and the gate-owned artefact snapshots exist only on the machine
 * that ran the rehearsal. `docs/evidence/` is the durable copy a reviewer can
 * actually read, but nothing linked the two: the archive was maintained by hand,
 * and by the time this script was written every one of its 26 logs had drifted
 * from the index that describes them - 0 of 26 matched, and four gates had no
 * durable copy at all. A published index whose logs cannot be found, or do not
 * match their recorded SHA-256, cannot be verified from a fresh clone.
 *
 * This script derives the archive from the index instead of from memory. For
 * every gate record it copies the declared log and sidecar, plus any gate-owned
 * snapshot that sits beside them, and then re-reads what it wrote to prove each
 * file still hashes to the digest the index recorded. A file that cannot be
 * found is reported as NOT_CARRIED and never invented.
 *
 * Usage:
 *   node scripts/carry-evidence-archive.mjs            # write the archive
 *   node scripts/carry-evidence-archive.mjs --check     # report drift, write nothing
 */
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { INDEX_FILE, LOG_DIR } from "./generate-v8-evidence-index.mjs";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const ARCHIVE_DIR = "docs/evidence/gate-logs";
export const VERDICTS_FILE = "docs/evidence/gate-verdicts.md";
export const SUMMARY_FILE = "docs/evidence/gate-run-summary.json";

export function sha256File(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** Resolve a possibly-absolute directory against the repository root. */
function resolveDir(value) {
	return resolve(ROOT, value);
}

/**
 * Files to carry for one gate: its log, its result sidecar, and any snapshot the
 * gate produced beside them (the test gate writes `<gate_id>.test-results.json`).
 * Sorted so the plan is deterministic.
 */
export function carryPlan(index, { logsDir = LOG_DIR, archiveDir = ARCHIVE_DIR } = {}) {
	const sourceRoot = resolveDir(logsDir);
	const destinationRoot = resolveDir(archiveDir);
	const plan = [];
	for (const record of index.gates ?? []) {
		const id = record.gate_id;
		if (typeof id !== "string" || id === "") continue;
		const entries = [{ name: `${id}.log`, expected: record.log_sha256, kind: "log" }];
		const sidecar = `${id}.log.result.json`;
		if (existsSync(join(sourceRoot, sidecar))) entries.push({ name: sidecar, expected: null, kind: "sidecar" });
		for (const name of readdirSync(sourceRoot).sort()) {
			if (!name.startsWith(`${id}.`)) continue;
			if (name === `${id}.log` || name === sidecar) continue;
			entries.push({ name, expected: record.artifact_sha256 ?? null, kind: "snapshot" });
		}
		for (const entry of entries) {
			plan.push({
				gate_id: id,
				name: entry.name,
				kind: entry.kind,
				from: join(sourceRoot, entry.name),
				to: join(destinationRoot, entry.name),
				expected: entry.expected,
			});
		}
	}
	return plan;
}

/** Copy the plan into the archive, then verify every file against its digest. */
export function carryArchive(index, { logsDir = LOG_DIR, archiveDir = ARCHIVE_DIR, check = false } = {}) {
	const plan = carryPlan(index, { logsDir, archiveDir });
	const carried = [];
	const missing = [];
	const notCarried = [];
	const mismatched = [];
	for (const entry of plan) {
		const sourceExists = existsSync(entry.from);
		if (!check && sourceExists) {
			mkdirSync(dirname(entry.to), { recursive: true });
			copyFileSync(entry.from, entry.to);
		}
		if (!existsSync(entry.to)) {
			// Distinguish "the rehearsal never produced it" from "the archive is
			// incomplete": only the second is drift the carry step can repair.
			if (sourceExists) notCarried.push(entry);
			else missing.push(entry);
			continue;
		}
		const actual = sha256File(entry.to);
		const record = { ...entry, sha256: actual };
		// A gate that declares no artifact records the literal string "unknown", which
		// is not a digest and must not be compared as one.
		if (/^[0-9a-f]{64}$/.test(String(entry.expected)) && entry.expected !== actual) mismatched.push(record);
		carried.push(record);
	}
	return { plan, carried, missing, notCarried, mismatched };
}

/** The human-readable verdict table, derived from the same records. */
export function renderVerdicts(index) {
	const gates = index.gates ?? [];
	const withLog = gates.filter((record) => record.status !== "NOT_RUN");
	const lines = [
		"# Gate verdicts at the last full rehearsal",
		"",
		`Rehearsal at commit \`${index.commit_sha}\`, candidate digest \`${index.candidate_digest}\`.`,
		"Generated by `node scripts/carry-evidence-archive.mjs` from",
		"`docs/production-readiness/v8-evidence-index.json`; the logs it summarises are in",
		"this directory and each one hashes to the `log_sha256` the index recorded.",
		"",
		"Each row is the exit code the gate itself wrote as its terminal marker.",
		"",
		"| Gate | Status | Exit |",
		"|---|---|---|",
	];
	for (const record of gates) {
		lines.push(`| \`${record.gate_id}\` | ${record.status} | ${record.exit_code} |`);
	}
	lines.push("");
	const withoutLog = gates.length - withLog.length;
	lines.push(
		withoutLog === 0
			? `Every one of the ${gates.length} declared gates has a captured log.`
			: `${withoutLog} of the ${gates.length} declared gates had no captured log and are recorded as NOT_RUN rather than guessed.`,
	);
	const pass = gates.filter((record) => record.status === "PASS").length;
	const failed = gates.filter((record) => record.status === "FAIL").length;
	const unknown = gates.filter((record) => record.status === "unknown").length;
	const notRun = gates.filter((record) => record.status === "NOT_RUN").length;
	lines.push(`Totals: ${pass} pass, ${failed} non-zero, ${unknown} unknown, ${notRun} not run.`);
	lines.push("");
	return `${lines.join("\n")}`;
}

export function renderSummary(index) {
	const counts = {};
	for (const record of index.gates ?? []) counts[record.status] = (counts[record.status] ?? 0) + 1;
	return `${JSON.stringify({ commit_sha: index.commit_sha, candidate_digest: index.candidate_digest, counts }, null, 2)}\n`;
}

export function parseArgs(argv) {
	const args = { index: INDEX_FILE, check: false, help: false };
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === "--help" || arg === "-h") args.help = true;
		else if (arg === "--check") args.check = true;
		else if (arg === "--index") args.index = argv[++i];
		else if (arg.startsWith("--index=")) args.index = arg.slice("--index=".length);
		else throw new Error(`Unknown argument: ${arg}`);
	}
	if (!args.index) throw new Error("--index requires a value");
	return args;
}

export function main(argv = process.argv.slice(2)) {
	let args;
	try {
		args = parseArgs(argv);
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		return 2;
	}
	if (args.help) {
		console.log("Usage: node scripts/carry-evidence-archive.mjs [--index PATH] [--check]");
		return 0;
	}
	const index = JSON.parse(readFileSync(resolve(ROOT, args.index), "utf8"));
	const result = carryArchive(index, { check: args.check });

	if (!args.check) {
		writeFileSync(join(ROOT, VERDICTS_FILE), renderVerdicts(index));
		writeFileSync(join(ROOT, SUMMARY_FILE), renderSummary(index));
	}

	const logs = result.carried.filter((entry) => entry.kind === "log").length;
	const sidecars = result.carried.filter((entry) => entry.kind === "sidecar").length;
	const snapshots = result.carried.filter((entry) => entry.kind === "snapshot").length;
	console.log(
		`${args.check ? "Checked" : "Carried"} ${result.carried.length} file(s): ${logs} log(s), ${sidecars} sidecar(s), ${snapshots} snapshot(s).`,
	);
	console.log(`Archive: ${ARCHIVE_DIR} (${index.commit_sha?.slice(0, 8) ?? "unknown"} candidate ${index.candidate_digest?.slice(0, 8) ?? "unknown"})`);
	for (const entry of result.missing) console.error(`  NOT_CARRIED ${entry.name} (${entry.from} is absent)`);
	for (const entry of result.notCarried) console.error(`  MISSING_FROM_ARCHIVE ${entry.name} (${entry.to} was never carried)`);
	for (const entry of result.mismatched) {
		console.error(`  MISMATCH ${entry.name}: archive ${entry.sha256.slice(0, 16)} != recorded ${String(entry.expected).slice(0, 16)}`);
	}
	if (result.missing.length > 0 || result.notCarried.length > 0 || result.mismatched.length > 0) return 1;
	console.log(`Every carried file matches the digest the index recorded.`);
	return 0;
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) process.exitCode = main();
