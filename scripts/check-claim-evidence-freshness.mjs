#!/usr/bin/env node

/**
 * Claim-evidence freshness gate.
 *
 * docs/scripts/claim-check.mjs records the digest of the registry it scanned as
 * `registrySha256`, the source commit as `source_commit`, and the release
 * candidate inventory digest as `candidate_digest` in every JSON artifact it
 * writes. A recorded value that no longer matches the current registry, source
 * commit or candidate inventory proves the scan behind the claim inventory is
 * stale: the artifact still looks like evidence while describing an older
 * checkout or release candidate. This gate compares every top-level
 * `.release-evidence/*claim*.json` record against all three current bindings and
 * fails closed on a mismatch, on a missing or malformed binding, and on an
 * unreadable record.
 *
 * `.release-evidence/` is gitignored and only exists after the release gates
 * have been run locally. A checkout with no such directory has no recorded scan
 * to contradict the current registry, so this gate exits 0 there; that is not a
 * statement that any claim is approved. Refresh a stale record by re-running the
 * recording command, never by editing a digest:
 *
 *   node docs/scripts/claim-check.mjs --mode=gate --json > .release-evidence/<name>.json
 *   node docs/scripts/claim-check.mjs --mode=inventory --json > .release-evidence/<name>.json
 *
 * Usage:
 *   node scripts/check-claim-evidence-freshness.mjs
 *   node scripts/check-claim-evidence-freshness.mjs --evidence-dir .release-evidence --registry docs/production-readiness/commercial-go-evidence-registry.json
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CANDIDATE_DIGEST_SOURCE, candidateDigest, gitCommitSha } from "./generate-v8-evidence-index.mjs";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REGISTRY_FILE = "docs/production-readiness/commercial-go-evidence-registry.json";
export const EVIDENCE_DIR = ".release-evidence";
export const CLAIM_EVIDENCE_FILE = /claim[^/\\]*\.json$/i;

export function sha256File(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** Claim scan records directly inside the evidence directory, sorted by name. */
export function listClaimEvidenceFiles(evidenceDir) {
	if (!existsSync(evidenceDir) || !statSync(evidenceDir).isDirectory()) return [];
	return readdirSync(evidenceDir)
		.filter((name) => CLAIM_EVIDENCE_FILE.test(name))
		.filter((name) => statSync(join(evidenceDir, name)).isFile())
		.sort();
}

/**
 * Compare every recorded claim scan with the current registry and release
 * provenance tuple. Returns { failures, registrySha256, source_commit,
 * candidate_digest, candidate_digest_source, checked }; failures is empty when
 * there is no evidence directory or every record is current and bound.
 *
 * `source_commit` and `candidate` are injectable for deterministic fixtures;
 * normal callers use the current git checkout and candidate inventory on disk.
 */
export function checkClaimEvidenceFreshness({
	root = ROOT,
	evidenceDir = EVIDENCE_DIR,
	registryPath = REGISTRY_FILE,
	source_commit: sourceCommitOverride,
	candidate: candidateOverride,
} = {}) {
	const failures = [];
	const registryFullPath = isAbsolute(registryPath) ? registryPath : resolve(root, registryPath);
	if (!existsSync(registryFullPath) || !statSync(registryFullPath).isFile()) {
		return {
			failures: [`claim registry is missing: ${registryPath}`],
			registrySha256: null,
			source_commit: sourceCommitOverride ?? null,
			candidate_digest: candidateOverride?.digest ?? null,
			candidate_digest_source: candidateOverride?.source ?? CANDIDATE_DIGEST_SOURCE,
			checked: [],
		};
	}
	const registrySha256 = sha256File(registryFullPath);
	const sourceCommit = sourceCommitOverride ?? gitCommitSha(root);
	const candidate = candidateOverride ?? candidateDigest(root);
	const evidenceFullPath = isAbsolute(evidenceDir) ? evidenceDir : resolve(root, evidenceDir);
	const checked = [];
	for (const name of listClaimEvidenceFiles(evidenceFullPath)) {
		let record;
		try {
			record = JSON.parse(readFileSync(join(evidenceFullPath, name), "utf8"));
		} catch (error) {
			failures.push(`${name}: cannot parse the recorded claim scan (${error instanceof Error ? error.message : String(error)})`);
			checked.push({ file: name, registrySha256: null, source_commit: null, candidate_digest: null });
			continue;
		}
		const recordedRegistry = typeof record?.registrySha256 === "string" ? record.registrySha256.trim().toLowerCase() : "";
		const recordedCommitValue = record?.source_commit ?? record?.sourceCommit ?? record?.commit_sha;
		const recordedCommit = typeof recordedCommitValue === "string" ? recordedCommitValue.trim().toLowerCase() : "";
		const recordedCandidateValue = record?.candidate_digest ?? record?.candidateDigest;
		const recordedCandidate = typeof recordedCandidateValue === "string" ? recordedCandidateValue.trim().toLowerCase() : "";
		const recordedCandidateSourceValue = record?.candidate_digest_source ?? record?.candidateDigestSource;
		const recordedCandidateSource = typeof recordedCandidateSourceValue === "string" ? recordedCandidateSourceValue.trim() : "";
		checked.push({
			file: name,
			registrySha256: recordedRegistry || null,
			source_commit: recordedCommit || null,
			candidate_digest: recordedCandidate || null,
		});
		if (!/^[0-9a-f]{64}$/.test(recordedRegistry)) {
			failures.push(`${name}: recorded claim scan has no valid registrySha256 digest to prove freshness`);
		} else if (recordedRegistry !== registrySha256) {
			failures.push(`${name}: recorded registrySha256 ${recordedRegistry} does not match the current registry digest ${registrySha256}`);
		}
		if (!/^[0-9a-f]{40}$/.test(sourceCommit)) {
			failures.push(`${name}: current source commit is unavailable, so claim freshness cannot be proven`);
		} else if (!/^[0-9a-f]{40}$/.test(recordedCommit)) {
			failures.push(`${name}: recorded claim scan has no valid source_commit binding to prove freshness`);
		} else if (recordedCommit !== sourceCommit) {
			failures.push(`${name}: recorded source_commit ${recordedCommit} does not match the current source commit ${sourceCommit}`);
		}
		if (!/^[0-9a-f]{64}$/.test(candidate.digest)) {
			failures.push(`${name}: current candidate artifact digest is unavailable, so claim freshness cannot be proven`);
		} else if (!/^[0-9a-f]{64}$/.test(recordedCandidate)) {
			failures.push(`${name}: recorded claim scan has no valid candidate_digest binding to prove freshness`);
		} else if (recordedCandidate !== candidate.digest) {
			failures.push(`${name}: recorded candidate_digest ${recordedCandidate} does not match the current candidate digest ${candidate.digest}`);
		}
		if (!recordedCandidateSource) {
			failures.push(`${name}: recorded claim scan has no candidate_digest_source binding to prove which artifact was scanned`);
		} else if (recordedCandidateSource !== candidate.source) {
			failures.push(`${name}: recorded candidate_digest_source ${recordedCandidateSource} does not match the current source ${candidate.source}`);
		}
	}
	return {
		failures,
		registrySha256,
		source_commit: sourceCommit,
		candidate_digest: candidate.digest,
		candidate_digest_source: candidate.source,
		checked,
	};
}

export function parseArgs(argv) {
	const args = { evidenceDir: EVIDENCE_DIR, registryPath: REGISTRY_FILE, help: false };
	for (let index = 0; index < argv.length; index += 1) {
		const arg = argv[index];
		if (arg === "--help" || arg === "-h") {
			args.help = true;
			continue;
		}
		if (arg === "--evidence-dir") {
			args.evidenceDir = argv[++index];
			continue;
		}
		if (arg.startsWith("--evidence-dir=")) {
			args.evidenceDir = arg.slice("--evidence-dir=".length);
			continue;
		}
		if (arg === "--registry") {
			args.registryPath = argv[++index];
			continue;
		}
		if (arg.startsWith("--registry=")) {
			args.registryPath = arg.slice("--registry=".length);
			continue;
		}
		throw new Error(`Unknown argument: ${arg}`);
	}
	if (!args.evidenceDir || !args.registryPath) throw new Error("--evidence-dir and --registry require a value");
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
		console.log("Usage: node scripts/check-claim-evidence-freshness.mjs [--evidence-dir DIR] [--registry PATH]");
		return 0;
	}
	const {
		failures,
		registrySha256,
		source_commit: resultSourceCommit,
		candidate_digest: resultCandidateDigest,
		candidate_digest_source: resultCandidateSource,
		checked,
	} = checkClaimEvidenceFreshness({ evidenceDir: args.evidenceDir, registryPath: args.registryPath });
	console.log(`Claim evidence freshness: ${failures.length === 0 ? "PASS" : "FAIL"}`);
	console.log(`Registry digest: ${registrySha256 ?? "unavailable"}`);
	console.log(`Source commit: ${resultSourceCommit ?? "unavailable"}`);
	console.log(`Candidate digest: ${resultCandidateDigest ?? "unavailable"} (${resultCandidateSource ?? "unavailable"})`);
	console.log(`Recorded claim scans compared: ${checked.length}`);
	for (const record of checked) {
		console.log(`- ${record.file}: registry=${record.registrySha256 ?? "no digest"}, source=${record.source_commit ?? "no commit"}, candidate=${record.candidate_digest ?? "no digest"}`);
	}
	if (failures.length > 0) {
		console.error(`${failures.length} stale or unprovable claim scan record(s):`);
		for (const failure of failures) console.error(`- ${failure}`);
	}
	return failures.length === 0 ? 0 : 1;
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
	try {
		process.exitCode = main();
	} catch (error) {
		console.error(`Claim evidence freshness error: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 2;
	}
}
