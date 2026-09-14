#!/usr/bin/env node

/**
 * Claim-evidence freshness gate.
 *
 * docs/scripts/claim-check.mjs records the digest of the registry it scanned as
 * `registrySha256` in every JSON artifact it writes. A recorded digest that no
 * longer matches the current registry proves the scan behind the claim
 * inventory is stale: the artifact still looks like evidence while describing a
 * registry revision that has since changed. This gate compares every top-level
 * `.release-evidence/*claim*.json` record against the current registry digest
 * and fails closed on a mismatch, on a missing or malformed digest, and on an
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
 * Compare every recorded claim scan digest with the current registry digest.
 * Returns { failures, registrySha256, checked }; failures is empty when there is
 * no evidence directory or every record is current.
 */
export function checkClaimEvidenceFreshness({ root = ROOT, evidenceDir = EVIDENCE_DIR, registryPath = REGISTRY_FILE } = {}) {
	const failures = [];
	const registryFullPath = isAbsolute(registryPath) ? registryPath : resolve(root, registryPath);
	if (!existsSync(registryFullPath) || !statSync(registryFullPath).isFile()) {
		return { failures: [`claim registry is missing: ${registryPath}`], registrySha256: null, checked: [] };
	}
	const registrySha256 = sha256File(registryFullPath);
	const evidenceFullPath = isAbsolute(evidenceDir) ? evidenceDir : resolve(root, evidenceDir);
	const checked = [];
	for (const name of listClaimEvidenceFiles(evidenceFullPath)) {
		let record;
		try {
			record = JSON.parse(readFileSync(join(evidenceFullPath, name), "utf8"));
		} catch (error) {
			failures.push(`${name}: cannot parse the recorded claim scan (${error instanceof Error ? error.message : String(error)})`);
			checked.push({ file: name, registrySha256: null });
			continue;
		}
		const recorded = typeof record?.registrySha256 === "string" ? record.registrySha256.trim().toLowerCase() : "";
		checked.push({ file: name, registrySha256: recorded || null });
		if (!/^[0-9a-f]{64}$/.test(recorded)) {
			failures.push(`${name}: recorded claim scan has no valid registrySha256 digest to prove freshness`);
			continue;
		}
		if (recorded !== registrySha256) {
			failures.push(`${name}: recorded registrySha256 ${recorded} does not match the current registry digest ${registrySha256}`);
		}
	}
	return { failures, registrySha256, checked };
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
	const { failures, registrySha256, checked } = checkClaimEvidenceFreshness({ evidenceDir: args.evidenceDir, registryPath: args.registryPath });
	console.log(`Claim evidence freshness: ${failures.length === 0 ? "PASS" : "FAIL"}`);
	console.log(`Registry digest: ${registrySha256 ?? "unavailable"}`);
	console.log(`Recorded claim scans compared: ${checked.length}`);
	for (const record of checked) console.log(`- ${record.file}: ${record.registrySha256 ?? "no digest"}`);
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
