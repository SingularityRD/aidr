#!/usr/bin/env node

/**
 * Candidate-bound production GO gate (audit item 14).
 *
 * The release workflows prove that an RC bundle is authentic (attestations,
 * signatures, anti-rollback). None of that says the business may ship it: the
 * commercial evidence registry can say NO-GO, name no candidate, or name a
 * different one. This gate is the missing link and is run, from the immutable
 * trusted verifier checkout, before anything is published or deployed to
 * production. It exits 0 only when ALL of the following hold for the SAME
 * candidate:
 *
 *   1. registry.decision is "GO";
 *   2. registry.releaseCandidate is the SHA-256 of the bundle's
 *      release-inventory.json (the single candidate digest also used by the v8
 *      evidence index, the claim-evidence freshness check and the receipt
 *      verifier; see CANDIDATE_DIGEST_SOURCE), and equals --candidate-digest
 *      when that is given;
 *   3. every hard gate of the release profile (default production-ga) is
 *      closed, and its receipt is closed, bound to that digest and recorded no
 *      earlier than --max-evidence-age-days ago and not in the future;
 *   4. scripts/verify-commercial-gate-receipts.mjs passes for that digest;
 *   5. registry.lastReviewed is within the same freshness window;
 *   6. `node docs/scripts/claim-check.mjs --mode=gate`, bound to the bundle's
 *      inventory, passes and reports the same registry bytes and candidate.
 *
 * Anything else - NO-GO, an empty candidate, a wrong digest, stale or
 * future-dated evidence, an unreadable input - exits 1 (usage errors exit 2).
 *
 * Promotion ledger: with --ledger FILE --record, a passing check appends the
 * candidate (digest, version, git SHA, registry digest) to a ledger that the
 * promote job persists in its protected state artifact. Rollback runs with
 * --rollback --ledger FILE: it does NOT need the current registry to be GO
 * (the registry has usually moved on, or been set to NO-GO because of the bad
 * release) but it only accepts a bundle whose exact candidate passed this gate
 * when it was promoted. A version promoted before the ledger existed is
 * therefore refused - fail closed, roll forward instead.
 *
 * Usage:
 *   node scripts/verify-production-go.mjs --bundle release-output [--candidate-digest <sha256>]
 *     [--profile production-ga] [--root <trusted checkout>] [--max-evidence-age-days 90]
 *     [--ledger <file> --record] [--json]
 *   node scripts/verify-production-go.mjs --rollback --bundle release-output --ledger <file>
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CANDIDATE_DIGEST_SOURCE, gitCommitSha } from "./generate-v8-evidence-index.mjs";
import { REGISTRY_FILE, validateCommercialGateReceipts } from "./verify-commercial-gate-receipts.mjs";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULT_PROFILE = "production-ga";
export const DEFAULT_MAX_EVIDENCE_AGE_DAYS = 90;
export const BUNDLE_INVENTORY = "release-inventory.json";
export const BUNDLE_METADATA = "release-metadata.json";
export const LEDGER_SCHEMA = "aidr-production-go-ledger/v1";
export const CLAIM_CHECK_SCRIPT = "docs/scripts/claim-check.mjs";
const SHA256 = /^[0-9a-f]{64}$/;
const DAY_MS = 86_400_000;

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** The candidate digest of a release bundle: SHA-256 of its release-inventory.json. */
export function bundleCandidate(bundleDir) {
	const inventoryPath = join(bundleDir, BUNDLE_INVENTORY);
	let info;
	try {
		info = lstatSync(inventoryPath);
	} catch {
		throw new Error(`release bundle has no ${BUNDLE_INVENTORY}: ${inventoryPath}`);
	}
	if (!info.isFile()) throw new Error(`${inventoryPath} is not a regular file`);
	const metadataPath = join(bundleDir, BUNDLE_METADATA);
	let metadata = null;
	if (existsSync(metadataPath)) {
		try {
			metadata = JSON.parse(readFileSync(metadataPath, "utf8"));
		} catch {
			throw new Error(`${metadataPath} is not valid JSON`);
		}
	}
	return {
		inventoryPath,
		digest: sha256(readFileSync(inventoryPath)),
		version: typeof metadata?.release_version === "string" ? metadata.release_version : null,
		gitSha: typeof metadata?.git_sha === "string" ? metadata.git_sha : null,
		tag: typeof metadata?.release_tag === "string" ? metadata.release_tag : null,
	};
}

function parseInstant(value) {
	if (typeof value !== "string") return Number.NaN;
	return /^\d{4}-\d{2}-\d{2}$/u.test(value) ? Date.parse(`${value}T00:00:00.000Z`) : Date.parse(value);
}

function freshness(label, value, now, maxAgeDays) {
	const at = parseInstant(value);
	if (!Number.isFinite(at)) return `${label} has no valid date (${JSON.stringify(value)})`;
	if (at > now.getTime()) return `${label} ${value} is in the future`;
	if (now.getTime() - at > maxAgeDays * DAY_MS) return `${label} ${value} is older than ${maxAgeDays} day(s); re-review the evidence for this candidate`;
	return null;
}

/** Run docs/scripts/claim-check.mjs --mode=gate in `root`, bound to the bundle inventory. */
export function runClaimCheckGate({ root, candidateInventoryPath }) {
	const result = spawnSync(process.execPath, [join(root, CLAIM_CHECK_SCRIPT), "--mode=gate", "--json", "--candidate-inventory", candidateInventoryPath], {
		cwd: root,
		encoding: "utf8",
		maxBuffer: 64 * 1024 * 1024,
		timeout: 10 * 60_000,
	});
	let report = null;
	try {
		report = JSON.parse(result.stdout ?? "");
	} catch {}
	return { exitCode: result.status, report, error: result.error?.message ?? (result.stderr || "").trim().split("\n").slice(-3).join(" | ") };
}

/**
 * Evaluate the production GO decision for one candidate. Pure apart from the
 * injectable `claimCheck` and the files the receipt verifier reads under
 * `root`. Returns { go, failures, candidateDigest, profile, gates }.
 */
export function evaluateProductionGo({
	registry,
	registrySha256,
	receipts,
	schema,
	root = ROOT,
	receiptsPath,
	schemaPath,
	bundleInventoryPath,
	candidateDigest,
	expectedCandidateDigest = null,
	profile = DEFAULT_PROFILE,
	now = new Date(),
	maxEvidenceAgeDays = DEFAULT_MAX_EVIDENCE_AGE_DAYS,
	claimCheck = runClaimCheckGate,
}) {
	const failures = [];
	if (!SHA256.test(candidateDigest ?? "")) failures.push(`the release bundle candidate digest is missing or invalid (${JSON.stringify(candidateDigest)})`);
	if (expectedCandidateDigest !== null && expectedCandidateDigest !== candidateDigest) {
		failures.push(`--candidate-digest ${expectedCandidateDigest} is not the bundle's release-inventory digest ${candidateDigest}`);
	}

	// 1-2: the decision and its candidate.
	if (registry?.decision !== "GO") failures.push(`registry decision is ${JSON.stringify(registry?.decision)}, not "GO"`);
	const recorded = registry?.releaseCandidate;
	if (recorded === null || recorded === undefined || recorded === "") {
		failures.push("registry releaseCandidate is empty: no candidate has been approved");
	} else if (typeof recorded !== "string" || !SHA256.test(recorded)) {
		failures.push(`registry releaseCandidate must be the SHA-256 of ${BUNDLE_INVENTORY}, found ${JSON.stringify(recorded)}`);
	} else if (recorded !== candidateDigest) {
		failures.push(`registry releaseCandidate ${recorded} is a different candidate than this bundle (${candidateDigest})`);
	}
	const reviewed = freshness("registry lastReviewed", registry?.lastReviewed, now, maxEvidenceAgeDays);
	if (reviewed) failures.push(reviewed);

	// 3: every hard gate of the profile is closed with a fresh, bound receipt.
	const hardGates = Array.isArray(registry?.hardGates) ? registry.hardGates : [];
	const profileGates = hardGates.filter((gate) => gate?.class === "hard" && Array.isArray(gate.decisionProfiles) && gate.decisionProfiles.includes(profile));
	if (profileGates.length === 0) failures.push(`no hard gate names decision profile ${JSON.stringify(profile)}; refusing to treat an unknown profile as GO`);
	const receiptByGate = new Map((Array.isArray(receipts) ? receipts : []).map((receipt) => [receipt?.gate_id, receipt]));
	for (const gate of profileGates) {
		if (gate.status !== "closed") failures.push(`${gate.id}: hard gate is ${gate.status} for profile ${profile}`);
		const receipt = receiptByGate.get(gate.id);
		if (!receipt) {
			failures.push(`${gate.id}: no receipt`);
			continue;
		}
		if (receipt.decision !== "closed") failures.push(`${gate.id}: receipt decision is ${receipt.decision}`);
		if (receipt.candidate_digest !== candidateDigest) failures.push(`${gate.id}: receipt is bound to candidate ${JSON.stringify(receipt.candidate_digest)}, not ${candidateDigest}`);
		const fresh = freshness(`${gate.id}: receipt recorded_at_utc`, receipt.recorded_at_utc, now, maxEvidenceAgeDays);
		if (fresh) failures.push(fresh);
	}

	// 4: the receipt set as a whole verifies against this exact candidate.
	const receiptResult = validateCommercialGateReceipts({
		registry,
		receipts,
		schema,
		root,
		...(receiptsPath ? { receiptsPath } : {}),
		...(schemaPath ? { schemaPath } : {}),
		releaseInventoryPath: bundleInventoryPath,
		expectedCandidateDigest: candidateDigest,
		now,
	});
	for (const failure of receiptResult.failures) failures.push(`receipts: ${failure}`);

	// 6: the claim gate, bound to the same registry bytes and candidate.
	const claim = claimCheck({ root, candidateInventoryPath: bundleInventoryPath });
	if (claim.exitCode !== 0 || claim.report?.result !== "PASS") {
		const open = (claim.report?.openHardGates ?? []).map((gate) => gate.id);
		failures.push(`claim-check --mode=gate did not pass (exit ${claim.exitCode}${open.length ? `; open hard gates: ${open.join(", ")}` : ""}${claim.report ? "" : `; ${claim.error || "no JSON report"}`})`);
	} else {
		if (claim.report.candidate_digest !== candidateDigest) failures.push(`claim-check scanned candidate ${claim.report.candidate_digest}, not ${candidateDigest}`);
		if (registrySha256 && claim.report.registrySha256 !== registrySha256) failures.push("claim-check read different registry bytes than this gate");
		if (claim.report.decision !== "GO") failures.push(`claim-check reports registry decision ${claim.report.decision}`);
	}

	return { go: failures.length === 0, failures, candidateDigest, profile, gates: profileGates.map((gate) => gate.id) };
}

// ─── promotion ledger ─────────────────────────────────────────────────────

export function readLedger(path) {
	if (!existsSync(path)) return { schema: LEDGER_SCHEMA, entries: [] };
	if (!lstatSync(path).isFile()) throw new Error(`ledger ${path} is not a regular file`);
	const ledger = JSON.parse(readFileSync(path, "utf8"));
	if (ledger?.schema !== LEDGER_SCHEMA || !Array.isArray(ledger.entries)) throw new Error(`ledger ${path} is not an ${LEDGER_SCHEMA} document`);
	return ledger;
}

export function appendLedger(path, entry) {
	const ledger = readLedger(path);
	ledger.entries.push(entry);
	const temporary = `${path}.${process.pid}.tmp`;
	writeFileSync(temporary, `${JSON.stringify(ledger, null, 2)}\n`, { mode: 0o600 });
	renameSync(temporary, path);
	return ledger;
}

/** Rollback: the bundle's exact candidate must have passed the GO gate when it was promoted. */
export function evaluateRollback({ ledger, candidate, expectedVersion = null, expectedSha = null }) {
	const failures = [];
	if (!SHA256.test(candidate?.digest ?? "")) failures.push("the rollback bundle candidate digest is missing or invalid");
	if (expectedVersion !== null && candidate?.version !== expectedVersion) failures.push(`rollback bundle is version ${candidate?.version}, expected ${expectedVersion}`);
	if (expectedSha !== null && candidate?.gitSha !== expectedSha) failures.push(`rollback bundle is commit ${candidate?.gitSha}, expected ${expectedSha}`);
	const match = (ledger?.entries ?? []).find(
		(entry) => entry?.decision === "GO" && entry.candidate_digest === candidate?.digest && entry.release_version === candidate?.version && entry.git_sha === candidate?.gitSha,
	);
	if (!match) failures.push(`candidate ${candidate?.digest} (${candidate?.version}) has no production GO record in the promotion ledger; only a previously GO-promoted candidate may be restored`);
	return { go: failures.length === 0, failures, entry: match ?? null };
}

// ─── CLI ──────────────────────────────────────────────────────────────────

export function parseArgs(argv) {
	const options = { bundle: null, candidateDigest: null, profile: DEFAULT_PROFILE, root: ROOT, maxEvidenceAgeDays: DEFAULT_MAX_EVIDENCE_AGE_DAYS, ledger: null, record: false, rollback: false, json: false, expectedVersion: null, expectedSha: null };
	const valued = { "--bundle": "bundle", "--candidate-digest": "candidateDigest", "--profile": "profile", "--root": "root", "--max-evidence-age-days": "maxEvidenceAgeDays", "--ledger": "ledger", "--expected-version": "expectedVersion", "--expected-sha": "expectedSha" };
	for (let index = 0; index < argv.length; index++) {
		let arg = argv[index];
		if (arg === "--") continue;
		let value;
		const eq = arg.indexOf("=");
		if (arg.startsWith("--") && eq > 0) {
			value = arg.slice(eq + 1);
			arg = arg.slice(0, eq);
		}
		if (arg in valued) {
			value ??= argv[++index];
			if (value === undefined || value === "") throw new Error(`${arg} needs a value`);
			options[valued[arg]] = value;
		} else if (arg === "--record") options.record = true;
		else if (arg === "--rollback") options.rollback = true;
		else if (arg === "--json") options.json = true;
		else if (arg === "--help" || arg === "-h") options.help = true;
		else throw new Error(`Unknown argument: ${arg}`);
	}
	if (options.help) return options;
	if (!options.bundle) throw new Error("--bundle is required");
	if (options.candidateDigest !== null && !SHA256.test(options.candidateDigest)) throw new Error("--candidate-digest must be a lowercase SHA-256 hex digest");
	const days = Number(options.maxEvidenceAgeDays);
	if (!Number.isInteger(days) || days < 1) throw new Error("--max-evidence-age-days must be a positive integer");
	options.maxEvidenceAgeDays = days;
	if (options.record && !options.ledger) throw new Error("--record needs --ledger");
	if (options.rollback && (!options.ledger || options.record)) throw new Error("--rollback needs --ledger and cannot --record");
	options.root = resolve(options.root);
	return options;
}

const USAGE = `Usage:
  node scripts/verify-production-go.mjs --bundle DIR [--candidate-digest SHA256] [--profile ${DEFAULT_PROFILE}]
      [--root TRUSTED_CHECKOUT] [--max-evidence-age-days ${DEFAULT_MAX_EVIDENCE_AGE_DAYS}] [--ledger FILE --record] [--json]
  node scripts/verify-production-go.mjs --rollback --bundle DIR --ledger FILE [--expected-version X.Y.Z] [--expected-sha SHA]
Exits 0 only on a candidate-bound production GO; 1 on NO-GO; 2 on usage errors.`;

export function main(argv = process.argv.slice(2), { now = new Date(), claimCheck = runClaimCheckGate, log = console.log, error = console.error } = {}) {
	let options;
	try {
		options = parseArgs(argv);
	} catch (problem) {
		error(`verify-production-go: ${problem.message}\n${USAGE}`);
		return 2;
	}
	if (options.help) {
		log(USAGE);
		return 0;
	}
	const report = (result, extra = {}) => {
		if (options.json) log(JSON.stringify({ ...extra, ...result }, null, 2));
		else {
			log(`Production GO (${extra.mode}): ${result.go ? "GO" : "NO-GO"} for candidate ${extra.candidate_digest ?? "unknown"}`);
			for (const failure of result.failures) error(`- ${failure}`);
		}
		return result.go ? 0 : 1;
	};
	let candidate;
	try {
		candidate = bundleCandidate(isAbsolute(options.bundle) ? options.bundle : resolve(options.bundle));
	} catch (problem) {
		return report({ go: false, failures: [problem.message] }, { mode: options.rollback ? "rollback" : "promote" });
	}
	const ledgerPath = options.ledger ? resolve(options.ledger) : null;

	if (options.rollback) {
		let ledger;
		try {
			ledger = readLedger(ledgerPath);
		} catch (problem) {
			return report({ go: false, failures: [problem.message] }, { mode: "rollback", candidate_digest: candidate.digest });
		}
		const result = evaluateRollback({ ledger, candidate, expectedVersion: options.expectedVersion, expectedSha: options.expectedSha });
		return report(result, { mode: "rollback", candidate_digest: candidate.digest });
	}

	let loaded;
	try {
		const registryPath = resolve(options.root, REGISTRY_FILE);
		const registryBytes = readFileSync(registryPath);
		const registry = JSON.parse(registryBytes.toString("utf8"));
		const receiptsPath = registry?.hardGateReceipts?.receiptsPath;
		const schemaPath = registry?.hardGateReceipts?.schemaPath;
		if (typeof receiptsPath !== "string" || typeof schemaPath !== "string") throw new Error("registry hardGateReceipts must name receiptsPath and schemaPath");
		loaded = {
			registry,
			registrySha256: sha256(registryBytes),
			receipts: JSON.parse(readFileSync(resolve(options.root, receiptsPath), "utf8")),
			schema: JSON.parse(readFileSync(resolve(options.root, schemaPath), "utf8")),
			receiptsPath,
			schemaPath,
		};
	} catch (problem) {
		return report({ go: false, failures: [`cannot read the trusted registry/receipts: ${problem.message}`] }, { mode: "promote", candidate_digest: candidate.digest });
	}
	const result = evaluateProductionGo({
		...loaded,
		root: options.root,
		bundleInventoryPath: candidate.inventoryPath,
		candidateDigest: candidate.digest,
		expectedCandidateDigest: options.candidateDigest,
		profile: options.profile,
		now,
		maxEvidenceAgeDays: options.maxEvidenceAgeDays,
		claimCheck,
	});
	if (result.go && options.record) {
		try {
			appendLedger(ledgerPath, {
				decision: "GO",
				profile: options.profile,
				candidate_digest: candidate.digest,
				candidate_digest_source: CANDIDATE_DIGEST_SOURCE,
				release_version: candidate.version,
				release_tag: candidate.tag,
				git_sha: candidate.gitSha,
				registry_sha256: loaded.registrySha256,
				trusted_verifier_commit: gitCommitSha(options.root),
				verified_at_utc: now.toISOString(),
			});
		} catch (problem) {
			return report({ go: false, failures: [...result.failures, `could not record the GO decision: ${problem.message}`] }, { mode: "promote", candidate_digest: candidate.digest });
		}
	}
	return report(result, { mode: "promote", candidate_digest: candidate.digest });
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
	try {
		process.exitCode = main();
	} catch (problem) {
		console.error(`verify-production-go: ${problem instanceof Error ? problem.message : String(problem)}`);
		process.exitCode = 1;
	}
}
