#!/usr/bin/env node

/**
 * Verify a signed AIDR release before installation.
 *
 * The signer policy and anti-rollback state must live outside the untrusted
 * release directory. When a command follows `--`, it runs only after the
 * signature, signer, expiry, rollback state, inventory and every artifact
 * digest have passed. The rollback state advances only after that command
 * exits successfully.
 *
 * Usage:
 *   node scripts/release-verify.mjs --bundle <dir> --policy <json> --state <json>
 *     [--record] [--receipt <json>] [--] [installer [arguments...]]
 */

import { spawn } from "node:child_process";
import { lstat } from "node:fs/promises";
import path from "node:path";

import {
	RELEASE_MANIFEST_NAME,
	RELEASE_SIGNATURE_NAME,
	acquireRollbackLock,
	atomicJsonWrite,
	enforceRollbackState,
	isWithin,
	loadReleaseBundle,
	loadRollbackState,
	loadSignerPolicy,
	readJsonFile,
	recordRollbackState,
	resolveExternalControlPath,
	sha256,
	validateReleaseManifest,
	verifyManifestSignature,
} from "./release-signing-lib.mjs";

try {
	const { options, installCommand } = parseArguments(process.argv.slice(2));
	if (!options["--bundle"] || !options["--policy"] || !options["--state"]) {
		usage();
		process.exit(2);
	}
	const bundle = await loadReleaseBundle(options["--bundle"], { allowSignedControlFiles: true });
	const policy = await loadSignerPolicy(options["--policy"], bundle.bundle);
	const manifestRecord = await readJsonFile(path.join(bundle.bundle, RELEASE_MANIFEST_NAME), "release manifest");
	const signatureRecord = await readJsonFile(path.join(bundle.bundle, RELEASE_SIGNATURE_NAME), "release signature");
	const manifest = manifestRecord.value;
	const validated = validateReleaseManifest(manifest, bundle, policy);
	verifyManifestSignature(manifestRecord.raw, signatureRecord.value, validated);
	const manifestDigest = sha256(manifestRecord.raw);
	const initialState = await loadRollbackState(options["--state"], bundle.bundle);
	const statePath = initialState.path;
	const receiptPath = await validateReceiptPath(options["--receipt"], bundle.bundle, statePath, policy.path);
	// Serialize the state check, installer execution and state advancement. A
	// second process fails closed rather than racing an older release over a
	// newer one. A lock left by a killed process requires operator inspection.
	const lock = await acquireRollbackLock(statePath);
	try {
		const state = await loadRollbackState(statePath, bundle.bundle);
		enforceRollbackState(state, manifest, manifestDigest);
		const verifiedAt = new Date();
		const baseReceipt = {
			schema_version: 1,
			status: "verified",
			verified_at: verifiedAt.toISOString(),
			policy_id: policy.policyId,
			product_id: manifest.product_id,
			channel: manifest.channel,
			release_sequence: manifest.release_sequence,
			release_version: manifest.release_version,
			git_sha: manifest.git_sha,
			manifest_sha256: manifestDigest,
			key_id: validated.keyId,
			fingerprint_sha256: validated.fingerprint,
			artifacts_verified: bundle.artifacts.length,
			expires_at: manifest.expires_at,
		};

		if (installCommand.length > 0) {
			const status = await runInstaller(installCommand, bundle.bundle, {
				...process.env,
				AIDR_VERIFIED_RELEASE_MANIFEST_SHA256: manifestDigest,
				AIDR_VERIFIED_RELEASE_SEQUENCE: String(manifest.release_sequence),
				AIDR_VERIFIED_RELEASE_VERSION: manifest.release_version,
			});
			if (status !== 0) {
				console.error(`Verified installer exited with status ${status}; anti-rollback state was not advanced.`);
				process.exitCode = status;
			} else {
				await recordRollbackState(state, manifest, manifestDigest);
				await writeReceipt(receiptPath, {
					...baseReceipt,
					status: "installed",
					installer_exit_status: 0,
					anti_rollback_state_recorded: true,
				});
				console.log(JSON.stringify({ ...baseReceipt, status: "installed", anti_rollback_state_recorded: true }));
			}
		} else {
			const shouldRecord = options["--record"] === true;
			if (shouldRecord) await recordRollbackState(state, manifest, manifestDigest);
			await writeReceipt(receiptPath, {
				...baseReceipt,
				anti_rollback_state_recorded: shouldRecord,
			});
			console.log(JSON.stringify({ ...baseReceipt, anti_rollback_state_recorded: shouldRecord }));
		}
	} finally {
		await lock.release();
	}
} catch (error) {
	console.error(`Release verification failed: ${formatError(error)}`);
	process.exit(1);
}

function parseArguments(argv) {
	const delimiter = argv.indexOf("--");
	const optionArguments = delimiter >= 0 ? argv.slice(0, delimiter) : argv;
	const installCommand = delimiter >= 0 ? argv.slice(delimiter + 1) : [];
	if (delimiter >= 0 && installCommand.length === 0) throw new Error("installer command is missing after --");
	const options = {};
	const flags = new Set(["--record"]);
	const valued = new Set(["--bundle", "--policy", "--state", "--receipt"]);
	for (let index = 0; index < optionArguments.length; index += 1) {
		const flag = optionArguments[index];
		if (options[flag] !== undefined) throw new Error(`duplicate option: ${flag}`);
		if (flags.has(flag)) {
			options[flag] = true;
			continue;
		}
		if (!valued.has(flag)) throw new Error(`unknown option: ${flag}`);
		const value = optionArguments[index + 1];
		if (!value || value.startsWith("--")) throw new Error(`missing value for ${flag}`);
		options[flag] = value;
		index += 1;
	}
	return { options, installCommand };
}

async function runInstaller(command, cwd, env) {
	const child = spawn(command[0], command.slice(1), {
		cwd,
		env,
		stdio: "inherit",
		shell: false,
		windowsHide: true,
	});
	return await new Promise((resolve, reject) => {
		child.once("error", reject);
		child.once("close", (code, signal) => {
			if (signal) reject(new Error(`installer was terminated by signal ${signal}`));
			else resolve(code ?? 1);
		});
	});
}

async function validateReceiptPath(receiptPath, bundlePath, statePath, policyPath) {
	if (!receiptPath) return;
	const resolved = await resolveExternalControlPath(receiptPath, bundlePath, "verification receipt");
	if (samePath(resolved, statePath)) throw new Error("verification receipt and anti-rollback state must use different paths");
	if (samePath(resolved, policyPath)) throw new Error("verification receipt and signer policy must use different paths");
	try {
		const info = await lstat(resolved);
		if (!info.isFile() || info.isSymbolicLink()) throw new Error("verification receipt must be a regular file path");
	} catch (error) {
		if (error?.code !== "ENOENT") throw error;
	}
	return resolved;
}

function samePath(left, right) {
	return isWithin(left, right) && isWithin(right, left);
}

async function writeReceipt(receiptPath, receipt) {
	if (!receiptPath) return;
	await atomicJsonWrite(receiptPath, receipt, 0o600);
}

function usage() {
	console.error(
		"Usage: node scripts/release-verify.mjs --bundle <dir> --policy <json> --state <json> [--record] [--receipt <json>] [-- installer ...]",
	);
}

function formatError(error) {
	return error instanceof Error ? error.message : String(error);
}
