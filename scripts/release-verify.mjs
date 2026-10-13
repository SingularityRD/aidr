#!/usr/bin/env node

/**
 * Verify a signed AIDR release before installation.
 *
 * The anti-rollback lock is taken first. Every bundle file is then copied once
 * into a fresh owner-only temporary directory; signature and digests are
 * verified against those copies and the installer runs from that directory
 * (also exported as AIDR_VERIFIED_RELEASE_DIR), so a writer of the delivered
 * directory cannot swap a file between verification and installation.
 *
 * The signer policy and anti-rollback state must live outside the untrusted
 * release directory. When a command follows `--`, it runs only after the
 * signature, signer, expiry, rollback state, inventory and every artifact
 * digest have passed. The rollback state advances only after that command
 * exits successfully.
 *
 * --require-state refuses a missing state file instead of treating it as a
 * first install; production promotion uses it so a lost state cannot reset
 * the rollback floor.
 *
 * Usage:
 *   node scripts/release-verify.mjs --bundle <dir> --policy <json> --state <json>
 *     [--record] [--require-state] [--receipt <json>] [--] [installer [arguments...]]
 */

import { verifyAndInstallRelease } from "./release-signing-lib.mjs";

try {
	const { options, installCommand } = parseArguments(process.argv.slice(2));
	if (!options["--bundle"] || !options["--policy"] || !options["--state"]) {
		usage();
		process.exit(2);
	}
	process.exitCode = await verifyAndInstallRelease(
		{
			bundle: options["--bundle"],
			policy: options["--policy"],
			state: options["--state"],
			receipt: options["--receipt"],
			record: options["--record"] === true,
			requireState: options["--require-state"] === true,
		},
		installCommand,
	);
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
	const flags = new Set(["--record", "--require-state"]);
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

function usage() {
	console.error(
		"Usage: node scripts/release-verify.mjs --bundle <dir> --policy <json> --state <json> [--record] [--require-state] [--receipt <json>] [-- installer ...]",
	);
}

function formatError(error) {
	return error instanceof Error ? error.message : String(error);
}
