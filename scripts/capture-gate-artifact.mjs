#!/usr/bin/env node
/**
 * Snapshot a gate's own output to a gate-scoped path.
 *
 * A gate's result file is bound to the SHA-256 of the artifact it declares, and
 * `scripts/generate-v8-evidence-index.mjs` refuses to derive PASS when that
 * binding does not hold when the index is generated. That rule is correct, but
 * it made gate `11-test-ci-final` impossible to prove: it declared
 * `coverage/test-results.json`, which `vitest.config.ts` rewrites on *every*
 * vitest run, so the later `12-test-coverage` gate rebound the file and the
 * index recorded `unknown` for a suite that had passed 4257 of 4258 tests. The
 * strongest local gate therefore contributed no proven evidence at all.
 *
 * The remedy is to let a gate own its artifact: the gate command runs the suite
 * and then copies the generated JSON to a path no other gate writes. This is not
 * a weaker binding - the same bytes are hashed, at the same moment - it just
 * stops a later gate from invalidating the record.
 *
 * Nothing is written when the source is missing, unreadable, empty or not a
 * regular file, or when the copy would overwrite its own source: a gate must
 * never be able to bind to an empty or self-referential snapshot.
 *
 * Usage:
 *   node scripts/capture-gate-artifact.mjs <source> <destination> [--expect-json]
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** A refused capture. The CLI turns this into a non-zero exit and no writes. */
export class CaptureError extends Error {}

function show(root, value) {
	const shown = relative(root, value);
	return shown === "" || shown.startsWith("..") ? value : shown;
}

/**
 * Copy `source` to `destination`, both resolved against `root` unless absolute.
 *
 * Returns { source, destination, byte_length, sha256 } for the captured bytes.
 * Throws CaptureError, having written nothing, when the source cannot be
 * trusted as this gate's output.
 */
export function captureArtifact({ source, destination, root = ROOT, expectJson = false } = {}) {
	if (typeof source !== "string" || source.trim() === "") throw new CaptureError("a source path is required");
	if (typeof destination !== "string" || destination.trim() === "") throw new CaptureError("a destination path is required");
	const sourcePath = isAbsolute(source) ? source : resolve(root, source);
	const destinationPath = isAbsolute(destination) ? destination : resolve(root, destination);
	if (sourcePath === destinationPath) {
		throw new CaptureError(`source and destination are the same path (${show(root, sourcePath)}); a self-copy proves nothing`);
	}

	let stats;
	try {
		stats = statSync(sourcePath);
	} catch (error) {
		throw new CaptureError(`source artifact is missing: ${show(root, sourcePath)} (${error.code ?? error.message})`);
	}
	if (!stats.isFile()) throw new CaptureError(`source artifact is not a regular file: ${show(root, sourcePath)}`);

	let bytes;
	try {
		bytes = readFileSync(sourcePath);
	} catch (error) {
		throw new CaptureError(`source artifact is unreadable: ${show(root, sourcePath)} (${error.code ?? error.message})`);
	}
	if (bytes.length === 0) throw new CaptureError(`source artifact is empty: ${show(root, sourcePath)}`);

	if (expectJson) {
		// A half-written report is the failure this guards against: it would still
		// be hashed and bound, and the gate would look proven.
		try {
			JSON.parse(bytes.toString("utf8"));
		} catch (error) {
			throw new CaptureError(`source artifact is not parseable JSON: ${show(root, sourcePath)} (${error.message})`);
		}
	}

	mkdirSync(dirname(destinationPath), { recursive: true });
	writeFileSync(destinationPath, bytes);
	return {
		source: sourcePath,
		destination: destinationPath,
		byte_length: bytes.length,
		sha256: createHash("sha256").update(bytes).digest("hex"),
	};
}

export function parseArgs(argv) {
	const args = { source: null, destination: null, expectJson: false, help: false };
	const positional = [];
	for (const arg of argv) {
		if (arg === "--help" || arg === "-h") args.help = true;
		else if (arg === "--expect-json") args.expectJson = true;
		else if (arg.startsWith("-")) throw new CaptureError(`unknown argument: ${arg}`);
		else positional.push(arg);
	}
	if (positional.length > 2) throw new CaptureError(`expected at most two paths, received ${positional.length}`);
	[args.source, args.destination] = positional;
	return args;
}

export function main(argv = process.argv.slice(2), { root = ROOT } = {}) {
	let args;
	try {
		args = parseArgs(argv);
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		return 2;
	}
	if (args.help) {
		console.log("Usage: node scripts/capture-gate-artifact.mjs <source> <destination> [--expect-json]");
		return 0;
	}
	try {
		const captured = captureArtifact({ source: args.source, destination: args.destination, root, expectJson: args.expectJson });
		console.log(
			`[capture-gate-artifact] ${show(root, captured.destination)} <- ${show(root, captured.source)} ` +
				`(${captured.byte_length} bytes, sha256 ${captured.sha256.slice(0, 16)})`,
		);
		return 0;
	} catch (error) {
		console.error(`[capture-gate-artifact] ${error instanceof Error ? error.message : String(error)}`);
		return 1;
	}
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) process.exitCode = main();
