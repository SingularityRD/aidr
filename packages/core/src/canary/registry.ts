/**
 * Local registry of deployed canary credentials (honeytokens).
 *
 * The registry lives in the AIDR state directory, which the self-defense rules
 * (CLT-SELF-008) put out of an agent's reach: any tool call that names
 * `.singularity-aidr` is a hard block. It stores, per canary, only the decoy's
 * path, its kind, and SHA-256 digests (plus lengths) of the token values; the
 * raw values exist nowhere but in the decoy file itself.
 */

import { createHash } from "node:crypto";
import {
	closeSync,
	constants,
	fsyncSync,
	lstatSync,
	openSync,
	readFileSync,
	renameSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";
import { resolvePath } from "../config.js";
import { preparePrivateLocalDirectory } from "../private-local-file.js";

export const CANARY_KINDS = ["aws", "github", "openai", "env", "ssh-config", "db-url"] as const;
export type CanaryKind = (typeof CANARY_KINDS)[number];

/** Shortest token core the detector hashes; every generated token is at least this long. */
export const MIN_CANARY_TOKEN_LENGTH = 20;
export const MAX_CANARY_TOKEN_LENGTH = 128;

const HEX_DIGEST = /^[a-f0-9]{64}$/;

const CanaryTokenDigestSchema = z
	.object({
		sha256: z.string().regex(HEX_DIGEST),
		length: z.number().int().min(MIN_CANARY_TOKEN_LENGTH).max(MAX_CANARY_TOKEN_LENGTH),
	})
	.strict();

const CanaryRecordSchema = z
	.object({
		id: z.string().regex(/^cny_[a-f0-9]{16}$/),
		kind: z.enum(CANARY_KINDS),
		path: z.string().min(1).max(4096),
		created_at: z.string().min(1).max(64),
		/** Digest of the decoy file as written, so removal never deletes a file someone changed. */
		file_sha256: z.string().regex(HEX_DIGEST),
		tokens: z.array(CanaryTokenDigestSchema).min(1).max(16),
		/** Directories deploy created for this decoy (outermost first); removed again when empty. */
		created_dirs: z.array(z.string().min(1).max(4096)).max(16),
	})
	.strict();

const CanaryRegistrySchema = z
	.object({
		version: z.literal(1),
		canaries: z.array(CanaryRecordSchema).max(1024),
	})
	.strict();

export type CanaryTokenDigest = z.infer<typeof CanaryTokenDigestSchema>;
export type CanaryRecord = z.infer<typeof CanaryRecordSchema>;
export type CanaryRegistry = z.infer<typeof CanaryRegistrySchema>;

export type CanaryRegistryRead =
	| { status: "absent" }
	| { status: "ok"; registry: CanaryRegistry }
	| { status: "invalid"; reason: string };

/** Registry location: `~/.singularity-aidr/canary/registry.json` (resolved at call time). */
export function defaultCanaryRegistryPath(): string {
	return resolvePath("~/.singularity-aidr/canary/registry.json");
}

export function sha256Hex(value: string | Buffer): string {
	return createHash("sha256").update(value).digest("hex");
}

export function emptyCanaryRegistry(): CanaryRegistry {
	return { version: 1, canaries: [] };
}

/** Parse registry text. Never throws; an unusable registry is `invalid`, not empty. */
export function parseCanaryRegistry(text: string): CanaryRegistryRead {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return { status: "invalid", reason: "registry is not valid JSON" };
	}
	const result = CanaryRegistrySchema.safeParse(parsed);
	if (!result.success) return { status: "invalid", reason: "registry does not match the schema" };
	return { status: "ok", registry: result.data };
}

/** Read the registry. A missing file means no canaries; anything unreadable is `invalid`. */
export function readCanaryRegistry(path = defaultCanaryRegistryPath()): CanaryRegistryRead {
	let info: ReturnType<typeof lstatSync>;
	try {
		info = lstatSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return { status: "absent" };
		return { status: "invalid", reason: "registry could not be inspected" };
	}
	if (info.isSymbolicLink() || !info.isFile()) {
		return { status: "invalid", reason: "registry is not a regular file" };
	}
	try {
		return parseCanaryRegistry(readFileSync(path, "utf8"));
	} catch {
		return { status: "invalid", reason: "registry could not be read" };
	}
}

/**
 * Atomically replace the registry (0600 file in a private 0700 directory).
 * The temporary file is created exclusively, so a planted symlink is refused.
 */
export function writeCanaryRegistry(
	registry: CanaryRegistry,
	path = defaultCanaryRegistryPath(),
): void {
	const validated = CanaryRegistrySchema.parse(registry);
	const directory = dirname(path);
	preparePrivateLocalDirectory(directory);
	const temporary = join(directory, `.registry-${process.pid}-${Date.now()}.tmp`);
	const flags =
		constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0);
	const handle = openSync(temporary, flags, 0o600);
	try {
		writeSync(handle, `${JSON.stringify(validated, null, 2)}\n`);
		fsyncSync(handle);
	} catch (error) {
		closeSync(handle);
		unlinkSync(temporary);
		throw error;
	}
	closeSync(handle);
	try {
		renameSync(temporary, path);
	} catch (error) {
		unlinkSync(temporary);
		throw error;
	}
}
