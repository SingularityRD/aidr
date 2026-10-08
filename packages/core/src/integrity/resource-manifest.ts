/**
 * Runtime view of the artifact manifest for one bundled resource directory
 * (`dist/resources/threats`, `dist/resources/allowlists`).
 *
 * The connector-start integrity check (`verifyArtifactIntegrityAndLog`) only
 * runs when integrity is enabled, which it is not by default outside a
 * commercial build. The rule and allowlist loaders therefore check the files
 * they actually read against the shipped manifest themselves, whenever one is
 * present: a listed file must match its digest, and a file the manifest does not
 * list is not part of the release (a resource directory is a closed set).
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { ArtifactManifestV1Schema } from "./schema.js";
import { DEFAULT_MANIFEST_NAME, DEFAULT_SIGNATURE_NAME, verifyEd25519Signature } from "./verify.js";

/** How far above the resource directory the manifest may live (dist/resources/threats -> dist). */
const MAX_PARENT_LEVELS = 3;

export type ResourceManifestCoverage =
	/** No manifest found, or the manifest does not describe this directory. */
	| { status: "none" }
	/**
	 * `files` maps a path relative to the resource directory (POSIX separators)
	 * to its expected SHA-256. `signature` is `verified` only when public keys
	 * were supplied and the manifest signature checked out against one of them.
	 */
	| {
			status: "covered";
			manifestPath: string;
			files: ReadonlyMap<string, string>;
			signature: "verified" | "unverified";
	  }
	/** A manifest exists but cannot be trusted; nothing in the directory is verified. */
	| { status: "invalid"; manifestPath: string; reason: string };

export interface ResourceManifestOptions {
	/** Ed25519 public keys; when non-empty, the manifest signature is required. */
	publicKeysPem?: readonly string[];
}

async function readOptional(file: string): Promise<string | null> {
	try {
		return await readFile(file, "utf8");
	} catch {
		return null;
	}
}

/** Locate and parse the manifest that covers `resourceDir`, if any. */
export async function loadResourceManifestCoverage(
	resourceDir: string,
	options: ResourceManifestOptions = {},
): Promise<ResourceManifestCoverage> {
	const resourceAbs = path.resolve(resourceDir);
	let candidate = resourceAbs;
	for (let level = 0; level <= MAX_PARENT_LEVELS; level++) {
		const manifestPath = path.join(candidate, DEFAULT_MANIFEST_NAME);
		const raw = await readOptional(manifestPath);
		if (raw !== null) return parseCoverage(raw, manifestPath, candidate, resourceAbs, options);
		const parent = path.dirname(candidate);
		if (parent === candidate) break;
		candidate = parent;
	}
	return { status: "none" };
}

async function parseCoverage(
	raw: string,
	manifestPath: string,
	rootAbs: string,
	resourceAbs: string,
	options: ResourceManifestOptions,
): Promise<ResourceManifestCoverage> {
	let json: unknown;
	try {
		json = JSON.parse(raw);
	} catch {
		return { status: "invalid", manifestPath, reason: "manifest is not valid JSON" };
	}
	const parsed = ArtifactManifestV1Schema.safeParse(json);
	if (!parsed.success) {
		return { status: "invalid", manifestPath, reason: "manifest does not match the schema" };
	}

	let signature: "verified" | "unverified" = "unverified";
	const keys = options.publicKeysPem ?? [];
	if (keys.length > 0) {
		const sigRaw = await readOptional(path.join(rootAbs, DEFAULT_SIGNATURE_NAME));
		if (sigRaw === null) {
			return { status: "invalid", manifestPath, reason: "manifest signature is missing" };
		}
		if (!verifyEd25519Signature(Buffer.from(raw, "utf8"), sigRaw, [...keys])) {
			return { status: "invalid", manifestPath, reason: "manifest signature does not verify" };
		}
		signature = "verified";
	}

	const prefix = path.relative(rootAbs, resourceAbs).split(path.sep).join("/");
	const files = new Map<string, string>();
	for (const entry of parsed.data.files) {
		const normalized = entry.path.replace(/\\/g, "/");
		const rel =
			prefix === ""
				? normalized
				: normalized.startsWith(`${prefix}/`)
					? normalized.slice(prefix.length + 1)
					: null;
		if (rel) files.set(rel, entry.sha256.toLowerCase());
	}
	if (files.size === 0) return { status: "none" };
	return { status: "covered", manifestPath, files, signature };
}

/**
 * Read a data file from a covered resource directory, or `null` when the
 * manifest says it is not a shipped file (unlisted, modified, or the manifest
 * itself is untrusted). For an allowlist, ignoring such a file only ever makes
 * detection stricter. Read errors propagate to the caller.
 */
export async function readShippedResourceText(
	coverage: ResourceManifestCoverage,
	relativePath: string,
	absolutePath: string,
	logger: { warn: (message: string, meta?: Record<string, unknown>) => void },
): Promise<string | null> {
	const bytes = await readFile(absolutePath);
	const verified = checkCoveredFile(coverage, relativePath, bytes);
	if (verified && !verified.ok) {
		logger.warn(`Ignoring ${relativePath}: not a shipped file per the artifact manifest`, {
			reason: verified.reason,
		});
		return null;
	}
	return bytes.toString("utf8");
}

/** SHA-256 of the exact bytes on disk, as the manifest records it. */
function sha256Hex(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

/**
 * Whether `relativePath` (POSIX, relative to the covered directory) with these
 * bytes is a shipped file. `null` means the coverage does not constrain it.
 */
export function checkCoveredFile(
	coverage: ResourceManifestCoverage,
	relativePath: string,
	bytes: Uint8Array,
):
	| { ok: true }
	| { ok: false; reason: "unlisted" | "hash_mismatch" | "untrusted_manifest" }
	| null {
	if (coverage.status === "none") return null;
	if (coverage.status === "invalid") return { ok: false, reason: "untrusted_manifest" };
	const expected = coverage.files.get(relativePath);
	if (expected === undefined) return { ok: false, reason: "unlisted" };
	return sha256Hex(bytes) === expected ? { ok: true } : { ok: false, reason: "hash_mismatch" };
}
