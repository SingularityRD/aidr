import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import { type ArtifactManifestV1, ArtifactManifestV1Schema } from "./schema.js";

export type IntegrityStatus =
	| "ok"
	| "skipped"
	| "revoked"
	| "missing_manifest"
	| "missing_signature"
	| "invalid_manifest"
	| "no_public_keys"
	| "bad_signature"
	| "path_traversal"
	| "missing_file"
	| "hash_mismatch"
	| "unlisted_file"
	| "io_error";

export interface IntegrityMismatch {
	path: string;
	expected: string;
	actual: string | null;
}

export interface IntegrityCheckResult {
	status: IntegrityStatus;
	manifest?: ArtifactManifestV1;
	reason?: string;
	mismatches?: IntegrityMismatch[];
}

export const DEFAULT_MANIFEST_NAME = "aidr-artifact.manifest.json";
export const DEFAULT_SIGNATURE_NAME = "aidr-artifact.manifest.sig";

/**
 * Directory names whose contents are runtime data (threat rules, allowlists).
 * Any directory a manifest path enters through one of these names is a closed
 * set: a file inside it that the manifest does not list changes verdicts just
 * as surely as a modified one, so it is an integrity failure.
 */
const CLOSED_RESOURCE_DIR_NAMES = new Set(["resources", "threats", "allowlists"]);

function sha256Hex(buf: Uint8Array): string {
	return createHash("sha256").update(buf).digest("hex");
}

function isSafeRelativePath(p: string): boolean {
	const normalized = p.replace(/\\/g, "/");
	if (!normalized.trim()) return false;
	if (normalized.startsWith("/")) return false;
	if (normalized.includes("\0")) return false;
	// Disallow Windows drive letters / protocols.
	if (normalized.includes(":")) return false;
	const parts = normalized.split("/");
	return !parts.some((seg) => seg === ".." || seg === "");
}

function resolveUnderRoot(rootAbs: string, rel: string): string | null {
	if (!isSafeRelativePath(rel)) return null;
	const full = path.resolve(rootAbs, rel);
	const rootWithSep = rootAbs.endsWith(path.sep) ? rootAbs : `${rootAbs}${path.sep}`;
	if (full === rootAbs) return full;
	if (!full.startsWith(rootWithSep)) return null;
	return full;
}

function parseSignatureBase64(raw: string): Buffer | null {
	const trimmed = raw.trim();
	if (!trimmed) return null;
	try {
		const buf = Buffer.from(trimmed, "base64");
		// Ed25519 signatures are 64 bytes.
		if (buf.length !== 64) return null;
		return buf;
	} catch {
		return null;
	}
}

function toPublicKey(key: string) {
	const t = key.trim();
	if (!t) return null;
	try {
		if (t.includes("BEGIN PUBLIC KEY")) return createPublicKey(t);
		// Allow base64-encoded SPKI DER for easier env/config distribution.
		return createPublicKey({ key: Buffer.from(t, "base64"), format: "der", type: "spki" });
	} catch {
		return null;
	}
}

/** Verify a base64 Ed25519 signature file's content over `message` against any of `publicKeys`. */
export function verifyEd25519Signature(
	message: Buffer,
	signatureBase64: string,
	publicKeys: string[],
): boolean {
	const sig = parseSignatureBase64(signatureBase64);
	return sig !== null && verifyEd25519(message, sig, publicKeys);
}

/** The closed resource directories (relative, POSIX) a manifest's paths enter. */
function closedResourceDirs(paths: readonly string[]): Set<string> {
	const dirs = new Set<string>();
	for (const p of paths) {
		const parts = p.split("/");
		const index = parts.slice(0, -1).findIndex((part) => CLOSED_RESOURCE_DIR_NAMES.has(part));
		if (index >= 0) dirs.add(parts.slice(0, index + 1).join("/"));
	}
	return dirs;
}

async function listFilesRecursive(rootAbs: string, rel: string, out: string[]): Promise<void> {
	let entries: import("node:fs").Dirent[];
	try {
		entries = await readdir(path.join(rootAbs, rel), { withFileTypes: true });
	} catch {
		return;
	}
	for (const entry of entries) {
		const child = `${rel}/${entry.name}`;
		if (entry.isDirectory()) await listFilesRecursive(rootAbs, child, out);
		else out.push(child);
	}
}

function verifyEd25519(message: Buffer, signature: Buffer, publicKeys: string[]): boolean {
	for (const k of publicKeys) {
		const key = toPublicKey(k);
		if (!key) continue;
		try {
			// For Ed25519 the algorithm parameter must be null.
			if (cryptoVerify(null, message, key, signature)) return true;
		} catch {}
	}
	return false;
}

export async function verifyArtifactIntegrity(params: {
	artifactDir: string;
	publicKeysPem: string[];
	verifySignatures: boolean;
	manifestName?: string;
	signatureName?: string;
	expectedArtifactId?: string;
}): Promise<IntegrityCheckResult> {
	const artifactDirAbs = path.resolve(params.artifactDir);
	const manifestPath = path.join(artifactDirAbs, params.manifestName ?? DEFAULT_MANIFEST_NAME);
	const signaturePath = path.join(artifactDirAbs, params.signatureName ?? DEFAULT_SIGNATURE_NAME);

	let manifestRaw: string;
	try {
		manifestRaw = await readFile(manifestPath, "utf8");
	} catch {
		return { status: "missing_manifest" };
	}

	let manifestJson: unknown;
	try {
		manifestJson = JSON.parse(manifestRaw) as unknown;
	} catch {
		return { status: "invalid_manifest" };
	}
	const parsed = ArtifactManifestV1Schema.safeParse(manifestJson);
	if (!parsed.success) return { status: "invalid_manifest" };
	const manifest = parsed.data;

	if (params.expectedArtifactId && manifest.artifact_id !== params.expectedArtifactId) {
		return {
			status: "invalid_manifest",
			manifest,
			reason: `artifact_id mismatch: expected ${params.expectedArtifactId} got ${manifest.artifact_id}`,
		};
	}

	if (params.verifySignatures) {
		if (params.publicKeysPem.length === 0) return { status: "no_public_keys", manifest };

		let sigRaw: string;
		try {
			sigRaw = await readFile(signaturePath, "utf8");
		} catch {
			return { status: "missing_signature", manifest, reason: signaturePath };
		}

		const sig = parseSignatureBase64(sigRaw);
		if (!sig) return { status: "bad_signature", manifest };

		// Verify signature over the exact manifest bytes written on disk.
		const msg = Buffer.from(manifestRaw, "utf8");
		if (!verifyEd25519(msg, sig, params.publicKeysPem))
			return { status: "bad_signature", manifest };
	}

	const mismatches: IntegrityMismatch[] = [];
	let missingCount = 0;
	for (const f of manifest.files) {
		const full = resolveUnderRoot(artifactDirAbs, f.path);
		if (!full) {
			return { status: "path_traversal", manifest, reason: f.path };
		}

		let bytes: Buffer;
		try {
			bytes = await readFile(full);
		} catch {
			mismatches.push({ path: f.path, expected: f.sha256, actual: null });
			missingCount += 1;
			continue;
		}

		const actual = sha256Hex(bytes);
		if (actual.toLowerCase() !== f.sha256.toLowerCase()) {
			mismatches.push({ path: f.path, expected: f.sha256, actual });
		}
	}

	if (mismatches.length > 0) {
		return { status: missingCount > 0 ? "missing_file" : "hash_mismatch", manifest, mismatches };
	}

	// Resource directories are closed sets: an extra rule or allowlist file
	// would be loaded and change verdicts even though every listed file matches.
	const listed = new Set(manifest.files.map((f) => f.path.split("\\").join("/")));
	const unlisted: IntegrityMismatch[] = [];
	for (const dir of closedResourceDirs([...listed])) {
		const present: string[] = [];
		await listFilesRecursive(artifactDirAbs, dir, present);
		for (const file of present) {
			if (!listed.has(file)) unlisted.push({ path: file, expected: "", actual: null });
		}
	}
	if (unlisted.length > 0) return { status: "unlisted_file", manifest, mismatches: unlisted };

	return { status: "ok", manifest };
}
