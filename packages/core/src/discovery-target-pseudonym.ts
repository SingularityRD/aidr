/**
 * Pseudonymous discovery target identifiers.
 *
 * The managed panel receives CVE id, severity, component, version and rule id
 * only; target addresses stay on the device. Discovery uploads therefore carry a
 * keyed, tenant-scoped pseudonym of each target origin instead of the origin:
 *
 *   tid1_<hex(HMAC-SHA256(key, "aidr-discovery-target-v1\0" + tenant + "\0" + origin))>
 *
 * The key is 32 random bytes generated once per installation and kept at
 * `~/.singularity-aidr/discovery-target-key` (mode 0600). It never leaves the
 * device, so the panel cannot reverse or dictionary-test a pseudonym, while the
 * same collector reports a stable identifier for the same origin across cycles.
 * Operators correlate pseudonyms with addresses from the local inventory.
 *
 * Failure is closed: if the key cannot be read or created, or is malformed,
 * callers get an error and must not upload (and never fall back to the address).
 */

import { createHmac, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { resolvePath } from "./config.js";

export const DISCOVERY_TARGET_ID_PATTERN = /^tid1_[a-f0-9]{64}$/;
const KEY_FILE = "discovery-target-key";
const KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function decodeKey(text: string): Buffer {
	const trimmed = text.trim();
	if (!KEY_PATTERN.test(trimmed)) throw new Error("discovery_target_key_invalid");
	const key = Buffer.from(trimmed, "base64url");
	if (key.length !== 32) throw new Error("discovery_target_key_invalid");
	return key;
}

/** Read the per-installation pseudonym key, creating it on first use. */
export async function getDiscoveryTargetKey(aidrDirPath?: string): Promise<Buffer> {
	const aidrDir = aidrDirPath ?? resolvePath("~/.singularity-aidr");
	const keyPath = join(aidrDir, KEY_FILE);
	try {
		return decodeKey(await readFile(keyPath, "utf8"));
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
			throw error instanceof Error && error.message === "discovery_target_key_invalid"
				? error
				: new Error("discovery_target_key_unavailable");
		}
	}
	try {
		await mkdir(aidrDir, { recursive: true, mode: 0o700 });
		await writeFile(keyPath, randomBytes(32).toString("base64url"), {
			encoding: "utf8",
			mode: 0o600,
			flag: "wx",
		});
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
			throw new Error("discovery_target_key_unavailable");
		}
	}
	// Re-read so a concurrent creator's key wins consistently.
	try {
		return decodeKey(await readFile(keyPath, "utf8"));
	} catch (error) {
		throw error instanceof Error && error.message === "discovery_target_key_invalid"
			? error
			: new Error("discovery_target_key_unavailable");
	}
}

/** Keyed, tenant-scoped pseudonym for a canonical target origin (`https://host:port/`). */
export function discoveryTargetPseudonym(key: Buffer, tenantId: string, origin: string): string {
	if (key.length !== 32) throw new Error("discovery_target_key_invalid");
	const digest = createHmac("sha256", key)
		.update("aidr-discovery-target-v1\0")
		.update(tenantId.toLowerCase())
		.update("\0")
		.update(origin)
		.digest("hex");
	return `tid1_${digest}`;
}
