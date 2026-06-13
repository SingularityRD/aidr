/**
 * Local file encryption for cache and audit files.
 *
 * Uses AES-256-GCM with a key derived from the installation ID and machine
 * hostname.  Encrypted files are prefixed with an `AIDRENC:1:` header so
 * that they can be detected without attempting to decrypt.
 *
 * ## Format
 *
 * ```
 * AIDRENC:1:<base64(iv + ciphertext + authTag)>
 * ```
 *
 * - **Header** (`AIDRENC:1:`) — 9 ASCII bytes identifying the format.
 * - **Base64 payload** — IV (12 bytes) ‖ AES-256-GCM ciphertext ‖ auth tag (16 bytes).
 *
 * ## Graceful fallback
 *
 * `decryptFile` returns the raw file content as-is when the header is absent,
 * so plaintext files can be read transparently during the migration window.
 *
 * @module encryption
 */

import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { readFile, rename, unlink, writeFile } from "node:fs/promises";
import { hostname } from "node:os";

// ── Constants ──────────────────────────────────────────────────────────

/** Encryption metadata header prefix. */
const HEADER = "AIDRENC:1:";

/** AES-256 key length in bytes. */
const KEY_LENGTH = 32;

/** Initialization vector length in bytes (12 is standard for GCM). */
const IV_LENGTH = 12;

/** Authentication tag length in bytes. */
const TAG_LENGTH = 16;

/** PBKDF2 iterations for key derivation (100k). */
const PBKDF2_ITERATIONS = 100_000;

/** Fixed salt prefix combined with the hostname. */
const PBKDF2_SALT = "aidr-encryption-v1";

// ── Key Derivation ─────────────────────────────────────────────────────

/**
 * Derive an AES-256-GCM encryption key from the installation ID and machine
 * hostname.
 *
 * Uses PBKDF2-SHA256 with 100 000 iterations.  The salt incorporates the
 * machine hostname so that the key is **both** installation-specific and
 * machine-specific.
 *
 * @param installationId - Persistent UUID obtained from `getInstallationId()`.
 * @returns A 32-byte Buffer suitable for AES-256-GCM.
 */
export function deriveKey(installationId: string): Buffer {
	const salt = `${PBKDF2_SALT}-${hostname()}`;
	return pbkdf2Sync(installationId, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha256");
}

// ── Buffer-Level Encryption / Decryption ───────────────────────────────

/**
 * Encrypt a buffer with AES-256-GCM.
 *
 * The returned payload layout is: **IV (12 bytes) ‖ ciphertext ‖ auth tag (16 bytes)**.
 *
 * @param plaintext - Data to encrypt.
 * @param key       - 32-byte AES-256 key from `deriveKey()`.
 * @returns IV + ciphertext + GCM authentication tag.
 */
export function encryptBuffer(plaintext: Buffer, key: Buffer): Buffer {
	const iv = randomBytes(IV_LENGTH);
	const cipher = createCipheriv("aes-256-gcm", key, iv);
	const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	const tag = cipher.getAuthTag();
	return Buffer.concat([iv, encrypted, tag]);
}

/**
 * Decrypt a buffer that was encrypted with `encryptBuffer`.
 *
 * Expects the same layout: **IV (12 bytes) ‖ ciphertext ‖ auth tag (16 bytes)**.
 *
 * @param encrypted - Payload to decrypt.
 * @param key       - 32-byte AES-256 key from `deriveKey()`.
 * @returns Decrypted plaintext.
 * @throws If the payload is too short or the GCM authentication tag is invalid.
 */
export function decryptBuffer(encrypted: Buffer, key: Buffer): Buffer {
	if (encrypted.length < IV_LENGTH + TAG_LENGTH) {
		throw new RangeError(
			`Encrypted payload too short: ${encrypted.length} bytes (need ≥ ${IV_LENGTH + TAG_LENGTH})`,
		);
	}

	const iv = encrypted.subarray(0, IV_LENGTH);
	const tag = encrypted.subarray(encrypted.length - TAG_LENGTH);
	const ciphertext = encrypted.subarray(IV_LENGTH, encrypted.length - TAG_LENGTH);

	const decipher = createDecipheriv("aes-256-gcm", key, iv);
	decipher.setAuthTag(tag);
	return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ── Format Detection ───────────────────────────────────────────────────

/**
 * Check whether a buffer or string starts with the `AIDRENC:1:` header.
 *
 * @param data - Raw file content (Buffer or UTF-8 string).
 * @returns `true` if the data appears to be in encrypted format.
 */
export function isEncrypted(data: Buffer | string): boolean {
	const prefix = HEADER;
	if (typeof data === "string") {
		return data.startsWith(prefix);
	}
	if (data.length < prefix.length) return false;
	for (let i = 0; i < prefix.length; i++) {
		if (data[i] !== prefix.charCodeAt(i)) return false;
	}
	return true;
}

// ── File-Level Operations ──────────────────────────────────────────────

/**
 * Encrypt a file **in-place**.
 *
 * Reads the file, encrypts its contents with AES-256-GCM, prepends the
 * `AIDRENC:1:` header, and writes the result back.  If the file is already
 * encrypted this is a no-op.
 *
 * @param filePath - Absolute path to the file to encrypt.
 * @param key      - 32-byte AES-256 key from `deriveKey()`.
 * @throws If the file cannot be read or written.
 */
export async function encryptFile(filePath: string, key: Buffer): Promise<void> {
	const plaintext = await readFile(filePath);
	if (isEncrypted(plaintext)) return; // already encrypted

	const encrypted = encryptBuffer(plaintext, key);
	const encoded = `${HEADER}${encrypted.toString("base64")}\n`;
	await writeFile(filePath, encoded, { mode: 0o600 });
}

/**
 * Read and decrypt an encrypted file.
 *
 * If the file does **not** carry the `AIDRENC:1:` header the raw content is
 * returned as-is (graceful fallback for unencrypted files).
 *
 * @param filePath - Absolute path to the file to decrypt.
 * @param key      - 32-byte AES-256 key from `deriveKey()`.
 * @returns Decrypted (or raw plaintext) file content as a UTF-8 string.
 * @throws If the file cannot be read or the GCM tag is invalid.
 */
export async function decryptFile(filePath: string, key: Buffer): Promise<string> {
	const raw = await readFile(filePath, { encoding: "utf-8" });

	if (!isEncrypted(raw)) {
		// Graceful fallback — unencrypted file
		return raw;
	}

	const base64Data = raw.slice(HEADER.length).trim();
	const encrypted = Buffer.from(base64Data, "base64");
	const decrypted = decryptBuffer(encrypted, key);
	return decrypted.toString("utf-8");
}

/**
 * Migrate an unencrypted file to encrypted format **atomically**.
 *
 * Reads the file, encrypts it, and replaces the original via an atomic
 * write (temp-file + rename).  If the file is already encrypted this is
 * a no-op.
 *
 * @param filePath - Absolute path to the file to migrate.
 * @param key      - 32-byte AES-256 key from `deriveKey()`.
 * @throws If the file cannot be read or written.
 */
export async function migrateToEncrypted(filePath: string, key: Buffer): Promise<void> {
	const raw = await readFile(filePath);
	if (isEncrypted(raw)) return; // already encrypted

	const encrypted = encryptBuffer(raw, key);
	const encoded = `${HEADER}${encrypted.toString("base64")}\n`;

	// Atomic write via temp file
	const tmp = `${filePath}.${randomBytes(4).toString("hex")}.enc.tmp`;
	try {
		await writeFile(tmp, encoded, { mode: 0o600 });
		await rename(tmp, filePath);
	} catch (err) {
		try {
			await unlink(tmp);
		} catch {
			// best-effort cleanup
		}
		throw err;
	}
}
