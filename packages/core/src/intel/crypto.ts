import { createDecipheriv } from "node:crypto";

/**
 * Decrypt an AES-256-GCM envelope.
 *
 * Envelope format (binary):
 * - 12 bytes: IV/nonce
 * - N bytes: ciphertext
 * - 16 bytes: auth tag
 */
export function decryptAes256GcmEnvelope(params: {
	key: Uint8Array;
	blob: Uint8Array;
}): Uint8Array | null {
	const key = params.key;
	const blob = params.blob;

	// Minimum: 12B IV + 16B tag (allow empty plaintext, though uncommon)
	if (blob.length < 12 + 16) return null;
	if (key.length !== 32) return null;

	const iv = blob.subarray(0, 12);
	const tag = blob.subarray(blob.length - 16);
	const ciphertext = blob.subarray(12, blob.length - 16);

	try {
		const decipher = createDecipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(iv));
		decipher.setAuthTag(Buffer.from(tag));
		const out = Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
		return new Uint8Array(out);
	} catch {
		return null;
	}
}
