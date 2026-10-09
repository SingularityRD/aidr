import { z } from "zod";

const IntelFileKindSchema = z.enum([
	"url_denylist",
	"url_allowlist",
	"domain_risk",
	"package_name_denylist",
	"package_hash_denylist",
	"plugin_signature_denylist",
]);

const IntelPackFileSchema = z.object({
	kind: IntelFileKindSchema,
	path: z.string().min(1),
	/**
	 * SHA-256 of the plaintext file content (utf-8 bytes for text files).
	 * For encrypted files this is optional; use ciphertext_sha256 as the primary integrity check.
	 */
	sha256: z
		.string()
		.regex(/^[0-9a-f]{64}$/i)
		.optional(),
	/** If true, the file at `path` is an encrypted binary blob. */
	encrypted: z.boolean().default(false),
	/** Encryption algorithm for encrypted blobs. */
	cipher: z.enum(["aes-256-gcm"]).optional(),
	/** Key id used to decrypt this blob (looked up in local entitlement/keyring). */
	key_id: z.string().min(1).optional(),
	/** SHA-256 of the ciphertext blob bytes (required when encrypted=true). */
	ciphertext_sha256: z
		.string()
		.regex(/^[0-9a-f]{64}$/i)
		.optional(),
});

export const IntelPackManifestSchema = z.object({
	pack_id: z.string().min(1),
	version: z.string().min(1),
	issued_at: z.string().min(1),
	expires_at: z.string().optional(),
	key_id: z.string().min(1),
	files: z.array(IntelPackFileSchema).default([]),
});

export const PackActivePointerSchema = z.object({
	version: z.string().min(1),
});
