import { z } from "zod";

export const ArtifactManifestFileSchema = z.object({
	path: z.string().min(1),
	sha256: z.string().regex(/^[0-9a-f]{64}$/i),
});

/**
 * Watermark lineage: embed per-customer/per-channel identifiers inside the signed manifest
 * to enable leak attribution for closed-source commercial distributions.
 *
 * This is signed as part of the manifest bytes, so it is tamper-evident.
 */
export const ArtifactManifestLineageSchema = z.object({
	/**
	 * Unique watermark identifier (recommended per customer per release).
	 * Example: "cust_acme_2026q1_r3".
	 */
	watermark_id: z.string().min(1).max(128),
	/** Optional label: customer/org/team name (avoid sensitive data). */
	issued_to: z.string().min(1).max(128).optional(),
	/** Distribution channel. */
	channel: z.enum(["dev", "commercial"]).optional(),
	/**
	 * Nonce to ensure uniqueness even when build inputs are identical.
	 * Base64 string (suggested >= 16 bytes).
	 */
	nonce_b64: z.string().min(8).max(512).optional(),
	/** Build metadata (best-effort, non-sensitive). */
	build_id: z.string().min(1).max(128).optional(),
	git_sha: z.string().min(7).max(64).optional(),
	ci_provider: z.string().min(1).max(64).optional(),
	ci_run_id: z.string().min(1).max(128).optional(),
});

const ARTIFACT_ID_RE = /^[a-z0-9][a-z0-9/_-]{0,127}$/;
// Keep this permissive; some builds may append metadata (e.g. "0.6.0+sha.abc").
const VERSION_RE = /^[0-9A-Za-z.+_-]{1,64}$/;

export const ArtifactManifestV1Schema = z
	.object({
		schema_version: z.literal(1),
		artifact_id: z.string().regex(ARTIFACT_ID_RE),
		artifact_version: z.string().regex(VERSION_RE),
		created_at: z.string().datetime(),
		/**
		 * Key identifier for signature verification. Optional for developer builds.
		 * Commercial builds should set this to the public key id used for signing.
		 */
		key_id: z.string().min(1).optional(),
		/**
		 * Files are relative to the artifact directory. Paths MUST be unique.
		 * Generators should sort paths to make manifests deterministic.
		 */
		files: z.array(ArtifactManifestFileSchema).min(1).max(4096),
		/** Optional watermark lineage for commercial leak attribution. */
		lineage: ArtifactManifestLineageSchema.optional(),
	})
	.superRefine((m, ctx) => {
		const seen = new Set<string>();
		for (const f of m.files) {
			const p = f.path.replace(/\\/g, "/").trim();
			if (!p) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					path: ["files"],
					message: "file path must not be empty",
				});
				continue;
			}
			if (seen.has(p)) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					path: ["files"],
					message: `duplicate file path: ${p}`,
				});
				break;
			}
			seen.add(p);
		}
	});

export type ArtifactManifestV1 = z.infer<typeof ArtifactManifestV1Schema>;
