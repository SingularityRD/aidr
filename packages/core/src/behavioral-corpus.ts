/**
 * Inline operator corpus format for signed V2 detector policies.
 * `sha256` covers UTF-8 canonicalDetectorPolicyPayload(corpus without sha256),
 * including tenant, corpus ID/version, model version, dimension and all entries.
 * The containing policy signature authenticates both content and digest; a digest
 * alone is not trust. Delivery uses the fixed detector policy file, never a tool
 * path or remote URL. No threat samples or efficacy claims ship here.
 */
import { z } from "zod";
import { EMBEDDING_DIM } from "./ml/embedder.js";

export const LOCAL_EMBEDDER_MODEL_VERSION = "local-tinyhash-v1";
export const MAX_BEHAVIORAL_CORPUS_ENTRIES = 1024;
const Identifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
const BoundedText = z
	.string()
	.min(1)
	.max(1024)
	.refine((value) => value.trim() === value && !/[\u0000-\u001f\u007f]/.test(value));

export const BehavioralCorpusSchema = z
	.object({
		schema_version: z.literal(1),
		tenant_id: Identifier,
		corpus_id: Identifier,
		corpus_version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
		model_version: z.literal(LOCAL_EMBEDDER_MODEL_VERSION),
		dimension: z.literal(EMBEDDING_DIM),
		sha256: z.string().regex(/^[a-f0-9]{64}$/),
		entries: z
			.array(
				z
					.object({
						threatId: Identifier,
						embedding: z
							.array(z.number().finite().min(-1).max(1))
							.length(EMBEDDING_DIM)
							.refine((vector) => {
								const normSquared = vector.reduce((sum, value) => sum + value * value, 0);
								return Math.abs(normSquared - 1) <= 0.01;
							}, "Threat vector must be unit normalized"),
						metadata: z
							.object({
								category: BoundedText,
								severity: BoundedText,
								description: BoundedText,
							})
							.strict(),
					})
					.strict(),
			)
			.min(1)
			.max(MAX_BEHAVIORAL_CORPUS_ENTRIES)
			.refine(
				(entries) => new Set(entries.map((entry) => entry.threatId)).size === entries.length,
				"Duplicate threat identifiers",
			),
	})
	.strict();

export type BehavioralCorpus = z.infer<typeof BehavioralCorpusSchema>;
