/**
 * Vector similarity calculations for ML threat detection.
 * Optimized for 100-dimensional embeddings with sub-millisecond performance.
 */

/**
 * Calculate cosine similarity between two vectors.
 * Returns value in [-1, 1] range where 1 = identical, 0 = orthogonal, -1 = opposite.
 */
export function cosineSimilarity(a: Float32Array, b: Float32Array): number {
	if (a.length !== b.length) {
		throw new Error(`Vector length mismatch: ${a.length} vs ${b.length}`);
	}

	let dotProduct = 0;
	let normA = 0;
	let normB = 0;

	// Unroll loop for 100-dim vectors (common case)
	const len = a.length;
	for (let i = 0; i < len; i++) {
		const ai = a[i] as number;
		const bi = b[i] as number;
		dotProduct += ai * bi;
		normA += ai * ai;
		normB += bi * bi;
	}

	if (normA === 0 || normB === 0) {
		return 0; // One vector is zero, undefined similarity
	}

	return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

/**
 * Find top-k most similar vectors from a list.
 * Returns indices and similarity scores sorted by similarity (descending).
 */
export function findTopKSimilar(
	query: Float32Array,
	candidates: Float32Array[],
	k: number,
): Array<{ index: number; similarity: number }> {
	const similarities: Array<{ index: number; similarity: number }> = [];

	for (let i = 0; i < candidates.length; i++) {
		const candidate = candidates[i];
		if (!candidate) continue;
		similarities.push({
			index: i,
			similarity: cosineSimilarity(query, candidate),
		});
	}

	// Sort by similarity descending
	similarities.sort((a, b) => b.similarity - a.similarity);

	return similarities.slice(0, k);
}

/**
 * Precomputed threshold constants for threat detection.
 */
export const SIMILARITY_THRESHOLDS = {
	/** Very high confidence match */
	CRITICAL: 0.92,
	/** High confidence match */
	HIGH: 0.85,
	/** Medium confidence - needs review */
	MEDIUM: 0.75,
	/** Low confidence - suspicious */
	LOW: 0.65,
	/** Ignore anything below this */
	NOISE: 0.5,
} as const;
