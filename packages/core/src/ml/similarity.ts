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
 * Calculate cosine distance (1 - similarity) for clustering.
 */
export function cosineDistance(a: Float32Array, b: Float32Array): number {
	return 1 - cosineSimilarity(a, b);
}

/**
 * Calculate Euclidean distance between two vectors.
 * Useful for finding nearest neighbors in embedding space.
 */
export function euclideanDistance(a: Float32Array, b: Float32Array): number {
	if (a.length !== b.length) {
		throw new Error(`Vector length mismatch: ${a.length} vs ${b.length}`);
	}

	let sumSquares = 0;
	for (let i = 0; i < a.length; i++) {
		const diff = a[i]! - b[i]!;
		sumSquares += diff * diff;
	}

	return Math.sqrt(sumSquares);
}

/**
 * Calculate Manhattan (L1) distance.
 * More robust to outliers than Euclidean.
 */
export function manhattanDistance(a: Float32Array, b: Float32Array): number {
	if (a.length !== b.length) {
		throw new Error(`Vector length mismatch: ${a.length} vs ${b.length}`);
	}

	let sum = 0;
	for (let i = 0; i < a.length; i++) {
		sum += Math.abs(a[i]! - b[i]!);
	}

	return sum;
}

/**
 * Find top-k most similar vectors from a list.
 * Returns indices and similarity scores sorted by similarity (descending).
 */
export function findTopKSimilar(
	query: Float32Array,
	candidates: Float32Array[],
	k: number
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
 * Find all similar vectors above a threshold.
 * Returns indices and scores for all candidates exceeding threshold.
 */
export function findSimilarAboveThreshold(
	query: Float32Array,
	candidates: Float32Array[],
	threshold: number
): Array<{ index: number; similarity: number }> {
	const results: Array<{ index: number; similarity: number }> = [];

	for (let i = 0; i < candidates.length; i++) {
		const candidate = candidates[i];
		if (!candidate) continue;
		const sim = cosineSimilarity(query, candidate);
		if (sim >= threshold) {
			results.push({ index: i, similarity: sim });
		}
	}

	// Sort by similarity descending
	results.sort((a, b) => b.similarity - a.similarity);

	return results;
}

/**
 * Calculate average similarity across multiple vectors.
 * Useful for ensemble scoring.
 */
export function averageSimilarity(query: Float32Array, references: Float32Array[]): number {
	if (references.length === 0) return 0;

	let totalSim = 0;
	for (const ref of references) {
		totalSim += cosineSimilarity(query, ref);
	}

	return totalSim / references.length;
}

/**
 * Calculate maximum similarity to any reference vector.
 * Best match approach for threat detection.
 */
export function maxSimilarity(query: Float32Array, references: Float32Array[]): number {
	let maxSim = -1;

	for (const ref of references) {
		const sim = cosineSimilarity(query, ref);
		if (sim > maxSim) {
			maxSim = sim;
		}
	}

	return maxSim;
}

/**
 * Calculate similarity percentile (how unique is this vector).
 * Higher percentile = more unique (less similar to references).
 */
export function similarityPercentile(
	query: Float32Array,
	references: Float32Array[]
): number {
	if (references.length === 0) return 1;

	const sims = references.map(ref => cosineSimilarity(query, ref));
	sims.sort((a, b) => a - b);

	// Find where query would rank
	// Higher percentile = less similar to known threats
	const maxSim = Math.max(...sims);
	return 1 - maxSim; // Normalize to [0, 1]
}

/**
 * Batch cosine similarity calculation for efficiency.
 * Returns matrix of similarities between query set and reference set.
 */
export function batchCosineSimilarity(
	queries: Float32Array[],
	references: Float32Array[]
): number[][] {
	const matrix: number[][] = [];

	for (const query of queries) {
		const row: number[] = [];
		for (const ref of references) {
			row.push(cosineSimilarity(query, ref));
		}
		matrix.push(row);
	}

	return matrix;
}

/**
 * Convert similarity score to probability estimate using sigmoid.
 * Maps [-1, 1] similarity to [0, 1] probability.
 */
export function similarityToProbability(similarity: number, steepness: number = 5): number {
	return 1 / (1 + Math.exp(-steepness * similarity));
}

/**
 * Calculate soft maximum similarity with temperature scaling.
 * Smoother than hard max, useful for gradient-based approaches.
 */
export function softMaxSimilarity(
	query: Float32Array,
	references: Float32Array[],
	temperature: number = 0.1
): number {
	if (references.length === 0) return 0;

	const sims = references.map(ref => cosineSimilarity(query, ref));
	const scaledSims = sims.map(s => s / temperature);
	const maxScaled = Math.max(...scaledSims);
	
	// Numerically stable softmax
	const expSims = scaledSims.map(s => Math.exp(s - maxScaled));
	const sumExp = expSims.reduce((a, b) => a + b, 0);
	
	// Weighted average
	let weightedSum = 0;
	for (let i = 0; i < sims.length; i++) {
		weightedSum += sims[i] * (expSims[i] / sumExp);
	}
	
	return weightedSum;
}

/**
 * Check if two embeddings are approximately equal.
 * Useful for testing and deduplication.
 */
export function embeddingsEqual(
	a: Float32Array,
	b: Float32Array,
	tolerance: number = 1e-5
): boolean {
	if (a.length !== b.length) return false;

	for (let i = 0; i < a.length; i++) {
		const ai = a[i];
		const bi = b[i];
		if (ai === undefined || bi === undefined) {
			return false;
		}
		if (Math.abs(ai - bi) > tolerance) {
			return false;
		}
	}

	return true;
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
	NOISE: 0.50,
} as const;

/**
 * Convert similarity to risk level string.
 */
export function similarityToRiskLevel(similarity: number): 'critical' | 'high' | 'medium' | 'low' | 'none' {
	if (similarity >= SIMILARITY_THRESHOLDS.CRITICAL) return 'critical';
	if (similarity >= SIMILARITY_THRESHOLDS.HIGH) return 'high';
	if (similarity >= SIMILARITY_THRESHOLDS.MEDIUM) return 'medium';
	if (similarity >= SIMILARITY_THRESHOLDS.LOW) return 'low';
	return 'none';
}
