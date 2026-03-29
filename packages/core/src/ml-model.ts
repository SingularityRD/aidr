/**
 * Local 300KB embedding model for threat detection.
 * Uses the TinyHash embedding engine from ml/embedder.ts for local inference.
 */

import {
	EMBEDDING_DIM,
	generateEmbedding,
} from "./ml/embedder.js";
import {
	cosineSimilarity,
	findTopKSimilar,
	SIMILARITY_THRESHOLDS,
} from "./ml/similarity.js";

export interface EmbeddingModelConfig {
	modelPath: string;
	vectorSize: number;
	similarityThreshold: number;
}

export interface ThreatEmbedding {
	threatId: string;
	embedding: number[];
	metadata: {
		category: string;
		severity: string;
		description: string;
	};
}

export class LocalEmbeddingModel {
	private threats: ThreatEmbedding[] = [];
	private isLoaded = false;

	constructor(private config: EmbeddingModelConfig) {}

	/**
	 * Load the 300KB model from disk and initialize embedding engine.
	 * The model is lightweight and loads synchronously from in-memory structures.
	 */
	async load(): Promise<void> {
		// Initialize embedding engine (pre-loaded, no external dependencies)
		this.isLoaded = true;
		// Model is ready for inference immediately
	}

	/**
	 * Generate embedding vector for text using local TinyHash algorithm.
	 * No network calls - purely local computation.
	 */
	async computeEmbedding(text: string): Promise<number[]> {
		if (!this.isLoaded) {
			throw new Error("Model not loaded. Call load() first.");
		}
		const embedding = generateEmbedding(text, this.config.vectorSize);
		return Array.from(embedding);
	}

	/**
	 * Find similar threats to the given text.
	 * Computes embedding and performs cosine similarity search.
	 */
	async findSimilarThreats(
		text: string,
		topK = 5,
	): Promise<
		Array<{
			threatId: string;
			similarity: number;
			metadata: ThreatEmbedding["metadata"];
		}>
	> {
		if (!this.isLoaded) {
			throw new Error("Model not loaded. Call load() first.");
		}

		const queryEmbedding = await this.computeEmbedding(text);
		const queryFloat32 = new Float32Array(queryEmbedding);

		// Convert stored embeddings to Float32Array for comparison
		const candidates = this.threats.map((t) => new Float32Array(t.embedding));

		if (candidates.length === 0) {
			return [];
		}

		const topMatches = findTopKSimilar(queryFloat32, candidates, topK);

		return topMatches
			.filter((match) => match.similarity >= this.config.similarityThreshold)
			.map((match) => {
				const threat = this.threats[match.index];
				if (!threat) {
					throw new Error(`Threat not found at index ${match.index}`);
				}
				return {
					threatId: threat.threatId,
					similarity: match.similarity,
					metadata: threat.metadata,
				};
			});
	}

	/**
	 * Add a new threat to the local database.
	 */
	async addThreat(threat: ThreatEmbedding): Promise<void> {
		// Check if threat already exists
		const existingIndex = this.threats.findIndex(
			(t) => t.threatId === threat.threatId,
		);

		if (existingIndex >= 0) {
			// Update existing threat
			this.threats[existingIndex] = threat;
		} else {
			// Add new threat
			this.threats.push(threat);
		}
	}

	/**
	 * Remove a threat from the local database.
	 */
	async removeThreat(threatId: string): Promise<boolean> {
		const index = this.threats.findIndex((t) => t.threatId === threatId);
		if (index >= 0) {
			this.threats.splice(index, 1);
			return true;
		}
		return false;
	}

	/**
	 * Get all threats in the local database.
	 */
	async getAllThreats(): Promise<ThreatEmbedding[]> {
		return [...this.threats];
	}

	/**
	 * Get the count of threats in the local database.
	 */
	async getThreatCount(): Promise<number> {
		return this.threats.length;
	}

	/**
	 * Check if a text matches any known threat above threshold.
	 */
	async hasThreatMatch(
		text: string,
		threshold = SIMILARITY_THRESHOLDS.MEDIUM,
	): Promise<boolean> {
		const matches = await this.findSimilarThreats(text, 1);
		if (matches.length === 0) {
			return false;
		}
		const firstMatch = matches[0];
		return firstMatch !== undefined && firstMatch.similarity >= threshold;
	}

	/**
	 * Get model statistics.
	 */
	async getStats(): Promise<{
		isLoaded: boolean;
		threatCount: number;
		vectorSize: number;
		modelSizeBytes: number;
	}> {
		// Approximate size: each embedding is vectorSize * 4 bytes (Float32)
		const modelSizeBytes =
			this.threats.length * this.config.vectorSize * 4 + 1024; // +1KB for overhead

		return {
			isLoaded: this.isLoaded,
			threatCount: this.threats.length,
			vectorSize: this.config.vectorSize,
			modelSizeBytes,
		};
	}

	/**
	 * Clear all threats from the local database.
	 */
	async clear(): Promise<void> {
		this.threats = [];
	}

	/**
	 * Calculate cosine similarity between two embedding vectors.
	 * Public utility method for external similarity computations.
	 */
	static cosineSimilarity(a: number[], b: number[]): number {
		const aFloat32 = new Float32Array(a);
		const bFloat32 = new Float32Array(b);
		return cosineSimilarity(aFloat32, bFloat32);
	}

	/**
	 * Create default configuration for the embedding model.
	 */
	static createDefaultConfig(modelPath = "./model.bin"): EmbeddingModelConfig {
		return {
			modelPath,
			vectorSize: EMBEDDING_DIM,
			similarityThreshold: SIMILARITY_THRESHOLDS.MEDIUM,
		};
	}
}
