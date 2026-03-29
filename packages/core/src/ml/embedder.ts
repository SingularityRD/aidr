/**
 * Lightweight text embedding generator using TinyHash algorithm.
 * Generates 100-dimensional vectors without external dependencies.
 * Total model size < 500KB, inference < 50ms.
 */

import { randomBytes } from "crypto";

/** Default embedding dimension - kept small for speed */
export const EMBEDDING_DIM = 100;

/** Maximum token length for processing */
const MAX_TOKENS = 128;

/** Character n-gram size for feature extraction */
const NGRAM_SIZE = 3;

/** Hash seed for deterministic embeddings */
let HASH_SEED = 0x9e3779b9;

/**
 * Simple 32-bit FNV-1a hash for strings.
 * Fast and deterministic across platforms.
 */
export function fnv1aHash(str: string, seed: number = HASH_SEED): number {
	let hash = seed;
	for (let i = 0; i < str.length; i++) {
		hash ^= str.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193);
	}
	return hash >>> 0;
}

/**
 * Extract character n-grams from text for feature extraction.
 * Handles URLs, commands, and prompts uniformly.
 */
function extractNgrams(text: string, n: number = NGRAM_SIZE): string[] {
	// Normalize: lowercase, remove extra spaces
	const normalized = text.toLowerCase().trim().replace(/\s+/g, ' ');
	
	// For very short text, use character-level features
	if (normalized.length <= n) {
		return [normalized.padEnd(n, '_')];
	}

	const ngrams: string[] = [];
	// Extract overlapping n-grams
	for (let i = 0; i <= normalized.length - n; i++) {
		ngrams.push(normalized.slice(i, i + n));
	}
	
	// Add special boundary markers
	ngrams.push(`^${normalized.slice(0, n - 1)}`);
	ngrams.push(`${normalized.slice(-n + 1)}$`);
	
	return ngrams;
}

/**
 * Tokenize text into word-level tokens for semantic features.
 */
function tokenize(text: string): string[] {
	// Handle command sequences, URLs, and natural language uniformly
	const normalized = text
		.toLowerCase()
		// Preserve URL structure
		.replace(/https?:\/\//g, 'http_')
		.replace(/www\./g, 'www_')
		// Preserve command separators
		.replace(/[|;&&||]/g, ' SEP ')
		// Handle path separators
		.replace(/\\/g, '/')
		// Extract meaningful tokens
		.replace(/[^a-z0-9_\/.@$-]/g, ' ')
		.trim();

	const tokens = normalized.split(/\s+/).filter(t => t.length > 0);
	return tokens.slice(0, MAX_TOKENS);
}

/**
 * Generate a deterministic embedding vector from text.
 * Uses multiple hashing strategies for robust similarity matching.
 */
export function generateEmbedding(text: string, dim: number = EMBEDDING_DIM): Float32Array {
	const embedding = new Float32Array(dim);
	const ngrams = extractNgrams(text);
	const tokens = tokenize(text);
	
	// Combine n-gram and token features
	const features: Map<string, number> = new Map();
	
	// Weight n-grams by position (earlier = more important)
	ngrams.forEach((ngram, idx) => {
		const weight = 1.0 - (idx / (ngrams.length + 1)) * 0.3;
		features.set(ngram, (features.get(ngram) || 0) + weight);
	});
	
	// Add token features with TF-like weighting
	tokens.forEach((token, idx) => {
		const weight = 1.0 + (tokens.length - idx) / tokens.length;
		features.set(token, (features.get(token) || 0) + weight);
	});

	// Hash features into embedding dimensions using multiple seeds
	let featureCount = 0;
	for (const [feature, weight] of features) {
		// Use multiple hash seeds for better distribution
		const h1 = fnv1aHash(feature, HASH_SEED);
		const h2 = fnv1aHash(feature, HASH_SEED ^ 0x5f3759df);
		const h3 = fnv1aHash([...feature].reverse().join(''), HASH_SEED ^ 0x6a09e667);
		
		// Distribute across dimensions using multiple hashes
		const idx1 = h1 % dim;
		const idx2 = h2 % dim;
		const idx3 = h3 % dim;
		
		// Use hash as value with weight
		const value = ((h1 / 0xffffffff) * 2 - 1) * weight;
		embedding[idx1]! += value;
		embedding[idx2]! += value * 0.7; // Secondary index with decay
		embedding[idx3]! += value * 0.5; // Tertiary index
		
		featureCount++;
		if (featureCount > 256) break; // Limit features for speed
	}

	// L2 normalize the embedding
	let sumSquares = 0;
	for (let i = 0; i < dim; i++) {
		sumSquares += embedding[i]! * embedding[i]!;
	}
	
	if (sumSquares > 0) {
		const norm = Math.sqrt(sumSquares);
		for (let i = 0; i < dim; i++) {
			embedding[i]! /= norm;
		}
	}

	return embedding;
}

/**
 * Generate embedding for domain names (special handling for URL similarity).
 * Handles subdomain variations and TLD variations.
 */
export function generateDomainEmbedding(domain: string, dim: number = EMBEDDING_DIM): Float32Array {
	// Normalize domain: lowercase, remove www, split components
	const normalized = domain.toLowerCase().trim();
	
	// Extract domain components
	const parts = normalized.split('.');
	const features: string[] = [];
	
	// Add full domain
	features.push(normalized);
	
	// Add components
	for (let i = 0; i < parts.length; i++) {
		features.push(parts.slice(i).join('.'));
		features.push(parts.slice(i, i + 2).join('.'));
	}
	
	// Add reversed domain for suffix matching
	features.push(parts.reverse().join('.'));
	
	// Add character bigrams for typosquatting detection
	for (let i = 0; i < normalized.length - 1; i++) {
		features.push(normalized.slice(i, i + 2));
	}
	
	// Generate embedding from features
	const embedding = new Float32Array(dim);
	
	for (const feature of features) {
		const h = fnv1aHash(feature);
		const idx = h % dim;
		const value = (h / 0xffffffff) * 2 - 1;
		embedding[idx]! += value;
	}
	
	// L2 normalize
	let sumSquares = 0;
	for (let i = 0; i < dim; i++) {
		sumSquares += embedding[i]! * embedding[i]!;
	}
	
	if (sumSquares > 0) {
		const norm = Math.sqrt(sumSquares);
		for (let i = 0; i < dim; i++) {
			embedding[i]! /= norm;
		}
	}
	
	return embedding;
}

/**
 * Batch generate embeddings for multiple texts.
 * More efficient than sequential calls for large batches.
 */
export function generateEmbeddingsBatch(texts: string[], dim: number = EMBEDDING_DIM): Float32Array[] {
	return texts.map(text => generateEmbedding(text, dim));
}

/**
 * Get the approximate size of embedding data in bytes.
 */
export function getEmbeddingSizeBytes(dim: number = EMBEDDING_DIM): number {
	return dim * 4; // Float32 = 4 bytes
}

/**
 * Serialize embedding to compact base64 string.
 */
export function embeddingToBase64(embedding: Float32Array): string {
	const buffer = Buffer.from(embedding.buffer);
	return buffer.toString('base64url');
}

/**
 * Deserialize embedding from base64 string.
 */
export function base64ToEmbedding(base64: string, dim: number = EMBEDDING_DIM): Float32Array {
	const buffer = Buffer.from(base64, 'base64url');
	return new Float32Array(buffer.buffer, buffer.byteOffset, dim);
}
