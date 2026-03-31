/**
 * LlamaIndex integration adapter for AIDR SDK
 *
 * Provides seamless integration with LlamaIndex query engines and agents
 * by adding AIDR security validation for document retrieval URLs and
 * tool-based operations.
 */

import type { AIDRClient } from "../client.js";
import type { CheckResult } from "../config.js";

/**
 * Options for AIDRQueryEngine wrapper
 */
export interface AIDRQueryEngineOptions {
	/** Session ID for tracking security decisions */
	sessionId?: string;
	/** Whether to throw on deny verdict (default: true) */
	throwOnDeny?: boolean;
	/** Whether to validate source URLs (default: true) */
	validateSourceUrls?: boolean;
}

/**
 * Error thrown when AIDR blocks a query operation
 */
export class AIDRLlamaIndexError extends Error {
	constructor(
		message: string,
		public readonly verdict: CheckResult,
		public readonly query: string,
		public readonly sourceUrls?: string[],
	) {
		super(message);
		this.name = "AIDRLlamaIndexError";
	}
}

/**
 * Source node with metadata for URL extraction
 */
interface SourceNode {
	node?: {
		metadata?: Record<string, unknown>;
	};
	metadata?: Record<string, unknown>;
}

/**
 * Query result with source information
 */
interface QueryResult {
	response?: string;
	sourceNodes?: SourceNode[];
	metadata?: Record<string, unknown>;
}

/**
 * AIDRQueryEngine - Security wrapper for LlamaIndex query engines
 *
 * This class wraps a LlamaIndex query engine and adds AIDR security
 * validation for all queries and document retrieval operations. It
 * validates source URLs and secures tool-based agent operations.
 *
 * @example
 * ```typescript
 * const queryEngine = index.asQueryEngine();
 * const secureEngine = new AIDRQueryEngine(queryEngine, aidrClient);
 * const result = await secureEngine.query("What is the revenue forecast?");
 * ```
 */
export class AIDRQueryEngine {
	/**
	 * Create a new AIDRQueryEngine
	 *
	 * @param innerEngine - The LlamaIndex query engine to wrap
	 * @param aidrClient - AIDR client for security checks
	 * @param options - Optional configuration
	 */
	constructor(
		private innerEngine: {
			query(query: string): Promise<QueryResult>;
			queryEngine?: unknown;
		},
		private aidrClient: AIDRClient,
		private options: AIDRQueryEngineOptions = {},
	) {}

	/**
	 * Execute a query with AIDR security validation
	 *
	 * This method:
	 * 1. Validates the query through AIDR security check
	 * 2. Extracts and validates document source URLs
	 * 3. Executes the query if allowed
	 * 4. Returns the result with security metadata
	 *
	 * @param query - The query string to execute
	 * @returns Promise resolving to the query result
	 * @throws AIDRLlamaIndexError if verdict is deny and throwOnDeny is true
	 */
	async query(query: string): Promise<QueryResult> {
		// Validate the query through AIDR
		const verdict = await this.aidrClient.check({
			action: "read",
			resource: query,
			context: {
				sessionId: this.options.sessionId || `llamaindex_${Date.now()}`,
				tool: "llamaindex_query",
				type: "query",
			},
		});

		if (verdict.decision !== "allow") {
			const errorMessage = `AIDR: ${verdict.reason || "Query blocked by security policy"}`;

			if (this.options.throwOnDeny !== false) {
				throw new AIDRLlamaIndexError(errorMessage, verdict, query);
			}

			return {
				response: `[BLOCKED] ${errorMessage}`,
				metadata: {
					aidrBlocked: true,
					aidrDecision: verdict.decision,
					aidrReason: verdict.reason,
				},
			};
		}

		// Execute the query
		const result = await this.innerEngine.query(query);

		// Validate source URLs if enabled
		if (this.options.validateSourceUrls !== false) {
			const sourceUrls = this.extractSourceUrls(result);

			for (const url of sourceUrls) {
				const urlVerdict = await this.aidrClient.check({
					action: "fetch",
					resource: url,
					context: {
						sessionId: this.options.sessionId || `llamaindex_${Date.now()}`,
						tool: "llamaindex_source_url",
						type: "url_validation",
					},
				});

				if (urlVerdict.decision === "deny") {
					const errorMessage = `AIDR: Source URL blocked - ${url}: ${urlVerdict.reason || "URL validation failed"}`;

					if (this.options.throwOnDeny !== false) {
						throw new AIDRLlamaIndexError(errorMessage, urlVerdict, query, sourceUrls);
					}

					// Mark the result with warning but don't block
					result.metadata = {
						...result.metadata,
						aidrUrlWarnings: [...((result.metadata?.aidrUrlWarnings as string[]) || []), url],
					};
				}
			}
		}

		// Add security metadata to result
		result.metadata = {
			...result.metadata,
			aidrValidated: true,
			aidrDecision: verdict.decision,
			aidrConfidence: verdict.confidence,
		};

		return result;
	}

	/**
	 * Extract source URLs from query result metadata
	 *
	 * @param result - The query result
	 * @returns Array of URLs found in source nodes
	 */
	private extractSourceUrls(result: QueryResult): string[] {
		const urls: string[] = [];
		const urlPattern = /^https?:\/\/[^\s"'<>()[\]{}]+/i;

		// Extract from source nodes
		if (result.sourceNodes && Array.isArray(result.sourceNodes)) {
			for (const node of result.sourceNodes) {
				const metadata = node.node?.metadata || node.metadata || {};

				// Check common URL fields
				const urlFields = ["url", "source", "link", "href", "file_path", "file_name"];
				for (const field of urlFields) {
					const value = metadata[field];
					if (typeof value === "string" && urlPattern.test(value)) {
						urls.push(value);
					}
				}
			}
		}

		// Also check top-level metadata
		if (result.metadata) {
			const urlFields = ["source_url", "document_url", "url"];
			for (const field of urlFields) {
				const value = result.metadata[field];
				if (typeof value === "string" && urlPattern.test(value)) {
					urls.push(value);
				}
			}
		}

		return [...new Set(urls)]; // Remove duplicates
	}

	/**
	 * Get the wrapped inner query engine
	 *
	 * @returns The wrapped LlamaIndex query engine
	 */
	getInnerEngine(): typeof this.innerEngine {
		return this.innerEngine;
	}

	/**
	 * Get current options
	 *
	 * @returns Current AIDRQueryEngineOptions
	 */
	getOptions(): AIDRQueryEngineOptions {
		return { ...this.options };
	}

	/**
	 * Create a new AIDRQueryEngine with updated options
	 *
	 * @param newOptions - Options to merge with current options
	 * @returns New AIDRQueryEngine instance with merged options
	 */
	withOptions(newOptions: Partial<AIDRQueryEngineOptions>): AIDRQueryEngine {
		return new AIDRQueryEngine(this.innerEngine, this.aidrClient, {
			...this.options,
			...newOptions,
		});
	}
}

/**
 * Factory function to wrap a LlamaIndex query engine with AIDR security
 *
 * @param engine - The LlamaIndex query engine to wrap
 * @param client - AIDR client for security checks
 * @param options - Optional configuration
 * @returns Wrapped query engine with AIDR security
 *
 * @example
 * ```typescript
 * const queryEngine = index.asQueryEngine();
 * const secureEngine = withAIDRLlamaIndex(queryEngine, aidrClient);
 * ```
 */
export function withAIDRLlamaIndex(
	engine: {
		query(query: string): Promise<QueryResult>;
		queryEngine?: unknown;
	},
	client: AIDRClient,
	options?: AIDRQueryEngineOptions,
): AIDRQueryEngine {
	return new AIDRQueryEngine(engine, client, options);
}

/**
 * Wrap multiple query engines with AIDR security
 *
 * @param engines - Array of query engines to wrap
 * @param client - AIDR client for security checks
 * @param options - Optional configuration (applied to all engines)
 * @returns Array of wrapped query engines
 *
 * @example
 * ```typescript
 * const engines = [index1.asQueryEngine(), index2.asQueryEngine()];
 * const secureEngines = wrapQueryEnginesWithAIDR(engines, aidrClient);
 * ```
 */
export function wrapQueryEnginesWithAIDR(
	engines: Array<{
		query(query: string): Promise<QueryResult>;
		queryEngine?: unknown;
	}>,
	client: AIDRClient,
	options?: AIDRQueryEngineOptions,
): AIDRQueryEngine[] {
	return engines.map((engine) => new AIDRQueryEngine(engine, client, options));
}
