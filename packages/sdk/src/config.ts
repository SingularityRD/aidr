import { ArtifactSchema } from "@singularityrd/aidr-core";
import { z } from "zod";

/**
 * SDK Configuration Schema
 */

export const SDKConfigSchema = z.object({
	apiKey: z.string().trim().min(1, "API key is required"),
	baseUrl: z.string().url().optional(),
	timeout: z.number().min(1000).max(60000).default(5000),
	retries: z.number().int().min(0).max(5).default(2),
	cache: z.boolean().default(true),
	cacheTtl: z.number().min(60000).max(86400000).default(300000), // 5 minutes
	environment: z.enum(["production", "staging", "development"]).default("production"),
	/** Share fetch URLs with the configured reputation provider. Off unless explicitly enabled. */
	urlReputationEnabled: z.boolean().default(false),
	/** Include query parameters in reputation requests; credentials/fragments are always withheld. */
	includeUrlQueryParameters: z.boolean().default(false),
	logger: z.any().optional(), // pino.Logger compatible
});

export type SDKConfig = z.infer<typeof SDKConfigSchema>;
/** Constructor input; fields with schema defaults may be omitted. */
export type SDKConfigInput = z.input<typeof SDKConfigSchema>;

/**
 * Security Check Request
 */
export const CheckRequestSchema = z.object({
	action: z.string().min(1),
	resource: z.string().min(1),
	/** Additional typed artifacts extracted from a structured tool call. */
	artifacts: z.array(ArtifactSchema).optional(),
	context: z.record(z.unknown()).optional(),
	sessionId: z.string().optional(),
	metadata: z.record(z.unknown()).optional(),
});

export type CheckRequest = z.infer<typeof CheckRequestSchema>;

/**
 * Security Check Result
 */
export const CheckResultSchema = z.object({
	allowed: z.boolean(),
	decision: z.enum(["allow", "deny", "ask"]),
	confidence: z.number().min(0).max(1),
	reason: z.string().optional(),
	threatId: z.string().optional(),
	metadata: z.record(z.unknown()).optional(),
});

export type CheckResult = z.infer<typeof CheckResultSchema>;

/**
 * Event Types
 */
export type DecisionEvent = {
	type: "decision";
	timestamp: number;
	request: CheckRequest;
	result: CheckResult;
};

export type ErrorEvent = {
	type: "error";
	timestamp: number;
	error: Error;
	context?: unknown;
};

export type SDKEvent = DecisionEvent | ErrorEvent;

/**
 * Event Listener Types
 */
export type EventListener<T extends SDKEvent = SDKEvent> = (event: T) => void;

/**
 * Middleware Context
 */
export interface MiddlewareContext {
	request: CheckRequest;
	result?: CheckResult;
	error?: Error;
	next: () => Promise<void>;
}

export type MiddlewareFn = (ctx: MiddlewareContext) => Promise<void> | void;
