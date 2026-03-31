/**
 * Singularity AIDR SDK — Universal SDK for AI agent security integration
 *
 * This SDK provides adapters and clients for integrating AIDR security
 * into various AI agent frameworks and applications.
 *
 * @module @singularityrd/aidr-sdk
 */

// Re-export core types for SDK consumers
export type {
	Artifact,
	Decision,
	Logger,
	ToolEvaluationContext,
	ToolEvaluationRequest,
	Verdict,
} from "@singularityrd/aidr-core";
export type {
	AIDRSpeakerOptions,
	AutoGenMessage,
	AutoGenSender,
	MessageValidationResult,
} from "./adapters/autogen.js";
// AutoGen adapter exports
export {
	AIDRAutoGenError,
	AIDRSpeaker,
	createAIDRSpeaker,
	wrapAutoGenHandler,
} from "./adapters/autogen.js";
export type {
	AIDRCrewToolOptions,
	CrewAITool,
} from "./adapters/crewai.js";
// CrewAI adapter exports
export {
	AIDRCrewSecurityError,
	AIDRCrewTool,
	withCrewAIDR,
	wrapCrewAgentWithAIDR,
	wrapCrewToolsWithAIDR,
	wrapCrewWithAIDR,
} from "./adapters/crewai.js";
export type {
	MiddlewareContext as GenericMiddlewareContext,
	MiddlewareFunction,
	MiddlewareOptions,
	NextFunction,
} from "./adapters/generic.js";
// Generic middleware adapter exports
export {
	AIDRMiddlewareError,
	composeMiddleware,
	createMiddleware as createGenericMiddleware,
	createMiddlewarePipeline,
	createSyncCompatibleMiddleware,
	wrapToolWithMiddleware,
} from "./adapters/generic.js";
export type {
	AIDRToolOptions,
	AIDRToolResult,
	SecurityMetadata,
} from "./adapters/langchain.js";
// LangChain adapter exports
export {
	AIDRSecurityError,
	AIDRTool,
	withAIDR,
	wrapToolsWithAIDR,
} from "./adapters/langchain.js";
export type { AIDRQueryEngineOptions } from "./adapters/llamaindex.js";
// LlamaIndex adapter exports
export {
	AIDRLlamaIndexError,
	AIDRQueryEngine,
	withAIDRLlamaIndex,
	wrapQueryEnginesWithAIDR,
} from "./adapters/llamaindex.js";
export type {
	BillingConfig,
	CheckoutData,
	LicenseValidationResult,
	UsageInfo,
} from "./billing.js";
// Billing exports
export { LemonSqueezyBilling } from "./billing.js";
// SDK client and config exports
export { AIDRClient } from "./client.js";
export type {
	CheckRequest,
	CheckResult,
	DecisionEvent,
	ErrorEvent,
	EventListener,
	MiddlewareContext,
	MiddlewareFn,
	SDKConfig,
	SDKEvent,
} from "./config.js";
export {
	CheckRequestSchema,
	CheckResultSchema,
	SDKConfigSchema,
} from "./config.js";
export type {
	FreemiumCheckResult,
	FreemiumOptions,
	LicenseInfo,
	LicenseManager,
	UsageRecord,
} from "./freemium.js";
// Freemium exports
export {
	DEFAULT_FREEMIUM_OPTIONS,
	FreemiumManager,
	InMemoryLicenseManager,
} from "./freemium.js";
// Middleware exports
export { createMiddleware } from "./middleware.js";
export type {
	LeaderboardEntry,
	Referral,
	ReferralConfig,
	ReferralStats,
	ReferralStorage,
} from "./referral.js";
// Referral system exports
export { ReferralSystem } from "./referral.js";
export type {
	SecurityEvent,
	Team,
	TeamDatabase,
	TeamMember,
} from "./team-dashboard.js";
// Team Dashboard exports
export { TeamDashboard } from "./team-dashboard.js";

/**
 * SDK version
 */
export const SDK_VERSION = "1.0.0";

/**
 * SDK name
 */
export const SDK_NAME = "@singularityrd/aidr-sdk";
