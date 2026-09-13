/**
 * Singularity AIDR SDK — Universal SDK for AI agent security integration
 *
 * This SDK provides adapters and clients for integrating AIDR security
 * into various AI agent frameworks and applications.
 *
 * @module @singularityrd/aidr-sdk
 */

import { VERSION } from "@singularityrd/aidr-core";

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
// Licence/entitlement types (provider-agnostic).
//
// There is deliberately no payment-provider client in the SDK. Lemon Squeezy was
// removed after its webhook was found to perform no signature verification, and
// billing/entitlement issuance is a server-side concern handled by the
// signature-verified Stripe webhook Edge Function.
export type { LicenseValidationResult, UsageInfo } from "./license.js";
// Bundled rule-data resolution (threats + allowlists). Exported so host
// applications, health checks and tests can report exactly where detection data
// came from instead of assuming the cwd.
export type {
	AssetKind,
	DataDirOptions,
	DataDirResolution,
	DataDirSource,
} from "./bundled-dirs.js";
export {
	AIDRDataDirError,
	AIDRInitError,
	getBundledDataDirs,
	resolveDataDirs,
} from "./bundled-dirs.js";
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
export type { MiddlewareEnforcementOptions } from "./middleware.js";
// Fail-closed enforcement (shared by every adapter and middleware)
export type {
	ApprovalCallback,
	EnforcementBlock,
	EnforcementOptions,
	EnforcementOutcome,
} from "./enforcement.js";
export {
	ASK_DENIED_MESSAGE,
	ASK_REQUIRES_APPROVAL_MESSAGE,
	DENY_MESSAGE_PREFIX,
	INDETERMINATE_MESSAGE,
	INDETERMINATE_METADATA_KEY,
	enforceCheckResult,
	isInconsistent,
	isIndeterminate,
} from "./enforcement.js";
export type {
	ToolOutputDelivery,
	ToolOutputGuardOptions,
	ToolOutputGuardResult,
	ToolOutputFinding,
	ToolOutputInspection,
	ToolOutputInspectionStatus,
	ToolOutputUnsafeAction,
} from "./output-guard.js";
export {
	AIDRToolOutputError,
	DEFAULT_TOOL_OUTPUT_MAX_BYTES,
	MAX_TOOL_OUTPUT_MAX_BYTES,
	enforceToolOutput,
	formatToolOutputBlockReason,
	guardToolOutput,
	scanToolOutput,
} from "./output-guard.js";
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
export const SDK_VERSION = VERSION;

/**
 * SDK name
 */
export const SDK_NAME = "@singularityrd/aidr-sdk";
