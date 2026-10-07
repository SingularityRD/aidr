/**
 * Singularity AIDR SDK — security client and framework-neutral middleware
 *
 * The generic middleware adapter is the supported extension point. Typed
 * framework adapters belong here only after a real product consumer needs one.
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
export { AIDRClient, HTTP_REQUEST_ACTION, MAX_CONTEXT_BODY_CHARS } from "./client.js";
export type {
	CheckRequest,
	CheckResult,
	DecisionEvent,
	ErrorEvent,
	EventListener,
	MiddlewareContext,
	MiddlewareFn,
	SDKConfig,
	SDKConfigInput,
	SDKEvent,
} from "./config.js";
export {
	CheckRequestSchema,
	CheckResultSchema,
	SDKConfigSchema,
} from "./config.js";
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
	enforceCheckResult,
	INDETERMINATE_MESSAGE,
	INDETERMINATE_METADATA_KEY,
	isInconsistent,
	isIndeterminate,
} from "./enforcement.js";
// Licence/entitlement types (provider-agnostic).
//
// There is deliberately no payment-provider client in the SDK. Lemon Squeezy was
// removed after its webhook was found to perform no signature verification, and
// billing/entitlement issuance is a server-side concern handled by the
// signature-verified Stripe webhook Edge Function.
export type { LicenseValidationResult, UsageInfo } from "./license.js";
export type { MiddlewareEnforcementOptions } from "./middleware.js";
// Middleware exports
export { createMiddleware } from "./middleware.js";
export type {
	ToolOutputDelivery,
	ToolOutputFinding,
	ToolOutputGuardOptions,
	ToolOutputGuardResult,
	ToolOutputInspection,
	ToolOutputInspectionStatus,
	ToolOutputUnsafeAction,
} from "./output-guard.js";
export {
	AIDRToolOutputError,
	DEFAULT_TOOL_OUTPUT_MAX_BYTES,
	enforceToolOutput,
	formatToolOutputBlockReason,
	guardToolOutput,
	MAX_TOOL_OUTPUT_MAX_BYTES,
	scanToolOutput,
} from "./output-guard.js";
export type {
	PrivacyGatewayOptions,
	PrivacyTextSendOptions,
	SDKPrivateOptions,
} from "./privacy-text.js";
export { AIDRPrivacyTextError } from "./privacy-text.js";
/**
 * SDK version
 */
export const SDK_VERSION = VERSION;

/**
 * SDK name
 */
export const SDK_NAME = "@singularityrd/aidr-sdk";
