/**
 * LangChain integration adapter for AIDR SDK
 *
 * Provides seamless integration with LangChain agents by wrapping tools
 * with security analysis through AIDR's evaluation pipeline.
 */

import type { RunnableConfig } from "@langchain/core/runnables";
import { Tool } from "@langchain/core/tools";
import type { Decision, Verdict } from "@singularityrd/aidr-core";
import type { CheckRequest, CheckResult } from "../config.js";
import { enforceCheckResult } from "../enforcement.js";
import {
	formatToolOutputBlockReason,
	guardToolOutput,
	type ToolOutputGuardOptions,
} from "../output-guard.js";

/**
 * Options for AIDRTool wrapper
 */
export interface AIDRToolOptions {
	/** Session ID for tracking security decisions */
	sessionId?: string;
	/** Whether to throw on deny verdict (default: true) */
	throwOnDeny?: boolean;
	/** Whether to throw on ask verdict (default: false) */
	throwOnAsk?: boolean;
	/**
	 * Allow an indeterminate result (failed/inconsistent security check) to be
	 * routed to `onAsk`. Defaults to `false`: a broken check is never turned
	 * into an approval.
	 */
	allowApprovalOfIndeterminateResults?: boolean;
	/** Handler for deny verdict */
	onDeny?: (verdict: Verdict, input: unknown) => void;
	/**
	 * Caller-supplied human-approval callback for ask verdicts - returns true if
	 * approved. When omitted, an `ask` verdict blocks the tool call.
	 */
	onAsk?: (verdict: Verdict, input: unknown) => Promise<boolean>;
	/** Inspect the returned tool value before LangChain can deliver it to the model. */
	outputGuard?: ToolOutputGuardOptions;
}

/**
 * Security metadata returned with tool execution results
 */
export interface SecurityMetadata {
	/** AIDR verdict decision */
	decision: Decision;
	/** Verdict confidence (0-1) */
	confidence: number;
	/** Verdict category */
	category: string;
	/** Verdict severity */
	severity: "info" | "warning" | "critical";
	/** Matched threat ID if any */
	matchedThreatId: string | null;
	/** Reason messages */
	reasons: string[];
	/** Artifacts detected */
	artifacts: string[];
}

/**
 * Result from executing an AIDRTool-wrapped tool
 */
export interface AIDRToolResult {
	/** Tool output */
	output: string;
	/** Security analysis metadata */
	security: SecurityMetadata;
	/** Whether execution was allowed */
	allowed: boolean;
}

/**
 * Error thrown when AIDR blocks a tool execution
 */
export class AIDRSecurityError extends Error {
	constructor(
		message: string,
		public readonly verdict: Verdict,
		public readonly toolName: string,
		public readonly toolInput: unknown,
	) {
		super(message);
		this.name = "AIDRSecurityError";
	}
}

/**
 * AIDR client interface for making security checks
 */
export interface AIDRClient {
	check(request: CheckRequest): Promise<CheckResult>;
}

/**
 * Convert an SDK CheckResult into a core Verdict (used for callbacks).
 */
function asVerdictFrom(result: CheckResult): Verdict {
	return {
		decision: result.decision,
		category: "",
		confidence: result.confidence,
		severity: "info",
		source: "sdk",
		artifacts: [],
		matchedThreatId: result.threatId ?? null,
		reasons: result.reason ? [result.reason] : [],
	};
}

/**
 * Wrapper class that adds AIDR security analysis to any LangChain Tool
 *
 * This class intercepts tool calls, performs security analysis using AIDR's
 * evaluation pipeline, and either allows, denies, or asks for approval based
 * on the verdict.
 *
 * @example
 * ```typescript
 * const bashTool = new ShellTool();
 * const secureBash = new AIDRTool(bashTool, aidrClient);
 * const result = await secureBash.invoke("ls -la");
 * ```
 */
export class AIDRTool<T extends Tool> extends Tool {
	/** Tool name - delegates to inner tool */
	name: string;

	/** Tool description - delegates to inner tool */
	description: string;

	constructor(
		private innerTool: T,
		private aidrClient: AIDRClient,
		private options: AIDRToolOptions = {},
	) {
		super();
		this.name = `secure_${innerTool.name}`;
		this.description = `[AIDR Protected] ${innerTool.description}`;
	}

	/**
	 * Required abstract method from Tool base class.
	 * Delegates to invoke and returns just the output string.
	 */
	async _call(input: string): Promise<string> {
		const result = await this.invoke(input);
		return result.output;
	}

	/**
	 * Invoke method for LCEL (LangChain Expression Language) compatibility.
	 *
	 * Returns a structured result with both tool output and security metadata.
	 *
	 * Fail-closed: the inner tool is invoked only on an explicit `allow` verdict,
	 * or on an `ask` verdict that the caller-supplied `onAsk` callback
	 * explicitly approved. `deny` always blocks. An `ask` verdict with no
	 * approval callback — and any indeterminate (failed) check — returns
	 * `allowed: false` without executing; it is never silently executed.
	 *
	 * @param input - Tool input (string for simple tools, object for structured)
	 * @param config - Optional RunnableConfig
	 * @returns Promise resolving to AIDRToolResult
	 */
	async invoke(input: unknown, config?: RunnableConfig): Promise<AIDRToolResult> {
		// Normalize input to object format
		const args = typeof input === "string" ? { input } : (input as Record<string, unknown>);

		const checkResult = await this.aidrClient.check({
			action: "execute",
			resource: typeof input === "string" ? input : JSON.stringify(input),
			context: { toolName: this.innerTool.name, input: args },
		});

		const securityMetadata: SecurityMetadata = {
			decision: checkResult.decision,
			confidence: checkResult.confidence,
			category: "",
			severity: "info",
			matchedThreatId: checkResult.threatId ?? null,
			reasons: checkResult.reason ? [checkResult.reason] : [],
			artifacts: [],
		};

		const asVerdict: Verdict = asVerdictFrom(checkResult);

		const onAskOption = this.options.onAsk;
		const outcome = await enforceCheckResult(checkResult, {
			onAsk: onAskOption ? (result) => onAskOption(asVerdictFrom(result), input) : undefined,
			allowApprovalOfIndeterminateResults: this.options.allowApprovalOfIndeterminateResults,
		});

		// Handle deny verdict
		if (!outcome.execute && outcome.block === "deny") {
			this.options.onDeny?.(asVerdict, input);
			const errorMessage = `Security violation: ${checkResult.reason || "Unknown threat"}`;

			if (this.options.throwOnDeny !== false) {
				throw new AIDRSecurityError(errorMessage, asVerdict, this.innerTool.name, input);
			}

			return {
				output: `[BLOCKED] ${errorMessage}`,
				security: securityMetadata,
				allowed: false,
			};
		}

		// Handle ask verdict (and indeterminate results) - block unless approved
		if (!outcome.execute) {
			if (this.options.throwOnAsk) {
				throw new AIDRSecurityError(outcome.message, asVerdict, this.innerTool.name, input);
			}
			return {
				output: `[DENIED] ${outcome.message}`,
				security: securityMetadata,
				allowed: false,
			};
		}

		const result = await this.innerTool.invoke(args, config);

		// Handle different result types
		let output: string;
		if (typeof result === "string") {
			output = result;
		} else if (result && typeof result === "object") {
			output = JSON.stringify(result);
		} else {
			output = String(result);
		}

		const guardedOutput = guardToolOutput(output, this.options.outputGuard);
		if (guardedOutput.delivery === "block") {
			const reason = formatToolOutputBlockReason(guardedOutput.inspection);
			const outputVerdict: Verdict = {
				decision: "deny",
				category: "output_security",
				confidence: 1,
				severity: "critical",
				source: "sdk_output_guard",
				artifacts: [],
				matchedThreatId: guardedOutput.inspection.findings[0]?.ruleId ?? null,
				reasons: [reason],
			};
			this.options.onDeny?.(outputVerdict, input);
			if (this.options.throwOnDeny !== false) {
				throw new AIDRSecurityError(reason, outputVerdict, this.innerTool.name, input);
			}
			return {
				output: `[BLOCKED] ${reason}`,
				security: {
					decision: "deny",
					confidence: 1,
					category: "output_security",
					severity: "critical",
					matchedThreatId: outputVerdict.matchedThreatId,
					reasons: [reason],
					artifacts: [],
				},
				allowed: false,
			};
		}
		output = guardedOutput.output as string;

		return {
			output,
			security: securityMetadata,
			allowed: true,
		};
	}

	/**
	 * Get the wrapped inner tool.
	 * @returns The wrapped LangChain tool
	 */
	getInnerTool(): T {
		return this.innerTool;
	}

	/**
	 * Get current options.
	 * @returns Current AIDRToolOptions
	 */
	getOptions(): AIDRToolOptions {
		return { ...this.options };
	}

	/**
	 * Create a new AIDRTool with updated options.
	 * @param newOptions - Options to merge with current options
	 * @returns New AIDRTool instance with merged options
	 */
	withOptions(newOptions: Partial<AIDRToolOptions>): AIDRTool<T> {
		return new AIDRTool(this.innerTool, this.aidrClient, {
			...this.options,
			...newOptions,
		});
	}
}

/**
 * Factory function to wrap a LangChain tool with AIDR security.
 *
 * @param tool - The LangChain tool to wrap
 * @param client - AIDR client for security checks
 * @param options - Optional configuration
 * @returns Wrapped tool with AIDR security
 *
 * @example
 * ```typescript
 * const shellTool = new ShellTool();
 * const secureShell = withAIDR(shellTool, aidrClient);
 * ```
 */
export function withAIDR<T extends Tool>(
	tool: T,
	client: AIDRClient,
	options?: AIDRToolOptions,
): AIDRTool<T> {
	return new AIDRTool(tool, client, options);
}

/**
 * Batch wrap multiple tools with AIDR security.
 *
 * @param tools - Array of tools to wrap
 * @param client - AIDR client for security checks
 * @param options - Optional configuration (applied to all tools)
 * @returns Array of wrapped tools
 *
 * @example
 * ```typescript
 * const tools = [new ShellTool(), new FileTool()];
 * const secureTools = wrapToolsWithAIDR(tools, aidrClient);
 * const agent = new Agent({ tools: secureTools, llm });
 * ```
 */
export function wrapToolsWithAIDR<T extends Tool>(
	tools: T[],
	client: AIDRClient,
	options?: AIDRToolOptions,
): AIDRTool<T>[] {
	return tools.map((tool) => new AIDRTool(tool, client, options));
}
