/**
 * AutoGen integration adapter for AIDR SDK
 *
 * Provides seamless integration with AutoGen multi-agent systems by
 * intercepting messages between agents and securing function calls
 * and code execution operations.
 */

import type { AIDRClient } from "../client.js";
import type { CheckResult } from "../config.js";
import {
	type ApprovalCallback,
	type EnforcementOutcome,
	enforceCheckResult,
} from "../enforcement.js";
import {
	formatToolOutputBlockReason,
	guardToolOutput,
	type ToolOutputGuardOptions,
} from "../output-guard.js";

/**
 * Options for AIDRSpeaker wrapper
 */
export interface AIDRSpeakerOptions {
	/** Session ID for tracking security decisions */
	sessionId?: string;
	/**
	 * Whether to throw AIDRAutoGenError instead of returning
	 * `{ allowed: false }` when a message must not proceed. Applies to every
	 * non-executing verdict: `deny`, and `ask` without (or refused) approval.
	 * Default: false — the message is blocked/returned as not allowed.
	 */
	throwOnDeny?: boolean;
	/** Whether to block code execution agents (default: true) */
	blockCodeExecution?: boolean;
	/**
	 * Caller-supplied human-approval callback for `ask` verdicts. When omitted
	 * (the default) an `ask` verdict blocks: the message is reported as not
	 * allowed instead of being treated as "all checks passed".
	 */
	onAsk?: ApprovalCallback;
	/**
	 * Allow an indeterminate result (failed/inconsistent security check) to be
	 * routed to `onAsk`. Defaults to `false`.
	 */
	allowApprovalOfIndeterminateResults?: boolean;
	/** Allow specific agent roles */
	allowedRoles?: string[];
	/** Deny specific agent roles */
	deniedRoles?: string[];
	/** Inspect model/tool message content before another AutoGen agent consumes it. */
	outputGuard?: ToolOutputGuardOptions;
}

/**
 * AutoGen message structure
 */
export interface AutoGenMessage {
	/** Message content */
	content?: string;
	/** Message role (user, assistant, function, etc.) */
	role?: string;
	/** Function call details */
	function_call?: {
		name?: string;
		arguments?: string;
	};
	/** Tool calls array (OpenAI format) */
	tool_calls?: Array<{
		id?: string;
		function?: {
			name?: string;
			arguments?: string;
		};
	}>;
	/** Message metadata */
	metadata?: Record<string, unknown>;
}

/**
 * AutoGen agent sender information
 */
export interface AutoGenSender {
	/** Agent name */
	name: string;
	/** Agent role */
	role?: string;
	/** Additional agent metadata */
	metadata?: Record<string, unknown>;
}

/**
 * Error thrown when AIDR blocks a message
 */
export class AIDRAutoGenError extends Error {
	constructor(
		message: string,
		public readonly verdict: CheckResult,
		public readonly autoGenMessage: AutoGenMessage,
		public readonly sender: AutoGenSender,
	) {
		super(message);
		this.name = "AIDRAutoGenError";
	}
}

/**
 * Result of message validation
 */
export interface MessageValidationResult {
	/** Whether the message was allowed */
	allowed: boolean;
	/** The AIDR verdict */
	verdict: CheckResult;
	/** Filtered/cleaned message if modifications were made */
	filteredMessage?: AutoGenMessage;
}

/**
 * AIDRSpeaker - Security interceptor for AutoGen agent communication
 *
 * This class wraps AutoGen speaker/agent functionality and adds AIDR
 * security validation for all inter-agent messages. It intercepts
 * function calls, validates content, and secures code execution agents.
 *
 * @example
 * ```typescript
 * const speaker = new AIDRSpeaker(aidrClient, {
 *   sessionId: "my_session",
 *   blockCodeExecution: true
 * });
 *
 * // In AutoGen conversation
 * await speaker.onMessage(message, sender);
 * ```
 */
export class AIDRSpeaker {
	/**
	 * Create a new AIDRSpeaker
	 *
	 * @param aidrClient - AIDR client for security checks
	 * @param options - Optional configuration
	 */
	constructor(
		private aidrClient: AIDRClient,
		private options: AIDRSpeakerOptions = {},
	) {}

	/**
	 * Handle and validate an incoming message
	 *
	 * This method:
	 * 1. Validates the sender role
	 * 2. Checks message content for security issues
	 * 3. Validates function/tool calls
	 * 4. Blocks code execution if configured
	 * 5. Returns validation result
	 *
	 * Enforcement is fail-closed: the message proceeds only when every check
	 * returns an explicit `allow`, or when an `ask` verdict was explicitly
	 * approved by the caller-supplied `onAsk` callback. An `ask` verdict with no
	 * approval callback — and any indeterminate (failed) check — is reported as
	 * `allowed: false`; it is never converted into a synthesized allow.
	 *
	 * @param message - The AutoGen message
	 * @param sender - The sender agent information
	 * @returns Promise resolving to validation result
	 * @throws AIDRAutoGenError when a check does not allow the message and throwOnDeny is true
	 */
	async onMessage(
		message: AutoGenMessage,
		sender: AutoGenSender,
	): Promise<MessageValidationResult> {
		// Check role-based filters first
		if (this.options.deniedRoles?.includes(sender.role || "")) {
			const verdict: CheckResult = {
				allowed: false,
				decision: "deny",
				confidence: 1.0,
				reason: `Sender role '${sender.role}' is in denied roles list`,
			};

			return this.blockMessage(
				`AIDR: Message blocked - denied role: ${sender.role}`,
				verdict,
				message,
				sender,
			);
		}

		if (this.options.allowedRoles && !this.options.allowedRoles.includes(sender.role || "")) {
			const verdict: CheckResult = {
				allowed: false,
				decision: "deny",
				confidence: 1.0,
				reason: `Sender role '${sender.role}' is not in allowed roles list`,
			};

			return this.blockMessage(
				`AIDR: Message blocked - role not allowed: ${sender.role}`,
				verdict,
				message,
				sender,
			);
		}

		const guardedContent = guardToolOutput(message.content ?? "", this.options.outputGuard);
		if (guardedContent.delivery === "block") {
			const reason = formatToolOutputBlockReason(guardedContent.inspection);
			return this.blockMessage(
				reason,
				{
					allowed: false,
					decision: "deny",
					confidence: 1,
					reason,
					metadata: { outputInspection: true },
				},
				message,
				sender,
			);
		}
		const inspectedMessage =
			guardedContent.delivery === "redact"
				? { ...message, content: guardedContent.output as string }
				: message;

		// Validate message content
		const contentVerdict = await this.aidrClient.check({
			action: "read",
			resource: inspectedMessage.content || "",
			context: {
				sessionId: this.options.sessionId || `autogen_${Date.now()}`,
				tool: "autogen_message",
				type: "message_content",
				sender: sender.name,
				senderRole: sender.role,
			},
		});

		const contentOutcome = await this.enforce(contentVerdict);
		if (!contentOutcome.execute) {
			return this.blockMessage(
				`AIDR: ${contentOutcome.message}`,
				contentVerdict,
				inspectedMessage,
				sender,
			);
		}
		const contentApproved = contentVerdict.decision !== "allow";

		// Validate function calls
		if (inspectedMessage.function_call || inspectedMessage.tool_calls) {
			const functionVerdict = await this.validateFunctionCalls(inspectedMessage, sender);

			const functionOutcome = await this.enforce(functionVerdict);
			if (!functionOutcome.execute) {
				return this.blockMessage(
					`AIDR: ${functionOutcome.message}`,
					functionVerdict,
					inspectedMessage,
					sender,
				);
			}

			// Block code execution if configured
			if (this.options.blockCodeExecution !== false) {
				const codeVerdict = await this.checkCodeExecution(inspectedMessage, sender);

				const codeOutcome = await this.enforce(codeVerdict);
				if (!codeOutcome.execute) {
					return this.blockMessage(
						`AIDR: ${codeOutcome.message}`,
						codeVerdict,
						inspectedMessage,
						sender,
					);
				}
			}
		}

		// Every check either returned an explicit allow or was approved by the
		// caller-supplied onAsk callback. No verdict is invented here.
		const combinedVerdict: CheckResult = {
			allowed: true,
			decision: "allow",
			confidence: contentVerdict.confidence,
			reason: contentApproved
				? "Message validated successfully (ask verdict approved by onAsk)"
				: "Message validated successfully",
		};

		return {
			allowed: true,
			verdict: combinedVerdict,
			filteredMessage: inspectedMessage,
		};
	}

	/**
	 * Apply the shared fail-closed enforcement semantic to a check result.
	 *
	 * @param result - The verdict returned by the AIDR client
	 * @returns The enforcement outcome (execute or block)
	 */
	private enforce(result: CheckResult): Promise<EnforcementOutcome> {
		return enforceCheckResult(result, {
			onAsk: this.options.onAsk,
			allowApprovalOfIndeterminateResults: this.options.allowApprovalOfIndeterminateResults,
		});
	}

	/**
	 * Report a message that must not proceed, throwing only when the caller
	 * opted into throwing.
	 */
	private blockMessage(
		reason: string,
		verdict: CheckResult,
		message: AutoGenMessage,
		sender: AutoGenSender,
	): MessageValidationResult {
		if (this.options.throwOnDeny) {
			throw new AIDRAutoGenError(reason, verdict, message, sender);
		}

		return { allowed: false, verdict };
	}

	/**
	 * Validate function/tool calls in the message
	 *
	 * @param message - The AutoGen message
	 * @param sender - The sender agent
	 * @returns AIDR verdict for function calls; the first verdict that is not an
	 * explicit `allow` (so `deny` and `ask` both stop the message from being
	 * treated as validated)
	 */
	private async validateFunctionCalls(
		message: AutoGenMessage,
		sender: AutoGenSender,
	): Promise<CheckResult> {
		const functionCalls: Array<{ name: string; arguments: string }> = [];

		// Extract function calls
		if (message.function_call) {
			functionCalls.push({
				name: message.function_call.name || "unknown",
				arguments: message.function_call.arguments || "{}",
			});
		}

		if (message.tool_calls) {
			for (const toolCall of message.tool_calls) {
				if (toolCall.function) {
					functionCalls.push({
						name: toolCall.function.name || "unknown",
						arguments: toolCall.function.arguments || "{}",
					});
				}
			}
		}

		// Validate each function call
		for (const func of functionCalls) {
			const verdict = await this.aidrClient.check({
				action: "execute",
				resource: `${func.name}(${func.arguments})`,
				context: {
					sessionId: this.options.sessionId || `autogen_${Date.now()}`,
					tool: "autogen_function_call",
					type: "function_call",
					sender: sender.name,
					senderRole: sender.role,
					functionName: func.name,
				},
			});

			if (verdict.decision !== "allow") {
				return {
					...verdict,
					reason: `Function call '${func.name}' not allowed: ${verdict.reason}`,
				};
			}
		}

		return {
			allowed: true,
			decision: "allow",
			confidence: 0.95,
			reason: "Function calls validated",
		};
	}

	/**
	 * Check for code execution attempts
	 *
	 * @param message - The AutoGen message
	 * @param sender - The sender agent
	 * @returns AIDR verdict for code execution
	 */
	private async checkCodeExecution(
		message: AutoGenMessage,
		_sender: AutoGenSender,
	): Promise<CheckResult> {
		const codeExecutionFunctions = [
			"execute_code",
			"run_code",
			"exec",
			"eval",
			"execute_shell",
			"run_shell",
			"bash",
			"python",
			"javascript",
			"code_interpreter",
		];

		const functionCalls: Array<{ name: string }> = [];

		if (message.function_call) {
			functionCalls.push({
				name: message.function_call.name || "unknown",
			});
		}

		if (message.tool_calls) {
			for (const toolCall of message.tool_calls) {
				if (toolCall.function?.name) {
					functionCalls.push({ name: toolCall.function.name });
				}
			}
		}

		for (const func of functionCalls) {
			if (
				codeExecutionFunctions.some((name) => func.name.toLowerCase().includes(name.toLowerCase()))
			) {
				return {
					allowed: false,
					decision: "deny",
					confidence: 0.95,
					reason: `Code execution function '${func.name}' is blocked by AIDR policy`,
				};
			}
		}

		// Check message content for code execution patterns
		const content = message.content || "";
		const codePatterns = [
			/```(?:python|bash|sh|shell|js|javascript)\s*\n/i,
			/\b(eval|exec|subprocess|os\.system)\s*\(/i,
		];

		for (const pattern of codePatterns) {
			if (pattern.test(content)) {
				return {
					allowed: false,
					decision: "deny",
					confidence: 0.85,
					reason: "Potential code execution detected in message content",
				};
			}
		}

		return {
			allowed: true,
			decision: "allow",
			confidence: 0.9,
			reason: "No code execution detected",
		};
	}

	/**
	 * Validate a function response before sending
	 *
	 * Fail-closed: the response is only forwarded when the check explicitly
	 * allows it (or an `ask` verdict was approved through `onAsk`).
	 *
	 * @param functionName - Name of the function
	 * @param response - Function response content
	 * @param sender - The agent sending the response
	 * @returns Promise resolving to validation result
	 */
	async validateFunctionResponse(
		functionName: string,
		response: string,
		sender: AutoGenSender,
	): Promise<MessageValidationResult> {
		const verdict = await this.aidrClient.check({
			action: "read",
			resource: response,
			context: {
				sessionId: this.options.sessionId || `autogen_${Date.now()}`,
				tool: "autogen_function_response",
				type: "function_response",
				sender: sender.name,
				functionName,
			},
		});

		const outcome = await this.enforce(verdict);
		if (!outcome.execute) {
			return this.blockMessage(
				`AIDR: Function response blocked for '${functionName}': ${outcome.message}`,
				verdict,
				{ content: response, role: "function" },
				sender,
			);
		}

		const guardedResponse = guardToolOutput(response, this.options.outputGuard);
		if (guardedResponse.delivery === "block") {
			const reason = formatToolOutputBlockReason(guardedResponse.inspection);
			return this.blockMessage(
				reason,
				{
					allowed: false,
					decision: "deny",
					confidence: 1,
					reason,
					metadata: { outputInspection: true },
				},
				{ content: response, role: "function" },
				sender,
			);
		}

		return {
			allowed: true,
			verdict,
			filteredMessage: { content: guardedResponse.output as string, role: "function" },
		};
	}

	/**
	 * Get current options
	 *
	 * @returns Current AIDRSpeakerOptions
	 */
	getOptions(): AIDRSpeakerOptions {
		return { ...this.options };
	}

	/**
	 * Create a new AIDRSpeaker with updated options
	 *
	 * @param newOptions - Options to merge with current options
	 * @returns New AIDRSpeaker instance with merged options
	 */
	withOptions(newOptions: Partial<AIDRSpeakerOptions>): AIDRSpeaker {
		return new AIDRSpeaker(this.aidrClient, {
			...this.options,
			...newOptions,
		});
	}

	/**
	 * Create a group chat filter function for AutoGen
	 *
	 * @returns Function that can be used as a speaker selection filter
	 *
	 * @example
	 * ```typescript
	 * const speaker = new AIDRSpeaker(aidrClient);
	 * const groupchat = new GroupChat({
	 *   speaker_selection_method: speaker.createGroupChatFilter(),
	 *   // ... other options
	 * });
	 * ```
	 */
	createGroupChatFilter(): (
		lastSpeaker: AutoGenSender,
		groupchat: unknown,
	) => Promise<AutoGenSender | null> {
		return async (lastSpeaker: AutoGenSender, _groupchat: unknown) => {
			// Validate the last speaker's message was processed
			// This is a placeholder - actual implementation would integrate
			// with the group chat's message history
			const verdict = await this.aidrClient.check({
				action: "read",
				resource: lastSpeaker.name,
				context: {
					sessionId: this.options.sessionId || `autogen_${Date.now()}`,
					tool: "autogen_speaker_filter",
					type: "speaker_validation",
					sender: lastSpeaker.name,
					senderRole: lastSpeaker.role,
				},
			});

			const outcome = await this.enforce(verdict);
			if (!outcome.execute) {
				return null; // Block this speaker
			}

			return lastSpeaker;
		};
	}
}

/**
 * Factory function to create an AIDRSpeaker
 *
 * @param client - AIDR client for security checks
 * @param options - Optional configuration
 * @returns AIDRSpeaker instance
 *
 * @example
 * ```typescript
 * const speaker = createAIDRSpeaker(aidrClient, {
 *   blockCodeExecution: true
 * });
 * ```
 */
export function createAIDRSpeaker(client: AIDRClient, options?: AIDRSpeakerOptions): AIDRSpeaker {
	return new AIDRSpeaker(client, options);
}

/**
 * Wrap an AutoGen agent's message handler with AIDR security
 *
 * @param handler - Original message handler function
 * @param client - AIDR client for security checks
 * @param options - Optional configuration
 * @returns Wrapped handler with AIDR security
 *
 * @example
 * ```typescript
 * const secureHandler = wrapAutoGenHandler(
 *   async (message, sender) => {
 *     // Original handler logic
 *   },
 *   aidrClient
 * );
 * ```
 */
export function wrapAutoGenHandler(
	handler: (message: AutoGenMessage, sender: AutoGenSender) => Promise<void>,
	client: AIDRClient,
	options?: AIDRSpeakerOptions,
): (message: AutoGenMessage, sender: AutoGenSender) => Promise<void> {
	const speaker = new AIDRSpeaker(client, options);

	return async (message: AutoGenMessage, sender: AutoGenSender) => {
		const result = await speaker.onMessage(message, sender);

		if (result.allowed) {
			await handler(result.filteredMessage ?? message, sender);
		}
		// Fail-closed: on deny, ask without approval, or a failed/indeterminate
		// check the message is dropped (or AIDRAutoGenError is thrown when
		// throwOnDeny is set). The handler is never called for `ask`.
	};
}
