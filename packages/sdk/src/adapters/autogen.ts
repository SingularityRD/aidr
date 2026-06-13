/**
 * AutoGen integration adapter for AIDR SDK
 *
 * Provides seamless integration with AutoGen multi-agent systems by
 * intercepting messages between agents and securing function calls
 * and code execution operations.
 */

import type { AIDRClient } from "../client.js";
import type { CheckResult } from "../config.js";

/**
 * Options for AIDRSpeaker wrapper
 */
export interface AIDRSpeakerOptions {
	/** Session ID for tracking security decisions */
	sessionId?: string;
	/** Whether to throw on deny verdict (default: false - messages are silently dropped) */
	throwOnDeny?: boolean;
	/** Whether to block code execution agents (default: true) */
	blockCodeExecution?: boolean;
	/** Allow specific agent roles */
	allowedRoles?: string[];
	/** Deny specific agent roles */
	deniedRoles?: string[];
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
	 * @param message - The AutoGen message
	 * @param sender - The sender agent information
	 * @returns Promise resolving to validation result
	 * @throws AIDRAutoGenError if verdict is deny and throwOnDeny is true
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

			if (this.options.throwOnDeny) {
				throw new AIDRAutoGenError(
					`AIDR: Message blocked - denied role: ${sender.role}`,
					verdict,
					message,
					sender,
				);
			}

			return { allowed: false, verdict };
		}

		if (this.options.allowedRoles && !this.options.allowedRoles.includes(sender.role || "")) {
			const verdict: CheckResult = {
				allowed: false,
				decision: "deny",
				confidence: 1.0,
				reason: `Sender role '${sender.role}' is not in allowed roles list`,
			};

			if (this.options.throwOnDeny) {
				throw new AIDRAutoGenError(
					`AIDR: Message blocked - role not allowed: ${sender.role}`,
					verdict,
					message,
					sender,
				);
			}

			return { allowed: false, verdict };
		}

		// Validate message content
		const contentVerdict = await this.aidrClient.check({
			action: "read",
			resource: message.content || "",
			context: {
				sessionId: this.options.sessionId || `autogen_${Date.now()}`,
				tool: "autogen_message",
				type: "message_content",
				sender: sender.name,
				senderRole: sender.role,
			},
		});

		if (contentVerdict.decision === "deny") {
			if (this.options.throwOnDeny) {
				throw new AIDRAutoGenError(
					`AIDR: ${contentVerdict.reason || "Message content blocked"}`,
					contentVerdict,
					message,
					sender,
				);
			}

			return { allowed: false, verdict: contentVerdict };
		}

		// Validate function calls
		if (message.function_call || message.tool_calls) {
			const functionVerdict = await this.validateFunctionCalls(message, sender);

			if (functionVerdict.decision === "deny") {
				if (this.options.throwOnDeny) {
					throw new AIDRAutoGenError(
						`AIDR: ${functionVerdict.reason || "Function call blocked"}`,
						functionVerdict,
						message,
						sender,
					);
				}

				return { allowed: false, verdict: functionVerdict };
			}

			// Block code execution if configured
			if (this.options.blockCodeExecution !== false) {
				const codeVerdict = await this.checkCodeExecution(message, sender);

				if (codeVerdict.decision === "deny") {
					if (this.options.throwOnDeny) {
						throw new AIDRAutoGenError(
							`AIDR: ${codeVerdict.reason || "Code execution blocked"}`,
							codeVerdict,
							message,
							sender,
						);
					}

					return { allowed: false, verdict: codeVerdict };
				}
			}
		}

		// All checks passed
		const combinedVerdict: CheckResult = {
			allowed: true,
			decision: "allow",
			confidence: contentVerdict.confidence,
			reason: "Message validated successfully",
		};

		return {
			allowed: true,
			verdict: combinedVerdict,
			filteredMessage: message,
		};
	}

	/**
	 * Validate function/tool calls in the message
	 *
	 * @param message - The AutoGen message
	 * @param sender - The sender agent
	 * @returns AIDR verdict for function calls
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

			if (verdict.decision === "deny") {
				return {
					...verdict,
					reason: `Function call '${func.name}' blocked: ${verdict.reason}`,
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

		if (verdict.decision === "deny") {
			if (this.options.throwOnDeny) {
				throw new AIDRAutoGenError(
					`AIDR: Function response blocked for '${functionName}': ${verdict.reason}`,
					verdict,
					{ content: response, role: "function" },
					sender,
				);
			}

			return { allowed: false, verdict };
		}

		return {
			allowed: true,
			verdict,
			filteredMessage: { content: response, role: "function" },
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

			if (verdict.decision === "deny") {
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
			await handler(message, sender);
		}
		// If not allowed, message is silently dropped (or error thrown if throwOnDeny)
	};
}
