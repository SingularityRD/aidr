/**
 * CrewAI integration adapter for AIDR SDK
 *
 * Provides seamless integration with CrewAI agents by wrapping tools
 * with security analysis through AIDR's evaluation pipeline.
 * Secures task delegation between agents and monitors tool usage across crew execution.
 */

import type { AIDRClient } from "../client.js";
import type { CheckRequest, CheckResult } from "../config.js";

/**
 * Interface for CrewAI tool structure
 */
export interface CrewAITool {
	name: string;
	description: string;
	run: (...args: any[]) => Promise<any> | any;
}

/**
 * Error thrown when AIDR blocks a CrewAI tool execution
 */
export class AIDRCrewSecurityError extends Error {
	constructor(
		message: string,
		public readonly verdict: CheckResult,
		public readonly toolName: string,
	) {
		super(message);
		this.name = "AIDRCrewSecurityError";
	}
}

/**
 * Options for AIDRCrewTool wrapper
 */
export interface AIDRCrewToolOptions {
	/** Session ID for tracking security decisions */
	sessionId?: string;
	/** Whether to throw on deny verdict (default: true) */
	throwOnDeny?: boolean;
	/** Custom metadata for the security check */
	metadata?: Record<string, any>;
}

/**
 * Wrapper class that adds AIDR security analysis to any CrewAI tool
 *
 * This class intercepts tool calls, performs security analysis using AIDR's
 * evaluation pipeline, and either allows, denies, or asks for approval based
 * on the verdict. It secures task delegation between agents in a crew.
 *
 * @example
 * ```typescript
 * const searchTool = new SerperDevTool();
 * const secureSearch = new AIDRCrewTool(searchTool, aidrClient);
 * const result = await secureSearch.run("search query");
 * ```
 */
export class AIDRCrewTool {
	/** Tool name - delegates to inner tool */
	public readonly name: string;

	/** Tool description - delegates to inner tool */
	public readonly description: string;

	constructor(
		private innerTool: CrewAITool,
		private aidrClient: AIDRClient,
		private options: AIDRCrewToolOptions = {},
	) {
		this.name = innerTool.name;
		this.description = innerTool.description;
	}

	/**
	 * Execute the tool with AIDR security analysis.
	 *
	 * This method:
	 * 1. Calls AIDR client to evaluate security
	 * 2. Handles the verdict (allow/deny/ask)
	 * 3. Executes the inner tool if allowed
	 * 4. Returns the tool result
	 *
	 * @param args - Tool arguments
	 * @returns Tool result
	 * @throws AIDRCrewSecurityError if verdict is deny and throwOnDeny is true
	 */
	async run(...args: any[]): Promise<any> {
		const toolName = this.innerTool.name || "unknown";

		// Build check request
		const checkRequest: CheckRequest = {
			action: toolName,
			resource: JSON.stringify(args),
			sessionId: this.options.sessionId,
			metadata: this.options.metadata,
		};

		// Get verdict from AIDR client
		const verdict = await this.aidrClient.check(checkRequest);

		// Handle deny verdict
		if (verdict.decision === "deny") {
			const errorMessage = `AIDR blocked: ${verdict.reason}`;

			if (this.options.throwOnDeny !== false) {
				throw new AIDRCrewSecurityError(errorMessage, verdict, toolName);
			}

			// Return error indication if not throwing
			return { error: errorMessage, blocked: true };
		}

		// Handle ask verdict - could implement approval flow here
		if (verdict.decision === "ask") {
			// For 'ask' verdicts, we could trigger an approval flow
			// For now, we log and proceed (approval flow could be implemented via options)
			console.warn(`Security warning for tool "${toolName}": ${verdict.reason}`);
		}

		// Execute the wrapped tool
		return this.innerTool.run(...args);
	}

	/**
	 * Get the wrapped inner tool.
	 * @returns The wrapped CrewAI tool
	 */
	getInnerTool(): CrewAITool {
		return this.innerTool;
	}

	/**
	 * Get current options.
	 * @returns Current AIDRCrewToolOptions
	 */
	getOptions(): AIDRCrewToolOptions {
		return { ...this.options };
	}

	/**
	 * Create a new AIDRCrewTool with updated options.
	 * @param newOptions - Options to merge with current options
	 * @returns New AIDRCrewTool instance with merged options
	 */
	withOptions(newOptions: Partial<AIDRCrewToolOptions>): AIDRCrewTool {
		return new AIDRCrewTool(this.innerTool, this.aidrClient, {
			...this.options,
			...newOptions,
		});
	}
}

/**
 * Factory function to wrap a CrewAI tool with AIDR security.
 *
 * @param tool - The CrewAI tool to wrap
 * @param client - AIDR client for security checks
 * @param options - Optional configuration
 * @returns Wrapped tool with AIDR security
 *
 * @example
 * ```typescript
 * const searchTool = new SerperDevTool();
 * const secureSearch = withCrewAIDR(searchTool, aidrClient);
 * ```
 */
export function withCrewAIDR(
	tool: CrewAITool,
	client: AIDRClient,
	options?: AIDRCrewToolOptions,
): AIDRCrewTool {
	return new AIDRCrewTool(tool, client, options);
}

/**
 * Batch wrap multiple CrewAI tools with AIDR security.
 *
 * @param tools - Array of tools to wrap
 * @param client - AIDR client for security checks
 * @param options - Optional configuration (applied to all tools)
 * @returns Array of wrapped tools
 *
 * @example
 * ```typescript
 * const tools = [new SerperDevTool(), new FileReadTool()];
 * const secureTools = wrapCrewToolsWithAIDR(tools, aidrClient);
 * const crew = new Crew({ agents, tasks, tools: secureTools });
 * ```
 */
export function wrapCrewToolsWithAIDR(
	tools: CrewAITool[],
	client: AIDRClient,
	options?: AIDRCrewToolOptions,
): AIDRCrewTool[] {
	return tools.map((tool) => new AIDRCrewTool(tool, client, options));
}

/**
 * Creates a CrewAI agent wrapper that monitors task delegation
 * between agents in a crew.
 *
 * @param agent - The CrewAI agent to wrap
 * @param client - AIDR client for security checks
 * @param options - Optional configuration
 * @returns Wrapped agent with AIDR security monitoring
 *
 * @example
 * ```typescript
 * const researcher = new Agent({ role: "Researcher", tools: [searchTool] });
 * const secureResearcher = wrapCrewAgentWithAIDR(researcher, aidrClient);
 * ```
 */
export function wrapCrewAgentWithAIDR(
	agent: any,
	client: AIDRClient,
	options?: AIDRCrewToolOptions,
): any {
	// Wrap all tools in the agent
	if (agent.tools && Array.isArray(agent.tools)) {
		agent.tools = agent.tools.map((tool: CrewAITool) => new AIDRCrewTool(tool, client, options));
	}

	// Monitor task execution if agent has execute_task method
	if (agent.executeTask) {
		const originalExecuteTask = agent.executeTask.bind(agent);
		agent.executeTask = async (...args: any[]) => {
			const taskInput = args[0];

			// Check task delegation
			const checkRequest: CheckRequest = {
				action: "agent_task_delegation",
				resource: typeof taskInput === "string" ? taskInput : JSON.stringify(taskInput),
				sessionId: options?.sessionId,
				metadata: {
					agentName: agent.role || agent.name || "unknown",
					...options?.metadata,
				},
			};

			const verdict = await client.check(checkRequest);

			if (verdict.decision === "deny") {
				throw new AIDRCrewSecurityError(
					`Task delegation blocked: ${verdict.reason}`,
					verdict,
					agent.role || agent.name || "unknown",
				);
			}

			return originalExecuteTask(...args);
		};
	}

	return agent;
}

/**
 * Creates a CrewAI crew wrapper that monitors tool usage
 * across the entire crew execution.
 *
 * @param crew - The CrewAI crew to wrap
 * @param client - AIDR client for security checks
 * @param options - Optional configuration
 * @returns Wrapped crew with AIDR security monitoring
 *
 * @example
 * ```typescript
 * const crew = new Crew({ agents, tasks });
 * const secureCrew = wrapCrewWithAIDR(crew, aidrClient);
 * await secureCrew.kickoff();
 * ```
 */
export function wrapCrewWithAIDR(
	crew: any,
	client: AIDRClient,
	options?: AIDRCrewToolOptions,
): any {
	// Wrap kickoff method to monitor crew execution
	if (crew.kickoff) {
		const originalKickoff = crew.kickoff.bind(crew);
		crew.kickoff = async (...args: any[]) => {
			// Log crew execution start
			console.info(
				`Starting secure crew execution with session ${options?.sessionId || "default"}`,
			);

			// Wrap all agent tools in the crew
			if (crew.agents && Array.isArray(crew.agents)) {
				crew.agents = crew.agents.map((agent: any) =>
					wrapCrewAgentWithAIDR(agent, client, options),
				);
			}

			try {
				const result = await originalKickoff(...args);
				console.info("Secure crew execution completed");
				return result;
			} catch (error) {
				if (error instanceof AIDRCrewSecurityError) {
					console.error(`Crew execution blocked: ${error.message}`);
				}
				throw error;
			}
		};
	}

	return crew;
}
