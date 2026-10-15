import { CODEX_CONNECTOR } from "./types.js";

export const CODEX_COVERAGE_SCHEMA_VERSION = "aidr-connector-coverage/v1" as const;

export type CodexHookEventName = "PreToolUse" | "PostToolUse" | "UserPromptSubmit";
export type CodexCoverageHealthStatus = "degraded" | "unhealthy";

/** Events the shipped configuration registers (README, `aidr setup` guidance). */
export const CODEX_SHIPPED_EVENTS: readonly CodexHookEventName[] = [
	"PreToolUse",
	"UserPromptSubmit",
	"PostToolUse",
];

/**
 * Matchers of the shipped registration (README, `aidr setup` guidance). Codex
 * 0.141.0 names MCP tools `mcp__<server>__<tool>` for `PreToolUse` and
 * `PostToolUse`, so MCP calls are inspected before they run and their results
 * after; `apply_patch` output carries no third-party content and is not matched.
 */
export const CODEX_SHIPPED_MATCHERS = {
	PreToolUse: "^(Bash|apply_patch|mcp__.+)$",
	PostToolUse: "^(Bash|mcp__.+)$",
} as const;

/**
 * Tool paths outside the shipped matchers or outside the host's tool-hook path
 * (CODEX_HOOKS_0.141.0_REFERENCE.md, "Tool coverage"). Reported, never hidden.
 */
export const CODEX_UNCOVERED_TOOL_PATHS = [
	"other_local_function_tools_outside_matcher",
	"hosted_tools_not_hooked_by_host",
	"specialized_tool_paths_that_opt_out_of_hooks",
	"write_stdin_polls_do_not_rerun_pre_tool_use",
	"apply_patch_output_not_matched",
] as const;

export interface CodexEventInspectionCoverage {
	eventVisibility: {
		toolInput: boolean;
		toolOutput: boolean;
		userPrompt: boolean;
	};
	enforcement: {
		toolCall: "inline_blocking" | "none";
		prompt: "inline_blocking" | "none";
		outputBeforeModelConsumption: "unavailable";
	};
	outputInspection: "unavailable" | "post_execution_observation";
	hostFailureBoundary: "fail_open_if_hook_is_not_invoked_or_does_not_emit_a_valid_deny";
}

export interface CodexConnectorCoverageEvidence {
	schemaVersion: typeof CODEX_COVERAGE_SCHEMA_VERSION;
	connector: typeof CODEX_CONNECTOR;
	basis: "declared_connector_contract_not_runtime_registration";
	configuredEvents: CodexHookEventName[];
	/** Matchers the shipped registration uses; not read from the endpoint. */
	toolMatchers: { PreToolUse?: string; PostToolUse?: string };
	uncoveredToolPaths: readonly string[];
	eventCoverage: {
		preToolUse: boolean;
		postToolUse: boolean;
		userPromptSubmit: boolean;
	};
	capabilities: {
		toolInputInspection: "inline_blocking" | "unavailable";
		toolOutputInspection: "unavailable" | "post_execution_observation";
		promptInspection: "inline_blocking" | "unavailable";
		canBlockOutputBeforeModelConsumption: false;
	};
	claims: {
		inlineToolCallBlocking: boolean;
		inlinePromptBlocking: boolean;
		inlineOutputBlocking: false;
	};
	hostFailureBoundary: {
		mode: "fail_open";
		connectorCanOverride: false;
		conditions: readonly [
			"hook_not_registered_or_not_trusted",
			"hook_process_crash_or_timeout",
			"malformed_or_unsupported_hook_output",
		];
	};
	health: {
		status: CodexCoverageHealthStatus;
		reasonCodes: string[];
		runtimeRegistrationVerified: false;
	};
}

export function inspectionCoverageForEvent(
	eventName: CodexHookEventName,
): CodexEventInspectionCoverage {
	const isPrompt = eventName === "UserPromptSubmit";
	const isPostToolUse = eventName === "PostToolUse";
	return {
		eventVisibility: {
			toolInput: !isPrompt,
			toolOutput: isPostToolUse,
			userPrompt: isPrompt,
		},
		enforcement: {
			toolCall: eventName === "PreToolUse" ? "inline_blocking" : "none",
			prompt: isPrompt ? "inline_blocking" : "none",
			outputBeforeModelConsumption: "unavailable",
		},
		outputInspection: isPostToolUse ? "post_execution_observation" : "unavailable",
		hostFailureBoundary: "fail_open_if_hook_is_not_invoked_or_does_not_emit_a_valid_deny",
	};
}

/**
 * Describe what the configured Codex hook events can actually observe and
 * enforce. This is capability evidence, not proof that Codex loaded or trusted
 * the hook on a particular endpoint.
 */
export function getCodexConnectorCoverageEvidence(
	configuredEvents: readonly CodexHookEventName[] = CODEX_SHIPPED_EVENTS,
): CodexConnectorCoverageEvidence {
	const events = [...new Set(configuredEvents)];
	const preToolUse = events.includes("PreToolUse");
	const postToolUse = events.includes("PostToolUse");
	const userPromptSubmit = events.includes("UserPromptSubmit");
	const reasonCodes = [
		"host_hook_failure_is_fail_open",
		"runtime_hook_registration_and_trust_not_verified",
		postToolUse ? "tool_output_is_observation_only" : "tool_output_inspection_unavailable",
		"pre_model_output_blocking_unavailable",
	];
	if (!userPromptSubmit) reasonCodes.push("prompt_inspection_unavailable");
	if (!preToolUse) reasonCodes.unshift("pre_tool_use_enforcement_unavailable");

	return {
		schemaVersion: CODEX_COVERAGE_SCHEMA_VERSION,
		connector: CODEX_CONNECTOR,
		basis: "declared_connector_contract_not_runtime_registration",
		configuredEvents: events,
		toolMatchers: {
			...(preToolUse ? { PreToolUse: CODEX_SHIPPED_MATCHERS.PreToolUse } : {}),
			...(postToolUse ? { PostToolUse: CODEX_SHIPPED_MATCHERS.PostToolUse } : {}),
		},
		uncoveredToolPaths: CODEX_UNCOVERED_TOOL_PATHS,
		eventCoverage: { preToolUse, postToolUse, userPromptSubmit },
		capabilities: {
			toolInputInspection: preToolUse ? "inline_blocking" : "unavailable",
			toolOutputInspection: postToolUse ? "post_execution_observation" : "unavailable",
			promptInspection: userPromptSubmit ? "inline_blocking" : "unavailable",
			canBlockOutputBeforeModelConsumption: false,
		},
		claims: {
			inlineToolCallBlocking: preToolUse,
			inlinePromptBlocking: userPromptSubmit,
			inlineOutputBlocking: false,
		},
		hostFailureBoundary: {
			mode: "fail_open",
			connectorCanOverride: false,
			conditions: [
				"hook_not_registered_or_not_trusted",
				"hook_process_crash_or_timeout",
				"malformed_or_unsupported_hook_output",
			],
		},
		health: {
			status: preToolUse ? "degraded" : "unhealthy",
			reasonCodes,
			runtimeRegistrationVerified: false,
		},
	};
}
