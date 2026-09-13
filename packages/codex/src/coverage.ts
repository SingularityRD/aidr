import { CODEX_CONNECTOR } from "./types.js";

export const CODEX_COVERAGE_SCHEMA_VERSION = "aidr-connector-coverage/v1" as const;

export type CodexHookEventName = "PreToolUse" | "PostToolUse";
export type CodexCoverageHealthStatus = "degraded" | "unhealthy";

export interface CodexEventInspectionCoverage {
	eventVisibility: {
		toolInput: true;
		toolOutput: boolean;
	};
	enforcement: {
		toolCall: "inline_blocking" | "none";
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
	eventCoverage: {
		preToolUse: boolean;
		postToolUse: boolean;
	};
	capabilities: {
		toolInputInspection: "inline_blocking" | "unavailable";
		toolOutputInspection: "unavailable" | "post_execution_observation";
		canBlockOutputBeforeModelConsumption: false;
	};
	claims: {
		inlineToolCallBlocking: boolean;
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
	const isPreToolUse = eventName === "PreToolUse";
	return {
		eventVisibility: {
			toolInput: true,
			toolOutput: !isPreToolUse,
		},
		enforcement: {
			toolCall: isPreToolUse ? "inline_blocking" : "none",
			outputBeforeModelConsumption: "unavailable",
		},
		outputInspection: isPreToolUse ? "unavailable" : "post_execution_observation",
		hostFailureBoundary: "fail_open_if_hook_is_not_invoked_or_does_not_emit_a_valid_deny",
	};
}

/**
 * Describe what the configured Codex hook events can actually observe and
 * enforce. This is capability evidence, not proof that Codex loaded or trusted
 * the hook on a particular endpoint.
 */
export function getCodexConnectorCoverageEvidence(
	configuredEvents: readonly CodexHookEventName[] = ["PreToolUse"],
): CodexConnectorCoverageEvidence {
	const events = [...new Set(configuredEvents)];
	const preToolUse = events.includes("PreToolUse");
	const postToolUse = events.includes("PostToolUse");
	const reasonCodes = [
		"host_hook_failure_is_fail_open",
		"runtime_hook_registration_and_trust_not_verified",
		postToolUse ? "tool_output_is_observation_only" : "tool_output_inspection_unavailable",
		"pre_model_output_blocking_unavailable",
	];
	if (!preToolUse) reasonCodes.unshift("pre_tool_use_enforcement_unavailable");

	return {
		schemaVersion: CODEX_COVERAGE_SCHEMA_VERSION,
		connector: CODEX_CONNECTOR,
		basis: "declared_connector_contract_not_runtime_registration",
		configuredEvents: events,
		eventCoverage: { preToolUse, postToolUse },
		capabilities: {
			toolInputInspection: preToolUse ? "inline_blocking" : "unavailable",
			toolOutputInspection: postToolUse ? "post_execution_observation" : "unavailable",
			canBlockOutputBeforeModelConsumption: false,
		},
		claims: {
			inlineToolCallBlocking: preToolUse,
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
