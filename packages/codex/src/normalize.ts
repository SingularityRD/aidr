import { redactValue } from "./redaction.js";
import {
	CODEX_CONNECTOR,
	type CodexHookInput,
	CodexNormalizationError,
	type CodexPhase,
	type CodexRuntimeIdentity,
	createId,
	type NormalizedRuntimeEvent,
	RUNTIME_SCHEMA_VERSION,
	type RuntimeEventKind,
	sha256,
	stableJson,
} from "./types.js";

function requiredString(value: unknown, field: string): string {
	if (
		typeof value !== "string" ||
		value.trim() === "" ||
		value.length > 256 ||
		/[\u0000\r\n]/.test(value) ||
		/(?:bearer\s+|(?:api[_-]?key|secret|token|password)\s*[:=]|-----begin )/i.test(value)
	)
		throw new CodexNormalizationError(`${field} is required, bounded, and non-sensitive`);
	return value.trim();
}
function objectValue(value: unknown, field: string): Record<string, unknown> {
	if (value === undefined) return {};
	if (value === null || typeof value !== "object" || Array.isArray(value))
		throw new CodexNormalizationError(`${field} must be a JSON object`);
	return value as Record<string, unknown>;
}
function phaseOf(input: CodexHookInput): CodexPhase {
	const value = input.phase ?? input.event ?? input.type;
	if (
		value === undefined ||
		value === "pre_tool_use" ||
		value === "pre_tool" ||
		value === "before_tool_call"
	)
		return "pre_tool_use";
	if (value === "post_tool_use" || value === "post_tool" || value === "after_tool_call")
		return "post_tool_use";
	throw new CodexNormalizationError("unsupported Codex hook phase");
}
function kindOf(phase: CodexPhase, input: CodexHookInput): RuntimeEventKind {
	if (phase === "pre_tool_use") return "tool_call_requested";
	if (input.status === "failed" || input.error !== undefined) return "execution_failed";
	if (input.status === "unknown") return "execution_unknown";
	return "execution_completed";
}
export function normalizeCodexHookInput(
	input: CodexHookInput,
	identity: CodexRuntimeIdentity,
	now = new Date(),
): NormalizedRuntimeEvent {
	const phase = phaseOf(input);
	const toolName = requiredString(input.tool_name ?? input.tool, "tool_name");
	const callId = requiredString(input.call_id, "call_id");
	const args = objectValue(input.arguments ?? input.input ?? input.args, "arguments");
	const redactedInput = redactValue(args);
	const target = redactValue(input.target ?? input.cwd ?? "unknown");
	const observationSource = input.result ?? input.output ?? input.error;
	const observation = observationSource === undefined ? undefined : redactValue(observationSource);
	const sequence = input.sequence ?? identity.sequence ?? 1;
	if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1)
		throw new CodexNormalizationError("sequence must be a positive safe integer");
	for (const [key, value] of Object.entries(identity))
		if (key !== "sequence") requiredString(value, key);
	const inputCanonical = stableJson(redactedInput);
	const targetCanonical = stableJson(target);
	const actionHash = sha256(`${CODEX_CONNECTOR}:${toolName}:${inputCanonical}:${targetCanonical}`);
	return {
		eventId: createId("codex-event"),
		schemaVersion: RUNTIME_SCHEMA_VERSION,
		kind: kindOf(phase, input),
		phase,
		scope: { ...identity, sequence },
		connector: CODEX_CONNECTOR,
		toolName,
		callId,
		input: redactedInput,
		observation,
		inputHash: sha256(inputCanonical),
		targetHash: sha256(targetCanonical),
		actionHash,
		payloadHash: sha256(stableJson({ input: redactedInput, observation })),
		eventTime: now.toISOString(),
		sequence,
		idempotencyKey: sha256(`${identity.tenantId}:${identity.instanceId}:${callId}:${sequence}`),
		redaction: "redacted",
	};
}
