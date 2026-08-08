import { createHash, randomUUID } from "node:crypto";

export const CODEX_CONNECTOR = "codex" as const;
export const RUNTIME_SCHEMA_VERSION = "ai-runtime/v1" as const;
export type RedactedValue =
	| null
	| boolean
	| number
	| string
	| RedactedValue[]
	| { [key: string]: RedactedValue };
export type CodexPhase = "pre_tool_use" | "post_tool_use";
export type RuntimeEventKind =
	| "tool_call_requested"
	| "execution_completed"
	| "execution_failed"
	| "execution_unknown";
export type PolicyDecision = "allow" | "deny" | "require_approval";

export interface CodexRuntimeIdentity {
	tenantId: string;
	teamId: string;
	endpointId: string;
	agentId: string;
	instanceId: string;
	sessionId: string;
	connectorVersion: string;
	sequence?: number;
}

export interface CodexHookInput {
	event?: unknown;
	type?: unknown;
	phase?: unknown;
	tool_name?: unknown;
	tool?: unknown;
	call_id?: unknown;
	session_id?: unknown;
	arguments?: unknown;
	input?: unknown;
	args?: unknown;
	target?: unknown;
	cwd?: unknown;
	result?: unknown;
	output?: unknown;
	error?: unknown;
	status?: unknown;
	sequence?: unknown;
}

export interface NormalizedRuntimeEvent {
	eventId: string;
	schemaVersion: typeof RUNTIME_SCHEMA_VERSION;
	kind: RuntimeEventKind;
	phase: CodexPhase;
	scope: CodexRuntimeIdentity;
	connector: typeof CODEX_CONNECTOR;
	toolName: string;
	callId: string;
	input: RedactedValue;
	observation?: RedactedValue;
	inputHash: string;
	targetHash: string;
	actionHash: string;
	payloadHash: string;
	eventTime: string;
	sequence: number;
	idempotencyKey: string;
	redaction: "redacted";
}

export interface PolicyBinding {
	version: string;
	hash: string;
}
export interface CentralPolicyDecision {
	decision: PolicyDecision;
	decisionId: string;
	reasonCode: string;
	policy: PolicyBinding;
	approvalId?: string;
}
export interface PolicyHandoff {
	decide(event: NormalizedRuntimeEvent): Promise<CentralPolicyDecision>;
	publish(
		event: NormalizedRuntimeEvent,
	): Promise<{ accepted: true } | { accepted: false; reasonCode: string }>;
}
export interface CodexHookResult {
	decision: PolicyDecision;
	reasonCode: string;
	decisionId: string;
	event: NormalizedRuntimeEvent | null;
	policy?: PolicyBinding;
	approvalId?: string;
}
export class CodexNormalizationError extends Error {
	readonly code = "codex_input_malformed";
}
export class CentralPolicyError extends Error {
	readonly code = "central_policy_unavailable";
}
export function sha256(value: string): string {
	return createHash("sha256").update(value, "utf8").digest("hex");
}
export function stableJson(value: unknown): string {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
	const record = value as Record<string, unknown>;
	return `{${Object.keys(record)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
		.join(",")}}`;
}
export function createId(prefix: string): string {
	return `${prefix}-${randomUUID()}`;
}
