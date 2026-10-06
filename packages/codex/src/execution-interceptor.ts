import { normalizeCodexHookInput } from "./normalize.js";
import type {
	SignedIngressRequest,
	SignedIngressResponse,
} from "./signed-ingress.js";
import type {
	CodexHookInput,
	CodexRuntimeIdentity,
	NormalizedRuntimeEvent,
	PolicyBinding,
	RedactedValue,
} from "./types.js";

export type IngressTargetKind = "command" | "file" | "url" | "host" | "resource";
export type IngressDataClass = "public" | "internal" | "confidential" | "sensitive";
export type IngressRiskClass = "read_only" | "low" | "medium" | "high";

export interface RegisteredCodexTool {
	toolName: string;
	capability: string;
	schemaHash: string;
	riskClass: IngressRiskClass;
	dataClass: IngressDataClass;
	mutating: boolean;
	target: (input: RedactedValue, event: NormalizedRuntimeEvent) => {
		kind: IngressTargetKind;
		value: string;
	};
	title?: (event: NormalizedRuntimeEvent) => string;
}

export class CodexExecutionInterceptError extends Error {
	constructor(readonly code: string) {
		super(code);
		this.name = "CodexExecutionInterceptError";
	}
}

function validIdentifier(value: string): boolean {
	return (
		value.trim() === value &&
		value.length > 0 &&
		value.length <= 256 &&
		!/[\u0000\r\n]/.test(value) &&
		!/(?:bearer\s+|(?:password|secret|token|private[_-]?key)\s*[:=])/i.test(value)
	);
}

function validDigest(value: string): boolean {
	return /^[a-f0-9]{64}$/.test(value);
}

function validateRegistration(tool: RegisteredCodexTool): void {
	if (
		!validIdentifier(tool.toolName) ||
		!validIdentifier(tool.capability) ||
		!validDigest(tool.schemaHash) ||
		!(["read_only", "low", "medium", "high"] as const).includes(tool.riskClass) ||
		!(["public", "internal", "confidential", "sensitive"] as const).includes(tool.dataClass) ||
		typeof tool.mutating !== "boolean" ||
		typeof tool.target !== "function" ||
		(tool.riskClass === "read_only" && tool.mutating)
	) {
		throw new CodexExecutionInterceptError("codex_tool_registration_invalid");
	}
}

export class TypedCodexToolRegistry {
	private readonly tools = new Map<string, RegisteredCodexTool>();

	constructor(tools: RegisteredCodexTool[]) {
		if (tools.length === 0) {
			throw new CodexExecutionInterceptError("codex_tool_registry_empty");
		}
		for (const tool of tools) {
			validateRegistration(tool);
			if (this.tools.has(tool.toolName)) {
				throw new CodexExecutionInterceptError("codex_tool_registration_duplicate");
			}
			this.tools.set(tool.toolName, Object.freeze({ ...tool }));
		}
	}

	require(toolName: string): RegisteredCodexTool {
		const tool = this.tools.get(toolName);
		if (!tool) throw new CodexExecutionInterceptError("codex_tool_unregistered");
		return tool;
	}
}

export interface SignedIngressTransport {
	submit(request: SignedIngressRequest): Promise<SignedIngressResponse>;
}

export interface CodexExecutionInterceptorOptions {
	identity: CodexRuntimeIdentity;
	principal: { id: string; credentialDigest: string };
	policy: PolicyBinding;
	registry: TypedCodexToolRegistry;
	transport: SignedIngressTransport;
	now?: () => Date;
}

export interface CodexExecutionInterceptResult {
	decision: "suppress_local_execution";
	outcome: "server_executed" | "governed_handoff";
	suppressLocalExecution: true;
	route: "read_only" | "wt05";
	receiptDigest: string;
	replayed: boolean;
	event: NormalizedRuntimeEvent;
}

function scope(identity: CodexRuntimeIdentity): Record<string, string> {
	return {
		tenant_id: identity.tenantId,
		team_id: identity.teamId,
		endpoint_id: identity.endpointId,
		agent_id: identity.agentId,
		instance_id: identity.instanceId,
		session_id: identity.sessionId,
	};
}

function buildRequest(
	event: NormalizedRuntimeEvent,
	tool: RegisteredCodexTool,
	options: CodexExecutionInterceptorOptions,
): SignedIngressRequest {
	const target = tool.target(event.input, event);
	if (
		!(["command", "file", "url", "host", "resource"] as const).includes(target.kind) ||
		!validIdentifier(target.value)
	) {
		throw new CodexExecutionInterceptError("codex_tool_target_invalid");
	}
	const eventScope = scope(event.scope);
	const now = (options.now ?? (() => new Date()))().toISOString();
	const title = tool.title?.(event) ?? `${tool.capability} via ${event.toolName}`;
	if (!validIdentifier(title)) throw new CodexExecutionInterceptError("codex_tool_title_invalid");

	return {
		schema_version: "aidr-signed-http-ingress/v1",
		principal: {
			id: options.principal.id,
			credential_digest: { algorithm: "sha256", value: options.principal.credentialDigest },
		},
		event: {
			event_id: event.eventId,
			schema_version: event.schemaVersion,
			kind: "tool_call_requested",
			scope: eventScope,
			event_time: event.eventTime,
			ingest_time: now,
			sequence: event.sequence,
			idempotency_key: event.idempotencyKey,
			correlation_id: event.callId,
			source: event.connector,
			connector_version: event.scope.connectorVersion,
			policy: {
				version: options.policy.version,
				hash: { algorithm: "sha256", value: options.policy.hash },
			},
			redaction: event.redaction,
			payload_hash: { algorithm: "sha256", value: event.payloadHash },
			metadata: { tool_name: event.toolName, call_id: event.callId, phase: event.phase },
		},
		tool: {
			scope: eventScope,
			source: event.connector,
			connector_version: event.scope.connectorVersion,
			tool_name: tool.toolName,
			capability: tool.capability,
			schema_hash: { algorithm: "sha256", value: tool.schemaHash },
			arguments: event.input,
			target,
			data_class: tool.dataClass,
			mutating: tool.mutating,
			requested_at: event.eventTime,
		},
		connector: event.connector,
		title,
		requested_by: event.scope.agentId,
		target: target.value,
	};
}

export function createCodexExecutionInterceptor(options: CodexExecutionInterceptorOptions) {
	if (
		!validIdentifier(options.principal.id) ||
		!validDigest(options.principal.credentialDigest) ||
		!validIdentifier(options.policy.version) ||
		!validDigest(options.policy.hash)
	) {
		throw new CodexExecutionInterceptError("codex_execution_interceptor_invalid");
	}
	return {
		async execute(input: CodexHookInput): Promise<CodexExecutionInterceptResult> {
			const phase = input.hook_event_name ?? input.phase ?? input.event ?? input.type;
			if (
				phase === "PostToolUse" ||
				phase === "post_tool_use" ||
				phase === "post_tool" ||
				phase === "after_tool_call"
			) {
				throw new CodexExecutionInterceptError("codex_post_tool_execution_forbidden");
			}
			const event = normalizeCodexHookInput(input, options.identity);
			const registration = options.registry.require(event.toolName);
			const receipt = await options.transport.submit(buildRequest(event, registration, options));
			return {
				decision: "suppress_local_execution",
				outcome: receipt.route === "read_only" ? "server_executed" : "governed_handoff",
				suppressLocalExecution: true,
				route: receipt.route,
				receiptDigest: receipt.receipt_digest.value,
				replayed: receipt.replayed,
				event,
			};
		},
	};
}
