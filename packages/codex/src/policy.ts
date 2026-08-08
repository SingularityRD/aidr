import {
	type CentralPolicyDecision,
	CentralPolicyError,
	type NormalizedRuntimeEvent,
	type PolicyBinding,
	type PolicyHandoff,
	RUNTIME_SCHEMA_VERSION,
	sha256,
} from "./types.js";

export interface CentralPolicyClientOptions {
	endpoint: string;
	apiKey?: string;
	timeoutMs?: number;
	fetchImpl?: typeof fetch;
}
const DENY_POLICY: PolicyBinding = { version: "unavailable", hash: "0".repeat(64) };
const AUTOSECOPS_POLICY_VERSION = "wt08-runtime-policy-v1";
const AUTOSECOPS_POLICY_HASH = sha256(AUTOSECOPS_POLICY_VERSION);

function toAutoSecOpsRuntimeEvent(event: NormalizedRuntimeEvent) {
	return {
		event_id: event.eventId,
		schema_version: RUNTIME_SCHEMA_VERSION,
		kind: event.kind,
		scope: {
			tenant_id: event.scope.tenantId,
			team_id: event.scope.teamId,
			endpoint_id: event.scope.endpointId,
			agent_id: event.scope.agentId,
			instance_id: event.scope.instanceId,
			session_id: event.scope.sessionId,
		},
		event_time: event.eventTime,
		ingest_time: new Date().toISOString(),
		sequence: event.sequence,
		idempotency_key: event.idempotencyKey,
		source: event.connector,
		connector_version: event.scope.connectorVersion,
		policy: {
			version: AUTOSECOPS_POLICY_VERSION,
			hash: { algorithm: "sha256", value: AUTOSECOPS_POLICY_HASH },
		},
		redaction: "redacted",
		payload_hash: { algorithm: "sha256", value: event.payloadHash },
		metadata: {
			tool_name: event.toolName,
			call_id: event.callId,
			phase: event.phase,
		},
	};
}
function failClosed(reasonCode: string): CentralPolicyDecision {
	return {
		decision: "deny",
		decisionId: `fail-closed-${reasonCode}`,
		reasonCode,
		policy: DENY_POLICY,
	};
}
function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}
function validDigest(value: unknown): value is string {
	return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value);
}
function parseDecision(value: unknown): CentralPolicyDecision {
	if (!isRecord(value)) throw new CentralPolicyError("central policy response is not an object");
	if (
		value.decision !== "allow" &&
		value.decision !== "deny" &&
		value.decision !== "require_approval"
	)
		throw new CentralPolicyError("central policy decision is invalid");
	if (
		typeof value.decision_id !== "string" ||
		value.decision_id.trim() === "" ||
		typeof value.reason_code !== "string" ||
		value.reason_code.trim() === ""
	)
		throw new CentralPolicyError("central policy response identifiers are missing");
	const policy = value.policy;
	if (
		!isRecord(policy) ||
		typeof policy.version !== "string" ||
		policy.version.trim() === "" ||
		!validDigest(policy.hash)
	)
		throw new CentralPolicyError("central policy binding is invalid");
	if (value.approval_id !== undefined && typeof value.approval_id !== "string")
		throw new CentralPolicyError("central approval binding is invalid");
	return {
		decision: value.decision,
		decisionId: value.decision_id,
		reasonCode: value.reason_code,
		policy: { version: policy.version, hash: policy.hash },
		approvalId: value.approval_id as string | undefined,
	};
}
export class CentralPolicyClient implements PolicyHandoff {
	private readonly endpoint: string;
	private readonly apiKey: string;
	private readonly timeoutMs: number;
	private readonly fetchImpl: typeof fetch;
	constructor(options: CentralPolicyClientOptions) {
		this.endpoint = options.endpoint.trim().replace(/\/+$/, "");
		this.apiKey = options.apiKey?.trim() ?? "";
		this.timeoutMs = options.timeoutMs ?? 1000;
		this.fetchImpl = options.fetchImpl ?? fetch;
	}
	async decide(event: NormalizedRuntimeEvent): Promise<CentralPolicyDecision> {
		if (!this.endpoint) return failClosed("central_policy_endpoint_missing");
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.timeoutMs);
		try {
			const response = await this.fetchImpl(`${this.endpoint}/v1/aidr/policy/decide`, {
				method: "POST",
				signal: controller.signal,
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					...(this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {}),
				},
				body: JSON.stringify({ schema_version: RUNTIME_SCHEMA_VERSION, event }),
			});
			if (!response.ok) return failClosed("central_policy_http_error");
			return parseDecision(await response.json());
		} catch (error) {
			return failClosed(
				error instanceof CentralPolicyError
					? "central_policy_malformed"
					: "central_policy_unavailable",
			);
		} finally {
			clearTimeout(timer);
		}
	}
	async publish(
		event: NormalizedRuntimeEvent,
	): Promise<{ accepted: true } | { accepted: false; reasonCode: string }> {
		if (!this.endpoint) return { accepted: false, reasonCode: "central_event_endpoint_missing" };
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.timeoutMs);
		try {
			const response = await this.fetchImpl(`${this.endpoint}/v1/aidr/runtime/events`, {
				method: "POST",
				signal: controller.signal,
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					...(this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {}),
				},
				body: JSON.stringify({ event: toAutoSecOpsRuntimeEvent(event) }),
			});
			return response.ok
				? { accepted: true }
				: { accepted: false, reasonCode: "central_event_http_error" };
		} catch {
			return { accepted: false, reasonCode: "central_event_unavailable" };
		} finally {
			clearTimeout(timer);
		}
	}
}
