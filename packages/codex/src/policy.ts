import { installedPrivacyRequired, PRIVACY_ROUTE_UNAVAILABLE } from "./privacy.js";
import {
	type CentralPolicyDecision,
	CentralPolicyError,
	type NormalizedRuntimeEvent,
	type PolicyBinding,
	type PolicyHandoff,
	RUNTIME_SCHEMA_VERSION,
} from "./types.js";

export interface CentralPolicyClientOptions {
	endpoint: string;
	apiKey?: string;
	timeoutMs?: number;
	fetchImpl?: typeof fetch;
}
const DENY_POLICY: PolicyBinding = { version: "unavailable", hash: "0".repeat(64) };
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
		if (await installedPrivacyRequired()) return failClosed(PRIVACY_ROUTE_UNAVAILABLE);
		if (!this.endpoint) return failClosed("central_policy_endpoint_missing");
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.timeoutMs);
		try {
			const body = JSON.stringify({ schema_version: RUNTIME_SCHEMA_VERSION, event });
			if (await installedPrivacyRequired()) return failClosed(PRIVACY_ROUTE_UNAVAILABLE);
			const response = await this.fetchImpl(`${this.endpoint}/v1/aidr/policy/decide`, {
				method: "POST",
				signal: controller.signal,
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					...(this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {}),
				},
				body,
			});
			if (!response.ok) return failClosed("central_policy_http_error");
			const decision = await response.json();
			if (await installedPrivacyRequired()) return failClosed(PRIVACY_ROUTE_UNAVAILABLE);
			return parseDecision(decision);
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
		_event: NormalizedRuntimeEvent,
	): Promise<{ accepted: true } | { accepted: false; reasonCode: string }> {
		// AutoSecOps intentionally has no bearer-authenticated runtime event route.
		// Machine events must use SignedIngressClient so caller identity, replay
		// state, exact body bytes and the resulting receipt are cryptographically bound.
		return { accepted: false, reasonCode: "central_signed_ingress_required" };
	}
}
