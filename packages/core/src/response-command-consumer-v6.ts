import { controlPlaneUrl } from "./clients/control-plane-url.js";
import {
	createDeviceAttestation,
	type DeviceAttestation,
	deviceAttestationPayload,
} from "./device-attestation.js";

/**
 * One-shot fleet response consumer. It is deliberately inert without a
 * separately installed and verified endpoint adapter. This transport does not
 * implement OS network isolation or pause host hooks by itself.
 */
export type FleetResponseCommandType =
	| "agent_pause"
	| "agent_resume"
	| "network_isolate"
	| "network_release";

export interface FleetResponseIdentity {
	tenantId: string;
	agentId: string;
}

export interface FleetResponseCommand {
	id: string;
	commandType: FleetResponseCommandType;
	expiresAt: string;
	attempt: number;
	rollbackOf: string | null;
}

export interface FleetResponseActionAdapter {
	/** An adapter must be provisioned for this exact enrollment identity. */
	readonly identity: FleetResponseIdentity;
	/** A narrow, explicit allowlist; the consumer never executes arbitrary code. */
	readonly supportedCommands: readonly FleetResponseCommandType[];
	/** Apply the requested local OS or host action. */
	execute(
		command: FleetResponseCommand,
		signal?: AbortSignal,
	): Promise<{ ok: true } | { ok: false; code: string }>;
	/** Observe the resulting host state independently of execute's return value. */
	verify(
		command: FleetResponseCommand,
		signal?: AbortSignal,
	): Promise<{ observed: true } | { observed: false; code: string }>;
}

export interface FleetResponseAuditEvent {
	result: FleetResponseCycleResult;
	/** The enrollment binding used for this cycle; keyHash is not the bearer. */
	attestation: DeviceAttestation;
}

export interface FleetResponseConsumerOptions {
	/** Supabase Functions base (e.g. https://api.example/functions) or /v1 base. */
	endpoint: string;
	apiKey: string;
	identity: FleetResponseIdentity;
	/** Installation identifier registered on the agent row during enrollment. */
	installationId: string;
	adapter?: FleetResponseActionAdapter;
	/** Best-effort local audit hook; failures never turn an outcome into success. */
	audit?: (event: FleetResponseAuditEvent) => void | Promise<void>;
	timeoutMs?: number;
	/** Maximum time allowed for each local execute or verify call. */
	actionTimeoutMs?: number;
	/** Explicitly opt into http://localhost for isolated development tests. */
	developmentLoopback?: boolean;
	fetchImpl?: typeof fetch;
	now?: () => number;
}

export type FleetResponseCycleResult =
	| { status: "idle" }
	| { status: "access_rejected"; stage: "poll" | "ack"; code: "http_401" | "http_403" }
	| { status: "invalid_command"; reason: string }
	| { status: "expired"; commandId: string }
	| { status: "rejected"; commandId: string; code: string }
	| { status: "failed"; commandId: string; code: string }
	| { status: "succeeded"; commandId: string }
	| {
			status: "outcome_unknown";
			commandId?: string;
			stage: "poll" | "ack" | "result";
			reason: string;
	  };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RESULT_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const COMMAND_TYPES: readonly FleetResponseCommandType[] = [
	"agent_pause",
	"agent_resume",
	"network_isolate",
	"network_release",
];
const MAX_RESPONSE_BYTES = 8192;

class FleetResponseActionInterrupted extends Error {}
class FleetResponseAccessRejected extends Error {
	constructor(readonly status: 401 | 403) {
		super(`http_${status}`);
	}
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUuid(value: unknown): value is string {
	return typeof value === "string" && UUID.test(value);
}

function resultCode(value: string, fallback: string): string {
	return RESULT_CODE.test(value) ? value : fallback;
}

function identityError(
	value: Record<string, unknown>,
	identity: FleetResponseIdentity,
): string | null {
	if (value.tenant_id !== undefined && value.tenant_id !== identity.tenantId)
		return "tenant_mismatch";
	if (value.agent_id !== undefined && value.agent_id !== identity.agentId) return "agent_mismatch";
	return null;
}

function rollbackError(value: Record<string, unknown>): string | null {
	if (value.rollback_of !== null && value.rollback_of !== undefined && !isUuid(value.rollback_of)) {
		return "invalid_rollback_reference";
	}
	const isRollback =
		value.command_type === "agent_resume" || value.command_type === "network_release";
	return isRollback !== isUuid(value.rollback_of) ? "rollback_reference_mismatch" : null;
}

function commandFrom(
	value: unknown,
	identity: FleetResponseIdentity,
	now: number,
): { ok: true; command: FleetResponseCommand } | { ok: false; reason: string; expiredId?: string } {
	if (!isRecord(value)) return { ok: false, reason: "command_not_object" };
	if (!isUuid(value.id)) return { ok: false, reason: "invalid_command_id" };
	const targetError = identityError(value, identity);
	if (targetError) return { ok: false, reason: targetError };
	if (!COMMAND_TYPES.includes(value.command_type as FleetResponseCommandType)) {
		return { ok: false, reason: "unsupported_command_type" };
	}
	if (typeof value.expires_at !== "string") return { ok: false, reason: "invalid_expiry" };
	const expires = Date.parse(value.expires_at);
	if (!Number.isFinite(expires)) return { ok: false, reason: "invalid_expiry" };
	if (
		!Number.isSafeInteger(value.attempt) ||
		(value.attempt as number) < 1 ||
		(value.attempt as number) > 5
	) {
		return { ok: false, reason: "invalid_attempt" };
	}
	const referenceError = rollbackError(value);
	if (referenceError) return { ok: false, reason: referenceError };
	if (expires <= now) return { ok: false, reason: "expired", expiredId: value.id };
	return {
		ok: true,
		command: {
			id: value.id,
			commandType: value.command_type as FleetResponseCommandType,
			expiresAt: value.expires_at,
			attempt: value.attempt as number,
			rollbackOf: (value.rollback_of as string | null | undefined) ?? null,
		},
	};
}

async function boundedJson(response: Response): Promise<unknown> {
	const length = Number(response.headers.get("content-length"));
	if (Number.isFinite(length) && length > MAX_RESPONSE_BYTES) throw new Error("response_too_large");
	if (!response.body) throw new Error("missing_response_body");
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let bytes = 0;
	try {
		while (true) {
			const next = await reader.read();
			if (next.done) break;
			bytes += next.value.byteLength;
			if (bytes > MAX_RESPONSE_BYTES) throw new Error("response_too_large");
			chunks.push(next.value);
		}
	} finally {
		reader.releaseLock();
	}
	const body = new Uint8Array(bytes);
	let offset = 0;
	for (const chunk of chunks) {
		body.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)) as unknown;
}

function responseEndpoint(endpoint: string, developmentLoopback: boolean): string {
	const parsed = new URL(endpoint);
	if (parsed.username || parsed.password || parsed.search || parsed.hash) {
		throw new Error("invalid_fleet_endpoint");
	}
	const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
	if (
		parsed.protocol !== "https:" &&
		!(developmentLoopback && parsed.protocol === "http:" && loopback)
	) {
		throw new Error("fleet_endpoint_requires_https");
	}
	if (!/^\/(?:functions(?:\/v1)?|v1)?\/?$/.test(parsed.pathname)) {
		throw new Error("invalid_fleet_endpoint_path");
	}
	return controlPlaneUrl(parsed.toString().replace(/\/$/, ""), "revocations");
}

export class FleetResponseCommandConsumer {
	private readonly url: string;
	private apiKey: string;
	private accessRejectionStatus: 401 | 403 | null = null;
	private readonly identity: FleetResponseIdentity;
	private readonly adapter?: FleetResponseActionAdapter;
	protected readonly audit?: FleetResponseConsumerOptions["audit"];
	private readonly fetchImpl: typeof fetch;
	private readonly timeoutMs: number;
	private readonly actionTimeoutMs: number;
	protected readonly now: () => number;
	protected readonly deviceAttestation: DeviceAttestation;

	constructor(options: FleetResponseConsumerOptions) {
		if (!isUuid(options.identity.tenantId) || !isUuid(options.identity.agentId)) {
			throw new Error("invalid_fleet_identity");
		}
		if (!options.apiKey.trim() || /[\r\n]/.test(options.apiKey))
			throw new Error("invalid_fleet_api_key");
		if (
			options.adapter &&
			(options.adapter.identity.tenantId !== options.identity.tenantId ||
				options.adapter.identity.agentId !== options.identity.agentId)
		)
			throw new Error("fleet_adapter_identity_mismatch");
		this.url = responseEndpoint(options.endpoint, options.developmentLoopback === true);
		this.apiKey = options.apiKey.trim();
		this.deviceAttestation = createDeviceAttestation(options.installationId, this.apiKey);
		this.identity = { ...options.identity };
		this.adapter = options.adapter;
		this.audit = options.audit;
		this.fetchImpl = options.fetchImpl ?? fetch;
		this.timeoutMs = Math.min(10_000, Math.max(100, options.timeoutMs ?? 3000));
		this.actionTimeoutMs = Math.min(60_000, Math.max(100, options.actionTimeoutMs ?? 30_000));
		this.now = options.now ?? Date.now;
	}

	protected isActionInterrupted(error: unknown): boolean {
		return error instanceof FleetResponseActionInterrupted;
	}

	protected async runBoundedAction<T>(
		operation: (signal: AbortSignal) => Promise<T>,
		parentSignal?: AbortSignal,
	): Promise<T> {
		if (parentSignal?.aborted) {
			throw new FleetResponseActionInterrupted("fleet_response_action_interrupted");
		}
		const controller = new AbortController();
		let rejectInterrupted: (error: FleetResponseActionInterrupted) => void = () => {};
		const interrupted = new Promise<never>((_resolve, reject) => {
			rejectInterrupted = reject;
		});
		let finished = false;
		const interrupt = () => {
			if (finished) return;
			rejectInterrupted(new FleetResponseActionInterrupted("fleet_response_action_interrupted"));
			controller.abort();
		};
		const timeout = setTimeout(interrupt, this.actionTimeoutMs);
		parentSignal?.addEventListener("abort", interrupt, { once: true });
		try {
			return await Promise.race([operation(controller.signal), interrupted]);
		} finally {
			finished = true;
			clearTimeout(timeout);
			parentSignal?.removeEventListener("abort", interrupt);
		}
	}

	private async post(body: Record<string, unknown>): Promise<unknown> {
		if (this.accessRejectionStatus !== null) {
			throw new FleetResponseAccessRejected(this.accessRejectionStatus);
		}
		const response = await this.fetchImpl(this.url, {
			method: "POST",
			headers: {
				Authorization: `Bearer ${this.apiKey}`,
				"Content-Type": "application/json",
				Accept: "application/json",
			},
			body: JSON.stringify({
				tenant_id: this.identity.tenantId,
				...body,
				device_attestation: deviceAttestationPayload(this.deviceAttestation),
			}),
			signal: AbortSignal.timeout(this.timeoutMs),
		});
		if (response.status === 401 || response.status === 403) {
			this.accessRejectionStatus = response.status;
			// The credential has been invalidated by the control plane; do not retain
			// or reuse it through this consumer instance after a definitive 401.
			if (response.status === 401) this.apiKey = "";
			throw new FleetResponseAccessRejected(response.status);
		}
		if (!response.ok) throw new Error(`http_${response.status}`);
		return boundedJson(response);
	}

	protected hasAccessRejection(): boolean {
		return this.accessRejectionStatus !== null;
	}

	protected accessRejectionCode(): "http_401" | "http_403" {
		return this.accessRejectionStatus === 403 ? "http_403" : "http_401";
	}

	protected async record(
		commandId: string,
		action: "ack" | "result",
		outcome: "accepted" | "rejected" | "succeeded" | "failed",
		code?: string,
	): Promise<boolean> {
		const body = await this.post({
			action,
			command_id: commandId,
			outcome,
			result_code: code ?? null,
		});
		const state = action === "ack" ? (outcome === "accepted" ? "acknowledged" : "failed") : outcome;
		return (
			isRecord(body) && body.ok === true && body.command_id === commandId && body.state === state
		);
	}

	protected async pollCommand(): Promise<FleetResponseCommand | FleetResponseCycleResult> {
		let polled: unknown;
		try {
			polled = await this.post({ action: "poll" });
		} catch (error) {
			if (error instanceof FleetResponseAccessRejected) {
				return {
					status: "access_rejected",
					stage: "poll",
					code: error.status === 401 ? "http_401" : "http_403",
				};
			}
			return { status: "outcome_unknown", stage: "poll", reason: "poll_unavailable" };
		}
		if (!isRecord(polled) || polled.ok !== true || !("command" in polled)) {
			return { status: "outcome_unknown", stage: "poll", reason: "invalid_poll_response" };
		}
		if (polled.command === null) return { status: "idle" };
		const parsed = commandFrom(polled.command, this.identity, this.now());
		if (parsed.ok === false) {
			if (parsed.expiredId) return { status: "expired", commandId: parsed.expiredId };
			return { status: "invalid_command", reason: parsed.reason };
		}
		return parsed.command;
	}

	protected async rejectUnsupported(commandId: string): Promise<FleetResponseCycleResult> {
		try {
			const recorded = await this.record(commandId, "ack", "rejected", "unsupported_action");
			if (recorded) return { status: "rejected", commandId, code: "unsupported_action" };
		} catch (error) {
			if (error instanceof FleetResponseAccessRejected) {
				return {
					status: "access_rejected",
					stage: "ack",
					code: error.status === 401 ? "http_401" : "http_403",
				};
			}
		}
		return { status: "outcome_unknown", commandId, stage: "ack", reason: "rejection_unconfirmed" };
	}

	protected async acknowledge(commandId: string): Promise<boolean> {
		try {
			return await this.record(commandId, "ack", "accepted");
		} catch (error) {
			if (error instanceof FleetResponseAccessRejected) return false;
			return false;
		}
	}

	protected commandSupported(
		command: FleetResponseCommand,
		adapter: FleetResponseActionAdapter,
	): boolean {
		return adapter.supportedCommands.includes(command.commandType);
	}

	protected async executeAndVerify(
		command: FleetResponseCommand,
		adapter: FleetResponseActionAdapter,
		signal?: AbortSignal,
	): Promise<string | null> {
		if (Date.parse(command.expiresAt) <= this.now()) return "ttl_elapsed";
		try {
			const execution = await this.runBoundedAction(
				(actionSignal) => adapter.execute(command, actionSignal),
				signal,
			);
			if (execution.ok === false) return resultCode(execution.code, "execution_failed");
			const verification = await this.runBoundedAction(
				(actionSignal) => adapter.verify(command, actionSignal),
				signal,
			);
			return verification.observed === true
				? null
				: resultCode(verification.code, "verification_failed");
		} catch (error) {
			if (this.isActionInterrupted(error)) throw error;
			return "execution_failed";
		}
	}

	protected async report(
		commandId: string,
		code: string | null,
	): Promise<FleetResponseCycleResult> {
		const outcome = code ? "failed" : "succeeded";
		try {
			const recorded = await this.record(commandId, "result", outcome, code ?? undefined);
			if (!recorded) throw new Error("result_unconfirmed");
		} catch {
			return {
				status: "outcome_unknown",
				commandId,
				stage: "result",
				reason: this.hasAccessRejection()
					? "access_rejected_after_execution"
					: "result_unconfirmed",
			};
		}
		return code ? { status: "failed", commandId, code } : { status: "succeeded", commandId };
	}

	private async pollOnceInternal(signal?: AbortSignal): Promise<FleetResponseCycleResult> {
		const command = await this.pollCommand();
		if ("status" in command) return command;
		const adapter = this.adapter;
		if (!adapter || !this.commandSupported(command, adapter)) {
			return this.rejectUnsupported(command.id);
		}
		// A lost ACK reply may have committed remotely. Never execute on ambiguity.
		if (!(await this.acknowledge(command.id))) {
			if (this.hasAccessRejection()) {
				return {
					status: "access_rejected",
					stage: "ack",
					code: this.accessRejectionCode(),
				};
			}
			return {
				status: "outcome_unknown",
				commandId: command.id,
				stage: "ack",
				reason: "ack_unconfirmed",
			};
		}
		let code: string | null;
		try {
			code = await this.executeAndVerify(command, adapter, signal);
		} catch (error) {
			if (!this.isActionInterrupted(error)) throw error;
			return {
				status: "outcome_unknown",
				commandId: command.id,
				stage: "result",
				reason: "execution_state_unverified",
			};
		}
		return this.report(command.id, code);
	}

	protected async emitAudit(result: FleetResponseCycleResult): Promise<void> {
		try {
			await this.audit?.({ result, attestation: this.deviceAttestation });
		} catch {
			// Audit observers cannot turn an uncertain or failed response into success.
		}
	}

	async pollOnce(signal?: AbortSignal): Promise<FleetResponseCycleResult> {
		const result = await this.pollOnceInternal(signal);
		await this.emitAudit(result);
		return result;
	}
}
