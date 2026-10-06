import { controlPlaneUrl } from "./clients/control-plane-url.js";
import {
	createDeviceAttestation,
	type DeviceAttestation,
	deviceAttestationPayload,
} from "./device-attestation.js";
import { verifyEd25519CanonicalJson } from "./managed.js";

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

export interface FleetResponseSignedDelivery {
	readonly alg: "ed25519";
	readonly key_id: string;
	readonly sig_b64: string;
	readonly payload: Readonly<Record<string, unknown>>;
}

export interface VerifiedFleetResponseCommand {
	command: FleetResponseCommand;
	delivery: FleetResponseSignedDelivery;
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
		delivery?: FleetResponseSignedDelivery,
	): Promise<{ ok: true } | { ok: false; code: string }>;
	/** Observe the resulting host state independently of execute's return value. */
	verify(
		command: FleetResponseCommand,
		signal?: AbortSignal,
		delivery?: FleetResponseSignedDelivery,
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
	/** Installed trust, keyed by signer ID. Never trust keys supplied by a poll reply. */
	trustedCommandKeys: Readonly<Record<string, string>>;
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
const MAX_RECENT_COMMANDS = 256;
const DELIVERY_FIELDS = [
	"schema_version",
	"purpose",
	"key_id",
	"tenant_id",
	"agent_id",
	"installation_id",
	"key_hash",
	"id",
	"command_type",
	"payload",
	"rollback_of",
	"created_at",
	"expires_at",
	"attempt",
];

function exactFields(value: Record<string, unknown>, fields: readonly string[]): boolean {
	return (
		Object.keys(value).length === fields.length &&
		fields.every((field) => Object.hasOwn(value, field))
	);
}

function isoTimestamp(value: unknown): number {
	if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
		return NaN;
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : NaN;
}

function commandTrust(
	keys: FleetResponseConsumerOptions["trustedCommandKeys"],
): Readonly<Record<string, string>> {
	if (!isRecord(keys) || Object.keys(keys).length === 0)
		throw new Error("missing_fleet_command_trust");
	const copy = Object.freeze({ ...keys });
	for (const [keyId, key] of Object.entries(copy)) {
		if (
			!keyId ||
			keyId.trim() !== keyId ||
			keyId.length > 128 ||
			/[\u0000-\u001f\u007f]/.test(keyId) ||
			typeof key !== "string" ||
			!key.trim()
		)
			throw new Error("invalid_fleet_command_trust");
	}
	return copy;
}

/** Native adapter interruption may have applied a side effect; preserve execution intent. */
export class FleetResponseActionInterrupted extends Error {}
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
	attestation: DeviceAttestation,
): string | null {
	if (value.tenant_id !== identity.tenantId) return "tenant_mismatch";
	if (value.agent_id !== identity.agentId) return "agent_mismatch";
	if (value.installation_id !== attestation.installationId) return "installation_mismatch";
	if (value.key_hash !== attestation.keyHash) return "credential_mismatch";
	return null;
}

function rollbackError(value: Record<string, unknown>): string | null {
	if (value.rollback_of !== null && value.rollback_of !== undefined && !isUuid(value.rollback_of)) {
		return "invalid_rollback_reference";
	}
	const isRollback =
		value.command_type === "agent_resume" || value.command_type === "network_release";
	if (value.rollback_of === value.id) return "invalid_rollback_reference";
	return isRollback !== isUuid(value.rollback_of) ? "rollback_reference_mismatch" : null;
}

function commandFrom(
	value: unknown,
	identity: FleetResponseIdentity,
	attestation: DeviceAttestation,
	now: number,
	allowExpired = false,
): { ok: true; command: FleetResponseCommand } | { ok: false; reason: string; expiredId?: string } {
	if (!isRecord(value)) return { ok: false, reason: "command_not_object" };
	if (!isUuid(value.id)) return { ok: false, reason: "invalid_command_id" };
	const targetError = identityError(value, identity, attestation);
	if (targetError) return { ok: false, reason: targetError };
	if (!COMMAND_TYPES.includes(value.command_type as FleetResponseCommandType)) {
		return { ok: false, reason: "unsupported_command_type" };
	}
	const expires = isoTimestamp(value.expires_at);
	if (!Number.isFinite(expires)) return { ok: false, reason: "invalid_expiry" };
	const created = isoTimestamp(value.created_at);
	if (!Number.isFinite(created) || created > now + 60_000)
		return { ok: false, reason: "invalid_created_at" };
	if (expires <= created || expires - created > 3_600_000)
		return { ok: false, reason: "invalid_command_lifetime" };
	if (
		!Number.isSafeInteger(value.attempt) ||
		(value.attempt as number) < 1 ||
		(value.attempt as number) > 5
	) {
		return { ok: false, reason: "invalid_attempt" };
	}
	const referenceError = rollbackError(value);
	if (referenceError) return { ok: false, reason: referenceError };
	if (!allowExpired && expires <= now) return { ok: false, reason: "expired", expiredId: value.id };
	return {
		ok: true,
		command: {
			id: value.id,
			commandType: value.command_type as FleetResponseCommandType,
			expiresAt: value.expires_at as string,
			attempt: value.attempt as number,
			rollbackOf: (value.rollback_of as string | null | undefined) ?? null,
		},
	};
}

/** Verify the exact server envelope for consumers and persisted native response barriers. */
export function verifyFleetResponseCommandDelivery(
	value: unknown,
	options: {
		identity: FleetResponseIdentity;
		attestation: DeviceAttestation;
		trustedCommandKeys: Readonly<Record<string, string>>;
		now: number;
		allowExpired?: boolean;
	},
): VerifiedFleetResponseCommand | FleetResponseCycleResult {
	const invalid = (reason: string): FleetResponseCycleResult => ({
		status: "invalid_command",
		reason,
	});
	if (
		!isRecord(value) ||
		!exactFields(value, ["alg", "key_id", "sig_b64", "payload"]) ||
		value.alg !== "ed25519" ||
		typeof value.key_id !== "string" ||
		typeof value.sig_b64 !== "string" ||
		!isRecord(value.payload)
	)
		return invalid("invalid_signed_command");
	const payload = value.payload;
	if (
		!exactFields(payload, DELIVERY_FIELDS) ||
		payload.schema_version !== 1 ||
		payload.purpose !== "aidr.fleet-response.command" ||
		payload.key_id !== value.key_id ||
		!isRecord(payload.payload) ||
		Object.keys(payload.payload).length !== 0 ||
		Object.entries(payload).some(
			([key, item]) =>
				key !== "payload" && item !== null && typeof item !== "string" && typeof item !== "number",
		)
	)
		return invalid("invalid_command_payload");
	if (!isRecord(options.trustedCommandKeys)) return invalid("missing_command_trust");
	if (!Number.isFinite(options.now)) return invalid("invalid_command_clock");
	const publicKey = Object.hasOwn(options.trustedCommandKeys, value.key_id)
		? options.trustedCommandKeys[value.key_id]
		: undefined;
	if (!publicKey) return invalid("unknown_command_signing_key");
	if (
		!/^[A-Za-z0-9+/]{86}==$/.test(value.sig_b64) ||
		Buffer.from(value.sig_b64, "base64").toString("base64") !== value.sig_b64 ||
		!verifyEd25519CanonicalJson({
			value: payload,
			sig_b64: value.sig_b64,
			public_keys_pem: [publicKey],
		})
	)
		return invalid("invalid_command_signature");
	const parsed = commandFrom(
		payload,
		options.identity,
		options.attestation,
		options.now,
		options.allowExpired,
	);
	if (parsed.ok === false) {
		if (parsed.expiredId) return { status: "expired", commandId: parsed.expiredId };
		return invalid(parsed.reason);
	}
	Object.freeze(payload.payload);
	Object.freeze(payload);
	return {
		command: Object.freeze(parsed.command),
		delivery: Object.freeze(value) as unknown as FleetResponseSignedDelivery,
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
	private readonly trustedCommandKeys: Readonly<Record<string, string>>;
	private readonly recentCommands = new Map<string, number>();
	private cycleRunning = false;
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
		this.trustedCommandKeys = commandTrust(options.trustedCommandKeys);
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
			redirect: "error",
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

	/** Recheck persisted provenance before any resumed acknowledgement or action. */
	protected deliveryError(command: FleetResponseCommand, delivery: unknown): string | null {
		const verified = verifyFleetResponseCommandDelivery(delivery, {
			identity: this.identity,
			attestation: this.deviceAttestation,
			trustedCommandKeys: this.trustedCommandKeys,
			now: this.now(),
			allowExpired: true,
		});
		if ("status" in verified)
			return verified.status === "invalid_command" ? verified.reason : "invalid_signed_command";
		const signed = verified.command;
		return signed.id === command.id &&
			signed.commandType === command.commandType &&
			signed.expiresAt === command.expiresAt &&
			signed.attempt === command.attempt &&
			signed.rollbackOf === command.rollbackOf
			? null
			: "journal_command_delivery_mismatch";
	}

	protected async pollCommand(): Promise<VerifiedFleetResponseCommand | FleetResponseCycleResult> {
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
		if (!isRecord(polled) || polled.ok !== true || !("command_signed" in polled)) {
			return { status: "outcome_unknown", stage: "poll", reason: "invalid_poll_response" };
		}
		if (polled.command_signed === null) return { status: "idle" };
		return verifyFleetResponseCommandDelivery(polled.command_signed, {
			identity: this.identity,
			attestation: this.deviceAttestation,
			trustedCommandKeys: this.trustedCommandKeys,
			now: this.now(),
		});
	}

	protected async rejectUnsupported(
		commandId: string,
		code = "unsupported_action",
	): Promise<FleetResponseCycleResult> {
		try {
			const recorded = await this.record(commandId, "ack", "rejected", code);
			if (recorded) return { status: "rejected", commandId, code };
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
		delivery: FleetResponseSignedDelivery,
		signal?: AbortSignal,
	): Promise<string | null> {
		if (Date.parse(command.expiresAt) <= this.now()) return "ttl_elapsed";
		let executed = false;
		try {
			const execution = await this.runBoundedAction(
				(actionSignal) => adapter.execute(command, actionSignal, delivery),
				signal,
			);
			if (execution.ok === false && execution.code === "native_action_outcome_unknown")
				throw new FleetResponseActionInterrupted("native_action_outcome_unknown");
			if (execution.ok === false) return resultCode(execution.code, "execution_failed");
			executed = true;
			const verification = await this.runBoundedAction(
				(actionSignal) => adapter.verify(command, actionSignal, delivery),
				signal,
			);
			// A completed apply can leave a partial effect even when observation fails.
			if (verification.observed === false)
				throw new FleetResponseActionInterrupted(
					resultCode(verification.code, "verification_failed"),
				);
			return null;
		} catch (error) {
			if (this.isActionInterrupted(error)) throw error;
			if (executed) throw new FleetResponseActionInterrupted("verification_failed");
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
		const verified = await this.pollCommand();
		if ("status" in verified) return verified;
		const command = verified.command;
		for (const [id, expiry] of this.recentCommands) {
			if (expiry <= this.now()) this.recentCommands.delete(id);
		}
		if (this.recentCommands.has(command.id))
			return {
				status: "outcome_unknown",
				commandId: command.id,
				stage: "poll",
				reason: "replayed_command_id",
			};
		if (this.recentCommands.size >= MAX_RECENT_COMMANDS)
			return { status: "outcome_unknown", stage: "poll", reason: "command_replay_cache_full" };
		// Keep the ID even after a lost ACK or interrupted action: neither proves no side effect.
		this.recentCommands.set(command.id, Date.parse(command.expiresAt));
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
			code = await this.executeAndVerify(command, adapter, verified.delivery, signal);
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
		if (this.cycleRunning)
			return { status: "outcome_unknown", stage: "poll", reason: "cycle_in_progress" };
		this.cycleRunning = true;
		try {
			const result = await this.pollOnceInternal(signal);
			await this.emitAudit(result);
			return result;
		} finally {
			this.cycleRunning = false;
		}
	}
}
