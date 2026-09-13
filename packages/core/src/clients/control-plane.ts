/**
 * Control plane client (optional).
 * Sends best-effort telemetry (audit events) for the dashboard and licensing.
 *
 * Fail-open: any error returns false and never blocks local detection.
 */

import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";
import { resolvePath } from "../config.js";
import { isDegradedSafeMode } from "../integrity/degraded-safe-mode.js";
import {
	DurableTelemetryQueue,
	type TelemetryFlushResult,
	type TelemetryQueueOptions,
	type TelemetryQueueStatus,
} from "../telemetry-queue.js";
import { redactTelemetryData, redactTelemetryString } from "../telemetry-redaction.js";
import type { ControlPlaneConfig, Logger } from "../types.js";
import { nullLogger } from "../types.js";
import { VERSION } from "../version.js";
import { controlPlaneUrl } from "./control-plane-url.js";

export interface ControlPlaneIngestPayload {
	iid?: string;
	agent_runtime?: string;
	agent_runtime_version?: string;
	aidr_version: string;
	events: Record<string, unknown>[];
}

export interface ControlPlaneIngestResult {
	ok: boolean;
	status?: number;
	error?: string;
	body?: Record<string, unknown>;
}

export interface ControlPlaneClientOptions {
	/** Override used by tests and embedded runtimes with a dedicated state root. */
	telemetryQueueRoot?: string;
	telemetryQueue?: Omit<TelemetryQueueOptions, "directory">;
}

export interface ControlPlaneRevocationsResult {
	ok: boolean;
	status?: number;
	error?: string;
	body?: Record<string, unknown>;
}

export interface ControlPlaneEnrollResult {
	ok: boolean;
	status?: number;
	error?: string;
	body?: Record<string, unknown>;
}

export interface ControlPlanePacksManifestResult {
	ok: boolean;
	status?: number;
	error?: string;
	body?: Record<string, unknown>;
}

export interface ControlPlaneBillingCheckoutResult {
	ok: boolean;
	status?: number;
	error?: string;
	body?: Record<string, unknown>;
}

export class ControlPlaneClient {
	private readonly baseUrl: string;
	private readonly timeoutMs: number;
	private readonly apiKey: string;
	private readonly logger: Logger;
	private readonly options: ControlPlaneClientOptions;

	constructor(
		config: ControlPlaneConfig,
		apiKey: string,
		logger: Logger = nullLogger,
		options: ControlPlaneClientOptions = {},
	) {
		this.baseUrl = (config.endpoint ?? "").replace(/\/+$/, "");
		this.timeoutMs = (config.timeout_seconds ?? 0.5) * 1000;
		this.apiKey = apiKey;
		this.logger = logger;
		this.options = options;
	}

	private authHeaders(): Record<string, string> {
		const token = (this.apiKey ?? "").trim();
		return token ? { Authorization: `Bearer ${token}` } : {};
	}

	/** Agent-reported policy loading receipt; failure never changes a security decision. */
	async acknowledgeRuntimePolicy(version: number, policySha256: string): Promise<boolean> {
		if (!this.baseUrl || isDegradedSafeMode()) return false;
		try {
			const response = await fetch(controlPlaneUrl(this.baseUrl, "policy-ack"), {
				method: "POST",
				signal: AbortSignal.timeout(Math.max(1, Math.min(this.timeoutMs, 500))),
				headers: { ...this.authHeaders(), "Content-Type": "application/json" },
				body: JSON.stringify({ version, policy_sha256: policySha256 }),
			});
			return response.ok;
		} catch {
			return false;
		}
	}

	/**
	 * Device-code bootstrap: start a login session without requiring an API key.
	 * Intended for first-time setup in managed-only commercial builds.
	 */
	async deviceStart(payload?: {
		iid?: string;
		agent_runtime?: string;
		agent_runtime_version?: string;
	}): Promise<{ ok: boolean; status?: number; error?: string; body?: Record<string, unknown> }> {
		if (!this.baseUrl) return { ok: false, error: "missing_endpoint" };
		if (isDegradedSafeMode()) return { ok: false, error: "degraded_safe_mode" };

		try {
			const response = await fetch(controlPlaneUrl(this.baseUrl, "device-start"), {
				method: "POST",
				signal: AbortSignal.timeout(this.timeoutMs),
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					"User-Agent": "aidr",
				},
				body: JSON.stringify(payload ?? {}),
			});

			let body: Record<string, unknown> | undefined;
			if (typeof (response as unknown as { json?: unknown }).json === "function") {
				try {
					const parsed = await (response as unknown as { json: () => Promise<unknown> }).json();
					if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
						body = parsed as Record<string, unknown>;
					}
				} catch {
					body = undefined;
				}
			}

			if (!response.ok) {
				return {
					ok: false,
					status: response.status,
					error: typeof body?.error === "string" ? (body.error as string) : "http_error",
					body,
				};
			}

			return { ok: true, status: response.status, body };
		} catch (e) {
			this.logger.debug("Control plane device-start failed", {
				error: redactTelemetryString(String(e)),
			});
			return { ok: false, error: "request_failed" };
		}
	}

	/**
	 * Device-code bootstrap: poll for authorization and (when approved) receive a one-time enrollment token.
	 * No API key required. The returned enrollment token should be exchanged via /v1/enroll.
	 */
	async devicePoll(payload: {
		device_code: string;
	}): Promise<{ ok: boolean; status?: number; error?: string; body?: Record<string, unknown> }> {
		if (!this.baseUrl) return { ok: false, error: "missing_endpoint" };
		if (isDegradedSafeMode()) return { ok: false, error: "degraded_safe_mode" };

		const deviceCode = payload.device_code?.trim();
		if (!deviceCode) return { ok: false, error: "missing_device_code" };

		try {
			const response = await fetch(controlPlaneUrl(this.baseUrl, "device-poll"), {
				method: "POST",
				signal: AbortSignal.timeout(this.timeoutMs),
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					Authorization: `Bearer ${deviceCode}`,
					"User-Agent": "aidr",
				},
				body: JSON.stringify({}),
			});

			let body: Record<string, unknown> | undefined;
			if (typeof (response as unknown as { json?: unknown }).json === "function") {
				try {
					const parsed = await (response as unknown as { json: () => Promise<unknown> }).json();
					if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
						body = parsed as Record<string, unknown>;
					}
				} catch {
					body = undefined;
				}
			}

			if (!response.ok) {
				return {
					ok: false,
					status: response.status,
					error: typeof body?.error === "string" ? (body.error as string) : "http_error",
					body,
				};
			}

			return { ok: true, status: response.status, body };
		} catch (e) {
			this.logger.debug("Control plane device-poll failed", {
				error: redactTelemetryString(String(e)),
			});
			return { ok: false, error: "request_failed" };
		}
	}

	async ingest(
		payload: Omit<ControlPlaneIngestPayload, "aidr_version">,
	): Promise<ControlPlaneIngestResult> {
		if (!this.baseUrl) return { ok: false, error: "missing_endpoint" };
		if (!this.apiKey?.trim()) return { ok: false, error: "missing_api_key" };
		// If the local runtime looks tampered, avoid sending any telemetry.
		if (isDegradedSafeMode()) return { ok: false, error: "degraded_safe_mode" };
		if (payload.events.length === 0) return await this.ingestHeartbeat(payload);
		if (!payload.iid?.trim()) return { ok: false, error: "missing_iid" };

		const redacted = redactTelemetryData(payload.events);
		if (!Array.isArray(redacted)) return { ok: false, error: "invalid_events" };
		const events = redacted.filter(
			(event): event is Record<string, unknown> =>
				Boolean(event) && typeof event === "object" && !Array.isArray(event),
		);
		if (events.length !== payload.events.length) return { ok: false, error: "invalid_events" };

		const queue = this.telemetryQueue(payload.iid);
		const enqueued = await queue.enqueue(events);
		if (enqueued.rejected.length > 0) {
			this.logger.warn("Telemetry queue rejected events", {
				reason: enqueued.reason ?? enqueued.rejected[0]?.reason ?? "unknown",
				rejected_events: enqueued.rejected.length,
				pending_events: enqueued.metrics.pendingEvents,
				lost_total: enqueued.metrics.lostTotal,
				storage_errors_total: enqueued.metrics.storageErrorsTotal,
			});
		}
		const { flushed, lastResult } = await this.flushTelemetryQueue(queue, payload);
		const telemetry = {
			...flushed,
			enqueue_rejections: enqueued.rejected,
		};

		if (enqueued.rejected.length > 0) {
			return {
				ok: false,
				status: lastResult?.status,
				error: "telemetry_storage_unavailable",
				body: this.withTelemetryStatus(lastResult?.body, telemetry),
			};
		}
		if (lastResult) {
			return {
				...lastResult,
				body: this.withTelemetryStatus(lastResult.body, telemetry),
			};
		}
		return {
			ok: false,
			error:
				flushed.deliveryState === "unavailable"
					? "telemetry_delivery_unavailable"
					: "telemetry_queued",
			body: this.withTelemetryStatus(undefined, telemetry),
		};
	}

	private async ingestHeartbeat(
		payload: Omit<ControlPlaneIngestPayload, "aidr_version">,
	): Promise<ControlPlaneIngestResult> {
		if (!payload.iid?.trim()) return await this.postIngest(payload);
		const queued = await this.flushTelemetryQueue(this.telemetryQueue(payload.iid), payload);
		if (queued.flushed.attemptedEventIds.length === 0) {
			const heartbeat = await this.postIngest(payload);
			return {
				...heartbeat,
				body: this.withTelemetryStatus(heartbeat.body, {
					...queued.flushed,
					enqueue_rejections: [],
				}),
			};
		}
		if (queued.lastResult) {
			return {
				...queued.lastResult,
				body: this.withTelemetryStatus(queued.lastResult.body, {
					...queued.flushed,
					enqueue_rejections: [],
				}),
			};
		}
		return {
			ok: false,
			error: "telemetry_delivery_unavailable",
			body: this.withTelemetryStatus(undefined, {
				...queued.flushed,
				enqueue_rejections: [],
			}),
		};
	}

	private async postIngest(
		payload: Omit<ControlPlaneIngestPayload, "aidr_version">,
	): Promise<ControlPlaneIngestResult> {
		try {
			const response = await fetch(controlPlaneUrl(this.baseUrl, "ingest"), {
				method: "POST",
				signal: AbortSignal.timeout(this.timeoutMs),
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					...this.authHeaders(),
					"User-Agent": "aidr",
				},
				body: JSON.stringify({
					...payload,
					aidr_version: VERSION,
				} satisfies ControlPlaneIngestPayload),
			});

			let body: Record<string, unknown> | undefined;
			// Best-effort JSON parsing. In tests we stub Response objects, so guard json() existence.
			if (typeof (response as unknown as { json?: unknown }).json === "function") {
				try {
					const parsed = await (response as unknown as { json: () => Promise<unknown> }).json();
					if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
						body = parsed as Record<string, unknown>;
					}
				} catch {
					body = undefined;
				}
			}

			if (!response.ok) {
				this.logger.debug(`Control plane ingest HTTP ${response.status}`);
				return {
					ok: false,
					status: response.status,
					error: typeof body?.error === "string" ? (body.error as string) : "http_error",
					body,
				};
			}

			return { ok: true, status: response.status, body };
		} catch (e) {
			this.logger.debug("Control plane ingest failed", {
				error: redactTelemetryString(String(e)),
			});
			return { ok: false, error: "request_failed" };
		}
	}

	private async flushTelemetryQueue(
		queue: DurableTelemetryQueue,
		payload: Omit<ControlPlaneIngestPayload, "aidr_version">,
	): Promise<{ flushed: TelemetryFlushResult; lastResult?: ControlPlaneIngestResult }> {
		let lastResult: ControlPlaneIngestResult | undefined;
		const flushed = await queue.flush(async (batch) => {
			lastResult = await this.postIngest({ ...payload, events: batch });
			const acknowledged = lastResult.body?.acknowledged_event_ids;
			return {
				ok: lastResult.ok,
				acknowledgedEventIds: Array.isArray(acknowledged)
					? acknowledged.filter((id): id is string => typeof id === "string")
					: undefined,
				retryable: this.isRetryableIngestFailure(lastResult),
				reason: lastResult.error,
			};
		});
		if (flushed.deliveryState === "unavailable") {
			this.logger.warn("Telemetry delivery unavailable; durable queue status follows", {
				reason: flushed.reason ?? "unknown",
				pending_events: flushed.metrics.pendingEvents,
				pending_bytes: flushed.metrics.pendingBytes,
				lost_total: flushed.metrics.lostTotal,
				delivery_failures_total: flushed.metrics.deliveryFailuresTotal,
				storage_errors_total: flushed.metrics.storageErrorsTotal,
			});
		}
		return { flushed, lastResult };
	}

	private telemetryQueue(iid: string): DurableTelemetryQueue {
		// Bind queued data to endpoint, credential and installation. A credential
		// moved to another tenant must never flush the previous tenant's records.
		const namespace = createHash("sha256")
			.update(`${this.baseUrl}\0${this.apiKey}\0${iid}`)
			.digest("hex");
		const root = this.options.telemetryQueueRoot ?? resolvePath("~/.singularity-aidr/telemetry");
		return new DurableTelemetryQueue({
			...this.options.telemetryQueue,
			directory: join(root, namespace),
		});
	}

	private isRetryableIngestFailure(result: ControlPlaneIngestResult): boolean {
		if (result.ok) return false;
		if (result.status === undefined) return true;
		return result.status === 408 || result.status === 429 || result.status >= 500;
	}

	private withTelemetryStatus(
		body: Record<string, unknown> | undefined,
		telemetry: TelemetryQueueStatus & Record<string, unknown>,
	): Record<string, unknown> {
		return { ...(body ?? {}), telemetry_queue: telemetry };
	}

	/**
	 * Fetches the signed revocation list (commercial licensing support).
	 * Fail-open: network/parse errors return ok=false and never block local protection.
	 */
	async fetchRevocations(): Promise<ControlPlaneRevocationsResult> {
		if (!this.baseUrl) return { ok: false, error: "missing_endpoint" };
		if (!this.apiKey?.trim()) return { ok: false, error: "missing_api_key" };
		if (isDegradedSafeMode()) return { ok: false, error: "degraded_safe_mode" };

		try {
			const response = await fetch(controlPlaneUrl(this.baseUrl, "revocations"), {
				method: "GET",
				signal: AbortSignal.timeout(this.timeoutMs),
				headers: {
					Accept: "application/json",
					...this.authHeaders(),
					"User-Agent": "aidr",
				},
			});

			let body: Record<string, unknown> | undefined;
			if (typeof (response as unknown as { json?: unknown }).json === "function") {
				try {
					const parsed = await (response as unknown as { json: () => Promise<unknown> }).json();
					if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
						body = parsed as Record<string, unknown>;
					}
				} catch {
					body = undefined;
				}
			}

			if (!response.ok) {
				this.logger.debug(`Control plane revocations HTTP ${response.status}`);
				return {
					ok: false,
					status: response.status,
					error: typeof body?.error === "string" ? (body.error as string) : "http_error",
					body,
				};
			}

			return { ok: true, status: response.status, body };
		} catch (e) {
			this.logger.debug("Control plane revocations fetch failed", {
				error: redactTelemetryString(String(e)),
			});
			return { ok: false, error: "request_failed" };
		}
	}

	/**
	 * Exchanges a one-time enrollment token for an API key (and optionally a signed entitlement).
	 * Fail-open: callers should treat failures as "not enrolled yet".
	 */
	async enroll(payload: {
		iid: string;
		agent_runtime?: string;
		agent_runtime_version?: string;
	}): Promise<ControlPlaneEnrollResult> {
		if (!this.baseUrl) return { ok: false, error: "missing_endpoint" };
		if (!this.apiKey?.trim()) return { ok: false, error: "missing_api_key" };
		if (isDegradedSafeMode()) return { ok: false, error: "degraded_safe_mode" };

		try {
			const response = await fetch(controlPlaneUrl(this.baseUrl, "enroll"), {
				method: "POST",
				signal: AbortSignal.timeout(this.timeoutMs),
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					...this.authHeaders(),
					"User-Agent": "aidr",
				},
				body: JSON.stringify(payload),
			});

			let body: Record<string, unknown> | undefined;
			if (typeof (response as unknown as { json?: unknown }).json === "function") {
				try {
					const parsed = await (response as unknown as { json: () => Promise<unknown> }).json();
					if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
						body = parsed as Record<string, unknown>;
					}
				} catch {
					body = undefined;
				}
			}

			if (!response.ok) {
				this.logger.debug(`Control plane enroll HTTP ${response.status}`);
				return {
					ok: false,
					status: response.status,
					error: typeof body?.error === "string" ? (body.error as string) : "http_error",
					body,
				};
			}
			return { ok: true, status: response.status, body };
		} catch (e) {
			this.logger.debug("Control plane enroll failed", {
				error: redactTelemetryString(String(e)),
			});
			return { ok: false, error: "request_failed" };
		}
	}

	/**
	 * Best-effort premium pack manifest (managed delivery).
	 */
	async fetchPacksManifest(): Promise<ControlPlanePacksManifestResult> {
		if (!this.baseUrl) return { ok: false, error: "missing_endpoint" };
		if (!this.apiKey?.trim()) return { ok: false, error: "missing_api_key" };
		if (isDegradedSafeMode()) return { ok: false, error: "degraded_safe_mode" };

		try {
			const response = await fetch(controlPlaneUrl(this.baseUrl, "packs-manifest"), {
				method: "GET",
				signal: AbortSignal.timeout(this.timeoutMs),
				headers: {
					Accept: "application/json",
					...this.authHeaders(),
					"User-Agent": "aidr",
				},
			});

			let body: Record<string, unknown> | undefined;
			if (typeof (response as unknown as { json?: unknown }).json === "function") {
				try {
					const parsed = await (response as unknown as { json: () => Promise<unknown> }).json();
					if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
						body = parsed as Record<string, unknown>;
					}
				} catch {
					body = undefined;
				}
			}

			if (!response.ok) {
				return {
					ok: false,
					status: response.status,
					error: typeof body?.error === "string" ? (body.error as string) : "http_error",
					body,
				};
			}
			return { ok: true, status: response.status, body };
		} catch (e) {
			this.logger.debug("Control plane packs manifest fetch failed", {
				error: redactTelemetryString(String(e)),
			});
			return { ok: false, error: "request_failed" };
		}
	}

	/**
	 * Returns a billing checkout URL (dashboard should use this via JWT; kept here for CLI parity).
	 */
	async fetchBillingCheckoutUrl(
		options: { seats?: number; plan?: "monthly" | "yearly"; requestId?: string } = {},
	): Promise<ControlPlaneBillingCheckoutResult> {
		if (!this.baseUrl) return { ok: false, error: "missing_endpoint" };
		if (!this.apiKey?.trim()) return { ok: false, error: "missing_api_key" };
		if (isDegradedSafeMode()) return { ok: false, error: "degraded_safe_mode" };

		try {
			const response = await fetch(controlPlaneUrl(this.baseUrl, "billing-checkout"), {
				method: "POST",
				signal: AbortSignal.timeout(this.timeoutMs),
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					...this.authHeaders(),
					"User-Agent": "aidr",
				},
				body: JSON.stringify({
					seats: options.seats ?? 1,
					plan: options.plan ?? "monthly",
					request_id: options.requestId ?? randomUUID(),
				}),
			});

			let body: Record<string, unknown> | undefined;
			if (typeof (response as unknown as { json?: unknown }).json === "function") {
				try {
					const parsed = await (response as unknown as { json: () => Promise<unknown> }).json();
					if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
						body = parsed as Record<string, unknown>;
					}
				} catch {
					body = undefined;
				}
			}

			if (!response.ok) {
				return {
					ok: false,
					status: response.status,
					error: typeof body?.error === "string" ? (body.error as string) : "http_error",
					body,
				};
			}
			return { ok: true, status: response.status, body };
		} catch (e) {
			this.logger.debug("Control plane billing checkout fetch failed", {
				error: redactTelemetryString(String(e)),
			});
			return { ok: false, error: "request_failed" };
		}
	}

	/**
	 * Fetches the runtime policy from the control plane.
	 * Fail-open: network/parse errors return ok=false and never block local protection.
	 */
	async fetchRuntimePolicy(): Promise<ControlPlanePacksManifestResult> {
		if (!this.baseUrl) return { ok: false, error: "missing_endpoint" };
		if (!this.apiKey?.trim()) return { ok: false, error: "missing_api_key" };
		if (isDegradedSafeMode()) return { ok: false, error: "degraded_safe_mode" };

		try {
			const response = await fetch(controlPlaneUrl(this.baseUrl, "policy"), {
				method: "GET",
				signal: AbortSignal.timeout(this.timeoutMs),
				headers: {
					Accept: "application/json",
					...this.authHeaders(),
					"User-Agent": "aidr",
				},
			});

			let body: Record<string, unknown> | undefined;
			if (typeof (response as unknown as { json?: unknown }).json === "function") {
				try {
					const parsed = await (response as unknown as { json: () => Promise<unknown> }).json();
					if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
						body = parsed as Record<string, unknown>;
					}
				} catch {
					body = undefined;
				}
			}

			if (!response.ok) {
				return {
					ok: false,
					status: response.status,
					error: typeof body?.error === "string" ? (body.error as string) : "http_error",
					body,
				};
			}
			return { ok: true, status: response.status, body };
		} catch (e) {
			this.logger.debug("Control plane runtime policy fetch failed", {
				error: redactTelemetryString(String(e)),
			});
			return { ok: false, error: "request_failed" };
		}
	}
}
