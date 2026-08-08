/**
 * Control plane client (optional).
 * Sends best-effort telemetry (audit events) for the dashboard and licensing.
 *
 * Fail-open: any error returns false and never blocks local detection.
 */

import { isDegradedSafeMode } from "../integrity/degraded-safe-mode.js";
import { redactTelemetryData, redactTelemetryString } from "../telemetry-redaction.js";
import type { ControlPlaneConfig, Logger } from "../types.js";
import { nullLogger } from "../types.js";
import { VERSION } from "../version.js";

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

	constructor(config: ControlPlaneConfig, apiKey: string, logger: Logger = nullLogger) {
		this.baseUrl = (config.endpoint ?? "").replace(/\/+$/, "");
		this.timeoutMs = (config.timeout_seconds ?? 0.5) * 1000;
		this.apiKey = apiKey;
		this.logger = logger;
	}

	private authHeaders(): Record<string, string> {
		const token = (this.apiKey ?? "").trim();
		return token ? { Authorization: `Bearer ${token}` } : {};
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
			const response = await fetch(`${this.baseUrl}/v1/device-start`, {
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
			const response = await fetch(`${this.baseUrl}/v1/device-poll`, {
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

		try {
			const response = await fetch(`${this.baseUrl}/v1/ingest`, {
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
					events: redactTelemetryData(payload.events),
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

	/**
	 * Fetches the signed revocation list (commercial licensing support).
	 * Fail-open: network/parse errors return ok=false and never block local protection.
	 */
	async fetchRevocations(): Promise<ControlPlaneRevocationsResult> {
		if (!this.baseUrl) return { ok: false, error: "missing_endpoint" };
		if (!this.apiKey?.trim()) return { ok: false, error: "missing_api_key" };
		if (isDegradedSafeMode()) return { ok: false, error: "degraded_safe_mode" };

		try {
			const response = await fetch(`${this.baseUrl}/v1/revocations`, {
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
			const response = await fetch(`${this.baseUrl}/v1/enroll`, {
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
			const response = await fetch(`${this.baseUrl}/v1/packs-manifest`, {
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
	async fetchBillingCheckoutUrl(): Promise<ControlPlaneBillingCheckoutResult> {
		if (!this.baseUrl) return { ok: false, error: "missing_endpoint" };
		if (!this.apiKey?.trim()) return { ok: false, error: "missing_api_key" };
		if (isDegradedSafeMode()) return { ok: false, error: "degraded_safe_mode" };

		try {
			const response = await fetch(`${this.baseUrl}/v1/billing-checkout`, {
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
			const response = await fetch(`${this.baseUrl}/v1/policy`, {
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
