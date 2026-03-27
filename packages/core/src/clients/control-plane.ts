/**
 * Control plane client (optional).
 * Sends best-effort telemetry (audit events) for the dashboard and licensing.
 *
 * Fail-open: any error returns false and never blocks local detection.
 */

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

	async ingest(payload: Omit<ControlPlaneIngestPayload, "aidr_version">): Promise<boolean> {
		if (!this.baseUrl) return false;

		try {
			const response = await fetch(`${this.baseUrl}/v1/ingest`, {
				method: "POST",
				signal: AbortSignal.timeout(this.timeoutMs),
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					Authorization: `Bearer ${this.apiKey}`,
					"User-Agent": "aidr",
				},
				body: JSON.stringify({
					...payload,
					aidr_version: VERSION,
				} satisfies ControlPlaneIngestPayload),
			});

			if (!response.ok) {
				this.logger.debug(`Control plane ingest HTTP ${response.status}`);
				return false;
			}

			return true;
		} catch (e) {
			this.logger.debug("Control plane ingest failed", { error: String(e) });
			return false;
		}
	}
}

