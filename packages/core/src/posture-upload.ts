/**
 * Upload AI security posture findings to the managed control plane.
 *
 * Posture upload is an explicit operator action (`aidr scan --upload`,
 * `aidr discover --upload`), so unlike runtime telemetry it never reports a
 * quiet success: a missing enrollment, an unconfigured endpoint and an
 * undelivered batch are returned as named errors for the CLI to print and
 * exit non-zero on. Events are delivered through the same durable telemetry
 * queue as runtime events, so an undelivered batch is retried on the next
 * successful ingest from this installation rather than lost.
 */

import { ControlPlaneClient, type ControlPlaneClientOptions } from "./clients/control-plane.js";
import { loadConfig, resolvePath } from "./config.js";
import { getInstallationId } from "./installation-id.js";
import { isSyncDisabled, loadManagedState, managedStatePath } from "./managed.js";
import type { Config, Logger } from "./types.js";
import { nullLogger } from "./types.js";
import { VERSION } from "./version.js";

/** Stay well inside the ingest contract's 200-event request limit. */
export const POSTURE_UPLOAD_BATCH_SIZE = 100;
/** A CLI upload may wait longer than the hook-path default of 0.5 s. */
const MIN_UPLOAD_TIMEOUT_SECONDS = 10;

export type PostureUploadError =
	| "control_plane_disabled"
	| "control_plane_not_configured"
	| "insecure_endpoint"
	| "not_enrolled"
	| "missing_installation_id"
	| "sync_disabled"
	| string;

export type PostureUploadResult =
	| { ok: true; delivered: number; total: number }
	| {
			ok: false;
			error: PostureUploadError;
			status?: number;
			delivered: number;
			total: number;
			/** True when undelivered events remain in the durable queue for a later retry. */
			queued: boolean;
	  };

export interface PostureUploadOptions {
	config?: Config;
	logger?: Logger;
	/** Runtime label recorded on the agent row; the CLI is its own agent. */
	agentRuntime?: string;
	/** Overrides for tests and embedded runtimes. */
	aidrDir?: string;
	managedStatePath?: string;
	clientOptions?: ControlPlaneClientOptions;
}

const QUEUED_ERRORS = new Set([
	"telemetry_queued",
	"telemetry_delivery_unavailable",
	"request_failed",
	"events_insert_failed",
	"entitlements_unavailable",
	"entitlements_changed",
	"admission_unavailable",
	"agent_registration_unavailable",
]);

function failure(
	error: PostureUploadError,
	total: number,
	delivered = 0,
	extra: { status?: number; queued?: boolean } = {},
): PostureUploadResult {
	return {
		ok: false,
		error,
		delivered,
		total,
		queued: extra.queued ?? false,
		status: extra.status,
	};
}

/** Deliver posture events with the enrolled API key of this installation. */
export async function uploadPostureEvents(
	events: Record<string, unknown>[],
	options: PostureUploadOptions = {},
): Promise<PostureUploadResult> {
	const total = events.length;
	const logger = options.logger ?? nullLogger;
	const config = options.config ?? (await loadConfig(undefined, logger));
	if (!config.control_plane.enabled) return failure("control_plane_disabled", total);
	if (!config.control_plane.endpoint.trim()) return failure("control_plane_not_configured", total);

	const managedState = await loadManagedState(options.managedStatePath ?? managedStatePath(), {
		authToken: config.auth.api_key?.trim() || undefined,
		publicKeysPem: config.licensing.public_keys_pem,
	});
	// Only an issued API key identifies an enrolled installation; an enrollment
	// token is exchanged by the connectors, never used to upload findings.
	const apiKey =
		config.auth.api_key?.trim() ||
		(typeof managedState.api_key === "string" ? managedState.api_key.trim() : "");
	if (!apiKey) return failure("not_enrolled", total);
	if (isSyncDisabled(managedState)) return failure("sync_disabled", total);

	const iid = await getInstallationId(options.aidrDir ?? resolvePath("~/.singularity-aidr"));
	if (!iid) return failure("missing_installation_id", total);
	if (total === 0) return { ok: true, delivered: 0, total };

	let client: ControlPlaneClient;
	try {
		client = new ControlPlaneClient(
			{
				...config.control_plane,
				timeout_seconds: Math.max(config.control_plane.timeout_seconds, MIN_UPLOAD_TIMEOUT_SECONDS),
			},
			apiKey,
			logger,
			options.clientOptions,
		);
	} catch {
		return failure("insecure_endpoint", total);
	}

	let delivered = 0;
	for (let start = 0; start < total; start += POSTURE_UPLOAD_BATCH_SIZE) {
		const batch = events.slice(start, start + POSTURE_UPLOAD_BATCH_SIZE);
		const result = await client.ingest({
			iid,
			agent_runtime: options.agentRuntime ?? "aidr-cli",
			agent_runtime_version: VERSION,
			events: batch,
		});
		if (!result.ok) {
			const error = result.error ?? "telemetry_delivery_unavailable";
			return failure(error, total, delivered, {
				status: result.status,
				queued: QUEUED_ERRORS.has(error) || (result.status !== undefined && result.status >= 500),
			});
		}
		delivered += batch.length;
	}
	return { ok: true, delivered, total };
}

/** Operator-readable explanation for an upload failure. */
export function describePostureUploadError(error: PostureUploadError): string {
	switch (error) {
		case "control_plane_disabled":
			return "control_plane.enabled is false in the AIDR configuration";
		case "control_plane_not_configured":
			return "no control_plane.endpoint is configured (aidr config --set control_plane.endpoint=https://…)";
		case "insecure_endpoint":
			return "the control-plane endpoint must use HTTPS";
		case "not_enrolled":
			return "this installation has no enrolled API key; enroll a connector or set auth.api_key first";
		case "missing_installation_id":
			return "the installation id under ~/.singularity-aidr could not be read or created";
		case "sync_disabled":
			return "control-plane sync is disabled for this installation (revoked or disabled by the tenant)";
		case "tenant_not_admitted":
			return "the tenant is not admitted (trial expired, revoked or not licensed)";
		case "agent_limit_exceeded":
			return "the tenant has no free agent seat for this installation";
		default:
			return `delivery failed (${error})`;
	}
}
