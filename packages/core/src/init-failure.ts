/**
 * Connector initialisation failure handling.
 *
 * In-process connectors (OpenCode, OpenClaw) initialise inside the host's plugin loader.
 * If initialisation throws, the host simply never registers the plugin's hooks and every
 * tool call then runs uninspected — the connector fails OPEN. Connectors must instead
 * catch initialisation failures, register their enforcement hooks anyway, and deny every
 * tool call with {@link formatInitFailureMessage}.
 *
 * The reason shown to the agent is a short machine code only: raw error messages can
 * carry local paths or configuration details and are logged, not surfaced.
 */

import { t } from "./i18n/index.js";
import { ArtifactIntegrityError } from "./integrity/runtime.js";
import type { IntegrityStatus } from "./integrity/verify.js";

const MAX_CODE_LENGTH = 64;

function sanitizeCode(value: string): string {
	const cleaned = value
		.replace(/[^A-Za-z0-9_.:-]+/g, "_")
		.replace(/^_+|_+$/g, "")
		.slice(0, MAX_CODE_LENGTH);
	return cleaned || "init_error";
}

/** Derives a short, non-sensitive failure code from an initialisation error. */
export function initFailureCode(error: unknown): string {
	if (error instanceof ArtifactIntegrityError) {
		return sanitizeCode(`integrity_${error.result.status}`);
	}
	if (error && typeof error === "object") {
		const code = (error as { code?: unknown }).code;
		if (typeof code === "string" && code.trim()) return sanitizeCode(code);
		if (error instanceof Error && error.name && error.name !== "Error") {
			return sanitizeCode(error.name);
		}
	}
	return "init_error";
}

/**
 * The block reason every tool call receives while a connector is
 * uninitialised: the cause in plain words and who fixes it. A failed release
 * integrity check gets the integrity message (see {@link integrityFailureMessage}).
 */
export function formatInitFailureMessage(code: string, error?: unknown): string {
	const integrity = integrityFailureMessage(error);
	if (integrity) return integrity.message;
	return t("init.failed.message", { code: sanitizeCode(code) });
}

/** The integrity result of an `ArtifactIntegrityError`, also across bundle copies of the class. */
function integrityStatusOf(error: unknown): IntegrityStatus | null {
	if (error instanceof ArtifactIntegrityError) return error.result.status;
	if (error instanceof Error && error.name === "ArtifactIntegrityError") {
		const status = (error as { result?: { status?: unknown } }).result?.status;
		return typeof status === "string" ? (status as IntegrityStatus) : "invalid_manifest";
	}
	return null;
}

function integrityCause(status: IntegrityStatus): string {
	switch (status) {
		case "revoked":
			return t("integrity.cause.revoked");
		case "io_error":
			return t("integrity.cause.io");
		case "missing_file":
		case "hash_mismatch":
		case "unlisted_file":
		case "path_traversal":
			return t("integrity.cause.files");
		default:
			return t("integrity.cause.signature");
	}
}

/** What every connector says when its own release integrity check failed. */
export interface IntegrityFailureMessage {
	/** Full message: cause, consequence and the administrator's fix. */
	message: string;
	/** Short reason for hosts with a separate, model-facing reason field. */
	reason: string;
	/** Session-start banner: the whole session is blocked, not "unprotected". */
	sessionStart: string;
}

/**
 * The message for a failed release integrity check, or null when `error` is
 * not one. The installation cannot vouch for its own code, so every call is
 * denied; the message says so and names the administrator's next step. A
 * missing release verification key gets its own wording because its fix is
 * `aidr setup --release-key`, not a reinstall.
 */
export function integrityFailureMessage(error: unknown): IntegrityFailureMessage | null {
	const status = integrityStatusOf(error);
	if (!status) return null;
	const agent = t("integrity.agent");
	if (status === "no_public_keys") {
		return {
			message: `${t("integrity.noKey.message")}\n${agent}`,
			reason: t("integrity.reason"),
			sessionStart: t("hook.sessionStartNoKey"),
		};
	}
	const cause = integrityCause(status);
	return {
		message: `${t("integrity.failed.message", { cause })}\n${agent}`,
		reason: t("integrity.reason"),
		sessionStart: t("hook.sessionStartIntegrity", { cause }),
	};
}
