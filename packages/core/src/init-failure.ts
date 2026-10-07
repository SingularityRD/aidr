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

import { ArtifactIntegrityError } from "./integrity/runtime.js";

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

/** The block reason every tool call receives while a connector is uninitialised. */
export function formatInitFailureMessage(code: string): string {
	return `AIDR failed to initialise: ${sanitizeCode(code)}; tool calls are blocked until fixed`;
}
