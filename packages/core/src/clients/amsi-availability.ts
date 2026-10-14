/**
 * Host-level AMSI availability, remembered across hook processes (D3).
 *
 * A hook is a fresh process per tool call. Without a record, a Windows host on
 * which AMSI cannot run (koffi missing or blocked and PowerShell in
 * ConstrainedLanguage under AppLocker/WDAC) paid a PowerShell start on every
 * call only to learn the same thing, and every allowed call became an `ask`.
 *
 * The record lives in `~/.singularity-aidr/amsi-state.json` (covered by the
 * self-defense rules like the rest of that directory). It only ever says
 * "AMSI could not be established here, re-probe after <ttl>" or "AMSI worked
 * with <backend>": it can never make a scan look clean. While a fresh
 * "unavailable" record exists the evaluator skips the start-up attempt and
 * treats the AMSI signal as unavailable (skipped, logged, surfaced on the
 * verdict; see `amsi_check.unavailable_action`). A change of state is logged
 * once, not on every call.
 */

import { hostname } from "node:os";
import { join } from "node:path";
import { AIDR_DIR, resolvePath } from "../config.js";
import { atomicWriteJson, getFileContent } from "../file-utils.js";
import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";
import { VERSION } from "../version.js";
import type { AmsiUnavailableKind } from "./amsi.js";
import { AmsiClient, isAmsiSupported } from "./amsi.js";

/** Re-probe interval after a ConstrainedLanguage refusal (policy does not change often). */
const CONSTRAINED_LANGUAGE_TTL_MS = 24 * 60 * 60 * 1000;
/** Re-probe interval after any other start-up failure. */
const NO_BACKEND_TTL_MS = 60 * 60 * 1000;

export type AmsiHostRecord =
	| {
			state: "available";
			backend: string;
			checkedAt: string;
			version: string;
			host: string;
	  }
	| {
			state: "unavailable";
			kind: AmsiUnavailableKind;
			reason: string;
			checkedAt: string;
			version: string;
			host: string;
	  };

function statePath(): string {
	return join(resolvePath(AIDR_DIR), "amsi-state.json");
}

function hostKey(): string {
	return `${process.platform}/${process.arch}/${hostname()}`;
}

function parseRecord(raw: string): AmsiHostRecord | null {
	let data: unknown;
	try {
		data = JSON.parse(raw);
	} catch {
		return null;
	}
	if (typeof data !== "object" || data === null) return null;
	const r = data as Record<string, unknown>;
	if (typeof r.checked_at !== "string" || typeof r.version !== "string") return null;
	if (typeof r.host !== "string") return null;
	const base = { checkedAt: r.checked_at, version: r.version, host: r.host };
	if (r.state === "available" && typeof r.backend === "string") {
		return { state: "available", backend: r.backend, ...base };
	}
	if (
		r.state === "unavailable" &&
		(r.kind === "constrained_language" || r.kind === "no_backend") &&
		typeof r.reason === "string"
	) {
		return { state: "unavailable", kind: r.kind, reason: r.reason.slice(0, 500), ...base };
	}
	return null;
}

/** The recorded AMSI state of this host, or null when none (or an unusable one) is stored. */
export async function readAmsiHostRecord(path = statePath()): Promise<AmsiHostRecord | null> {
	try {
		return parseRecord(await getFileContent(path));
	} catch {
		return null;
	}
}

/**
 * The reason AMSI is known to be unavailable on this host right now, or null
 * when it must be (re)probed. A record from another host, another AIDR
 * version, or older than its TTL never short-circuits the probe.
 */
export function freshUnavailableRecord(
	record: AmsiHostRecord | null,
	now = Date.now(),
): Extract<AmsiHostRecord, { state: "unavailable" }> | null {
	if (record?.state !== "unavailable") return null;
	if (record.version !== VERSION || record.host !== hostKey()) return null;
	const checked = Date.parse(record.checkedAt);
	if (!Number.isFinite(checked) || checked > now) return null;
	const ttl =
		record.kind === "constrained_language" ? CONSTRAINED_LANGUAGE_TTL_MS : NO_BACKEND_TTL_MS;
	return now - checked < ttl ? record : null;
}

/**
 * Store the outcome of a start-up attempt. Writes (and logs) only when the
 * state differs from what is stored, so an unchanged host costs no write and
 * no repeated warning. Best effort: a failed write is logged and ignored.
 */
export async function recordAmsiHostState(
	outcome:
		| { state: "available"; backend: string }
		| { state: "unavailable"; kind: AmsiUnavailableKind; reason: string },
	logger: Logger = nullLogger,
	options: { path?: string; now?: number } = {},
): Promise<void> {
	const path = options.path ?? statePath();
	const previous = await readAmsiHostRecord(path);
	const now = options.now ?? Date.now();
	const unchanged =
		previous !== null &&
		previous.version === VERSION &&
		previous.host === hostKey() &&
		previous.state === outcome.state &&
		(outcome.state === "available"
			? previous.state === "available" && previous.backend === outcome.backend
			: previous.state === "unavailable" &&
				previous.kind === outcome.kind &&
				freshUnavailableRecord(previous, now) !== null);
	if (unchanged) return;
	const record =
		outcome.state === "available"
			? { state: "available", backend: outcome.backend }
			: { state: "unavailable", kind: outcome.kind, reason: outcome.reason.slice(0, 500) };
	try {
		await atomicWriteJson(path, {
			...record,
			checked_at: new Date(now).toISOString(),
			version: VERSION,
			host: hostKey(),
		});
	} catch (error) {
		logger.debug("AMSI: host state could not be recorded", { error: String(error) });
	}
	if (outcome.state === "unavailable") {
		logger.warn(
			"AMSI is unavailable on this host; the AMSI signal is skipped (not treated as a clean scan) until it is re-probed",
			{ kind: outcome.kind, reason: outcome.reason },
		);
	} else if (previous?.state === "unavailable") {
		logger.warn("AMSI is available again on this host", { backend: outcome.backend });
	}
}

/**
 * Start-up probe (session start, `aidr doctor`): establish an AMSI backend
 * once, record the outcome and close it again. Returns the recorded outcome,
 * or null on a host that does not support AMSI.
 */
async function probeAmsiAvailability(
	logger: Logger = nullLogger,
	options: { path?: string } = {},
): Promise<AmsiHostRecord | null> {
	if (!isAmsiSupported()) return null;
	const client = new AmsiClient(logger);
	try {
		await client.init();
		if (client.isAvailable) {
			await recordAmsiHostState(
				{ state: "available", backend: client.backendKind },
				logger,
				options,
			);
		} else {
			await recordAmsiHostState(
				{
					state: "unavailable",
					kind: client.unavailableKind ?? "no_backend",
					reason: client.unavailableDetail ?? "no AMSI backend could be established on this host",
				},
				logger,
				options,
			);
		}
	} catch (error) {
		// A probe that threw says nothing stable about the host; do not record it.
		logger.debug("AMSI: start-up probe failed", { error: String(error) });
	} finally {
		client.close();
	}
	return readAmsiHostRecord(options.path ?? statePath());
}

/**
 * AMSI state for a session start banner: null when the leg does not apply
 * (disabled, or a host without AMSI); otherwise a fresh "unavailable" record
 * as stored, or the outcome of one start-up probe. Run once per session so the
 * per-call path finds the answer recorded instead of probing itself.
 */
export async function amsiSessionStatus(
	enabled: boolean,
	logger: Logger = nullLogger,
): Promise<AmsiHostRecord | null> {
	if (!enabled || !isAmsiSupported()) return null;
	const fresh = freshUnavailableRecord(await readAmsiHostRecord());
	if (fresh) return fresh;
	return probeAmsiAvailability(logger);
}
